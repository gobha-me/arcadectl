// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

// This synthetic-fixture screen is not a native lifecycle proof. Profiles and
// tool output stay in bounded RAM; only fixed identifiers and numbers escape.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"

	"golang.org/x/sys/unix"
)

const captureLimit = 8 << 20
const repeats = 16
const enginePackage = "github.com/gobha-me/arcadectl/internal/installengine."

var errScreen = errors.New("wrapper screen refused")

type target struct{ id, test, subtest, root string }

var targets = []target{
	{"baseline", "TestBaselineBehaviorWholeProviderRuntimeHealthy", "", enginePackage + "(*ClusterSecurityBaseline).Verify"},
	{"phase", "TestFixturePhaseCompleteOriginalAndFixedFixtureAccounting", "original", enginePackage + "(*fixtureWire).observePhaseLocked"},
}

// Never export profile-controlled function names, labels, comments or paths.
var functions = map[string]string{
	enginePackage + "(*ClusterSecurityBaseline).Verify":              "baseline-verify",
	enginePackage + "(*ClusterSecurityBaseline).newBaselineBehavior": "baseline-construction",
	enginePackage + "(*baselineBehavior).prove":                      "baseline-proof",
	enginePackage + "(*baselineBehavior).readExactDiagnostic":        "baseline-exact-read",
	enginePackage + "(*baselineBehavior).close":                      "baseline-close",
	enginePackage + "(*fixtureWire).observePhaseLocked":              "phase-observation",
	enginePackage + "(*fixtureWire).localCurrent":                    "phase-local-current",
	enginePackage + "(*fixtureLedger).readOriginalWorldsMode":        "original-worlds-read",
	enginePackage + "(*fixtureLedger).originalWorldsWALCurrent":      "original-worlds-wal",
	enginePackage + "(*fixtureLedger).matchCurrentWorlds":            "current-worlds-match",
	enginePackage + "(*fixtureDecodeCache).worldsLocked":             "decode-worlds",
	enginePackage + "(*fixtureDecodeCache).walLocked":                "decode-wal",
	enginePackage + "(*fixtureDecodeCache).journalLocked":            "decode-journal",
	enginePackage + "(*fixtureLedger).checkCurrentWAL":               "current-wal-check",
	enginePackage + "(*fixtureLedger).accountPhaseWithAccounts":      "phase-accounting",
	enginePackage + "(*fixtureLedger).validatePhaseFixture":          "phase-fixture-validation",
	enginePackage + "(*fixtureLedger).phaseGCRowsWithAccountsTrace":  "phase-gc-accounting",
	"encoding/json.Unmarshal":                                        "json-unmarshal",
	"encoding/json.Marshal":                                          "json-marshal",
}

type custody struct {
	Bytes  int    `json:"bytes"`
	SHA256 string `json:"sha256"`
}

// Refusals expose only closed stage/outcome identifiers, fixed-root counts and
// capture custody. Never include an underlying error or captured log text.
type rootCounts struct {
	ID     string `json:"id"`
	Runs   int    `json:"runs"`
	Passes int    `json:"passes"`
}
type screenRefusal struct {
	Stage        string       `json:"stage"`
	Target       string       `json:"target,omitempty"`
	Metric       string       `json:"metric,omitempty"`
	Reason       string       `json:"reason"`
	ExitCode     int          `json:"exitCode"`
	Stdout       custody      `json:"stdout"`
	Stderr       custody      `json:"stderr"`
	Truncated    bool         `json:"truncated"`
	TestTimedOut bool         `json:"testTimedOut"`
	Roots        []rootCounts `json:"roots,omitempty"`
}

func (*screenRefusal) Error() string { return "wrapper screen refused" }
func (*screenRefusal) Unwrap() error { return errScreen }
func refused(stage, target, metric string, err error) error {
	f := screenRefusal{Reason: "validation", ExitCode: -1}
	var child *screenRefusal
	if errors.As(err, &child) {
		f = *child
	}
	if stage != "" {
		f.Stage = stage
	}
	if target != "" {
		f.Target = target
	}
	if metric != "" {
		f.Metric = metric
	}
	return &f
}
func transcriptCounts(body []byte) []rootCounts {
	var counts []rootCounts
	for _, t := range targets {
		counts = append(counts, rootCounts{t.id,
			bytes.Count(body, []byte("=== RUN   "+t.test+"\n")),
			bytes.Count(body, []byte("--- PASS: "+t.test+" ("))})
	}
	return counts
}

type row struct {
	ID         string  `json:"id"`
	Flat       float64 `json:"flat"`
	Cumulative float64 `json:"cumulative"`
}
type metric struct {
	Kind           string  `json:"kind"`
	Profile        custody `json:"profile"`
	RootCumulative float64 `json:"rootCumulative"`
	UnknownFlat    float64 `json:"unknownFlat"`
	Rows           []row   `json:"rows"`
}
type result struct {
	ID         string   `json:"id"`
	Repeats    int      `json:"repeats"`
	WallNS     int64    `json:"wallNS"`
	TestOutput custody  `json:"testOutput"`
	Metrics    []metric `json:"metrics"`
}

// Keep draining on overflow while cancellation joins the child. Never forward
// raw tool output, even on failure. All callers wipe retained bytes.
type bounded struct {
	mu       sync.Mutex
	body     []byte
	overflow bool
	cancel   context.CancelFunc
}

func (b *bounded) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(p) > captureLimit-len(b.body) {
		b.overflow = true
		b.cancel()
	} else if !b.overflow {
		b.body = append(b.body, p...)
	}
	return len(p), nil
}
func (b *bounded) wipe() { clear(b.body); b.body = nil }
func describe(b []byte) custody {
	h := sha256.Sum256(b)
	return custody{len(b), hex.EncodeToString(h[:])}
}

// Cancellation terminates the owned process group and joins the direct child
// and capture readers. It cannot reap grandchildren. All commands are bounded.
func command(ctx context.Context, timeout time.Duration, stdin *os.File, extra []*os.File, name string, args ...string) ([]byte, error) {
	return commandAt(ctx, timeout, stdin, extra, "", name, args...)
}

func commandAt(ctx context.Context, timeout time.Duration, stdin *os.File, extra []*os.File, directory, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out, diagnostic := &bounded{cancel: cancel}, &bounded{cancel: cancel}
	defer diagnostic.wipe()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = directory
	cmd.Stdin, cmd.Stdout, cmd.Stderr, cmd.ExtraFiles = stdin, out, diagnostic, extra
	cmd.Env = append(os.Environ(), "GOMAXPROCS=2", "GOMEMLIMIT=1GiB", "GOTOOLCHAIN=local", "GOTELEMETRY=off", "PPROF_BINARY_PATH=/proc/self/fd/-1")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil && err != syscall.ESRCH {
			return err
		}
		return nil
	}
	cmd.WaitDelay = 5 * time.Second
	err := cmd.Start()
	// Children hold their own copies. Closing these is required for EOF.
	for _, f := range extra {
		_ = f.Close()
	}
	if err == nil {
		err = cmd.Wait()
		// Clean up screen-owned descendants even when their parent succeeded.
		if groupErr := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); groupErr != nil && groupErr != syscall.ESRCH {
			err = errScreen
		}
	}
	if err != nil || ctx.Err() != nil || out.overflow || diagnostic.overflow {
		f := &screenRefusal{Stage: "command", Reason: "child-exit", ExitCode: -1,
			Stdout: describe(out.body), Stderr: describe(diagnostic.body),
			Truncated:    out.overflow || diagnostic.overflow,
			TestTimedOut: bytes.Contains(out.body, []byte("panic: test timed out after ")) || bytes.Contains(diagnostic.body, []byte("panic: test timed out after ")),
			Roots:        transcriptCounts(out.body)}
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			f.ExitCode = exit.ExitCode()
		}
		if cmd.Process == nil {
			f.Reason = "start-refused"
		}
		if ctx.Err() == context.DeadlineExceeded {
			f.Reason = "command-deadline"
		}
		if ctx.Err() == context.Canceled {
			f.Reason = "command-cancelled"
		}
		if f.Truncated {
			f.Reason = "capture-limit"
		}
		out.wipe()
		return nil, f
	}
	return out.body, nil
}

func source(ctx context.Context, expected string) error {
	if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(expected) {
		return errScreen
	}
	b, err := command(ctx, time.Minute, nil, nil, "git", "rev-parse", "HEAD")
	if err != nil {
		return errScreen
	}
	defer clear(b)
	if string(bytes.TrimSpace(b)) != expected {
		return errScreen
	}
	dirty, err := command(ctx, time.Minute, nil, nil, "git", "status", "--porcelain", "--untracked-files=normal")
	defer clear(dirty)
	if err != nil || len(dirty) != 0 {
		return errScreen
	}
	return nil
}

func selectedOutput(body []byte, t target) bool {
	counts := map[string]int{}
	selected := t.test
	if t.subtest != "" {
		selected += "/" + t.subtest
	}
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "=== RUN   ") {
			name := strings.TrimPrefix(line, "=== RUN   ")
			if name != t.test && name != selected {
				return false
			}
			counts["run:"+name]++
		} else if strings.HasPrefix(line, "--- PASS: ") {
			fields := strings.Fields(strings.TrimPrefix(line, "--- PASS: "))
			if len(fields) != 2 || (fields[0] != t.test && fields[0] != selected) {
				return false
			}
			counts["pass:"+fields[0]]++
		} else if line == "PASS" {
			counts["whole"]++
		} else if line != "" {
			// No failure/skip/provider output may be accepted as a successful run.
			return false
		}
	}
	return counts["whole"] == 1 && counts["run:"+t.test] == repeats && counts["pass:"+t.test] == repeats && counts["run:"+selected] == repeats && counts["pass:"+selected] == repeats
}

func runTarget(ctx context.Context, binary string, t target) (result, error) {
	ctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
	defer cancel()
	var reads, writes []*os.File
	var captures []*bounded
	var readers sync.WaitGroup
	defer func() {
		for _, f := range reads {
			_ = f.Close()
		}
		for _, f := range writes {
			_ = f.Close()
		}
		readers.Wait()
		for _, b := range captures {
			b.wipe()
		}
	}()
	for range 2 {
		r, w, err := os.Pipe()
		if err != nil {
			return result{}, errScreen
		}
		reads, writes = append(reads, r), append(writes, w)
		b := &bounded{cancel: cancel}
		captures = append(captures, b)
		readers.Add(1)
		go func() {
			defer readers.Done()
			if _, err := io.Copy(b, r); err != nil {
				cancel()
			}
		}()
	}
	selector := "^" + t.test + "$"
	if t.subtest != "" {
		selector += "/^" + t.subtest + "$"
	}
	start := time.Now()
	body, err := command(ctx, 4*time.Minute, nil, writes, binary,
		"-test.run="+selector, "-test.count=16", "-test.v", "-test.timeout=3m",
		"-test.cpuprofile=/proc/self/fd/3", "-test.memprofile=/proc/self/fd/4", "-test.memprofilerate=8192")
	defer clear(body)
	joined := joinReaders(ctx, reads, &readers)
	if err != nil {
		return result{}, refused("test-child", t.id, "", err)
	}
	if !joined {
		return result{}, refused("profile-reader-join", t.id, "", errScreen)
	}
	if !selectedOutput(body, t) {
		return result{}, refused("test-transcript", t.id, "", errScreen)
	}
	r := result{ID: t.id, Repeats: repeats, WallNS: time.Since(start).Nanoseconds(), TestOutput: describe(body)}
	for i, kind := range []string{"cpu-nanoseconds", "sampled-alloc-bytes"} {
		if captures[i].overflow || len(captures[i].body) == 0 {
			return result{}, refused("profile-capture", t.id, kind, errScreen)
		}
		m, err := analyze(ctx, captures[i].body, t.root, kind)
		if err != nil {
			return result{}, refused("", t.id, kind, err)
		}
		r.Metrics = append(r.Metrics, m)
	}
	return r, nil
}

func joinReaders(ctx context.Context, reads []*os.File, readers *sync.WaitGroup) bool {
	done := make(chan struct{})
	go func() { readers.Wait(); close(done) }()
	select {
	case <-done:
		return ctx.Err() == nil
	case <-ctx.Done():
		for _, r := range reads {
			_ = r.Close()
		}
		<-done
		return false
	}
}

func analyze(ctx context.Context, body []byte, root, kind string) (metric, error) {
	return analyzeWithCatalog(ctx, body, root, kind, functions)
}

func analyzeWithCatalog(ctx context.Context, body []byte, root, kind string, catalog map[string]string) (metric, error) {
	// A perf input invokes conversion that creates a temporary raw file.
	if len(body) < 3 || !bytes.Equal(body[:3], []byte{0x1f, 0x8b, 8}) {
		return metric{}, refused("profile-format", "", kind, errScreen)
	}
	// pprof probes/reopens its source; a plain pipe would lose its first eight
	// bytes. The sealed anonymous RAM file permits independent /proc opens,
	// without creating a persistent raw profile or invoking a remote fetch.
	fd, err := unix.MemfdCreate("wrapper-screen", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return metric{}, refused("profile-memfd", "", kind, err)
	}
	f := os.NewFile(uintptr(fd), "wrapper-screen")
	defer f.Close()
	if _, err = f.Write(body); err != nil {
		return metric{}, refused("profile-write", "", kind, err)
	}
	if _, err = unix.FcntlInt(f.Fd(), unix.F_ADD_SEALS, unix.F_SEAL_WRITE|unix.F_SEAL_SHRINK|unix.F_SEAL_GROW|unix.F_SEAL_SEAL); err != nil {
		return metric{}, refused("profile-seal", "", kind, err)
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return metric{}, refused("profile-rewind", "", kind, err)
	}
	index, unit := "cpu", "ns"
	if kind == "sampled-alloc-bytes" {
		index, unit = "alloc_space", "bytes"
	}
	text, err := command(ctx, time.Minute, f, nil, "go", "tool", "pprof", "-top", "-cum", "-functions", "-nodecount=0", "-nodefraction=0", "-edgefraction=0", "-symbolize=none", "-unit="+unit, "-sample_index="+index, "-focus=^"+regexp.QuoteMeta(root)+"$", "/proc/self/fd/0")
	defer clear(text)
	if err != nil {
		return metric{}, refused("pprof-child", "", kind, err)
	}
	m, err := parseTopWithCatalog(text, root, kind, catalog)
	m.Profile = describe(body)
	if err != nil {
		return m, refused("pprof-projection", "", kind, err)
	}
	return m, err
}

func parseTop(body []byte, root, kind string) (metric, error) {
	return parseTopWithCatalog(body, root, kind, functions)
}

func parseTopWithCatalog(body []byte, root, kind string, catalog map[string]string) (metric, error) {
	m := metric{Kind: kind, Rows: []row{}}
	unit := "ns"
	if kind == "sampled-alloc-bytes" {
		unit = "B"
	}
	seen, header, sampleType := map[string]bool{}, false, false
	wantType := "Type: cpu"
	if kind == "sampled-alloc-bytes" {
		wantType = "Type: alloc_space"
	}
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(line)
		if strings.TrimSpace(line) == wantType {
			sampleType = true
		}
		if strings.Join(fields, " ") == "flat flat% sum% cum cum%" {
			header = true
			continue
		}
		if !header || len(fields) == 0 {
			continue
		}
		// pprof prints five numeric columns, then an unquoted function name.
		// Generic Go names can contain spaces; the remainder is one symbol,
		// not additional columns, and must never be matched by its first word.
		if len(fields) < 6 {
			return metric{}, projectionFailure("profile-row")
		}
		name := strings.TrimSpace(line)
		for range 5 {
			end := strings.IndexFunc(name, unicode.IsSpace)
			if end <= 0 {
				return metric{}, projectionFailure("profile-row")
			}
			name = strings.TrimLeftFunc(name[end:], unicode.IsSpace)
		}
		for _, suffix := range []string{" (inline)", " (partial-inline)"} {
			if strings.HasSuffix(name, suffix) {
				name = strings.TrimSuffix(name, suffix)
				break
			}
		}
		if name == "" {
			return metric{}, projectionFailure("profile-row")
		}
		value := func(s string) (float64, error) {
			if s == "0" {
				return 0, nil
			}
			if !strings.HasSuffix(s, unit) {
				return 0, errScreen
			}
			v, e := strconv.ParseFloat(strings.TrimSuffix(s, unit), 64)
			if e != nil || math.IsNaN(v) || math.IsInf(v, 0) || v < 0 || v > 1e18 {
				return 0, errScreen
			}
			return v, nil
		}
		flat, e1 := value(fields[0])
		cum, e2 := value(fields[3])
		for _, i := range []int{1, 2, 4} {
			if !strings.HasSuffix(fields[i], "%") {
				return metric{}, projectionFailure("profile-percent")
			}
			p, err := strconv.ParseFloat(strings.TrimSuffix(fields[i], "%"), 64)
			if err != nil || math.IsNaN(p) || math.IsInf(p, 0) || p < 0 || p > 100.01 {
				return metric{}, projectionFailure("profile-percent")
			}
		}
		if e1 != nil || e2 != nil || flat > cum {
			return metric{}, projectionFailure("profile-value")
		}
		if seen[name] {
			return metric{}, projectionFailure("profile-duplicate")
		}
		seen[name] = true
		if name == root {
			m.RootCumulative = cum
		}
		if id, ok := catalog[name]; ok {
			m.Rows = append(m.Rows, row{id, flat, cum})
		} else {
			m.UnknownFlat += flat
		}
	}
	if !header {
		return metric{}, projectionFailure("profile-header")
	}
	if !sampleType {
		return metric{}, projectionFailure("profile-sample-type")
	}
	if m.RootCumulative <= 0 {
		return metric{}, projectionFailure("profile-root")
	}
	return m, nil
}

func projectionFailure(reason string) error {
	return &screenRefusal{Stage: "pprof-projection", Reason: reason, ExitCode: -1}
}

func binaryDigest(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", errScreen
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", errScreen
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func screen(parent context.Context, expected string) error {
	ctx, cancel := context.WithTimeout(parent, 12*time.Minute)
	defer cancel()
	if err := source(ctx, expected); err != nil {
		return refused("opening-source", "", "", err)
	}
	dir, err := os.MkdirTemp("", "arcadectl-wrapper-screen-")
	if err != nil {
		return refused("scratch-create", "", "", err)
	}
	identity, err := os.Stat(dir)
	if err != nil {
		return refused("scratch-identity", "", "", err)
	}
	// Remove only our unchanged owned directory, never a shared cache/worktree.
	defer func() {
		if now, e := os.Lstat(dir); e == nil && os.SameFile(identity, now) {
			_ = os.RemoveAll(dir)
		}
	}()
	// Keep compiler scratch and testing.T temporary directories inside the
	// same owned cleanup boundary; never clear a shared Go cache.
	previousTmp := os.Getenv("TMPDIR")
	if os.Setenv("TMPDIR", dir) != nil {
		return refused("scratch-environment", "", "", errScreen)
	}
	defer os.Setenv("TMPDIR", previousTmp)
	binary := filepath.Join(dir, "installengine.test")
	out, err := command(ctx, 6*time.Minute, nil, nil, "go", "test", "-c", "-p", "1", "-o", binary, "./internal/installengine")
	clear(out)
	if err != nil {
		return refused("build-child", "", "", err)
	}
	digest, err := binaryDigest(binary)
	if err != nil {
		return refused("opening-binary", "", "", err)
	}
	results := []result{}
	for _, t := range targets {
		r, err := runTarget(ctx, binary, t)
		if err != nil {
			return err
		}
		results = append(results, r)
	}
	if err := source(ctx, expected); err != nil {
		return refused("closing-source", "", "", err)
	}
	if closing, err := binaryDigest(binary); err != nil || closing != digest {
		return refused("closing-binary", "", "", errScreen)
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		Schema         string   `json:"schema"`
		Source         string   `json:"source"`
		BinarySHA256   string   `json:"binarySHA256"`
		Scope          string   `json:"scope"`
		MemProfileRate int      `json:"memProfileRate"`
		Results        []result `json:"results"`
	}{"arcadectl-wrapper-screen-v1", expected, digest, "synthetic-root-focused-synchronous-stacks; formatted-rounded-values; cumulative-overlaps; sampled-allocations; profiling-perturbs-CPU; excludes-async-and-native-wait", 8192, results})
}

func main() {
	started := time.Now()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	var err error = errScreen
	if len(os.Args) == 2 {
		err = screen(ctx, os.Args[1])
	} else if len(os.Args) == 3 && os.Args[1] == "native-component" {
		err = nativeScreen(ctx, os.Args[2])
	}
	stop()
	if err != nil {
		f := &screenRefusal{Stage: "screen", Reason: "validation", ExitCode: -1}
		_ = errors.As(err, &f)
		schema := "arcadectl-wrapper-screen-refusal-v1"
		if len(os.Args) == 3 && os.Args[1] == "native-component" {
			schema = "arcadectl-native-component-screen-refusal-v1"
			f.Roots = nil // The synthetic root census is not a native transcript.
		}
		_ = json.NewEncoder(os.Stdout).Encode(struct {
			Schema    string         `json:"schema"`
			ElapsedNS int64          `json:"elapsedNS"`
			Refusal   *screenRefusal `json:"refusal"`
		}{schema, time.Since(started).Nanoseconds(), f})
		_, _ = io.WriteString(os.Stderr, "wrapper screen refused; no raw diagnostics exported\n")
		os.Exit(1)
	}
}
