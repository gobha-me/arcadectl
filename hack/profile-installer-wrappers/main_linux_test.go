// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func testTranscript(t target) string {
	var b strings.Builder
	for range repeats {
		fmt.Fprintf(&b, "=== RUN   %s\n", t.test)
		if t.subtest != "" {
			fmt.Fprintf(&b, "=== RUN   %s/%s\n", t.test, t.subtest)
		}
		fmt.Fprintf(&b, "--- PASS: %s (0.01s)\n", t.test)
		if t.subtest != "" {
			fmt.Fprintf(&b, "    --- PASS: %s/%s (0.01s)\n", t.test, t.subtest)
		}
	}
	b.WriteString("PASS\n")
	return b.String()
}

func TestSelectedOutputRequiresEveryExistingOracle(t *testing.T) {
	for _, target := range targets {
		good := testTranscript(target)
		if !selectedOutput([]byte(good), target) {
			t.Fatal("complete selected repetitions refused")
		}
		for _, bad := range []string{
			"PASS\n", "", strings.Replace(good, "=== RUN   ", "=== SKIP  ", 1),
			strings.Replace(good, "--- PASS:", "--- FAIL:", 1),
			strings.Replace(good, "--- PASS:", "--- SKIP:", 1),
			strings.Replace(good, "=== RUN   "+target.test, "=== RUN   Other", 1),
			strings.Replace(good, "PASS\n", "", 1), good + "PASS\n", good + "provider-controlled canary\n",
			good + "=== RUN   Extra\n", good + "--- PASS: Extra (0.01s)\n",
		} {
			if selectedOutput([]byte(bad), target) {
				t.Fatal("incomplete or foreign transcript accepted")
			}
		}
	}
}

func TestTopExportsOnlyClosedNumericRows(t *testing.T) {
	root := targets[0].root
	for _, fixture := range []struct{ kind, unit string }{{"cpu-nanoseconds", "ns"}, {"sampled-alloc-bytes", "B"}} {
		sampleType := "cpu"
		if fixture.kind == "sampled-alloc-bytes" {
			sampleType = "alloc_space"
		}
		text := "File: provider-canary\ncomment: private-canary\nType: " + sampleType + "\nflat flat% sum% cum cum%\n" +
			"0 0% 0% 100" + fixture.unit + " 100% " + root + "\n" +
			"50" + fixture.unit + " 50% 50% 50" + fixture.unit + " 50% provider-controlled-symbol\n" +
			"50" + fixture.unit + " 50% 100% 50" + fixture.unit + " 50% encoding/json.Marshal (inline)\n"
		m, err := parseTop([]byte(text), root, fixture.kind)
		if err != nil || m.RootCumulative != 100 || m.UnknownFlat != 50 || len(m.Rows) != 2 {
			t.Fatal("fixed projection incorrect")
		}
		encoded, err := json.Marshal(m)
		if err != nil || strings.Contains(string(encoded), "canary") || strings.Contains(string(encoded), "provider") || strings.Contains(string(encoded), root) {
			t.Fatal("raw profile metadata escaped")
		}
		for _, name := range []string{
			"provider[go.shape.struct { private string }].call",
			"provider[go.shape.struct { private string }].call (inline)",
			"provider[go.shape.struct { private string }].call (partial-inline)",
			"encoding/json.Marshal provider-private-canary",
		} {
			candidate := strings.Replace(text, "provider-controlled-symbol", name, 1)
			projected, err := parseTop([]byte(candidate), root, fixture.kind)
			if err != nil || projected.UnknownFlat != 50 || len(projected.Rows) != 2 {
				t.Fatal("complete multiword symbol was split or matched by prefix")
			}
			b, err := json.Marshal(projected)
			if err != nil || strings.Contains(string(b), "provider") || strings.Contains(string(b), "private") {
				t.Fatal("unknown multiword symbol escaped")
			}
		}
		sharedPrefix := strings.Replace(text, "50"+fixture.unit+" 50% 50% 50"+fixture.unit+" 50% provider-controlled-symbol\n",
			"25"+fixture.unit+" 25% 25% 25"+fixture.unit+" 25% provider[go.shape.struct { first string }].call\n"+
				"25"+fixture.unit+" 25% 50% 25"+fixture.unit+" 25% provider[go.shape.struct { second string }].call\n", 1)
		if projected, err := parseTop([]byte(sharedPrefix), root, fixture.kind); err != nil || projected.UnknownFlat != 50 {
			t.Fatal("distinct complete symbols sharing a first token were conflated")
		}
		for _, bad := range []string{
			text + "0 0% 0% 0 0% \n",
			strings.Replace(text, "Type: "+sampleType, "Type: unknown", 1),
			strings.Replace(text, "50% 50%", "NaN% 50%", 1),
			strings.Replace(text, "100"+fixture.unit+" 100% "+root, "0 100% "+root, 1),
			strings.Replace(text, "50"+fixture.unit+" 50% 50%", "NaN"+fixture.unit+" 50% 50%", 1),
			strings.Replace(text, "50"+fixture.unit+" 50% 50%", "-1"+fixture.unit+" 50% 50%", 1),
			strings.Replace(text, "50"+fixture.unit+" 50% 50%", "1e40"+fixture.unit+" 50% 50%", 1),
			strings.Replace(text, "flat flat% sum% cum cum%", "unknown header", 1),
			text + "0 0% 0% 100" + fixture.unit + " 100% " + root + "\n",
			text + "unrecognized trailing output\n",
		} {
			if _, err := parseTop([]byte(bad), root, fixture.kind); err == nil {
				t.Fatal("malformed or missing-root profile accepted")
			}
		}
	}
}

func TestBoundedCaptureCancelsAndDoesNotRetainOverflow(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := &bounded{cancel: cancel}
	defer b.wipe()
	if n, err := b.Write(make([]byte, captureLimit)); err != nil || n != captureLimit || ctx.Err() != nil {
		t.Fatal("capture refused its exact bound")
	}
	if n, err := b.Write([]byte("private-canary")); err != nil || n != 14 || !b.overflow || ctx.Err() == nil || len(b.body) != captureLimit {
		t.Fatal("overflow was retained or did not cancel")
	}
	b.wipe()
	if b.body != nil {
		t.Fatal("capture retained after wipe")
	}
}

func TestCommandCapturesAndJoinsWithoutForwardingRawErrors(t *testing.T) {
	// Reexec this small helper, never compile or launch a cluster in tests.
	for _, mode := range []string{"success", "failure", "timeout"} {
		t.Setenv("ARCADECTL_WRAPPER_SCREEN_HELPER", mode)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		body, err := command(ctx, 3*time.Second, nil, nil, os.Args[0], "-test.run=^TestCommandHelper$")
		cancel()
		if mode == "success" {
			if err != nil || string(body) != "controlled" {
				t.Fatal("bounded child result unavailable")
			}
		} else if !errors.Is(err, errScreen) || len(body) != 0 {
			t.Fatal("child failure was accepted or raw output escaped")
		} else {
			var refusal *screenRefusal
			if !errors.As(err, &refusal) || refusal.Stdout.SHA256 == "" || refusal.Stderr.SHA256 == "" {
				t.Fatal("child refusal lost bounded capture custody")
			}
			if mode == "failure" && (refusal.Reason != "child-exit" || refusal.ExitCode != 3 || refusal.Stderr.Bytes != 14) {
				t.Fatal("child exit classification incorrect")
			}
			if mode == "timeout" && refusal.Reason != "command-deadline" {
				t.Fatal("deadline classification incorrect")
			}
		}
		clear(body)
	}
}

func TestRefusalRetainsStageWithoutRawErrors(t *testing.T) {
	child := refused("pprof-child", "", "cpu-nanoseconds", errors.New("provider-private-canary"))
	err := refused("", "baseline", "cpu-nanoseconds", child)
	var refusal *screenRefusal
	if !errors.As(err, &refusal) || !errors.Is(err, errScreen) || refusal.Stage != "pprof-child" || refusal.Target != "baseline" {
		t.Fatal("nested refusal lost fixed context")
	}
	body, encodeErr := json.Marshal(refusal)
	if encodeErr != nil || strings.Contains(string(body), "canary") || strings.Contains(string(body), "provider") {
		t.Fatal("raw child error escaped")
	}
	counts := transcriptCounts(append([]byte(testTranscript(targets[0])), []byte("=== RUN   ProviderPrivateCanary\n")...))
	if len(counts) != 2 || counts[0].ID != "baseline" || counts[0].Runs != repeats || counts[0].Passes != repeats || counts[1].Runs != 0 || counts[1].Passes != 0 {
		t.Fatal("fixed-root transcript counters incorrect")
	}
}

func TestProfileReaderDeadlineClosesInheritedWriter(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal("pipe unavailable")
	}
	defer r.Close()
	defer w.Close()
	var readers sync.WaitGroup
	readers.Add(1)
	go func() { defer readers.Done(); var b [1]byte; _, _ = r.Read(b[:]) }()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if joinReaders(ctx, []*os.File{r}, &readers) {
		t.Fatal("held writer accepted as a complete profile")
	}
}

func TestAnalyzeRejectsNonGoProfilesWithoutToolExecution(t *testing.T) {
	for _, body := range [][]byte{nil, []byte("PERFILE2-private"), []byte("private-canary")} {
		if _, err := analyze(context.Background(), body, targets[0].root, "cpu-nanoseconds"); !errors.Is(err, errScreen) {
			t.Fatal("non-Go input reached analysis")
		}
	}
}

func TestMemfdProbeReopensFromStartAndCannotBeModified(t *testing.T) {
	fd, err := unix.MemfdCreate("wrapper-screen-test", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		t.Fatal("anonymous profile descriptor unavailable")
	}
	f := os.NewFile(uintptr(fd), "wrapper-screen-test")
	defer f.Close()
	data := []byte("eight-byte-probe-followed-by-profile")
	if _, err := f.Write(data); err != nil {
		t.Fatal("anonymous profile write refused")
	}
	if _, err := unix.FcntlInt(f.Fd(), unix.F_ADD_SEALS, unix.F_SEAL_WRITE|unix.F_SEAL_SHRINK|unix.F_SEAL_GROW|unix.F_SEAL_SEAL); err != nil {
		t.Fatal("profile sealing refused")
	}
	if _, err := f.Write([]byte("private-canary")); err == nil {
		t.Fatal("sealed profile remained writable")
	}
	path := fmt.Sprintf("/proc/self/fd/%d", fd)
	probe, err := os.Open(path)
	if err != nil {
		t.Fatal("profile probe unavailable")
	}
	var first [8]byte
	_, err = probe.Read(first[:])
	_ = probe.Close()
	if err != nil || !bytes.Equal(first[:], data[:8]) {
		t.Fatal("probe did not start from zero")
	}
	body, err := os.ReadFile(path)
	defer clear(body)
	if err != nil || !bytes.Equal(body, data) {
		t.Fatal("format probe consumed reopened profile")
	}
}

func TestSourceRefusesUnboundHeadWithoutCommands(t *testing.T) {
	for _, expected := range []string{"", "main", strings.Repeat("a", 39), strings.Repeat("A", 40), "private-canary"} {
		if source(context.Background(), expected) != errScreen {
			t.Fatal("unbound source accepted")
		}
	}
}

func TestSourceRefusesWrongHeadAndDirtyCheckout(t *testing.T) {
	t.Chdir(t.TempDir())
	ctx := t.Context()
	git := func(args ...string) string {
		t.Helper()
		b, err := command(ctx, 10*time.Second, nil, nil, "git", args...)
		defer clear(b)
		if err != nil {
			t.Fatal("source fixture unavailable")
		}
		return strings.TrimSpace(string(b))
	}
	git("init", "--quiet")
	if os.WriteFile("tracked", []byte("original"), 0600) != nil {
		t.Fatal("source fixture unavailable")
	}
	git("add", "tracked")
	git("-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "fixture")
	head := git("rev-parse", "HEAD")
	if source(ctx, head) != nil {
		t.Fatal("clean exact source refused")
	}
	if source(ctx, strings.Repeat("0", 40)) != errScreen {
		t.Fatal("wrong source accepted")
	}
	if os.WriteFile("untracked", []byte("fixture"), 0600) != nil {
		t.Fatal("source fixture unavailable")
	}
	if source(ctx, head) != errScreen {
		t.Fatal("untracked source accepted")
	}
	if os.Remove("untracked") != nil || os.WriteFile("tracked", []byte("changed"), 0600) != nil {
		t.Fatal("source fixture unavailable")
	}
	if source(ctx, head) != errScreen {
		t.Fatal("modified source accepted")
	}
}

func TestCommandTerminatesSurvivingProfileWriter(t *testing.T) {
	t.Setenv("ARCADECTL_WRAPPER_SCREEN_HELPER", "descendant-parent")
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal("pipe unavailable")
	}
	defer r.Close()
	defer w.Close()
	body, err := command(t.Context(), 5*time.Second, nil, []*os.File{w}, os.Args[0], "-test.run=^TestCommandHelper$")
	defer clear(body)
	if err != nil {
		t.Fatal("parent command refused")
	}
	var readers sync.WaitGroup
	readers.Add(1)
	go func() { defer readers.Done(); var b [1]byte; _, _ = r.Read(b[:]) }()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if !joinReaders(ctx, []*os.File{r}, &readers) {
		t.Fatal("surviving profile writer was not terminated")
	}
}

func TestCommandHelper(t *testing.T) {
	switch os.Getenv("ARCADECTL_WRAPPER_SCREEN_HELPER") {
	case "signal-context":
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		_, _ = os.Stdout.WriteString("ready\n")
		_ = os.Setenv("ARCADECTL_WRAPPER_SCREEN_HELPER", "timeout")
		body, err := command(ctx, 2*time.Second, nil, nil, os.Args[0], "-test.run=^TestCommandHelper$")
		clear(body)
		if errors.Is(err, errScreen) && ctx.Err() != nil {
			os.Exit(0)
		}
		os.Exit(4)
	case "descendant-parent":
		child := exec.Command(os.Args[0], "-test.run=^TestCommandHelper$")
		child.Env = append(os.Environ(), "ARCADECTL_WRAPPER_SCREEN_HELPER=descendant")
		child.ExtraFiles = []*os.File{os.NewFile(3, "profile-writer")}
		if child.Start() != nil {
			os.Exit(4)
		}
		os.Exit(0)
	case "descendant":
		time.Sleep(20 * time.Second)
		os.Exit(0)
	case "success":
		_, _ = os.Stdout.WriteString("controlled")
		os.Exit(0)
	case "failure":
		_, _ = os.Stderr.WriteString("private-canary")
		os.Exit(3)
	case "timeout":
		time.Sleep(20 * time.Second)
		os.Exit(0)
	}
}

func TestWrapperSignalCancelsCommandContext(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCommandHelper$")
	cmd.Env = append(os.Environ(), "ARCADECTL_WRAPPER_SCREEN_HELPER=signal-context")
	stdout, err := cmd.StdoutPipe()
	if err != nil || cmd.Start() != nil {
		t.Fatal("signal fixture unavailable")
	}
	defer stdout.Close()
	var ready [6]byte
	if _, err := io.ReadFull(stdout, ready[:]); err != nil || string(ready[:]) != "ready\n" {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatal("signal fixture not ready")
	}
	if cmd.Process.Signal(syscall.SIGTERM) != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatal("signal fixture unavailable")
	}
	if cmd.Wait() != nil {
		t.Fatal("wrapper signal did not cancel and join command")
	}
}
