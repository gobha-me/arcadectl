//go:build kindinstall

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installerprofile"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"golang.org/x/sys/unix"
)

func installerBinaryCPUAttempt(command *exec.Cmd, create func() (*installerprofile.Capture, error)) ([]byte, error, error) {
	capture, err := create()
	if err != nil || capture == nil {
		if capture != nil {
			capture.Close()
		}
		// Setup has not launched anything. Run the unchanged command exactly
		// once without profiling; diagnostic failure is never its exit status.
		return nil, ErrFixtures, command.Run()
	}
	defer capture.Close()
	return capture.Run(command)
}

// Hash only the already-built current executable in the private fixture base.
// This is diagnostic custody, not a replacement for signed installation inputs.
func installerBinaryCPUDigest(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", ErrFixtures
	}
	defer file.Close()
	var before, after unix.Stat_t
	if unix.Fstat(int(file.Fd()), &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Uid != uint32(os.Geteuid()) || before.Nlink != 1 || before.Mode&0022 != 0 || before.Size <= 0 || before.Size > 256*1024*1024 {
		return "", ErrFixtures
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(file, 256*1024*1024+1))
	if err != nil || n != before.Size || unix.Fstat(int(file.Fd()), &after) != nil {
		return "", ErrFixtures
	}
	before.Atim = after.Atim // Reading may change only the access timestamp.
	if before != after {
		return "", ErrFixtures
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

type installerBinaryCPURecord struct {
	Format                      string                       `json:"format"`
	Scope                       string                       `json:"scope"`
	SourceSHA                   string                       `json:"sourceSHA"`
	SourceDirty                 bool                         `json:"sourceDirty"`
	BinarySHA256                string                       `json:"binarySHA256"`
	Profile                     string                       `json:"profile"`
	Mode                        string                       `json:"mode"`
	Command                     string                       `json:"command"`
	CommandOutcome              string                       `json:"commandOutcome"`
	Diagnostic                  string                       `json:"diagnostic"`
	FlushTimeliness             string                       `json:"flushTimeliness"`
	Refusal                     installerprofile.CPURefusal  `json:"refusal"`
	CPU                         *installerprofile.CPUSummary `json:"cpu,omitempty"`
	RequestedCaptureNanoseconds uint64                       `json:"requestedCaptureNanoseconds,omitempty"`
	Trigger                     string                       `json:"trigger,omitempty"`
	Ordinal                     uint64                       `json:"ordinal,omitempty"`
}

func installerBinaryUsesMatrixCapture(mode, command string) bool {
	return mode == "transition" && command == "upgrade"
}

func TestInstallerBinaryMatrixNotStartedHelper(t *testing.T) {
	if os.Getenv("ARCADECTL_MATRIX_CUSTODY_HELPER") != "1" {
		return
	}
	s := installerprofile.StartInherited()
	if s == nil || !s.Stop() {
		os.Exit(90)
	}
	os.Exit(7)
}

func TestInstallerBinaryMatrixCustody(t *testing.T) { testInstallerBinaryMatrixCustody(t) }

func testInstallerBinaryMatrixCustody(t *testing.T) {
	t.Helper()
	for _, mode := range []string{"fresh", "transition", ""} {
		for _, command := range []string{"install", "enroll-baseline", "upgrade", "rollback", "uninstall", "resume", ""} {
			if installerBinaryUsesMatrixCapture(mode, command) != (mode == "transition" && command == "upgrade") {
				t.Fatal("current constructor selection expanded beyond transition upgrade")
			}
		}
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal("owned executable unavailable")
	}
	child := exec.CommandContext(t.Context(), executable, "-test.run=^TestInstallerBinaryMatrixNotStartedHelper$")
	child.Env = append(os.Environ(), "ARCADECTL_MATRIX_CUSTODY_HELPER=1")
	body, diagnostic, commandErr := installerBinaryCPUAttempt(child, installerprofile.NewFirstUpgradeMatrixCapture)
	if commandErr == nil || child.ProcessState == nil || child.ProcessState.ExitCode() != 7 || len(body) != 0 || !installerprofile.FirstUpgradeMatrixNotStarted(diagnostic) {
		t.Fatal("actual not-started child changed output/result or fabricated CPU")
	}
	status, cpu, reason := installerBinaryMatrixCPUParse(body, diagnostic, child.ProcessState, executable)
	if status != "not-started" || cpu != nil || reason != (installerprofile.CPURefusal{}) {
		t.Fatal("not-started was parsed as CPU")
	}
	killed := exec.CommandContext(t.Context(), "/bin/sh", "-c", "kill -KILL $$")
	if killed.Run() == nil || killed.ProcessState == nil || killed.ProcessState.Exited() {
		t.Fatal("owned signal fixture unavailable")
	}
	for _, diag := range []error{nil, diagnostic, ErrFixtures} {
		status, cpu, reason := installerBinaryMatrixCPUParse([]byte("PRIVATE-RAW-CANARY"), diag, killed.ProcessState, executable)
		if status != "capture-incomplete" || cpu != nil || reason != (installerprofile.CPURefusal{}) {
			t.Fatal("terminated child acquired matrix attribution")
		}
	}
	source, digest := strings.Repeat("a", 40), strings.Repeat("b", 64)
	summary := &installerprofile.CPUSummary{Samples: 1, CPUNanoseconds: 10000000, DurationNanoseconds: 31000000000,
		Buckets: []installerprofile.CPUBucket{{Category: "other", FlatNanoseconds: 10000000, CumulativeNanoseconds: 10000000}}}
	for _, diagnostic := range []string{"not-started", "capture-incomplete", "cpu-format-unavailable", "available"} {
		var cpu *installerprofile.CPUSummary
		var refusal installerprofile.CPURefusal
		if diagnostic == "available" {
			cpu = summary
		}
		if diagnostic == "cpu-format-unavailable" {
			refusal = installerprofile.CPURefusal{Stage: installerprofile.CPURefusalSchema}
		}
		body, err := installerBinaryMatrixCPURecordBytes(source, digest, installrender.Profile137, "transition", "upgrade", "exit-failure", diagnostic, false, cpu, refusal)
		var record installerBinaryCPURecord
		if err != nil || json.Unmarshal(body, &record) != nil || record.Format != "installer-child-cpu-summary-v4" || record.Scope != "same-attempt-current-child-first-upgrade-matrix-window-only" || record.Trigger != "first-current-upgrade-matrix-entry" || record.Ordinal != 1 || record.RequestedCaptureNanoseconds != 30000000000 || record.Diagnostic != diagnostic || record.FlushTimeliness != "not-certified" || strings.Contains(string(body), "PRIVATE-RAW-CANARY") {
			t.Fatal("matrix closed record lost separate scope/custody")
		}
		if cpu != nil && (record.CPU == nil || record.CPU.DurationNanoseconds != 31000000000) {
			t.Fatal("requested window clamped actual overshoot")
		}
	}
	for _, outcome := range []string{"terminated", "launch-failure"} {
		if _, err := installerBinaryMatrixCPURecordBytes(source, digest, installrender.Profile137, "transition", "upgrade", outcome, "not-started", false, nil, installerprofile.CPURefusal{}); err == nil {
			t.Fatal("unexited child acquired not-started attribution")
		}
	}
	for _, modeCommand := range [][2]string{{"fresh", "upgrade"}, {"transition", "resume"}, {"transition", "install"}} {
		if _, err := installerBinaryMatrixCPURecordBytes(source, digest, installrender.Profile137, modeCommand[0], modeCommand[1], "success", "not-started", false, nil, installerprofile.CPURefusal{}); err == nil {
			t.Fatal("wrong invocation acquired matrix record")
		}
	}
	if _, err := installerBinaryMatrixCPURecordBytes(source, digest, installrender.Profile137, "transition", "upgrade", "success", "not-started", false, summary, installerprofile.CPURefusal{}); err == nil {
		t.Fatal("not-started fabricated CPU")
	}
	for _, build := range []func(string, string, string, string, string, string, string, bool, *installerprofile.CPUSummary, installerprofile.CPURefusal) ([]byte, error){installerBinaryCPURecordBytes, installerBinaryPrefixCPURecordBytes} {
		if _, err := build(source, digest, installrender.Profile137, "transition", "upgrade", "success", "not-started", false, nil, installerprofile.CPURefusal{}); err == nil {
			t.Fatal("legacy scope reinterpreted not-started")
		}
	}
}

func installerBinaryMatrixCPUParse(body []byte, diagnosticErr error, state *os.ProcessState, executable string) (string, *installerprofile.CPUSummary, installerprofile.CPURefusal) {
	if state != nil && state.Exited() && len(body) == 0 && installerprofile.FirstUpgradeMatrixNotStarted(diagnosticErr) {
		return "not-started", nil, installerprofile.CPURefusal{}
	}
	return installerBinaryCPUParse(body, diagnosticErr, state, executable)
}

// This separately versioned record describes only the requested first matrix
// window. Actual duration may overshoot; process-wide samples neither identify
// the later failed operand nor establish whole-upgrade or matrix-exclusive cost.
func installerBinaryMatrixCPURecordBytes(source, digest, profile, mode, command, outcome, diagnostic string, dirty bool, summary *installerprofile.CPUSummary, refusal installerprofile.CPURefusal) ([]byte, error) {
	if !installerBinaryUsesMatrixCapture(mode, command) {
		return nil, ErrFixtures
	}
	baseDiagnostic := diagnostic
	if diagnostic == "not-started" {
		if summary != nil || refusal != (installerprofile.CPURefusal{}) || outcome != "success" && outcome != "exit-failure" {
			return nil, ErrFixtures
		}
		baseDiagnostic = "capture-incomplete" // Reuse custody validation, not old wire semantics.
	}
	body, err := installerBinaryCPURecordBytes(source, digest, profile, mode, command, outcome, baseDiagnostic, dirty, summary, refusal)
	if err != nil {
		return nil, err
	}
	var record installerBinaryCPURecord
	if json.Unmarshal(body, &record) != nil {
		return nil, ErrFixtures
	}
	record.Format = "installer-child-cpu-summary-v4"
	record.Scope = "same-attempt-current-child-first-upgrade-matrix-window-only"
	record.Diagnostic = diagnostic
	record.Trigger = "first-current-upgrade-matrix-entry"
	record.Ordinal = 1
	record.RequestedCaptureNanoseconds = installerprofile.FirstUpgradeMatrixRequestedNanoseconds
	return json.Marshal(record)
}

// Even a fully flushed prefix is not classified for a signal-terminated child.
// Keep process completion independent of raw profile availability and parsing.
func installerBinaryCPUParse(body []byte, diagnosticErr error, state *os.ProcessState, executable string) (string, *installerprofile.CPUSummary, installerprofile.CPURefusal) {
	if diagnosticErr != nil || state == nil || !state.Exited() {
		return "capture-incomplete", nil, installerprofile.CPURefusal{}
	}
	summary, reason, err := installerprofile.SummarizeCPUWithDiagnostic(body, executable)
	if err != nil {
		return "cpu-format-unavailable", nil, reason
	}
	return "available", &summary, reason
}

func TestInstallerBinaryPrefixTerminationDoesNotParseFinalizedBytes(t *testing.T) {
	testInstallerBinaryPrefixTermination(t)
}

func testInstallerBinaryPrefixTermination(t *testing.T) {
	command := exec.Command("/bin/sh", "-c", "kill -KILL $$")
	if command.Run() == nil || command.ProcessState == nil || command.ProcessState.Exited() {
		t.Fatal("owned signal-termination fixture unavailable")
	}
	// Intentionally invalid bytes would produce a nonzero parser refusal if the
	// parent ever parsed them; the exact same gate applies to valid prefix bytes.
	for _, body := range [][]byte{nil, []byte("private synthetic finalized prefix operand")} {
		status, summary, reason := installerBinaryCPUParse(body, nil, command.ProcessState, "/owned/installer")
		if status != "capture-incomplete" || summary != nil || reason != (installerprofile.CPURefusal{}) {
			t.Fatal("terminated child acquired prefix CPU attribution")
		}
	}
}

// The source-owned prefix protocol and parent invocation custody are distinct
// from full-command profiles. Actual sampling duration is only the validated
// CPU duration, when available; neither the requested timer nor command wall
// time substitutes for it. No whole-command CPU attribution follows.
func installerBinaryPrefixCPURecordBytes(source, digest, profile, mode, command, outcome, diagnostic string, dirty bool, summary *installerprofile.CPUSummary, refusal installerprofile.CPURefusal) ([]byte, error) {
	body, err := installerBinaryCPURecordBytes(source, digest, profile, mode, command, outcome, diagnostic, dirty, summary, refusal)
	if err != nil {
		return nil, err
	}
	var record installerBinaryCPURecord
	if json.Unmarshal(body, &record) != nil {
		return nil, ErrFixtures
	}
	record.Format = "installer-child-cpu-summary-v3"
	record.Scope = "same-attempt-current-child-prefix-only"
	record.RequestedCaptureNanoseconds = installerprofile.PrefixCaptureRequestedNanoseconds
	return json.Marshal(record)
}

func installerBinaryCPURecordBytes(source, digest, profile, mode, command, outcome, diagnostic string, dirty bool, summary *installerprofile.CPUSummary, refusal installerprofile.CPURefusal) ([]byte, error) {
	hexadecimal := func(value string, size int) bool {
		decoded, err := hex.DecodeString(value)
		return err == nil && len(decoded) == size && value == strings.ToLower(value)
	}
	if !hexadecimal(source, 20) || !hexadecimal(digest, 32) || profile != installrender.Profile135 && profile != installrender.Profile137 || mode != "fresh" && mode != "transition" {
		return nil, ErrFixtures
	}
	if !refusal.Valid() {
		return nil, ErrFixtures
	}
	switch command {
	case "install", "enroll-baseline", "upgrade", "rollback", "uninstall", "resume":
	default:
		return nil, ErrFixtures
	}
	switch outcome {
	case "success", "exit-failure", "terminated", "launch-failure":
	default:
		return nil, ErrFixtures
	}
	switch diagnostic {
	case "available":
		if summary == nil || outcome == "terminated" || outcome == "launch-failure" || refusal != (installerprofile.CPURefusal{}) {
			return nil, ErrFixtures
		}
	case "capture-incomplete":
		if summary != nil || refusal != (installerprofile.CPURefusal{}) {
			return nil, ErrFixtures
		}
	case "cpu-format-unavailable":
		if summary != nil || refusal.Stage == installerprofile.CPURefusalNone || outcome == "terminated" || outcome == "launch-failure" {
			return nil, ErrFixtures
		}
	default:
		return nil, ErrFixtures
	}
	return json.Marshal(installerBinaryCPURecord{
		Format: "installer-child-cpu-summary-v2", Scope: "same-attempt-current-child-cpu-only",
		SourceSHA: source, SourceDirty: dirty, BinarySHA256: digest, Profile: profile, Mode: mode,
		Command: command, CommandOutcome: outcome, Diagnostic: diagnostic,
		FlushTimeliness: "not-certified", Refusal: refusal, CPU: summary,
	})
}

func TestInstallerBinaryCPURecordClosedCustody(t *testing.T) {
	source, digest := strings.Repeat("a", 40), strings.Repeat("b", 64)
	for _, mode := range []string{"fresh", "transition"} {
		for _, outcome := range []string{"success", "exit-failure", "terminated", "launch-failure"} {
			body, err := installerBinaryCPURecordBytes(source, digest, installrender.Profile137, mode, "upgrade", outcome, "capture-incomplete", false, nil, installerprofile.CPURefusal{})
			if err != nil || !json.Valid(body) || !strings.Contains(string(body), `"flushTimeliness":"not-certified"`) {
				t.Fatal("closed diagnostic custody unavailable or inferred timely flush")
			}
		}
	}
	for _, scenario := range []string{"source", "digest", "profile", "mode", "command", "outcome", "diagnostic"} {
		values := []string{source, digest, installrender.Profile137, "transition", "upgrade", "exit-failure", "capture-incomplete"}
		for i, field := range []string{"source", "digest", "profile", "mode", "command", "outcome", "diagnostic"} {
			if field == scenario {
				values[i] = "PRIVATE-CANARY"
			}
		}
		if _, err := installerBinaryCPURecordBytes(values[0], values[1], values[2], values[3], values[4], values[5], values[6], false, nil, installerprofile.CPURefusal{}); err == nil {
			t.Fatal("unreviewed diagnostic custody escaped fixed fields")
		}
	}
	if _, err := installerBinaryCPURecordBytes(source, digest, installrender.Profile137, "transition", "upgrade", "exit-failure", "available", false, nil, installerprofile.CPURefusal{}); err == nil {
		t.Fatal("nil CPU record claimed available")
	}
}

func TestInstallerBinaryPrefixCPURecordDoesNotClaimWholeCommandCoverage(t *testing.T) {
	testInstallerBinaryPrefixCPURecord(t)
}

func testInstallerBinaryPrefixCPURecord(t *testing.T) {
	source, digest := strings.Repeat("a", 40), strings.Repeat("b", 64)
	summary := &installerprofile.CPUSummary{Samples: 1, CPUNanoseconds: 10000000, DurationNanoseconds: 31000000000,
		Buckets: []installerprofile.CPUBucket{{Category: "other", FlatNanoseconds: 10000000, CumulativeNanoseconds: 10000000}}}
	for _, status := range []string{"available", "capture-incomplete", "cpu-format-unavailable"} {
		var cpu *installerprofile.CPUSummary
		var refusal installerprofile.CPURefusal
		if status == "available" {
			cpu = summary
		}
		if status == "cpu-format-unavailable" {
			refusal = installerprofile.CPURefusal{Stage: installerprofile.CPURefusalWork, Bound: installerprofile.CPUBoundStackReferences}
		}
		body, err := installerBinaryPrefixCPURecordBytes(source, digest, installrender.Profile137, "transition", "upgrade", "exit-failure", status, false, cpu, refusal)
		if err != nil {
			t.Fatal("closed prefix diagnostic record refused")
		}
		var got installerBinaryCPURecord
		if json.Unmarshal(body, &got) != nil || got.Format != "installer-child-cpu-summary-v3" || got.Scope != "same-attempt-current-child-prefix-only" || got.RequestedCaptureNanoseconds != 30000000000 || got.FlushTimeliness != "not-certified" {
			t.Fatal("prefix record misstated coverage, duration or flush custody")
		}
		if cpu != nil && (got.CPU == nil || got.CPU.DurationNanoseconds != 31000000000) {
			t.Fatal("requested timer replaced actual overshooting profile duration")
		}
	}
	if _, err := installerBinaryPrefixCPURecordBytes(source, digest, installrender.Profile137, "fresh", "install", "terminated", "available", false, summary, installerprofile.CPURefusal{}); err == nil {
		t.Fatal("terminated command became a certified whole selected result")
	}
}

func TestInstallerBinaryCPURefusalRecordVersionAndClosedDomain(t *testing.T) {
	source, digest := strings.Repeat("a", 40), strings.Repeat("b", 64)
	summary := &installerprofile.CPUSummary{Samples: 1, CPUNanoseconds: 10000000, DurationNanoseconds: 1,
		Buckets: []installerprofile.CPUBucket{{Category: "other", FlatNanoseconds: 10000000, CumulativeNanoseconds: 10000000}}}
	body, err := installerBinaryCPURecordBytes(source, digest, installrender.Profile137, "fresh", "install", "success", "available", false, summary, installerprofile.CPURefusal{})
	if err != nil || !strings.Contains(string(body), `"refusal":{"stage":0,"bound":0},"cpu":`) {
		t.Fatal("available v2 zero-refusal summary unavailable")
	}
	classified := installerprofile.CPURefusal{Stage: installerprofile.CPURefusalSchema}
	if _, err := installerBinaryCPURecordBytes(source, digest, installrender.Profile137, "fresh", "install", "success", "available", false, summary, classified); err == nil {
		t.Fatal("available summary acquired a parser refusal")
	}
	for _, outcome := range []string{"terminated", "launch-failure"} {
		if _, err := installerBinaryCPURecordBytes(source, digest, installrender.Profile137, "transition", "upgrade", outcome, "cpu-format-unavailable", false, nil, classified); err == nil {
			t.Fatal("non-exited attempt claimed parser result")
		}
	}
	for _, reason := range []installerprofile.CPURefusal{
		{}, {Stage: 8}, {Bound: 1}, {Stage: installerprofile.CPURefusalWork},
		{Stage: installerprofile.CPURefusalWork, Bound: 8}, {Stage: installerprofile.CPURefusalSchema, Bound: 1},
	} {
		if _, err := installerBinaryCPURecordBytes(source, digest, installrender.Profile137, "transition", "upgrade", "exit-failure", "cpu-format-unavailable", false, nil, reason); err == nil {
			t.Fatal("unclassified or unreviewed numeric refusal accepted")
		}
	}
	for stage := installerprofile.CPURefusalEnvelope; stage <= installerprofile.CPURefusalAccounting; stage++ {
		reason := installerprofile.CPURefusal{Stage: stage}
		if stage == installerprofile.CPURefusalWork {
			reason.Bound = installerprofile.CPUBoundExpandedWork
		}
		body, err := installerBinaryCPURecordBytes(source, digest, installrender.Profile137, "transition", "upgrade", "exit-failure", "cpu-format-unavailable", false, nil, reason)
		if err != nil || !strings.Contains(string(body), `"format":"installer-child-cpu-summary-v2"`) || strings.Contains(string(body), `"cpu":`) || !strings.Contains(string(body), `"refusal":{`) {
			t.Fatal("versioned fixed refusal record unavailable or exposed CPU fallback")
		}
		if _, err := installerBinaryCPURecordBytes(source, digest, installrender.Profile137, "fresh", "install", "success", "capture-incomplete", false, nil, reason); err == nil {
			t.Fatal("capture failure invented a parser refusal")
		}
	}
}

func TestInstallerBinaryCPUSetupFailureRunsUnchangedCommandOnce(t *testing.T) {
	command := exec.Command("/bin/sh", "-c", "printf 'unchanged-output'; printf 'unchanged-error' >&2; exit 7")
	var stdout, stderr strings.Builder
	command.Stdout, command.Stderr = &stdout, &stderr
	setups := 0
	body, diag, err := installerBinaryCPUAttempt(command, func() (*installerprofile.Capture, error) { setups++; return nil, ErrFixtures })
	if setups != 1 || len(body) != 0 || diag == nil || err == nil || command.ProcessState == nil || command.ProcessState.ExitCode() != 7 || stdout.String() != "unchanged-output" || stderr.String() != "unchanged-error" || len(command.ExtraFiles) != 0 {
		t.Fatal("profile setup failure changed command output/status or requested replay")
	}
}
