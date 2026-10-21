//go:build kindinstall

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installerprofile"
	"github.com/gobha-me/arcadectl/internal/installrender"
)

// Separate wire type: new labels never pass through the legacy serializer.
type installerBinaryMatrixV5CPURecord struct {
	Format                      string                             `json:"format"`
	Scope                       string                             `json:"scope"`
	Classification              string                             `json:"classification"`
	SourceSHA                   string                             `json:"sourceSHA"`
	SourceDirty                 bool                               `json:"sourceDirty"`
	BinarySHA256                string                             `json:"binarySHA256"`
	Profile                     string                             `json:"profile"`
	Mode                        string                             `json:"mode"`
	Command                     string                             `json:"command"`
	CommandOutcome              string                             `json:"commandOutcome"`
	Diagnostic                  string                             `json:"diagnostic"`
	FlushTimeliness             string                             `json:"flushTimeliness"`
	Refusal                     installerprofile.CPURefusal        `json:"refusal"`
	CPU                         *installerprofile.MatrixCPUSummary `json:"cpu,omitempty"`
	RequestedCaptureNanoseconds uint64                             `json:"requestedCaptureNanoseconds"`
	Trigger                     string                             `json:"trigger"`
	Ordinal                     uint64                             `json:"ordinal"`
}

func installerBinaryMatrixV5CPUParse(body []byte, diagnosticErr error, state *os.ProcessState, executable string) (string, *installerprofile.MatrixCPUSummary, installerprofile.CPURefusal) {
	if state != nil && state.Exited() && len(body) == 0 && installerprofile.FirstUpgradeMatrixNotStarted(diagnosticErr) {
		return "not-started", nil, installerprofile.CPURefusal{}
	}
	if diagnosticErr != nil || state == nil || !state.Exited() {
		return "capture-incomplete", nil, installerprofile.CPURefusal{}
	}
	summary, reason, err := installerprofile.SummarizeCPUMatrixWithDiagnostic(body, executable)
	if err != nil {
		return "cpu-format-unavailable", nil, reason
	}
	return "available", &summary, reason
}

func installerBinaryMatrixV5CPURecordBytes(source, digest, profile, mode, command, outcome, diagnostic string, dirty bool, summary *installerprofile.MatrixCPUSummary, refusal installerprofile.CPURefusal) ([]byte, error) {
	if !installerBinaryUsesMatrixCapture(mode, command) {
		return nil, ErrFixtures
	}
	validationDiagnostic := diagnostic
	if diagnostic == "not-started" {
		if summary != nil || refusal != (installerprofile.CPURefusal{}) || outcome != "success" && outcome != "exit-failure" {
			return nil, ErrFixtures
		}
		validationDiagnostic = "capture-incomplete"
	}
	if err := validateInstallerBinaryCPURecord(source, digest, profile, mode, command, outcome, validationDiagnostic, dirty, summary != nil, refusal); err != nil {
		return nil, err
	}
	return json.Marshal(installerBinaryMatrixV5CPURecord{
		Format: "installer-child-cpu-summary-v5", Scope: "same-attempt-current-child-first-upgrade-matrix-window-only",
		Classification: installerprofile.MatrixCPUClassification,
		SourceSHA:      source, SourceDirty: dirty, BinarySHA256: digest, Profile: profile, Mode: mode,
		Command: command, CommandOutcome: outcome, Diagnostic: diagnostic, FlushTimeliness: "not-certified",
		Refusal: refusal, CPU: summary, RequestedCaptureNanoseconds: installerprofile.FirstUpgradeMatrixRequestedNanoseconds,
		Trigger: "first-current-upgrade-matrix-entry", Ordinal: 1,
	})
}

// Independent tiny producer used only for a parser-wiring control. It is not
// claimed to be an actual child profile or native performance measurement.
func matrixHarnessCPUFixture(t *testing.T, executable string) []byte {
	t.Helper()
	scalar := func(n int, v uint64) []byte { return binary.AppendUvarint(binary.AppendUvarint(nil, uint64(n<<3)), v) }
	data := func(n int, b []byte) []byte {
		return append(binary.AppendUvarint(binary.AppendUvarint(nil, uint64(n<<3|2)), uint64(len(b))), b...)
	}
	record := func(values ...uint64) []byte {
		var b []byte
		for i, v := range values {
			if v != 0 {
				b = append(b, scalar(i+1, v)...)
			}
		}
		return b
	}
	var wire []byte
	for _, v := range [][]byte{record(1, 2), record(3, 4)} {
		wire = append(wire, data(1, v)...)
	}
	refs := append(scalar(1, 1), scalar(1, 2)...)
	refs = append(refs, scalar(1, 1)...)
	values := append(scalar(2, 2), scalar(2, 20000000)...)
	wire = append(wire, data(2, append(refs, values...))...)
	wire = append(wire, data(3, record(1, 4096, 8192, 0, 5, 0, 1))...)
	for id := uint64(1); id <= 2; id++ {
		location := append(record(id, 1, 4096+id), data(4, record(id, 10))...)
		wire = append(wire, data(4, location)...)
	}
	for id := uint64(1); id <= 2; id++ {
		wire = append(wire, data(5, record(id, 5+id, 5+id, 8, 10))...)
	}
	for _, s := range []string{"", "samples", "count", "cpu", "nanoseconds", executable, "reflect.deepValueEqual", "crypto/sha256.Sum256", "/private/FILE-CANARY.go"} {
		wire = append(wire, data(6, []byte(s))...)
	}
	wire = append(wire, scalar(9, 1)...)
	wire = append(wire, scalar(10, 1)...)
	wire = append(wire, data(11, record(3, 4))...)
	wire = append(wire, scalar(12, 10000000)...)
	var compressed bytes.Buffer
	w := gzip.NewWriter(&compressed)
	if _, err := w.Write(wire); err != nil || w.Close() != nil {
		t.Fatal("owned numeric fixture unavailable")
	}
	return compressed.Bytes()
}

func TestInstallerBinaryMatrixV5ClosedVocabulary(t *testing.T) { testInstallerBinaryMatrixV5Custody(t) }

func testInstallerBinaryMatrixV5Custody(t *testing.T) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal("owned executable unavailable")
	}
	child := exec.CommandContext(t.Context(), executable, "-test.run=^TestInstallerBinaryMatrixNotStartedHelper$")
	child.Env = append(os.Environ(), "ARCADECTL_MATRIX_CUSTODY_HELPER=1")
	body, diagnostic, commandErr := installerBinaryCPUAttempt(child, installerprofile.NewFirstUpgradeMatrixCapture)
	status, cpu, reason := installerBinaryMatrixV5CPUParse(body, diagnostic, child.ProcessState, executable)
	if commandErr == nil || child.ProcessState == nil || child.ProcessState.ExitCode() != 7 || status != "not-started" || cpu != nil || reason != (installerprofile.CPURefusal{}) {
		t.Fatal("v5 fabricated not-started attribution")
	}
	status, cpu, reason = installerBinaryMatrixV5CPUParse(matrixHarnessCPUFixture(t, executable), nil, child.ProcessState, executable)
	if status != "available" || cpu == nil || len(cpu.Buckets) != 2 || cpu.Buckets[0] != (installerprofile.CPUBucket{Category: "hash", CumulativeNanoseconds: 20000000}) || cpu.Buckets[1] != (installerprofile.CPUBucket{Category: "reflect", FlatNanoseconds: 20000000, CumulativeNanoseconds: 20000000}) || reason != (installerprofile.CPURefusal{}) {
		t.Fatal("v5 parser used legacy classification or changed stack accounting")
	}
	status, cpu, reason = installerBinaryMatrixV5CPUParse([]byte("PRIVATE-RAW-CANARY"), nil, child.ProcessState, executable)
	if status != "cpu-format-unavailable" || cpu != nil || reason.Stage != installerprofile.CPURefusalEnvelope {
		t.Fatal("v5 parser lost closed refusal")
	}
	killed := exec.CommandContext(t.Context(), "/bin/sh", "-c", "kill -KILL $$")
	if killed.Run() == nil || killed.ProcessState == nil || killed.ProcessState.Exited() {
		t.Fatal("owned signal fixture unavailable")
	}
	for _, diag := range []error{nil, diagnostic, ErrFixtures} {
		status, cpu, reason = installerBinaryMatrixV5CPUParse([]byte("PRIVATE-RAW-CANARY"), diag, killed.ProcessState, executable)
		if status != "capture-incomplete" || cpu != nil || reason != (installerprofile.CPURefusal{}) {
			t.Fatal("v5 attributed a terminated child")
		}
	}
	names := []string{"apimachinery", "client-go", "hash", "http", "installengine", "io-syscall", "json", "other", "package-state", "proof-contract", "proof-observe", "reflect", "runtime", "runtime-gc", "tls", "unresolved"}
	summary := &installerprofile.MatrixCPUSummary{Samples: 16, CPUNanoseconds: 160000000, DurationNanoseconds: 31000000000}
	for _, name := range names {
		summary.Buckets = append(summary.Buckets, installerprofile.CPUBucket{Category: name, FlatNanoseconds: 10000000, CumulativeNanoseconds: 10000000})
	}
	source, digest := strings.Repeat("a", 40), strings.Repeat("b", 64)
	for _, diagnostic := range []string{"available", "not-started", "capture-incomplete", "cpu-format-unavailable"} {
		var cpu *installerprofile.MatrixCPUSummary
		var reason installerprofile.CPURefusal
		if diagnostic == "available" {
			cpu = summary
		}
		if diagnostic == "cpu-format-unavailable" {
			reason.Stage = installerprofile.CPURefusalSchema
		}
		body, err := installerBinaryMatrixV5CPURecordBytes(source, digest, installrender.Profile137, "transition", "upgrade", "exit-failure", diagnostic, false, cpu, reason)
		var record installerBinaryMatrixV5CPURecord
		if err != nil || json.Unmarshal(body, &record) != nil || record.Format != "installer-child-cpu-summary-v5" || record.Classification != installerprofile.MatrixCPUClassification || record.Scope != "same-attempt-current-child-first-upgrade-matrix-window-only" || record.Trigger != "first-current-upgrade-matrix-entry" || record.Ordinal != 1 || record.RequestedCaptureNanoseconds != 30000000000 || record.Diagnostic != diagnostic || record.FlushTimeliness != "not-certified" || bytes.Contains(body, []byte("CANARY")) {
			t.Fatal("v5 lost explicit vocabulary or interval/outcome custody")
		}
		if cpu != nil && (record.CPU == nil || len(record.CPU.Buckets) != 16 || record.CPU.DurationNanoseconds != 31000000000) {
			t.Fatal("v5 changed numeric data or clamped overshoot")
		}
	}
	for _, modeCommand := range [][2]string{{"fresh", "upgrade"}, {"transition", "resume"}, {"transition", "install"}} {
		if _, err := installerBinaryMatrixV5CPURecordBytes(source, digest, installrender.Profile137, modeCommand[0], modeCommand[1], "success", "not-started", false, nil, installerprofile.CPURefusal{}); err == nil {
			t.Fatal("v5 expanded independently fixed invocation context")
		}
	}
	for _, outcome := range []string{"terminated", "launch-failure"} {
		for _, diagnostic := range []string{"available", "not-started", "cpu-format-unavailable"} {
			var cpu *installerprofile.MatrixCPUSummary
			var reason installerprofile.CPURefusal
			if diagnostic == "available" {
				cpu = summary
			}
			if diagnostic == "cpu-format-unavailable" {
				reason.Stage = installerprofile.CPURefusalSchema
			}
			if _, err := installerBinaryMatrixV5CPURecordBytes(source, digest, installrender.Profile137, "transition", "upgrade", outcome, diagnostic, false, cpu, reason); err == nil {
				t.Fatal("v5 attributed an unexited process")
			}
		}
	}
	if _, err := installerBinaryMatrixV5CPURecordBytes(source, digest, installrender.Profile137, "transition", "upgrade", "success", "not-started", false, summary, installerprofile.CPURefusal{}); err == nil {
		t.Fatal("v5 not-started fabricated CPU")
	}
	bad := *summary
	bad.Buckets = append([]installerprofile.CPUBucket{}, summary.Buckets...)
	bad.Buckets[0].Category = "PRIVATE-CANARY"
	if body, err := installerBinaryMatrixV5CPURecordBytes(source, digest, installrender.Profile137, "transition", "upgrade", "success", "available", false, &bad, installerprofile.CPURefusal{}); err == nil || len(body) != 0 {
		t.Fatal("v5 serializer leaked unreviewed category")
	}
	legacy := installerprofile.CPUSummary(*summary)
	if _, err := installerBinaryPrefixCPURecordBytes(source, digest, installrender.Profile137, "fresh", "install", "success", "available", false, &legacy, installerprofile.CPURefusal{}); err == nil {
		t.Fatal("v5 vocabulary widened prefix protocol")
	}
}
