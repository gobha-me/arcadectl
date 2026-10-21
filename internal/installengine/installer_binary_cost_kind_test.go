//go:build kindinstall

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"reflect"
	"strings"
	"testing"
)

// Pure controls also run inside each selected native fixture; no cluster or
// installer invocation is needed to exercise the live-output boundary.
func testInstallerBinaryCostCapture(t *testing.T) {
	t.Helper()
	labels := []string{"admission", "phase", "baseline", "admission-construction", "admission-setup", "admission-matrix", "admission-drain", "admission-retirement", "admission-final", "sdk-wait"}
	if !reflect.DeepEqual(lifecycleCostLabels[:], labels) {
		t.Fatal("numeric output schema changed without updating the strict harness contract")
	}
	var empty *LifecycleCosts
	step := "installation diagnostic step-cost " + empty.Snapshot()
	final := "installation diagnostic command-cost " + empty.Snapshot()
	var maxCosts LifecycleCosts
	for index := range maxCosts.metrics {
		maxCosts.metrics[index].calls.Store(^uint64(0))
		maxCosts.metrics[index].returned.Store(^uint64(0))
		maxCosts.metrics[index].wallNS.Store(^uint64(0))
	}
	maxStep := "installation diagnostic step-cost " + maxCosts.Snapshot()
	maxFinal := "installation diagnostic command-cost " + maxCosts.Snapshot()
	for _, line := range []string{step, final, maxStep, maxFinal} {
		parsed, ok := installerBinaryCostLine(line)
		if !ok || parsed.final != strings.HasPrefix(line, "installation diagnostic command-cost ") {
			t.Fatal("canonical numeric cost line refused")
		}
		if strings.Contains(line, "18446744073709551615") {
			for _, n := range parsed.values {
				if n != ^uint64(0) {
					t.Fatal("cost parser lost unsigned 64-bit precision")
				}
			}
		}
		for split := 0; split <= len(line); split++ {
			var logs []string
			capture := &installerBinaryProgressCapture{log: func(s string) { logs = append(logs, s) }}
			_, _ = capture.Write([]byte(line[:split]))
			_, _ = capture.Write([]byte(line[split:]))
			if len(logs) != 0 {
				t.Fatal("numeric cost suffix flushed without newline")
			}
			_, _ = capture.Write([]byte{'\n'})
			if len(logs) != 1 || logs[0] != line || string(capture.output()) != line+"\n" {
				t.Fatal("fragmented numeric cost or original capture changed")
			}
		}
	}
	fields := strings.Split(empty.Snapshot(), " ")
	reordered := append([]string(nil), fields...)
	reordered[0], reordered[1] = reordered[1], reordered[0]
	duplicate := append([]string(nil), fields...)
	duplicate[1] = duplicate[0]
	bad := []string{
		"PRIVATE-CANARY", " " + step, step + " PRIVATE-CANARY", step + "\r", step + "\x00", step + "\x1b[0m",
		strings.Replace(step, "admission-calls", "PRIVATE-CANARY", 1),
		strings.Replace(step, "=0", "=", 1), strings.Replace(step, "=0", "=01", 1),
		strings.Replace(step, "=0", "=+1", 1), strings.Replace(step, "=0", "=-1", 1),
		strings.Replace(step, "=0", "=1.0", 1), strings.Replace(step, "=0", "=18446744073709551616", 1),
		strings.Replace(step, "=0", "=PRIVATE-CANARY", 1),
		strings.Replace(step, " admission-returned", "  admission-returned", 1),
		strings.Replace(step, " admission-returned", "\tadmission-returned", 1),
		"installation diagnostic step-cost " + strings.Join(reordered, " "),
		"installation diagnostic step-cost " + strings.Join(duplicate, " "),
		"installation diagnostic step-cost " + strings.Join(fields[1:], " "),
		strings.Repeat("x", 2049) + step,
	}
	for _, line := range bad {
		if _, ok := installerBinaryCostLine(line); ok {
			t.Fatal("unsafe numeric cost line accepted")
		}
	}
	stage := "installation stage applying revision 1"
	var logs []string
	capture := &installerBinaryProgressCapture{log: func(s string) { logs = append(logs, s) }}
	wire := strings.Join(bad, "\n") + "\n" + step + "\n" + stage + "\n" + final
	for _, b := range []byte(wire) {
		if n, err := capture.Write([]byte{b}); n != 1 || err != nil {
			t.Fatal("cost capture changed writer semantics")
		}
	}
	if !reflect.DeepEqual(logs, []string{step, stage}) || string(capture.output()) != wire {
		t.Fatal("unsafe/oversized/unterminated cost escaped or original output changed")
	}
	for _, costFirst := range []bool{false, true} {
		logs = nil
		capture = &installerBinaryProgressCapture{log: func(s string) { logs = append(logs, s) }}
		stages, costs := strings.Repeat(stage+"\n", 513), strings.Repeat(step+"\n", 514)
		wire = stages + costs
		if costFirst {
			wire = costs + stages
		}
		_, _ = capture.Write([]byte(wire))
		if len(logs) != 1025 || capture.emitted != 512 || capture.costEmitted != 513 || string(capture.output()) != wire {
			t.Fatal("cost forwarding consumed stage allowance or altered complete output")
		}
	}
	for _, test := range []struct {
		name string
		wire string
		max  int
		want bool
	}{
		{"one-step", stage + "\n" + step + "\n" + final + "\n", 1, true},
		{"cumulative", stage + "\n" + step + "\n" + stage + "\n" + maxStep + "\n" + maxFinal + "\n", 2, true},
		{"cross-stream-order", step + "\n" + final + "\n" + stage + "\n", 1, true},
		{"full-step-bound", strings.Repeat(stage+"\n"+step+"\n", 512) + final + "\n", 512, true},
		{"enrollment-bound", strings.Repeat("security baseline stage applying revision 1\n"+step+"\n", 32) + final + "\n", 32, true},
		{"missing-middle-step", strings.Repeat(stage+"\n", 10) + step + "\n" + final + "\n", 512, false},
		{"costs-without-stage", step + "\n" + final + "\n", 512, false},
		{"no-costs", stage + "\n", 512, false},
		{"no-step", stage + "\n" + final + "\n", 512, false},
		{"missing-final", stage + "\n" + step + "\n", 512, false},
		{"duplicate-final", stage + "\n" + step + "\n" + final + "\n" + final + "\n", 512, false},
		{"step-after-final", stage + "\n" + step + "\n" + final + "\n" + step + "\n", 512, false},
		{"changed-final", stage + "\n" + step + "\n" + maxFinal + "\n", 512, false},
		{"regression", stage + "\n" + maxStep + "\n" + stage + "\n" + step + "\n" + final + "\n", 512, false},
		{"unterminated-final", stage + "\n" + step + "\n" + final, 512, false},
		{"unterminated-stage", step + "\n" + final + "\n" + stage, 512, false},
		{"over-step-bound", strings.Repeat(stage+"\n"+step+"\n", 513) + final + "\n", 512, false},
		{"over-enrollment-bound", strings.Repeat(stage+"\n"+step+"\n", 33) + final + "\n", 32, false},
		{"malformed-step", stage + "\n" + bad[0] + "\n" + strings.Replace(step, "=0", "=01", 1) + "\n" + final + "\n", 512, false},
	} {
		if installerBinaryCompletedCosts([]byte(test.wire), test.max) != test.want {
			t.Fatalf("cost-series validation failed closed contract: %s", test.name)
		}
	}
}
