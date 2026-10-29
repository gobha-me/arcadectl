// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package install

import (
	"context"
	"strings"
	"testing"
	"time"
)

func nativeCLIOperationDiagnostic(phase string, generation, observedGeneration int64, completed bool) string {
	switch phase {
	case "Pending", "Running", "AwaitingConfirmation", "Succeeded", "Failed", "Cancelled":
	default:
		phase = "unknown"
	}
	current := generation >= 1 && observedGeneration == generation
	return "phase=" + phase + " current=" + map[bool]string{true: "true", false: "false"}[current] + " completed=" + map[bool]string{true: "true", false: "false"}[completed]
}

func TestNativeCLICompletionDiagnosticWithholdsPrivateCapture(t *testing.T) {
	const canary = "PRIVATE-CLI-CANARY"
	for _, test := range []struct {
		name, body, code string
		truncated        bool
	}{
		{"timeout", `{"version":"v1","code":"timeout","operationID":"PRIVATE-CLI-CANARY","attemptID":"PRIVATE-CLI-CANARY","suggestedAction":"PRIVATE-CLI-CANARY"}`, "timeout", false},
		{"transport", `{"version":"v1","code":"transport_or_protocol","reason":"PRIVATE-CLI-CANARY"}`, "transport_or_protocol", false},
		{"arbitrary", `{"version":"v1","code":"PRIVATE-CLI-CANARY","reason":"PRIVATE-CLI-CANARY"}`, "unknown", false},
		{"malformed", canary, "unknown", false},
		{"wrong-version", `{"version":"PRIVATE-CLI-CANARY","code":"timeout"}`, "unknown", false},
		{"truncated", `{"version":"v1","code":"timeout"}`, "unknown", true},
		{"oversize", strings.Repeat(canary, 5000), "unknown", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := nativeCLICompletionDiagnostic(t.Context(), 123*time.Millisecond, 5, []byte(test.body), false, test.truncated)
			if strings.Contains(got, canary) || len(got) > 350 || !strings.Contains(got, "exit=5 elapsed-ms=123") || !strings.Contains(got, " code="+test.code+" ") {
				t.Fatal("completion diagnostic lost finite classification or exposed private capture")
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got := nativeCLICompletionDiagnostic(ctx, -time.Second, 9999, nil, true, true); !strings.Contains(got, "exit=-1 elapsed-ms=0 deadline=false canceled=true") {
		t.Fatal("context/invalid process state was not classified safely")
	}
	ctx, cancel = context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancel()
	if got := nativeCLICompletionDiagnostic(ctx, 100*time.Hour, -1, nil, false, false); !strings.Contains(got, "elapsed-ms=172800000 deadline=true canceled=false") {
		t.Fatal("deadline or elapsed bound missing")
	}
}

func TestNativeCLIPostExitOperationDiagnosticIsClosed(t *testing.T) {
	for _, phase := range []string{"Pending", "Running", "AwaitingConfirmation", "Succeeded", "Failed", "Cancelled", "PRIVATE-CLI-CANARY"} {
		got := nativeCLIOperationDiagnostic(phase, 2, 2, true)
		if strings.Contains(got, "CANARY") || !strings.HasSuffix(got, "current=true completed=true") || len(got) > 80 {
			t.Fatal("post-exit observation escaped its closed fields")
		}
	}
	if got := nativeCLIOperationDiagnostic("Succeeded", 2, 1, true); got != "phase=Succeeded current=false completed=true" {
		t.Fatal("stale observed generation was called current")
	}
}
