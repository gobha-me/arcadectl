// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package install

import (
	"fmt"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
)

type nativeRuntimeStage uint8

const (
	nativeRuntimeInitialStart nativeRuntimeStage = iota + 1
	nativeRuntimeConfigure
	nativeRuntimeRestart
	nativeRuntimeImageUpdate
	nativeRuntimeCLIStart
)

func (stage nativeRuntimeStage) String() string {
	switch stage {
	case nativeRuntimeInitialStart:
		return "initial-start"
	case nativeRuntimeConfigure:
		return "configure"
	case nativeRuntimeRestart:
		return "restart"
	case nativeRuntimeImageUpdate:
		return "image-update"
	case nativeRuntimeCLIStart:
		return "cli-start"
	default:
		return "unavailable"
	}
}

// Diagnostic only: the restart/OOM refusal is unchanged. Only fixed enum
// labels and typed numeric counters cross the private-output boundary; never
// emit Reason verbatim, Message, container identity, image, or private logs.
func nativeRuntimeDiagnostic(stage nativeRuntimeStage, status corev1.ContainerStatus) string {
	reason := "none"
	var code, signal int32
	if previous := status.LastTerminationState.Terminated; previous != nil {
		code, signal = previous.ExitCode, previous.Signal
		switch previous.Reason {
		case "OOMKilled":
			reason = "oom-killed"
		case "Error":
			reason = "error"
		case "Completed":
			reason = "completed"
		case "ContainerCannotRun":
			reason = "cannot-run"
		case "StartError":
			reason = "start-error"
		case "DeadlineExceeded":
			reason = "deadline-exceeded"
		default:
			reason = "other"
		}
	}
	return fmt.Sprintf("fixed stage=%s restarts=%d previous=%s exitCode=%d signal=%d", stage, status.RestartCount, reason, code, signal)
}

func TestNativeRuntimeDiagnosticIsClosedAndCredentialFree(t *testing.T) {
	for i := 0; i < 256; i++ {
		stage := nativeRuntimeStage(i)
		want := "unavailable"
		switch stage {
		case nativeRuntimeInitialStart:
			want = "initial-start"
		case nativeRuntimeConfigure:
			want = "configure"
		case nativeRuntimeRestart:
			want = "restart"
		case nativeRuntimeImageUpdate:
			want = "image-update"
		case nativeRuntimeCLIStart:
			want = "cli-start"
		}
		if stage.String() != want {
			t.Fatal("runtime stage escaped its closed vocabulary")
		}
	}
	for _, fixture := range []struct{ input, output string }{
		{"OOMKilled", "oom-killed"}, {"Error", "error"}, {"Completed", "completed"},
		{"ContainerCannotRun", "cannot-run"}, {"StartError", "start-error"},
		{"DeadlineExceeded", "deadline-exceeded"}, {"PRIVATE-CANARY", "other"}, {"", "other"},
	} {
		status := corev1.ContainerStatus{Name: "PRIVATE-CANARY", Image: "PRIVATE-CANARY", ImageID: "PRIVATE-CANARY", ContainerID: "PRIVATE-CANARY", RestartCount: 2,
			LastTerminationState: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: fixture.input, Message: "PRIVATE-CANARY", ContainerID: "PRIVATE-CANARY", ExitCode: 137, Signal: 9}}}
		want := "fixed stage=image-update restarts=2 previous=" + fixture.output + " exitCode=137 signal=9"
		got := nativeRuntimeDiagnostic(nativeRuntimeImageUpdate, status)
		if got != want || strings.Contains(got, "PRIVATE-CANARY") {
			t.Fatal("runtime diagnostic disclosed private data or lost bounded counters")
		}
	}
	if nativeRuntimeDiagnostic(255, corev1.ContainerStatus{}) != "fixed stage=unavailable restarts=0 previous=none exitCode=0 signal=0" {
		t.Fatal("missing termination state or unknown stage acquired raw diagnostics")
	}
}
