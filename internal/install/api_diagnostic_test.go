// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package install

import (
	"strconv"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
)

// Preserve the closed native stage type and the richer Kind diagnostic's
// existing labels. Configure/update labels intentionally differ; never pass
// the enum's String through a mismatched string whitelist.
func kindRuntimeDiagnosticStage(stage nativeRuntimeStage) string {
	switch stage {
	case nativeRuntimeInitialStart:
		return "initial-start"
	case nativeRuntimeConfigure:
		return "configured-start"
	case nativeRuntimeRestart:
		return "restart"
	case nativeRuntimeImageUpdate:
		return "update"
	case nativeRuntimeCLIStart:
		return "cli-start"
	default:
		return "unknown"
	}
}

func TestKindRuntimeDiagnosticStageRetainsClosedNativeMapping(t *testing.T) {
	for stage := 0; stage < 256; stage++ {
		want := "unknown"
		switch nativeRuntimeStage(stage) {
		case nativeRuntimeInitialStart:
			want = "initial-start"
		case nativeRuntimeConfigure:
			want = "configured-start"
		case nativeRuntimeRestart:
			want = "restart"
		case nativeRuntimeImageUpdate:
			want = "update"
		case nativeRuntimeCLIStart:
			want = "cli-start"
		}
		if got := kindRuntimeDiagnosticStage(nativeRuntimeStage(stage)); got != want {
			t.Fatal("native stage lost its closed Kind diagnostic mapping")
		}
	}
}

// Fixed public fields only: native reason/message/container IDs and logs may
// contain arbitrary runtime bytes. Never print a raw ContainerStatus or Pod.
// Keep this pure helper and its regression in ordinary CI, not only Kind builds.
func kindRuntimeTerminationDiagnostic(stage string, status corev1.ContainerStatus) string {
	switch stage {
	case "initial-start", "configured-start", "restart", "update", "cli-start":
	default:
		stage = "unknown"
	}
	termination := func(state corev1.ContainerState) string {
		if state.Terminated == nil {
			return "none"
		}
		term := state.Terminated
		reason := "other"
		switch term.Reason {
		case "OOMKilled", "Error", "Completed", "ContainerCannotRun", "StartError":
			reason = term.Reason
		}
		return "reason=" + reason + " exit=" + strconv.Itoa(int(term.ExitCode)) + " signal=" + strconv.Itoa(int(term.Signal)) + " started=" + term.StartedAt.UTC().Format(time.RFC3339Nano) + " finished=" + term.FinishedAt.UTC().Format(time.RFC3339Nano)
	}
	return "stage=" + stage + " restarts=" + strconv.Itoa(int(status.RestartCount)) + " current=[" + termination(status.State) + "] previous=[" + termination(status.LastTerminationState) + "]"
}

func TestKindRuntimeTerminationDiagnosticIsBoundedAndPublic(t *testing.T) {
	const canary = "PRIVATE-RUNTIME-CANARY"
	for _, reason := range []string{"OOMKilled", "Error", "Completed", "ContainerCannotRun", "StartError", canary + strings.Repeat("x", 10000)} {
		state := corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: reason, Message: canary, ContainerID: canary, ExitCode: 137, Signal: 9}}
		status := corev1.ContainerStatus{Name: canary, ContainerID: canary, Image: canary, ImageID: canary, RestartCount: 1, State: state, LastTerminationState: state}
		result := kindRuntimeTerminationDiagnostic("initial-start", status)
		if strings.Contains(result, canary) || len(result) > 400 || !strings.Contains(result, "restarts=1") || !strings.Contains(result, "exit=137 signal=9") || !strings.Contains(result, "stage=initial-start") {
			t.Fatal("diagnostic leaked private/unbounded data or omitted termination fields")
		}
		if reason == "OOMKilled" && !strings.Contains(result, "reason=OOMKilled") {
			t.Fatal("native OOM reason lost")
		}
	}
	if result := kindRuntimeTerminationDiagnostic(canary, corev1.ContainerStatus{}); result != "stage=unknown restarts=0 current=[none] previous=[none]" {
		t.Fatal("arbitrary stage escaped closed diagnostic")
	}
}
