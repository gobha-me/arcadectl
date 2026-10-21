//go:build kindinstall

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Observations are independent facts, not a claim that a deadline caused a
// signal. In particular, after-attempt includes capture drain, not just Wait.
// Neither the context, command nor provider error can contribute free text.
func installerBinaryParentContext(ctx context.Context, now time.Time, command, phase string, state *os.ProcessState, commandErr error) string {
	record := struct {
		Format               string `json:"format"`
		Scope                string `json:"scope"`
		Command              string `json:"command"`
		Phase                string `json:"phase"`
		ParentState          string `json:"parentState"`
		DeadlinePresent      bool   `json:"deadlinePresent"`
		RemainingNanoseconds int64  `json:"remainingNanoseconds"`
		Process              string `json:"process"`
		ExitCode             int    `json:"exitCode"`
		Signal               string `json:"signal"`
	}{
		Format: "installer-parent-context-v1", Scope: "observation-not-termination-cause",
		Command: "unavailable", Phase: "unavailable", ParentState: "unavailable",
		Process: "not-started", ExitCode: -1, Signal: "none",
	}
	switch command {
	case "install", "enroll-baseline", "upgrade", "rollback", "uninstall":
		record.Command = command
	}
	switch phase {
	case "before-attempt", "after-attempt":
		record.Phase = phase
	}
	if ctx != nil {
		switch ctx.Err() {
		case nil:
			record.ParentState = "active"
		case context.Canceled:
			record.ParentState = "canceled"
		case context.DeadlineExceeded:
			record.ParentState = "deadline-exceeded"
		default:
			record.ParentState = "other-error"
		}
		if deadline, ok := ctx.Deadline(); ok {
			record.DeadlinePresent = true
			if remaining := deadline.Sub(now); remaining > 0 {
				record.RemainingNanoseconds = int64(remaining)
			}
		}
	}
	if state == nil && phase == "after-attempt" {
		record.Process = "launch-failure"
	} else if state != nil {
		record.Process, record.Signal = "other-termination", installerBinarySignalCategory(state.Sys())
		if state.Exited() {
			record.Process = "exit-failure"
			if code := state.ExitCode(); code >= 0 && code <= 255 {
				record.ExitCode = code
			}
			if commandErr == nil {
				record.Process = "success"
			}
		} else if status, ok := state.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			record.Process = "signal-termination"
		}
	}
	// This closed struct has no fallible JSON fields or provider-owned values.
	encoded, _ := json.Marshal(record)
	return string(encoded)
}

func installerBinarySignalCategory(value any) string {
	status, ok := value.(syscall.WaitStatus)
	if !ok {
		return "unavailable"
	}
	if !status.Signaled() {
		return "none"
	}
	switch status.Signal() {
	case syscall.SIGKILL:
		return "killed"
	case syscall.SIGTERM:
		return "terminated"
	default:
		return "other"
	}
}

func TestInstallerBinaryParentContext(t *testing.T) { testInstallerBinaryParentContext(t) }

func testInstallerBinaryParentContext(t *testing.T) {
	t.Helper()
	now := time.Now()
	assert := func(t *testing.T, record string, want map[string]any) {
		t.Helper()
		var got map[string]any
		if json.Unmarshal([]byte(record), &got) != nil || len(got) != 10 || strings.Contains(record, "PRIVATE-CANARY") || got["format"] != "installer-parent-context-v1" || got["scope"] != "observation-not-termination-cause" {
			t.Fatal("parent context diagnostic escaped its closed schema")
		}
		for key, value := range want {
			if got[key] != value {
				t.Fatalf("parent context diagnostic mismatch in %s", key)
			}
		}
	}
	t.Run("no-deadline-and-private-values", func(t *testing.T) {
		assert(t, installerBinaryParentContext(context.Background(), now, "PRIVATE-CANARY", "PRIVATE-CANARY", nil, errors.New("PRIVATE-CANARY")), map[string]any{"command": "unavailable", "phase": "unavailable", "parentState": "active", "deadlinePresent": false, "remainingNanoseconds": float64(0), "process": "not-started", "exitCode": float64(-1), "signal": "none"})
		if installerBinarySignalCategory("PRIVATE-CANARY") != "unavailable" || installerBinarySignalCategory(syscall.WaitStatus(syscall.SIGINT)) != "other" || installerBinarySignalCategory(syscall.WaitStatus(syscall.SIGTERM)) != "terminated" {
			t.Fatal("signal category leaked or accepted unsupported process state")
		}
	})
	t.Run("remaining-and-clamped-budget", func(t *testing.T) {
		ctx, cancel := context.WithDeadline(context.Background(), now.Add(time.Hour))
		defer cancel()
		assert(t, installerBinaryParentContext(ctx, now, "install", "before-attempt", nil, nil), map[string]any{"deadlinePresent": true, "remainingNanoseconds": float64(time.Hour), "parentState": "active", "process": "not-started"})
		assert(t, installerBinaryParentContext(ctx, now.Add(2*time.Hour), "install", "before-attempt", nil, nil), map[string]any{"remainingNanoseconds": float64(0), "parentState": "active"})
	})
	for _, mode := range []string{"success", "exit-failure", "active-kill", "canceled", "deadline", "expired-after-success", "launch-failure"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			if mode == "deadline" || mode == "expired-after-success" {
				cancel()
				ctx, cancel = context.WithTimeout(t.Context(), 2*time.Second)
			}
			defer cancel()
			script := "exit 0"
			want := map[string]any{"parentState": "active", "process": "success", "exitCode": float64(0), "signal": "none"}
			switch mode {
			case "exit-failure":
				script = "exit 7"
				want["process"], want["exitCode"] = "exit-failure", float64(7)
			case "active-kill":
				script = "kill -KILL $$"
				want["process"], want["exitCode"], want["signal"] = "signal-termination", float64(-1), "killed"
			case "canceled", "deadline":
				script = "printf ready; read -r decision"
				want["process"], want["exitCode"], want["signal"] = "signal-termination", float64(-1), "killed"
				want["parentState"] = "canceled"
				if mode == "deadline" {
					want["parentState"], want["remainingNanoseconds"] = "deadline-exceeded", float64(0)
				}
			case "expired-after-success":
				want["parentState"], want["remainingNanoseconds"] = "deadline-exceeded", float64(0)
			case "launch-failure":
				want["process"], want["exitCode"] = "launch-failure", float64(-1)
			}
			child := exec.CommandContext(ctx, "/bin/sh", "-c", script)
			if mode == "launch-failure" {
				child = exec.CommandContext(ctx, filepath.Join(t.TempDir(), "PRIVATE-CANARY"))
			}
			var commandErr error
			if mode == "canceled" || mode == "deadline" {
				pipe, err := child.StdoutPipe()
				if err != nil {
					t.Fatal("inert diagnostic pipe unavailable")
				}
				defer pipe.Close()
				input, err := child.StdinPipe()
				if err != nil {
					t.Fatal("inert diagnostic input unavailable")
				}
				if child.Start() != nil {
					input.Close()
					t.Fatal("inert diagnostic process unavailable")
				}
				waited := false
				t.Cleanup(func() {
					input.Close()
					if !waited {
						child.Process.Kill()
						child.Wait()
					}
				})
				ready := make([]byte, 5)
				if _, err := io.ReadFull(pipe, ready); err != nil || string(ready) != "ready" {
					t.Fatal("inert diagnostic readiness unavailable")
				}
				if mode == "canceled" {
					cancel()
				}
				commandErr = child.Wait()
				waited = true
			} else {
				commandErr = child.Run()
			}
			if mode == "expired-after-success" {
				<-ctx.Done() // Same parent expires after its child has exited.
			}
			assert(t, installerBinaryParentContext(ctx, time.Now(), "uninstall", "after-attempt", child.ProcessState, commandErr), want)
		})
	}
}
