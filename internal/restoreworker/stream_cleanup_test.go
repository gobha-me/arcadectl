// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package restoreworker

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

type rejectingStreamWriter struct {
	calls    int
	rejected chan struct{}
}

func (writer *rejectingStreamWriter) Write([]byte) (int, error) {
	writer.calls++
	if writer.rejected != nil && writer.calls == 1 {
		close(writer.rejected)
	}
	return 0, errors.New("destination-full credential-canary")
}

// Keep the fixture's script inode executable-busy on Linux. The repository
// runner contract must be tested after successful startup, not accidentally
// satisfied by a redacted startup error. A stable shell reads this script.
func keepRepositoryScriptExecutableBusy(t *testing.T, program string) {
	t.Helper()
	if runtime.GOOS != "linux" {
		return
	}
	writer, err := os.OpenFile(program, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := writer.Close(); err != nil {
			t.Error("fixture writer cleanup failed")
		}
	})
	command := exec.Command(program)
	if err := command.Start(); !errors.Is(err, syscall.ETXTBSY) {
		if err == nil {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
		t.Fatal("fixture did not exercise the executable-busy startup condition")
	}
}

func TestCommandRunnerDrainsAfterDestinationFailureBeforeRepositoryCleanup(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	program := filepath.Join(directory, "repository-stream")
	cleanup := filepath.Join(directory, "cleanup-complete")
	// More than a pipe buffer: stopping the stdout copier early interrupts the
	// child before its normal repository-lock cleanup can run.
	contents := "#!/bin/sh\nset -e\n/usr/bin/head -c 1048576 /dev/zero\nprintf done > \"$CLEANUP_PATH\"\n"
	if err := os.WriteFile(program, []byte(contents), 0o700); err != nil {
		t.Fatal(err)
	}
	keepRepositoryScriptExecutableBusy(t, program)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	writer := &rejectingStreamWriter{}
	err := (&commandRunner{path: "/bin/sh"}).Stream(ctx, map[string]string{"CLEANUP_PATH": cleanup}, writer, program, "dump")
	if err == nil || strings.Contains(err.Error(), "canary") || writer.calls != 1 {
		t.Fatalf("Stream failure must be bounded and stop destination writes: err=%v calls=%d", err, writer.calls)
	}
	if contents, err := os.ReadFile(cleanup); err != nil || string(contents) != "done" {
		t.Fatalf("destination failure interrupted normal child cleanup: cleanup=%q err=%v", contents, err)
	}
}

func TestCommandRunnerDrainingStillHonorsContextCancellation(t *testing.T) {
	t.Parallel()
	program := filepath.Join(t.TempDir(), "repository-stream")
	if err := os.WriteFile(program, []byte("#!/bin/sh\nexec /usr/bin/yes credential-canary\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	keepRepositoryScriptExecutableBusy(t, program)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	started := time.Now()
	writer := &rejectingStreamWriter{rejected: make(chan struct{})}
	// Cancel only after destination rejection, so scheduler load cannot turn
	// this into a process-startup timeout instead of a draining cancellation.
	go func() {
		select {
		case <-writer.rejected:
			cancel()
		case <-ctx.Done():
		}
	}()
	err := (&commandRunner{path: "/bin/sh"}).Stream(ctx, nil, writer, program, "dump")
	if err == nil || strings.Contains(err.Error(), "canary") || !errors.Is(ctx.Err(), context.Canceled) || writer.calls != 1 || time.Since(started) > 5*time.Second {
		t.Fatalf("draining ignored cancellation or leaked output: err=%v context=%v duration=%v", err, ctx.Err(), time.Since(started))
	}
}

func TestCommandRunnerControlLimitStillAllowsRepositoryCleanup(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	program := filepath.Join(directory, "repository-control")
	cleanup := filepath.Join(directory, "cleanup-complete")
	contents := "#!/bin/sh\nset -e\n/usr/bin/head -c 16777216 /dev/zero\nprintf done > \"$CLEANUP_PATH\"\n"
	if err := os.WriteFile(program, []byte(contents), 0o700); err != nil {
		t.Fatal(err)
	}
	keepRepositoryScriptExecutableBusy(t, program)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	output, err := (&commandRunner{path: "/bin/sh"}).Control(ctx, map[string]string{"CLEANUP_PATH": cleanup}, program, "snapshots")
	if err == nil || len(output) != 0 {
		t.Fatal("oversized control response must fail without publishing its partial output")
	}
	if contents, err := os.ReadFile(cleanup); err != nil || string(contents) != "done" {
		t.Fatalf("control response bound interrupted normal child cleanup: cleanup=%q err=%v", contents, err)
	}
}
