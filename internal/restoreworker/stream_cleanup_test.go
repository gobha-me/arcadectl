// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package restoreworker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type rejectingStreamWriter struct{ calls int }

func (writer *rejectingStreamWriter) Write([]byte) (int, error) {
	writer.calls++
	return 0, errors.New("destination-full credential-canary")
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
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	writer := &rejectingStreamWriter{}
	err := (&commandRunner{path: program}).Stream(ctx, map[string]string{"CLEANUP_PATH": cleanup}, writer, "dump")
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
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	err := (&commandRunner{path: program}).Stream(ctx, nil, &rejectingStreamWriter{}, "dump")
	if err == nil || strings.Contains(err.Error(), "canary") || ctx.Err() == nil || time.Since(started) > 2*time.Second {
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
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	output, err := (&commandRunner{path: program}).Control(ctx, map[string]string{"CLEANUP_PATH": cleanup}, "snapshots")
	if err == nil || len(output) != 0 {
		t.Fatal("oversized control response must fail without publishing its partial output")
	}
	if contents, err := os.ReadFile(cleanup); err != nil || string(contents) != "done" {
		t.Fatalf("control response bound interrupted normal child cleanup: cleanup=%q err=%v", contents, err)
	}
}
