// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package installerprofile

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func profileHelperCommand(t *testing.T, ctx context.Context, mode string) *exec.Cmd {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal("owned test executable unavailable")
	}
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestInheritedProfileHelper$")
	cmd.Env = append(os.Environ(), "ARCADECTL_PROFILE_TEST_HELPER=1", "ARCADECTL_PROFILE_TEST_MODE="+mode)
	return cmd
}

func TestCaptureRealChildAndCommandFailure(t *testing.T) {
	capture, err := NewCapture()
	if err != nil {
		t.Fatal("owned capture unavailable")
	}
	defer capture.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := profileHelperCommand(t, ctx, "enabled")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	body, diagnosticErr, commandErr := capture.Run(cmd)
	var exit *exec.ExitError
	if diagnosticErr != nil || len(body) == 0 || !errors.As(commandErr, &exit) || exit.ExitCode() != 7 ||
		stdout.String() != "unchanged stdout\n" || stderr.String() != "unchanged stderr\n" {
		t.Fatal("private capture masked command failure/output or lost owned finalized frame")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal("owned executable mapping unavailable")
	}
	summary, err := SummarizeCPU(body, executable)
	if err != nil || summary.Samples == 0 || summary.CPUNanoseconds == 0 {
		t.Fatal("actual Go child CPU profile failed bounded closed-summary validation")
	}
	if _, diag, command := capture.Run(cmd); diag == nil || command == nil {
		t.Fatal("capture permitted command replay")
	}
}

func TestCaptureMissingExecutableAndUnusedClose(t *testing.T) {
	for _, mode := range []string{"unused", "missing", "extra-files"} {
		t.Run(mode, func(t *testing.T) {
			capture, err := NewCapture()
			if err != nil {
				t.Fatal("owned capture unavailable")
			}
			defer capture.Close()
			if mode == "unused" {
				capture.Close()
				capture.Close()
			} else {
				cmd := exec.Command(filepath.Join(t.TempDir(), "missing-owned-fixture"))
				if mode == "extra-files" {
					cmd.ExtraFiles = []*os.File{os.Stdin}
				}
				body, diag, command := capture.Run(cmd)
				if len(body) != 0 || diag == nil || command == nil {
					t.Fatal("failed launch produced diagnostic success")
				}
			}
			select {
			case <-capture.done:
			default:
				t.Fatal("owned drain was not joined")
			}
			for _, file := range []*os.File{capture.reader, capture.writer, capture.control} {
				if _, err := file.Stat(); err == nil {
					t.Fatal("owned capture descriptor leaked")
				}
			}
		})
	}
}

type helperReady struct{ once chan struct{} }

func (r *helperReady) Write(p []byte) (int, error) {
	select {
	case r.once <- struct{}{}:
	default:
	}
	return len(p), nil
}

func TestCaptureForcedKillIsIncompleteAndJoins(t *testing.T) {
	capture, err := NewCapture()
	if err != nil {
		t.Fatal("owned capture unavailable")
	}
	defer capture.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := profileHelperCommand(t, ctx, "hang")
	ready := &helperReady{once: make(chan struct{}, 1)}
	cmd.Stdout, cmd.Stderr = ready, ready
	type result struct {
		body                []byte
		diagnostic, command error
	}
	done := make(chan result, 1)
	go func() { body, diag, command := capture.Run(cmd); done <- result{body, diag, command} }()
	select {
	case <-ready.once:
		cancel()
	case <-ctx.Done():
		t.Fatal("owned child did not reach bounded cancellation handshake")
	}
	select {
	case r := <-done:
		if len(r.body) != 0 || r.diagnostic == nil || r.command == nil || !errors.Is(ctx.Err(), context.Canceled) {
			t.Fatal("forced kill produced a complete profile or masked cancellation")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("private drain delayed killed command")
	}
}

func TestCaptureGracefulSignalKeepsCommandExitAndFinalizes(t *testing.T) {
	capture, err := NewCapture()
	if err != nil {
		t.Fatal("owned capture unavailable")
	}
	defer capture.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := profileHelperCommand(t, ctx, "graceful")
	ready := &helperReady{once: make(chan struct{}, 1)}
	cmd.Stdout, cmd.Stderr = ready, ready
	type result struct {
		body                []byte
		diagnostic, command error
	}
	done := make(chan result, 1)
	go func() { body, diag, command := capture.Run(cmd); done <- result{body, diag, command} }()
	select {
	case <-ready.once:
		if cmd.Process.Signal(syscall.SIGTERM) != nil {
			t.Fatal("owned graceful signal unavailable")
		}
	case <-ctx.Done():
		t.Fatal("owned graceful child did not reach handshake")
	}
	select {
	case r := <-done:
		var exit *exec.ExitError
		if len(r.body) == 0 || r.diagnostic != nil || !errors.As(r.command, &exit) || exit.ExitCode() != 7 || ctx.Err() != nil {
			t.Fatal("graceful signal lost complete frame or changed original command status")
		}
	case <-ctx.Done():
		t.Fatal("graceful profile did not join within existing command budget")
	}
}

func TestCaptureOverflowDiscardsAndJoins(t *testing.T) {
	capture, err := NewCapture()
	if err != nil {
		t.Fatal("owned capture unavailable")
	}
	defer capture.Close()
	if capture.writer.SetWriteDeadline(time.Now().Add(2*time.Second)) != nil {
		t.Fatal("owned writer deadline unavailable")
	}
	if n, err := capture.writer.Write(make([]byte, MaxFrameBytes+1)); err != nil || n != MaxFrameBytes+1 {
		t.Fatal("overflow reader failed to drain/discard owned input")
	}
	capture.claimed.Store(true) // Pure drain control, not an actual command proof.
	capture.release(true)
	if capture.readErr == nil || len(capture.frame) != 0 {
		t.Fatal("overflow retained a partial frame")
	}
}

func TestCaptureNativeLabelsCannotEscapeAsSummary(t *testing.T) {
	capture, err := NewCapture()
	if err != nil {
		t.Fatal("owned capture unavailable")
	}
	defer capture.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := profileHelperCommand(t, ctx, "labels")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	body, diag, command := capture.Run(cmd)
	executable, executableErr := os.Executable()
	var exit *exec.ExitError
	if diag != nil || !errors.As(command, &exit) || exit.ExitCode() != 7 || executableErr != nil || stdout.String() != "unchanged stdout\n" || stderr.String() != "unchanged stderr\n" {
		t.Fatal("owned labeled child did not finalize")
	}
	gz, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		t.Fatal("owned label canary gzip unavailable")
	}
	decoded, readErr := io.ReadAll(io.LimitReader(gz, maxDecodedBytes+1))
	closeErr := gz.Close()
	if readErr != nil || closeErr != nil || len(decoded) > maxDecodedBytes || !bytes.Contains(decoded, []byte("PRIVATE-LABEL-CANARY")) || !bytes.Contains(decoded, []byte("PRIVATE-VALUE-CANARY")) {
		t.Fatal("native labeled CPU samples did not contain both private canaries")
	}
	if _, err := SummarizeCPU(body, executable); err == nil {
		t.Fatal("native private labels passed summary gate")
	}
}
