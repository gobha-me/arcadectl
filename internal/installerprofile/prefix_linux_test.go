// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package installerprofile

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestCapturePrefixEarlyExitAndPrivacy(t *testing.T) {
	for _, mode := range []string{"enabled", "labels", "hang"} {
		t.Run(mode, func(t *testing.T) {
			capture, err := NewPrefixCapture()
			if err != nil {
				t.Fatal("owned prefix capture unavailable")
			}
			defer capture.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			command := profileHelperCommand(t, ctx, mode)
			var stdout, stderr bytes.Buffer
			command.Stdout, command.Stderr = &stdout, &stderr
			if mode == "hang" {
				ready := &helperReady{once: make(chan struct{}, 1)}
				command.Stdout, command.Stderr = ready, ready
				go func() {
					select {
					case <-ready.once:
						cancel()
					case <-ctx.Done():
					}
				}()
			}
			body, diagnostic, commandErr := capture.Run(command)
			if commandErr == nil {
				t.Fatal("prefix changed the failing command outcome")
			}
			if mode == "hang" {
				if diagnostic == nil || len(body) != 0 {
					t.Fatal("kill before prefix finalization fabricated coverage")
				}
				return
			}
			if diagnostic != nil || len(body) == 0 || command.ProcessState.ExitCode() != 7 || stdout.String() != "unchanged stdout\n" || stderr.String() != "unchanged stderr\n" {
				t.Fatal("early exit changed output/status or lost scoped finalization")
			}
			executable, err := os.Executable()
			if err != nil {
				t.Fatal("owned executable unavailable")
			}
			summary, reason, parseErr := SummarizeCPUWithDiagnostic(body, executable)
			if mode == "labels" {
				gzipReader, err := gzip.NewReader(bytes.NewReader(body))
				if err != nil {
					t.Fatal("owned labeled prefix gzip unavailable")
				}
				decoded, readErr := io.ReadAll(io.LimitReader(gzipReader, maxDecodedBytes+1))
				closeErr := gzipReader.Close()
				if readErr != nil || closeErr != nil || len(decoded) > maxDecodedBytes || !bytes.Contains(decoded, []byte("PRIVATE-LABEL-CANARY")) || !bytes.Contains(decoded, []byte("PRIVATE-VALUE-CANARY")) {
					t.Fatal("actual prefix lacked both private label operands")
				}
				if parseErr != errIncomplete || reason != (CPURefusal{Stage: CPURefusalSchema}) || summary.Samples != 0 || summary.Buckets != nil {
					t.Fatal("prefix bypassed existing label privacy refusal")
				}
			} else if parseErr != nil || summary.Samples == 0 || summary.DurationNanoseconds == 0 {
				t.Fatal("actual early prefix failed unchanged bounded CPU parser")
			}
		})
	}
}

func TestCapturePrefixTimerFinalizesWhileCommandStillRuns(t *testing.T) {
	capture, err := NewPrefixCapture()
	if err != nil {
		t.Fatal("owned prefix unavailable")
	}
	defer capture.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	command := profileHelperCommand(t, ctx, "prefix-wait")
	ready := &helperReady{once: make(chan struct{}, 1)}
	command.Stdout, command.Stderr = ready, ready
	type outcome struct {
		body                []byte
		diagnostic, command error
	}
	finished := make(chan outcome, 1)
	go func() { body, diagnostic, err := capture.Run(command); finished <- outcome{body, diagnostic, err} }()
	select {
	case <-ready.once:
	case <-ctx.Done():
		t.Fatal("prefix child handshake unavailable")
	}
	select {
	case <-capture.done: // Finalized frame + EOF while Wait still owns the child.
	case <-ctx.Done():
		t.Fatal("fixed prefix timer never finalized")
	}
	select {
	case <-finished:
		t.Fatal("timer ended the installation command")
	default:
	}
	if command.Process.Signal(syscall.SIGKILL) != nil {
		t.Fatal("owned command signal refused")
	}
	select {
	case got := <-finished:
		if got.command == nil || command.ProcessState.Exited() || got.diagnostic != nil || len(got.body) == 0 {
			t.Fatal("finalized prefix masked later forced termination")
		}
		executable, err := os.Executable()
		if err != nil {
			t.Fatal("owned executable unavailable")
		}
		summary, _, err := SummarizeCPUWithDiagnostic(got.body, executable)
		if err != nil || summary.Samples == 0 || summary.DurationNanoseconds < PrefixCaptureRequestedNanoseconds {
			t.Fatal("timer prefix lacked actual validated duration and CPU samples")
		}
	case <-ctx.Done():
		t.Fatal("owned prefix command failed to join")
	}
}
