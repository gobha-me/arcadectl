// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package installerprofile

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"io"
	"os"
	"runtime/pprof"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestMatrixInheritedHelper(t *testing.T) {
	if os.Getenv("ARCADECTL_PROFILE_TEST_HELPER") != "1" {
		return
	}
	mode := os.Getenv("ARCADECTL_PROFILE_TEST_MODE")
	var other *profileBuffer
	if mode == "existing" {
		other = newProfileBuffer()
		if pprof.StartCPUProfile(other) != nil {
			os.Exit(90)
		}
	}
	s := StartInherited()
	if s == nil || s.matrix == nil || StartInherited() != nil {
		os.Exit(91)
	}
	for _, fd := range []int{controlFD, outputFD} {
		flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		if err != nil || flags&unix.FD_CLOEXEC == 0 {
			os.Exit(92)
		}
	}
	command := "upgrade"
	if mode == "wrong-command" {
		command = "resume"
	}
	ctx := WithFirstUpgradeMatrix(context.Background(), command, s)
	var handle *Session
	if mode != "not-started" {
		handle = BeginFirstUpgradeMatrix(ctx)
	}
	if mode == "wrong-command" && handle != nil || mode != "wrong-command" && mode != "not-started" && handle != s {
		os.Exit(93)
	}
	if mode == "labels" {
		pprof.SetGoroutineLabels(pprof.WithLabels(context.Background(), pprof.Labels("PRIVATE-LABEL-CANARY", "PRIVATE-VALUE-CANARY")))
	}
	if mode == "hang" {
		_, _ = os.Stdout.WriteString("ready\n")
		select {}
	}
	payload := make([]byte, 8192)
	until := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(until) {
		payload[0]++
		_ = sha256.Sum256(payload)
	}
	if mode == "matrix-wait" {
		_, _ = os.Stdout.WriteString("ready\n")
		select {} // Timer must finalize independently; parent then kills the child.
	}
	handle.RequestMatrixStop()
	complete := s.Stop()
	if mode == "existing" {
		if complete || pprof.StartCPUProfile(newProfileBuffer()) == nil {
			os.Exit(94)
		}
		pprof.StopCPUProfile() // Only the test-owned other profiler.
		if other.overflow || len(other.bytes) == 0 {
			os.Exit(95)
		}
	} else if !complete {
		os.Exit(96)
	}
	if BeginFirstUpgradeMatrix(ctx) != nil || s.Stop() != complete {
		os.Exit(97)
	}
	// Force FD reuse after joined close. Late matrix callbacks must not close or
	// write to the new unrelated descriptor owners.
	var pair [2]int
	if unix.Pipe2(pair[:], unix.O_CLOEXEC|unix.O_NONBLOCK) != nil {
		os.Exit(98)
	}
	defer unix.Close(pair[0])
	defer unix.Close(pair[1])
	for _, fd := range []int{controlFD, outputFD} {
		if pair[0] != fd && pair[1] != fd && unix.Dup3(pair[1], fd, unix.O_CLOEXEC) != nil {
			os.Exit(99)
		}
	}
	s.RequestMatrixStop()
	s.matrix.requestStop()
	if _, err := unix.FcntlInt(controlFD, unix.F_GETFD, 0); err != nil {
		os.Exit(100)
	}
	if _, err := unix.FcntlInt(outputFD, unix.F_GETFD, 0); err != nil {
		os.Exit(101)
	}
	_, _ = os.Stdout.WriteString("unchanged stdout\n")
	_, _ = os.Stderr.WriteString("unchanged stderr\n")
	os.Exit(7)
}

func TestMatrixCaptureActualChildPrivacyAndNotStarted(t *testing.T) {
	for _, mode := range []string{"enabled", "not-started", "wrong-command", "existing", "labels", "hang"} {
		t.Run(mode, func(t *testing.T) {
			capture, err := NewFirstUpgradeMatrixCapture()
			if err != nil {
				t.Fatal("matrix capture unavailable")
			}
			defer capture.Close()
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			command := profileHelperCommand(t, ctx, mode)
			command.Args[1] = "-test.run=^TestMatrixInheritedHelper$"
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
				t.Fatal("matrix diagnostics masked command failure")
			}
			if mode == "hang" {
				if len(body) != 0 || diagnostic == nil || command.ProcessState == nil || command.ProcessState.Exited() {
					t.Fatal("killed matrix child fabricated coverage")
				}
				return
			}
			if command.ProcessState == nil || command.ProcessState.ExitCode() != 7 || stdout.String() != "unchanged stdout\n" || stderr.String() != "unchanged stderr\n" {
				t.Fatal("matrix changed command output/exit or descriptor ownership")
			}
			if mode == "not-started" || mode == "wrong-command" {
				if body != nil || !FirstUpgradeMatrixNotStarted(diagnostic) {
					t.Fatal("unreached matrix fabricated CPU")
				}
			} else if mode == "existing" {
				if body != nil || diagnostic != errIncomplete {
					t.Fatal("failed Start acquired another profiler")
				}
			} else {
				if diagnostic != nil || len(body) == 0 {
					t.Fatal("owned matrix profile incomplete")
				}
				executable, err := os.Executable()
				if err != nil {
					t.Fatal("owned executable unavailable")
				}
				summary, refusal, err := SummarizeCPUWithDiagnostic(body, executable)
				if mode == "labels" {
					reader, readErr := gzip.NewReader(bytes.NewReader(body))
					if readErr != nil {
						t.Fatal("owned profile gzip unavailable")
					}
					decoded, readErr := io.ReadAll(io.LimitReader(reader, maxDecodedBytes+1))
					closeErr := reader.Close()
					if readErr != nil || closeErr != nil || !bytes.Contains(decoded, []byte("PRIVATE-LABEL-CANARY")) || !bytes.Contains(decoded, []byte("PRIVATE-VALUE-CANARY")) || err != errIncomplete || refusal != (CPURefusal{Stage: CPURefusalSchema}) || summary.Samples != 0 || summary.Buckets != nil {
						t.Fatal("matrix raw canary bypassed CPU privacy refusal")
					}
				} else if err != nil || summary.Samples == 0 || summary.DurationNanoseconds == 0 {
					t.Fatal("matrix real CPU failed bounded parser")
				}
			}
			for _, file := range []*os.File{capture.control, capture.writer, capture.reader} {
				if _, err := file.Stat(); err == nil {
					t.Fatal("matrix parent descriptor leaked")
				}
			}
		})
	}
}

func TestMatrixDrainOverflowAndBoundedFlush(t *testing.T) {
	capture, err := NewFirstUpgradeMatrixCapture()
	if err != nil {
		t.Fatal("owned matrix unavailable")
	}
	defer capture.Close()
	if capture.writer.SetWriteDeadline(time.Now().Add(2*time.Second)) != nil {
		t.Fatal("owned write deadline unavailable")
	}
	if n, err := capture.writer.Write(make([]byte, MaxFrameBytes+2)); err != nil || n != MaxFrameBytes+2 {
		t.Fatal("matrix overflow did not drain")
	}
	capture.claimed.Store(true)
	capture.release(true)
	if capture.readErr != errIncomplete || capture.frame != nil {
		t.Fatal("matrix overflow retained partial frame")
	}
	reader, writer, _ := testPipe(t, true)
	_ = reader.Close()
	if flushMatrixProfile(int(writer.Fd()), []byte("owned synthetic profile"), false) || flushMatrixProfile(int(writer.Fd()), nil, true) {
		t.Fatal("broken pipe accepted matrix frame")
	}
}

func TestMatrixActualTimerFinalizesWithoutEndingCommand(t *testing.T) {
	capture, err := NewFirstUpgradeMatrixCapture()
	if err != nil {
		t.Fatal("owned matrix capture unavailable")
	}
	defer capture.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	command := profileHelperCommand(t, ctx, "matrix-wait")
	command.Args[1] = "-test.run=^TestMatrixInheritedHelper$"
	ready := &helperReady{once: make(chan struct{}, 1)}
	command.Stdout, command.Stderr = ready, ready
	type outcome struct {
		body                []byte
		diagnostic, command error
	}
	finished := make(chan outcome, 1)
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		body, diagnostic, commandErr := capture.Run(command)
		finished <- outcome{body, diagnostic, commandErr}
	}()
	defer func() {
		cancel()
		select {
		case <-joined:
		case <-time.After(2 * time.Second):
			t.Error("owned matrix timer child/drain did not join during cleanup")
		}
	}()
	select {
	case <-ready.once:
	case <-ctx.Done():
		t.Fatal("matrix timer handshake unavailable")
	}
	select {
	case <-capture.done:
	case <-ctx.Done():
		t.Fatal("production matrix timer never finalized")
	}
	select {
	case <-finished:
		t.Fatal("matrix timer ended the command")
	default:
	}
	if command.Process.Signal(syscall.SIGKILL) != nil {
		t.Fatal("owned timer command kill refused")
	}
	select {
	case got := <-finished:
		if got.command == nil || command.ProcessState == nil || command.ProcessState.Exited() || got.diagnostic != nil || len(got.body) == 0 {
			t.Fatal("timer finalization changed actual command termination")
		}
		executable, err := os.Executable()
		if err != nil {
			t.Fatal("owned executable unavailable")
		}
		summary, _, err := SummarizeCPUWithDiagnostic(got.body, executable)
		if err != nil || summary.Samples == 0 || summary.DurationNanoseconds < FirstUpgradeMatrixRequestedNanoseconds {
			t.Fatal("actual matrix timer lacked validated samples/duration")
		}
	case <-ctx.Done():
		t.Fatal("owned matrix timer command did not join")
	}
}
