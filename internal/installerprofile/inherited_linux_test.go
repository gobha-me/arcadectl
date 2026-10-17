// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package installerprofile

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"runtime/pprof"
	"strconv"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The environment selects this test-only subprocess, not the production hook.
func TestInheritedProfileHelper(t *testing.T) {
	if os.Getenv("ARCADECTL_PROFILE_TEST_HELPER") != "1" {
		return
	}
	mode := os.Getenv("ARCADECTL_PROFILE_TEST_MODE")
	if mode == "labels" {
		pprof.SetGoroutineLabels(pprof.WithLabels(context.Background(), pprof.Labels("PRIVATE-LABEL-CANARY", "PRIVATE-VALUE-CANARY")))
	}
	var other *profileBuffer
	if mode == "existing" {
		other = newProfileBuffer()
		if pprof.StartCPUProfile(other) != nil {
			os.Exit(98)
		}
	}
	beforeFlags, _ := unix.FcntlInt(controlFD, unix.F_GETFD, 0)
	beforeOffset, _ := unix.Seek(controlFD, 0, io.SeekCurrent)
	beforeOutputFlags, _ := unix.FcntlInt(outputFD, unix.F_GETFD, 0)
	beforeOutputAccess, _ := unix.FcntlInt(outputFD, unix.F_GETFL, 0)
	s := StartInherited()
	if StartInherited() != nil { // No repeated adoption or descriptor cleanup.
		os.Exit(91)
	}
	if mode == "existing" {
		if s != nil || pprof.StartCPUProfile(newProfileBuffer()) == nil {
			os.Exit(99)
		}
		pprof.StopCPUProfile() // Only this test's originally owned profiler.
		if other.overflow || len(other.bytes) == 0 {
			os.Exit(100)
		}
	} else if mode == "disabled" {
		if s != nil {
			os.Exit(92)
		}
		afterFlags, err := unix.FcntlInt(controlFD, unix.F_GETFD, 0)
		afterOffset, _ := unix.Seek(controlFD, 0, io.SeekCurrent)
		if err != nil || beforeFlags != afterFlags || beforeOffset != afterOffset {
			os.Exit(93)
		}
		afterOutputFlags, err := unix.FcntlInt(outputFD, unix.F_GETFD, 0)
		afterOutputAccess, accessErr := unix.FcntlInt(outputFD, unix.F_GETFL, 0)
		if err != nil || accessErr != nil || beforeOutputFlags != afterOutputFlags || beforeOutputAccess != afterOutputAccess {
			os.Exit(97)
		}
	} else {
		if s == nil {
			os.Exit(94)
		}
		for _, fd := range []int{controlFD, outputFD} {
			flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
			if err != nil || flags&unix.FD_CLOEXEC == 0 {
				os.Exit(95)
			}
		}
		descendantContext, cancel := context.WithTimeout(context.Background(), time.Second)
		descendant := exec.CommandContext(descendantContext, "/bin/sh", "-c", "test ! -e /proc/self/fd/3 && test ! -e /proc/self/fd/4")
		descendantErr := descendant.Run()
		cancel()
		if descendantErr != nil {
			os.Exit(101)
		}
		if mode == "graceful" {
			ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM)
			_, _ = os.Stdout.WriteString("ready\n")
			<-ctx.Done()
			cancel()
		}
		if mode == "prefix-wait" {
			ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM)
			payload := make([]byte, 8192)
			until := time.Now().Add(300 * time.Millisecond)
			for time.Now().Before(until) {
				payload[0]++
				_ = sha256.Sum256(payload)
			}
			_, _ = os.Stdout.WriteString("ready\n")
			<-ctx.Done()
			cancel()
		}
		if mode == "hang" {
			_, _ = os.Stdout.WriteString("ready\n")
			for {
				time.Sleep(time.Second)
			} // Parent must kill; no finalization.
		}
		payload := make([]byte, 8192)
		until := time.Now().Add(300 * time.Millisecond)
		for time.Now().Before(until) {
			payload[0]++
			_ = sha256.Sum256(payload)
		}
		complete := s.Stop()
		if mode == "broken" && complete || mode != "broken" && !complete || s.Stop() != complete {
			os.Exit(96)
		}
	}
	_, _ = os.Stdout.WriteString("unchanged stdout\n")
	_, _ = os.Stderr.WriteString("unchanged stderr\n")
	os.Exit(7) // Diagnostic success/failure must not replace command exit codes.
}

func rejectedTestControl(t *testing.T, identity unix.Stat_t, scenario string, prefix bool) *os.File {
	return rejectedTestControlForPurpose(t, identity, scenario, prefix, false)
}

func rejectedTestControlForPurpose(t *testing.T, identity unix.Stat_t, scenario string, prefix, matrix bool) *os.File {
	t.Helper()
	valid, err := newControlForPurpose(identity, prefix, matrix)
	if err != nil {
		t.Fatal("owned control fixture unavailable")
	}
	defer valid.Close()
	var record [controlBytes]byte
	if n, err := unix.Pread(int(valid.Fd()), record[:], 0); err != nil || n != len(record) {
		t.Fatal("owned control record unavailable")
	}
	name, mode, seals := controlName, uint32(0400), controlSeals
	if prefix {
		name = prefixControlName
	}
	if matrix {
		name = matrixControlName
	}
	switch scenario {
	case "wrong-purpose":
		name = "foreign-private-purpose"
	case "wrong-mode":
		mode = 0600
	case "unsealed":
		seals = 0
	case "wrong-magic":
		record[0] ^= 1
	case "other-protocol-purpose":
		name = prefixControlName
		if prefix {
			name = controlName
		}
	case "other-protocol-magic":
		magic := prefixControlMagic
		if prefix {
			magic = controlMagic
		}
		copy(record[:16], magic)
	case "wrong-cap":
		binary.LittleEndian.PutUint64(record[16:24], MaxProfileBytes+1)
	case "nonzero-reserved":
		record[63] = 1
	case "wrong-output-owner":
		binary.LittleEndian.PutUint32(record[40:44], identity.Uid+1)
	}
	fd, err := unix.MemfdCreate(name, unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		t.Fatal("owned alternative memfd unavailable")
	}
	defer unix.Close(fd)
	data := record[:]
	if scenario == "wrong-size" {
		data = data[:len(data)-1]
	}
	if n, err := unix.Write(fd, data); err != nil || n != len(data) || unix.Fchmod(fd, mode) != nil {
		t.Fatal("owned alternative control construction failed")
	}
	if seals != 0 {
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_ADD_SEALS, seals); err != nil {
			t.Fatal("owned alternative seals unavailable")
		}
	}
	var readFD int
	if scenario == "writable-control" {
		readFD, err = unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
	} else {
		readFD, err = unix.Open("/proc/self/fd/"+strconv.Itoa(fd), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	}
	if err != nil {
		t.Fatal("owned alternative control unavailable")
	}
	return os.NewFile(uintptr(readFD), "owned-alternative-control")
}

func TestInheritedRejectsEveryControlProtocolBoundaryWithoutChangingFDs(t *testing.T) {
	for _, purpose := range []string{"full", "prefix", "matrix"} {
		prefix, matrix := purpose == "prefix", purpose == "matrix"
		for _, scenario := range []string{"wrong-purpose", "wrong-mode", "unsealed", "wrong-magic", "other-protocol-purpose", "other-protocol-magic", "wrong-cap", "nonzero-reserved", "wrong-output-owner", "wrong-size", "writable-control"} {
			t.Run(purpose+"/"+scenario, func(t *testing.T) {
				reader, writer, identity := testPipe(t, true)
				control := rejectedTestControlForPurpose(t, identity, scenario, prefix, matrix)
				defer control.Close()
				runProfileHelper(t, control, writer, "disabled")
				wire, err := io.ReadAll(io.LimitReader(reader, MaxFrameBytes+1))
				if err != nil || len(wire) != 0 {
					t.Fatal("rejected private descriptor emitted bytes")
				}
			})
		}
	}
}

func testPipe(t *testing.T, nonblocking bool) (*os.File, *os.File, unix.Stat_t) {
	t.Helper()
	flags := unix.O_CLOEXEC
	if nonblocking {
		flags |= unix.O_NONBLOCK
	}
	var descriptors [2]int
	if unix.Pipe2(descriptors[:], flags) != nil {
		t.Fatal("owned test pipe unavailable")
	}
	reader, writer := os.NewFile(uintptr(descriptors[0]), "owned-profile-reader"), os.NewFile(uintptr(descriptors[1]), "owned-profile-writer")
	t.Cleanup(func() { _ = reader.Close(); _ = writer.Close() })
	var stat unix.Stat_t
	if unix.Fstat(descriptors[1], &stat) != nil {
		t.Fatal("owned pipe identity unavailable")
	}
	return reader, writer, stat
}

func runProfileHelper(t *testing.T, control, writer *os.File, mode string) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal("profile test executable unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable, "-test.run=^TestInheritedProfileHelper$")
	command.Env = append(os.Environ(), "ARCADECTL_PROFILE_TEST_HELPER=1", "ARCADECTL_PROFILE_TEST_MODE="+mode)
	command.ExtraFiles = []*os.File{control, writer}
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	if command.Start() != nil {
		t.Fatal("owned profile helper launch unavailable")
	}
	_ = writer.Close() // Only after Start has copied the descriptors.
	err = command.Wait()
	if ctx.Err() != nil || err == nil || command.ProcessState == nil || command.ProcessState.ExitCode() != 7 || stdout.String() != "unchanged stdout\n" || stderr.String() != "unchanged stderr\n" {
		t.Fatal("diagnostic changed helper output/exit or exceeded bounded completion")
	}
}

func TestInheritedRealProfileAndRejectedPairs(t *testing.T) {
	testInheritedRealProfileAndRejectedPairs(t, false)
}

func TestInheritedPrefixRealProfileAndRejectedPairs(t *testing.T) {
	testInheritedRealProfileAndRejectedPairs(t, true)
}

func testInheritedRealProfileAndRejectedPairs(t *testing.T, prefix bool) {
	for _, scenario := range []string{"valid", "foreign-file", "blocking-output", "wrong-pipe", "swapped", "broken-reader", "existing-profiler"} {
		t.Run(scenario, func(t *testing.T) {
			reader, writer, identity := testPipe(t, scenario != "blocking-output")
			control, err := newControlForProtocol(identity, prefix)
			if err != nil {
				t.Fatal("sealed read-only test control unavailable")
			}
			ownedControl := control // Cleanup must not follow later fixture swaps.
			t.Cleanup(func() { _ = ownedControl.Close() })
			mode := "disabled"
			if scenario == "valid" {
				mode = "enabled"
			} else if scenario == "broken-reader" {
				mode = "broken"
				_ = reader.Close()
			} else if scenario == "existing-profiler" {
				mode = "existing"
			} else if scenario == "foreign-file" {
				foreign, err := os.CreateTemp(t.TempDir(), "foreign-descriptor-")
				if err != nil {
					t.Fatal("foreign descriptor fixture unavailable")
				}
				t.Cleanup(func() { _ = foreign.Close() })
				if _, err := foreign.WriteString("private synthetic canary"); err != nil {
					t.Fatal("foreign fixture write unavailable")
				}
				control = foreign
			} else if scenario == "wrong-pipe" {
				_ = reader.Close()
				_ = writer.Close()
				reader, writer, _ = testPipe(t, true)
			} else if scenario == "swapped" {
				control, writer = writer, control
			}
			var received []byte
			finished := make(chan struct{})
			if scenario != "broken-reader" && scenario != "swapped" {
				go func() {
					received, _ = io.ReadAll(io.LimitReader(reader, MaxFrameBytes+1))
					close(finished)
				}()
			} else {
				close(finished)
			}
			runProfileHelper(t, control, writer, mode)
			select {
			case <-finished:
			case <-time.After(time.Second):
				_ = reader.Close()
				t.Fatal("owned profile reader failed to join")
			}
			if scenario == "valid" {
				body, err := decodeFrameForProtocol(received, prefix)
				if err != nil {
					t.Fatal("finalized owned profile frame unavailable")
				}
				compressed, err := gzip.NewReader(bytes.NewReader(body))
				if err != nil {
					t.Fatal("owned CPU gzip unavailable")
				}
				decoded, err := io.ReadAll(io.LimitReader(compressed, 32*1024*1024+1))
				closeErr := compressed.Close()
				if err != nil || closeErr != nil || len(decoded) == 0 || len(decoded) > 32*1024*1024 {
					t.Fatal("owned CPU gzip incomplete or exceeds decode cap")
				}
				// This is gzip/custody only. CPU protobuf/label/mapping privacy
				// validation is a separate harness requirement, not inferred here.
			} else if len(received) != 0 {
				t.Fatal("rejected descriptor pair emitted diagnostic bytes")
			}
		})
	}
}
