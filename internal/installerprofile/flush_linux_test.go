// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package installerprofile

import (
	"bytes"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestFlushFiniteBackpressureAndExactChunks(t *testing.T) {
	now := time.Unix(1, 0)
	attempts := 0
	var received []byte
	body := bytes.Repeat([]byte{0x73}, flushChunkBytes*3+1)
	write := func(fd int, p []byte) (int, error) {
		if fd != 7 || len(p) > flushChunkBytes {
			t.Fatal("flush changed the owned descriptor or atomic chunk bound")
		}
		attempts++
		if attempts <= 2 {
			return -1, unix.EAGAIN
		}
		received = append(received, p...)
		return len(p), nil
	}
	if !flushParts(7, [][]byte{body}, write, func() time.Time { return now }, func(d time.Duration) { now = now.Add(d) }) || !bytes.Equal(received, body) {
		t.Fatal("finite healthy-reader backpressure lost finalized bytes")
	}
}

func TestFlushRefusesWithoutUnboundedWait(t *testing.T) {
	for _, scenario := range []string{"stalled", "frozen-clock", "interrupted", "broken", "zero", "short"} {
		t.Run(scenario, func(t *testing.T) {
			now := time.Unix(1, 0)
			attempts := 0
			write := func(_ int, p []byte) (int, error) {
				attempts++
				switch scenario {
				case "stalled", "frozen-clock":
					return -1, unix.EAGAIN
				case "interrupted":
					return -1, unix.EINTR
				case "broken":
					return -1, unix.EPIPE
				case "short":
					return len(p) - 1, nil
				default:
					return 0, nil
				}
			}
			sleep := func(d time.Duration) {
				if scenario != "frozen-clock" {
					now = now.Add(d)
				}
			}
			if flushParts(7, [][]byte{[]byte("fixed private bytes")}, write, func() time.Time { return now }, sleep) || attempts > flushMaxAttempts || now.Sub(time.Unix(1, 0)) > flushBudget {
				t.Fatal("failed private flush passed or exceeded finite bounds")
			}
			if scenario == "frozen-clock" && attempts != flushMaxAttempts {
				t.Fatal("frozen clock did not exhaust the exact attempt ceiling")
			}
			if scenario == "interrupted" && attempts != flushMaxEINTR+1 {
				t.Fatal("interruption refusal escaped its exact retry allowance")
			}
		})
	}
}

func TestFlushFinalSuccessfulWriteAtDeadlineRefuses(t *testing.T) {
	for _, elapsed := range []time.Duration{flushBudget, flushBudget + time.Nanosecond} {
		now := time.Unix(1, 0)
		attempts := 0
		write := func(_ int, p []byte) (int, error) {
			attempts++
			now = now.Add(elapsed)
			return len(p), nil
		}
		if flushParts(7, [][]byte{[]byte("final full private write")}, write, func() time.Time { return now }, func(time.Duration) { t.Fatal("unexpected retry") }) || attempts != 1 {
			t.Fatal("final full write at or beyond deadline passed")
		}
	}
}

func TestFlushRealFullPipeRefusesWithinFiniteBudget(t *testing.T) {
	_, writer, _ := testPipe(t, true)
	chunk := make([]byte, flushChunkBytes)
	full := false
	for attempts := 0; attempts < flushMaxAttempts; attempts++ {
		if _, err := unix.Write(int(writer.Fd()), chunk); err == unix.EAGAIN {
			full = true
			break
		} else if err != nil {
			t.Fatal("owned full-pipe fixture unavailable")
		}
	}
	if !full {
		t.Fatal("owned fixture did not reach bounded full-pipe state")
	}
	started := time.Now()
	if flushProfile(int(writer.Fd()), []byte("synthetic complete body")) || time.Since(started) > 2*time.Second {
		t.Fatal("full nonblocking pipe accepted a frame or blocked beyond finite allowance")
	}
}
