// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installerprofile

import (
	"bytes"
	"io"
	"testing"
)

func TestSessionJoinsBeforeFlushAndClosesOnce(t *testing.T) {
	stopped, closed, flushed := 0, 0, 0
	var writer io.Writer
	s := startSession(func(w io.Writer) error { writer = w; return nil }, func() {
		stopped++
		if _, err := writer.Write([]byte("finalized synthetic diagnostic")); err != nil {
			t.Fatal("final memory write refused")
		}
	}, func(b []byte) bool {
		flushed++
		if stopped != 1 || !bytes.Equal(b, []byte("finalized synthetic diagnostic")) {
			t.Fatal("flush preceded joined finalization")
		}
		return true
	}, func() { closed++ })
	if s == nil || !s.Stop() || !s.Stop() || stopped != 1 || flushed != 1 || closed != 1 || s.buffer.bytes != nil {
		t.Fatal("owned diagnostic cleanup was not exact/idempotent")
	}
}

func TestSessionStartFailureDoesNotStopAnotherProfiler(t *testing.T) {
	closed := 0
	s := startSession(func(io.Writer) error { return errIncomplete }, func() {
		t.Fatal("failed start stopped another profiler")
	}, func([]byte) bool { t.Fatal("failed start flushed output"); return true }, func() { closed++ })
	if s != nil || s.Stop() || closed != 1 {
		t.Fatal("failed start adopted a session or lost owned cleanup")
	}
}

func TestSessionOverflowNeverFlushesPartialProfile(t *testing.T) {
	closed, stopped := 0, 0
	s := startSession(func(w io.Writer) error {
		_, err := w.Write(make([]byte, MaxProfileBytes+1))
		if err != errIncomplete {
			t.Fatal("capture overflow not observed")
		}
		return nil
	}, func() { stopped++ }, func([]byte) bool {
		t.Fatal("overflowed partial diagnostic was flushed")
		return true
	}, func() { closed++ })
	if s == nil || s.Stop() || stopped != 1 || closed != 1 {
		t.Fatal("overflow cleanup changed owned session semantics")
	}
}
