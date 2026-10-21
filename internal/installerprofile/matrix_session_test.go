// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installerprofile

import (
	"bytes"
	"context"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestMatrixExitBeforeTriggerAndExactCommandCapability(t *testing.T) {
	var flushed, closed atomic.Int32
	s := newMatrixSession(func(io.Writer) error { t.Error("unreached matrix started"); return nil }, func() { t.Error("unowned profiler stopped") }, func(body []byte, notStarted bool) bool {
		flushed.Add(1)
		return notStarted && body == nil
	}, func() { closed.Add(1) }, func(time.Duration, func()) func() bool { t.Error("unreached timer armed"); return nil })
	for _, command := range []string{"inspect", "install", "rollback", "uninstall", "resume", "enroll-baseline", "Upgrade", ""} {
		if BeginFirstUpgradeMatrix(WithFirstUpgradeMatrix(t.Context(), command, s)) != nil {
			t.Fatal("wrong command acquired capture capability")
		}
	}
	for _, ctx := range []context.Context{nil, t.Context(), WithFirstUpgradeMatrix(t.Context(), "upgrade", nil), WithFirstUpgradeMatrix(t.Context(), "upgrade", &Session{})} {
		if BeginFirstUpgradeMatrix(ctx) != nil {
			t.Fatal("missing/wrong purpose acquired capture capability")
		}
	}
	ctx := WithFirstUpgradeMatrix(t.Context(), "upgrade", s)
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if BeginFirstUpgradeMatrix(cancelled) != nil || !s.Stop() || !s.Stop() || BeginFirstUpgradeMatrix(ctx) != nil || flushed.Load() != 1 || closed.Load() != 1 {
		t.Fatal("exit-before-entry failed permanent, once-only not-started semantics")
	}
}

func TestMatrixFirstClaimAcrossConcurrentDriversAndAsyncReturn(t *testing.T) {
	var starts, stops, flushes, closes, cancels atomic.Int32
	var writer io.Writer
	var timer func()
	entered, release := make(chan struct{}), make(chan struct{})
	s := newMatrixSession(func(w io.Writer) error { starts.Add(1); writer = w; return nil }, func() {
		stops.Add(1)
		close(entered)
		<-release
		_, _ = writer.Write([]byte("owned matrix profile"))
	}, func(body []byte, notStarted bool) bool {
		flushes.Add(1)
		return !notStarted && bytes.Equal(body, []byte("owned matrix profile"))
	}, func() { closes.Add(1) }, func(d time.Duration, callback func()) func() bool {
		if d != 30*time.Second || uint64(d) != FirstUpgradeMatrixRequestedNanoseconds {
			t.Error("arbitrary matrix window")
		}
		timer = callback
		return func() bool { cancels.Add(1); return true }
	})
	ctx := WithFirstUpgradeMatrix(t.Context(), "upgrade", s)
	var group sync.WaitGroup
	var owners atomic.Int32
	for range 32 {
		group.Go(func() {
			if handle := BeginFirstUpgradeMatrix(ctx); handle != nil {
				owners.Add(1)
			}
		})
	}
	group.Wait()
	if owners.Load() != 1 || starts.Load() != 1 || timer == nil {
		t.Fatal("concurrent drivers did not share ordinal one")
	}
	s.RequestMatrixStop() // Must return while conversion is deliberately blocked.
	<-entered
	if BeginFirstUpgradeMatrix(ctx) != nil {
		t.Fatal("later driver restarted the stopped window")
	}
	for range 16 {
		group.Go(func() { timer(); s.RequestMatrixStop() })
		group.Go(func() {
			if !s.Stop() {
				t.Error("concurrent join lost flush result")
			}
		})
	}
	close(release)
	group.Wait()
	timer() // Dispatched callback after close cannot touch recycled descriptors.
	if !s.Stop() || starts.Load() != 1 || stops.Load() != 1 || flushes.Load() != 1 || closes.Load() != 1 || cancels.Load() != 1 || s.matrix.buffer.bytes != nil {
		t.Fatal("timer/return/exit repeated ownership or retained raw profile")
	}
}

func TestMatrixExitRacingStartAndStartFailure(t *testing.T) {
	for _, success := range []bool{false, true} {
		t.Run(map[bool]string{false: "failed-start", true: "started"}[success], func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			var stopped, closed, flushed atomic.Int32
			var writer io.Writer
			s := newMatrixSession(func(w io.Writer) error {
				writer = w
				close(entered)
				<-release
				if !success {
					return errIncomplete
				}
				return nil
			}, func() { stopped.Add(1); _, _ = writer.Write([]byte("joined owned writer")) }, func(body []byte, notStarted bool) bool {
				flushed.Add(1)
				return !notStarted && len(body) != 0
			}, func() { closed.Add(1) }, func(time.Duration, func()) func() bool { t.Error("exit-racing start armed timer"); return nil })
			ctx := WithFirstUpgradeMatrix(t.Context(), "upgrade", s)
			begun := make(chan *Session, 1)
			go func() { begun <- BeginFirstUpgradeMatrix(ctx) }()
			<-entered
			s.RequestMatrixStop()
			joined := make(chan bool, 1)
			go func() { joined <- s.Stop() }()
			select {
			case <-joined:
				t.Fatal("exit did not join ongoing Start")
			default:
			}
			close(release)
			if <-begun != s || <-joined != success || BeginFirstUpgradeMatrix(ctx) != nil || closed.Load() != 1 {
				t.Fatal("Start/exit race lost permanent claim or single close")
			}
			want := int32(0)
			if success {
				want = 1
			}
			if stopped.Load() != want || flushed.Load() != want {
				t.Fatal("failed Start stopped another profiler or invented not-started")
			}
		})
	}
}

func TestMatrixTimerInstallationRacingReturn(t *testing.T) {
	var closed, cancelled atomic.Int32
	entered, release := make(chan struct{}), make(chan struct{})
	var writer io.Writer
	s := newMatrixSession(func(w io.Writer) error { writer = w; return nil }, func() { _, _ = writer.Write([]byte("owned")) }, func([]byte, bool) bool { return true }, func() { closed.Add(1) }, func(_ time.Duration, callback func()) func() bool {
		close(entered)
		<-release
		callback() // Already dispatched at installation, after command exit.
		return func() bool { cancelled.Add(1); return false }
	})
	finished := make(chan *Session, 1)
	go func() { finished <- BeginFirstUpgradeMatrix(WithFirstUpgradeMatrix(t.Context(), "upgrade", s)) }()
	<-entered
	if !s.Stop() {
		t.Fatal("timer installation blocked command-exit finalization")
	}
	close(release)
	if <-finished != s || !s.Stop() || closed.Load() != 1 || cancelled.Load() != 1 {
		t.Fatal("late timer installation touched closed ownership")
	}
}

func TestMatrixOverflowAndFailedFlushNeverBecomeComplete(t *testing.T) {
	for _, overflow := range []bool{false, true} {
		var writer io.Writer
		var flushed, closed atomic.Int32
		s := newMatrixSession(func(w io.Writer) error { writer = w; return nil }, func() {
			body := []byte("owned")
			if overflow {
				body = make([]byte, MaxProfileBytes+1)
			}
			_, _ = writer.Write(body)
		}, func([]byte, bool) bool { flushed.Add(1); return false }, func() { closed.Add(1) }, func(time.Duration, func()) func() bool { return func() bool { return true } })
		if BeginFirstUpgradeMatrix(WithFirstUpgradeMatrix(t.Context(), "upgrade", s)) != s || s.Stop() || closed.Load() != 1 || overflow && flushed.Load() != 0 || !overflow && flushed.Load() != 1 || s.matrix.buffer.bytes != nil {
			t.Fatal("overflow/flush failure lost incomplete status or raw cleanup")
		}
	}
}
