// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installerprofile

import (
	"bytes"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPrefixTimerAndCommandExitShareOneOwnedFinalization(t *testing.T) {
	for _, timerFirst := range []bool{false, true} {
		t.Run(map[bool]string{false: "exit-first", true: "timer-first"}[timerFirst], func(t *testing.T) {
			var stopped, closed, flushed, cancelled atomic.Int32
			var writer io.Writer
			entered, release := make(chan struct{}), make(chan struct{})
			s := startSession(func(w io.Writer) error { writer = w; return nil }, func() {
				stopped.Add(1)
				close(entered)
				<-release
				if _, err := writer.Write([]byte("owned finalized prefix")); err != nil {
					t.Error("joined prefix write refused")
				}
			}, func(body []byte) bool {
				flushed.Add(1)
				return bytes.Equal(body, []byte("owned finalized prefix"))
			}, func() { closed.Add(1) })
			var callback func()
			s.armPrefixStop(func(d time.Duration, finish func()) func() bool {
				if d != 30*time.Second || uint64(d) != PrefixCaptureRequestedNanoseconds {
					t.Fatal("prefix requested an arbitrary window")
				}
				callback = finish
				return func() bool { cancelled.Add(1); return !timerFirst }
			})
			var group sync.WaitGroup
			group.Go(func() {
				if timerFirst {
					callback()
				} else if !s.Stop() {
					t.Error("exit finalization failed")
				}
			})
			<-entered
			for range 16 {
				group.Go(func() {
					if !s.Stop() {
						t.Error("concurrent finalization lost joined result")
					}
				})
			}
			group.Go(callback) // A timer already dispatched during cancellation.
			close(release)
			group.Wait()
			callback() // A late callback must not touch recycled descriptors.
			if !s.Stop() || stopped.Load() != 1 || flushed.Load() != 1 || closed.Load() != 1 || cancelled.Load() != 1 || s.buffer.bytes != nil {
				t.Fatal("timer/exit race repeated effects or retained raw prefix bytes")
			}
		})
	}
}

func TestPrefixAndFullFramesCannotCrossDecode(t *testing.T) {
	body := []byte("synthetic profile framing operand")
	for _, prefix := range []bool{false, true} {
		header, err := frameHeaderForProtocol(body, prefix)
		if err != nil {
			t.Fatal("owned framing unavailable")
		}
		wire := append(header[:], body...)
		decoded, err := decodeFrameForProtocol(wire, prefix)
		if err != nil || !bytes.Equal(decoded, body) {
			t.Fatal("exact protocol frame refused")
		}
		decoded[0] ^= 1
		if wire[frameHeaderBytes] != body[0] {
			t.Fatal("prefix decoder exposed frame backing bytes")
		}
		if value, err := decodeFrameForProtocol(wire, !prefix); value != nil || err != errIncomplete {
			t.Fatal("prefix/full protocol coverage was interchangeable")
		}
		for _, edit := range []func([]byte) []byte{
			func(b []byte) []byte { b[0] ^= 1; return b },
			func(b []byte) []byte { b[16] ^= 1; return b },
			func(b []byte) []byte { b[24] ^= 1; return b },
			func(b []byte) []byte { b[len(b)-1] ^= 1; return b },
			func(b []byte) []byte { return b[:len(b)-1] },
			func(b []byte) []byte { return append(b, 0) },
		} {
			if value, err := decodeFrameForProtocol(edit(bytes.Clone(wire)), prefix); value != nil || err != errIncomplete {
				t.Fatal("invalid scoped frame accepted")
			}
		}
	}
}
