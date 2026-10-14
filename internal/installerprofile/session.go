// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installerprofile

import (
	"io"
	"sync"
)

// Session owns only a successfully started private profile. Its methods never
// grant installation authority or write to normal command output.
type Session struct {
	once     sync.Once
	buffer   *profileBuffer
	stop     func()
	flush    func([]byte) bool
	close    func()
	complete bool
}

func startSession(start func(io.Writer) error, stop func(), flush func([]byte) bool, close func()) *Session {
	buffer := newProfileBuffer()
	if start(buffer) != nil {
		close()
		return nil // In particular, never stop an already-active other profiler.
	}
	return &Session{buffer: buffer, stop: stop, flush: flush, close: close}
}

// Stop joins the owned profile writer before inspecting its memory sink, then
// attempts a separately bounded nonblocking flush. It is nil-safe and
// idempotent. False means incomplete diagnostics, not an installer failure.
// The 500ms flush bound does not bound pprof's internal conversion CPU work.
func (s *Session) Stop() bool {
	if s == nil {
		return false
	}
	s.once.Do(func() {
		defer s.close()
		s.stop()
		if !s.buffer.overflow && len(s.buffer.bytes) != 0 {
			s.complete = s.flush(s.buffer.bytes)
		}
		s.buffer.bytes = nil
	})
	return s.complete
}
