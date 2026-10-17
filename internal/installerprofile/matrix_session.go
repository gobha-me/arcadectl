// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installerprofile

import (
	"context"
	"io"
	"sync"
	"time"
)

// FirstUpgradeMatrixRequestedNanoseconds is a requested process-wide sampling
// interval, not a hard stop deadline, thread-exclusive matrix cost, whole-command
// coverage, or a claim about the eventual slowest/failed matrix invocation.
const FirstUpgradeMatrixRequestedNanoseconds uint64 = uint64(30 * time.Second)

type matrixContextKey struct{}

// WithFirstUpgradeMatrix attaches only the concrete deferred diagnostic handle
// to an already parsed upgrade command. It grants no installation authority.
func WithFirstUpgradeMatrix(ctx context.Context, command string, s *Session) context.Context {
	if ctx == nil || command != "upgrade" || s == nil || s.matrix == nil {
		return ctx
	}
	return context.WithValue(ctx, matrixContextKey{}, s)
}

// BeginFirstUpgradeMatrix claims ordinal one across the command, including
// concurrent or subsequent drivers. The caller additionally checks the validated
// lifecycle mode and calls this only after successful original-fixture setup.
// A failed Start permanently consumes the claim; diagnostics never retry it.
func BeginFirstUpgradeMatrix(ctx context.Context) *Session {
	if ctx == nil || ctx.Err() != nil {
		return nil
	}
	s, _ := ctx.Value(matrixContextKey{}).(*Session)
	if s == nil || s.matrix == nil || !s.matrix.begin() {
		return nil
	}
	return s
}

// RequestMatrixStop never joins pprof conversion/flush under the matrix mutex.
// Only the first claimant gets a handle; later drivers cannot stop its window.
// Command exit calls Stop to join the same single finalizer.
func (s *Session) RequestMatrixStop() {
	if s != nil && s.matrix != nil {
		s.matrix.requestStop()
	}
}

type matrixState uint8

const (
	matrixPending matrixState = iota
	matrixStarting
	matrixRunning
	matrixFinalizing
	matrixFinalized
)

type matrixSession struct {
	mu            sync.Mutex
	state         matrixState
	stopRequested bool
	buffer        *profileBuffer
	start         func(io.Writer) error
	stop          func()
	flush         func([]byte, bool) bool
	close         func()
	schedule      func(time.Duration, func()) func() bool
	cancel        func() bool
	done          chan struct{}
	complete      bool // Read only after joining done.
}

func newMatrixSession(start func(io.Writer) error, stop func(), flush func([]byte, bool) bool, close func(), schedule func(time.Duration, func()) func() bool) *Session {
	return &Session{matrix: &matrixSession{start: start, stop: stop, flush: flush, close: close, schedule: schedule, done: make(chan struct{})}}
}

func (m *matrixSession) begin() bool {
	m.mu.Lock()
	if m.state != matrixPending {
		m.mu.Unlock()
		return false
	}
	m.state = matrixStarting
	m.mu.Unlock()
	buffer := newProfileBuffer()
	started := m.start(buffer) == nil
	m.mu.Lock()
	m.buffer = buffer
	if !started || m.stopRequested {
		m.state = matrixFinalizing
		m.mu.Unlock()
		go m.finish(started, false)
		return true
	}
	m.state = matrixRunning
	m.mu.Unlock()
	// Scheduling is outside mu: even an already-dispatched callback or command
	// exit racing timer installation cannot deadlock or acquire descriptor work.
	cancel := m.schedule(time.Duration(FirstUpgradeMatrixRequestedNanoseconds), m.requestStop)
	m.mu.Lock()
	if m.state == matrixRunning {
		m.cancel = cancel
		m.mu.Unlock()
	} else {
		m.mu.Unlock()
		cancel()
	}
	return true
}

func (m *matrixSession) requestStop() {
	m.mu.Lock()
	switch m.state {
	case matrixPending:
		m.state = matrixFinalizing // Exit before entry permanently prevents Start.
		m.mu.Unlock()
		go m.finish(false, true)
	case matrixStarting:
		m.stopRequested = true // Start's owner completes this transition.
		m.mu.Unlock()
	case matrixRunning:
		m.state = matrixFinalizing
		m.mu.Unlock()
		go m.finish(true, false)
	default:
		m.mu.Unlock()
	}
}

func (m *matrixSession) finish(started, notStarted bool) {
	m.mu.Lock()
	cancel := m.cancel
	m.cancel = nil
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if started {
		m.stop() // Joins only our successfully started writer, never another profiler.
		if !m.buffer.overflow && len(m.buffer.bytes) != 0 {
			m.complete = m.flush(m.buffer.bytes, false)
		}
	} else if notStarted {
		m.complete = m.flush(nil, true)
	}
	if m.buffer != nil {
		m.buffer.bytes = nil
	}
	m.close()
	m.mu.Lock()
	m.state = matrixFinalized
	m.mu.Unlock()
	close(m.done)
}
