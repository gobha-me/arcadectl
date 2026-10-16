// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package installerprofile

import (
	"io"
	"os"
	"os/exec"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

const drainBudget = time.Second

// Capture owns a single command's explicit private descriptor pair and drain.
// It never reads command arguments/environment/output or discovers file paths.
// Construct immediately before Run; Run or Close must be called on every path.
type Capture struct {
	reader, writer, control *os.File
	claimed                 atomic.Bool
	done                    chan struct{}
	frame                   []byte // Written only by drain, inspected only after its join.
	readErr                 error
	prefix                  bool
}

func NewCapture() (*Capture, error) {
	return newCapture(false)
}

// NewPrefixCapture requests only the first sampling interval of the current
// executable. It never claims whole-command coverage, hard timer precision or
// representativeness of later admission work. Old full-profile framing remains
// distinct and cannot be decoded as a prefix (or vice versa).
func NewPrefixCapture() (*Capture, error) {
	return newCapture(true)
}

func newCapture(prefix bool) (*Capture, error) {
	var pair [2]int
	if unix.Pipe2(pair[:], unix.O_CLOEXEC|unix.O_NONBLOCK) != nil {
		return nil, errIncomplete
	}
	reader := os.NewFile(uintptr(pair[0]), "owned-installer-cpu-reader")
	writer := os.NewFile(uintptr(pair[1]), "owned-installer-cpu-writer")
	var identity unix.Stat_t
	if unix.Fstat(pair[1], &identity) != nil {
		_ = reader.Close()
		_ = writer.Close()
		return nil, errIncomplete
	}
	control, err := newControlForProtocol(identity, prefix)
	if err != nil {
		_ = reader.Close()
		_ = writer.Close()
		return nil, errIncomplete
	}
	c := &Capture{reader: reader, writer: writer, control: control, done: make(chan struct{}), prefix: prefix}
	go c.drain() // Before Start; pollable reads are interruptible by Close.
	return c, nil
}

func (c *Capture) drain() {
	defer close(c.done)
	frame := make([]byte, 0, MaxFrameBytes)
	var scratch [32 * 1024]byte
	overflow := false
	for {
		n, err := c.reader.Read(scratch[:])
		if n > 0 && !overflow {
			if n > MaxFrameBytes-len(frame) {
				overflow, frame = true, nil
			} else {
				frame = append(frame, scratch[:n]...)
			}
		}
		if err != nil {
			if err != io.EOF || overflow {
				c.readErr = errIncomplete
			} else {
				c.frame = frame
			}
			return
		}
		// Overflow is sticky, but keep draining/discarding while the command
		// runs so diagnostics do not block or change its normal output/result.
	}
}

// Run preserves Start/Wait errors and normal stdio. The second error concerns
// diagnostics only. Returned bytes have exact framing but are NOT yet validated
// CPU data or safe to retain/report: a separate bounded privacy parser is required.
// No caller, fixture, test or job timeout is extended by diagnostic capture.
func (c *Capture) Run(command *exec.Cmd) (body []byte, diagnosticErr, commandErr error) {
	if c == nil || !c.claimed.CompareAndSwap(false, true) {
		return nil, errIncomplete, errIncomplete
	}
	if command == nil || len(command.ExtraFiles) != 0 || command.Process != nil {
		c.release(false)
		return nil, errIncomplete, errIncomplete
	}
	command.ExtraFiles = []*os.File{c.control, c.writer} // Exactly child FD3/4.
	commandErr = command.Start()
	_ = c.control.Close()
	_ = c.writer.Close() // After Start copied, or refused copying, the pair.
	if commandErr == nil {
		commandErr = command.Wait()
	}
	c.release(true)
	if c.readErr != nil {
		return nil, errIncomplete, commandErr
	}
	body, diagnosticErr = decodeFrameForProtocol(c.frame, c.prefix)
	c.frame = nil
	return body, diagnosticErr, commandErr
}

func (c *Capture) release(finish bool) {
	_ = c.control.Close()
	_ = c.writer.Close()
	if finish {
		// Only the private drain gets a deadline, after the command has exited.
		// A descendant holding FD4 open cannot indefinitely delay the harness.
		if c.reader.SetReadDeadline(time.Now().Add(drainBudget)) != nil {
			_ = c.reader.Close()
		}
	} else {
		_ = c.reader.Close()
	}
	<-c.done
	_ = c.reader.Close()
}

// Close aborts an unused capture and joins its drain. Once Run owns the capture,
// Close is a no-op; cancellation remains the command context's responsibility.
func (c *Capture) Close() {
	if c != nil && c.claimed.CompareAndSwap(false, true) {
		c.release(false)
	}
}
