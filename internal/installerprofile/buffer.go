// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

// Package installerprofile contains private, opt-in installer CPU diagnostics.
// Diagnostic bytes are not installation state or effect authority.
package installerprofile

import "errors"

// MaxProfileBytes bounds compressed captured output, not pprof's internal
// aggregation memory, total process memory, or profile-conversion CPU time.
const MaxProfileBytes = 8 * 1024 * 1024

var errIncomplete = errors.New("private installer profile incomplete")

// Only the pprof writer may mutate this buffer. Its caller must join the owned
// profile writer before inspecting bytes or overflow; no asynchronous Stop.
type profileBuffer struct {
	bytes    []byte
	overflow bool
}

func newProfileBuffer() *profileBuffer {
	return &profileBuffer{bytes: make([]byte, 0, MaxProfileBytes)}
}

func (b *profileBuffer) Write(p []byte) (int, error) {
	if b == nil || b.overflow {
		return 0, errIncomplete
	}
	if len(p) > MaxProfileBytes-len(b.bytes) {
		b.overflow = true
		return 0, errIncomplete
	}
	b.bytes = append(b.bytes, p...)
	return len(p), nil
}
