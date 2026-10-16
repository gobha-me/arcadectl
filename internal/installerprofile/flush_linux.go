// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package installerprofile

import (
	"time"

	"golang.org/x/sys/unix"
)

const (
	flushBudget      = 500 * time.Millisecond
	flushChunkBytes  = 4096 // Linux PIPE_BUF; only an already-nonblocking pipe.
	flushMaxAttempts = 8192
	flushMaxEINTR    = 8
)

// The caller must already own and validate fd as the exact nonblocking pipe.
// This flush follows the joined memory-only Stop; it never passes os.File.Write
// to pprof or changes an operation, fixture, test, or job deadline.
func flushProfile(fd int, body []byte) bool {
	return flushProfileForProtocol(fd, body, false)
}

func flushProfileForProtocol(fd int, body []byte, prefix bool) bool {
	header, err := frameHeaderForProtocol(body, prefix)
	if err != nil {
		return false
	}
	return flushParts(fd, [][]byte{header[:], body}, unix.Write, time.Now, time.Sleep)
}

func flushParts(fd int, parts [][]byte, write func(int, []byte) (int, error), now func() time.Time, sleep func(time.Duration)) bool {
	deadline := now().Add(flushBudget)
	attempts, interrupted := 0, 0
	for _, part := range parts {
		for len(part) != 0 {
			if attempts >= flushMaxAttempts || !now().Before(deadline) {
				return false
			}
			chunk := part
			if len(chunk) > flushChunkBytes {
				chunk = chunk[:flushChunkBytes]
			}
			attempts++
			n, err := write(fd, chunk)
			if !now().Before(deadline) {
				return false // Even a final full write is not a timely flush.
			}
			if n > 0 && (err != nil || n != len(chunk)) {
				return false // A partial envelope cannot be treated as complete.
			}
			if err == unix.EINTR {
				interrupted++
				if interrupted > flushMaxEINTR {
					return false
				}
				continue
			}
			if err == unix.EAGAIN {
				remaining := deadline.Sub(now())
				if remaining <= 0 {
					return false
				}
				pause := time.Millisecond
				if remaining < pause {
					pause = remaining
				}
				sleep(pause)
				continue
			}
			if err != nil || n != len(chunk) {
				return false
			}
			part = part[n:]
		}
	}
	return now().Before(deadline)
}
