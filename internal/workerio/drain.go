// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

// Package workerio keeps repository subprocess cleanup reachable when the
// bounded verifier or candidate filesystem rejects its streamed output.
package workerio

import "io"

// DrainingWriter remembers a destination failure without closing the child
// stdout pipe. Subsequent bytes are discarded, never buffered or written to the
// failed destination. The caller must reject the operation when Failed is true.
// It is written by a single stdout-copy goroutine and inspected only after Wait.
type DrainingWriter struct {
	destination io.Writer
	failed      bool
}

func NewDrainingWriter(destination io.Writer) *DrainingWriter {
	return &DrainingWriter{destination: destination}
}

func (writer *DrainingWriter) Write(contents []byte) (int, error) {
	if !writer.failed {
		if writer.destination == nil {
			writer.failed = true
		} else if count, err := writer.destination.Write(contents); err != nil || count != len(contents) {
			writer.failed = true
		}
	}
	return len(contents), nil
}

func (writer *DrainingWriter) Failed() bool { return writer.failed }
