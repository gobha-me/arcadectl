// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package workerio

import (
	"bytes"
	"errors"
	"testing"
)

type failingWriter struct {
	count int
	err   error
	calls int
}

func (writer *failingWriter) Write([]byte) (int, error) {
	writer.calls++
	return writer.count, writer.err
}

func TestDrainingWriterPreservesSuccess(t *testing.T) {
	t.Parallel()
	var destination bytes.Buffer
	writer := NewDrainingWriter(&destination)
	if count, err := writer.Write([]byte("world")); count != 5 || err != nil || writer.Failed() || destination.String() != "world" {
		t.Fatalf("successful stream changed: count=%d err=%v failed=%t output=%q", count, err, writer.Failed(), destination.String())
	}
}

func TestDrainingWriterNeverRevivesFailedDestination(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name  string
		count int
		err   error
	}{
		{"error", 0, errors.New("credential-canary")},
		{"partial-error", 2, errors.New("credential-canary")},
		{"short-write", 2, nil},
		{"invalid-count", 9, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			destination := &failingWriter{count: test.count, err: test.err}
			writer := NewDrainingWriter(destination)
			for attempt := 0; attempt < 3; attempt++ {
				if count, err := writer.Write([]byte("world")); count != 5 || err != nil || !writer.Failed() {
					t.Fatalf("must drain without passing errors to pipe copier: count=%d err=%v failed=%t", count, err, writer.Failed())
				}
			}
			if destination.calls != 1 {
				t.Fatalf("failed destination was retried %d times", destination.calls)
			}
		})
	}
	writer := NewDrainingWriter(nil)
	if count, err := writer.Write([]byte("world")); count != 5 || err != nil || !writer.Failed() {
		t.Fatal("missing destination must fail closed while draining")
	}
}
