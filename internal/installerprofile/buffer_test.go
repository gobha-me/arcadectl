// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installerprofile

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestBufferExactCapAndStickyOverflow(t *testing.T) {
	b := newProfileBuffer()
	input := bytes.Repeat([]byte{0x71}, MaxProfileBytes)
	if n, err := b.Write(input); n != len(input) || err != nil || b.overflow || cap(b.bytes) != MaxProfileBytes {
		t.Fatal("exact diagnostic cap refused or widened")
	}
	if n, err := b.Write([]byte{0x72}); n != 0 || err != errIncomplete || !b.overflow || len(b.bytes) != MaxProfileBytes {
		t.Fatal("overflow was not latched without extending captured output")
	}
	if n, err := b.Write(nil); n != 0 || err != errIncomplete || cap(b.bytes) != MaxProfileBytes {
		t.Fatal("overflow could be cleared or allocate beyond the cap")
	}
	if !bytes.Equal(b.bytes, input) {
		t.Fatal("overflow changed earlier private bytes")
	}
}

func TestFrameExactIntegrityAndDetachment(t *testing.T) {
	body := []byte("synthetic framing input, not a CPU profile")
	header, err := frameHeader(body)
	if err != nil {
		t.Fatal("fixed framing unavailable")
	}
	frame := append(header[:], body...)
	decoded, err := DecodeFrame(frame)
	if err != nil || !bytes.Equal(decoded, body) {
		t.Fatal("exact frame refused")
	}
	decoded[0] ^= 1
	if frame[frameHeaderBytes] != body[0] {
		t.Fatal("decoder exposed frame backing storage")
	}
	for _, mutate := range []func([]byte) []byte{
		func(b []byte) []byte { return b[:frameHeaderBytes-1] },
		func(b []byte) []byte { b[0] ^= 1; return b },
		func(b []byte) []byte { binary.LittleEndian.PutUint64(b[16:24], 0); return b },
		func(b []byte) []byte { binary.LittleEndian.PutUint64(b[16:24], MaxProfileBytes+1); return b },
		func(b []byte) []byte { b[24] ^= 1; return b },
		func(b []byte) []byte { b[len(b)-1] ^= 1; return b },
		func(b []byte) []byte { return b[:len(b)-1] },
		func(b []byte) []byte { return append(b, 0) },
	} {
		if got, err := DecodeFrame(mutate(bytes.Clone(frame))); got != nil || err != errIncomplete {
			t.Fatal("malformed, truncated or trailing frame accepted")
		}
	}
	if _, err := frameHeader(nil); err != errIncomplete {
		t.Fatal("empty output accepted")
	}
}
