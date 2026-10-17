// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installerprofile

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

func TestMatrixFramesHaveSeparateClosedStatusAndCoverage(t *testing.T) {
	for _, notStarted := range []bool{false, true} {
		body := []byte("synthetic owned CPU framing")
		if notStarted {
			body = nil
		}
		parts, err := matrixFrameParts(body, notStarted)
		if err != nil {
			t.Fatal("matrix frame unavailable")
		}
		wire := bytes.Join(parts, nil)
		decoded, err := decodeMatrixFrame(wire)
		if notStarted {
			if decoded != nil || !FirstUpgradeMatrixNotStarted(err) {
				t.Fatal("not-started fabricated CPU")
			}
		} else {
			if err != nil || !bytes.Equal(decoded, body) {
				t.Fatal("matrix profile frame refused")
			}
			decoded[0] ^= 1
			if wire[frameHeaderBytes+1] != body[0] {
				t.Fatal("matrix decoder exposed raw backing bytes")
			}
		}
		for _, prefix := range []bool{false, true} {
			if value, err := decodeFrameForProtocol(wire, prefix); value != nil || err != errIncomplete {
				t.Fatal("matrix acquired full/prefix scope")
			}
			header, err := frameHeaderForProtocol([]byte("synthetic full/prefix"), prefix)
			if err != nil {
				t.Fatal("legacy frame unavailable")
			}
			if value, err := decodeMatrixFrame(append(header[:], []byte("synthetic full/prefix")...)); value != nil || err != errIncomplete {
				t.Fatal("legacy acquired matrix scope")
			}
		}
		for _, edit := range []func([]byte) []byte{
			func(b []byte) []byte { b[0] ^= 1; return b },
			func(b []byte) []byte { b[16] ^= 1; return b },
			func(b []byte) []byte { b[24] ^= 1; return b },
			func(b []byte) []byte { return b[:len(b)-1] },
			func(b []byte) []byte { return append(b, 0) },
			func(b []byte) []byte {
				b[frameHeaderBytes] = 2
				digest := sha256.Sum256(b[frameHeaderBytes:])
				copy(b[24:frameHeaderBytes], digest[:])
				return b
			},
		} {
			if value, err := decodeMatrixFrame(edit(bytes.Clone(wire))); value != nil || err != errIncomplete {
				t.Fatal("malformed matrix envelope accepted")
			}
		}
	}
	for _, input := range []struct {
		body       []byte
		notStarted bool
	}{{nil, false}, {[]byte("extra"), true}, {make([]byte, MaxProfileBytes+1), false}} {
		if _, err := matrixFrameParts(input.body, input.notStarted); err != errIncomplete {
			t.Fatal("invalid matrix payload accepted")
		}
	}
	// Correct digest/length cannot make status=1 without CPU into not-started.
	parts, _ := matrixFrameParts(nil, true)
	wire := bytes.Join(parts, nil)
	wire[frameHeaderBytes] = 1
	digest := sha256.Sum256(wire[frameHeaderBytes:])
	copy(wire[24:frameHeaderBytes], digest[:])
	binary.LittleEndian.PutUint64(wire[16:24], 1)
	if body, err := decodeMatrixFrame(wire); body != nil || err != errIncomplete {
		t.Fatal("empty CPU accepted")
	}
	maximum := bytes.Repeat([]byte{0x73}, MaxProfileBytes)
	parts, err := matrixFrameParts(maximum, false)
	if err != nil {
		t.Fatal("exact profile cap refused")
	}
	wire = bytes.Join(parts, nil)
	if body, err := decodeMatrixFrame(wire); err != nil || !bytes.Equal(body, maximum) || len(wire) != MaxFrameBytes+1 {
		t.Fatal("matrix changed the exact raw profile cap")
	}
	wire[frameHeaderBytes] = 0
	digest = sha256.Sum256(wire[frameHeaderBytes:])
	copy(wire[24:frameHeaderBytes], digest[:])
	if body, err := decodeMatrixFrame(wire); body != nil || err != errIncomplete {
		t.Fatal("rehashed nonempty not-started payload accepted")
	}
}
