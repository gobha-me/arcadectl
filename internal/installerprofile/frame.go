// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installerprofile

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
)

const frameMagic = "ARCADECPUPROF001"
const frameHeaderBytes = 16 + 8 + sha256.Size

// MaxFrameBytes is a separate wire bound including the fixed envelope.
const MaxFrameBytes = MaxProfileBytes + frameHeaderBytes

func frameHeader(body []byte) ([frameHeaderBytes]byte, error) {
	var header [frameHeaderBytes]byte
	if len(body) == 0 || len(body) > MaxProfileBytes {
		return header, errIncomplete
	}
	copy(header[:16], frameMagic)
	binary.LittleEndian.PutUint64(header[16:24], uint64(len(body)))
	digest := sha256.Sum256(body)
	copy(header[24:], digest[:])
	return header, nil
}

// DecodeFrame verifies exact bounded framing and returns detached bytes.
// It does NOT validate gzip, CPU-profile semantics, privacy, source identity,
// command completion, or a successful installer operation. Those are separate
// mandatory harness custody checks before retaining or reporting evidence.
func DecodeFrame(frame []byte) ([]byte, error) {
	if len(frame) < frameHeaderBytes || len(frame) > MaxFrameBytes || !bytes.Equal(frame[:16], []byte(frameMagic)) {
		return nil, errIncomplete
	}
	length := binary.LittleEndian.Uint64(frame[16:24])
	if length == 0 || length > MaxProfileBytes || length != uint64(len(frame)-frameHeaderBytes) {
		return nil, errIncomplete
	}
	body := frame[frameHeaderBytes:]
	digest := sha256.Sum256(body)
	if !bytes.Equal(frame[24:frameHeaderBytes], digest[:]) {
		return nil, errIncomplete
	}
	return bytes.Clone(body), nil
}
