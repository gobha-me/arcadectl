// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installerprofile

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

const matrixFrameMagic = "ARCADECPUMTX0001"

var errMatrixNotStarted = errors.New("first upgrade matrix capture not started")

// FirstUpgradeMatrixNotStarted recognizes only a complete, independently framed
// not-started record. It must still be gated on normal child process exit before
// attribution; it is never raw CPU input or an invented zero-duration profile.
func FirstUpgradeMatrixNotStarted(err error) bool { return err == errMatrixNotStarted }

func matrixFrameParts(body []byte, notStarted bool) ([][]byte, error) {
	if len(body) > MaxProfileBytes || notStarted && len(body) != 0 || !notStarted && len(body) == 0 {
		return nil, errIncomplete
	}
	status := []byte{1}
	if notStarted {
		status[0] = 0
	}
	header := make([]byte, frameHeaderBytes)
	copy(header[:16], matrixFrameMagic)
	binary.LittleEndian.PutUint64(header[16:24], uint64(len(body)+1))
	hash := sha256.New()
	_, _ = hash.Write(status)
	_, _ = hash.Write(body)
	copy(header[24:], hash.Sum(nil))
	return [][]byte{header, status, body}, nil
}

func decodeMatrixFrame(frame []byte) ([]byte, error) {
	if len(frame) < frameHeaderBytes+1 || len(frame) > MaxFrameBytes+1 || !bytes.Equal(frame[:16], []byte(matrixFrameMagic)) {
		return nil, errIncomplete
	}
	length := binary.LittleEndian.Uint64(frame[16:24])
	if length != uint64(len(frame)-frameHeaderBytes) {
		return nil, errIncomplete
	}
	payload := frame[frameHeaderBytes:]
	digest := sha256.Sum256(payload)
	if !bytes.Equal(frame[24:frameHeaderBytes], digest[:]) {
		return nil, errIncomplete
	}
	if payload[0] == 0 && len(payload) == 1 {
		return nil, errMatrixNotStarted
	}
	if payload[0] != 1 || len(payload) == 1 {
		return nil, errIncomplete
	}
	return bytes.Clone(payload[1:]), nil
}
