// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"encoding/binary"
	"io"
	"sync/atomic"
)

const forwardWireBudget = 1024 * 1024
const forwardFrameBudget = 256

// forwardFrames checks advertised lengths BEFORE the codec can allocate. It
// retains at most one 64 KiB frame and never releases unsolicited stream/header
// frames to a decompressor. Only two fixed acknowledgements can contain headers.
type forwardFrames struct {
	reader        io.Reader
	buffer        []byte
	opened        atomic.Uint32
	acked, fin    uint32 // owned by the sole reader
	bytes, frames int
}

func streamBit(id uint32) uint32 {
	switch id {
	case 1:
		return 1
	case 3:
		return 2
	}
	return 0
}

func (g *forwardFrames) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(g.buffer) == 0 {
		if err := g.frame(); err != nil {
			return 0, ErrActivation
		}
	}
	n := copy(p, g.buffer)
	g.buffer = g.buffer[n:]
	return n, nil
}

func (g *forwardFrames) frame() error {
	var header [8]byte
	if _, err := io.ReadFull(g.reader, header[:]); err != nil {
		return ErrActivation
	}
	word := binary.BigEndian.Uint32(header[:4])
	flags := header[4]
	length := int(header[5])<<16 | int(header[6])<<8 | int(header[7])
	g.frames++
	g.bytes += 8 + length
	if g.frames > forwardFrameBudget || g.bytes > forwardWireBudget {
		return ErrActivation
	}
	control := word&0x80000000 != 0
	kind := uint16(word)
	if !control {
		bit := streamBit(word)
		if bit == 0 || g.opened.Load()&bit == 0 || g.acked&bit == 0 || g.fin&bit != 0 || flags&^byte(1) != 0 || length > 65536 || word == 1 && length != 0 {
			return ErrActivation
		}
		if flags == 1 {
			g.fin |= bit
		}
	} else {
		if word>>16 != 0x8003 || length > 4096 {
			return ErrActivation
		}
		switch kind {
		case 2:
			if flags != 0 || length < 4 {
				return ErrActivation
			}
		case 4:
			if flags&^byte(1) != 0 || length < 4 {
				return ErrActivation
			}
		case 6:
			if flags != 0 || length != 4 {
				return ErrActivation
			}
		case 9:
			if flags != 0 || length != 8 {
				return ErrActivation
			}
		default:
			return ErrActivation // never decode SYN_STREAM/HEADERS/RST/GOAWAY
		}
	}
	frame := make([]byte, 8+length)
	copy(frame, header[:])
	if _, err := io.ReadFull(g.reader, frame[8:]); err != nil {
		return ErrActivation
	}
	if control {
		value := binary.BigEndian.Uint32(frame[8:12])
		switch kind {
		case 2:
			bit := streamBit(value)
			if bit == 0 || g.opened.Load()&bit == 0 || g.acked&bit != 0 {
				return ErrActivation
			}
			g.acked |= bit
		case 4:
			if value > 8 || length != 4+int(value)*8 {
				return ErrActivation
			}
		case 6:
			if value == 0 || value%2 != 0 {
				return ErrActivation
			}
		case 9:
			bit := streamBit(value)
			delta := binary.BigEndian.Uint32(frame[12:16])
			if value != 0 && (bit == 0 || g.opened.Load()&bit == 0) || delta == 0 || delta&0x80000000 != 0 {
				return ErrActivation
			}
		}
	}
	g.buffer = frame
	return nil
}
