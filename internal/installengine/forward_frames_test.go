// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"github.com/moby/spdystream/spdy"
)

func rawFrame(word uint32, flags byte, body []byte, advertised int) []byte {
	result := make([]byte, 8+len(body))
	binary.BigEndian.PutUint32(result, word)
	result[4] = flags
	result[5] = byte(advertised >> 16)
	result[6] = byte(advertised >> 8)
	result[7] = byte(advertised)
	copy(result[8:], body)
	return result
}
func frameWord(value uint32) []byte {
	body := make([]byte, 4)
	binary.BigEndian.PutUint32(body, value)
	return body
}
func TestForwardFrameGuardRejectsBeforeCodecAllocation(t *testing.T) {
	cases := map[string][]byte{
		"advertised-large-data": rawFrame(3, 0, nil, 0xffffff),
		"large-control":         rawFrame(0x80030002, 0, nil, 4097),
		"server-stream":         rawFrame(0x80030001, 0, nil, 0),
		"extra-headers":         rawFrame(0x80030008, 0, nil, 0),
		"unknown-id":            rawFrame(5, 0, nil, 0),
		"reserved-id":           rawFrame(0x40000003, 0, nil, 0),
		"error-bytes":           rawFrame(1, 0, nil, 1),
		"reset":                 rawFrame(0x80030003, 0, nil, 8),
		"go-away":               rawFrame(0x80030007, 0, nil, 8),
		"version":               rawFrame(0x80020002, 0, frameWord(1), 4),
		"bad-data-flags":        rawFrame(3, 2, nil, 0),
		"bad-reply-flags":       rawFrame(0x80030002, 1, frameWord(1), 4),
		"odd-ping":              rawFrame(0x80030006, 0, frameWord(1), 4),
		"zero-ping":             rawFrame(0x80030006, 0, frameWord(0), 4),
		"settings-count":        rawFrame(0x80030004, 0, frameWord(1000), 4),
		"truncated-payload":     rawFrame(3, 0, nil, 10),
		"truncated-header":      []byte{0, 0, 0},
	}
	for name, wire := range cases {
		t.Run(name, func(t *testing.T) {
			g := &forwardFrames{reader: bytes.NewReader(wire), acked: 3}
			g.opened.Store(3)
			var one [1]byte
			if n, err := g.Read(one[:]); n != 0 || !errors.Is(err, ErrActivation) || len(g.buffer) != 0 {
				t.Fatal("unsafe frame reached codec")
			}
		})
	}
}
func TestForwardFrameGuardBudgetsAndSequence(t *testing.T) {
	for _, name := range []string{"unopened", "unacknowledged", "duplicate-ack", "after-fin", "frame-budget", "byte-budget"} {
		t.Run(name, func(t *testing.T) {
			wire := rawFrame(3, 0, nil, 0)
			g := &forwardFrames{acked: 3}
			g.opened.Store(3)
			switch name {
			case "unopened":
				g.opened.Store(1)
			case "unacknowledged":
				g.acked = 1
			case "duplicate-ack":
				wire = rawFrame(0x80030002, 0, frameWord(3), 4)
			case "after-fin":
				g.fin = 2
			case "frame-budget":
				g.frames = forwardFrameBudget
			case "byte-budget":
				g.bytes = forwardWireBudget
			}
			g.reader = bytes.NewReader(wire)
			var one [1]byte
			if _, err := g.Read(one[:]); !errors.Is(err, ErrActivation) {
				t.Fatal("sequence/budget accepted")
			}
		})
	}
}
func TestForwardCodecRejectsCompressedHeaderExpansion(t *testing.T) {
	for _, change := range []string{"count", "field"} {
		t.Run(change, func(t *testing.T) {
			var wire bytes.Buffer
			writer, err := spdy.NewFramer(&wire, bytes.NewReader(nil))
			if err != nil {
				t.Fatal(err)
			}
			headers := map[string][]string{}
			if change == "field" {
				headers["x"] = []string{string(bytes.Repeat([]byte("x"), 10000))}
			} else {
				for _, name := range []string{"a", "b", "c", "d", "e", "f", "g", "h", "i"} {
					headers[name] = []string{"v"}
				}
			}
			if writer.WriteFrame(&spdy.SynReplyFrame{StreamId: 1, Headers: headers}) != nil {
				t.Fatal("fixture encoding")
			}
			g := &forwardFrames{reader: &wire}
			g.opened.Store(1)
			reader, err := spdy.NewFramerWithOptions(io.Discard, g, spdy.WithMaxControlFramePayloadSize(4096), spdy.WithMaxHeaderFieldSize(256), spdy.WithMaxHeaderCount(8))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := reader.ReadFrame(); err == nil {
				t.Fatal("header expansion accepted")
			}
		})
	}
}
func FuzzForwardFrameGuard(f *testing.F) {
	f.Add(rawFrame(3, 0, []byte("small"), 5))
	f.Add(rawFrame(0x80030002, 0, frameWord(1), 4))
	f.Add([]byte{0})
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > forwardWireBudget+8 {
			return
		}
		g := &forwardFrames{reader: bytes.NewReader(raw), acked: 3}
		g.opened.Store(3)
		_, _ = io.Copy(io.Discard, g)
		if len(g.buffer) > 65544 || g.frames > forwardFrameBudget+1 || g.bytes > forwardWireBudget+0x1000007 {
			t.Fatal("guard bounds changed")
		}
	})
}
