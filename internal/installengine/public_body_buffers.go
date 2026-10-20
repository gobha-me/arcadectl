// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"io"
	"sync"
)

const publicBodyBufferBytes = 64 * 1024
const publicBodyBufferSlots = 8

// Per-HTTPAccess scratch, not response/identity/permission caching. Retained
// storage is bounded by eight zeroed buffers; active requests can exceed that
// count and are not an aggregate heap/RSS bound. Private/actor/non-GET paths
// never select this reader. Every borrowed body is completely reread.
type publicBodyBuffers struct {
	once sync.Once
	free chan []byte
}

type publicBodyLoan struct {
	body    []byte
	scratch []byte
	pool    *publicBodyBuffers
}

// reader must already have the caller's unchanged max-response-plus-one bound.
// The loan owns only a temporary mutable byte graph; no result may escape
// requestAt before strict decoding has produced independently owned objects.
func (p *publicBodyBuffers) read(reader io.Reader) (publicBodyLoan, error) {
	p.once.Do(func() { p.free = make(chan []byte, publicBodyBufferSlots) })
	var scratch []byte
	select {
	case scratch = <-p.free:
	default:
		scratch = make([]byte, publicBodyBufferBytes)
	}
	body := scratch[:0]
	for {
		// Retain io.ReadAll's EOF/error and zero-progress semantics. Only the
		// initial owned storage is reused; a larger body still grows normally.
		if len(body) == cap(body) {
			body = append(body, 0)[:len(body)]
		}
		n, err := reader.Read(body[len(body):cap(body)])
		body = body[:len(body)+n]
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			return publicBodyLoan{body: body, scratch: scratch, pool: p}, err
		}
	}
}

func (loan *publicBodyLoan) release() {
	if loan == nil || loan.pool == nil {
		return
	}
	// The entire retained scratch is zeroed even when the underlying read failed
	// or returned fewer bytes. A grown temporary body is cleared as well.
	clear(loan.body[:cap(loan.body)])
	clear(loan.scratch)
	pool, scratch := loan.pool, loan.scratch
	loan.body, loan.scratch, loan.pool = nil, nil, nil
	select {
	case pool.free <- scratch:
	default:
		// Excess simultaneous loans are dropped, never retained beyond the cap.
	}
}
