// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"

	"github.com/gobha-me/arcadectl/internal/privatefs"
)

// A pinned LOCAL boundary for one serialized, read-only complete phase. It is
// constructed only inside observePhaseLocked, never accepted by an effect,
// recovery or retirement route, and contains no authorization receipt. Each
// complete pass still needs live original witnesses before and after ALL reads.
// Discovery, SSAR, typed/metadata LISTs and exact named GETs remain uncached.
type fixturePhaseRead struct {
	wire     *fixtureWire
	body     []byte
	identity privatefs.FileIdentity
}

func (b *fixturePhaseRead) local(ctx context.Context, w *fixtureWire) error {
	reason := uint32(0)
	// Preserve the original short-circuit order and every existing check.
	switch {
	case b == nil:
		reason = 4
	case ctx == nil || ctx.Err() != nil:
		reason = 3
	case w == nil || b.wire != w:
		reason = 4
	case !w.phaseReadable():
		reason = 5
	case w.ledger.identity != b.identity:
		reason = 6
	case !bytes.Equal(w.ledger.body, b.body):
		reason = 7
	case w.localCurrent() != nil:
		reason = 8
	}
	if reason != 0 {
		traceTypedCollection(ctx, typedCollectionLocalClosing, reason)
		return ErrFixtures
	}
	return nil
}

func (b *fixturePhaseRead) current(ctx context.Context) error {
	if b == nil || b.local(ctx, b.wire) != nil || b.wire.current(ctx) != nil || b.local(ctx, b.wire) != nil {
		return ErrFixtures
	}
	// Close pinned bytes/inode/world durability AFTER the live actor reads too.
	return nil
}
