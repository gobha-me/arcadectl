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
	if b == nil || ctx == nil || ctx.Err() != nil || w == nil || b.wire != w || !w.phaseReadable() || w.ledger.identity != b.identity || !bytes.Equal(w.ledger.body, b.body) || w.localCurrent() != nil {
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
