//go:build kindinstall

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"reflect"
	"testing"
	"time"
)

// One named, original-administrator dry-run UPDATE of the fixed v2 verified
// leaf. This test-only component does NOT certify the whole finite matrix or
// publish a completion receipt. Unknown results require owned Kind teardown.
func proveKindVerifiedCancelledUpdate(t *testing.T, ctx context.Context, wire *fixtureWire, access *HTTPAccess, previous *fixturePhaseObservation) (*fixturePhaseObservation, error) {
	t.Helper()
	if wire == nil || wire.ledger == nil || access == nil || access.actor != nil || previous == nil || ctx == nil {
		return nil, ErrFixtures
	}
	f := wire.ledger
	if f.document.Recipe != fixtureRecipeV2 || !validFixtureRecipe(f.document) || f.document.DestroySeed != nil || f.document.RetainedMarker != nil || f.document.Behavior != nil {
		return nil, ErrFixtures
	}
	for _, entry := range f.document.Entries {
		if entry.State != fixtureOriginal || !nativeFixtureUID(string(entry.OriginalUID)) {
			return nil, ErrFixtures
		}
	}
	body, identity, revision := bytes.Clone(f.body), f.identity, f.document.Revision
	unchanged := func() bool {
		if !bytes.Equal(body, f.body) || identity != f.identity || revision != f.document.Revision || f.ackSlot != -1 || f.effectSlot != -1 || f.seedAck || f.seedEffect || f.markerAck || f.markerEffect || f.worldPublication || f.behaviorCompletion != nil || wire.current(ctx) != nil {
			return false
		}
		s := wire.actors.request.Snapshot
		fresh, err := f.engine.journal.Load(ctx, s.Anchor())
		if err != nil || !bytes.Equal(fresh.Bytes(), s.Bytes()) || fresh.ResourceVersion() != s.ResourceVersion() {
			return false
		}
		// Close the protected-file boundary AFTER the last remote read, just as
		// complete phase observation does. In-memory equality is not durability.
		durable, freshIdentity, err := f.engine.files.Read(f.name, fixtureLedgerMaxBytes)
		if err != nil || freshIdentity != identity || !bytes.Equal(durable, body) || f.engine.files.ConfirmDurable(f.name, identity) != nil || f.originalWorldsCurrent() != nil {
			return false
		}
		decoded, err := f.engine.decodeFixtureLedger(durable)
		return err == nil && reflect.DeepEqual(decoded, f.document) && bytes.Equal(body, f.body) && identity == f.identity && revision == f.document.Revision
	}
	before, err := wire.observePhase(ctx)
	if err != nil || before == nil || !samePhaseBaseline(previous.phase, before.phase) || !reflect.DeepEqual(previous.objects, before.objects) || !unchanged() {
		return nil, ErrFixtures
	}
	original := before.objects[fixtureVerifiedCancelledDestroy]
	if f.validatePhaseFixture(fixtureVerifiedCancelledDestroy, original, &before.phase, time.Now().UTC()) != nil {
		return nil, ErrFixtures
	}
	permission, err := actorPermission(f.document.Entries[fixtureVerifiedCancelledDestroy].Key, probeUpdateOperation)
	if err != nil || access.authorize(ctx, permission.spec) != nil || !unchanged() {
		return nil, ErrFixtures
	}
	t.Log("checking fixed verified original-administrator unchanged dry-run UPDATE")
	reply, probeErr := access.probeOperation(ctx, probeUpdateOperation, original.DeepCopy(), "", "", "") // exactly one send, never replayed
	// Reprove the complete domain even when the reply is refused or unknown.
	after, phaseErr := wire.observePhase(ctx)
	if phaseErr != nil || after == nil || !samePhaseBaseline(before.phase, after.phase) || !reflect.DeepEqual(before.objects, after.objects) || !unchanged() || probeErr != nil || f.validateVerifiedCancelledUnchangedUpdate(original, reply, &before.phase, time.Now().UTC()) != nil {
		return nil, ErrFixtures
	}
	t.Log("verified original unchanged UPDATE whole return accepted; every original, complete phase, protected WAL and journal unchanged; no completion capability")
	return after, nil
}
