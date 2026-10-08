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

// Test-only certification of the fixed whole no-op endpoints. Before seed:
// three original worker Pods, unmarked retained PVC, cancelled unsafe destroy,
// and the two plain-Pod subresources. After seed: the original dedicated
// controller's unchanged warm-seeded destroy. The verified leaf has its own
// strict test. No phase alone, subset, skipped endpoint or reply grants Behavior.
func proveKindFixedNoopReplies(t *testing.T, ctx context.Context, wire *fixtureWire, access *HTTPAccess, previous *fixturePhaseObservation) (*fixturePhaseObservation, error) {
	t.Helper()
	if ctx == nil || wire == nil || wire.ledger == nil || wire.actors == nil || wire.actors.admission == nil || wire.actors.admission.prerequisites == nil || access == nil || access.actor != nil || access != wire.actors.admission.prerequisites.access || previous == nil {
		return nil, ErrFixtures
	}
	f := wire.ledger
	f.wireMu.Lock()
	defer f.wireMu.Unlock()
	if f.document.Recipe != fixtureRecipeV2 || !validFixtureRecipe(f.document) || f.document.RetainedMarker != nil || f.document.Behavior != nil {
		return nil, ErrFixtures
	}
	for _, entry := range f.document.Entries {
		if entry.State != fixtureOriginal || !nativeFixtureUID(string(entry.OriginalUID)) {
			return nil, ErrFixtures
		}
	}
	type fixedCase struct {
		slot      int
		operation admissionProbeOperation
		actor     admissionActor
	}
	cases := []fixedCase{
		{fixtureBackupPod, probeUpdateOperation, 0},
		{fixtureRestorePod, probeUpdateOperation, 0},
		{fixtureDestroyPod, probeUpdateOperation, 0},
		{fixtureRetainedPVC, probeUpdateOperation, 0},
		{fixtureCancelledDestroy, probeUpdateOperation, 0},
		{fixturePlainPod, probeEphemeralOperation, 0},
		{fixturePlainPod, probeResizeOperation, 0},
	}
	if f.document.DestroySeed != nil {
		if !validFixtureDestroySeedDocument(f.document) || f.document.DestroySeed.State != fixtureDestroySeedAcknowledged || f.document.DestroySeed.Mode != fixtureDestroySeedWarmCancelled {
			return nil, ErrFixtures
		}
		cases = []fixedCase{{fixtureCancelledDestroy, probeUpdateOperation, destroyControllerActor}}
	}
	body, identity, revision := bytes.Clone(f.body), f.identity, f.document.Revision
	unchanged := func() bool {
		if !bytes.Equal(body, f.body) || identity != f.identity || revision != f.document.Revision || !wire.phaseReadable() || wire.current(ctx) != nil {
			return false
		}
		s := wire.actors.request.Snapshot
		fresh, err := f.engine.journal.Load(ctx, s.Anchor())
		if err != nil || !bytes.Equal(fresh.Bytes(), s.Bytes()) || fresh.ResourceVersion() != s.ResourceVersion() {
			return false
		}
		durable, fileID, err := f.engine.files.Read(f.name, fixtureLedgerMaxBytes)
		if err != nil || fileID != identity || !bytes.Equal(durable, body) || f.engine.files.ConfirmDurable(f.name, identity) != nil || f.originalWorldsCurrent() != nil {
			return false
		}
		decoded, err := f.engine.decodeFixtureLedger(durable)
		return err == nil && reflect.DeepEqual(decoded, f.document) && bytes.Equal(body, f.body) && identity == f.identity && revision == f.document.Revision && wire.phaseReadable()
	}
	for _, item := range cases {
		before, err := wire.observePhaseLocked(ctx)
		if err != nil || before == nil || !samePhaseBaseline(previous.phase, before.phase) || !reflect.DeepEqual(previous.objects, before.objects) || !unchanged() {
			return nil, ErrFixtures
		}
		original := before.objects[item.slot]
		if f.validatePhaseFixture(item.slot, original, &before.phase, time.Now().UTC()) != nil {
			return nil, ErrFixtures
		}
		// These are observations of pre-existing named rights, never RBAC grants.
		permission, err := actorPermission(f.document.Entries[item.slot].Key, probeUpdateOperation)
		if err != nil {
			return nil, ErrFixtures
		}
		if item.operation == probeEphemeralOperation {
			permission.spec.ResourceAttributes.Subresource = "ephemeralcontainers"
		} else if item.operation == probeResizeOperation {
			permission.spec.ResourceAttributes.Subresource = "resize"
		}
		discovery, err := access.discover(ctx, f.document.Entries[item.slot].Key.APIVersion)
		authorizer := access
		if item.actor != 0 {
			authorizer = wire.actors.clients[item.actor]
		}
		if err != nil || !discoveredPermission(discovery, permission) || authorizer == nil || authorizer.authorize(ctx, permission.spec) != nil || !unchanged() {
			return nil, ErrFixtures
		}
		t.Logf("checking fixed no-op slot=%d operation=%d actor=%d", item.slot, item.operation, item.actor)
		var replyErr error
		var reply = original.DeepCopy()
		if item.actor == 0 {
			reply, replyErr = access.probeOperation(ctx, item.operation, original.DeepCopy(), "", "", "")
		} else {
			reply, replyErr = wire.actors.probe(ctx, item.actor, item.operation, original.DeepCopy(), "", "", "")
		}
		// Reprove every original and the whole domain even on refusal/uncertainty.
		after, phaseErr := wire.observePhaseLocked(ctx)
		if phaseErr != nil || after == nil || !samePhaseBaseline(before.phase, after.phase) || !reflect.DeepEqual(before.objects, after.objects) || !unchanged() || replyErr != nil {
			return nil, ErrFixtures
		}
		if item.slot == fixturePlainPod {
			err = f.validatePlainPodUnchangedSubresource(item.operation, original, reply, &before.phase, time.Now().UTC())
		} else {
			err = f.validateFixtureUnchangedUpdate(item.slot, original, reply, &before.phase, time.Now().UTC())
		}
		if err != nil {
			return nil, ErrFixtures
		}
		previous = after
		t.Logf("fixed no-op whole reply accepted slot=%d operation=%d actor=%d; every original/WAL/journal unchanged; no completion", item.slot, item.operation, item.actor)
	}
	return previous, nil
}
