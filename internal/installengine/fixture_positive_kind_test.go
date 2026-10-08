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

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Test-only native certification helper for the remaining FIVE fixed positive
// whole-return contracts. No caller case selection, partial-bit completion,
// persistent worker authorization/PVC deletion, default recipe or grant change.
func proveKindFixedPositiveDeltas(t *testing.T, ctx context.Context, wire *fixtureWire, access *HTTPAccess, previous *fixturePhaseObservation) (*fixturePhaseObservation, error) {
	t.Helper()
	if ctx == nil || wire == nil || wire.ledger == nil || wire.actors == nil || wire.actors.admission == nil || wire.actors.admission.prerequisites == nil || access == nil || access.actor != nil || access != wire.actors.admission.prerequisites.access || previous == nil {
		return nil, ErrFixtures
	}
	f := wire.ledger
	f.wireMu.Lock()
	defer f.wireMu.Unlock()
	if f.document.Recipe != fixtureRecipeV2 || !validFixtureRecipe(f.document) || f.document.DestroySeed != nil || f.document.RetainedMarker != nil || f.document.Behavior != nil {
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
		family    string
	}
	cases := []fixedCase{
		{fixtureBackupPod, probeUpdateOperation, ordinaryControllerActor, "backup"},
		{fixtureRestorePod, probeUpdateOperation, ordinaryControllerActor, "restore"},
		{fixtureDestroyPod, probeUpdateOperation, destroyControllerActor, "destroy"},
		{fixtureRetainedPVC, probeDeletePVCOperation, destroyControllerActor, ""},
		{fixturePlainPVC, probeDeletePVCOperation, 0, ""},
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
		permission, err := actorPermission(f.document.Entries[item.slot].Key, item.operation)
		discovery, discoveryErr := access.discover(ctx, f.document.Entries[item.slot].Key.APIVersion)
		authorizer := access
		if item.actor != 0 {
			authorizer = wire.actors.clients[item.actor]
		}
		if err != nil || discoveryErr != nil || !discoveredPermission(discovery, permission) || authorizer == nil || authorizer.authorize(ctx, permission.spec) != nil || !unchanged() {
			return nil, ErrFixtures
		}
		candidate := original.DeepCopy()
		if item.operation == probeUpdateOperation {
			unstructured.RemoveNestedField(candidate.Object, "spec", "schedulingGates")
			annotations := candidate.GetAnnotations()
			if annotations == nil {
				annotations = map[string]string{}
			}
			annotations["arcade.gobha.me/"+item.family+"-pod-authorized"] = string(original.GetUID())
			candidate.SetAnnotations(annotations)
		}
		t.Logf("checking fixed positive delta slot=%d operation=%d actor=%d", item.slot, item.operation, item.actor)
		started := time.Now().UTC()
		var reply *unstructured.Unstructured
		var replyErr error
		if item.actor == 0 {
			reply, replyErr = access.probeOperation(ctx, item.operation, candidate, "", "", "")
		} else {
			reply, replyErr = wire.actors.probe(ctx, item.actor, item.operation, candidate, "", "", "")
		}
		// Complete all-original accounting even after refusal/lost response; a
		// dry-run reply is never persistent mutation/cleanup evidence.
		after, phaseErr := wire.observePhaseLocked(ctx)
		observed := time.Now().UTC()
		if phaseErr != nil || after == nil || !samePhaseBaseline(before.phase, after.phase) || !reflect.DeepEqual(before.objects, after.objects) || !unchanged() || replyErr != nil {
			return nil, ErrFixtures
		}
		if item.operation == probeUpdateOperation {
			err = f.validateWorkerGateAuthorization(item.slot, original, reply, &before.phase, observed)
		} else {
			err = f.validateFixturePVCDeleteReply(item.slot, original, reply, &before.phase, started, observed)
		}
		if err != nil {
			return nil, ErrFixtures
		}
		previous = after
		t.Logf("fixed positive whole delta accepted slot=%d operation=%d actor=%d; every original/WAL/journal unchanged; no completion", item.slot, item.operation, item.actor)
	}
	return previous, nil
}
