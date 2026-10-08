// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"reflect"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Setups are NOT matrix bits. Each is exactly two durable revisions around
// one persistent send, followed by a paired whole target delta and unchanged
// complete domain/other originals. A reliable ACK alone cannot rebaseline.
func (d *fixtureAdmissionDriver) seedLocked(ctx context.Context) error {
	w, f := d.wire, d.wire.ledger
	if d.failed || d.next != 39 || d.completed != (uint64(1)<<39)-1 || f.document.DestroySeed != nil || f.document.RetainedMarker != nil || f.document.Behavior != nil {
		return ErrFixtures
	}
	seal, err := d.sealLocked()
	if err != nil {
		return err
	}
	before, err := w.observePhaseLocked(ctx)
	if err != nil || !fixtureSameObservation(d.previous, before) || d.unchangedLocked(ctx, seal) != nil {
		return ErrFixtures
	}
	mode := fixtureDestroySeedCold
	for _, leader := range before.phase.Leaders {
		if leader.Row.Key.Name == "destroy-controller.arcade.gobha.me" {
			mode = fixtureDestroySeedWarmCancelled
		}
	}
	original := before.objects[fixtureCancelledDestroy]
	if original == nil || f.validatePhaseFixture(fixtureCancelledDestroy, original, &before.phase, time.Now().UTC()) != nil {
		return ErrFixtures
	}
	next, err := f.nextDocument()
	if err != nil {
		return err
	}
	next.DestroySeed = &fixtureDestroySeedReceipt{Mode: mode, State: fixtureDestroySeedAttempted, BeforeResourceVersion: original.GetResourceVersion()}
	if f.advance(next) != nil {
		return ErrFixtures
	}
	var reply *unstructured.Unstructured
	var sendErr error
	if mode == fixtureDestroySeedWarmCancelled {
		reply, sendErr = w.seedWarmDestroyStatusLocked(ctx)
	} else {
		reply, sendErr = w.seedDestroyStatusLocked(ctx)
	}
	after, phaseErr := w.observePhaseLocked(ctx) // even unknown/refused sends
	if phaseErr != nil || sendErr != nil || reply == nil || after == nil || f.document.DestroySeed == nil {
		return ErrFixtures
	}
	next.Revision++
	next.DestroySeed.State = fixtureDestroySeedAcknowledged
	next.DestroySeed.AcknowledgedResourceVersion = reply.GetResourceVersion()
	if !reflect.DeepEqual(next, f.document) || f.document.Revision != seal.revision+2 {
		return ErrFixtures
	}
	observed := time.Now().UTC()
	if mode == fixtureDestroySeedWarmCancelled {
		err = f.validateWarmDestroySeedDelta(original, reply, observed)
	} else {
		err = f.validateDestroySeedDelta(original, reply, observed)
	}
	if err != nil || !reflect.DeepEqual(reply, after.objects[fixtureCancelledDestroy]) || !fixtureSameSetupPhase(before, after, fixtureCancelledDestroy) {
		return ErrFixtures
	}
	postSeal, err := d.sealLocked()
	if err != nil || postSeal.worldID != seal.worldID || d.unchangedLocked(ctx, postSeal) != nil {
		return ErrFixtures
	}
	d.previous = after
	return nil
}

func (d *fixtureAdmissionDriver) markerLocked(ctx context.Context) error {
	w, f := d.wire, d.wire.ledger
	if d.failed || d.next != 45 || d.completed != (uint64(1)<<45)-1 || f.document.DestroySeed == nil || f.document.DestroySeed.State != fixtureDestroySeedAcknowledged || f.document.RetainedMarker != nil || f.document.Behavior != nil {
		return ErrFixtures
	}
	seal, err := d.sealLocked()
	if err != nil {
		return err
	}
	before, err := w.observePhaseLocked(ctx)
	if err != nil || !fixtureSameObservation(d.previous, before) || d.unchangedLocked(ctx, seal) != nil {
		return ErrFixtures
	}
	original := before.objects[fixtureRetainedPVC]
	if original == nil || f.validatePhaseFixture(fixtureRetainedPVC, original, &before.phase, time.Now().UTC()) != nil {
		return ErrFixtures
	}
	next, err := f.nextDocument()
	if err != nil {
		return err
	}
	next.RetainedMarker = &fixtureRetainedMarkerReceipt{State: fixtureRetainedMarkerAttempted, BeforeResourceVersion: original.GetResourceVersion()}
	if f.advance(next) != nil {
		return ErrFixtures
	}
	reply, sendErr := w.markRetainedPVCLocked(ctx)
	after, phaseErr := w.observePhaseLocked(ctx) // never skip after refusal
	if phaseErr != nil || sendErr != nil || reply == nil || after == nil {
		return ErrFixtures
	}
	next.Revision++
	next.RetainedMarker.State = fixtureRetainedMarkerAcknowledged
	next.RetainedMarker.AcknowledgedResourceVersion = reply.GetResourceVersion()
	if !reflect.DeepEqual(next, f.document) || f.document.Revision != seal.revision+2 || f.validateRetainedMarkerDelta(original, reply, time.Now().UTC()) != nil || !reflect.DeepEqual(reply, after.objects[fixtureRetainedPVC]) || !fixtureSameSetupPhase(before, after, fixtureRetainedPVC) {
		return ErrFixtures
	}
	postSeal, err := d.sealLocked()
	if err != nil || postSeal.worldID != seal.worldID || d.unchangedLocked(ctx, postSeal) != nil {
		return ErrFixtures
	}
	d.previous = after
	return nil
}

func fixtureSameSetupPhase(before, after *fixturePhaseObservation, slot int) bool {
	if before == nil || after == nil || !samePhaseBaseline(before.phase, after.phase) {
		return false
	}
	for index := range before.objects {
		if index != slot && !reflect.DeepEqual(before.objects[index], after.objects[index]) {
			return false
		}
	}
	return true
}
