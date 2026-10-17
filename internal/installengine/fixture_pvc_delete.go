// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"reflect"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Candidate contract for exactly the two protected synthetic PVC dry-run
// DELETE replies. No real world, actor/phase proof, deletion, original absence
// or completion authority. Native v1.35.8/v1.37.0 must independently certify
// it. Their PVC Store has ReturnDeletedObject=true; generic registry deletion
// with this original pending finalizer marks timestamp/zero grace, without a
// generation increment for a PVC. Generic StatusSuccess is not this variant.
func (f *fixtureLedger) validateFixturePVCDeleteReply(slot int, before, after *unstructured.Unstructured, phase *fixturePhaseBaseline, started, observed time.Time) error {
	if slot != fixtureRetainedPVC && slot != fixturePlainPVC || f == nil || before == nil || after == nil || phase == nil || started.IsZero() || started.Year() < 1 || started.Year() > 9999 || observed.Before(started) || f.validatePhaseFixture(slot, before, phase, observed) != nil {
		return ErrFixtures
	}
	var typed corev1.PersistentVolumeClaim
	if decodeServing(after, &typed) != nil || typed.DeletionTimestamp == nil || typed.DeletionGracePeriodSeconds == nil || *typed.DeletionGracePeriodSeconds != 0 {
		return ErrFixtures
	}
	metadata, ok := after.Object["metadata"].(map[string]any)
	if !ok || !reflect.DeepEqual(metadata["deletionGracePeriodSeconds"], int64(0)) {
		return ErrFixtures
	}
	earliest := started.UTC().Truncate(time.Second)
	if creation := before.GetCreationTimestamp().Time; creation.After(earliest) {
		earliest = creation
	}
	if !fixtureResultTime(metadata["deletionTimestamp"], earliest, observed.UTC().Add(time.Second)) {
		return ErrFixtures
	}
	// Independently bounded canonical timestamp + exact zero grace are the
	// ONLY admitted delta. Raw full equality keeps all original UID/RV/spec/
	// status/labels/annotations/finalizers/owners and managed fields unchanged.
	adjusted := after.DeepCopy()
	adjustedMetadata := adjusted.Object["metadata"].(map[string]any)
	delete(adjustedMetadata, "deletionTimestamp")
	delete(adjustedMetadata, "deletionGracePeriodSeconds")
	if !reflect.DeepEqual(before.Object, adjusted.Object) {
		return ErrFixtures
	}
	return nil
}
