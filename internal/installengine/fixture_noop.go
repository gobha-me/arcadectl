// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"reflect"
	"time"

	arcadev1 "github.com/gobha-me/arcadectl/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Whole-return checks for the fixed no-op positive cases, not a phase/actor
// witness, permission, send capability or behavior completion. The finite
// driver must independently prove the complete domain around each one send.
func (f *fixtureLedger) validateFixtureUnchangedUpdate(slot int, before, after *unstructured.Unstructured, phase *fixturePhaseBaseline, observed time.Time) error {
	switch slot {
	case fixtureBackupPod, fixtureRestorePod, fixtureDestroyPod, fixtureRetainedPVC, fixtureCancelledDestroy, fixtureVerifiedCancelledDestroy:
		return f.validateFixtureWholeNoop(slot, before, after, phase, observed)
	default:
		return ErrFixtures
	}
}

// Empty plain-Pod ephemeralcontainers/resize requests must preserve the whole
// original, not merely its spec. Both native profiles must separately certify
// these exact endpoints before either case can count toward completion.
func (f *fixtureLedger) validatePlainPodUnchangedSubresource(operation admissionProbeOperation, before, after *unstructured.Unstructured, phase *fixturePhaseBaseline, observed time.Time) error {
	if operation != probeEphemeralOperation && operation != probeResizeOperation {
		return ErrFixtures
	}
	return f.validateFixtureWholeNoop(fixturePlainPod, before, after, phase, observed)
}

func (f *fixtureLedger) validateFixtureWholeNoop(slot int, before, after *unstructured.Unstructured, phase *fixturePhaseBaseline, observed time.Time) error {
	if f == nil || !validFixtureRecipe(f.document) || before == nil || after == nil || phase == nil || f.validatePhaseFixture(slot, before, phase, observed) != nil || !reflect.DeepEqual(before.Object, after.Object) {
		return ErrFixtures
	}
	// Equality must not bypass strict raw/typed decoding. Never project away
	// bookkeeping, status, null presence or unknown fields to manufacture a no-op.
	var err error
	switch before.GetKind() {
	case "Pod":
		var typed corev1.Pod
		err = decodeServing(after, &typed)
	case "PersistentVolumeClaim":
		var typed corev1.PersistentVolumeClaim
		err = decodeServing(after, &typed)
	case "GameDestroy":
		var typed arcadev1.GameDestroy
		err = decodeServing(after, &typed)
	default:
		return ErrFixtures
	}
	if err != nil {
		return ErrFixtures
	}
	return nil
}
