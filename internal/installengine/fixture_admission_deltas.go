// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"reflect"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Role lookup is used only AFTER a closed whole-shape validator has accepted
// every field, role and native ordering. It never normalizes an unknown role.
func fixtureManagedRole(o *unstructured.Unstructured, manager, subresource string) map[string]any {
	fields, _, _ := unstructured.NestedSlice(o.Object, "metadata", "managedFields")
	for _, value := range fields {
		field, ok := value.(map[string]any)
		if ok && field["manager"] == manager && (field["subresource"] == subresource || subresource == "" && field["subresource"] == nil) {
			return field
		}
	}
	return nil
}

func (f *fixtureLedger) validateDestroySeedDelta(before, after *unstructured.Unstructured, observed time.Time) error {
	return f.validateAdmissionSeedDelta(before, after, observed, false)
}

func (f *fixtureLedger) validateWarmDestroySeedDelta(before, after *unstructured.Unstructured, observed time.Time) error {
	return f.validateAdmissionSeedDelta(before, after, observed, true)
}

func (f *fixtureLedger) validateAdmissionSeedDelta(before, after *unstructured.Unstructured, observed time.Time, warm bool) error {
	if f == nil || before == nil || after == nil || f.document.DestroySeed == nil || !validFixtureDestroySeedDocument(f.document) || f.document.DestroySeed.State != fixtureDestroySeedAcknowledged || before.GetResourceVersion() != f.document.DestroySeed.BeforeResourceVersion || after.GetResourceVersion() != f.document.DestroySeed.AcknowledgedResourceVersion {
		return ErrFixtures
	}
	if warm {
		if f.document.DestroySeed.Mode != fixtureDestroySeedWarmCancelled || f.validateWarmCancelledDestroyResult(before, observed) != nil || f.validateWarmDestroySeedResult(after, observed) != nil {
			return ErrFixtures
		}
		if !reflect.DeepEqual(fixtureManagedRole(before, "arcadectl-controller", ""), fixtureManagedRole(after, "arcadectl-controller", "")) {
			return ErrFixtures
		}
		oldStatus := fixtureManagedRole(before, "arcadectl-controller", "status")
		newStatus := fixtureManagedRole(after, "arcadectl-controller", "status")
		if oldStatus == nil || newStatus == nil {
			return ErrFixtures
		}
		newStatus["fieldsV1"] = oldStatus["fieldsV1"]
		if !reflect.DeepEqual(oldStatus, newStatus) {
			return ErrFixtures
		}
	} else if f.document.DestroySeed.Mode != fixtureDestroySeedCold || f.validateResult(fixtureCancelledDestroy, fixtureStableResult, before, observed) != nil || f.validateDestroySeedResult(after, observed) != nil {
		return ErrFixtures
	}
	if !reflect.DeepEqual(fixtureManagedRole(before, "arcadectl-installer", ""), fixtureManagedRole(after, "arcadectl-installer", "")) {
		return ErrFixtures
	}
	adjusted := after.DeepCopy()
	if status, exists := before.Object["status"]; exists {
		adjusted.Object["status"] = status
	} else {
		delete(adjusted.Object, "status")
	}
	adjusted.SetResourceVersion(before.GetResourceVersion())
	fields, _, _ := unstructured.NestedSlice(before.Object, "metadata", "managedFields")
	if unstructured.SetNestedSlice(adjusted.Object, fields, "metadata", "managedFields") != nil || !reflect.DeepEqual(before.Object, adjusted.Object) {
		return ErrFixtures
	}
	return nil
}

// The two standalone confirmation validators bound native shape. This paired
// contract additionally preserves every historic role/time and every raw field
// except the fixed challenge, generation and installer-main ownership/time.
func (f *fixtureLedger) validateAdmissionConfirmationDelta(before, after *unstructured.Unstructured, phase *fixturePhaseBaseline, observed time.Time) error {
	if f == nil || before == nil || after == nil || f.document.DestroySeed == nil || f.validatePhaseFixture(fixtureCancelledDestroy, before, phase, observed) != nil {
		return ErrFixtures
	}
	var err error
	if f.document.DestroySeed.Mode == fixtureDestroySeedWarmCancelled {
		err = f.validateWarmDestroyConfirmationResult(after, observed)
	} else {
		err = f.validateDestroyConfirmationResult(after, observed)
	}
	if err != nil {
		return ErrFixtures
	}
	oldMain := fixtureManagedRole(before, "arcadectl-installer", "")
	newMain := fixtureManagedRole(after, "arcadectl-installer", "")
	if oldMain == nil || newMain == nil {
		return ErrFixtures
	}
	oldTime, oldErr := time.Parse(time.RFC3339Nano, oldMain["time"].(string))
	newTime, newErr := time.Parse(time.RFC3339Nano, newMain["time"].(string))
	if oldErr != nil || newErr != nil || newTime.Before(oldTime) {
		return ErrFixtures
	}
	newMain["fieldsV1"], newMain["time"] = oldMain["fieldsV1"], oldMain["time"]
	if !reflect.DeepEqual(oldMain, newMain) {
		return ErrFixtures
	}
	oldFields, _, _ := unstructured.NestedSlice(before.Object, "metadata", "managedFields")
	newFields, _, _ := unstructured.NestedSlice(after.Object, "metadata", "managedFields")
	if len(oldFields) != len(newFields) {
		return ErrFixtures
	}
	for _, value := range oldFields {
		field := value.(map[string]any)
		manager, _ := field["manager"].(string)
		subresource, _ := field["subresource"].(string)
		if manager == "arcadectl-installer" && subresource == "" {
			continue
		}
		if !reflect.DeepEqual(field, fixtureManagedRole(after, manager, subresource)) {
			return ErrFixtures
		}
	}
	adjusted := after.DeepCopy()
	unstructured.RemoveNestedField(adjusted.Object, "spec", "confirmationChallenge")
	adjusted.SetGeneration(before.GetGeneration())
	if unstructured.SetNestedSlice(adjusted.Object, oldFields, "metadata", "managedFields") != nil || !reflect.DeepEqual(before.Object, adjusted.Object) {
		return ErrFixtures
	}
	return nil
}
