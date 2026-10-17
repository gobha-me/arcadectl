// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"reflect"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Candidate whole-return contract for the three fixed dry-run controller gate
// removals. NOT native certification, actor/phase evidence, persistent gate
// authorization or behavior completion. Both pinned native profiles must still
// prove these exact endpoints and bookkeeping. The signed policy authorizes the
// original POD UID; the separately ACKed Job remains unchanged owner closure.
// Pod strategy in Kubernetes v1.35.8/v1.37.0 preserves old status and increments
// generation for a changed spec (pkg/registry/core/pod/strategy.go). A scheduling
// gate removal is a spec change; manager/tree/time remain independently checked.
func (f *fixtureLedger) validateWorkerGateAuthorization(slot int, before, after *unstructured.Unstructured, phase *fixturePhaseBaseline, observed time.Time) error {
	worker := ""
	switch slot {
	case fixtureBackupPod:
		worker = "backup"
	case fixtureRestorePod:
		worker = "restore"
	case fixtureDestroyPod:
		worker = "destroy"
	default:
		return ErrFixtures
	}
	if f == nil || before == nil || after == nil || phase == nil || f.validatePhaseFixture(slot, before, phase, observed) != nil || after.GetGeneration() != 2 {
		return ErrFixtures
	}
	var typed corev1.Pod
	if decodeServing(after, &typed) != nil || len(typed.ManagedFields) != 1 {
		return ErrFixtures
	}
	if _, present, err := unstructured.NestedFieldNoCopy(after.Object, "spec", "schedulingGates"); err != nil || present {
		return ErrFixtures // absent, never null/empty/another gate
	}
	want, err := f.object(slot)
	if err != nil {
		return ErrFixtures
	}
	authorization := "arcade.gobha.me/" + worker + "-pod-authorized"
	annotations := want.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}
	annotations[authorization] = string(before.GetUID())
	want.SetAnnotations(annotations)
	metadata, ok := after.Object["metadata"].(map[string]any)
	if !ok || !reflect.DeepEqual(metadata["annotations"], want.Object["metadata"].(map[string]any)["annotations"]) {
		return ErrFixtures
	}
	// Derive from the unchanged constructor, not returned ownership leaves.
	// The ordinary fieldset constructor requires the one original gate; remove
	// precisely that declared subtree after constructing the complete tree.
	owned := fixtureResultFieldset(want)
	if owned == nil {
		return ErrFixtures
	}
	spec, ok := owned["f:spec"].(map[string]any)
	if !ok {
		return ErrFixtures
	}
	if _, present := spec["f:schedulingGates"]; !present {
		return ErrFixtures
	}
	delete(spec, "f:schedulingGates")
	fields, found, err := unstructured.NestedSlice(after.Object, "metadata", "managedFields")
	if err != nil || !found || len(fields) != 1 {
		return ErrFixtures
	}
	main, ok := fields[0].(map[string]any)
	if !ok || !fixtureResultTime(main["time"], before.GetCreationTimestamp().Time, observed.UTC().Add(time.Second)) {
		return ErrFixtures
	}
	expected := map[string]any{"manager": "arcadectl-installer", "operation": "Update", "apiVersion": "v1", "fieldsType": "FieldsV1", "fieldsV1": owned, "time": main["time"]}
	if !reflect.DeepEqual(main, expected) {
		return ErrFixtures
	}
	oldFields, found, err := unstructured.NestedSlice(before.Object, "metadata", "managedFields")
	if err != nil || !found || len(oldFields) != 1 {
		return ErrFixtures
	}
	oldMain, ok := oldFields[0].(map[string]any)
	if !ok {
		return ErrFixtures
	}
	oldTime, oldErr := time.Parse(time.RFC3339, oldMain["time"].(string))
	newTime, newErr := time.Parse(time.RFC3339, main["time"].(string))
	if oldErr != nil || newErr != nil || newTime.Before(oldTime) {
		return ErrFixtures
	}
	// Reverse ONLY the independently specified gate, annotation, generation
	// and main ownership/time delta. Every other raw field, including complete
	// status, owner ACK, identity/RV and null presence, must match the original.
	adjusted := after.DeepCopy()
	oldGates, _, _ := unstructured.NestedSlice(before.Object, "spec", "schedulingGates")
	if unstructured.SetNestedSlice(adjusted.Object, oldGates, "spec", "schedulingGates") != nil {
		return ErrFixtures
	}
	adjusted.SetGeneration(before.GetGeneration())
	oldMetadata := before.Object["metadata"].(map[string]any)
	adjustedMetadata := adjusted.Object["metadata"].(map[string]any)
	if _, present := oldMetadata["annotations"]; present {
		// Both inputs remain caller-owned; obtain mutable values from a copy.
		adjustedMetadata["annotations"] = before.DeepCopy().Object["metadata"].(map[string]any)["annotations"]
	} else {
		delete(adjustedMetadata, "annotations")
	}
	if unstructured.SetNestedSlice(adjusted.Object, oldFields, "metadata", "managedFields") != nil || !reflect.DeepEqual(before.Object, adjusted.Object) {
		return ErrFixtures
	}
	return nil
}
