// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"reflect"
	"slices"
	"time"

	platformkube "github.com/gobha-me/arcadectl/internal/platform/kube"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Constructor only. Never apply the synthetic binder annotation or marker to
// an adopted/real world. The original protected recipe supplies every byte.
func (f *fixtureLedger) retainedMarkerObject() (*unstructured.Unstructured, error) {
	if f == nil || f.document.RetainedMarker == nil {
		return nil, ErrFixtures
	}
	o, err := f.object(fixtureRetainedPVC)
	if err != nil {
		return nil, ErrFixtures
	}
	annotations := o.GetAnnotations()
	annotations[platformkube.AnnotationColdBackupUID] = f.document.RunID
	o.SetAnnotations(annotations)
	return o, nil
}

// Pure exact whole-shape contract learned on BOTH supported native profiles.
// This is not fresh observation, authenticated authority, coldness, cleanup or
// WAL retirement. The diagnostic subset dictionary never supplies acceptance.
func (f *fixtureLedger) validateRetainedMarkerResult(o *unstructured.Unstructured, observed time.Time) error {
	if f == nil || o == nil || observed.IsZero() || observed.Year() < 1 || observed.Year() > 9999 || f.document.RetainedMarker == nil || f.document.RetainedMarker.State != fixtureRetainedMarkerAcknowledged || !validFixtureRetainedMarkerDocument(f.document) || f.document.Entries[fixtureRetainedPVC].State != fixtureOriginal || o.GetUID() != f.document.Entries[fixtureRetainedPVC].OriginalUID || o.GetResourceVersion() != f.document.RetainedMarker.AcknowledgedResourceVersion {
		return ErrFixtures
	}
	want, err := f.retainedMarkerObject()
	var typed corev1.PersistentVolumeClaim
	fields, found, fieldsErr := unstructured.NestedSlice(o.Object, "metadata", "managedFields")
	metadata, metadataOK := o.Object["metadata"].(map[string]any)
	if err != nil || !metadataOK || !reflect.DeepEqual(metadata["annotations"], want.Object["metadata"].(map[string]any)["annotations"]) || fieldsErr != nil || !found || len(fields) != 2 || decodeServing(o, &typed) != nil || len(typed.ManagedFields) != 2 || !slices.IsSortedFunc(typed.ManagedFields, fixtureNativeFieldOrder) {
		return ErrFixtures
	}
	seen := [2]bool{}
	var main, status any
	for index, field := range typed.ManagedFields {
		raw, ok := fields[index].(map[string]any)
		if !ok || field.Time == nil || !fixtureResultTime(raw["time"], typed.CreationTimestamp.Time, observed.UTC().Add(time.Second)) {
			return ErrFixtures
		}
		role := -1
		var tree map[string]any
		switch {
		case field.Manager == "arcadectl-installer" && field.Subresource == "":
			role, tree, main = 0, fixtureResultFieldset(want), raw
		case field.Manager == "kube-controller-manager" && field.Subresource == "status":
			role, tree, status = 1, map[string]any{"f:status": fixtureFieldLeaves("phase")}, raw
		}
		if role < 0 || seen[role] || tree == nil {
			return ErrFixtures
		}
		seen[role] = true
		expected := map[string]any{"manager": field.Manager, "operation": "Update", "apiVersion": "v1", "fieldsType": "FieldsV1", "fieldsV1": tree, "time": raw["time"]}
		if field.Subresource != "" {
			expected["subresource"] = field.Subresource
		}
		if !reflect.DeepEqual(raw, expected) {
			return ErrFixtures
		}
	}
	if !seen[0] || !seen[1] {
		return ErrFixtures
	}
	// Remove ONLY independently validated additions on a private copy. Native
	// field order was already checked; normalize for the unchanged base validator.
	base := o.DeepCopy()
	annotations := base.GetAnnotations()
	delete(annotations, platformkube.AnnotationColdBackupUID)
	base.SetAnnotations(annotations)
	if unstructured.SetNestedSlice(base.Object, []any{main, status}, "metadata", "managedFields") != nil {
		return ErrFixtures
	}
	baseMain := base.Object["metadata"].(map[string]any)["managedFields"].([]any)[0].(map[string]any)
	delete(baseMain["fieldsV1"].(map[string]any)["f:metadata"].(map[string]any)["f:annotations"].(map[string]any), "f:"+platformkube.AnnotationColdBackupUID)
	return f.validateResult(fixtureRetainedPVC, fixtureStableResult, base, observed)
}

// Dedicated pre/post delta, NOT an ordinary-world observation filter. Both
// whole shapes are independently checked before removing the sole permitted
// annotation on a copy. Every other raw field must preserve the original.
func (f *fixtureLedger) validateRetainedMarkerDelta(before, after *unstructured.Unstructured, observed time.Time) error {
	if before == nil || after == nil || f == nil || f.validateResult(fixtureRetainedPVC, fixtureStableResult, before, observed) != nil || f.validateRetainedMarkerResult(after, observed) != nil || before.GetResourceVersion() != f.document.RetainedMarker.BeforeResourceVersion {
		return ErrFixtures
	}
	beforeFields := before.Object["metadata"].(map[string]any)["managedFields"].([]any)
	afterFields := after.Object["metadata"].(map[string]any)["managedFields"].([]any)
	var main map[string]any
	var status any
	for _, raw := range afterFields {
		field := raw.(map[string]any) // independently exact whole-validated above
		if field["manager"] == "arcadectl-installer" {
			main = field
		} else {
			status = field
		}
	}
	// BOTH native profiles preserved this record byte-for-byte. Whole shape
	// permits bounded timestamps; only this original delta pins their history.
	if !reflect.DeepEqual(status, beforeFields[1]) || main == nil {
		return ErrFixtures
	}
	previousTime, previousErr := time.Parse(time.RFC3339, beforeFields[0].(map[string]any)["time"].(string))
	currentTime, currentErr := time.Parse(time.RFC3339, main["time"].(string))
	if previousErr != nil || currentErr != nil || currentTime.Before(previousTime) {
		return ErrFixtures
	}
	copy := after.DeepCopy()
	annotations := copy.GetAnnotations()
	delete(annotations, platformkube.AnnotationColdBackupUID)
	copy.SetAnnotations(annotations)
	copy.SetResourceVersion(before.GetResourceVersion())
	copy.Object["metadata"].(map[string]any)["managedFields"] = before.DeepCopy().Object["metadata"].(map[string]any)["managedFields"]
	if !reflect.DeepEqual(copy.Object, before.Object) {
		return ErrFixtures
	}
	return nil
}
