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

// These are pure candidate contracts for two fixed synthetic dry-run replies,
// NOT persistent marker acknowledgements, current phase/actor witnesses, cleanup
// authority or behavior completion. BOTH native profiles must certify each
// endpoint before its finite-case bit may count. No learning dictionary supplies
// acceptance and no real-world object can be selected by these private methods.
func (f *fixtureLedger) validateRetainedMarkerDryRunAdd(before, after *unstructured.Unstructured, phase *fixturePhaseBaseline, observed time.Time) error {
	if f == nil || f.document.RetainedMarker != nil {
		return ErrFixtures
	}
	return f.validateRetainedMarkerDryRunDelta(before, after, phase, observed, true)
}

func (f *fixtureLedger) validateRetainedMarkerDryRunRemove(before, after *unstructured.Unstructured, phase *fixturePhaseBaseline, observed time.Time) error {
	if f == nil || f.document.RetainedMarker == nil || f.document.RetainedMarker.State != fixtureRetainedMarkerAcknowledged {
		return ErrFixtures
	}
	return f.validateRetainedMarkerDryRunDelta(before, after, phase, observed, false)
}

func (f *fixtureLedger) validateRetainedMarkerDryRunDelta(before, after *unstructured.Unstructured, phase *fixturePhaseBaseline, observed time.Time, add bool) error {
	if f == nil || !validFixtureRecipe(f.document) || before == nil || after == nil || phase == nil || f.validatePhaseFixture(fixtureRetainedPVC, before, phase, observed) != nil || after.GetResourceVersion() != before.GetResourceVersion() {
		return ErrFixtures
	}
	// Only constructor-derived annotation values are admitted. In particular,
	// no caller-selected marker or fabricated persistent ACK is needed here.
	want, err := f.object(fixtureRetainedPVC)
	if err != nil {
		return ErrFixtures
	}
	marked := want.DeepCopy()
	annotations := marked.GetAnnotations()
	annotations[platformkube.AnnotationColdBackupUID] = f.document.RunID
	marked.SetAnnotations(annotations)
	beforeWant, afterWant := want, marked
	if !add {
		beforeWant, afterWant = marked, want
	}
	beforeMain, beforeStatus, err := fixtureMarkerDryRunRoles(before, beforeWant, observed)
	if err != nil {
		return ErrFixtures
	}
	afterMain, afterStatus, err := fixtureMarkerDryRunRoles(after, afterWant, observed)
	if err != nil || !reflect.DeepEqual(beforeStatus, afterStatus) {
		return ErrFixtures
	}
	oldTime, oldErr := time.Parse(time.RFC3339Nano, beforeMain["time"].(string))
	newTime, newErr := time.Parse(time.RFC3339Nano, afterMain["time"].(string))
	if oldErr != nil || newErr != nil || newTime.Before(oldTime) {
		return ErrFixtures
	}
	// Each role/tree/order/time was independently checked above. Reverse ONLY
	// the declared marker/tree/main-time delta on a private copy, then require
	// exact equality of ALL remaining raw metadata/spec/status/null presence.
	adjusted := after.DeepCopy()
	adjusted.SetAnnotations(before.GetAnnotations())
	afterMain["fieldsV1"], afterMain["time"] = beforeMain["fieldsV1"], beforeMain["time"]
	oldFields, _, _ := unstructured.NestedSlice(before.Object, "metadata", "managedFields")
	fields := []any{afterMain, afterStatus}
	if oldFields[0].(map[string]any)["subresource"] == "status" {
		fields = []any{afterStatus, afterMain}
	}
	if unstructured.SetNestedSlice(adjusted.Object, fields, "metadata", "managedFields") != nil || !reflect.DeepEqual(before.Object, adjusted.Object) {
		return ErrFixtures
	}
	return nil
}

// Closed public bookkeeping frames, independently specified for the fixed
// marked/unmarked constructor. No generic normalization, optional role, field
// subset, status update, annotation wildcard or extra manager is accepted.
func fixtureMarkerDryRunRoles(o, want *unstructured.Unstructured, observed time.Time) (map[string]any, map[string]any, error) {
	var typed corev1.PersistentVolumeClaim
	if o == nil || want == nil || decodeServing(o, &typed) != nil || len(typed.ManagedFields) != 2 || !slices.IsSortedFunc(typed.ManagedFields, fixtureNativeFieldOrder) || !reflect.DeepEqual(o.GetAnnotations(), want.GetAnnotations()) {
		return nil, nil, ErrFixtures
	}
	fields, found, err := unstructured.NestedSlice(o.Object, "metadata", "managedFields")
	if err != nil || !found || len(fields) != 2 {
		return nil, nil, ErrFixtures
	}
	var main, status map[string]any
	for index, field := range typed.ManagedFields {
		raw, ok := fields[index].(map[string]any)
		if !ok || field.Time == nil || !fixtureResultTime(raw["time"], typed.CreationTimestamp.Time, observed.UTC().Add(time.Second)) {
			return nil, nil, ErrFixtures
		}
		var tree map[string]any
		switch {
		case field.Manager == "arcadectl-installer" && field.Subresource == "" && main == nil:
			tree, main = fixtureResultFieldset(want), raw
		case field.Manager == "kube-controller-manager" && field.Subresource == "status" && status == nil:
			tree, status = map[string]any{"f:status": fixtureFieldLeaves("phase")}, raw
		default:
			return nil, nil, ErrFixtures
		}
		expected := map[string]any{"manager": field.Manager, "operation": "Update", "apiVersion": "v1", "fieldsType": "FieldsV1", "fieldsV1": tree, "time": raw["time"]}
		if field.Subresource != "" {
			expected["subresource"] = "status"
		}
		if !reflect.DeepEqual(raw, expected) {
			return nil, nil, ErrFixtures
		}
	}
	if main == nil || status == nil {
		return nil, nil, ErrFixtures
	}
	return main, status, nil
}
