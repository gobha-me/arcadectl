// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"reflect"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Test-only diagnosis of an already-refused whole-body comparison. No values,
// names, UID/RV strings, unknown field names or schema projections are returned.
func warmNativeObjectDifference(original, fresh *unstructured.Unstructured) string {
	if original == nil || fresh == nil {
		return "unavailable"
	}
	for _, field := range []string{"name", "namespace", "uid", "resourceVersion", "generation", "creationTimestamp", "deletionTimestamp", "deletionGracePeriodSeconds", "ownerReferences", "finalizers", "managedFields", "labels", "annotations"} {
		before, beforeFound, beforeErr := unstructured.NestedFieldNoCopy(original.Object, "metadata", field)
		after, afterFound, afterErr := unstructured.NestedFieldNoCopy(fresh.Object, "metadata", field)
		if beforeErr != nil || afterErr != nil {
			return "metadata-unavailable"
		}
		if beforeFound != afterFound || !reflect.DeepEqual(before, after) {
			return "metadata-" + field
		}
	}
	for _, field := range []string{"metadata", "spec", "status"} {
		before, beforeFound := original.Object[field]
		after, afterFound := fresh.Object[field]
		if beforeFound != afterFound || !reflect.DeepEqual(before, after) {
			return field
		}
	}
	// A caller uses this only after a refused exact comparison. Even an equal
	// pair must not return a success-shaped empty label or authorize anything.
	return "other-or-unclassified"
}

func warmNativeDiagnosticKind(kind string) string {
	for _, known := range typedMetadataKinds {
		if kind == known {
			return known
		}
	}
	if kind == "VolumeAttachment" {
		return "VolumeAttachment"
	}
	return "unknown"
}

func TestWarmNativeGuardDiagnosticClosedCategories(t *testing.T) {
	original := &unstructured.Unstructured{Object: map[string]any{"metadata": map[string]any{"resourceVersion": "1"}}}
	for _, field := range []string{"name", "namespace", "uid", "resourceVersion", "generation", "creationTimestamp", "deletionTimestamp", "deletionGracePeriodSeconds", "ownerReferences", "finalizers", "managedFields", "labels", "annotations", "PRIVATE-CANARY"} {
		fresh := original.DeepCopy()
		if unstructured.SetNestedField(fresh.Object, "PRIVATE-CANARY", "metadata", field) != nil {
			t.Fatal("abstract difference unavailable")
		}
		want := "metadata-" + field
		if field == "PRIVATE-CANARY" {
			want = "metadata"
		}
		if got := warmNativeObjectDifference(original, fresh); got != want || strings.Contains(got, "CANARY") {
			t.Fatal("difference escaped closed category", got)
		}
	}
	for _, field := range []string{"spec", "status", "PRIVATE-CANARY"} {
		fresh := original.DeepCopy()
		fresh.Object[field] = "PRIVATE-CANARY"
		want := field
		if field == "PRIVATE-CANARY" {
			want = "other-or-unclassified"
		}
		if got := warmNativeObjectDifference(original, fresh); got != want || strings.Contains(got, "CANARY") {
			t.Fatal("body field escaped closed category", got)
		}
	}
	missing := original.DeepCopy()
	missing.Object["metadata"].(map[string]any)["labels"] = nil
	if warmNativeObjectDifference(original, missing) != "metadata-labels" {
		t.Fatal("presence versus null was normalized")
	}
	broken := original.DeepCopy()
	broken.Object["metadata"] = "PRIVATE-CANARY"
	if warmNativeObjectDifference(original, broken) != "metadata-unavailable" || warmNativeObjectDifference(nil, original) != "unavailable" || warmNativeObjectDifference(original, original.DeepCopy()) != "other-or-unclassified" {
		t.Fatal("unknown/equal observation supplied a success label")
	}
	for _, kind := range []string{"Pod", "Secret", "VolumeAttachment", "PRIVATE-CANARY", "Pod\nPRIVATE-CANARY"} {
		want := kind
		if strings.Contains(kind, "CANARY") {
			want = "unknown"
		}
		if warmNativeDiagnosticKind(kind) != want {
			t.Fatal("kind escaped fixed whitelist")
		}
	}
	compound := original.DeepCopy()
	compound.SetResourceVersion("PRIVATE-CANARY")
	compound.Object["spec"] = map[string]any{"PRIVATE-CANARY": "PRIVATE-CANARY"}
	beforeOriginal, beforeCompound := original.DeepCopy(), compound.DeepCopy()
	if warmNativeObjectDifference(original, compound) != "metadata-resourceVersion" || !reflect.DeepEqual(original.Object, beforeOriginal.Object) || !reflect.DeepEqual(compound.Object, beforeCompound.Object) {
		t.Fatal("first-category precedence or input immutability changed")
	}
	if !reflect.DeepEqual(original.Object, map[string]any{"metadata": map[string]any{"resourceVersion": "1"}}) {
		t.Fatal("diagnostic mutated original object")
	}
}
