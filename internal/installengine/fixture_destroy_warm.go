// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"reflect"
	"slices"
	"strings"
	"time"

	arcadev1 "github.com/gobha-me/arcadectl/api/v1alpha1"
	platformkube "github.com/gobha-me/arcadectl/internal/platform/kube"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Pure whole-original shape validation, NOT identity, coldness, freshness or
// effect/cleanup authority. Both native profiles separately produced these exact
// three record roles/trees. Manager names are bookkeeping, not authentication.
// A provider still needs current original-controller, world/storage, derived-
// resource absence, actor/policy/journal/WAL and complete GC witnesses.
//
// Deliberately separate from the cold absent-status/seed validators. No status
// seed, confirmation, deletion progression or unknown-effect adoption is allowed.
func (f *fixtureLedger) validateWarmCancelledDestroyResult(o *unstructured.Unstructured, observed time.Time) error {
	return f.validateWarmCancelledDestroySlotResult(fixtureCancelledDestroy, o, observed)
}

// v2 construction reuses the cancellation algorithm over only these two fixed
// originals. Slot10's native three-role shape remains separately unproved until
// both profile tests certify it; this helper does not grant effect authority.
func (f *fixtureLedger) validateWarmCancelledDestroySlotResult(slot int, o *unstructured.Unstructured, observed time.Time) error {
	if slot != fixtureCancelledDestroy && slot != fixtureVerifiedCancelledDestroy {
		return ErrFixtures
	}
	want, err := f.object(slot)
	if err != nil || fixtureWarmCancellationStatus(o, observed) != nil {
		return ErrFixtures
	}
	var typed arcadev1.GameDestroy
	if decodeServing(o, &typed) != nil || len(typed.ManagedFields) != 3 || !slices.IsSortedFunc(typed.ManagedFields, fixtureNativeFieldOrder) {
		return ErrFixtures
	}
	fields, found, err := unstructured.NestedSlice(o.Object, "metadata", "managedFields")
	if err != nil || !found || len(fields) != 3 {
		return ErrFixtures
	}
	seen := [3]bool{}
	var installer any
	for i, field := range typed.ManagedFields {
		raw, ok := fields[i].(map[string]any)
		if !ok || field.Time == nil || !fixtureResultTime(raw["time"], typed.CreationTimestamp.Time, observed.UTC().Add(time.Second)) {
			return ErrFixtures
		}
		role := -1
		var tree map[string]any
		switch {
		case field.Manager == "arcadectl-installer" && field.Subresource == "":
			role, tree = 0, fixtureResultFieldset(want)
			installer = fields[i]
		case field.Manager == "arcadectl-controller" && field.Subresource == "":
			role, tree = 1, fixtureWarmFinalizerFieldset()
		case field.Manager == "arcadectl-controller" && field.Subresource == "status":
			role, tree = 2, fixtureWarmCancellationFieldset()
		}
		if role == -1 || seen[role] || tree == nil {
			return ErrFixtures
		}
		seen[role] = true
		expected := map[string]any{
			"manager": field.Manager, "operation": "Update", "apiVersion": want.GetAPIVersion(),
			"fieldsType": "FieldsV1", "fieldsV1": tree, "time": raw["time"],
		}
		if field.Subresource != "" {
			expected["subresource"] = field.Subresource
		}
		if !reflect.DeepEqual(fields[i], expected) {
			return ErrFixtures
		}
	}
	// Remove ONLY separately checked additions on a private copy. The unchanged
	// cold whole-object validator checks every remaining raw metadata/spec field,
	// original durable UID, canonical RV and original generation. No observation
	// snapshot is filtered into an ordinary lifecycle safety checkpoint.
	base := o.DeepCopy()
	delete(base.Object, "status")
	delete(base.Object["metadata"].(map[string]any), "finalizers")
	if unstructured.SetNestedSlice(base.Object, []any{installer}, "metadata", "managedFields") != nil || f.validateResult(slot, fixtureStableResult, base, observed) != nil {
		return ErrFixtures
	}
	return nil
}

// Native apimachinery sorts by this COMPLETE tuple. Different manager names
// make a main-before-status shortcut wrong for equal-second warm updates.
func fixtureNativeFieldOrder(a, b metav1.ManagedFieldsEntry) int {
	if c := strings.Compare(string(a.Operation), string(b.Operation)); c != 0 {
		return c
	}
	var at, bt int64
	if a.Time != nil {
		at = a.Time.Unix()
	}
	if b.Time != nil {
		bt = b.Time.Unix()
	}
	if at < bt {
		return -1
	}
	if at > bt {
		return 1
	}
	if c := strings.Compare(a.Manager, b.Manager); c != 0 {
		return c
	}
	if c := strings.Compare(a.APIVersion, b.APIVersion); c != 0 {
		return c
	}
	return strings.Compare(a.Subresource, b.Subresource)
}

func fixtureWarmFinalizerFieldset() map[string]any {
	return map[string]any{"f:metadata": map[string]any{"f:finalizers": map[string]any{
		".": map[string]any{}, `v:"` + platformkube.DestroyFinalizer + `"`: map[string]any{},
	}}}
}

func fixtureWarmCancellationFieldset() map[string]any {
	status := fixtureFieldLeaves(".", "completedAt", "observedGeneration", "phase", "startedAt")
	status["f:conditions"] = map[string]any{
		".": map[string]any{}, `k:{"type":"Complete"}`: fixtureFieldLeaves(".", "lastTransitionTime", "message", "observedGeneration", "reason", "status", "type"),
	}
	return map[string]any{"f:status": status}
}

func fixtureWarmCancellationStatus(o *unstructured.Unstructured, observed time.Time) error {
	if o == nil || o.GetAPIVersion() != "arcade.gobha.me/v1alpha1" || o.GetKind() != "GameDestroy" || o.GetGeneration() != 1 || o.GetDeletionTimestamp() != nil || !fixtureRV(o.GetResourceVersion()) || !nativeFixtureUID(string(o.GetUID())) || !reflect.DeepEqual(o.GetFinalizers(), []string{platformkube.DestroyFinalizer}) {
		return ErrFixtures
	}
	created := o.GetCreationTimestamp().Time
	if observed.IsZero() || created.IsZero() || created.Year() < 1 || created.Year() > 9999 || observed.Year() > 9999 || created.After(observed.Add(time.Second)) {
		return ErrFixtures
	}
	status, found, err := unstructured.NestedMap(o.Object, "status")
	if err != nil || !found {
		return ErrFixtures
	}
	conditions, ok := status["conditions"].([]any)
	if !ok || len(conditions) != 1 {
		return ErrFixtures
	}
	condition, ok := conditions[0].(map[string]any)
	if !ok {
		return ErrFixtures
	}
	ceiling := observed.UTC().Add(time.Second)
	for _, raw := range []any{status["startedAt"], status["completedAt"], condition["lastTransitionTime"]} {
		if !fixtureResultTime(raw, created, ceiling) {
			return ErrFixtures
		}
	}
	started, _ := time.Parse(time.RFC3339, status["startedAt"].(string))
	completed, _ := time.Parse(time.RFC3339, status["completedAt"].(string))
	transition, _ := time.Parse(time.RFC3339, condition["lastTransitionTime"].(string))
	if completed.Before(started) || transition.Before(completed) || !reflect.DeepEqual(status, map[string]any{
		"phase": "Cancelled", "observedGeneration": int64(1), "startedAt": status["startedAt"], "completedAt": status["completedAt"],
		"conditions": []any{map[string]any{"type": arcadev1.ConditionOperationComplete, "status": "False", "observedGeneration": int64(1), "reason": "Cancelled", "message": "destroy cancelled before any PVC deletion", "lastTransitionTime": condition["lastTransitionTime"]}},
	}) {
		return ErrFixtures
	}
	return nil
}
