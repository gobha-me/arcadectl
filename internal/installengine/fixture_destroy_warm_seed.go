// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"reflect"
	"slices"
	"time"

	arcadev1 "github.com/gobha-me/arcadectl/api/v1alpha1"
	platformkube "github.com/gobha-me/arcadectl/internal/platform/kube"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Pure constructor-derived warm recipe, NOT status mutation permission. Mode
// must have been chosen in the protected intent before any effect. Neither live
// cancellation bookkeeping nor returned status supplies bytes for this recipe.
func (f *fixtureLedger) destroyWarmSeedStatus() (map[string]any, error) {
	if f == nil || f.document.DestroySeed == nil || f.document.DestroySeed.Mode != fixtureDestroySeedWarmCancelled {
		return nil, ErrFixtures
	}
	if _, err := f.object(fixtureCancelledDestroy); err != nil || f.document.Entries[fixtureCancelledDestroy].State != fixtureOriginal || !nativeFixtureUID(string(f.document.Entries[fixtureCancelledDestroy].OriginalUID)) {
		return nil, ErrFixtures
	}
	return map[string]any{"phase": "Cancelled", "preview": map[string]any{
		"challenge": f.document.RunID, "expiresAt": fixtureDestroySeedExpiry, "restoreGuidance": fixtureDestroySeedGuidance,
	}}, nil
}

// Exact four native roles were independently observed on both declared profiles.
// This pure shape contract does NOT send status, confer identity/freshness,
// prove coldness, authorize cleanup, accept confirmation or retire a WAL. The
// private TEST learning subset dictionary is deliberately NOT reused here.
func (f *fixtureLedger) validateWarmDestroySeedResult(o *unstructured.Unstructured, observed time.Time) error {
	expiry := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	if f == nil || o == nil || observed.Year() > 9999 || !observed.After(expiry) || f.document.DestroySeed == nil || f.document.DestroySeed.Mode != fixtureDestroySeedWarmCancelled || f.document.DestroySeed.State != fixtureDestroySeedAcknowledged || o.GetResourceVersion() != f.document.DestroySeed.AcknowledgedResourceVersion || o.GetGeneration() != 1 || !reflect.DeepEqual(o.GetFinalizers(), []string{platformkube.DestroyFinalizer}) {
		return ErrFixtures
	}
	want, err := f.object(fixtureCancelledDestroy)
	status, statusErr := f.destroyWarmSeedStatus()
	if err != nil || statusErr != nil || !reflect.DeepEqual(o.Object["status"], status) {
		return ErrFixtures
	}
	var typed arcadev1.GameDestroy
	fields, found, fieldsErr := unstructured.NestedSlice(o.Object, "metadata", "managedFields")
	if fieldsErr != nil || !found || len(fields) != 4 || decodeServing(o, &typed) != nil || len(typed.ManagedFields) != 4 || !slices.IsSortedFunc(typed.ManagedFields, fixtureNativeFieldOrder) {
		return ErrFixtures
	}
	seen := [4]bool{}
	var installer any
	for index, field := range typed.ManagedFields {
		raw, ok := fields[index].(map[string]any)
		if !ok || field.Time == nil || !fixtureResultTime(raw["time"], typed.CreationTimestamp.Time, observed.UTC().Add(time.Second)) {
			return ErrFixtures
		}
		role := -1
		var tree map[string]any
		switch {
		case field.Manager == "arcadectl-installer" && field.Subresource == "":
			role, tree, installer = 0, fixtureResultFieldset(want), raw
		case field.Manager == "arcadectl-controller" && field.Subresource == "":
			role, tree = 1, fixtureWarmFinalizerFieldset()
		case field.Manager == "arcadectl-controller" && field.Subresource == "status":
			role, tree = 2, fixtureWarmSeedControllerFieldset()
		case field.Manager == "arcadectl-installer" && field.Subresource == "status":
			role, tree = 3, fixtureWarmSeedInstallerFieldset()
		}
		if role == -1 || seen[role] || tree == nil {
			return ErrFixtures
		}
		seen[role] = true
		expected := map[string]any{"manager": field.Manager, "operation": "Update", "apiVersion": want.GetAPIVersion(), "fieldsType": "FieldsV1", "fieldsV1": tree, "time": raw["time"]}
		if field.Subresource != "" {
			expected["subresource"] = field.Subresource
		}
		if !reflect.DeepEqual(raw, expected) {
			return ErrFixtures
		}
	}
	// Strip ONLY independently checked additions on a private copy. Preserve the
	// checked original installer-main record and run unchanged whole validation
	// over every remaining raw metadata/spec field and durable original identity.
	base := o.DeepCopy()
	delete(base.Object, "status")
	unstructured.RemoveNestedField(base.Object, "metadata", "finalizers")
	if unstructured.SetNestedSlice(base.Object, []any{installer}, "metadata", "managedFields") != nil || f.validateResult(fixtureCancelledDestroy, fixtureStableResult, base, observed) != nil {
		return ErrFixtures
	}
	return nil
}

func fixtureWarmSeedControllerFieldset() map[string]any {
	return map[string]any{"f:status": fixtureFieldLeaves(".", "phase")}
}

func fixtureWarmSeedInstallerFieldset() map[string]any {
	return map[string]any{"f:status": map[string]any{
		"f:preview": fixtureFieldLeaves(".", "challenge", "expiresAt", "restoreGuidance"),
	}}
}
