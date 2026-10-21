// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"reflect"
	"slices"
	"time"

	arcadev1 "github.com/gobha-me/arcadectl/api/v1alpha1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Pure warm dry-run shape contract. The exact four-role delta is certified by
// the separate native test on both supported profiles. This is NOT permission
// to persist confirmation or a provider checkpoint. The closed caller must
// verify distinct-admin acceptance, exact controller-policy denial and a fresh
// byte-exact original GET after EVERY dry-run, with independent isolation.
func (f *fixtureLedger) validateWarmDestroyConfirmationResult(result *unstructured.Unstructured, observed time.Time) error {
	if f == nil || result == nil || f.document.DestroySeed == nil || f.document.DestroySeed.Mode != fixtureDestroySeedWarmCancelled || f.document.DestroySeed.State != fixtureDestroySeedAcknowledged || result.GetResourceVersion() != f.document.DestroySeed.AcknowledgedResourceVersion || result.GetGeneration() != 2 {
		return ErrFixtures
	}
	want, err := f.object(fixtureCancelledDestroy)
	if err != nil || unstructured.SetNestedField(want.Object, f.document.RunID, "spec", "confirmationChallenge") != nil || !reflect.DeepEqual(result.Object["spec"], want.Object["spec"]) {
		return ErrFixtures
	}
	fieldset := fixtureResultFieldset(want)
	if fieldset == nil {
		return ErrFixtures
	}
	fieldset["f:spec"].(map[string]any)["f:confirmationChallenge"] = map[string]any{}
	var typed arcadev1.GameDestroy
	fields, found, err := unstructured.NestedSlice(result.Object, "metadata", "managedFields")
	if err != nil || !found || len(fields) != 4 || decodeServing(result, &typed) != nil || len(typed.ManagedFields) != 4 || !slices.IsSortedFunc(typed.ManagedFields, fixtureNativeFieldOrder) {
		return ErrFixtures
	}
	mainIndex := -1
	var mainTime, seedTime time.Time
	for index, field := range typed.ManagedFields {
		if field.Manager != "arcadectl-installer" {
			continue
		}
		if field.Time == nil {
			return ErrFixtures
		}
		switch field.Subresource {
		case "":
			raw, ok := fields[index].(map[string]any)
			if !ok || mainIndex != -1 || !reflect.DeepEqual(raw["fieldsV1"], fieldset) {
				return ErrFixtures
			}
			mainIndex, mainTime = index, field.Time.Time
		case "status":
			if !seedTime.IsZero() {
				return ErrFixtures
			}
			seedTime = field.Time.Time
		}
	}
	if mainIndex == -1 || seedTime.IsZero() || mainTime.Before(seedTime) {
		return ErrFixtures
	}
	base := result.DeepCopy()
	unstructured.RemoveNestedField(base.Object, "spec", "confirmationChallenge")
	base.SetGeneration(1)
	delete(fieldset["f:spec"].(map[string]any), "f:confirmationChallenge")
	fields[mainIndex].(map[string]any)["fieldsV1"] = fieldset
	// Removing one fieldset leaf changes none of the native sort tuple. Keep
	// the independently checked returned ordering rather than repair a reply.
	if unstructured.SetNestedSlice(base.Object, fields, "metadata", "managedFields") != nil || f.validateWarmDestroySeedResult(base, observed) != nil {
		return ErrFixtures
	}
	return nil
}
