// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"reflect"
	"time"

	arcadev1 "github.com/gobha-me/arcadectl/api/v1alpha1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Pure validation of the ONE schema-valid dry-run confirmation delta. It is
// not permission to persist confirmation, an ownership ACK or cleanup proof.
// The provider must pair distinct-admin acceptance with exact controller policy
// denial and uncached byte-exact original observation after EVERY dry-run.
func (f *fixtureLedger) validateDestroyConfirmationResult(result *unstructured.Unstructured, observedAt time.Time) error {
	if result == nil || f == nil || f.document.DestroySeed == nil || f.document.DestroySeed.Mode != fixtureDestroySeedCold || f.document.DestroySeed.State != fixtureDestroySeedAcknowledged || result.GetResourceVersion() != f.document.DestroySeed.AcknowledgedResourceVersion || result.GetGeneration() != 2 {
		return ErrFixtures
	}
	want, err := f.object(fixtureCancelledDestroy)
	if err != nil {
		return ErrFixtures
	}
	fieldset := fixtureResultFieldset(want)
	if fieldset == nil {
		return ErrFixtures
	}
	fieldset["f:spec"].(map[string]any)["f:confirmationChallenge"] = map[string]any{}
	if unstructured.SetNestedField(want.Object, f.document.RunID, "spec", "confirmationChallenge") != nil || !reflect.DeepEqual(result.Object["spec"], want.Object["spec"]) {
		return ErrFixtures
	}
	fields, found, err := unstructured.NestedSlice(result.Object, "metadata", "managedFields")
	if err != nil || !found || len(fields) != 2 {
		return ErrFixtures
	}
	var main, status map[string]any
	mainIndex := -1
	for index, raw := range fields {
		field, ok := raw.(map[string]any)
		if !ok {
			return ErrFixtures
		}
		subresource, present := field["subresource"]
		if !present && main == nil {
			main, mainIndex = field, index
		} else if subresource == "status" && status == nil {
			status = field
		} else {
			return ErrFixtures
		}
	}
	var typed arcadev1.GameDestroy
	if main == nil || status == nil || decodeServing(result, &typed) != nil || !reflect.DeepEqual(main["fieldsV1"], fieldset) || !fixtureResultTime(main["time"], typed.CreationTimestamp.Time, observedAt.UTC().Add(time.Second)) || !fixtureResultTime(status["time"], typed.CreationTimestamp.Time, observedAt.UTC().Add(time.Second)) {
		return ErrFixtures
	}
	mainTime, _ := time.Parse(time.RFC3339, main["time"].(string))
	statusTime, _ := time.Parse(time.RFC3339, status["time"].(string))
	// Native managedFields sorts by whole-second time before subresource. A
	// changed main spec updates its time; older status therefore comes first.
	// Equal times sort main's absent subresource before status. The update may
	// not predate the original seed. All other exact field attributes are still
	// checked by the strict seeded validator after this verified role ordering.
	if mainTime.Before(statusTime) || mainTime.Equal(statusTime) && mainIndex != 0 || mainTime.After(statusTime) && mainIndex != 1 {
		return ErrFixtures
	}
	base := result.DeepCopy()
	unstructured.RemoveNestedField(base.Object, "spec", "confirmationChallenge")
	base.SetGeneration(1)
	delete(fieldset["f:spec"].(map[string]any), "f:confirmationChallenge")
	main["fieldsV1"] = fieldset
	if unstructured.SetNestedSlice(base.Object, []any{main, status}, "metadata", "managedFields") != nil || f.validateDestroySeedResult(base, observedAt) != nil {
		return ErrFixtures
	}
	return nil
}
