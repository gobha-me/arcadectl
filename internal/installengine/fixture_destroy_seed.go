// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"reflect"
	"time"

	arcadev1 "github.com/gobha-me/arcadectl/api/v1alpha1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

const (
	fixtureDestroySeedExpiry   = "2000-01-01T00:00:00Z"
	fixtureDestroySeedGuidance = "Isolated cancelled admission fixture; no world or restore artifact exists."
)

// Pure closed recipe, NOT permission to update status. A future provider must
// independently prove the original controller is cold, the original object
// has the absent-status shape, descendants are absent, and a durable once-only
// status intent exists. Never reuse this recipe for an adopted object or world.
// The expired preview enables a schema-valid dry-run confirmation addition;
// no confirmation is persisted. Cancelled status alone does not prove coldness:
// a running controller may still add a finalizer and perform terminal cleanup.
func (f *fixtureLedger) destroySeedStatus() (map[string]any, error) {
	if f == nil || f.document.DestroySeed != nil && f.document.DestroySeed.Mode != fixtureDestroySeedCold {
		return nil, ErrFixtures
	}
	if _, err := f.object(fixtureCancelledDestroy); err != nil {
		return nil, ErrFixtures
	}
	entry := f.document.Entries[fixtureCancelledDestroy]
	if entry.State != fixtureOriginal || !nativeFixtureUID(string(entry.OriginalUID)) {
		return nil, ErrFixtures
	}
	return map[string]any{
		"phase": "Cancelled",
		"preview": map[string]any{
			"challenge": f.document.RunID, "expiresAt": fixtureDestroySeedExpiry, "restoreGuidance": fixtureDestroySeedGuidance,
		},
	}, nil
}

// This schema-derived fieldset is not by itself native-profile certification.
// The once-only status transport must prove it against both declared profiles.
func fixtureDestroySeedFieldset() map[string]any {
	return map[string]any{"f:status": map[string]any{
		".": map[string]any{}, "f:phase": map[string]any{},
		"f:preview": fixtureFieldLeaves(".", "challenge", "expiresAt", "restoreGuidance"),
	}}
}

// Pure whole-shape check, deliberately separate from validateResult, which
// continues to reject EVERY GameDestroy status. This is neither a status ACK
// nor freshness/permission/recovery/cleanup authority. In particular it cannot
// settle an unknown effect or relax the active fixture WAL fence.
func (f *fixtureLedger) validateDestroySeedResult(result *unstructured.Unstructured, observedAt time.Time) error {
	expiry := time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)
	if f == nil || f.document.DestroySeed != nil && f.document.DestroySeed.Mode != fixtureDestroySeedCold || result == nil || observedAt.Year() > 9999 || !observedAt.After(expiry) {
		return ErrFixtures
	}
	status, err := f.destroySeedStatus()
	if err != nil || !reflect.DeepEqual(result.Object["status"], status) {
		return ErrFixtures
	}
	var typed arcadev1.GameDestroy
	if decodeServing(result, &typed) != nil {
		return ErrFixtures
	}
	fields, found, err := unstructured.NestedSlice(result.Object, "metadata", "managedFields")
	if err != nil || !found || len(fields) != 2 {
		return ErrFixtures
	}
	field, ok := fields[1].(map[string]any)
	if !ok || !fixtureResultTime(field["time"], typed.CreationTimestamp.Time, observedAt.UTC().Add(time.Second)) {
		return ErrFixtures
	}
	if !reflect.DeepEqual(field, map[string]any{
		"manager": "arcadectl-installer", "operation": "Update", "apiVersion": "arcade.gobha.me/v1alpha1",
		"fieldsType": "FieldsV1", "fieldsV1": fixtureDestroySeedFieldset(), "time": field["time"], "subresource": "status",
	}) {
		return ErrFixtures
	}
	// Remove ONLY the independently checked exact status and extra fieldset on a
	// private copy. The ordinary validator still checks all remaining metadata,
	// signed spec/audit annotation, original UID, canonical RV and generation.
	base := result.DeepCopy()
	delete(base.Object, "status")
	if unstructured.SetNestedSlice(base.Object, fields[:1], "metadata", "managedFields") != nil || f.validateResult(fixtureCancelledDestroy, fixtureStableResult, base, observedAt) != nil {
		return ErrFixtures
	}
	return nil
}
