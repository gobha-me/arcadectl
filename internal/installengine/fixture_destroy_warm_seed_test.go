// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"encoding/json"
	"reflect"
	"slices"
	"testing"
	"time"

	arcadev1 "github.com/gobha-me/arcadectl/api/v1alpha1"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Pure native-derived examples and abstract receipt instrumentation, NOT live
// status effects, reliable wire ACKs, coldness or cleanup permission. Non-main
// role trees below are independent exact golden bytes from BOTH native profiles,
// never derived from the production fieldset helpers under test.
func fixtureWarmSeededExample(t *testing.T, f *fixtureLedger, created time.Time, offsets [4]time.Duration) *unstructured.Unstructured {
	t.Helper()
	o := fixtureWarmCancelledExample(t, f, created, [3]time.Duration{time.Second, time.Second, time.Second})
	o.SetResourceVersion("102")
	o.Object["status"] = map[string]any{"phase": "Cancelled", "preview": map[string]any{
		"challenge": f.document.RunID, "expiresAt": "2000-01-01T00:00:00Z", "restoreGuidance": "Isolated cancelled admission fixture; no world or restore artifact exists.",
	}}
	want, err := f.object(fixtureCancelledDestroy)
	if err != nil {
		t.Fatal("protected original constructor unavailable")
	}
	trees := []map[string]any{fixtureResultFieldset(want)}
	for _, golden := range []string{
		`{"f:metadata":{"f:finalizers":{".":{},"v:\"arcade.gobha.me/destroy-protection\"":{}}}}`,
		`{"f:status":{".":{},"f:phase":{}}}`,
		`{"f:status":{"f:preview":{".":{},"f:challenge":{},"f:expiresAt":{},"f:restoreGuidance":{}}}}`,
	} {
		var tree map[string]any
		if json.Unmarshal([]byte(golden), &tree) != nil {
			t.Fatal("independent native golden tree invalid")
		}
		trees = append(trees, tree)
	}
	fields := make([]any, 4)
	for index, role := range []struct{ manager, subresource string }{
		{"arcadectl-installer", ""}, {"arcadectl-controller", ""}, {"arcadectl-controller", "status"}, {"arcadectl-installer", "status"},
	} {
		field := map[string]any{"manager": role.manager, "operation": "Update", "apiVersion": o.GetAPIVersion(), "fieldsType": "FieldsV1", "fieldsV1": trees[index], "time": created.Add(offsets[index]).Format(time.RFC3339)}
		if role.subresource != "" {
			field["subresource"] = role.subresource
		}
		fields[index] = field
	}
	var typed arcadev1.GameDestroy
	if unstructured.SetNestedSlice(o.Object, fields, "metadata", "managedFields") != nil || decodeServing(o, &typed) != nil {
		t.Fatal("native golden metadata unavailable")
	}
	indices := []int{0, 1, 2, 3}
	slices.SortFunc(indices, func(i, j int) int { return fixtureNativeFieldOrder(typed.ManagedFields[i], typed.ManagedFields[j]) })
	ordered := []any{fields[indices[0]], fields[indices[1]], fields[indices[2]], fields[indices[3]]}
	if unstructured.SetNestedSlice(o.Object, ordered, "metadata", "managedFields") != nil {
		t.Fatal("native golden role ordering unavailable")
	}
	return o
}

func TestFixtureWarmDestroySeedExactNativeRolesAndPurity(t *testing.T) {
	created := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	for _, profile := range []string{installrender.Profile135, installrender.Profile137} {
		t.Run(profile, func(t *testing.T) {
			f := newFixtureWithPlans(t, false, fixturePlanProfile(t, "isolated-install", profile))
			ledger, err := f.engine.prepareFixtureLedger(t.Context(), f.snapshot)
			if err != nil {
				t.Fatal("original ledger unavailable")
			}
			defer ledger.close()
			acknowledgeAllRecipeFixtures(t, ledger)
			intent := fixtureSeedIntent(t, ledger)
			intent.DestroySeed.Mode = fixtureDestroySeedWarmCancelled
			if ledger.advance(intent) != nil {
				t.Fatal("abstract warm intent unavailable")
			}
			unknown := fixtureWarmSeededExample(t, ledger, created, [4]time.Duration{time.Second, time.Second, time.Second, 2 * time.Second})
			if ledger.validateWarmDestroySeedResult(unknown, created.Add(time.Minute)) != ErrFixtures {
				t.Fatal("unknown intent acquired pure seeded acceptance")
			}
			ledger.seedEffect = false // TEST instrumentation, not a native wire ACK
			if ledger.advance(fixtureSeedAcknowledgement(t, ledger)) != nil {
				t.Fatal("abstract warm receipt instrumentation refused")
			}
			before, identity, revision := bytes.Clone(ledger.body), ledger.identity, ledger.document.Revision
			expiry := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
			old := fixtureWarmSeededExample(t, ledger, expiry.Add(-time.Minute), [4]time.Duration{time.Second, time.Second, time.Second, 2 * time.Second})
			for _, observed := range []time.Time{expiry.Add(-time.Second), expiry} {
				if ledger.validateWarmDestroySeedResult(old, observed) != ErrFixtures {
					t.Fatal("warm supposedly expired preview accepted before/at expiry")
				}
			}
			if ledger.validateWarmDestroySeedResult(old, expiry.Add(time.Nanosecond)) != nil {
				t.Fatal("strictly expired public preview boundary refused")
			}
			for _, golden := range []struct {
				offsets [4]time.Duration
				roles   []string
			}{
				{[4]time.Duration{time.Second, time.Second, time.Second, 2 * time.Second}, []string{"arcadectl-controller:", "arcadectl-controller:status", "arcadectl-installer:", "arcadectl-installer:status"}},
				{[4]time.Duration{time.Second, 2 * time.Second, 3 * time.Second, 4 * time.Second}, []string{"arcadectl-installer:", "arcadectl-controller:", "arcadectl-controller:status", "arcadectl-installer:status"}},
				{[4]time.Duration{3 * time.Second, time.Second, time.Second, 3 * time.Second}, []string{"arcadectl-controller:", "arcadectl-controller:status", "arcadectl-installer:", "arcadectl-installer:status"}},
				{[4]time.Duration{4 * time.Second, time.Second, 2 * time.Second, 3 * time.Second}, []string{"arcadectl-controller:", "arcadectl-controller:status", "arcadectl-installer:status", "arcadectl-installer:"}},
			} {
				o := fixtureWarmSeededExample(t, ledger, created, golden.offsets)
				original := o.DeepCopy()
				roles := []string{}
				for _, field := range o.GetManagedFields() {
					roles = append(roles, field.Manager+":"+field.Subresource)
				}
				if !reflect.DeepEqual(roles, golden.roles) || ledger.validateWarmDestroySeedResult(o, created.Add(time.Minute)) != nil || !reflect.DeepEqual(o, original) {
					t.Fatal("strict warm seeded golden/order/purity contract refused")
				}
				status, err := ledger.destroyWarmSeedStatus()
				if err != nil || !reflect.DeepEqual(status, o.Object["status"]) {
					t.Fatal("warm recipe differs from independent native fixed status")
				}
				status["phase"] = "Deleting"
				if o.Object["status"].(map[string]any)["phase"] != "Cancelled" || ledger.validateDestroySeedResult(o, created.Add(time.Minute)) != ErrFixtures || ledger.validateWarmCancelledDestroyResult(o, created.Add(time.Minute)) != ErrFixtures {
					t.Fatal("pure warm recipe aliases input or relaxes other whole validators")
				}
				fields, _, _ := unstructured.NestedSlice(o.Object, "metadata", "managedFields")
				for index := range fields {
					for _, change := range []string{"drop", "duplicate", "manager", "operation", "apiVersion", "fieldsType", "unknown", "null-subresource", "null-tree", "time", "controller-leftovers", "installer-phase", "installer-root"} {
						bad := o.DeepCopy()
						copyFields, _, _ := unstructured.NestedSlice(bad.Object, "metadata", "managedFields")
						field := copyFields[index].(map[string]any)
						switch change {
						case "drop":
							copyFields = append(copyFields[:index], copyFields[index+1:]...)
						case "duplicate":
							copyFields[index] = copyFields[(index+1)%4]
						case "null-subresource":
							field["subresource"] = nil
						case "null-tree":
							field["fieldsV1"] = nil
						case "time":
							field["time"] = created.Add(time.Hour).Format(time.RFC3339)
						case "controller-leftovers":
							if field["manager"] != "arcadectl-controller" || field["subresource"] != "status" {
								continue
							}
							field["fieldsV1"] = fixtureWarmCancellationFieldset()
						case "installer-phase", "installer-root":
							if field["manager"] != "arcadectl-installer" || field["subresource"] != "status" {
								continue
							}
							tree := field["fieldsV1"].(map[string]any)["f:status"].(map[string]any)
							key := "f:phase"
							if change == "installer-root" {
								key = "."
							}
							tree[key] = map[string]any{}
						default:
							field[change] = "PRIVATE-WARM-SEEDED-CANARY"
						}
						_ = unstructured.SetNestedSlice(bad.Object, copyFields, "metadata", "managedFields")
						if ledger.validateWarmDestroySeedResult(bad, created.Add(time.Minute)) != ErrFixtures {
							t.Fatal("strict warm seeded raw role mutation accepted", change)
						}
					}
					for other := index + 1; other < len(fields); other++ {
						bad := o.DeepCopy()
						copyFields, _, _ := unstructured.NestedSlice(bad.Object, "metadata", "managedFields")
						copyFields[index], copyFields[other] = copyFields[other], copyFields[index]
						_ = unstructured.SetNestedSlice(bad.Object, copyFields, "metadata", "managedFields")
						if ledger.validateWarmDestroySeedResult(bad, created.Add(time.Minute)) != ErrFixtures {
							t.Fatal("unordered native warm seeded roles accepted")
						}
					}
				}
				for _, change := range []string{"rv", "uid", "generation", "spec", "status", "finalizer", "metadata", "annotation"} {
					bad := o.DeepCopy()
					switch change {
					case "rv":
						bad.SetResourceVersion("999")
					case "uid":
						bad.SetUID("c0000000-0000-4000-8000-000000000001")
					case "generation":
						bad.SetGeneration(2)
					case "spec":
						_ = unstructured.SetNestedField(bad.Object, false, "spec", "cancelRequested")
					case "status":
						_ = unstructured.SetNestedField(bad.Object, "PRIVATE-WARM-SEEDED-CANARY", "status", "preview", "restoreGuidance")
					case "finalizer":
						bad.SetFinalizers(nil)
					case "metadata":
						_ = unstructured.SetNestedField(bad.Object, nil, "metadata", "unknown")
					case "annotation":
						bad.SetAnnotations(nil)
					}
					if ledger.validateWarmDestroySeedResult(bad, created.Add(time.Minute)) != ErrFixtures {
						t.Fatal("unproved warm seeded metadata/spec/status accepted", change)
					}
				}
			}
			stored, storedID, err := f.engine.files.Read(ledger.name, fixtureLedgerMaxBytes)
			if err != nil || !bytes.Equal(stored, before) || storedID != identity || !bytes.Equal(ledger.body, before) || ledger.document.Revision != revision || ledger.seedAck || ledger.seedEffect || f.access.writes != 0 || f.nsUpdates != 0 || f.engine.fixtureFence(f.snapshot) != ErrFixtures {
				t.Fatal("pure warm seeded validation mutated WAL/capabilities or granted effects")
			}
			// In-memory mode corruption cannot route to warm acceptance; the
			// protected canonical document and ordinary cold contract stay intact.
			ledger.document.DestroySeed.Mode = fixtureDestroySeedCold
			if _, err := ledger.destroyWarmSeedStatus(); err != ErrFixtures || ledger.validateWarmDestroySeedResult(unknown, created.Add(time.Minute)) != ErrFixtures {
				t.Fatal("cold mode entered warm recipe/whole validator")
			}
			ledger.document.DestroySeed.Mode = fixtureDestroySeedWarmCancelled
			if (&fixtureWire{ledger: ledger}).fixturesSettled() {
				t.Fatal("warm shape acceptance relaxed cold composition")
			}
		})
	}
	var absent *fixtureLedger
	if _, err := absent.destroyWarmSeedStatus(); err != ErrFixtures || absent.validateWarmDestroySeedResult(nil, created) != ErrFixtures {
		t.Fatal("nil warm recipe/shape receiver accepted")
	}
}
