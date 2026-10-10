// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"reflect"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installrender"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Synthetic native-derived confirmation examples, NOT real native replies.
// Role trees start from the independently native-derived seeded goldens; the
// ONE new leaf and expected role order are explicit, not production-derived.
func fixtureWarmConfirmationExample(t *testing.T, f *fixtureLedger, created time.Time, sameSecond bool) *unstructured.Unstructured {
	t.Helper()
	o := fixtureWarmSeededExample(t, f, created, [4]time.Duration{time.Second, time.Second, time.Second, 2 * time.Second})
	o.SetGeneration(2)
	if unstructured.SetNestedField(o.Object, f.document.RunID, "spec", "confirmationChallenge") != nil {
		t.Fatal("hypothetical confirmation unavailable")
	}
	fields, _, _ := unstructured.NestedSlice(o.Object, "metadata", "managedFields")
	roles := map[string]any{}
	for _, item := range fields {
		field := item.(map[string]any)
		subresource, _ := field["subresource"].(string)
		role := field["manager"].(string) + ":" + subresource
		if role == "arcadectl-installer:" {
			field["fieldsV1"].(map[string]any)["f:spec"].(map[string]any)["f:confirmationChallenge"] = map[string]any{}
			delay := 3 * time.Second
			if sameSecond {
				delay = 2 * time.Second
			}
			field["time"] = created.Add(delay).Format(time.RFC3339)
		}
		roles[role] = field
	}
	ordered := []any{roles["arcadectl-controller:"], roles["arcadectl-controller:status"], roles["arcadectl-installer:status"], roles["arcadectl-installer:"]}
	if sameSecond {
		ordered[2], ordered[3] = ordered[3], ordered[2]
	}
	if unstructured.SetNestedSlice(o.Object, ordered, "metadata", "managedFields") != nil {
		t.Fatal("hypothetical ordered fields unavailable")
	}
	return o
}

func TestFixtureWarmConfirmationClosedDeltaOrderingAndPurity(t *testing.T) {
	created := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	observed := created.Add(time.Minute)
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
			unknown := fixtureWarmConfirmationExample(t, ledger, created, false)
			if ledger.validateWarmDestroyConfirmationResult(unknown, observed) != ErrFixtures {
				t.Fatal("unknown seed acquired confirmation acceptance")
			}
			ledger.seedEffect = false // Abstract test receipt, never a wire ACK.
			if ledger.advance(fixtureSeedAcknowledgement(t, ledger)) != nil {
				t.Fatal("abstract warm receipt unavailable")
			}
			before, identity, revision := bytes.Clone(ledger.body), ledger.identity, ledger.document.Revision
			for _, sameSecond := range []bool{false, true} {
				result := fixtureWarmConfirmationExample(t, ledger, created, sameSecond)
				input := result.DeepCopy()
				if ledger.validateWarmDestroyConfirmationResult(result, observed) != nil || !reflect.DeepEqual(input, result) || ledger.validateWarmDestroySeedResult(result, observed) != ErrFixtures || ledger.validateDestroyConfirmationResult(result, observed) != ErrFixtures {
					t.Fatal("pure hypothetical delta/order refused, mutated input or crossed modes")
				}
				for _, change := range []string{"challenge", "missing-challenge", "missing-main-leaf", "extra-main-leaf", "cancel", "uid", "rv", "generation", "status", "finalizer", "metadata", "missing-role", "duplicate-role", "order", "before-seed"} {
					bad := result.DeepCopy()
					fields, _, _ := unstructured.NestedSlice(bad.Object, "metadata", "managedFields")
					switch change {
					case "challenge":
						_ = unstructured.SetNestedField(bad.Object, "foreign", "spec", "confirmationChallenge")
					case "missing-challenge":
						// Keep the owned leaf, testing the independent spec guard.
						unstructured.RemoveNestedField(bad.Object, "spec", "confirmationChallenge")
					case "missing-main-leaf", "extra-main-leaf":
						// Keep the exact valid spec, isolating the main-fieldset
						// check before composition replaces that tree.
						for _, item := range fields {
							field := item.(map[string]any)
							if field["manager"] != "arcadectl-installer" || field["subresource"] != nil {
								continue
							}
							spec := field["fieldsV1"].(map[string]any)["f:spec"].(map[string]any)
							if change == "missing-main-leaf" {
								delete(spec, "f:confirmationChallenge")
							} else {
								spec["f:PRIVATE-CANARY"] = map[string]any{}
							}
						}
					case "cancel":
						_ = unstructured.SetNestedField(bad.Object, false, "spec", "cancelRequested")
					case "uid":
						bad.SetUID("20000000-0000-4000-8000-000000000001")
					case "rv":
						bad.SetResourceVersion("999")
					case "generation":
						bad.SetGeneration(1)
					case "status":
						_ = unstructured.SetNestedField(bad.Object, "Deleting", "status", "phase")
					case "finalizer":
						bad.SetFinalizers(nil)
					case "metadata":
						_ = unstructured.SetNestedField(bad.Object, "PRIVATE-CANARY", "metadata", "private")
					case "missing-role":
						fields = fields[:3]
					case "duplicate-role":
						fields[0] = fields[1]
					case "order":
						fields[0], fields[1] = fields[1], fields[0]
					case "before-seed":
						// Maintain valid native ordering, isolating the temporal
						// guard from the returned-order rejection above.
						mainIndex := 3
						if sameSecond {
							mainIndex = 2
						}
						main := fields[mainIndex].(map[string]any)
						main["time"] = created.Add(time.Second).Format(time.RFC3339)
						status := fields[2]
						if sameSecond {
							status = fields[3]
						}
						fields = []any{fields[0], fields[1], main, status}
					}
					_ = unstructured.SetNestedSlice(bad.Object, fields, "metadata", "managedFields")
					if ledger.validateWarmDestroyConfirmationResult(bad, observed) != ErrFixtures {
						t.Fatal("foreign confirmation accepted", change)
					}
				}
				for index := range result.GetManagedFields() {
					for _, change := range []string{"manager", "operation", "apiVersion", "fieldsType", "time", "fieldsV1", "unknown", "null-subresource"} {
						bad := result.DeepCopy()
						fields, _, _ := unstructured.NestedSlice(bad.Object, "metadata", "managedFields")
						field := fields[index].(map[string]any)
						if change == "null-subresource" {
							field["subresource"] = nil
						} else {
							field[change] = "PRIVATE-CANARY"
						}
						_ = unstructured.SetNestedSlice(bad.Object, fields, "metadata", "managedFields")
						if ledger.validateWarmDestroyConfirmationResult(bad, observed) != ErrFixtures {
							t.Fatal("unknown/raw role attribute accepted", index, change)
						}
					}
				}
			}
			if !bytes.Equal(before, ledger.body) || identity != ledger.identity || revision != ledger.document.Revision || ledger.seedAck || ledger.seedEffect {
				t.Fatal("pure confirmation changed receipt or capabilities")
			}
			if ledger.validateWarmDestroyConfirmationResult(nil, observed) != ErrFixtures || (*fixtureLedger)(nil).validateWarmDestroyConfirmationResult(unknown, observed) != ErrFixtures {
				t.Fatal("nil confirmation accepted")
			}
			ledger.document.DestroySeed.Mode = fixtureDestroySeedCold // Pure refusal instrumentation.
			if ledger.validateWarmDestroyConfirmationResult(unknown, observed) != ErrFixtures {
				t.Fatal("cold receipt acquired warm confirmation acceptance")
			}
		})
	}
}
