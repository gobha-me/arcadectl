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

// Pure dry-run shapes and test-only ACK instrumentation, not policy evidence.
func TestFixtureDestroyConfirmationExactDryOnlyDelta(t *testing.T) {
	created := time.Date(2026, time.October, 6, 10, 0, 0, 0, time.UTC)
	for _, profile := range []string{installrender.Profile135, installrender.Profile137} {
		t.Run(profile, func(t *testing.T) {
			f := newFixtureWithPlans(t, false, fixturePlanProfile(t, "isolated-install", profile))
			ledger, err := f.engine.prepareFixtureLedger(t.Context(), f.snapshot)
			if err != nil {
				t.Fatal(err)
			}
			defer ledger.close()
			acknowledgeAllRecipeFixtures(t, ledger)
			if ledger.advance(fixtureSeedIntent(t, ledger)) != nil {
				t.Fatal("seed intent unavailable")
			}
			ledger.seedEffect = false
			if ledger.advance(fixtureSeedAcknowledgement(t, ledger)) != nil {
				t.Fatal("test-only seed receipt unavailable")
			}
			seed := fixtureDestroySeedExample(t, ledger, created)
			seed.SetResourceVersion("102")
			result := seed.DeepCopy()
			_ = unstructured.SetNestedField(result.Object, ledger.document.RunID, "spec", "confirmationChallenge")
			result.SetGeneration(2)
			result.Object["metadata"].(map[string]any)["managedFields"].([]any)[0].(map[string]any)["fieldsV1"].(map[string]any)["f:spec"].(map[string]any)["f:confirmationChallenge"] = map[string]any{}
			fields := result.Object["metadata"].(map[string]any)["managedFields"].([]any)
			fields[0].(map[string]any)["time"] = created.Add(12 * time.Second).Format(time.RFC3339)
			fields[0], fields[1] = fields[1], fields[0] // older seeded status precedes updated main
			observed := created.Add(time.Minute)
			before, input := bytes.Clone(ledger.body), result.DeepCopy()
			if ledger.validateDestroyConfirmationResult(result, observed) != nil || !reflect.DeepEqual(result, input) || !bytes.Equal(before, ledger.body) || ledger.validateDestroySeedResult(result, observed) != ErrFixtures {
				t.Fatal("pure changed result refused, aliased input, changed WAL or relaxed unchanged validation")
			}
			sameSecond := result.DeepCopy()
			sameFields := sameSecond.Object["metadata"].(map[string]any)["managedFields"].([]any)
			sameFields[1].(map[string]any)["time"] = sameFields[0].(map[string]any)["time"]
			sameFields[0], sameFields[1] = sameFields[1], sameFields[0]
			if ledger.validateDestroyConfirmationResult(sameSecond, observed) != nil {
				t.Fatal("native same-second main-before-status result refused")
			}
			sameFields[0], sameFields[1] = sameFields[1], sameFields[0]
			if ledger.validateDestroyConfirmationResult(sameSecond, observed) != ErrFixtures || !bytes.Equal(before, ledger.body) {
				t.Fatal("same-second reversed ownership ordering accepted or WAL changed")
			}
			for label, change := range map[string]func(*unstructured.Unstructured){
				"missing-confirmation": func(o *unstructured.Unstructured) {
					unstructured.RemoveNestedField(o.Object, "spec", "confirmationChallenge")
				},
				"foreign-confirmation": func(o *unstructured.Unstructured) {
					_ = unstructured.SetNestedField(o.Object, "foreign-challenge", "spec", "confirmationChallenge")
				},
				"cancel-cleared": func(o *unstructured.Unstructured) {
					_ = unstructured.SetNestedField(o.Object, false, "spec", "cancelRequested")
				},
				"rv-old":         func(o *unstructured.Unstructured) { o.SetResourceVersion("101") },
				"rv-new":         func(o *unstructured.Unstructured) { o.SetResourceVersion("103") },
				"generation-old": func(o *unstructured.Unstructured) { o.SetGeneration(1) },
				"generation-new": func(o *unstructured.Unstructured) { o.SetGeneration(3) },
				"uid":            func(o *unstructured.Unstructured) { o.SetUID("c0000000-0000-4000-8000-000000000001") },
				"status":         func(o *unstructured.Unstructured) { o.Object["status"].(map[string]any)["phase"] = "Deleting" },
				"audit":          func(o *unstructured.Unstructured) { o.SetAnnotations(nil) },
				"metadata-extra": func(o *unstructured.Unstructured) {
					o.Object["metadata"].(map[string]any)["private"] = "PRIVATE-CANARY"
				},
				"fieldset-missing": func(o *unstructured.Unstructured) {
					delete(o.Object["metadata"].(map[string]any)["managedFields"].([]any)[1].(map[string]any)["fieldsV1"].(map[string]any)["f:spec"].(map[string]any), "f:confirmationChallenge")
				},
				"fieldset-extra": func(o *unstructured.Unstructured) {
					o.Object["metadata"].(map[string]any)["managedFields"].([]any)[1].(map[string]any)["fieldsV1"].(map[string]any)["f:spec"].(map[string]any)["f:private"] = map[string]any{}
				},
				"manager": func(o *unstructured.Unstructured) {
					o.Object["metadata"].(map[string]any)["managedFields"].([]any)[0].(map[string]any)["manager"] = "foreign"
				},
				"time": func(o *unstructured.Unstructured) {
					o.Object["metadata"].(map[string]any)["managedFields"].([]any)[0].(map[string]any)["time"] = "2026-10-06T10:01:02Z"
				},
				"order": func(o *unstructured.Unstructured) {
					fields := o.Object["metadata"].(map[string]any)["managedFields"].([]any)
					fields[0], fields[1] = fields[1], fields[0]
				},
				"update-before-seed": func(o *unstructured.Unstructured) {
					o.Object["metadata"].(map[string]any)["managedFields"].([]any)[1].(map[string]any)["time"] = created.Add(9 * time.Second).Format(time.RFC3339)
				},
				"duplicate-main": func(o *unstructured.Unstructured) {
					fields := o.Object["metadata"].(map[string]any)["managedFields"].([]any)
					fields[0] = fields[1]
				},
				"duplicate-status": func(o *unstructured.Unstructured) {
					fields := o.Object["metadata"].(map[string]any)["managedFields"].([]any)
					fields[1] = fields[0]
				},
				"main-explicit-empty-subresource": func(o *unstructured.Unstructured) {
					o.Object["metadata"].(map[string]any)["managedFields"].([]any)[1].(map[string]any)["subresource"] = ""
				},
			} {
				t.Run(label, func(t *testing.T) {
					o := result.DeepCopy()
					change(o)
					if ledger.validateDestroyConfirmationResult(o, observed) != ErrFixtures || !bytes.Equal(before, ledger.body) {
						t.Fatal("foreign changed shape accepted or WAL changed")
					}
				})
			}
			if ledger.validateDestroyConfirmationResult(seed, observed) != ErrFixtures || ledger.validateDestroyConfirmationResult(nil, observed) != ErrFixtures || (*fixtureLedger)(nil).validateDestroyConfirmationResult(result, observed) != ErrFixtures {
				t.Fatal("nonconfirmation/nil accepted")
			}
			ledger.document.DestroySeed.State = fixtureDestroySeedAttempted
			if ledger.validateDestroyConfirmationResult(result, observed) != ErrFixtures {
				t.Fatal("unknown seed granted confirmation shape acceptance")
			}
		})
	}
}
