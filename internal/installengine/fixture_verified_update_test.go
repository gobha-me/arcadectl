// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"reflect"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Pure candidate/refusal tests, not native UPDATE or actor/phase certification.
func TestFixtureVerifiedUnchangedUpdateWholeOriginalNoDelta(t *testing.T) {
	created := time.Date(2026, 10, 6, 10, 0, 0, 0, time.UTC)
	for _, profile := range []string{installrender.Profile135, installrender.Profile137} {
		t.Run(profile, func(t *testing.T) {
			f := newFixtureWithPlans(t, false, fixturePlanProfile(t, "isolated-install", profile))
			ledger, err := f.engine.prepareFixtureLedger(t.Context(), f.snapshot)
			if err != nil {
				t.Fatal(err)
			}
			defer ledger.close()
			instrumentFreshFixtureRecipeV2(t, ledger)
			acknowledgeAllRecipeFixtures(t, ledger)
			for _, warm := range []bool{false, true} {
				phase := &fixturePhaseBaseline{}
				original := fixtureResultExample(t, ledger, fixtureVerifiedCancelledDestroy, fixtureStableResult, created)
				if warm {
					phase.Leaders = []fixturePhaseLeader{{Row: fixtureWorldRow{Key: installstate.Key{Name: "destroy-controller.arcade.gobha.me"}}}}
					original = fixtureWarmCancelledSlotExample(t, ledger, fixtureVerifiedCancelledDestroy, created, [3]time.Duration{time.Second, 2 * time.Second, 3 * time.Second})
				}
				body, identity := bytes.Clone(ledger.body), ledger.identity
				saved := original.DeepCopy()
				if ledger.validateVerifiedCancelledUnchangedUpdate(original, original.DeepCopy(), phase, created.Add(time.Minute)) != nil {
					t.Fatal("exact no-op return refused")
				}
				mutations := map[string]func(*unstructured.Unstructured){
					"rv":            func(o *unstructured.Unstructured) { o.SetResourceVersion("102") },
					"uid":           func(o *unstructured.Unstructured) { o.SetUID("b0000000-0000-4000-8000-00000000000b") },
					"creation":      func(o *unstructured.Unstructured) { o.SetCreationTimestamp(metav1.NewTime(created.Add(-time.Second))) },
					"generation":    func(o *unstructured.Unstructured) { o.SetGeneration(2) },
					"unknown":       func(o *unstructured.Unstructured) { o.Object["extra"] = "PRIVATE-CANARY" },
					"metadata-null": func(o *unstructured.Unstructured) { o.Object["metadata"].(map[string]any)["deletionTimestamp"] = nil },
					"managed-time": func(o *unstructured.Unstructured) {
						o.Object["metadata"].(map[string]any)["managedFields"].([]any)[0].(map[string]any)["time"] = created.Add(4 * time.Second).Format(time.RFC3339)
					},
					"unsafe-audit": func(o *unstructured.Unstructured) {
						o.SetAnnotations(map[string]string{"arcade.gobha.me/unsafe-requested-by": "foreign"})
					},
					"backup": func(o *unstructured.Unstructured) {
						_ = unstructured.SetNestedField(o.Object, "foreign", "spec", "backupRef", "uid")
					},
					"confirmation": func(o *unstructured.Unstructured) {
						_ = unstructured.SetNestedField(o.Object, "foreign_confirmation_challenge", "spec", "confirmationChallenge")
					},
					"status-null": func(o *unstructured.Unstructured) { o.Object["status"] = nil },
				}
				if warm {
					mutations["managed-order"] = func(o *unstructured.Unstructured) {
						fields := o.Object["metadata"].(map[string]any)["managedFields"].([]any)
						fields[0], fields[1] = fields[1], fields[0]
					}
					mutations["cancel-time"] = func(o *unstructured.Unstructured) {
						status := o.Object["status"].(map[string]any)
						stamp := created.Add(4 * time.Second).Format(time.RFC3339)
						status["startedAt"], status["completedAt"] = stamp, stamp
						status["conditions"].([]any)[0].(map[string]any)["lastTransitionTime"] = stamp
					}
				}
				for name, mutate := range mutations {
					t.Run(name, func(t *testing.T) {
						changed := original.DeepCopy()
						mutate(changed)
						if ledger.validateVerifiedCancelledUnchangedUpdate(original, changed, phase, created.Add(time.Minute)) != ErrFixtures {
							t.Fatal("no-op admitted a raw delta")
						}
					})
				}
				for _, field := range []string{"status", "spec", "metadata"} {
					corrupt := original.DeepCopy()
					corrupt.Object[field] = nil
					if ledger.validateVerifiedCancelledUnchangedUpdate(corrupt, corrupt.DeepCopy(), phase, created.Add(time.Minute)) != ErrFixtures {
						t.Fatal("equality bypassed original whole-shape validation")
					}
				}
				if ledger.validateVerifiedCancelledUnchangedUpdate(nil, original, phase, created.Add(time.Minute)) != ErrFixtures || ledger.validateVerifiedCancelledUnchangedUpdate(original, nil, phase, created.Add(time.Minute)) != ErrFixtures || ledger.validateVerifiedCancelledUnchangedUpdate(original, original, nil, created.Add(time.Minute)) != ErrFixtures || ledger.validateVerifiedCancelledUnchangedUpdate(original, original, phase, time.Time{}) != ErrFixtures {
					t.Fatal("invalid no-op inputs admitted")
				}
				if !reflect.DeepEqual(saved, original) || !bytes.Equal(body, ledger.body) || identity != ledger.identity || ledger.behaviorCompletion != nil {
					t.Fatal("pure no-op validator mutated evidence or granted completion")
				}
			}
		})
	}
}

func TestFixtureRecipeV2BehaviorVersionRequiresAllOriginals(t *testing.T) {
	f := newFixture(t, false)
	ledger, err := f.engine.prepareFixtureLedger(t.Context(), f.snapshot)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.close()
	instrumentFreshFixtureRecipeV2(t, ledger)
	if ledger.sealOriginalWorlds([]fixtureWorldRow{}) != nil {
		t.Fatal("world seal unavailable")
	}
	fixtureBehaviorPrerequisites(t, ledger, fixtureDestroySeedCold)
	next := fixtureBehaviorIntent(t, ledger)
	if validFixtureBehaviorDocument(next) {
		t.Fatal("v1 completion version used for v2 recipe")
	}
	next.Behavior.Version = fixtureBehaviorVersionV2
	if !validFixtureBehaviorDocument(next) {
		t.Fatal("complete v2 receipt schema refused")
	}
	missing := next
	missing.Entries = append([]fixtureEntry{}, next.Entries...)
	missing.Entries[fixtureVerifiedCancelledDestroy].OriginalUID = ""
	if validFixtureBehaviorDocument(missing) {
		t.Fatal("receipt omitted eleventh original")
	}
	ledger.behaviorCompletion = instrumentFixtureBehaviorCompletion(ledger)
	if ledger.advance(next) != nil || ledger.behaviorCompletion != nil {
		t.Fatal("test-only v2 completion transition refused or restored capability")
	}
	for slot := len(ledger.document.Entries) - 1; slot >= 0; slot-- {
		next, _ = ledger.nextDocument()
		next.Entries[slot].State, next.Entries[slot].DeleteResourceVersion = fixtureDeleteAttempted, "101"
		if ledger.advance(next) != nil {
			t.Fatal("receipt changed during cleanup intent")
		}
		next, _ = ledger.nextDocument()
		next.Entries[slot].State = fixtureAbsent
		if ledger.advance(next) != nil {
			t.Fatal("receipt changed during absence")
		}
	}
	if !validFixtureBehaviorDocument(ledger.document) {
		t.Fatal("v2 cleanup chronology invalidated completion")
	}
}
