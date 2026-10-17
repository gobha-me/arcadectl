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
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Pure contract examples/refusals, NOT native no-op return certification.
func TestFixtureFixedNoopWholeOriginalAndClosedCases(t *testing.T) {
	created := time.Date(2026, 10, 6, 10, 0, 0, 0, time.UTC)
	for _, profile := range []string{installrender.Profile135, installrender.Profile137} {
		for _, recipe := range []string{fixtureRecipeV1, fixtureRecipeV2} {
			t.Run(profile+"/"+recipe, func(t *testing.T) {
				f := newFixtureWithPlans(t, false, fixturePlanProfile(t, "isolated-install", profile))
				ledger, err := f.engine.prepareFixtureLedger(t.Context(), f.snapshot)
				if err != nil {
					t.Fatal("original ledger unavailable")
				}
				defer ledger.close()
				if recipe == fixtureRecipeV2 {
					instrumentFreshFixtureRecipeV2(t, ledger)
				}
				acknowledgeAllRecipeFixtures(t, ledger)
				phase := &fixturePhaseBaseline{}
				body, identity, revision := bytes.Clone(ledger.body), ledger.identity, ledger.document.Revision
				for slot := range ledger.document.Entries {
					original := fixtureResultExample(t, ledger, slot, fixtureStableResult, created)
					saved := original.DeepCopy()
					allowed := slot == fixtureBackupPod || slot == fixtureRestorePod || slot == fixtureDestroyPod || slot == fixtureRetainedPVC || slot == fixtureCancelledDestroy || slot == fixtureVerifiedCancelledDestroy
					want := ErrFixtures
					if allowed {
						want = nil
					}
					if ledger.validateFixtureUnchangedUpdate(slot, original, original.DeepCopy(), phase, created.Add(time.Minute)) != want {
						t.Fatal("fixed no-op case membership or original shape changed")
					}
					if slot == fixturePlainPod {
						for _, operation := range []admissionProbeOperation{probeEphemeralOperation, probeResizeOperation} {
							if ledger.validatePlainPodUnchangedSubresource(operation, original, original.DeepCopy(), phase, created.Add(time.Minute)) != nil {
								t.Fatal("exact plain subresource no-op refused")
							}
						}
						for _, operation := range []admissionProbeOperation{0, probeCreateOperation, probeUpdateOperation, probeDeletePVCOperation} {
							if ledger.validatePlainPodUnchangedSubresource(operation, original, original, phase, created.Add(time.Minute)) != ErrFixtures {
								t.Fatal("foreign operation counted as a plain subresource")
							}
						}
					}
					if allowed || slot == fixturePlainPod {
						validate := func(before, after *unstructured.Unstructured, phase *fixturePhaseBaseline, at time.Time) error {
							if slot == fixturePlainPod {
								return ledger.validatePlainPodUnchangedSubresource(probeResizeOperation, before, after, phase, at)
							}
							return ledger.validateFixtureUnchangedUpdate(slot, before, after, phase, at)
						}
						for _, mutate := range []func(*unstructured.Unstructured){
							func(o *unstructured.Unstructured) { o.SetUID("b0000000-0000-4000-8000-00000000000b") },
							func(o *unstructured.Unstructured) { o.SetResourceVersion("102") },
							func(o *unstructured.Unstructured) { o.SetGeneration(2) },
							func(o *unstructured.Unstructured) { o.SetAnnotations(map[string]string{"private": "PRIVATE-CANARY"}) },
							func(o *unstructured.Unstructured) { o.Object["extra"] = "PRIVATE-CANARY" },
							func(o *unstructured.Unstructured) { o.Object["metadata"].(map[string]any)["deletionTimestamp"] = nil },
							func(o *unstructured.Unstructured) {
								o.Object["metadata"].(map[string]any)["managedFields"].([]any)[0].(map[string]any)["time"] = created.Add(30 * time.Second).Format(time.RFC3339)
							},
							func(o *unstructured.Unstructured) { o.Object["status"] = nil },
						} {
							changed := original.DeepCopy()
							mutate(changed)
							if validate(original, changed, phase, created.Add(time.Minute)) != ErrFixtures {
								t.Fatal("whole no-op admitted a raw delta")
							}
						}
						corrupt := original.DeepCopy()
						corrupt.Object["spec"] = nil
						if validate(corrupt, corrupt.DeepCopy(), phase, created.Add(time.Minute)) != ErrFixtures || validate(nil, original, phase, created.Add(time.Minute)) != ErrFixtures || validate(original, nil, phase, created.Add(time.Minute)) != ErrFixtures || validate(original, original, nil, created.Add(time.Minute)) != ErrFixtures || validate(original, original, phase, time.Time{}) != ErrFixtures {
							t.Fatal("equality bypassed original validation or missing inputs")
						}
						foreign := original.DeepCopy()
						foreign.SetUID("b0000000-0000-4000-8000-00000000000b")
						if validate(foreign, foreign.DeepCopy(), phase, created.Add(time.Minute)) != ErrFixtures {
							t.Fatal("equal foreign UID acquired original status")
						}
						if !reflect.DeepEqual(original, saved) {
							t.Fatal("pure no-op check mutated caller original")
						}
					}
				}
				if !bytes.Equal(body, ledger.body) || identity != ledger.identity || revision != ledger.document.Revision || ledger.behaviorCompletion != nil || ledger.seedAck || ledger.seedEffect || ledger.markerAck || ledger.markerEffect {
					t.Fatal("pure no-op validation changed durable evidence or granted effects")
				}
			})
		}
	}
}

func TestFixtureFixedNoopSeededWarmAndMarkedWholeOriginals(t *testing.T) {
	created := time.Date(2026, 10, 6, 10, 0, 0, 0, time.UTC)
	for _, profile := range []string{installrender.Profile135, installrender.Profile137} {
		for _, variant := range []string{"cold-seeded", "warm-seeded", "warm-cancelled-unsafe", "warm-cancelled-verified", "retained-marker"} {
			t.Run(profile+"/"+variant, func(t *testing.T) {
				f := newFixtureWithPlans(t, false, fixturePlanProfile(t, "isolated-install", profile))
				ledger, err := f.engine.prepareFixtureLedger(t.Context(), f.snapshot)
				if err != nil {
					t.Fatal("original ledger unavailable")
				}
				defer ledger.close()
				instrumentFreshFixtureRecipeV2(t, ledger)
				acknowledgeAllRecipeFixtures(t, ledger)
				phase := &fixturePhaseBaseline{}
				warm := variant == "warm-seeded" || variant == "warm-cancelled-unsafe" || variant == "warm-cancelled-verified"
				if warm {
					phase.Leaders = []fixturePhaseLeader{{Row: fixtureWorldRow{Key: installstate.Key{Name: "destroy-controller.arcade.gobha.me"}}}}
				}
				slot := fixtureCancelledDestroy
				var original *unstructured.Unstructured
				switch variant {
				case "cold-seeded", "warm-seeded":
					intent := fixtureSeedIntent(t, ledger)
					if warm {
						intent.DestroySeed.Mode = fixtureDestroySeedWarmCancelled
					}
					if ledger.advance(intent) != nil {
						t.Fatal("abstract seed intent unavailable")
					}
					ledger.seedEffect = false // Abstract instrumentation, NEVER a native send or wire ACK.
					if ledger.advance(fixtureSeedAcknowledgement(t, ledger)) != nil {
						t.Fatal("abstract acknowledged seed unavailable")
					}
					if warm {
						original = fixtureWarmSeededExample(t, ledger, created, [4]time.Duration{time.Second, time.Second, time.Second, 2 * time.Second})
					} else {
						original = fixtureDestroySeedExample(t, ledger, created)
						original.SetResourceVersion("102")
					}
				case "warm-cancelled-unsafe", "warm-cancelled-verified":
					if variant == "warm-cancelled-verified" {
						slot = fixtureVerifiedCancelledDestroy
					}
					original = fixtureWarmCancelledSlotExample(t, ledger, slot, created, [3]time.Duration{time.Second, 2 * time.Second, 3 * time.Second})
				case "retained-marker":
					slot = fixtureRetainedPVC
					if ledger.advance(fixtureMarkerIntent(t, ledger)) != nil {
						t.Fatal("abstract marker intent unavailable")
					}
					ledger.markerEffect = false // Abstract instrumentation, NEVER a native send or wire ACK.
					if ledger.advance(fixtureMarkerAcknowledgement(t, ledger)) != nil {
						t.Fatal("abstract acknowledged marker unavailable")
					}
					original = fixtureMarkedRetainedExample(t, ledger, created)
				}
				body, identity, revision := bytes.Clone(ledger.body), ledger.identity, ledger.document.Revision
				saved := original.DeepCopy()
				if ledger.validateFixtureUnchangedUpdate(slot, original, original.DeepCopy(), phase, created.Add(time.Minute)) != nil {
					t.Fatal("receipt-pinned/warm whole no-op original refused")
				}
				for _, mutate := range []func(*unstructured.Unstructured){
					func(o *unstructured.Unstructured) { o.Object["status"] = nil },
					func(o *unstructured.Unstructured) {
						o.Object["metadata"].(map[string]any)["managedFields"].([]any)[0].(map[string]any)["time"] = created.Add(30 * time.Second).Format(time.RFC3339)
					},
					func(o *unstructured.Unstructured) { o.SetResourceVersion("103") },
					func(o *unstructured.Unstructured) { o.SetAnnotations(map[string]string{"private": "PRIVATE-CANARY"}) },
				} {
					changed := original.DeepCopy()
					mutate(changed)
					if ledger.validateFixtureUnchangedUpdate(slot, original, changed, phase, created.Add(time.Minute)) != ErrFixtures {
						t.Fatal("seeded/warm/marked no-op admitted a whole raw delta")
					}
				}
				if variant == "cold-seeded" || variant == "warm-seeded" || variant == "retained-marker" {
					stale := original.DeepCopy()
					stale.SetResourceVersion("101")
					if ledger.validateFixtureUnchangedUpdate(slot, stale, stale.DeepCopy(), phase, created.Add(time.Minute)) != ErrFixtures {
						t.Fatal("equal stale body bypassed reliable receipt pin")
					}
				}
				if slot != fixtureRetainedPVC {
					wrongPhase := &fixturePhaseBaseline{}
					if !warm {
						wrongPhase.Leaders = []fixturePhaseLeader{{Row: fixtureWorldRow{Key: installstate.Key{Name: "destroy-controller.arcade.gobha.me"}}}}
					}
					if ledger.validateFixtureUnchangedUpdate(slot, original, original.DeepCopy(), wrongPhase, created.Add(time.Minute)) != ErrFixtures {
						t.Fatal("wrong controller-chain mode acquired seeded/warm no-op acceptance")
					}
				}
				if !reflect.DeepEqual(saved, original) || !bytes.Equal(body, ledger.body) || identity != ledger.identity || revision != ledger.document.Revision || ledger.behaviorCompletion != nil || ledger.ackSlot != -1 || ledger.effectSlot != -1 || ledger.seedAck || ledger.seedEffect || ledger.markerAck || ledger.markerEffect {
					t.Fatal("seeded/warm/marked pure validation mutated evidence or granted effects")
				}
			})
		}
	}
}
