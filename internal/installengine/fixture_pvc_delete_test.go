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

// Source-derived pure reply candidates, never native admission certification.
func TestFixturePVCDeleteWholeCandidateDeltaAndRefusals(t *testing.T) {
	created := time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)
	started, observed := created.Add(30*time.Second+500*time.Millisecond), created.Add(time.Minute)
	for _, profile := range []string{installrender.Profile135, installrender.Profile137} {
		for _, recipe := range []string{fixtureRecipeV1, fixtureRecipeV2} {
			for _, marked := range []bool{false, true} {
				name := "unmarked"
				if marked {
					name = "marked"
				}
				t.Run(profile+"/"+recipe+"/"+name, func(t *testing.T) {
					h := newFixtureWithPlans(t, false, fixturePlanProfile(t, "isolated-install", profile))
					f, err := h.engine.prepareFixtureLedger(t.Context(), h.snapshot)
					if err != nil {
						t.Fatal("original ledger unavailable")
					}
					defer f.close()
					if recipe == fixtureRecipeV2 {
						instrumentFreshFixtureRecipeV2(t, f)
					}
					acknowledgeAllRecipeFixtures(t, f)
					if marked {
						if f.advance(fixtureMarkerIntent(t, f)) != nil {
							t.Fatal("abstract marker intent unavailable")
						}
						f.markerEffect = false // abstract instrumentation, no native send/ACK
						if f.advance(fixtureMarkerAcknowledgement(t, f)) != nil {
							t.Fatal("abstract marker receipt unavailable")
						}
					}
					phase := &fixturePhaseBaseline{}
					for _, slot := range []int{fixtureRetainedPVC, fixturePlainPVC} {
						before := fixtureResultExample(t, f, slot, fixtureStableResult, created)
						if marked && slot == fixtureRetainedPVC {
							before = fixtureMarkedRetainedExample(t, f, created)
						}
						after := before.DeepCopy()
						metadata := after.Object["metadata"].(map[string]any)
						metadata["deletionTimestamp"], metadata["deletionGracePeriodSeconds"] = created.Add(31*time.Second).Format(time.RFC3339), int64(0)
						savedBefore, savedAfter := before.DeepCopy(), after.DeepCopy()
						body, identity, revision := bytes.Clone(f.body), f.identity, f.document.Revision
						if f.validateFixturePVCDeleteReply(slot, before, after, phase, started, observed) != nil {
							t.Fatal("fixed PVC delete candidate refused")
						}
						for label, mutate := range map[string]func(*unstructured.Unstructured){
							"wrong-uid":  func(o *unstructured.Unstructured) { o.SetUID("b0000000-0000-4000-8000-000000000099") },
							"wrong-rv":   func(o *unstructured.Unstructured) { o.SetResourceVersion("999") },
							"missing-rv": func(o *unstructured.Unstructured) { o.SetResourceVersion("") },
							"generic-status": func(o *unstructured.Unstructured) {
								o.Object = map[string]any{"apiVersion": "v1", "kind": "Status", "status": "Success", "code": int64(200)}
							},
							"wrong-name":        func(o *unstructured.Unstructured) { o.SetName("foreign") },
							"wrong-namespace":   func(o *unstructured.Unstructured) { o.SetNamespace("foreign") },
							"changed-finalizer": func(o *unstructured.Unstructured) { o.SetFinalizers([]string{"foreign"}) },
							"missing-finalizer": func(o *unstructured.Unstructured) { unstructured.RemoveNestedField(o.Object, "metadata", "finalizers") },
							"extra-annotation": func(o *unstructured.Unstructured) {
								a := o.GetAnnotations()
								a["private"] = "PRIVATE-CANARY"
								o.SetAnnotations(a)
							},
							"missing-annotations": func(o *unstructured.Unstructured) {
								unstructured.RemoveNestedField(o.Object, "metadata", "annotations")
							},
							"foreign-labels":   func(o *unstructured.Unstructured) { o.SetLabels(map[string]string{"private": "PRIVATE-CANARY"}) },
							"extra-generation": func(o *unstructured.Unstructured) { o.SetGeneration(1) },
							"extra-owner":      func(o *unstructured.Unstructured) { o.Object["metadata"].(map[string]any)["ownerReferences"] = []any{} },
							"extra-spec":       func(o *unstructured.Unstructured) { o.Object["spec"].(map[string]any)["private"] = "PRIVATE-CANARY" },
							"changed-status":   func(o *unstructured.Unstructured) { o.Object["status"].(map[string]any)["phase"] = "Pending" },
							"null-status":      func(o *unstructured.Unstructured) { o.Object["status"] = nil },
							"extra-top-level":  func(o *unstructured.Unstructured) { o.Object["private"] = "PRIVATE-CANARY" },
							"missing-managed-fields": func(o *unstructured.Unstructured) {
								unstructured.RemoveNestedField(o.Object, "metadata", "managedFields")
							},
							"changed-managed-time": func(o *unstructured.Unstructured) {
								o.Object["metadata"].(map[string]any)["managedFields"].([]any)[0].(map[string]any)["time"] = created.Add(32 * time.Second).Format(time.RFC3339)
							},
							"missing-timestamp": func(o *unstructured.Unstructured) {
								unstructured.RemoveNestedField(o.Object, "metadata", "deletionTimestamp")
							},
							"null-timestamp": func(o *unstructured.Unstructured) { o.Object["metadata"].(map[string]any)["deletionTimestamp"] = nil },
							"invalid-timestamp": func(o *unstructured.Unstructured) {
								o.Object["metadata"].(map[string]any)["deletionTimestamp"] = "PRIVATE-CANARY"
							},
							"pre-request-timestamp": func(o *unstructured.Unstructured) {
								o.Object["metadata"].(map[string]any)["deletionTimestamp"] = created.Add(29 * time.Second).Format(time.RFC3339)
							},
							"future-timestamp": func(o *unstructured.Unstructured) {
								o.Object["metadata"].(map[string]any)["deletionTimestamp"] = created.Add(62 * time.Second).Format(time.RFC3339)
							},
							"missing-grace": func(o *unstructured.Unstructured) {
								unstructured.RemoveNestedField(o.Object, "metadata", "deletionGracePeriodSeconds")
							},
							"null-grace": func(o *unstructured.Unstructured) {
								o.Object["metadata"].(map[string]any)["deletionGracePeriodSeconds"] = nil
							},
							"nonzero-grace": func(o *unstructured.Unstructured) {
								o.Object["metadata"].(map[string]any)["deletionGracePeriodSeconds"] = int64(1)
							},
							"float-grace": func(o *unstructured.Unstructured) {
								o.Object["metadata"].(map[string]any)["deletionGracePeriodSeconds"] = float64(0)
							},
						} {
							t.Run(label, func(t *testing.T) {
								changed := after.DeepCopy()
								mutate(changed)
								saved := changed.DeepCopy()
								if f.validateFixturePVCDeleteReply(slot, before, changed, phase, started, observed) != ErrFixtures || !reflect.DeepEqual(saved.Object, changed.Object) {
									t.Fatal("PVC delete refusal accepted or mutated input")
								}
							})
						}
						for _, stamp := range []time.Time{started.Truncate(time.Second), observed.Add(time.Second)} {
							boundary := after.DeepCopy()
							boundary.Object["metadata"].(map[string]any)["deletionTimestamp"] = stamp.Format(time.RFC3339)
							if f.validateFixturePVCDeleteReply(slot, before, boundary, phase, started, observed) != nil {
								t.Fatal("legal native timestamp boundary refused")
							}
						}
						// Isolate the pure creation-floor branch; this synthetic time
						// arrangement is not an actual lifecycle/provenance proof.
						earlyStart := created.Add(-2 * time.Second)
						creationBound := after.DeepCopy()
						creationBound.Object["metadata"].(map[string]any)["deletionTimestamp"] = created.Add(-time.Second).Format(time.RFC3339)
						if f.validateFixturePVCDeleteReply(slot, before, creationBound, phase, earlyStart, observed) != ErrFixtures {
							t.Fatal("request bound hid pre-creation deletion time")
						}
						creationBound.Object["metadata"].(map[string]any)["deletionTimestamp"] = created.Format(time.RFC3339)
						if f.validateFixturePVCDeleteReply(slot, before, creationBound, phase, earlyStart, observed) != nil {
							t.Fatal("exact creation timestamp floor refused")
						}
						malformed := before.DeepCopy()
						malformed.SetFinalizers([]string{"foreign"})
						var missing *fixtureLedger
						if missing.validateFixturePVCDeleteReply(slot, before, after, phase, started, observed) != ErrFixtures || f.validateFixturePVCDeleteReply(fixturePlainPod, before, after, phase, started, observed) != ErrFixtures || f.validateFixturePVCDeleteReply(slot, malformed, after, phase, started, observed) != ErrFixtures || f.validateFixturePVCDeleteReply(slot, before, after, nil, started, observed) != ErrFixtures || f.validateFixturePVCDeleteReply(slot, before, after, phase, time.Time{}, observed) != ErrFixtures || f.validateFixturePVCDeleteReply(slot, before, after, phase, observed.Add(time.Second), observed) != ErrFixtures {
							t.Fatal("unbound PVC original/slot/phase/request became a delete reply")
						}
						if f.validatePhaseFixture(slot, after, phase, observed) != ErrFixtures {
							t.Fatal("dry-run deletion reply became persistent original/absence")
						}
						if !reflect.DeepEqual(savedBefore.Object, before.Object) || !reflect.DeepEqual(savedAfter.Object, after.Object) || !bytes.Equal(body, f.body) || identity != f.identity || revision != f.document.Revision || f.ackSlot != -1 || f.effectSlot != -1 || f.seedAck || f.seedEffect || f.markerAck || f.markerEffect || f.worldPublication || f.behaviorCompletion != nil || h.access.writes != 0 {
							t.Fatal("pure delete check mutated input/WAL/capability or cluster")
						}
					}
				})
			}
		}
	}
}
