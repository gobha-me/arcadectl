// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"reflect"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installrender"
	platformkube "github.com/gobha-me/arcadectl/internal/platform/kube"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Pure source/native-persistent-shape-derived candidates. They are deliberately
// NOT native dry-run certification or reliable persistent marker ACKs.
func TestFixtureMarkerDryRunWholeDeclaredDeltaAndPurity(t *testing.T) {
	created := time.Date(2026, 10, 7, 15, 0, 0, 0, time.UTC)
	for _, profile := range []string{installrender.Profile135, installrender.Profile137} {
		for _, recipe := range []string{fixtureRecipeV1, fixtureRecipeV2} {
			for _, add := range []bool{true, false} {
				name := "remove"
				if add {
					name = "add"
				}
				t.Run(profile+"/"+recipe+"/"+name, func(t *testing.T) {
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
					before := fixtureResultExample(t, ledger, fixtureRetainedPVC, fixtureStableResult, created)
					after := fixtureMarkedRetainedExample(t, ledger, created)
					validate := ledger.validateRetainedMarkerDryRunAdd
					if add {
						after.SetResourceVersion(before.GetResourceVersion())
					} else {
						if ledger.advance(fixtureMarkerIntent(t, ledger)) != nil {
							t.Fatal("abstract marker intent unavailable")
						}
						unknown := fixtureMarkedRetainedExample(t, ledger, created)
						body := bytes.Clone(ledger.body)
						if ledger.validateRetainedMarkerDryRunRemove(unknown, before, phase, created.Add(time.Minute)) != ErrFixtures || !bytes.Equal(body, ledger.body) || !ledger.markerAck || !ledger.markerEffect {
							t.Fatal("unknown marker acquired return/ACK authority")
						}
						ledger.markerEffect = false // Abstract instrumentation, NEVER a native send/ACK.
						if ledger.advance(fixtureMarkerAcknowledgement(t, ledger)) != nil {
							t.Fatal("abstract acknowledged marker unavailable")
						}
						before = fixtureMarkedRetainedExample(t, ledger, created)
						after = fixtureResultExample(t, ledger, fixtureRetainedPVC, fixtureStableResult, created)
						after.SetResourceVersion(before.GetResourceVersion())
						fields := after.Object["metadata"].(map[string]any)["managedFields"].([]any)
						fields[0].(map[string]any)["time"] = created.Add(30 * time.Second).Format(time.RFC3339)
						after.Object["metadata"].(map[string]any)["managedFields"] = []any{fields[1], fields[0]}
						validate = ledger.validateRetainedMarkerDryRunRemove
					}
					body, identity, revision := bytes.Clone(ledger.body), ledger.identity, ledger.document.Revision
					savedBefore, savedAfter := before.DeepCopy(), after.DeepCopy()
					if validate(before, after, phase, created.Add(time.Minute)) != nil {
						t.Fatal("fixed marker dry-run declared delta refused")
					}
					// Select roles by identity, not their incidental golden position.
					role := func(o *unstructured.Unstructured, status bool) map[string]any {
						t.Helper()
						for _, raw := range o.Object["metadata"].(map[string]any)["managedFields"].([]any) {
							field := raw.(map[string]any)
							if (field["subresource"] == "status") == status {
								return field
							}
						}
						t.Fatal("fixed managed-field role missing")
						return nil
					}
					oldMainTime, err := time.Parse(time.RFC3339, role(before, false)["time"].(string))
					if err != nil {
						t.Fatal("fixed main timestamp unavailable")
					}
					for label, mutate := range map[string]func(*unstructured.Unstructured){
						"main-regression": func(o *unstructured.Unstructured) {
							role(o, false)["time"] = oldMainTime.Add(-time.Second).Format(time.RFC3339)
							main, status := role(o, false), role(o, true)
							// Keep native order legal to isolate monotonicity refusal.
							fields := []any{main, status}
							if !add {
								fields = []any{status, main}
							}
							o.Object["metadata"].(map[string]any)["managedFields"] = fields
						},
						"main-future": func(o *unstructured.Unstructured) {
							role(o, false)["time"] = created.Add(62 * time.Second).Format(time.RFC3339)
						},
						"main-missing-leaf": func(o *unstructured.Unstructured) {
							delete(role(o, false)["fieldsV1"].(map[string]any), "f:spec")
						},
						"main-extra-leaf": func(o *unstructured.Unstructured) {
							role(o, false)["fieldsV1"].(map[string]any)["f:private"] = map[string]any{}
						},
						"status-missing-leaf": func(o *unstructured.Unstructured) {
							delete(role(o, true)["fieldsV1"].(map[string]any)["f:status"].(map[string]any), "f:phase")
						},
						"status-extra-leaf": func(o *unstructured.Unstructured) {
							role(o, true)["fieldsV1"].(map[string]any)["f:status"].(map[string]any)["f:private"] = map[string]any{}
						},
						"duplicate-main": func(o *unstructured.Unstructured) {
							main := role(o, false)
							o.Object["metadata"].(map[string]any)["managedFields"] = []any{main, main}
						},
						"duplicate-status": func(o *unstructured.Unstructured) {
							status := role(o, true)
							o.Object["metadata"].(map[string]any)["managedFields"] = []any{status, status}
						},
						"wrong-native-order": func(o *unstructured.Unstructured) {
							fields := o.Object["metadata"].(map[string]any)["managedFields"].([]any)
							o.Object["metadata"].(map[string]any)["managedFields"] = []any{fields[1], fields[0]}
						},
					} {
						t.Run(label, func(t *testing.T) {
							changed := after.DeepCopy()
							mutate(changed)
							if validate(before, changed, phase, created.Add(time.Minute)) != ErrFixtures {
								t.Fatal("invalid closed dry-run bookkeeping accepted")
							}
						})
					}
					// The exact original main timestamp can remain unchanged. A tie
					// with status uses the complete native tuple (main sorts first).
					for _, stamp := range []time.Time{oldMainTime, created.Add(10 * time.Second), created.Add(61 * time.Second)} {
						if stamp.Before(oldMainTime) {
							continue
						}
						changed := after.DeepCopy()
						main, status := role(changed, false), role(changed, true)
						main["time"] = stamp.Format(time.RFC3339)
						fields := []any{main, status}
						if stamp.After(created.Add(10 * time.Second)) {
							fields = []any{status, main}
						}
						changed.Object["metadata"].(map[string]any)["managedFields"] = fields
						if validate(before, changed, phase, created.Add(time.Minute)) != nil {
							t.Fatal("legal same/tied/bounded main timestamp refused")
						}
					}
					tiedBefore, tiedAfter := before.DeepCopy(), after.DeepCopy()
					for _, o := range []*unstructured.Unstructured{tiedBefore, tiedAfter} {
						main, status := role(o, false), role(o, true)
						main["time"], status["time"] = oldMainTime.Format(time.RFC3339), oldMainTime.Format(time.RFC3339)
						o.Object["metadata"].(map[string]any)["managedFields"] = []any{main, status}
					}
					if validate(tiedBefore, tiedAfter, phase, created.Add(time.Minute)) != nil {
						t.Fatal("legal tied original/return native order refused")
					}
					wrongTie := tiedAfter.DeepCopy()
					fields := wrongTie.Object["metadata"].(map[string]any)["managedFields"].([]any)
					wrongTie.Object["metadata"].(map[string]any)["managedFields"] = []any{fields[1], fields[0]}
					if validate(tiedBefore, wrongTie, phase, created.Add(time.Minute)) != ErrFixtures {
						t.Fatal("invalid tied native order accepted")
					}
					if add {
						if ledger.validateRetainedMarkerResult(after, created.Add(time.Minute)) != ErrFixtures || ledger.validateRetainedMarkerDryRunRemove(before, after, phase, created.Add(time.Minute)) != ErrFixtures {
							t.Fatal("dry-run addition became a persistent ACK or removal case")
						}
					} else if ledger.validateRetainedMarkerDryRunAdd(before, after, phase, created.Add(time.Minute)) != ErrFixtures {
						t.Fatal("marked original became an unmarked addition case")
					}
					for _, mutate := range []func(*unstructured.Unstructured){
						func(o *unstructured.Unstructured) { o.SetUID("b0000000-0000-4000-8000-000000000008") },
						func(o *unstructured.Unstructured) { o.SetResourceVersion("999") },
						func(o *unstructured.Unstructured) { o.SetGeneration(1) },
						func(o *unstructured.Unstructured) { o.SetCreationTimestamp(metav1.NewTime(created.Add(-time.Second))) },
						func(o *unstructured.Unstructured) { o.SetLabels(map[string]string{"private": "PRIVATE-CANARY"}) },
						func(o *unstructured.Unstructured) { o.SetAnnotations(map[string]string{"private": "PRIVATE-CANARY"}) },
						func(o *unstructured.Unstructured) { o.SetFinalizers(nil) },
						func(o *unstructured.Unstructured) {
							o.SetDeletionTimestamp(&metav1.Time{Time: created.Add(time.Second)})
						},
						func(o *unstructured.Unstructured) { o.Object["extra"] = "PRIVATE-CANARY" },
						func(o *unstructured.Unstructured) { o.Object["status"] = nil },
						func(o *unstructured.Unstructured) { o.Object["metadata"].(map[string]any)["ownerReferences"] = nil },
						func(o *unstructured.Unstructured) {
							o.Object["metadata"].(map[string]any)["managedFields"].([]any)[0].(map[string]any)["manager"] = "PRIVATE-CANARY"
						},
					} {
						changed := after.DeepCopy()
						mutate(changed)
						if validate(before, changed, phase, created.Add(time.Minute)) != ErrFixtures {
							t.Fatal("marker dry-run admitted an undeclared whole-object delta")
						}
					}
					for _, field := range []string{"spec", "metadata", "status"} {
						corrupt := before.DeepCopy()
						corrupt.Object[field] = nil
						if validate(corrupt, after, phase, created.Add(time.Minute)) != ErrFixtures {
							t.Fatal("invalid original acquired dry-run validation")
						}
						corrupt = after.DeepCopy()
						corrupt.Object[field] = nil
						if validate(before, corrupt, phase, created.Add(time.Minute)) != ErrFixtures {
							t.Fatal("invalid return acquired dry-run validation")
						}
					}
					if validate(nil, after, phase, created.Add(time.Minute)) != ErrFixtures || validate(before, nil, phase, created.Add(time.Minute)) != ErrFixtures || validate(before, after, nil, created.Add(time.Minute)) != ErrFixtures || validate(before, after, phase, time.Time{}) != ErrFixtures {
						t.Fatal("missing dry-run witnesses accepted")
					}
					// Exact status-role preservation; a native main UPDATE does not
					// count as authority to rewrite the controller's role/time.
					changed := after.DeepCopy()
					role(changed, true)["time"] = created.Add(11 * time.Second).Format(time.RFC3339)
					if validate(before, changed, phase, created.Add(time.Minute)) != ErrFixtures {
						t.Fatal("status-role timestamp rewrite accepted")
					}
					foreignMarker := after.DeepCopy()
					annotations := foreignMarker.GetAnnotations()
					annotations[platformkube.AnnotationColdBackupUID] = "PRIVATE-CANARY"
					foreignMarker.SetAnnotations(annotations)
					if validate(before, foreignMarker, phase, created.Add(time.Minute)) != ErrFixtures {
						t.Fatal("caller-selected marker acquired acceptance")
					}
					if !reflect.DeepEqual(savedBefore, before) || !reflect.DeepEqual(savedAfter, after) || !bytes.Equal(body, ledger.body) || identity != ledger.identity || revision != ledger.document.Revision || ledger.ackSlot != -1 || ledger.effectSlot != -1 || ledger.markerAck || ledger.markerEffect || ledger.behaviorCompletion != nil {
						t.Fatal("pure marker dry-run mutated inputs/evidence or granted effects")
					}
				})
			}
		}
	}
}
