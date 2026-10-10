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

// Pure, independently framed candidates, NOT a native dry-run/actor proof.
func workerGateReplyExample(before *unstructured.Unstructured, family string, stamp time.Time) *unstructured.Unstructured {
	o := before.DeepCopy()
	unstructured.RemoveNestedField(o.Object, "spec", "schedulingGates")
	o.SetGeneration(2)
	key := "arcade.gobha.me/" + family + "-pod-authorized"
	o.SetAnnotations(map[string]string{key: string(before.GetUID())})
	main := o.Object["metadata"].(map[string]any)["managedFields"].([]any)[0].(map[string]any)
	main["time"] = stamp.Format(time.RFC3339)
	owned := main["fieldsV1"].(map[string]any)
	delete(owned["f:spec"].(map[string]any), "f:schedulingGates")
	owned["f:metadata"].(map[string]any)["f:annotations"] = map[string]any{".": map[string]any{}, "f:" + key: map[string]any{}}
	return o
}

func TestFixtureWorkerGateWholeCandidateDeltaAndRefusals(t *testing.T) {
	created := time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)
	observed := created.Add(time.Minute)
	for _, profile := range []string{installrender.Profile135, installrender.Profile137} {
		for _, recipe := range []string{fixtureRecipeV1, fixtureRecipeV2} {
			t.Run(profile+"/"+recipe, func(t *testing.T) {
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
				phase := &fixturePhaseBaseline{}
				for _, test := range []struct {
					slot   int
					family string
				}{
					{fixtureBackupPod, "backup"}, {fixtureRestorePod, "restore"}, {fixtureDestroyPod, "destroy"},
				} {
					t.Run(test.family, func(t *testing.T) {
						before := fixtureResultExample(t, f, test.slot, fixtureStableResult, created)
						after := workerGateReplyExample(before, test.family, created.Add(30*time.Second))
						savedBefore, savedAfter := before.DeepCopy(), after.DeepCopy()
						body, identity, revision := bytes.Clone(f.body), f.identity, f.document.Revision
						if f.validateWorkerGateAuthorization(test.slot, before, after, phase, observed) != nil {
							t.Fatal("fixed gate candidate whole delta refused")
						}
						role := func(o *unstructured.Unstructured) map[string]any {
							return o.Object["metadata"].(map[string]any)["managedFields"].([]any)[0].(map[string]any)
						}
						key := "arcade.gobha.me/" + test.family + "-pod-authorized"
						for label, change := range map[string]func(*unstructured.Unstructured){
							"wrong-pod-uid": func(o *unstructured.Unstructured) { o.SetUID("b0000000-0000-4000-8000-000000000099") },
							"wrong-rv":      func(o *unstructured.Unstructured) { o.SetResourceVersion("999") },
							"missing-rv":    func(o *unstructured.Unstructured) { o.SetResourceVersion("") },
							"job-uid-annotation": func(o *unstructured.Unstructured) {
								o.SetAnnotations(map[string]string{key: string(before.GetOwnerReferences()[0].UID)})
							},
							"foreign-uid-annotation": func(o *unstructured.Unstructured) { o.SetAnnotations(map[string]string{key: "foreign"}) },
							"wrong-family": func(o *unstructured.Unstructured) {
								o.SetAnnotations(map[string]string{"arcade.gobha.me/foreign-pod-authorized": string(before.GetUID())})
							},
							"extra-annotation": func(o *unstructured.Unstructured) {
								o.SetAnnotations(map[string]string{key: string(before.GetUID()), "private": "PRIVATE-CANARY"})
							},
							"missing-annotation": func(o *unstructured.Unstructured) {
								unstructured.RemoveNestedField(o.Object, "metadata", "annotations")
							},
							"null-annotation":      func(o *unstructured.Unstructured) { o.Object["metadata"].(map[string]any)["annotations"] = nil },
							"wrong-generation":     func(o *unstructured.Unstructured) { o.SetGeneration(3) },
							"unchanged-generation": func(o *unstructured.Unstructured) { o.SetGeneration(1) },
							"missing-generation":   func(o *unstructured.Unstructured) { unstructured.RemoveNestedField(o.Object, "metadata", "generation") },
							"null-gates":           func(o *unstructured.Unstructured) { o.Object["spec"].(map[string]any)["schedulingGates"] = nil },
							"empty-gates": func(o *unstructured.Unstructured) {
								_ = unstructured.SetNestedSlice(o.Object, []any{}, "spec", "schedulingGates")
							},
							"unchanged-gates": func(o *unstructured.Unstructured) {
								gates, _, _ := unstructured.NestedSlice(before.Object, "spec", "schedulingGates")
								_ = unstructured.SetNestedSlice(o.Object, gates, "spec", "schedulingGates")
							},
							"foreign-label": func(o *unstructured.Unstructured) { o.SetLabels(map[string]string{"private": "PRIVATE-CANARY"}) },
							"foreign-owner": func(o *unstructured.Unstructured) {
								owners := o.GetOwnerReferences()
								owners[0].UID = "b0000000-0000-4000-8000-000000000099"
								o.SetOwnerReferences(owners)
							},
							"missing-owner": func(o *unstructured.Unstructured) {
								unstructured.RemoveNestedField(o.Object, "metadata", "ownerReferences")
							},
							"extra-spec": func(o *unstructured.Unstructured) { o.Object["spec"].(map[string]any)["private"] = "PRIVATE-CANARY" },
							"changed-image": func(o *unstructured.Unstructured) {
								o.Object["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)["image"] = "foreign:test"
							},
							"null-status": func(o *unstructured.Unstructured) { o.Object["status"] = nil },
							"extra-status": func(o *unstructured.Unstructured) {
								o.Object["status"].(map[string]any)["observedGeneration"] = int64(2)
							},
							"changed-status":  func(o *unstructured.Unstructured) { o.Object["status"].(map[string]any)["phase"] = "Running" },
							"extra-metadata":  func(o *unstructured.Unstructured) { o.Object["metadata"].(map[string]any)["deletionTimestamp"] = nil },
							"extra-top-level": func(o *unstructured.Unstructured) { o.Object["private"] = "PRIVATE-CANARY" },
							"foreign-manager": func(o *unstructured.Unstructured) { role(o)["manager"] = "PRIVATE-CANARY" },
							"wrong-operation": func(o *unstructured.Unstructured) { role(o)["operation"] = "Apply" },
							"status-role":     func(o *unstructured.Unstructured) { role(o)["subresource"] = "status" },
							"missing-tree":    func(o *unstructured.Unstructured) { delete(role(o), "fieldsV1") },
							"extra-leaf": func(o *unstructured.Unstructured) {
								role(o)["fieldsV1"].(map[string]any)["f:private"] = map[string]any{}
							},
							"missing-annotation-leaf": func(o *unstructured.Unstructured) {
								delete(role(o)["fieldsV1"].(map[string]any)["f:metadata"].(map[string]any), "f:annotations")
							},
							"old-gate-leaf": func(o *unstructured.Unstructured) {
								role(o)["fieldsV1"].(map[string]any)["f:spec"].(map[string]any)["f:schedulingGates"] = map[string]any{}
							},
							"duplicate-role": func(o *unstructured.Unstructured) {
								fields := o.Object["metadata"].(map[string]any)["managedFields"].([]any)
								o.Object["metadata"].(map[string]any)["managedFields"] = append(fields, role(o))
							},
							"regressed-time": func(o *unstructured.Unstructured) { role(o)["time"] = created.Format(time.RFC3339) },
							"future-time": func(o *unstructured.Unstructured) {
								role(o)["time"] = created.Add(62 * time.Second).Format(time.RFC3339)
							},
							"invalid-time": func(o *unstructured.Unstructured) { role(o)["time"] = "PRIVATE-CANARY" },
							"null-time":    func(o *unstructured.Unstructured) { role(o)["time"] = nil },
						} {
							t.Run(label, func(t *testing.T) {
								changed := after.DeepCopy()
								change(changed)
								saved := changed.DeepCopy()
								if f.validateWorkerGateAuthorization(test.slot, before, changed, phase, observed) != ErrFixtures {
									t.Fatal("unrelated gate-return delta accepted")
								}
								if !reflect.DeepEqual(saved.Object, changed.Object) {
									t.Fatal("refusal mutated caller-owned gate reply")
								}
							})
						}
						for _, stamp := range []time.Time{created.Add(time.Second), observed.Add(time.Second)} {
							legal := after.DeepCopy()
							role(legal)["time"] = stamp.Format(time.RFC3339)
							if f.validateWorkerGateAuthorization(test.slot, before, legal, phase, observed) != nil {
								t.Fatal("legal same/bounded main time refused")
							}
						}
						badBefore := before.DeepCopy()
						badBefore.SetUID("b0000000-0000-4000-8000-000000000099")
						if f.validateWorkerGateAuthorization(test.slot, badBefore, after, phase, observed) != ErrFixtures || f.validateWorkerGateAuthorization(fixturePlainPod, before, after, phase, observed) != ErrFixtures || f.validateWorkerGateAuthorization(test.slot, nil, after, phase, observed) != ErrFixtures || f.validateWorkerGateAuthorization(test.slot, before, nil, phase, observed) != ErrFixtures || f.validateWorkerGateAuthorization(test.slot, before, after, nil, observed) != ErrFixtures || f.validateWorkerGateAuthorization(test.slot, before, after, phase, time.Time{}) != ErrFixtures {
							t.Fatal("unbound original/slot/phase/time became a gate reply")
						}
						for label, mutate := range map[string]func(*unstructured.Unstructured){
							"old-null-time":      func(o *unstructured.Unstructured) { role(o)["time"] = nil },
							"old-invalid-time":   func(o *unstructured.Unstructured) { role(o)["time"] = "PRIVATE-CANARY" },
							"old-nonstring-time": func(o *unstructured.Unstructured) { role(o)["time"] = true },
							"old-missing-tree":   func(o *unstructured.Unstructured) { delete(role(o), "fieldsV1") },
							"old-null-role": func(o *unstructured.Unstructured) {
								o.Object["metadata"].(map[string]any)["managedFields"] = []any{nil}
							},
						} {
							t.Run(label, func(t *testing.T) {
								malformed := before.DeepCopy()
								mutate(malformed)
								saved := malformed.DeepCopy()
								if f.validateWorkerGateAuthorization(test.slot, malformed, after, phase, observed) != ErrFixtures || !reflect.DeepEqual(saved.Object, malformed.Object) {
									t.Fatal("malformed original accepted or changed during refusal")
								}
							})
						}
						var missing *fixtureLedger
						if missing.validateWorkerGateAuthorization(test.slot, before, after, phase, observed) != ErrFixtures {
							t.Fatal("missing ledger became gate-return authority")
						}
						if f.validatePhaseFixture(test.slot, after, phase, observed) != ErrFixtures {
							t.Fatal("dry-run gate reply became persistent original shape")
						}
						if !reflect.DeepEqual(savedBefore.Object, before.Object) || !reflect.DeepEqual(savedAfter.Object, after.Object) || !bytes.Equal(body, f.body) || identity != f.identity || revision != f.document.Revision || f.ackSlot != -1 || f.effectSlot != -1 || f.seedAck || f.seedEffect || f.markerAck || f.markerEffect || f.worldPublication || f.behaviorCompletion != nil || h.access.writes != 0 {
							t.Fatal("pure gate check mutated input/WAL/capability or cluster")
						}
					})
				}
			})
		}
	}
}
