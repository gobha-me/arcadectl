// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installrender"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
)

// Unit construction is not native fieldset certification: both actual native
// profiles independently call the production validator on real dry-run/ACK/GET
// responses. These fixtures exercise closed refusal and pure ownership behavior.
func fixtureResultExample(t *testing.T, ledger *fixtureLedger, slot int, phase fixtureResultPhase, created time.Time) *unstructured.Unstructured {
	t.Helper()
	o, err := ledger.object(slot)
	if err != nil {
		t.Fatal("closed example unavailable")
	}
	uid := ledger.document.Entries[slot].OriginalUID
	if phase == fixtureDryRunResult {
		uid = types.UID(fmt.Sprintf("b0000000-0000-4000-8000-%012x", slot+1))
	}
	o.SetUID(uid)
	o.SetCreationTimestamp(metav1.NewTime(created))
	if phase != fixtureDryRunResult {
		o.SetResourceVersion("101")
	}
	if o.GetKind() != "PersistentVolumeClaim" && o.GetKind() != "ServiceAccount" {
		o.SetGeneration(1)
	} else if o.GetKind() == "PersistentVolumeClaim" {
		o.SetFinalizers([]string{"kubernetes.io/pvc-protection"})
	}
	fields := []any{map[string]any{"manager": "arcadectl-installer", "operation": "Update", "apiVersion": o.GetAPIVersion(), "fieldsType": "FieldsV1", "fieldsV1": fixtureResultFieldset(o), "time": created.Add(time.Second).Format(time.RFC3339)}}
	if phase == fixtureStableResult && (o.GetKind() == "Job" || o.GetKind() == "PersistentVolumeClaim") {
		owned := map[string]any{"f:status": fixtureFieldLeaves("phase")}
		if o.GetKind() == "Job" {
			owned = map[string]any{"f:status": fixtureFieldLeaves("conditions", "ready", "terminating", "uncountedTerminatedPods")}
		}
		fields = append(fields, map[string]any{"manager": "kube-controller-manager", "operation": "Update", "apiVersion": o.GetAPIVersion(), "fieldsType": "FieldsV1", "fieldsV1": owned, "time": created.Add(10 * time.Second).Format(time.RFC3339), "subresource": "status"})
	}
	o.Object["metadata"].(map[string]any)["managedFields"] = fields
	switch o.GetKind() {
	case "Job":
		o.Object["status"] = map[string]any{}
		if phase == fixtureStableResult {
			o.Object["status"] = map[string]any{"ready": int64(0), "terminating": int64(0), "uncountedTerminatedPods": map[string]any{}, "conditions": []any{map[string]any{"type": "Suspended", "status": "True", "reason": "JobSuspended", "message": "Job suspended", "lastProbeTime": created.Add(4 * time.Second).Format(time.RFC3339), "lastTransitionTime": created.Add(3 * time.Second).Format(time.RFC3339)}}}
		}
	case "PersistentVolumeClaim":
		phaseName := "Pending"
		if phase == fixtureStableResult {
			phaseName = "Lost"
		}
		o.Object["status"] = map[string]any{"phase": phaseName}
	case "Pod":
		o.Object["status"] = map[string]any{"phase": "Pending", "qosClass": "BestEffort", "conditions": []any{map[string]any{"type": "PodScheduled", "status": "False", "reason": "SchedulingGated", "message": "Scheduling is blocked due to non-empty scheduling gates", "lastProbeTime": nil, "lastTransitionTime": created.Add(2 * time.Second).Format(time.RFC3339)}}}
	}
	return o
}

func TestFixtureResultClosedPhasesOriginalOwnershipAndWholeShape(t *testing.T) {
	created := time.Date(2026, time.October, 6, 10, 0, 0, 0, time.UTC)
	observed := created.Add(2 * time.Minute)
	for _, profile := range []string{installrender.Profile135, installrender.Profile137} {
		t.Run(profile, func(t *testing.T) {
			f := newFixtureWithPlans(t, false, fixturePlanProfile(t, "isolated-install", profile))
			ledger, err := f.engine.prepareFixtureLedger(t.Context(), f.snapshot)
			if err != nil {
				t.Fatal(err)
			}
			defer ledger.close()
			for slot := range fixtureCatalog {
				dry := fixtureResultExample(t, ledger, slot, fixtureDryRunResult, created)
				fixtureResultRefusals(t, ledger, slot, fixtureDryRunResult, dry, observed)
				if ledger.document.Entries[slot].OriginalUID != "" {
					t.Fatal("dry-run UID was adopted")
				}
				acknowledgeRecipeFixture(t, ledger, slot, types.UID(fmt.Sprintf("a0000000-0000-4000-8000-%012x", slot+1)))
				if ledger.validateResult(slot, fixtureDryRunResult, dry, observed) != ErrFixtures || ledger.validateResult(slot, fixtureAcknowledgedResult, dry, observed) != ErrFixtures {
					t.Fatal("dry-run identity became persistent ownership")
				}
				for _, phase := range []fixtureResultPhase{fixtureAcknowledgedResult, fixtureStableResult} {
					o := fixtureResultExample(t, ledger, slot, phase, created)
					fixtureResultRefusals(t, ledger, slot, phase, o, observed)
					if ledger.validateResult(slot, phase, o, observed.Add(24*time.Hour)) != nil {
						t.Fatal("resumed original was incorrectly tied to current proof start")
					}
					changed := o.DeepCopy()
					changed.SetUID(types.UID("c0000000-0000-4000-8000-000000000001"))
					if ledger.validateResult(slot, phase, changed, observed) != ErrFixtures {
						t.Fatal("same-address replacement adopted")
					}
					// Shape well-formedness cannot certify freshness. Only the
					// surrounding wire/current witnesses may do so.
					changed = o.DeepCopy()
					changed.SetResourceVersion("999")
					if ledger.validateResult(slot, phase, changed, observed) != nil {
						t.Fatal("pure shape checker invented a freshness/RV authority")
					}
				}
			}
			// Pending DELETE cannot be reset or upgraded to acceptance by a
			// still-live matching UID and valid-looking body.
			o := fixtureResultExample(t, ledger, fixturePlainPVC, fixtureStableResult, created)
			next, _ := ledger.nextDocument()
			next.Entries[fixturePlainPVC].State = fixtureDeleteAttempted
			next.Entries[fixturePlainPVC].DeleteResourceVersion = "101"
			if ledger.advance(next) != nil {
				t.Fatal("test delete intent unavailable")
			}
			before := bytes.Clone(ledger.body)
			if ledger.validateResult(fixturePlainPVC, fixtureStableResult, o, observed) != ErrFixtures || !bytes.Equal(before, ledger.body) {
				t.Fatal("pending deletion repaired by shape evidence")
			}
			if f.access.writes != 0 || f.nsUpdates != 0 {
				t.Fatal("pure validator performed cluster effects")
			}
		})
	}
}

func TestFixtureResultIndependentNativeMetadataTimes(t *testing.T) {
	created := time.Date(2026, time.October, 6, 10, 0, 0, 0, time.UTC)
	observed := created.Add(2 * time.Minute)
	for _, profile := range []string{installrender.Profile135, installrender.Profile137} {
		t.Run(profile, func(t *testing.T) {
			for _, recipe := range []string{fixtureRecipeV1, fixtureRecipeV2, fixtureRecipeV3} {
				t.Run(recipe, func(t *testing.T) {
					f := newFixtureWithPlans(t, false, fixturePlanProfile(t, "isolated-install", profile))
					ledger, err := f.engine.prepareFixtureLedgerRecipe(t.Context(), f.snapshot, recipe)
					if err != nil {
						t.Fatal(err)
					}
					defer ledger.close()
					for _, slot := range fixtureCreationOrder(ledger.document) {
						for _, phase := range []fixtureResultPhase{fixtureDryRunResult, fixtureAcknowledgedResult, fixtureStableResult} {
							if phase == fixtureAcknowledgedResult {
								acknowledgeRecipeFixture(t, ledger, slot, types.UID(fmt.Sprintf("a0000000-0000-4000-8000-%012x", slot+1)))
							}
							original := fixtureResultExample(t, ledger, slot, phase, created)
							if ledger.validateResult(slot, phase, original, observed) != nil {
								t.Fatalf("healthy original slot%d phase%d refused", slot, phase)
							}
							before := bytes.Clone(ledger.body)
							changed := original.DeepCopy()
							fields := changed.Object["metadata"].(map[string]any)["managedFields"].([]any)
							// Native field management runs before REST creation stamping.
							// Independent second-resolution timestamps can straddle a
							// boundary. Their relative order is not identity/freshness proof.
							fields[0].(map[string]any)["time"] = created.Add(-time.Second).Format(time.RFC3339)
							if ledger.validateResult(slot, phase, changed, observed) != nil {
								t.Errorf("independently valid native times refused slot%d phase%d", slot, phase)
							}
							for _, invalid := range []any{nil, "0001-01-01T00:00:00Z", "0000-01-01T00:00:00Z", "10000-01-01T00:00:00Z", created.Format(time.RFC3339Nano) + ".bad", observed.Add(2 * time.Second).Format(time.RFC3339)} {
								bad := changed.DeepCopy()
								bad.Object["metadata"].(map[string]any)["managedFields"].([]any)[0].(map[string]any)["time"] = invalid
								if ledger.validateResult(slot, phase, bad, observed) != ErrFixtures {
									t.Fatalf("invalid managed timestamp accepted slot%d phase%d", slot, phase)
								}
							}
							if !bytes.Equal(before, ledger.body) || f.access.writes != 0 || f.nsUpdates != 0 {
								t.Fatal("metadata shape proof changed ownership or cluster state")
							}
						}
					}
				})
			}
		})
	}
}

func fixtureResultRefusals(t *testing.T, ledger *fixtureLedger, slot int, phase fixtureResultPhase, o *unstructured.Unstructured, observed time.Time) {
	t.Helper()
	before := bytes.Clone(ledger.body)
	if ledger.validateResult(slot, phase, o, observed) != nil {
		t.Fatalf("closed positive slot%d phase%d refused", slot, phase)
	}
	for _, invalid := range []struct {
		slot   int
		phase  fixtureResultPhase
		object *unstructured.Unstructured
		now    time.Time
	}{
		{-1, phase, o, observed}, {len(fixtureCatalogFor(ledger.document)), phase, o, observed}, {slot, 0, o, observed}, {slot, 99, o, observed}, {slot, phase, nil, observed}, {slot, phase, o, time.Time{}},
		{slot, phase, o, time.Date(0, 1, 1, 0, 0, 0, 0, time.UTC)}, {slot, phase, o, time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)},
	} {
		if ledger.validateResult(invalid.slot, invalid.phase, invalid.object, invalid.now) != ErrFixtures {
			t.Fatal("invalid validator input admitted")
		}
	}
	mutations := map[string]func(*unstructured.Unstructured){
		"top-level":   func(x *unstructured.Unstructured) { x.Object["private"] = "PRIVATE-CANARY" },
		"api-version": func(x *unstructured.Unstructured) { x.SetAPIVersion("foreign/v1") },
		"kind":        func(x *unstructured.Unstructured) { x.SetKind("Secret") },
		"name":        func(x *unstructured.Unstructured) { x.SetName("foreign") },
		"namespace":   func(x *unstructured.Unstructured) { x.SetNamespace("foreign") },
		"uid-case":    func(x *unstructured.Unstructured) { x.SetUID(types.UID(strings.ToUpper(string(x.GetUID())))) },
		"uid-zero":    func(x *unstructured.Unstructured) { x.SetUID("00000000-0000-0000-0000-000000000000") },
		"rv":          func(x *unstructured.Unstructured) { x.SetResourceVersion("01") },
		"spec":        func(x *unstructured.Unstructured) { x.Object["spec"].(map[string]any)["private"] = true },
		"metadata-unknown": func(x *unstructured.Unstructured) {
			x.Object["metadata"].(map[string]any)["private"] = "PRIVATE-CANARY"
		},
		"metadata-known-zero": func(x *unstructured.Unstructured) { x.Object["metadata"].(map[string]any)["selfLink"] = "" },
		"metadata-null":       func(x *unstructured.Unstructured) { x.Object["metadata"].(map[string]any)["deletionTimestamp"] = nil },
		"generation":          func(x *unstructured.Unstructured) { x.Object["metadata"].(map[string]any)["generation"] = int64(2) },
		"label":               func(x *unstructured.Unstructured) { x.SetLabels(map[string]string{"private": "PRIVATE-CANARY"}) },
		"annotation":          func(x *unstructured.Unstructured) { x.SetAnnotations(map[string]string{"private": "PRIVATE-CANARY"}) },
		"owners":              func(x *unstructured.Unstructured) { x.Object["metadata"].(map[string]any)["ownerReferences"] = nil },
		"finalizer":           func(x *unstructured.Unstructured) { x.SetFinalizers([]string{"foreign"}) },
		"creation-nanoseconds": func(x *unstructured.Unstructured) {
			x.Object["metadata"].(map[string]any)["creationTimestamp"] = "2026-10-06T10:00:00.000Z"
		},
		"creation-future": func(x *unstructured.Unstructured) {
			x.SetCreationTimestamp(metav1.NewTime(observed.Add(2 * time.Second)))
		},
		"managed-null":   func(x *unstructured.Unstructured) { x.Object["metadata"].(map[string]any)["managedFields"] = nil },
		"status-null":    func(x *unstructured.Unstructured) { x.Object["status"] = nil },
		"status-unknown": func(x *unstructured.Unstructured) { x.Object["status"] = map[string]any{"private": "PRIVATE-CANARY"} },
	}
	if o.GetKind() == "ServiceAccount" {
		mutations["spec"] = func(x *unstructured.Unstructured) { x.Object["spec"] = map[string]any{} }
		mutations["automount-missing"] = func(x *unstructured.Unstructured) { delete(x.Object, "automountServiceAccountToken") }
		for name, value := range map[string]any{"null": nil, "true": true, "string": "false", "zero": int64(0)} {
			mutations["automount-"+name] = func(x *unstructured.Unstructured) { x.Object["automountServiceAccountToken"] = value }
		}
		for _, key := range []string{"secrets", "imagePullSecrets", "spec", "status"} {
			for name, value := range map[string]any{"null": nil, "empty-list": []any{}, "empty-map": map[string]any{}} {
				mutations[key+"-"+name] = func(x *unstructured.Unstructured) { x.Object[key] = value }
			}
		}
		for name, value := range map[string]any{"zero": int64(0), "one": int64(1), "null": nil} {
			mutations["generation-"+name] = func(x *unstructured.Unstructured) { x.Object["metadata"].(map[string]any)["generation"] = value }
		}
		for _, key := range []string{"f:spec", "f:status", "f:secrets", "f:imagePullSecrets"} {
			mutations["managed-authority-"+key] = func(x *unstructured.Unstructured) {
				x.Object["metadata"].(map[string]any)["managedFields"].([]any)[0].(map[string]any)["fieldsV1"] = map[string]any{key: map[string]any{}}
			}
		}
	}
	for _, field := range []string{"manager", "operation", "apiVersion", "fieldsType", "fieldsV1", "subresource", "time"} {
		mutations["managed-"+field] = func(x *unstructured.Unstructured) {
			entry := x.Object["metadata"].(map[string]any)["managedFields"].([]any)[0].(map[string]any)
			entry[field] = "PRIVATE-CANARY"
		}
	}
	mutations["managed-time-year-zero"] = func(x *unstructured.Unstructured) {
		x.Object["metadata"].(map[string]any)["managedFields"].([]any)[0].(map[string]any)["time"] = "0000-01-01T00:00:00Z"
	}
	mutations["managed-time-future"] = func(x *unstructured.Unstructured) {
		x.Object["metadata"].(map[string]any)["managedFields"].([]any)[0].(map[string]any)["time"] = observed.Add(2 * time.Second).Format(time.RFC3339)
	}
	mutations["managed-extra"] = func(x *unstructured.Unstructured) {
		m := x.Object["metadata"].(map[string]any)
		m["managedFields"] = append(m["managedFields"].([]any), map[string]any{})
	}
	mutations["rv-null"] = func(x *unstructured.Unstructured) { x.Object["metadata"].(map[string]any)["resourceVersion"] = nil }
	mutations["rv-empty"] = func(x *unstructured.Unstructured) { x.Object["metadata"].(map[string]any)["resourceVersion"] = "" }
	mutations["creation-year-zero"] = func(x *unstructured.Unstructured) {
		x.Object["metadata"].(map[string]any)["creationTimestamp"] = "0000-01-01T00:00:00Z"
	}
	if o.GetKind() == "PersistentVolumeClaim" {
		mutations["generation-zero"] = func(x *unstructured.Unstructured) { x.Object["metadata"].(map[string]any)["generation"] = int64(0) }
		mutations["generation-null"] = func(x *unstructured.Unstructured) { x.Object["metadata"].(map[string]any)["generation"] = nil }
	}
	if phase == fixtureStableResult && (o.GetKind() == "Job" || o.GetKind() == "PersistentVolumeClaim") {
		mutations["managed-status-missing"] = func(x *unstructured.Unstructured) {
			m := x.Object["metadata"].(map[string]any)
			m["managedFields"] = m["managedFields"].([]any)[:1]
		}
		mutations["managed-status-swapped"] = func(x *unstructured.Unstructured) {
			m := x.Object["metadata"].(map[string]any)["managedFields"].([]any)
			m[0], m[1] = m[1], m[0]
		}
		mutations["managed-status-authority"] = func(x *unstructured.Unstructured) {
			m := x.Object["metadata"].(map[string]any)["managedFields"].([]any)
			m[1].(map[string]any)["fieldsV1"] = map[string]any{"f:spec": map[string]any{}}
		}
	}
	if o.GetKind() == "Pod" || o.GetKind() == "Job" && phase == fixtureStableResult {
		for _, field := range []string{"type", "status", "reason", "message", "lastProbeTime", "lastTransitionTime"} {
			mutations["condition-"+field] = func(x *unstructured.Unstructured) {
				x.Object["status"].(map[string]any)["conditions"].([]any)[0].(map[string]any)[field] = "PRIVATE-CANARY"
			}
		}
		for _, value := range []string{"2026-10-06T09:59:59Z", observed.Add(2 * time.Second).Format(time.RFC3339), "0000-01-01T00:00:00Z"} {
			mutations["condition-time-"+value] = func(x *unstructured.Unstructured) {
				x.Object["status"].(map[string]any)["conditions"].([]any)[0].(map[string]any)["lastTransitionTime"] = value
			}
		}
	}
	if o.GetKind() == "Pod" && slot != fixturePlainPod {
		mutations["owner-original-uid"] = func(x *unstructured.Unstructured) {
			x.Object["metadata"].(map[string]any)["ownerReferences"].([]any)[0].(map[string]any)["uid"] = "c0000000-0000-4000-8000-000000000001"
		}
		mutations["owner-controller"] = func(x *unstructured.Unstructured) {
			x.Object["metadata"].(map[string]any)["ownerReferences"].([]any)[0].(map[string]any)["controller"] = true
		}
		mutations["owner-fieldset"] = func(x *unstructured.Unstructured) {
			x.Object["metadata"].(map[string]any)["managedFields"].([]any)[0].(map[string]any)["fieldsV1"] = map[string]any{"f:metadata": map[string]any{"f:ownerReferences": map[string]any{}}}
		}
	}
	for name, mutation := range mutations {
		t.Run(fmt.Sprintf("slot%d-phase%d/%s", slot, phase, name), func(t *testing.T) {
			x := o.DeepCopy()
			mutation(x)
			if ledger.validateResult(slot, phase, x, observed) != ErrFixtures {
				t.Fatal("mutated whole shape admitted")
			}
		})
	}
	if !bytes.Equal(before, ledger.body) {
		t.Fatal("validation changed durable fixture intent")
	}
}

func TestFixtureResultReloadKeepsOriginalOwnershipAndNoSendCapability(t *testing.T) {
	f := newFixture(t, false)
	ledger, err := f.engine.prepareFixtureLedger(t.Context(), f.snapshot)
	if err != nil {
		t.Fatal(err)
	}
	for slot := range fixtureCatalog {
		acknowledgeRecipeFixture(t, ledger, slot, types.UID(fmt.Sprintf("a0000000-0000-4000-8000-%012x", slot+1)))
	}
	created := time.Date(2026, time.October, 6, 10, 0, 0, 0, time.UTC)
	objects := make([]*unstructured.Unstructured, len(fixtureCatalog))
	for slot := range fixtureCatalog {
		objects[slot] = fixtureResultExample(t, ledger, slot, fixtureStableResult, created)
	}
	before := bytes.Clone(ledger.body)
	if ledger.close() != nil {
		t.Fatal("original lock close failed")
	}
	resumed, err := f.engine.loadFixtureLedger(t.Context(), f.snapshot)
	if err != nil {
		t.Fatal("protected original resume refused")
	}
	defer resumed.close()
	for slot, object := range objects {
		if resumed.validateResult(slot, fixtureStableResult, object, created.Add(24*time.Hour)) != nil {
			t.Fatal("resumed original shape refused")
		}
	}
	if resumed.ackSlot != -1 || resumed.effectSlot != -1 || !bytes.Equal(before, resumed.body) || f.engine.fixtureFence(f.snapshot) != ErrFixtures || f.access.writes != 0 || f.nsUpdates != 0 {
		t.Fatal("shape resume restored authority, changed evidence or retired fence")
	}
}

func TestFixtureResultRefusesExecutionBindingAndStatusAuthority(t *testing.T) {
	f := newFixture(t, false)
	ledger, err := f.engine.prepareFixtureLedger(t.Context(), f.snapshot)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.close()
	for slot := range fixtureCatalog {
		acknowledgeRecipeFixture(t, ledger, slot, types.UID(fmt.Sprintf("a0000000-0000-4000-8000-%012x", slot+1)))
	}
	created := time.Date(2026, time.October, 6, 10, 0, 0, 0, time.UTC)
	for _, slot := range []int{fixtureBackupJob, fixtureBackupPod, fixtureRetainedPVC, fixtureCancelledDestroy} {
		o := fixtureResultExample(t, ledger, slot, fixtureStableResult, created)
		var changes []func(*unstructured.Unstructured)
		switch o.GetKind() {
		case "Job":
			for _, field := range []string{"active", "succeeded", "failed", "ready", "terminating"} {
				changes = append(changes, func(x *unstructured.Unstructured) { x.Object["status"].(map[string]any)[field] = int64(1) })
			}
			changes = append(changes, func(x *unstructured.Unstructured) {
				x.Object["status"].(map[string]any)["uncountedTerminatedPods"] = map[string]any{"succeeded": []any{"foreign"}}
			})
		case "Pod":
			for _, field := range []string{"hostIP", "podIP", "nodeName", "containerStatuses"} {
				changes = append(changes, func(x *unstructured.Unstructured) { x.Object["status"].(map[string]any)[field] = "foreign" })
			}
			changes = append(changes, func(x *unstructured.Unstructured) { x.Object["spec"].(map[string]any)["nodeName"] = "foreign" })
		case "PersistentVolumeClaim":
			changes = append(changes,
				func(x *unstructured.Unstructured) { x.Object["status"].(map[string]any)["phase"] = "Bound" },
				func(x *unstructured.Unstructured) {
					x.Object["status"].(map[string]any)["capacity"] = map[string]any{"storage": "1Mi"}
				},
				func(x *unstructured.Unstructured) { x.Object["spec"].(map[string]any)["volumeName"] = "foreign" },
			)
		case "GameDestroy":
			changes = append(changes, func(x *unstructured.Unstructured) { x.Object["status"] = map[string]any{} }, func(x *unstructured.Unstructured) { x.Object["status"] = map[string]any{"phase": "Cancelled"} })
		}
		for index, change := range changes {
			x := o.DeepCopy()
			change(x)
			if ledger.validateResult(slot, fixtureStableResult, x, created.Add(time.Minute)) != ErrFixtures {
				t.Fatalf("execution/binding/status authority admitted slot%d change%d", slot, index)
			}
		}
	}
}
