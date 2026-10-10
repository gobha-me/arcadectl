// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"reflect"
	"slices"
	"testing"
	"time"

	arcadev1 "github.com/gobha-me/arcadectl/api/v1alpha1"
	"github.com/gobha-me/arcadectl/internal/installrender"
	platformkube "github.com/gobha-me/arcadectl/internal/platform/kube"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Canonical source/native-derived synthetic examples, NOT evidence that a
// caller's matching object is authentic/current or safe to mutate.
func fixtureWarmCancelledExample(t *testing.T, f *fixtureLedger, created time.Time, offsets [3]time.Duration) *unstructured.Unstructured {
	return fixtureWarmCancelledSlotExample(t, f, fixtureCancelledDestroy, created, offsets)
}

func fixtureWarmCancelledSlotExample(t *testing.T, f *fixtureLedger, slot int, created time.Time, offsets [3]time.Duration) *unstructured.Unstructured {
	t.Helper()
	o := fixtureResultExample(t, f, slot, fixtureStableResult, created)
	fields, _, _ := unstructured.NestedSlice(o.Object, "metadata", "managedFields")
	fields[0].(map[string]any)["time"] = created.Add(offsets[0]).Format(time.RFC3339)
	for i, tree := range []map[string]any{fixtureWarmFinalizerFieldset(), fixtureWarmCancellationFieldset()} {
		field := map[string]any{"manager": "arcadectl-controller", "operation": "Update", "apiVersion": o.GetAPIVersion(), "fieldsType": "FieldsV1", "fieldsV1": tree, "time": created.Add(offsets[i+1]).Format(time.RFC3339)}
		if i == 1 {
			field["subresource"] = "status"
		}
		fields = append(fields, field)
	}
	var typed arcadev1.GameDestroy
	if unstructured.SetNestedSlice(o.Object, fields, "metadata", "managedFields") != nil || decodeServing(o, &typed) != nil {
		t.Fatal("warm example metadata unavailable")
	}
	indices := []int{0, 1, 2}
	slices.SortFunc(indices, func(i, j int) int { return fixtureNativeFieldOrder(typed.ManagedFields[i], typed.ManagedFields[j]) })
	ordered := []any{fields[indices[0]], fields[indices[1]], fields[indices[2]]}
	if unstructured.SetNestedSlice(o.Object, ordered, "metadata", "managedFields") != nil {
		t.Fatal("warm example field order unavailable")
	}
	o.SetFinalizers([]string{platformkube.DestroyFinalizer})
	stamp := created.Add(offsets[2]).Format(time.RFC3339)
	o.Object["status"] = map[string]any{
		"phase": "Cancelled", "observedGeneration": int64(1), "startedAt": stamp, "completedAt": stamp,
		"conditions": []any{map[string]any{"type": "Complete", "status": "False", "observedGeneration": int64(1), "reason": "Cancelled", "message": "destroy cancelled before any PVC deletion", "lastTransitionTime": stamp}},
	}
	return o
}

func TestFixtureWarmCancelledDestroyClosedWholeShape(t *testing.T) {
	created := time.Date(2026, 10, 6, 10, 0, 0, 0, time.UTC)
	for _, profile := range []string{installrender.Profile135, installrender.Profile137} {
		t.Run(profile, func(t *testing.T) {
			f := newFixtureWithPlans(t, false, fixturePlanProfile(t, "isolated-install", profile))
			ledger, err := f.engine.prepareFixtureLedger(t.Context(), f.snapshot)
			if err != nil {
				t.Fatal("original ledger unavailable")
			}
			defer ledger.close()
			acknowledgeAllRecipeFixtures(t, ledger)
			before, identity, revision := bytes.Clone(ledger.body), ledger.identity, ledger.document.Revision
			// Independent golden role order, not derived from the comparator
			// under test. Equal-second manager ordering is native-certified.
			for _, order := range []struct {
				offsets [3]time.Duration
				roles   []string
			}{
				{[3]time.Duration{time.Second, time.Second, time.Second}, []string{"arcadectl-controller:", "arcadectl-controller:status", "arcadectl-installer:"}},
				{[3]time.Duration{time.Second, 2 * time.Second, 3 * time.Second}, []string{"arcadectl-installer:", "arcadectl-controller:", "arcadectl-controller:status"}},
				{[3]time.Duration{time.Second, time.Second, 2 * time.Second}, []string{"arcadectl-controller:", "arcadectl-installer:", "arcadectl-controller:status"}},
				{[3]time.Duration{time.Second, 2 * time.Second, 2 * time.Second}, []string{"arcadectl-installer:", "arcadectl-controller:", "arcadectl-controller:status"}},
			} {
				o := fixtureWarmCancelledExample(t, ledger, created, order.offsets)
				roles := []string{}
				for _, field := range o.GetManagedFields() {
					roles = append(roles, field.Manager+":"+field.Subresource)
				}
				if !reflect.DeepEqual(roles, order.roles) {
					t.Fatal("warm native ordering diverged from independent golden roles")
				}
				original := o.DeepCopy()
				if ledger.validateWarmCancelledDestroyResult(o, created.Add(time.Minute)) != nil || !reflect.DeepEqual(original, o) {
					t.Fatal("closed warm original refused or mutated")
				}
				if ledger.validateResult(fixtureCancelledDestroy, fixtureStableResult, o, created.Add(time.Minute)) != ErrFixtures || ledger.validateDestroySeedResult(o, created.Add(time.Minute)) != ErrFixtures {
					t.Fatal("cold validator accepted warm additions")
				}
				fields, _, _ := unstructured.NestedSlice(o.Object, "metadata", "managedFields")
				for i := range fields {
					for j := i + 1; j < len(fields); j++ {
						bad := o.DeepCopy()
						copy, _, _ := unstructured.NestedSlice(bad.Object, "metadata", "managedFields")
						copy[i], copy[j] = copy[j], copy[i]
						_ = unstructured.SetNestedSlice(bad.Object, copy, "metadata", "managedFields")
						if ledger.validateWarmCancelledDestroyResult(bad, created.Add(time.Minute)) != ErrFixtures {
							t.Fatal("non-native warm ownership ordering accepted")
						}
					}
				}
			}
			valid := fixtureWarmCancelledExample(t, ledger, created, [3]time.Duration{time.Second, time.Second, time.Second})
			faults := []struct {
				name   string
				change func(*unstructured.Unstructured)
			}{
				{"unknown-top", func(o *unstructured.Unstructured) { o.Object["PRIVATE-CANARY"] = "PRIVATE-CANARY" }},
				{"metadata-extra", func(o *unstructured.Unstructured) {
					o.Object["metadata"].(map[string]any)["PRIVATE-CANARY"] = "PRIVATE-CANARY"
				}},
				{"wrong-original", func(o *unstructured.Unstructured) { o.SetUID("b0000000-0000-4000-8000-000000000001") }},
				{"rv-absent", func(o *unstructured.Unstructured) { o.SetResourceVersion("") }},
				{"generation", func(o *unstructured.Unstructured) { o.SetGeneration(2) }},
				{"no-finalizer", func(o *unstructured.Unstructured) { o.SetFinalizers(nil) }},
				{"extra-finalizer", func(o *unstructured.Unstructured) {
					o.SetFinalizers([]string{platformkube.DestroyFinalizer, "other/hold"})
				}},
				{"deletion-null", func(o *unstructured.Unstructured) { o.Object["metadata"].(map[string]any)["deletionTimestamp"] = nil }},
				{"grace-null", func(o *unstructured.Unstructured) {
					o.Object["metadata"].(map[string]any)["deletionGracePeriodSeconds"] = nil
				}},
				{"labels-null", func(o *unstructured.Unstructured) { o.Object["metadata"].(map[string]any)["labels"] = nil }},
				{"audit", func(o *unstructured.Unstructured) {
					o.SetAnnotations(map[string]string{"arcade.gobha.me/unsafe-requested-by": "other"})
				}},
				{"spec-change", func(o *unstructured.Unstructured) {
					_ = unstructured.SetNestedField(o.Object, false, "spec", "cancelRequested")
				}},
				{"status-extra", func(o *unstructured.Unstructured) {
					_ = unstructured.SetNestedField(o.Object, "PRIVATE-CANARY", "status", "unexpected")
				}},
				{"preview", func(o *unstructured.Unstructured) {
					_ = unstructured.SetNestedMap(o.Object, map[string]any{}, "status", "preview")
				}},
				{"journal-null", func(o *unstructured.Unstructured) {
					_ = unstructured.SetNestedField(o.Object, nil, "status", "deletionJournal")
				}},
				{"status-generation", func(o *unstructured.Unstructured) {
					_ = unstructured.SetNestedField(o.Object, int64(2), "status", "observedGeneration")
				}},
				{"future-completion", func(o *unstructured.Unstructured) {
					_ = unstructured.SetNestedField(o.Object, created.Add(time.Hour).Format(time.RFC3339), "status", "completedAt")
				}},
				{"time-inversion", func(o *unstructured.Unstructured) {
					_ = unstructured.SetNestedField(o.Object, created.Add(2*time.Second).Format(time.RFC3339), "status", "startedAt")
				}},
				{"condition-message", func(o *unstructured.Unstructured) {
					c, _, _ := unstructured.NestedSlice(o.Object, "status", "conditions")
					c[0].(map[string]any)["message"] = "PRIVATE-CANARY"
					_ = unstructured.SetNestedSlice(o.Object, c, "status", "conditions")
				}},
				{"condition-observed", func(o *unstructured.Unstructured) {
					c, _, _ := unstructured.NestedSlice(o.Object, "status", "conditions")
					c[0].(map[string]any)["observedGeneration"] = int64(2)
					_ = unstructured.SetNestedSlice(o.Object, c, "status", "conditions")
				}},
			}
			for _, fault := range faults {
				t.Run(fault.name, func(t *testing.T) {
					o := valid.DeepCopy()
					fault.change(o)
					if ledger.validateWarmCancelledDestroyResult(o, created.Add(time.Minute)) != ErrFixtures {
						t.Fatal("nonclosed warm shape accepted")
					}
				})
			}
			for i := 0; i < 3; i++ {
				for _, key := range []string{"manager", "operation", "apiVersion", "fieldsType", "subresource", "time", "fieldsV1", "PRIVATE-CANARY"} {
					o := valid.DeepCopy()
					fields, _, _ := unstructured.NestedSlice(o.Object, "metadata", "managedFields")
					fields[i].(map[string]any)[key] = "PRIVATE-CANARY"
					_ = unstructured.SetNestedSlice(o.Object, fields, "metadata", "managedFields")
					if ledger.validateWarmCancelledDestroyResult(o, created.Add(time.Minute)) != ErrFixtures {
						t.Fatal("nonclosed managed-field role accepted")
					}
				}
				for _, mode := range []string{"drop", "duplicate", "foreign-tree"} {
					o := valid.DeepCopy()
					fields, _, _ := unstructured.NestedSlice(o.Object, "metadata", "managedFields")
					switch mode {
					case "drop":
						fields = append(fields[:i], fields[i+1:]...)
					case "duplicate":
						fields[(i+1)%3] = fields[i]
					case "foreign-tree":
						fields[i].(map[string]any)["fieldsV1"] = map[string]any{"f:spec": fixtureFieldLeaves("confirmationChallenge")}
					}
					_ = unstructured.SetNestedSlice(o.Object, fields, "metadata", "managedFields")
					if ledger.validateWarmCancelledDestroyResult(o, created.Add(time.Minute)) != ErrFixtures {
						t.Fatal("incomplete/extra ownership accepted")
					}
				}
			}
			if ledger.validateWarmCancelledDestroyResult(nil, created.Add(time.Minute)) != ErrFixtures || ledger.validateWarmCancelledDestroyResult(valid, time.Time{}) != ErrFixtures {
				t.Fatal("nil/unbounded warm observation accepted")
			}
			var absentLedger *fixtureLedger
			if absentLedger.validateWarmCancelledDestroyResult(valid, created.Add(time.Minute)) != ErrFixtures {
				t.Fatal("nil ledger accepted observed identity")
			}
			memo := ledger.document
			ledger.document.RunID = "PRIVATE-MEMO-CANARY"
			memoResult := ledger.validateWarmCancelledDestroyResult(valid, created.Add(time.Minute))
			ledger.document = memo
			if memoResult != ErrFixtures {
				t.Fatal("document mismatch accepted observed identity")
			}
			protected := ledger.body
			ledger.body = []byte(`{"PRIVATE-BODY-CANARY":true}`)
			bodyResult := ledger.validateWarmCancelledDestroyResult(valid, created.Add(time.Minute))
			ledger.body = protected
			if bodyResult != ErrFixtures {
				t.Fatal("noncanonical protected body accepted observed identity")
			}
			trusted := ledger.engine.plans
			untrusted := map[string]*installrender.Plan{}
			for digest := range trusted {
				untrusted[digest] = &installrender.Plan{}
			}
			ledger.engine.plans = untrusted
			trustResult := ledger.validateWarmCancelledDestroyResult(valid, created.Add(time.Minute))
			ledger.engine.plans = trusted
			if trustResult != ErrFixtures {
				t.Fatal("untrusted plan accepted observed identity")
			}
			stored, storedID, err := f.engine.files.Read(ledger.name, fixtureLedgerMaxBytes)
			if err != nil || !bytes.Equal(stored, before) || storedID != identity || !bytes.Equal(ledger.body, before) || ledger.identity != identity || ledger.document.Revision != revision || ledger.ackSlot != -1 || ledger.effectSlot != -1 || ledger.seedAck || ledger.seedEffect || f.access.writes != 0 || f.nsUpdates != 0 || f.engine.fixtureFence(f.snapshot) != ErrFixtures {
				t.Fatal("pure warm validation changed ownership/capabilities/effects/fence")
			}
			next, err := ledger.nextDocument()
			if err != nil {
				t.Fatal("original cleanup intent unavailable")
			}
			next.Entries[fixtureCancelledDestroy].State = fixtureDeleteAttempted
			next.Entries[fixtureCancelledDestroy].DeleteResourceVersion = valid.GetResourceVersion()
			if ledger.advance(next) != nil {
				t.Fatal("original cleanup intent not durable")
			}
			pending, pendingIdentity := bytes.Clone(ledger.body), ledger.identity
			pendingEffect, pendingACK := ledger.effectSlot, ledger.ackSlot
			if ledger.validateWarmCancelledDestroyResult(valid, created.Add(time.Minute)) != ErrFixtures || !bytes.Equal(pending, ledger.body) || pendingIdentity != ledger.identity || pendingEffect != ledger.effectSlot || pendingACK != ledger.ackSlot {
				t.Fatal("matching warm observation settled an uncertain original DELETE")
			}
		})
	}
}
