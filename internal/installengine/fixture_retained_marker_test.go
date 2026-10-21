// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installrender"
	platformkube "github.com/gobha-me/arcadectl/internal/platform/kube"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Independent native golden addition from BOTH profiles. This is an abstract
// example, not a wire ACK, freshness proof or permission to delete fixtures.
func fixtureMarkedRetainedExample(t *testing.T, f *fixtureLedger, created time.Time) *unstructured.Unstructured {
	t.Helper()
	o := fixtureResultExample(t, f, fixtureRetainedPVC, fixtureStableResult, created)
	o.SetResourceVersion("102")
	annotations := o.GetAnnotations()
	annotations[platformkube.AnnotationColdBackupUID] = f.document.RunID
	o.SetAnnotations(annotations)
	fields := o.Object["metadata"].(map[string]any)["managedFields"].([]any)
	main := fields[0].(map[string]any)
	main["fieldsV1"].(map[string]any)["f:metadata"].(map[string]any)["f:annotations"].(map[string]any)["f:arcade.gobha.me/cold-backup-uid"] = map[string]any{}
	main["time"] = created.Add(20 * time.Second).Format(time.RFC3339)
	o.Object["metadata"].(map[string]any)["managedFields"] = []any{fields[1], main}
	return o
}

func TestFixtureRetainedMarkerExactNativeWholeAndPurity(t *testing.T) {
	created := time.Date(2026, 10, 7, 15, 0, 0, 0, time.UTC)
	for _, profile := range []string{installrender.Profile135, installrender.Profile137} {
		t.Run(profile, func(t *testing.T) {
			f := newFixtureWithPlans(t, false, fixturePlanProfile(t, "isolated-install", profile))
			ledger, err := f.engine.prepareFixtureLedger(t.Context(), f.snapshot)
			if err != nil {
				t.Fatal("original ledger unavailable")
			}
			defer ledger.close()
			acknowledgeAllRecipeFixtures(t, ledger)
			if ledger.advance(fixtureMarkerIntent(t, ledger)) != nil {
				t.Fatal("abstract marker intent unavailable")
			}
			o := fixtureMarkedRetainedExample(t, ledger, created)
			if ledger.validateRetainedMarkerResult(o, created.Add(time.Minute)) != ErrFixtures {
				t.Fatal("unknown marker adopted a result")
			}
			ledger.markerEffect = false // abstract instrumentation, NOT a native send
			if ledger.advance(fixtureMarkerAcknowledgement(t, ledger)) != nil {
				t.Fatal("abstract marker acknowledgement unavailable")
			}
			body, identity := bytes.Clone(ledger.body), ledger.identity
			before, _ := json.Marshal(o.Object)
			for _, observed := range []time.Time{created.Add(time.Minute), created.Add(24 * time.Hour)} {
				if ledger.validateRetainedMarkerResult(o, observed) != nil {
					t.Fatal("exact learned native marker shape refused")
				}
			}
			// A tied second is legal native bookkeeping; test the complete native
			// ordering rather than hard-coding the observed status-first order.
			tied := o.DeepCopy()
			fields := tied.Object["metadata"].(map[string]any)["managedFields"].([]any)
			fields[1].(map[string]any)["time"] = fields[0].(map[string]any)["time"]
			tied.Object["metadata"].(map[string]any)["managedFields"] = []any{fields[1], fields[0]}
			if ledger.validateRetainedMarkerResult(tied, created.Add(time.Minute)) != nil {
				t.Fatal("legal native tie order refused")
			}
			if ledger.validateResult(fixtureRetainedPVC, fixtureStableResult, o, created.Add(time.Minute)) != ErrFixtures || !ledger.markerUnresolved() || f.engine.fixtureFence(f.snapshot) != ErrFixtures {
				t.Fatal("marked shape bypassed ordinary acceptance/fence")
			}
			after, _ := json.Marshal(o.Object)
			if !bytes.Equal(before, after) || !bytes.Equal(body, ledger.body) || identity != ledger.identity || ledger.markerAck || ledger.markerEffect {
				t.Fatal("pure marker validation mutated input or WAL/capabilities")
			}
		})
	}
}

func TestFixtureRetainedMarkerRejectsWholeShapeAndReceiptDrift(t *testing.T) {
	f := newFixture(t, false)
	ledger, err := f.engine.prepareFixtureLedger(t.Context(), f.snapshot)
	if err != nil {
		t.Fatal("original ledger unavailable")
	}
	defer ledger.close()
	acknowledgeAllRecipeFixtures(t, ledger)
	if ledger.advance(fixtureMarkerIntent(t, ledger)) != nil {
		t.Fatal("abstract marker intent unavailable")
	}
	ledger.markerEffect = false
	if ledger.advance(fixtureMarkerAcknowledgement(t, ledger)) != nil {
		t.Fatal("abstract marker acknowledgement unavailable")
	}
	created := time.Date(2026, 10, 7, 15, 0, 0, 0, time.UTC)
	original := fixtureMarkedRetainedExample(t, ledger, created)
	if ledger.validateRetainedMarkerResult(original, created.Add(time.Minute)) != nil {
		t.Fatal("valid marker control refused")
	}
	mutations := map[string]func(*unstructured.Unstructured){
		"foreign-uid":     func(o *unstructured.Unstructured) { o.SetUID("b0000000-0000-4000-8000-000000000001") },
		"foreign-rv":      func(o *unstructured.Unstructured) { o.SetResourceVersion("103") },
		"generation-zero": func(o *unstructured.Unstructured) { o.Object["metadata"].(map[string]any)["generation"] = int64(0) },
		"generation-one":  func(o *unstructured.Unstructured) { o.SetGeneration(1) },
		"deleting": func(o *unstructured.Unstructured) {
			o.SetDeletionTimestamp(&metav1.Time{Time: created.Add(time.Second)})
		},
		"null-owner": func(o *unstructured.Unstructured) { o.Object["metadata"].(map[string]any)["ownerReferences"] = nil },
		"foreign-owner": func(o *unstructured.Unstructured) {
			o.SetOwnerReferences([]metav1.OwnerReference{{APIVersion: "v1", Kind: "Pod", Name: "foreign", UID: "foreign"}})
		},
		"private-metadata": func(o *unstructured.Unstructured) {
			o.Object["metadata"].(map[string]any)["privateCredential"] = "PRIVATE-CANARY"
		},
		"wrong-marker": func(o *unstructured.Unstructured) {
			a := o.GetAnnotations()
			a[platformkube.AnnotationColdBackupUID] = "foreign"
			o.SetAnnotations(a)
		},
		"missing-marker": func(o *unstructured.Unstructured) {
			a := o.GetAnnotations()
			delete(a, platformkube.AnnotationColdBackupUID)
			o.SetAnnotations(a)
		},
		"missing-binder": func(o *unstructured.Unstructured) {
			a := o.GetAnnotations()
			delete(a, "pv.kubernetes.io/bind-completed")
			o.SetAnnotations(a)
		},
		"extra-annotation": func(o *unstructured.Unstructured) {
			a := o.GetAnnotations()
			a["private"] = "PRIVATE-CANARY"
			o.SetAnnotations(a)
		},
		"retention-label": func(o *unstructured.Unstructured) {
			a := o.GetLabels()
			delete(a, platformkube.LabelDataPolicy)
			o.SetLabels(a)
		},
		"finalizer":      func(o *unstructured.Unstructured) { o.SetFinalizers(nil) },
		"bound-status":   func(o *unstructured.Unstructured) { o.Object["status"] = map[string]any{"phase": "Bound"} },
		"private-status": func(o *unstructured.Unstructured) { o.Object["status"].(map[string]any)["private"] = "PRIVATE-CANARY" },
		"storage":        func(o *unstructured.Unstructured) { o.Object["spec"].(map[string]any)["storageClassName"] = "foreign" },
		"volume":         func(o *unstructured.Unstructured) { o.Object["spec"].(map[string]any)["volumeName"] = "foreign" },
		"top-level":      func(o *unstructured.Unstructured) { o.Object["private"] = "PRIVATE-CANARY" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			o := original.DeepCopy()
			mutate(o)
			if ledger.validateRetainedMarkerResult(o, created.Add(time.Minute)) != ErrFixtures {
				t.Fatal("foreign whole shape accepted")
			}
		})
	}
	for _, change := range []string{"missing-leaf", "extra-leaf", "escaped-leaf", "extra-role", "duplicate-role", "reverse-order", "null-subresource", "empty-subresource", "apply", "private-attribute", "future-time", "past-time", "noncanonical-time", "status-leaf", "null-tree"} {
		t.Run(change, func(t *testing.T) {
			o := original.DeepCopy()
			fields := o.Object["metadata"].(map[string]any)["managedFields"].([]any)
			main := fields[1].(map[string]any)
			annotations := main["fieldsV1"].(map[string]any)["f:metadata"].(map[string]any)["f:annotations"].(map[string]any)
			switch change {
			case "missing-leaf":
				delete(annotations, "f:arcade.gobha.me/cold-backup-uid")
			case "extra-leaf":
				annotations["f:private"] = map[string]any{}
			case "escaped-leaf":
				delete(annotations, "f:arcade.gobha.me/cold-backup-uid")
				annotations["f:arcade.gobha.me~1cold-backup-uid"] = map[string]any{}
			case "extra-role":
				fields = append(fields, main)
			case "duplicate-role":
				fields[0] = main
			case "reverse-order":
				fields = []any{fields[1], fields[0]}
			case "null-subresource":
				main["subresource"] = nil
			case "empty-subresource":
				main["subresource"] = ""
			case "apply":
				main["operation"] = "Apply"
			case "private-attribute":
				main["private"] = "PRIVATE-CANARY"
			case "future-time":
				main["time"] = created.Add(2 * time.Minute).Format(time.RFC3339)
			case "past-time":
				main["time"] = created.Add(-time.Second).Format(time.RFC3339)
			case "noncanonical-time":
				main["time"] = created.Add(20 * time.Second).Format("2006-01-02T15:04:05+00:00")
			case "status-leaf":
				fields[0].(map[string]any)["fieldsV1"].(map[string]any)["f:status"].(map[string]any)["f:private"] = map[string]any{}
			case "null-tree":
				main["fieldsV1"] = nil
			}
			o.Object["metadata"].(map[string]any)["managedFields"] = fields
			if ledger.validateRetainedMarkerResult(o, created.Add(time.Minute)) != ErrFixtures {
				t.Fatal("unlearned managed-field bookkeeping accepted")
			}
		})
	}
	originalReceipt := *ledger.document.RetainedMarker
	for _, receipt := range []*fixtureRetainedMarkerReceipt{nil, {State: fixtureRetainedMarkerAttempted, BeforeResourceVersion: "101"}, {State: fixtureRetainedMarkerAcknowledged, BeforeResourceVersion: "101", AcknowledgedResourceVersion: "103"}} {
		ledger.document.RetainedMarker = receipt
		if ledger.validateRetainedMarkerResult(original, created.Add(time.Minute)) != ErrFixtures {
			t.Fatal("missing/unknown/foreign receipt acquired shape authority")
		}
	}
	ledger.document.RetainedMarker = &originalReceipt
	if !reflect.DeepEqual(originalReceipt, *ledger.document.RetainedMarker) {
		t.Fatal("test receipt restoration failed")
	}
}
