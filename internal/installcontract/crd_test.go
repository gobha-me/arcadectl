// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installcontract

import (
	"errors"
	"testing"

	crdv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestCRDCurrentStorageAndConditionsBeforeAnyUpgradeEffects(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		c := testContract(t, legacy)
		for key := range c.resources {
			if key.Kind != "CustomResourceDefinition" {
				continue
			}
			template, _ := c.Template(key, false)
			for _, observed := range []int64{0, 1} {
				live := liveObject(t, template)
				if observed != 0 {
					_ = unstructured.SetNestedField(live.Object, observed, "status", "observedGeneration")
				}
				if err := template.CheckCRD(live, "original-uid", template); err != nil {
					t.Fatalf("healthy CRD %s: %v", key.Name, err)
				}
			}
		}
	}
	template := mustTemplate(t, testContract(t, false), "CustomResourceDefinition", "", false)
	for _, change := range []func(*crdv1.CustomResourceDefinition){
		func(o *crdv1.CustomResourceDefinition) { o.Status.StoredVersions = nil },
		func(o *crdv1.CustomResourceDefinition) { o.Status.StoredVersions = []string{"v1alpha1", "v1beta1"} },
		func(o *crdv1.CustomResourceDefinition) { o.Status.StoredVersions = []string{"v1beta1"} },
		func(o *crdv1.CustomResourceDefinition) { o.Status.AcceptedNames.Kind = "Foreign" },
		func(o *crdv1.CustomResourceDefinition) { o.Status.Conditions = nil },
		func(o *crdv1.CustomResourceDefinition) { o.Status.Conditions[0].Status = crdv1.ConditionFalse },
		func(o *crdv1.CustomResourceDefinition) { o.Status.Conditions[1].Status = crdv1.ConditionFalse },
		func(o *crdv1.CustomResourceDefinition) {
			o.Status.Conditions = append(o.Status.Conditions, o.Status.Conditions[0])
		},
		func(o *crdv1.CustomResourceDefinition) { o.Status.Conditions[0].ObservedGeneration = 99 },
		func(o *crdv1.CustomResourceDefinition) { o.Status.ObservedGeneration = 99 },
		func(o *crdv1.CustomResourceDefinition) {
			o.Status.Conditions = append(o.Status.Conditions, crdv1.CustomResourceDefinitionCondition{Type: crdv1.Terminating, Status: crdv1.ConditionTrue})
		},
		func(o *crdv1.CustomResourceDefinition) {
			o.Status.Conditions = append(o.Status.Conditions, crdv1.CustomResourceDefinitionCondition{Type: crdv1.StorageMigrating, Status: crdv1.ConditionTrue})
		},
		func(o *crdv1.CustomResourceDefinition) {
			o.Status.Conditions = append(o.Status.Conditions, crdv1.CustomResourceDefinitionCondition{Type: crdv1.NonStructuralSchema, Status: crdv1.ConditionTrue})
		},
		func(o *crdv1.CustomResourceDefinition) {
			o.Finalizers = []string{"customresourcecleanup.apiextensions.k8s.io"}
		},
		func(o *crdv1.CustomResourceDefinition) { o.Spec.Versions[0].Served = false },
		func(o *crdv1.CustomResourceDefinition) { o.Spec.Versions[0].Storage = false },
		func(o *crdv1.CustomResourceDefinition) { o.Spec.Conversion.Strategy = crdv1.WebhookConverter },
	} {
		live := liveObject(t, template)
		var object crdv1.CustomResourceDefinition
		if runtime.DefaultUnstructuredConverter.FromUnstructured(live.Object, &object) != nil {
			t.Fatal("decode")
		}
		change(&object)
		body, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&object)
		if err != nil {
			t.Fatal(err)
		}
		if err := template.CheckCRD(&unstructured.Unstructured{Object: body}, "original-uid", template); !errors.Is(err, ErrCRD) {
			t.Fatal("unsafe CRD transition passed")
		}
	}
}

func TestCRDUnknownNestedSchemaCannotDisappearInTypedUnionDecoder(t *testing.T) {
	template := mustTemplate(t, testContract(t, false), "CustomResourceDefinition", "", false)
	live := liveObject(t, template)
	versions, _, _ := unstructured.NestedSlice(live.Object, "spec", "versions")
	schema := versions[0].(map[string]any)["schema"].(map[string]any)["openAPIV3Schema"].(map[string]any)
	properties := schema["properties"].(map[string]any)
	properties["spec"].(map[string]any)["unsignedField"] = "raw-canary"
	_ = unstructured.SetNestedSlice(live.Object, versions, "spec", "versions")
	if err := template.MatchLive(live, "original-uid"); !errors.Is(err, ErrDrift) {
		t.Fatal("unknown nested schema lost before comparison")
	}
	if err := template.CheckCRD(live, "original-uid", template); !errors.Is(err, ErrCRD) {
		t.Fatal("unknown schema upgrade accepted")
	}
}

func TestPresentZeroCRDGenerationIsNotMissingEvidence(t *testing.T) {
	template := mustTemplate(t, testContract(t, false), "CustomResourceDefinition", "", false)
	for _, aggregate := range []bool{false, true} {
		live := liveObject(t, template)
		if aggregate {
			_ = unstructured.SetNestedField(live.Object, int64(0), "status", "observedGeneration")
		} else {
			conditions, _, _ := unstructured.NestedSlice(live.Object, "status", "conditions")
			conditions[0].(map[string]any)["observedGeneration"] = int64(0)
			_ = unstructured.SetNestedSlice(live.Object, conditions, "status", "conditions")
		}
		if err := template.CheckCRD(live, "original-uid", template); !errors.Is(err, ErrCRD) {
			t.Fatal("explicit stale zero generation treated as absence")
		}
	}
}
