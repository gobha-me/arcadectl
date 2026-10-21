// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installcontract

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"sync"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Reference the previous signed/live normalization, independently of the new
// helper, including exact raw nested keys and JSON numeric equivalence.
func previousCRDSpecBytes(o *unstructured.Unstructured) []byte {
	spec, exists, err := unstructured.NestedMap(o.Object, "spec")
	if err != nil || !exists {
		return nil
	}
	if _, exists := spec["conversion"]; !exists {
		spec["conversion"] = map[string]any{"strategy": "None"}
	}
	if value, exists := spec["preserveUnknownFields"]; exists && value == false {
		delete(spec, "preserveUnknownFields")
	}
	body, err := json.Marshal(spec)
	if err != nil {
		return nil
	}
	return body
}

func TestSignedCRDNormalizationPreservesPreviousExactShape(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		c := testContract(t, legacy)
		for key := range c.resources {
			if key.Kind != "CustomResourceDefinition" {
				continue
			}
			template, err := c.Template(key, false)
			if err != nil || !bytes.Equal(template.crdSpec, previousCRDSpecBytes(template.resource.Object)) {
				t.Fatal("compiled signed normalization changed")
			}
			for _, change := range []func(*unstructured.Unstructured){
				func(o *unstructured.Unstructured) {},
				func(o *unstructured.Unstructured) { unstructured.RemoveNestedField(o.Object, "spec", "conversion") },
				func(o *unstructured.Unstructured) {
					_ = unstructured.SetNestedField(o.Object, false, "spec", "preserveUnknownFields")
				},
				func(o *unstructured.Unstructured) {
					_ = unstructured.SetNestedField(o.Object, true, "spec", "preserveUnknownFields")
				},
				func(o *unstructured.Unstructured) {
					_ = unstructured.SetNestedField(o.Object, "Webhook", "spec", "conversion", "strategy")
				},
				func(o *unstructured.Unstructured) {
					_ = unstructured.SetNestedField(o.Object, "unknown", "spec", "unsigned")
				},
				func(o *unstructured.Unstructured) { unstructured.RemoveNestedField(o.Object, "spec") },
				func(o *unstructured.Unstructured) { o.Object["spec"] = "malformed" },
			} {
				live := template.resource.Object.DeepCopy()
				change(live)
				before := live.DeepCopy()
				want := previousCRDSpecBytes(live)
				if !bytes.Equal(normalizedCRDSpec(live), want) || template.matchCRDSpec(live) != (want != nil && bytes.Equal(template.crdSpec, want)) {
					t.Fatal("live comparison diverged from previous exact normalization")
				}
				if !reflect.DeepEqual(before, live) {
					t.Fatal("normalization mutated live observation")
				}
			}
		}
	}
	integer := &unstructured.Unstructured{Object: map[string]any{"spec": map[string]any{"schema": map[string]any{"minimum": int64(1)}}}}
	decimal := &unstructured.Unstructured{Object: map[string]any{"spec": map[string]any{"schema": map[string]any{"minimum": float64(1)}}}}
	if !bytes.Equal(normalizedCRDSpec(integer), normalizedCRDSpec(decimal)) {
		t.Fatal("equivalent integral JSON numbers became drift")
	}
	if normalizedCRDSpec(nil) != nil || (&Template{}).matchCRDSpec(integer) || (&Template{}).sameSignedCRDSpec(&Template{}) {
		t.Fatal("uncompiled or absent evidence matched")
	}
}

func TestSignedCRDNormalizationNeverCachesLiveMatchOrMutableCandidate(t *testing.T) {
	template := mustTemplate(t, testContract(t, false), "CustomResourceDefinition", "", false)
	targetContract := testContractVariant(t, false, template.contract.plan.Namespace(), template.contract.plan.Profile().ID, "c", "d")
	target, err := targetContract.Template(template.Key(), false)
	if err != nil || !template.sameSignedCRDSpec(target) {
		t.Fatal("independently compiled unchanged CRD transition refused")
	}
	live := liveObject(t, template)
	if template.CheckCRD(live, "original-uid", target) != nil {
		t.Fatal("healthy initial transition refused")
	}
	changed := live.DeepCopy()
	_ = unstructured.SetNestedField(changed.Object, "Webhook", "spec", "conversion", "strategy")
	if !errors.Is(template.CheckCRD(changed, "original-uid", target), ErrCRD) {
		t.Fatal("earlier success hid fresh conversion drift")
	}
	changed = live.DeepCopy()
	changed.SetUID("replacement-uid")
	if !errors.Is(template.CheckCRD(changed, "original-uid", target), ErrCRD) {
		t.Fatal("compiled spec bypassed live original identity")
	}
	candidate, err := template.Candidate("0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	_ = unstructured.SetNestedField(candidate.Object, "Webhook", "spec", "conversion", "strategy")
	if !template.sameSignedCRDSpec(target) || !template.matchCRDSpec(live) {
		t.Fatal("mutable candidate changed compiled signed evidence")
	}
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < 4; n++ {
				if template.CheckCRD(live.DeepCopy(), "original-uid", target) != nil {
					t.Error("concurrent immutable signed comparison changed")
				}
			}
		}()
	}
	wg.Wait()
}

func TestSignedCRDNormalizationRejectsChangedTargetWithHealthyOriginal(t *testing.T) {
	original := mustTemplate(t, testContract(t, false), "CustomResourceDefinition", "", false)
	c := testContract(t, false)
	// Exercise compilation of a distinct target spec, not mutation of a
	// published Template or a changed live observation.
	r := c.resources[original.Key()]
	r.Object = r.Object.DeepCopy()
	_ = unstructured.SetNestedField(r.Object.Object, "Webhook", "spec", "conversion", "strategy")
	c.resources[original.Key()] = r
	target, err := c.compileTemplate(original.Key(), false)
	if err != nil {
		t.Fatal(err)
	}
	live := liveObject(t, original)
	if original.MatchLive(live, "original-uid") != nil {
		t.Fatal("original is not independently healthy")
	}
	if !errors.Is(original.CheckCRD(live, "original-uid", target), ErrCRD) {
		t.Fatal("changed signed target bypassed CRD transition gate")
	}
	if _, err := target.UpdateCandidate(original, live, "original-uid", "0123456789abcdef0123456789abcdef"); !errors.Is(err, ErrCRD) {
		t.Fatal("healthy original allowed changed signed CRD update")
	}
}

func TestSignedCRDNormalizationAvoidsRepeatedSignedSchemaAllocations(t *testing.T) {
	template := mustTemplate(t, testContract(t, false), "CustomResourceDefinition", "", false)
	live := template.resource.Object.DeepCopy()
	previous := testing.AllocsPerRun(3, func() {
		if !sameCRDSpec(template.resource.Object, live) {
			t.Fatal("previous comparison refused")
		}
	})
	compiled := testing.AllocsPerRun(3, func() {
		if !template.matchCRDSpec(live) {
			t.Fatal("compiled comparison refused")
		}
	})
	if compiled >= previous {
		t.Fatal("signed-side precompilation did not reduce pure comparison allocations")
	}
	t.Logf("pure CRD comparison allocations previous=%.0f compiled=%.0f; not native runtime certification", previous, compiled)
}
