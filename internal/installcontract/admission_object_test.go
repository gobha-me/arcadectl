// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installcontract

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"sync"
	"testing"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	strictjson "sigs.k8s.io/json"
)

// Independent original caller conversion: the stricter serving decoder, not
// decodeObserved, decodeBody or the new matched-object path.
func originalAdmissionObject(t *Template, live *unstructured.Unstructured) (runtime.Object, error) {
	body, err := json.Marshal(live.Object)
	if err != nil || len(body) > maxObjectBytes {
		return nil, ErrInvalid
	}
	var out runtime.Object
	if t.key.Kind == "ValidatingAdmissionPolicy" {
		out = &admissionv1.ValidatingAdmissionPolicy{}
	} else {
		out = &admissionv1.ValidatingAdmissionPolicyBinding{}
	}
	strictErrors, err := strictjson.UnmarshalStrict(body, out)
	if err != nil || len(strictErrors) != 0 {
		return nil, ErrDrift
	}
	return out, nil
}

func admissionObjectContracts(t *testing.T) []*Contract {
	t.Helper()
	baseline, _ := fixtureBaselineContract(t)
	return []*Contract{testContract(t, false), testContract(t, true), baseline}
}

func TestMatchedAdmissionObjectsKeepOriginalFieldsAndDefensiveGraphs(t *testing.T) {
	for _, contract := range admissionObjectContracts(t) {
		for key := range contract.resources {
			if key.Kind != "ValidatingAdmissionPolicy" && key.Kind != "ValidatingAdmissionPolicyBinding" {
				continue
			}
			template, err := contract.Template(key, false)
			if err != nil {
				t.Fatal("admission template absent")
			}
			live := liveObject(t, template)
			live.SetManagedFields([]metav1.ManagedFieldsEntry{{Manager: "fixture", Operation: metav1.ManagedFieldsOperationUpdate, APIVersion: key.APIVersion}})
			if key.Kind == "ValidatingAdmissionPolicy" {
				live.Object["status"] = map[string]any{"observedGeneration": int64(1), "typeChecking": map[string]any{}}
			}
			inputBefore, _ := json.Marshal(live.Object)
			expectedBefore, _ := json.Marshal(template.expected)
			want, err := originalAdmissionObject(template, live)
			if err != nil || template.MatchLive(live, "original-uid") != nil {
				t.Fatal("original two-step admission path refused")
			}
			for attempt := 0; attempt < 3; attempt++ {
				got, err := template.MatchLiveAdmissionObject(live, "original-uid")
				if err != nil || !reflect.DeepEqual(want, got) || !template.decoded.strictAdmission {
					t.Fatal("matched result lost fresh unnormalized strict fields")
				}
				got.(metav1.Object).SetUID("foreign-return")
				got.(metav1.Object).SetAnnotations(map[string]string{"foreign": "return-only"})
				switch object := got.(type) {
				case *admissionv1.ValidatingAdmissionPolicy:
					object.Spec.Validations[0].Expression = "false"
					object.Status.TypeChecking.ExpressionWarnings = append(object.Status.TypeChecking.ExpressionWarnings, admissionv1.ExpressionWarning{Warning: "return-only"})
				case *admissionv1.ValidatingAdmissionPolicyBinding:
					object.Spec.PolicyName = "foreign-return"
					object.Spec.ValidationActions[0] = admissionv1.Warn
					object.Spec.MatchResources.NamespaceSelector.MatchLabels["kubernetes.io/metadata.name"] = "foreign-return"
				}
			}
			inputAfter, _ := json.Marshal(live.Object)
			expectedAfter, _ := json.Marshal(template.expected)
			if !bytes.Equal(inputBefore, inputAfter) || !bytes.Equal(expectedBefore, expectedAfter) || !reflect.DeepEqual(template.decoded.object, want) {
				t.Fatal("returned nested graph changed input, expected shape or private memo")
			}
			if key.Kind == "ValidatingAdmissionPolicy" {
				// Health is NOT template authority. Same UID/RV but new unhealthy
				// status must be freshly returned for the caller's health checks.
				_ = unstructured.SetNestedField(live.Object, int64(0), "status", "observedGeneration")
				fresh, err := template.MatchLiveAdmissionObject(live, "original-uid")
				if err != nil || fresh.(*admissionv1.ValidatingAdmissionPolicy).Status.ObservedGeneration != 0 || fresh.(metav1.Object).GetResourceVersion() != "42" {
					t.Fatal("strict conversion reused a health/status verdict")
				}
			}
		}
	}
	if got, err := (*Template)(nil).MatchLiveAdmissionObject(nil, "original-uid"); got != nil || err != ErrInvalid {
		t.Fatal("nil template offered admission object")
	}
	other := mustTemplate(t, testContract(t, false), "Deployment", "arcadectl-controller", false)
	if got, err := other.MatchLiveAdmissionObject(liveObject(t, other), "original-uid"); got != nil || err != ErrInvalid {
		t.Fatal("non-admission template offered typed admission path")
	}
}

func TestMatchedAdmissionStrictnessCannotInheritStandardMemo(t *testing.T) {
	for _, contract := range admissionObjectContracts(t) {
		for _, kind := range []string{"ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding"} {
			template := mustTemplate(t, contract, kind, "", false)
			live := liveObject(t, template)
			for _, alias := range []string{"top", "metadata", "spec", "duplicate-case", "status"} {
				if alias == "status" && kind != "ValidatingAdmissionPolicy" {
					continue
				}
				changed := live.DeepCopy()
				spec := changed.Object["spec"].(map[string]any)
				field := "failurePolicy"
				if kind == "ValidatingAdmissionPolicyBinding" {
					field = "policyName"
				}
				switch alias {
				case "top":
					changed.Object["Spec"] = spec
					delete(changed.Object, "spec")
				case "metadata":
					metadata := changed.Object["metadata"].(map[string]any)
					metadata["Generation"] = metadata["generation"]
					delete(metadata, "generation")
				case "spec", "duplicate-case":
					spec[strings.ToUpper(field[:1])+field[1:]] = spec[field]
					if alias == "spec" {
						delete(spec, field)
					}
				case "status":
					changed.Object["status"] = map[string]any{"ObservedGeneration": int64(1), "typeChecking": map[string]any{}}
				}
				// Old MatchLive's standard decoder really accepts this shape.
				if template.MatchLive(changed, "original-uid") != nil || template.decoded.strictAdmission {
					t.Fatal("case-folding standard-memo control did not reach its boundary")
				}
				if _, err := originalAdmissionObject(template, changed); err == nil {
					t.Fatal("original strict caller unexpectedly accepted a case alias")
				}
				got, err := template.MatchLiveAdmissionObject(changed, "original-uid")
				if got != nil || err == nil || template.decoded.body != nil || template.decoded.object != nil || template.decoded.strictAdmission {
					t.Fatal("standard memo bypassed strict admission conversion or refusal clearing")
				}
				if got, err := template.MatchLiveAdmissionObject(live, "original-uid"); err != nil || got == nil {
					t.Fatal("case refusal poisoned later original admission object")
				}
			}
		}
	}
}

func TestMatchedAdmissionRefusalsClearConversionsAndReturnNoGraph(t *testing.T) {
	for _, kind := range []string{"ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding"} {
		template := mustTemplate(t, testContract(t, false), kind, "", false)
		live := liveObject(t, template)
		for _, mutation := range []func(*unstructured.Unstructured){
			func(o *unstructured.Unstructured) { o.SetUID("replacement") },
			func(o *unstructured.Unstructured) { o.SetResourceVersion("") },
			func(o *unstructured.Unstructured) { o.SetName("foreign") },
			func(o *unstructured.Unstructured) { o.SetFinalizers([]string{"foreign"}) },
			func(o *unstructured.Unstructured) { stamp := metav1.Now(); o.SetDeletionTimestamp(&stamp) },
			func(o *unstructured.Unstructured) { o.Object["unknown"] = true },
			func(o *unstructured.Unstructured) { o.Object["metadata"].(map[string]any)["unknown"] = true },
			func(o *unstructured.Unstructured) { o.Object["spec"].(map[string]any)["unknown"] = true },
			func(o *unstructured.Unstructured) { o.Object["status"] = map[string]any{"unknown": true} },
			func(o *unstructured.Unstructured) { o.Object["metadata"].(map[string]any)["generation"] = "wrong-type" },
			func(o *unstructured.Unstructured) {
				o.SetAnnotations(map[string]string{"oversize": strings.Repeat("x", maxObjectBytes+1)})
			},
			func(o *unstructured.Unstructured) { o.Object["unknown"] = make(chan int) },
			func(o *unstructured.Unstructured) {
				field, value := "failurePolicy", "Ignore"
				if kind == "ValidatingAdmissionPolicyBinding" {
					field, value = "policyName", "foreign"
				}
				_ = unstructured.SetNestedField(o.Object, value, "spec", field)
			},
		} {
			if _, err := template.MatchLiveAdmissionObject(live, "original-uid"); err != nil {
				t.Fatal("warm original refused")
			}
			changed := live.DeepCopy()
			mutation(changed)
			if got, err := template.MatchLiveAdmissionObject(changed, "original-uid"); err == nil || got != nil || template.decoded.object != nil || template.decoded.body != nil || template.decoded.strictAdmission {
				t.Fatal("identity/shape refusal returned a graph or retained a conversion")
			}
		}
		if got, err := template.MatchLiveAdmissionObject(live, "wrong-original"); got != nil || err != ErrIdentity {
			t.Fatal("caller original UID was cached")
		}
	}
}

func TestMatchedAdmissionConcurrentInputsAndPrivateResults(t *testing.T) {
	template := mustTemplate(t, testContract(t, false), "ValidatingAdmissionPolicy", "", false)
	live := liveObject(t, template)
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Go(func() {
			for j := 0; j < 12; j++ {
				input := live.DeepCopy()
				input.Object["status"] = map[string]any{"observedGeneration": int64(j), "typeChecking": map[string]any{}}
				if j%3 == 0 {
					input.Object["unknown"] = true
				}
				got, err := template.MatchLiveAdmissionObject(input, "original-uid")
				if j%3 == 0 {
					if err == nil || got != nil {
						t.Error("concurrent unknown input accepted")
					}
					continue
				}
				if err != nil || got.(*admissionv1.ValidatingAdmissionPolicy).Status.ObservedGeneration != int64(j) {
					t.Error("concurrent distinct status reused another result")
					return
				}
				got.(*admissionv1.ValidatingAdmissionPolicy).Spec.Validations[0].Expression = "return-only"
			}
		})
	}
	workers.Wait()
}

func TestMatchedAdmissionAllocationReductionAgainstOriginalStrictCaller(t *testing.T) {
	for _, kind := range []string{"ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding"} {
		template := mustTemplate(t, testContract(t, false), kind, "", false)
		live := liveObject(t, template)
		want, err := originalAdmissionObject(template, live)
		got, gotErr := template.MatchLiveAdmissionObject(live, "original-uid")
		if err != nil || gotErr != nil || !reflect.DeepEqual(want, got) {
			t.Fatal("allocation oracle lacks equivalent original result")
		}
		warm := testing.AllocsPerRun(10, func() {
			if _, err := template.MatchLiveAdmissionObject(live, "original-uid"); err != nil {
				t.Fatal("warm matched conversion refused")
			}
		})
		original := testing.AllocsPerRun(10, func() {
			if template.MatchLive(live, "original-uid") != nil {
				t.Fatal("original match refused")
			}
			if _, err := originalAdmissionObject(template, live); err != nil {
				t.Fatal("original strict conversion refused")
			}
		})
		if warm >= original {
			t.Fatalf("matched conversion did not reduce allocations: warm=%v original=%v", warm, original)
		}
		t.Logf("matched admission allocations: kind=%s warm=%v original=%v; pure fixture, not native latency", kind, warm, original)
	}
}
