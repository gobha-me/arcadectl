// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installcontract

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installstate"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

// Independent original decoder: no memo or production decodeBody dispatch.
func originalObservedDecode(t *Template, object *unstructured.Unstructured) (runtime.Object, error) {
	body, err := json.Marshal(object.Object)
	if err != nil || len(body) > maxObjectBytes {
		return nil, ErrInvalid
	}
	result := reflect.New(reflect.TypeOf(t.expected).Elem()).Interface().(runtime.Object)
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if d.Decode(result) != nil || d.Decode(&struct{}{}) != io.EOF {
		return nil, ErrDrift
	}
	return result, nil
}

func TestObservedDecodeMemoWholeBytesAndDefensiveResults(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		contract := testContract(t, legacy)
		for key := range contract.resources {
			template, err := contract.Template(key, false)
			if err != nil {
				t.Fatal(err)
			}
			live := liveObject(t, template)
			before, _ := json.Marshal(live.Object)
			want, wantErr := originalObservedDecode(template, live)
			for i := 0; i < 3; i++ {
				got, gotErr := template.decodeObserved(live)
				if gotErr != wantErr || !reflect.DeepEqual(got, want) {
					t.Fatalf("complete strict conversion changed for %s", key.String())
				}
				// Normalization/caller mutation must not affect the private graph.
				got.(metav1.Object).SetUID(types.UID("changed-result"))
				got.(metav1.Object).SetAnnotations(map[string]string{"foreign": "changed-result"})
			}
			after, _ := json.Marshal(live.Object)
			if !bytes.Equal(before, after) {
				t.Fatal("strict conversion mutated observed input")
			}
			for _, mutate := range []func(*unstructured.Unstructured){
				func(o *unstructured.Unstructured) { o.Object["unknownField"] = true },
				func(o *unstructured.Unstructured) { o.Object["metadata"].(map[string]any)["unknownField"] = true },
				func(o *unstructured.Unstructured) { o.Object["metadata"].(map[string]any)["name"] = int64(4) },
				func(o *unstructured.Unstructured) {
					o.SetAnnotations(map[string]string{"oversized": strings.Repeat("x", maxObjectBytes+1)})
				},
				func(o *unstructured.Unstructured) { o.Object["unknownField"] = make(chan int) },
			} {
				changed := live.DeepCopy()
				mutate(changed)
				want, wantErr := originalObservedDecode(template, changed)
				got, gotErr := template.decodeObserved(changed)
				if wantErr == nil || gotErr != wantErr || !reflect.DeepEqual(got, want) || template.decoded.object != nil || template.decoded.body != nil {
					t.Fatal("unsuccessful whole-byte miss was cached or changed error")
				}
				if _, err := template.decodeObserved(live); err != nil {
					t.Fatal("refusal poisoned later original conversion")
				}
			}
		}
	}
}

func TestObservedDecodeMemoDoesNotReuseShapeOrOriginalAuthority(t *testing.T) {
	template := mustTemplate(t, testContract(t, false), "Deployment", "arcadectl-controller", false)
	live := liveObject(t, template)
	for _, mutate := range []func(*unstructured.Unstructured){
		func(o *unstructured.Unstructured) { o.SetUID(types.UID("replacement")) },
		func(o *unstructured.Unstructured) { o.SetResourceVersion("") },
		func(o *unstructured.Unstructured) { o.SetName("wrong-address") },
		func(o *unstructured.Unstructured) { o.SetAPIVersion("foreign/v1") },
		func(o *unstructured.Unstructured) {
			stamp := metav1.NewTime(time.Unix(1, 0))
			o.SetDeletionTimestamp(&stamp)
		},
		func(o *unstructured.Unstructured) { o.SetOwnerReferences([]metav1.OwnerReference{{Name: "foreign"}}) },
		func(o *unstructured.Unstructured) { o.SetFinalizers([]string{"foreign"}) },
		func(o *unstructured.Unstructured) { o.Object["unknownField"] = true },
		func(o *unstructured.Unstructured) { o.SetAnnotations(map[string]string{"foreign": "same-uid-rv"}) },
		func(o *unstructured.Unstructured) {
			_ = unstructured.SetNestedField(o.Object, int64(5), "spec", "replicas")
		},
	} {
		if template.MatchLive(live, "original-uid") != nil || template.MatchLive(live, "original-uid") != nil {
			t.Fatal("original warm whole match refused")
		}
		changed := live.DeepCopy()
		mutate(changed)
		if template.MatchLive(changed, "original-uid") == nil {
			t.Fatal("pure conversion became original identity or shape authority")
		}
		if template.decoded.body != nil || template.decoded.object != nil {
			t.Fatal("refused original identity or shape retained a prior conversion")
		}
		if template.MatchLive(live, "wrong-original") != ErrIdentity || template.MatchLive(live, "original-uid") != nil {
			t.Fatal("caller original UID was cached or refusal poisoned original")
		}
	}
	// A type-valid, shape-invalid decode must be evicted by the full matcher.
	changed := live.DeepCopy()
	_ = unstructured.SetNestedField(changed.Object, int64(5), "spec", "replicas")
	if template.MatchLive(changed, "original-uid") != ErrDrift || template.decoded.body != nil || template.decoded.object != nil {
		t.Fatal("shape refusal retained its pure conversion")
	}
	namespace := mustTemplate(t, template.contract, "Namespace", "", false)
	observed, journal := namespaceJournal(t, namespace)
	if namespace.MatchNamespace(observed, journal) != nil || namespace.MatchNamespace(observed, journal) != nil || namespace.MatchAdmitted(observed) != ErrIdentity {
		t.Fatal("cached namespace decode bypassed journal requirement")
	}
	for _, annotation := range []string{installstate.Annotation, installstate.BootstrapAnnotation} {
		if namespace.MatchNamespace(observed, journal) != nil || namespace.MatchNamespace(observed, journal) != nil {
			t.Fatal("original warm namespace conversion refused")
		}
		changed := observed.DeepCopy()
		a := changed.GetAnnotations()
		a[annotation] = "foreign"
		changed.SetAnnotations(a)
		if namespace.MatchNamespace(changed, journal) == nil {
			t.Fatal("warm namespace conversion ignored changed annotations")
		}
	}
}

func TestObservedDecodeMemoIncludesIgnoredFreshFieldsAndRawCRDSchema(t *testing.T) {
	contract := testContract(t, false)
	template := mustTemplate(t, contract, "Deployment", "arcadectl-controller", false)
	live := liveObject(t, template)
	if template.MatchLive(live, "original-uid") != nil {
		t.Fatal("opening whole match refused")
	}
	live.SetResourceVersion("new-observed-rv")
	_ = unstructured.SetNestedField(live.Object, int64(3), "status", "availableReplicas")
	live.SetManagedFields([]metav1.ManagedFieldsEntry{{Manager: "fresh-observation", Operation: metav1.ManagedFieldsOperationUpdate, APIVersion: "apps/v1"}})
	if template.MatchLive(live, "original-uid") != nil {
		t.Fatal("reviewed dynamic fields were not normalized on fresh input")
	}
	body, _ := json.Marshal(live.Object)
	private := template.decoded.object.(*appsv1.Deployment)
	if !bytes.Equal(body, template.decoded.body) || private.ResourceVersion != "new-observed-rv" || private.Status.AvailableReplicas != 3 || len(private.ManagedFields) != 1 {
		t.Fatal("pure decode memo omitted changed whole-input fields or retained normalization")
	}
	for key := range contract.resources {
		if key.Kind != "CustomResourceDefinition" {
			continue
		}
		crd, err := contract.Template(key, false)
		if err != nil {
			t.Fatal(err)
		}
		original := liveObject(t, crd)
		if crd.MatchLive(original, "original-uid") != nil || crd.MatchLive(original, "original-uid") != nil {
			t.Fatal("opening warm CRD match refused")
		}
		changed := original.DeepCopy()
		versions := changed.Object["spec"].(map[string]any)["versions"].([]any)
		schema := versions[0].(map[string]any)["schema"].(map[string]any)["openAPIV3Schema"].(map[string]any)
		schema["unknownNestedSchema"] = true
		if crd.MatchLive(changed, "original-uid") != ErrDrift || crd.decoded.object != nil || crd.decoded.body != nil {
			t.Fatal("warm pure conversion hid raw nested CRD schema drift")
		}
	}
}

func TestObservedDecodeMemoConcurrentDistinctInputs(t *testing.T) {
	template := mustTemplate(t, testContract(t, false), "Deployment", "arcadectl-controller", false)
	original := liveObject(t, template)
	expectedBefore, _ := json.Marshal(template.expected)
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Go(func() {
			for j := 0; j < 12; j++ {
				live := original.DeepCopy()
				if j%2 != 0 {
					live.Object["unknownField"] = true
				}
				err := template.MatchLive(live, "original-uid")
				if (err == nil) != (j%2 == 0) {
					t.Error("concurrent exact-byte conversions shared match verdicts")
					return
				}
			}
		})
	}
	workers.Wait()
	expectedAfter, _ := json.Marshal(template.expected)
	if !bytes.Equal(expectedBefore, expectedAfter) {
		t.Fatal("concurrent comparisons mutated signed expected state")
	}
}

func TestObservedDecodeMemoAllocationReduction(t *testing.T) {
	template := mustTemplate(t, testContract(t, false), "Deployment", "arcadectl-controller", false)
	live := liveObject(t, template)
	if _, err := template.decodeObserved(live); err != nil {
		t.Fatal(err)
	}
	warm := testing.AllocsPerRun(10, func() {
		if _, err := template.decodeObserved(live); err != nil {
			t.Fatal(err)
		}
	})
	original := testing.AllocsPerRun(10, func() {
		if _, err := originalObservedDecode(template, live); err != nil {
			t.Fatal(err)
		}
	})
	cold := testing.AllocsPerRun(10, func() {
		template.decoded.clear()
		if _, err := template.decodeObserved(live); err != nil {
			t.Fatal(err)
		}
	})
	if warm >= cold || warm >= original {
		t.Fatalf("pure strict conversion reuse did not reduce original allocations: warm=%v cold=%v original=%v", warm, cold, original)
	}
	t.Logf("pure conversion allocations: warm=%v cold=%v original=%v; not native runtime certification", warm, cold, original)
}
