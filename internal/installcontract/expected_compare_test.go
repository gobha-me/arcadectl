// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installcontract

import (
	"reflect"
	"sync"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
)

func TestImmutableExpectedComparisonMatchesCopiedOperandOracle(t *testing.T) {
	for _, contract := range admissionObjectContracts(t) {
		for key := range contract.resources {
			template, err := contract.Template(key, false)
			if err != nil {
				t.Fatal("signed template absent")
			}
			before := template.expected.DeepCopyObject()
			actual := template.expected.DeepCopyObject()
			for _, changed := range []bool{false, true} {
				if changed {
					metadata, err := meta.Accessor(actual)
					if err != nil {
						t.Fatal("typed metadata absent")
					}
					metadata.SetName("different-signed-object")
				}
				old := apiequality.Semantic.DeepEqual(template.expected.DeepCopyObject(), actual)
				got := apiequality.Semantic.DeepEqual(template.expected, actual)
				if got != old || got == changed || !reflect.DeepEqual(before, template.expected) {
					t.Fatal("read-only expected comparison changed oracle or expected graph")
				}
			}
		}
	}
}

func TestImmutableExpectedSemanticQuantityOperandsRemainUnchanged(t *testing.T) {
	for _, pair := range []struct {
		left, right string
		equal       bool
	}{{"64Mi", "67108864", true}, {"1", "1000m", true}, {"1.5", "1500m", true}, {"0", "0", true}, {"64Mi", "67108865", false}} {
		for _, decimalLeft := range []bool{false, true} {
			left, right := resource.MustParse(pair.left), resource.MustParse(pair.right)
			if decimalLeft {
				left.ToDec()
			} else {
				right.ToDec()
			}
			beforeLeft, beforeRight := left.DeepCopy(), right.DeepCopy()
			for repeat := 0; repeat < 4; repeat++ {
				if apiequality.Semantic.DeepEqual(left, right) != pair.equal || apiequality.Semantic.DeepEqual(right, left) != pair.equal || !reflect.DeepEqual(left, beforeLeft) || !reflect.DeepEqual(right, beforeRight) {
					t.Fatal("semantic quantity comparator mutated decimal/integer operands")
				}
			}
		}
	}
	var zero resource.Quantity
	explicit := resource.MustParse("0")
	if !apiequality.Semantic.DeepEqual(zero, explicit) || !apiequality.Semantic.DeepEqual(explicit, zero) || !reflect.DeepEqual(zero, resource.Quantity{}) {
		t.Fatal("uninitialized quantity equality changed")
	}
	// Kubernetes semantic equality intentionally equates nil and empty maps.
	if !apiequality.Semantic.DeepEqual(corev1.ResourceList(nil), corev1.ResourceList{}) {
		t.Fatal("nil/empty semantic map equality changed")
	}
}

func TestImmutableExpectedWholeMatchesAndRefusalsRemainPrivate(t *testing.T) {
	for _, contract := range admissionObjectContracts(t) {
		for key := range contract.resources {
			template, err := contract.Template(key, false)
			if err != nil {
				t.Fatal("signed template absent")
			}
			expectedBefore, resourceBefore := template.expected.DeepCopyObject(), template.resource.Object.DeepCopy()
			if key.Kind == "Namespace" {
				live, journal := namespaceJournal(t, template)
				for repeat := 0; repeat < 3; repeat++ {
					if template.MatchNamespace(live, journal) != nil {
						t.Fatal("original namespace refused")
					}
					changed := live.DeepCopy()
					changed.Object["unknown"] = true
					if template.MatchNamespace(changed, journal) == nil {
						t.Fatal("unknown namespace field accepted")
					}
				}
			} else {
				live := liveObject(t, template)
				var workers sync.WaitGroup
				for worker := 0; worker < 4; worker++ {
					workers.Go(func() {
						for repeat := 0; repeat < 6; repeat++ {
							observed := live.DeepCopy()
							if repeat%2 != 0 {
								observed.Object["unknown"] = true
							}
							err := template.MatchLive(observed, "original-uid")
							if (err == nil) != (repeat%2 == 0) {
								t.Error("shared template reused a shape verdict")
								return
							}
						}
					})
				}
				workers.Wait()
			}
			if !reflect.DeepEqual(expectedBefore, template.expected) || !reflect.DeepEqual(resourceBefore, template.resource.Object) {
				t.Fatal("successful/refused matches mutated signed expected or resource graph")
			}
		}
	}
}

func TestImmutableExpectedComparisonAvoidsWholeCopyAllocations(t *testing.T) {
	contract := testContract(t, false)
	for _, kind := range []string{"Deployment", "CustomResourceDefinition", "ClusterRole", "ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding"} {
		template := mustTemplate(t, contract, kind, "", false)
		actual := template.expected.DeepCopyObject()
		withoutCopy := testing.AllocsPerRun(10, func() {
			if !apiequality.Semantic.DeepEqual(template.expected, actual) {
				t.Fatal("read-only original comparison refused")
			}
		})
		original := testing.AllocsPerRun(10, func() {
			if !apiequality.Semantic.DeepEqual(template.expected.DeepCopyObject(), actual) {
				t.Fatal("copied original comparison refused")
			}
		})
		if withoutCopy >= original {
			t.Fatalf("copy elimination did not reduce allocations: kind=%s new=%v old=%v", kind, withoutCopy, original)
		}
		t.Logf("expected comparison allocations: kind=%s new=%v old=%v; pure fixture, not native latency", kind, withoutCopy, original)
	}
}
