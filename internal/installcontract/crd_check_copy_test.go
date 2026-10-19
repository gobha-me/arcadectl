// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installcontract

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installrender"
	crdv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
)

type crdCheckCopyFixture struct {
	name                         string
	production, baseline, target *Template
	live                         *unstructured.Unstructured
}

func crdCheckCopyFixtures(t testing.TB) []crdCheckCopyFixture {
	t.Helper()
	var fixtures []crdCheckCopyFixture
	for _, configuration := range []struct {
		profile, namespace string
		legacy             bool
	}{
		{installrender.Profile135, "isolated-install", false},
		{installrender.Profile137, "isolated-install", false},
		// The preserved predecessor supports ONLY137 and its original namespace.
		{installrender.Profile137, installrender.DefaultNamespace, true},
	} {
		profile, legacy := configuration.profile, configuration.legacy
		c := testContractVariant(t, legacy, configuration.namespace, profile, "a", "b")
		var names []string
		for key := range c.resources {
			if key.Kind == "CustomResourceDefinition" {
				names = append(names, key.Name)
			}
		}
		sort.Strings(names)
		if len(names) != 5 {
			t.Fatal("signed CRD census changed")
		}
		for _, name := range names {
			template := mustTemplate(t, c, "CustomResourceDefinition", name, false)
			baseline, err := c.compileTemplate(template.key, false)
			if err != nil {
				t.Fatal(err)
			}
			target, err := c.compileTemplate(template.key, false)
			if err != nil {
				t.Fatal(err)
			}
			generation := "Current"
			if legacy {
				generation = "Legacy"
			}
			fixtures = append(fixtures, crdCheckCopyFixture{profile + generation + crdBorrowIDs[name], template, baseline, target, liveObject(t, template)})
		}
	}
	return fixtures
}

func compareCRDCheckCopy(t testing.TB, fixture crdCheckCopyFixture, live *unstructured.Unstructured, uid types.UID) {
	t.Helper()
	before, _ := json.Marshal(live.Object)
	got := fixture.production.MatchLive(live, uid)
	want := fixture.baseline.frozenCRDMatchLive(live, uid)
	if got != want {
		t.Fatalf("whole MatchLive differs: got %v want %v", got, want)
	}
	got = fixture.production.CheckCRD(live, uid, fixture.target)
	want = fixture.baseline.frozenCRDCheck(live, uid, fixture.target)
	if got != want {
		t.Fatalf("whole CheckCRD differs: got %v want %v", got, want)
	}
	after, _ := json.Marshal(live.Object)
	if !bytes.Equal(before, after) {
		t.Fatal("whole checks mutated observed input")
	}
}

func crdCopySchema(o *unstructured.Unstructured) map[string]any {
	return o.Object["spec"].(map[string]any)["versions"].([]any)[0].(map[string]any)["schema"].(map[string]any)["openAPIV3Schema"].(map[string]any)
}

func TestCRDCheckCopyWholeOperationOracle(t *testing.T) {
	for _, fixture := range crdCheckCopyFixtures(t) {
		t.Run(fixture.name, func(t *testing.T) {
			if fixture.production.MatchLive(fixture.live, fixture.live.GetUID()) != nil || fixture.production.CheckCRD(fixture.live, fixture.live.GetUID(), fixture.target) != nil || fixture.baseline.frozenCRDMatchLive(fixture.live, fixture.live.GetUID()) != nil || fixture.baseline.frozenCRDCheck(fixture.live, fixture.live.GetUID(), fixture.target) != nil {
				t.Fatal("healthy whole-operation control refused")
			}
			for i := 0; i < 5; i++ {
				compareCRDCheckCopy(t, fixture, fixture.live, fixture.live.GetUID())
			}
			for _, mutate := range []func(*unstructured.Unstructured){
				func(o *unstructured.Unstructured) { o.SetUID("replacement") },
				func(o *unstructured.Unstructured) { o.SetResourceVersion("") },
				func(o *unstructured.Unstructured) { o.SetName("foreign") },
				func(o *unstructured.Unstructured) { o.SetAPIVersion("foreign/v1") },
				func(o *unstructured.Unstructured) { o.SetGeneration(-1) },
				func(o *unstructured.Unstructured) { o.SetFinalizers([]string{"foreign"}) },
				func(o *unstructured.Unstructured) { o.SetOwnerReferences([]metav1.OwnerReference{{Name: "foreign"}}) },
				func(o *unstructured.Unstructured) {
					stamp := metav1.NewTime(time.Unix(1, 0))
					o.SetDeletionTimestamp(&stamp)
				},
				func(o *unstructured.Unstructured) { o.Object["unknown"] = true },
				func(o *unstructured.Unstructured) { o.Object["metadata"].(map[string]any)["unknown"] = true },
				func(o *unstructured.Unstructured) { crdCopySchema(o)["unknownNestedSchema"] = true },
				func(o *unstructured.Unstructured) { crdCopySchema(o)["description"] = "unsigned" },
				func(o *unstructured.Unstructured) { delete(o.Object["spec"].(map[string]any), "conversion") },
				func(o *unstructured.Unstructured) { o.Object["spec"].(map[string]any)["conversion"] = nil },
				func(o *unstructured.Unstructured) {
					spec := o.Object["spec"].(map[string]any)
					spec["Scope"] = spec["scope"]
					delete(spec, "scope")
				},
				func(o *unstructured.Unstructured) {
					_ = unstructured.SetNestedField(o.Object, "Cluster", "spec", "scope")
				},
				func(o *unstructured.Unstructured) {
					_ = unstructured.SetNestedField(o.Object, int64(0), "status", "observedGeneration")
				},
				func(o *unstructured.Unstructured) {
					_ = unstructured.SetNestedField(o.Object, int64(7), "status", "observedGeneration")
				},
				func(o *unstructured.Unstructured) {
					_ = unstructured.SetNestedSlice(o.Object, []any{"foreign"}, "status", "storedVersions")
				},
				func(o *unstructured.Unstructured) {
					_ = unstructured.SetNestedField(o.Object, "Foreign", "status", "acceptedNames", "kind")
				},
				func(o *unstructured.Unstructured) { o.Object["status"].(map[string]any)["conditions"] = nil },
				func(o *unstructured.Unstructured) {
					conditions := o.Object["status"].(map[string]any)["conditions"].([]any)
					conditions[0].(map[string]any)["observedGeneration"] = int64(0)
				},
				func(o *unstructured.Unstructured) {
					conditions := o.Object["status"].(map[string]any)["conditions"].([]any)
					conditions[0].(map[string]any)["status"] = "False"
				},
				func(o *unstructured.Unstructured) {
					conditions := o.Object["status"].(map[string]any)["conditions"].([]any)
					o.Object["status"].(map[string]any)["conditions"] = append(conditions, conditions[0])
				},
				// Valid ignored fresh fields exercise misses without authorizing stale data.
				func(o *unstructured.Unstructured) { o.SetResourceVersion("43") },
				func(o *unstructured.Unstructured) {
					o.SetManagedFields([]metav1.ManagedFieldsEntry{{Manager: "fresh"}})
				},
			} {
				// Independent byte/raw warmup before each fresh drift.
				for i := 0; i < 4; i++ {
					compareCRDCheckCopy(t, fixture, fixture.live, fixture.live.GetUID())
				}
				changed := fixture.live.DeepCopy()
				mutate(changed)
				compareCRDCheckCopy(t, fixture, changed, fixture.live.GetUID())
				compareCRDCheckCopy(t, fixture, fixture.live, "wrong-original")
			}
			target, err := fixture.target.contract.compileTemplate(fixture.target.key, false)
			if err != nil {
				t.Fatal(err)
			}
			target.crdSpec = append(append([]byte(nil), target.crdSpec...), ' ')
			fixture.target = target
			compareCRDCheckCopy(t, fixture, fixture.live, fixture.live.GetUID())
			if fixture.production.CheckCRD(fixture.live, fixture.live.GetUID(), target) != ErrCRD {
				t.Fatal("changed target was accepted")
			}
		})
	}
}

func TestCRDCheckCopyOwnsMetadataStatusAndGenericResults(t *testing.T) {
	for _, fixture := range crdCheckCopyFixtures(t) {
		t.Run(fixture.name, func(t *testing.T) {
			template := fixture.production
			live := fixture.live.DeepCopy()
			// The borrowed Spec MUST come from actual conversion, never signed defaults.
			crdCopySchema(live)["description"] = "actual-only"
			crdCopySchema(live)["default"] = map[string]any{"proof": "actual"}
			live.SetManagedFields([]metav1.ManagedFieldsEntry{{Manager: "owned", FieldsV1: &metav1.FieldsV1{Raw: []byte("{}")}}})
			template.decoded.clear()
			first, err := template.decodeObservedCRDForCheck(live)
			if err != nil {
				t.Fatal(err)
			}
			memo := template.decoded.object.(*crdv1.CustomResourceDefinition)
			if first.(*crdv1.CustomResourceDefinition).Spec.Versions[0].Schema == memo.Spec.Versions[0].Schema {
				t.Fatal("miss returned a borrowed Spec")
			}
			if memo.Spec.Versions[0].Schema.OpenAPIV3Schema.Description != "actual-only" {
				t.Fatal("memo was seeded from desired Spec")
			}
			missBefore, _ := json.Marshal(memo)
			miss := first.(*crdv1.CustomResourceDefinition)
			miss.Spec.Versions[0].Schema.OpenAPIV3Schema.Description = "foreign"
			miss.Spec.Versions[0].Schema.OpenAPIV3Schema.Default.Raw[0] = '['
			miss.ManagedFields[0].FieldsV1.Raw[0] = '['
			miss.Status.StoredVersions[0] = "foreign"
			missAfter, _ := json.Marshal(memo)
			if !bytes.Equal(missBefore, missAfter) {
				t.Fatal("miss result aliased private memo")
			}
			var borrowed *crdv1.CustomResourceDefinition
			for i := 0; i < 5; i++ {
				before, _ := json.Marshal(memo)
				result, err := template.decodeObservedCRDForCheck(live)
				if err != nil {
					t.Fatal(err)
				}
				private := result.(*crdv1.CustomResourceDefinition)
				borrowed = private
				if private == memo || private.Spec.Versions[0].Schema != memo.Spec.Versions[0].Schema {
					t.Fatal("private hit did not borrow only actual Spec")
				}
				private.Annotations["foreign"] = "mutated"
				private.Labels["foreign"] = "mutated"
				private.ManagedFields[0].FieldsV1.Raw[0] = '['
				private.Status.StoredVersions[0] = "foreign"
				private.Status.AcceptedNames.Kind = "Foreign"
				if len(private.Status.AcceptedNames.ShortNames) > 0 {
					private.Status.AcceptedNames.ShortNames[0] = "foreign"
				}
				private.Status.Conditions[0].Message = "foreign"
				generic, err := template.decodeObserved(live)
				if err != nil {
					t.Fatal(err)
				}
				owned := generic.(*crdv1.CustomResourceDefinition)
				if owned.Spec.Versions[0].Schema == memo.Spec.Versions[0].Schema {
					t.Fatal("generic hit borrowed Spec")
				}
				owned.Spec.Versions[0].Schema.OpenAPIV3Schema.Description = "foreign"
				owned.Spec.Versions[0].Schema.OpenAPIV3Schema.Default.Raw[0] = '['
				nested := owned.Spec.Versions[0].Schema.OpenAPIV3Schema.Properties["spec"]
				nested.Description = "foreign"
				owned.Spec.Versions[0].Schema.OpenAPIV3Schema.Properties["spec"] = nested
				owned.Spec.Versions[0].Name = "foreign"
				after, _ := json.Marshal(memo)
				if !bytes.Equal(before, after) {
					t.Fatal("returned metadata/status/generic Spec mutated memo")
				}
			}
			// Explicitly keep one input/memo through byte-hit and eligible raw-hit paths.
			for i := 0; i < 5; i++ {
				if _, err := template.decodeObservedCRDForCheck(live); err != nil {
					t.Fatal(err)
				}
			}
			_, eligible := cloneObservedJSON(live.Object)
			if eligible && template.decoded.raw == nil {
				t.Fatal("eligible control never reached raw-hit branch")
			}
			if !eligible && template.decoded.raw != nil {
				t.Fatal("ineligible graph was captured")
			}
			template.decoded.clear()
			replacement := live.DeepCopy()
			crdCopySchema(replacement)["description"] = "new-actual"
			if _, err := template.decodeObservedCRDForCheck(replacement); err != nil {
				t.Fatal(err)
			}
			if borrowed.Spec.Versions[0].Schema.OpenAPIV3Schema.Description != "actual-only" {
				t.Fatal("borrowed Spec changed after clear/replacement")
			}
		})
	}
}

func TestCRDCheckCopyConcurrentLifetimeAndRefusal(t *testing.T) {
	fixture := crdCheckCopyFixtures(t)[0]
	template, live := fixture.production, fixture.live
	original, _ := json.Marshal(template.expected)
	var workers sync.WaitGroup
	for worker := 0; worker < 3; worker++ {
		workers.Add(1)
		go func(worker int) {
			defer workers.Done()
			for i := 0; i < 20; i++ {
				switch worker {
				case 0:
					object, err := template.decodeObservedCRDForCheck(live)
					if err != nil {
						t.Error(err)
						return
					}
					borrowed := object.(*crdv1.CustomResourceDefinition)
					want := borrowed.Spec.DeepCopy()
					if template.MatchLive(live, live.GetUID()) != nil || template.CheckCRD(live, live.GetUID(), fixture.target) != nil || !reflect.DeepEqual(want, &borrowed.Spec) {
						t.Error("concurrent private check changed Spec")
						return
					}
				case 1:
					object, err := template.decodeObserved(live)
					if err != nil {
						t.Error(err)
						return
					}
					owned := object.(*crdv1.CustomResourceDefinition)
					owned.Spec.Versions[0].Schema.OpenAPIV3Schema.Description = "foreign"
					owned.Spec.Versions[0].Name = "foreign"
				case 2:
					template.decoded.clear()
					changed := live.DeepCopy()
					changed.SetResourceVersion(strconv.Itoa(50 + i))
					if template.MatchLive(changed, live.GetUID()) != nil {
						t.Error("fresh replacement refused")
						return
					}
					changed.Object["unknown"] = true
					if template.MatchLive(changed, live.GetUID()) != ErrDrift {
						t.Error("refusal reused prior verdict")
						return
					}
				}
			}
		}(worker)
	}
	workers.Wait()
	after, _ := json.Marshal(template.expected)
	if !bytes.Equal(original, after) || template.CheckCRD(live, live.GetUID(), fixture.target) != nil {
		t.Fatal("concurrent owning result escaped into private state")
	}
}

func TestCRDCheckCopyPreservesUnsupportedAndSizeRefusals(t *testing.T) {
	fixture := crdCheckCopyFixtures(t)[0]
	for _, value := range []any{make(chan int), strings.Repeat("x", maxObjectBytes+1)} {
		for i := 0; i < 4; i++ {
			compareCRDCheckCopy(t, fixture, fixture.live, fixture.live.GetUID())
		}
		changed := fixture.live.DeepCopy()
		changed.Object["unknown"] = value
		got, gotErr := fixture.production.decodeObservedCRDForCheck(changed)
		want, wantErr := fixture.baseline.frozenCRDDecodeObservedMode(changed, false)
		if gotErr != ErrInvalid || gotErr != wantErr || !reflect.DeepEqual(got, want) || fixture.production.decoded.object != nil || fixture.production.decoded.raw != nil || fixture.production.decoded.body != nil {
			t.Fatal("private conversion changed size/unsupported refusal or retained memo")
		}
	}
}

type crdCopyMarshaler struct {
	callback func()
	mode     int
}

func (m crdCopyMarshaler) MarshalJSON() ([]byte, error) {
	m.callback()
	if m.mode == 1 {
		return nil, errors.New("synthetic refusal")
	}
	if m.mode == 2 {
		panic("synthetic panic")
	}
	return []byte(`"same-value"`), nil
}

func TestCRDCheckCopyPreservesCallbacksErrorsAndPanicOrdering(t *testing.T) {
	fixture := crdCheckCopyFixtures(t)[0]
	done := make(chan bool, 1)
	go func() {
		okay := true
		for mode := 0; mode < 3; mode++ {
			counts := [2]int{}
			errors := [2]error{}
			panics := [2]bool{}
			for index, template := range []*Template{fixture.baseline, fixture.production} {
				for i := 0; i < 4; i++ {
					if index == 0 {
						template.frozenCRDMatchLive(fixture.live, fixture.live.GetUID())
					} else {
						template.MatchLive(fixture.live, fixture.live.GetUID())
					}
				}
				changed := fixture.live.DeepCopy()
				annotations := changed.Object["metadata"].(map[string]any)["annotations"].(map[string]any)
				annotations["custom"] = crdCopyMarshaler{func() { counts[index]++; template.decoded.clear() }, mode}
				func() {
					defer func() { panics[index] = recover() != nil }()
					if index == 0 {
						errors[index] = template.frozenCRDMatchLive(changed, fixture.live.GetUID())
					} else {
						errors[index] = template.MatchLive(changed, fixture.live.GetUID())
					}
				}()
			}
			if counts[0] != 1 || counts[1] != 1 || errors[0] != errors[1] || panics[0] != panics[1] || panics[0] != (mode == 2) {
				okay = false
			}
		}
		done <- okay
	}()
	select {
	case okay := <-done:
		if !okay {
			t.Fatal("custom callback/error/panic behavior changed")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("custom callback reentered a locked memo")
	}
}

func FuzzCRDCheckCopyWholeOperations(f *testing.F) {
	fixtures := crdCheckCopyFixtures(f)
	for index := range fixtures {
		f.Add(byte(index), byte(0), []byte(`{}`))
	}
	for mode := byte(0); mode < 10; mode++ {
		for _, value := range []string{`null`, `{}`, `{"type":"object","properties":{"spec":{"type":"object"}}}`, `0`, `["v1alpha1"]`} {
			f.Add(byte(0), mode, []byte(value))
		}
	}
	f.Fuzz(func(t *testing.T, fixtureSelector, selector byte, body []byte) {
		if len(body) > 8192 {
			return
		}
		var value any
		if json.Unmarshal(body, &value) != nil {
			return
		}
		fixture := fixtures[int(fixtureSelector)%len(fixtures)]
		fixture.production.decoded.clear()
		fixture.baseline.decoded.clear()
		for i := 0; i < 4; i++ {
			compareCRDCheckCopy(t, fixture, fixture.live, fixture.live.GetUID())
		}
		changed := fixture.live.DeepCopy()
		switch selector % 10 {
		case 0: // Unmodified success control.
		case 1:
			crdCopySchema(changed)["unknownNestedSchema"] = value
		case 2:
			changed.Object["spec"].(map[string]any)["versions"].([]any)[0].(map[string]any)["schema"].(map[string]any)["openAPIV3Schema"] = value
		case 3:
			changed.Object["status"].(map[string]any)["observedGeneration"] = value
		case 4:
			changed.Object["spec"].(map[string]any)["conversion"] = value
		case 5:
			changed.Object["metadata"].(map[string]any)["annotations"].(map[string]any)["unknown"] = value
		case 6:
			delete(changed.Object["spec"].(map[string]any), "conversion")
		case 7:
			spec := changed.Object["spec"].(map[string]any)
			spec["Scope"] = spec["scope"]
			delete(spec, "scope")
		case 8:
			changed.Object["status"].(map[string]any)["storedVersions"] = value
		case 9:
			changed.SetUID("foreign")
		}
		compareCRDCheckCopy(t, fixture, changed, fixture.live.GetUID())
	})
}

// Paired COMPLETE operations with separately compiled memos. Both stable and
// every-call revision churn are measured, in forward and reverse order. No
// network/native latency or whole lifecycle claim follows from these fixtures.
func BenchmarkCRDCheckCopyWholeOperations(b *testing.B) {
	benchmarkCRDCheckCopyWholeOperations(b, false)
}
func BenchmarkCRDCheckCopyWholeOperationsReverse(b *testing.B) {
	benchmarkCRDCheckCopyWholeOperations(b, true)
}
func benchmarkCRDCheckCopyWholeOperations(b *testing.B, reverse bool) {
	for _, fixture := range crdCheckCopyFixtures(b) {
		b.Run(fixture.name, func(b *testing.B) {
			for _, operation := range []string{"MatchLive", "CheckCRD"} {
				b.Run(operation, func(b *testing.B) {
					for _, churn := range []bool{false, true} {
						mode := "Stable"
						if churn {
							mode = "Churn"
						}
						b.Run(mode, func(b *testing.B) {
							for _, baseline := range []bool{!reverse, reverse} {
								name := "Production"
								if baseline {
									name = "FrozenOwning"
								}
								b.Run(name, func(b *testing.B) {
									template, err := fixture.production.contract.compileTemplate(fixture.production.key, false)
									if err != nil {
										b.Fatal(err)
									}
									inputs := [2]*unstructured.Unstructured{fixture.live.DeepCopy(), fixture.live.DeepCopy()}
									if churn {
										inputs[1].SetResourceVersion("43")
									}
									check := func(input *unstructured.Unstructured) error {
										if baseline {
											if operation == "MatchLive" {
												return template.frozenCRDMatchLive(input, input.GetUID())
											}
											return template.frozenCRDCheck(input, input.GetUID(), fixture.target)
										}
										if operation == "MatchLive" {
											return template.MatchLive(input, input.GetUID())
										}
										return template.CheckCRD(input, input.GetUID(), fixture.target)
									}
									for i := 0; i < 4; i++ {
										if err := check(inputs[0]); err != nil {
											b.Fatal(err)
										}
									}
									b.ReportAllocs()
									b.ResetTimer()
									for i := 0; i < b.N; i++ {
										if err := check(inputs[i%2]); err != nil {
											b.Fatal(err)
										}
									}
								})
							}
						})
					}
				})
			}
		})
	}
}
