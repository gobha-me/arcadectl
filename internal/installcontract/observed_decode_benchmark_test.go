// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installcontract

import (
	"bytes"
	"encoding/json"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installstate"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	strictjson "sigs.k8s.io/json"
)

// Exact pre-experiment marshal-plus-byte-memo performance baseline from
// 1dc3c19. This deliberately does not use the candidate lookup or its clear
// helper. Correctness continues to use originalObservedDecode and the existing
// independent strict-admission oracle; this is not an uncached decoder baseline.
type observedByteMemoBaseline struct {
	mu              sync.Mutex
	body            []byte
	object          runtime.Object
	strictAdmission bool
}

func (m *observedByteMemoBaseline) decode(t *Template, object *unstructured.Unstructured, strictAdmission bool) (runtime.Object, error) {
	body, err := json.Marshal(object.Object)
	m.mu.Lock()
	defer m.mu.Unlock()
	if err != nil || len(body) > maxObjectBytes {
		m.body, m.object, m.strictAdmission = nil, nil, false
		return nil, ErrInvalid
	}
	if m.object != nil && bytes.Equal(m.body, body) && (!strictAdmission || m.strictAdmission) {
		return m.object.DeepCopyObject(), nil
	}
	m.body, m.object, m.strictAdmission = nil, nil, false
	var decoded runtime.Object
	if strictAdmission {
		switch t.key.APIVersion + "/" + t.key.Kind {
		case "admissionregistration.k8s.io/v1/ValidatingAdmissionPolicy":
			decoded = &admissionv1.ValidatingAdmissionPolicy{}
		case "admissionregistration.k8s.io/v1/ValidatingAdmissionPolicyBinding":
			decoded = &admissionv1.ValidatingAdmissionPolicyBinding{}
		default:
			return nil, ErrInvalid
		}
		strictErrors, decodeErr := strictjson.UnmarshalStrict(body, decoded)
		if decodeErr != nil || len(strictErrors) != 0 {
			return nil, ErrDrift
		}
	} else {
		decoded, err = decodeBody(t.key.APIVersion+"/"+t.key.Kind, body)
	}
	if err != nil {
		return nil, err
	}
	m.body, m.object, m.strictAdmission = body, decoded.DeepCopyObject(), strictAdmission
	return decoded, nil
}

type observedDecodeBenchmarkFixture struct {
	name     string
	template *Template
	object   *unstructured.Unstructured
	strict   bool
}

func observedDecodeBenchmarkFixtures(t testing.TB) []observedDecodeBenchmarkFixture {
	t.Helper()
	c := testContract(t, false)
	baseline, _ := fixtureBaselineContract(t)
	var fixtures []observedDecodeBenchmarkFixture
	for _, selection := range []struct {
		name, kind string
		contract   *Contract
	}{
		{"Namespace", "Namespace", c},
		{"Deployment", "Deployment", c},
		{"CustomResourceDefinition", "CustomResourceDefinition", c},
		{"runtime-policy", "ValidatingAdmissionPolicy", c},
		{"runtime-binding", "ValidatingAdmissionPolicyBinding", c},
		{"baseline-policy", "ValidatingAdmissionPolicy", baseline},
		{"baseline-binding", "ValidatingAdmissionPolicyBinding", baseline},
	} {
		kind, contract := selection.kind, selection.contract
		// Select the largest real signed shape of each kind, with stable ties.
		var keys []installstate.Key
		for key := range contract.resources {
			if key.Kind == kind {
				keys = append(keys, key)
			}
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i].String() < keys[j].String() })
		var selected *Template
		var live *unstructured.Unstructured
		largest := -1
		for _, key := range keys {
			template, err := contract.Template(key, false)
			if err != nil {
				t.Fatal(err)
			}
			object := liveObject(t, template)
			body, err := json.Marshal(object.Object)
			if err != nil {
				t.Fatal(err)
			}
			if len(body) > largest {
				selected, live, largest = template, object, len(body)
			}
		}
		if selected == nil {
			t.Fatal("missing benchmark kind")
		}
		if kind == "Namespace" {
			// Explicit synthetic journal-sized payload; no claim of a valid
			// installation journal or a whole Namespace match from conversion.
			annotations := live.GetAnnotations()
			if annotations == nil {
				annotations = map[string]string{}
			}
			annotations[installstate.Annotation] = strings.Repeat("j", 16*1024)
			live.SetAnnotations(annotations)
		}
		fixtures = append(fixtures, observedDecodeBenchmarkFixture{selection.name, selected, live, strings.HasPrefix(kind, "ValidatingAdmission")})
	}
	return fixtures
}

func TestObservedByteMemoBaselineMatchesProduction(t *testing.T) {
	for _, fixture := range observedDecodeBenchmarkFixtures(t) {
		t.Run(fixture.name, func(t *testing.T) {
			var baseline observedByteMemoBaseline
			for i := 0; i < 12; i++ {
				input := fixture.object.DeepCopy()
				if i%3 == 0 {
					input.SetResourceVersion(strconv.Itoa(i + 100))
				}
				if i == 8 {
					input.Object["unknownField"] = true
				}
				strict := fixture.strict && i%2 == 0
				want, wantErr := baseline.decode(fixture.template, input, strict)
				got, gotErr := fixture.template.decodeObservedMode(input, strict)
				if gotErr != wantErr || !reflect.DeepEqual(got, want) {
					t.Fatal("exact current byte-memo baseline diverged")
				}
			}
		})
	}
}

// Conversion microbenchmarks, not native latency, failed-operand attribution,
// whole-match authority or deadline-cure evidence. Warm inputs are independent
// graphs; churn changes RV at the stated frequency, including every-call misses.
func BenchmarkObservedDecodeCurrentMemo(b *testing.B) {
	benchmarkObservedDecodeCurrentMemo(b, false)
}

func BenchmarkObservedDecodeCurrentMemoReverse(b *testing.B) {
	benchmarkObservedDecodeCurrentMemo(b, true)
}

func benchmarkObservedDecodeCurrentMemo(b *testing.B, reverse bool) {
	for _, fixture := range observedDecodeBenchmarkFixtures(b) {
		b.Run(fixture.name, func(b *testing.B) {
			for _, every := range []int{0, 10, 2, 1} {
				label := "warm"
				if every != 0 {
					label = "churn-every-" + strconv.Itoa(every)
				}
				b.Run(label, func(b *testing.B) {
					for _, useBaseline := range []bool{!reverse, reverse} {
						name := "candidate"
						if useBaseline {
							name = "current-byte-baseline"
						}
						b.Run(name, func(b *testing.B) {
							var baseline observedByteMemoBaseline
							fixture.template.decoded.clear()
							inputs := [2]*unstructured.Unstructured{fixture.object.DeepCopy(), fixture.object.DeepCopy()}
							for i := range inputs {
								inputs[i].SetResourceVersion("42")
							}
							b.ReportAllocs()
							_, eligible := cloneObservedJSON(fixture.object.Object)
							b.ResetTimer()
							for i := 0; i < b.N; i++ {
								input := inputs[i%2]
								if every != 0 {
									// Two independent graphs per stable interval, never a
									// pointer-identity hit or a growing revision string.
									input.SetResourceVersion(strconv.Itoa(42 + (i/every)%2))
								}
								var err error
								if useBaseline {
									_, err = baseline.decode(fixture.template, input, fixture.strict)
								} else {
									_, err = fixture.template.decodeObservedMode(input, fixture.strict)
								}
								if err != nil {
									b.Fatal("benchmark conversion refused")
								}
							}
							b.StopTimer()
							if eligible {
								b.ReportMetric(1, "raw-eligible")
							} else {
								b.ReportMetric(0, "raw-eligible")
							}
						})
					}
				})
			}
		})
	}
}
