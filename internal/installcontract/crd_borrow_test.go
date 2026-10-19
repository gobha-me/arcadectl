// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installcontract

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"strings"
	"sync"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// TEST-ONLY: eligibility is a bounded optimization, never an acceptance limit.
// Unsupported/large graphs take the unchanged production deep-copy path,
// including its refusal/panic behavior and no custom-marshaler invocation.
func shallowCRDSpecCandidate(o *unstructured.Unstructured) []byte {
	if o == nil {
		return nil
	}
	value, exists, err := unstructured.NestedFieldNoCopy(o.Object, "spec")
	spec, ok := value.(map[string]any)
	if err != nil || !exists || !ok || spec == nil {
		return nil
	}
	if !sameObservedJSON(spec, spec) {
		return normalizedCRDSpec(o)
	}
	local := make(map[string]any, len(spec)+1)
	for key, value := range spec {
		local[key] = value
	}
	if _, exists := local["conversion"]; !exists {
		local["conversion"] = map[string]any{"strategy": "None"}
	}
	if value, exists := local["preserveUnknownFields"]; exists && value == false {
		delete(local, "preserveUnknownFields")
	}
	body, err := json.Marshal(local)
	if err != nil {
		return nil
	}
	return body
}

// Frozen independent oracle: exact previous complete normalization, including
// the nil-spec guard (the older previousCRDSpecBytes test helper predates it).
func deepCRDSpecOracle(o *unstructured.Unstructured) []byte {
	if o == nil {
		return nil
	}
	spec, exists, err := unstructured.NestedMap(o.Object, "spec")
	if err != nil || !exists || spec == nil {
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

func captureNormalization(fn func(*unstructured.Unstructured) []byte, o *unstructured.Unstructured) (body []byte, panicked bool) {
	defer func() {
		if recover() != nil {
			panicked = true
		}
	}()
	return fn(o), false
}

func assertCRDNormalizationOracle(t testing.TB, o *unstructured.Unstructured) {
	t.Helper()
	want, wantPanic := captureNormalization(deepCRDSpecOracle, o)
	got, gotPanic := captureNormalization(shallowCRDSpecCandidate, o)
	if wantPanic != gotPanic || (want == nil) != (got == nil) || !bytes.Equal(want, got) {
		t.Fatal("shallow candidate changed complete normalization disposition")
	}
}

type unsupportedCRDMap map[string]any
type unsupportedCRDString string
type crdCallbackCanary struct{ calls *int }

func (c crdCallbackCanary) MarshalJSON() ([]byte, error) {
	(*c.calls)++
	return []byte(`{"unsafe":"callback"}`), nil
}

func TestCRDShallowBorrowPreservesFallbackAndRawShape(t *testing.T) {
	assertCRDNormalizationOracle(t, nil)
	for _, spec := range []any{
		nil, "wrong-type", map[string]any(nil), map[string]any{},
		map[string]any{"conversion": nil},
		map[string]any{"conversion": map[string]any{"strategy": "None"}, "preserveUnknownFields": false},
		map[string]any{"conversion": map[string]any{"strategy": "Webhook"}, "preserveUnknownFields": true},
		map[string]any{"preserveUnknownFields": "false", "unsigned": map[string]any{"unknown": []any{nil, true}}},
		map[string]any{"nilMap": map[string]any(nil), "nilSlice": []any(nil), "emptyMap": map[string]any{}, "emptySlice": []any{}},
		map[string]any{"integer": int64(1), "float": float64(1), "negativeZero": math.Copysign(0, -1)},
		map[string]any{"number": json.Number("1.0")}, map[string]any{"number": json.Number("invalid")},
		map[string]any{"nan": math.NaN()}, map[string]any{"infinity": math.Inf(1)},
		map[string]any{"invalidUTF8": string([]byte{0xff}), string([]byte{0xff}): "key"},
		map[string]any{"unsupported": int(1)}, map[string]any{"unsupported": int32(1)},
		map[string]any{"unsupported": uint64(1)}, map[string]any{"unsupported": json.RawMessage(`null`)},
		map[string]any{"unsupported": []byte("public")},
		map[string]any{"unsupported": unsupportedCRDMap{"nested": true}},
		map[string]any{"unsupported": unsupportedCRDString("public")},
		map[string]any{"overTextBudget": strings.Repeat("x", observedJSONStrings+1)},
		map[string]any{"overNodeBudget": make([]any, observedJSONNodes+1)},
	} {
		o := &unstructured.Unstructured{Object: map[string]any{"spec": spec}}
		assertCRDNormalizationOracle(t, o)
	}
	calls := 0
	for _, value := range []any{crdCallbackCanary{&calls}, &crdCallbackCanary{&calls}} {
		spec := map[string]any{"callback": value}
		if sameObservedJSON(spec, spec) {
			t.Fatal("custom callback became eligible for borrowing")
		}
		assertCRDNormalizationOracle(t, &unstructured.Unstructured{Object: map[string]any{"spec": spec}})
	}
	if calls != 0 {
		t.Fatal("candidate invoked a previously refused custom marshaler")
	}
	deep := map[string]any{"leaf": true}
	for range observedJSONDepth + 1 {
		deep = map[string]any{"nested": deep}
	}
	if sameObservedJSON(deep, deep) {
		t.Fatal("over-depth graph escaped bounded eligibility")
	}
	assertCRDNormalizationOracle(t, &unstructured.Unstructured{Object: map[string]any{"spec": deep}})
	shared := map[string]any{"minimum": int64(1), "unknown": []any{"public", nil}}
	live := &unstructured.Unstructured{Object: map[string]any{"spec": map[string]any{"a": shared, "b": shared, "preserveUnknownFields": false}}}
	before := live.DeepCopy()
	first := shallowCRDSpecCandidate(live)
	assertCRDNormalizationOracle(t, live)
	if !reflect.DeepEqual(before, live) {
		t.Fatal("shallow normalization mutated the caller graph")
	}
	shared["minimum"] = int64(2)
	if bytes.Equal(first, shallowCRDSpecCandidate(live)) {
		t.Fatal("earlier normalization hid fresh nested drift")
	}
	cycle := map[string]any{}
	cycle["cycle"] = cycle
	if sameObservedJSON(cycle, cycle) {
		t.Fatal("cyclic graph escaped bounded eligibility")
	}
	// Deliberately do not invoke either deep-copy fallback on a cycle: the old
	// recursive copier has no cycle contract and may exhaust the stack.
}

func TestCRDShallowBorrowConcurrentImmutableInput(t *testing.T) {
	c := testContract(t, false)
	for key, resource := range c.resources {
		if key.Kind != "CustomResourceDefinition" {
			continue
		}
		live := resource.Object.DeepCopy()
		before := live.DeepCopy()
		want := deepCRDSpecOracle(live)
		var group sync.WaitGroup
		for range 3 {
			group.Add(1)
			go func() {
				defer group.Done()
				for range 4 {
					if !bytes.Equal(shallowCRDSpecCandidate(live), want) {
						t.Error("immutable concurrent normalization changed")
						return
					}
				}
			}()
		}
		group.Wait()
		if !reflect.DeepEqual(before, live) {
			t.Fatal("concurrent readers mutated input")
		}
	}
}

var crdBorrowIDs = map[string]string{
	"gameservers.arcade.gobha.me": "GameServer", "gamebackups.arcade.gobha.me": "GameBackup",
	"gamerestores.arcade.gobha.me": "GameRestore", "gamedestroys.arcade.gobha.me": "GameDestroy",
	"arcadeoperations.arcade.gobha.me": "ArcadeOperation",
}

func TestCRDShallowBorrowMatchesAllSignedSchemas(t *testing.T) {
	type eligibility struct {
		Generation      string `json:"generation"`
		ID              string `json:"id"`
		Eligible        bool   `json:"eligible"`
		NormalizedBytes int    `json:"normalizedBytes"`
	}
	rows := []eligibility{}
	for _, legacy := range []bool{false, true} {
		generation := "current"
		if legacy {
			generation = "legacy"
		}
		c := testContract(t, legacy)
		for key, resource := range c.resources {
			if key.Kind != "CustomResourceDefinition" {
				continue
			}
			id, ok := crdBorrowIDs[key.Name]
			if !ok {
				t.Fatal("unmapped signed CRD")
			}
			live := resource.Object.DeepCopy()
			before := live.DeepCopy()
			assertCRDNormalizationOracle(t, live)
			spec, _, _ := unstructured.NestedFieldNoCopy(live.Object, "spec")
			rows = append(rows, eligibility{generation, id, sameObservedJSON(spec, spec), len(deepCRDSpecOracle(live))})
			if !reflect.DeepEqual(before, live) {
				t.Fatal("signed graph mutated")
			}
		}
	}
	if len(rows) != 10 {
		t.Fatal("signed CRD inventory incomplete")
	}
	body, err := json.Marshal(struct {
		Schema string        `json:"schema"`
		Rows   []eligibility `json:"rows"`
	}{"arcadectl-crd-shallow-eligibility-v1", rows})
	if err != nil {
		t.Fatal("fixed eligibility report unavailable")
	}
	fmt.Println(string(body))
}

func FuzzCRDShallowBorrowMatchesDeepCopy(f *testing.F) {
	for _, body := range []string{`{}`, `{"spec":null}`, `{"spec":{}}`, `{"spec":{"preserveUnknownFields":false}}`, `{"spec":{"conversion":{"strategy":"None"},"unknown":[0,1,null]}}`} {
		f.Add([]byte(body))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > 64*1024 {
			t.Skip()
		}
		var object map[string]any
		if json.Unmarshal(body, &object) != nil {
			return
		}
		assertCRDNormalizationOracle(t, &unstructured.Unstructured{Object: object})
	})
}

func BenchmarkCRDSpecWholeNormalization(b *testing.B) {
	for _, legacy := range []bool{false, true} {
		generation := "Current"
		if legacy {
			generation = "Legacy"
		}
		c := testContract(b, legacy)
		for key, resource := range c.resources {
			if key.Kind != "CustomResourceDefinition" {
				continue
			}
			id, ok := crdBorrowIDs[key.Name]
			if !ok {
				b.Fatal("unmapped benchmark CRD")
			}
			live := resource.Object.DeepCopy()
			assertCRDNormalizationOracle(b, live)
			want := deepCRDSpecOracle(live)
			b.Run(generation+id, func(b *testing.B) {
				for _, implementation := range []string{"OracleDeepCopy", "CandidateBorrow"} {
					b.Run(implementation, func(b *testing.B) {
						b.ReportAllocs()
						b.SetBytes(int64(len(want)))
						b.ResetTimer()
						for range b.N {
							var got []byte
							if implementation == "OracleDeepCopy" {
								got = deepCRDSpecOracle(live)
							} else {
								got = shallowCRDSpecCandidate(live)
							}
							if !bytes.Equal(got, want) {
								b.Fatal("whole normalization changed")
							}
						}
					})
				}
			})
		}
	}
}
