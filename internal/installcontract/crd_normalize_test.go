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
	got, gotPanic := captureNormalization(normalizedCRDSpecShallow, o)
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
	first := normalizedCRDSpecShallow(live)
	assertCRDNormalizationOracle(t, live)
	if !reflect.DeepEqual(before, live) {
		t.Fatal("shallow normalization mutated the caller graph")
	}
	shared["minimum"] = int64(2)
	if bytes.Equal(first, normalizedCRDSpecShallow(live)) {
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
					if !bytes.Equal(normalizedCRDSpecShallow(live), want) {
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
				for _, implementation := range []string{"OracleDeepCopy", "ProductionShallow"} {
					b.Run(implementation, func(b *testing.B) {
						b.ReportAllocs()
						b.SetBytes(int64(len(want)))
						b.ResetTimer()
						for range b.N {
							var got []byte
							if implementation == "OracleDeepCopy" {
								got = deepCRDSpecOracle(live)
							} else {
								got = normalizedCRDSpecShallow(live)
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

func TestCRDCompiledShallowHintIsNotAuthority(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		c := testContract(t, legacy)
		for key := range c.resources {
			if key.Kind != "CustomResourceDefinition" {
				continue
			}
			production, err := c.compileTemplate(key, false)
			if err != nil {
				t.Fatal(err)
			}
			baseline, err := c.compileTemplate(key, false)
			if err != nil {
				t.Fatal(err)
			}
			// Independently compiled: never copy Template's memo mutex.
			baseline.crdShallow = false
			raw, _, _ := unstructured.NestedFieldNoCopy(production.resource.Object.Object, "spec")
			if production.crdShallow != sameObservedJSON(raw, raw) {
				t.Fatal("compiled hint does not reflect private signed input")
			}
			live := liveObject(t, production)
			if production.MatchLive(live, live.GetUID()) != nil || baseline.MatchLive(live, live.GetUID()) != nil || production.CheckCRD(live, live.GetUID(), baseline) != nil || baseline.CheckCRD(live, live.GetUID(), production) != nil {
				t.Fatal("complete signed live fixture was refused")
			}
			// Even a forced hint cannot bypass fresh eligibility or signed bytes.
			production.crdShallow = true
			for _, value := range []any{true, json.Number("1"), strings.Repeat("x", observedJSONStrings+1), make([]any, observedJSONNodes+1)} {
				changed := live.DeepCopy()
				changed.Object["spec"].(map[string]any)["unknownNested"] = map[string]any{"value": value}
				if production.matchCRDSpec(changed) || baseline.matchCRDSpec(changed) || production.MatchLive(changed, live.GetUID()) == nil || baseline.MatchLive(changed, live.GetUID()) == nil {
					t.Fatal("hint accepted fresh unsigned nested drift")
				}
			}
			foreign := live.DeepCopy()
			foreign.SetUID("foreign-uid")
			if production.MatchLive(foreign, live.GetUID()) == nil || baseline.MatchLive(foreign, live.GetUID()) == nil {
				t.Fatal("hint bypassed original identity")
			}
			stale := live.DeepCopy()
			if err := unstructured.SetNestedField(stale.Object, int64(0), "status", "observedGeneration"); err != nil {
				t.Fatal(err)
			}
			if production.CheckCRD(stale, live.GetUID(), baseline) == nil || baseline.CheckCRD(stale, live.GetUID(), production) == nil {
				t.Fatal("hint bypassed fresh health")
			}
			other, err := c.compileTemplate(key, false)
			if err != nil {
				t.Fatal(err)
			}
			other.crdSpec = append(append([]byte(nil), other.crdSpec...), ' ')
			if production.CheckCRD(live, live.GetUID(), other) == nil {
				t.Fatal("hint bypassed signed target agreement")
			}
			wantBytes := append([]byte(nil), production.crdSpec...)
			wantHint := production.crdShallow
			candidate, err := production.Candidate(strings.Repeat("a", 32))
			if err != nil {
				t.Fatal(err)
			}
			candidate.Object["spec"].(map[string]any)["unsigned"] = true
			if production.crdShallow != wantHint || !bytes.Equal(production.crdSpec, wantBytes) || production.matchCRDSpec(candidate) || !production.matchCRDSpec(live) {
				t.Fatal("candidate mutation escaped private signed state")
			}
		}
	}
}

// Complete fresh MatchLive/CheckCRD operations, including normalization guards,
// strict conversion/memo checks, original identity and health. Setup and warmup
// are outside timing. Each mode owns a separately compiled memo, never a copy.
// Warm stable-input, fixed-oracle-first ordering; not network/native latency.
func BenchmarkCRDWholeMatch(b *testing.B) {
	for _, legacy := range []bool{false, true} {
		generation := "Current"
		if legacy {
			generation = "Legacy"
		}
		c := testContract(b, legacy)
		for key := range c.resources {
			if key.Kind != "CustomResourceDefinition" {
				continue
			}
			id, ok := crdBorrowIDs[key.Name]
			if !ok {
				b.Fatal("unmapped whole-match CRD")
			}
			b.Run(generation+id, func(b *testing.B) {
				for _, operation := range []string{"MatchLive", "CheckCRD"} {
					b.Run(operation, func(b *testing.B) {
						for _, implementation := range []string{"OracleDeepCopy", "Production"} {
							b.Run(implementation, func(b *testing.B) {
								template, err := c.compileTemplate(key, false)
								if err != nil {
									b.Fatal(err)
								}
								if implementation == "OracleDeepCopy" {
									template.crdShallow = false
								}
								target, err := c.compileTemplate(key, false)
								if err != nil {
									b.Fatal(err)
								}
								live := liveObject(b, template)
								if template.MatchLive(live, live.GetUID()) != nil || template.CheckCRD(live, live.GetUID(), target) != nil {
									b.Fatal("whole fixture refused outside timing")
								}
								body, err := json.Marshal(live.Object)
								if err != nil {
									b.Fatal(err)
								}
								b.ReportAllocs()
								b.SetBytes(int64(len(body)))
								b.ResetTimer()
								for range b.N {
									if operation == "MatchLive" {
										err = template.MatchLive(live, live.GetUID())
									} else {
										err = template.CheckCRD(live, live.GetUID(), target)
									}
									if err != nil {
										b.Fatal("whole live comparison changed")
									}
								}
							})
						}
					})
				}
			})
		}
	}
}
