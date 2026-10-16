// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installcontract

import (
	"bytes"
	"encoding/json"
	"math"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestObservedJSONOwnedExactWireOperand(t *testing.T) {
	values := []any{nil, false, true, int64(-4), float64(1.25), math.Copysign(0, -1), "escaped\n\"\xff", map[string]any(nil), map[string]any{}, []any(nil), []any{}, map[string]any{"nested": []any{int64(1), "x", map[string]any{"z": false}}}}
	for _, input := range values {
		owned, eligible := cloneObservedJSON(input)
		if !eligible || !sameObservedJSON(input, owned) {
			t.Fatal("ordinary complete JSON graph ineligible or different")
		}
		before, err := json.Marshal(input)
		after, cloneErr := json.Marshal(owned)
		if err != nil || cloneErr != nil || !bytes.Equal(before, after) {
			t.Fatal("owned graph changed complete wire bytes")
		}
	}
	for _, pair := range [][2]any{{int64(1), float64(1)}, {float64(0), math.Copysign(0, -1)}, {[]any(nil), []any{}}, {map[string]any(nil), map[string]any{}}, {nil, []any(nil)}, {map[string]any{"a": nil}, map[string]any{}}, {map[string]any{"status": int64(1)}, map[string]any{"status": int64(2)}}} {
		if sameObservedJSON(pair[0], pair[1]) {
			t.Fatal("type, signed zero, nil/empty, presence or status difference hidden")
		}
	}
	// Keys and short value substrings must not pin arbitrary caller backing data.
	backing := strings.Repeat("x", 2*1024*1024)
	key, value := backing[:11], backing[31:48]
	input := map[string]any{key: []any{value, map[string]any{"mutable": "original"}}}
	owned, ok := cloneObservedJSON(input)
	if !ok {
		t.Fatal("small substrings ineligible")
	}
	copy := owned.(map[string]any)
	for copiedKey := range copy {
		if unsafe.StringData(copiedKey) == unsafe.StringData(key) {
			t.Fatal("map key retained caller backing storage")
		}
	}
	list := copy[key].([]any)
	if unsafe.StringData(list[0].(string)) == unsafe.StringData(value) {
		t.Fatal("value retained caller backing storage")
	}
	list[1].(map[string]any)["mutable"] = "copy-only"
	if input[key].([]any)[1].(map[string]any)["mutable"] != "original" {
		t.Fatal("owned operand exposed caller containers")
	}
}

func observedNestedJSON(levels int) any {
	var value any = nil
	for i := 0; i < levels; i++ {
		value = map[string]any{"n": value}
	}
	return value
}

func TestObservedJSONEligibilityLimitsDoNotDefineValidity(t *testing.T) {
	for _, test := range []struct {
		name     string
		input    any
		eligible bool
	}{
		{"string-exact", strings.Repeat("s", observedJSONStrings), true},
		{"string-over", strings.Repeat("s", observedJSONStrings+1), false},
		{"nodes-exact", make([]any, observedJSONNodes-1), true},
		{"nodes-over", make([]any, observedJSONNodes), false},
		{"depth-exact", observedNestedJSON(observedJSONDepth), true},
		{"depth-over", observedNestedJSON(observedJSONDepth + 1), false},
		{"unsupported-valid-integer", int(3), false},
		{"unsupported-valid-number", json.Number("3"), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			owned, ok := cloneObservedJSON(test.input)
			if ok != test.eligible || !ok && owned != nil {
				t.Fatal("eligibility bound or partial operand escaped")
			}
			if ok && !sameObservedJSON(test.input, owned) {
				t.Fatal("exact-bound operand could not compare")
			}
			if _, err := json.Marshal(test.input); err != nil {
				t.Fatal("eligibility-only fixture unexpectedly invalid JSON")
			}
		})
	}
	cycle := map[string]any{}
	cycle["cycle"] = cycle
	if owned, ok := cloneObservedJSON(cycle); ok || owned != nil {
		t.Fatal("cycle escaped bounded traversal")
	}
}

func TestObservedMemoPromotionChurnAndRefusalClearing(t *testing.T) {
	template := mustTemplate(t, testContract(t, false), "Namespace", "", false)
	live := liveObject(t, template)
	for i := 0; i < 5; i++ {
		if _, err := template.decodeObserved(live); err != nil {
			t.Fatal(err)
		}
		want := uint8(0)
		if i == 1 {
			want = 1
		}
		if i >= 2 {
			want = 3
		}
		if template.decoded.rawCaptureHits != want || (template.decoded.raw != nil) != (i >= 2) {
			t.Fatal("unexpected bounded promotion progression")
		}
	}
	for i := 0; i < 12; i++ {
		live.SetResourceVersion(strconv.Itoa(i + 100))
		if _, err := template.decodeObserved(live); err != nil || template.decoded.raw != nil || template.decoded.rawCaptureHits != 0 {
			t.Fatal("changing bytes incurred or retained graph promotion")
		}
	}
	for _, fault := range []func(*unstructured.Unstructured){
		func(o *unstructured.Unstructured) { o.Object["unknown"] = true },
		func(o *unstructured.Unstructured) { o.Object["unsupported"] = make(chan int) },
		func(o *unstructured.Unstructured) {
			o.SetAnnotations(map[string]string{"large": strings.Repeat("x", maxObjectBytes+1)})
		},
		func(o *unstructured.Unstructured) { o.Object["nonfinite"] = math.NaN() },
		func(o *unstructured.Unstructured) {
			cycle := map[string]any{}
			cycle["cycle"] = cycle
			o.Object["cycle"] = cycle
		},
	} {
		for i := 0; i < 3; i++ {
			if _, err := template.decodeObserved(live); err != nil {
				t.Fatal(err)
			}
		}
		if template.decoded.raw == nil {
			t.Fatal("refusal control was not warm")
		}
		changed := live.DeepCopy()
		fault(changed)
		_, wantErr := originalObservedDecode(template, changed)
		got, err := template.decodeObserved(changed)
		if wantErr == nil || err != wantErr || got != nil || template.decoded.raw != nil || template.decoded.body != nil || template.decoded.object != nil || template.decoded.rawCaptureHits != 0 {
			t.Fatal("refusal failed complete memo clearing or changed original error")
		}
	}
	template.decoded.clear()
	if template.decoded.raw != nil || template.decoded.rawCaptureHits != 0 {
		t.Fatal("explicit clear retained pure operand state")
	}
}

func TestObservedMemoIneligibleValidGraphsUseOriginalBytePath(t *testing.T) {
	template := mustTemplate(t, testContract(t, false), "Namespace", "", false)
	for _, scenario := range []string{"strings", "nodes", "depth", "integer", "number"} {
		t.Run(scenario, func(t *testing.T) {
			template.decoded.clear()
			live := liveObject(t, template)
			metadata := live.Object["metadata"].(map[string]any)
			switch scenario {
			case "strings":
				live.SetAnnotations(map[string]string{"long": strings.Repeat("x", observedJSONStrings+1)})
			case "nodes":
				a := map[string]string{}
				for i := 0; i < observedJSONNodes; i++ {
					a["k"+strconv.Itoa(i)] = "v"
				}
				live.SetAnnotations(a)
			case "depth":
				metadata["managedFields"] = []any{map[string]any{"manager": "fixture", "apiVersion": "v1", "operation": "Apply", "fieldsType": "FieldsV1", "fieldsV1": observedNestedJSON(observedJSONDepth + 1)}}
			case "integer":
				metadata["generation"] = int(3)
			case "number":
				metadata["generation"] = json.Number("3")
			}
			if owned, ok := cloneObservedJSON(live.Object); ok || owned != nil {
				t.Fatal("fallback fixture unexpectedly eligible")
			}
			want, err := originalObservedDecode(template, live)
			if err != nil {
				t.Fatal("original valid fallback refused", err)
			}
			for i := 0; i < 8; i++ {
				got, err := template.decodeObserved(live)
				if err != nil || !reflect.DeepEqual(got, want) || template.decoded.raw != nil {
					t.Fatal("retention ineligibility changed complete conversion")
				}
			}
			if template.decoded.rawCaptureHits != 3 {
				t.Fatal("ineligible capture attempt was not bounded")
			}
		})
	}
}

type observedCallbackMarshaler struct {
	callback func()
	value    string
}

func (m observedCallbackMarshaler) MarshalJSON() ([]byte, error) {
	m.callback()
	return json.Marshal(m.value)
}

func TestObservedMemoCustomMarshalerRemainsOutsideMutexAfterPromotion(t *testing.T) {
	template := mustTemplate(t, testContract(t, false), "Deployment", "arcadectl-controller", false)
	live := liveObject(t, template)
	a := live.GetAnnotations()
	a["custom"] = "same-value"
	live.SetAnnotations(a)
	for i := 0; i < 3; i++ {
		if _, err := template.decodeObserved(live); err != nil {
			t.Fatal(err)
		}
	}
	if template.decoded.raw == nil {
		t.Fatal("custom-marshaler test was not promoted")
	}
	want, err := originalObservedDecode(template, live)
	if err != nil {
		t.Fatal(err)
	}
	annotations := live.Object["metadata"].(map[string]any)["annotations"].(map[string]any)
	calls := 0
	annotations["custom"] = observedCallbackMarshaler{func() { calls++; template.decoded.clear() }, "same-value"}
	done := make(chan bool, 1)
	go func() { got, err := template.decodeObserved(live); done <- err == nil && reflect.DeepEqual(got, want) }()
	select {
	case ok := <-done:
		if !ok || calls != 1 || template.decoded.raw != nil {
			t.Fatal("custom marshaler skipped, changed conversion, or became retained operand")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("custom marshaler reentered locked memo")
	}
}

func TestObservedMemoPromotedStandardCannotSeedStrictAdmission(t *testing.T) {
	for _, fixture := range observedDecodeBenchmarkFixtures(t) {
		if !fixture.strict {
			continue
		}
		t.Run(fixture.name, func(t *testing.T) {
			fixture.template.decoded.clear()
			for i := 0; i < 3; i++ {
				if _, err := fixture.template.decodeObservedMode(fixture.object, false); err != nil {
					t.Fatal(err)
				}
			}
			if fixture.template.decoded.raw == nil || fixture.template.decoded.strictAdmission {
				t.Fatal("standard-only operand control not promoted")
			}
			var reference observedByteMemoBaseline
			want, wantErr := reference.decode(fixture.template, fixture.object, true)
			got, err := fixture.template.decodeObservedMode(fixture.object, true)
			if err != wantErr || !reflect.DeepEqual(got, want) || !fixture.template.decoded.strictAdmission || fixture.template.decoded.raw != nil || fixture.template.decoded.rawCaptureHits != 0 {
				t.Fatal("standard graph bypassed fresh strict conversion")
			}
		})
	}
}

func TestObservedMemoPromotedDefensiveResultsAndConcurrentHits(t *testing.T) {
	for _, fixture := range observedDecodeBenchmarkFixtures(t) {
		t.Run(fixture.name, func(t *testing.T) {
			// Conversion-only metadata fixture, not a whole signed-shape match.
			labels := fixture.object.GetLabels()
			if labels == nil {
				labels = map[string]string{}
			}
			labels["defensive-copy-test"] = "original"
			fixture.object.SetLabels(labels)
			_, eligible := cloneObservedJSON(fixture.object.Object)
			fixture.template.decoded.clear()
			var reference observedByteMemoBaseline
			want, err := reference.decode(fixture.template, fixture.object, fixture.strict)
			if err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 3; i++ {
				if _, err := fixture.template.decodeObservedMode(fixture.object, fixture.strict); err != nil {
					t.Fatal(err)
				}
			}
			if (fixture.template.decoded.raw != nil) != eligible {
				t.Fatal("fixture promotion did not match complete-operand eligibility")
			}
			before, _ := json.Marshal(fixture.object.Object)
			privateBefore, _ := json.Marshal(fixture.template.decoded.raw)
			// All calls after promotion use independent input graphs and exercise
			// defensive copies, including mutation of an existing nested map.
			var workers sync.WaitGroup
			for i := 0; i < 8; i++ {
				workers.Go(func() {
					for j := 0; j < 5; j++ {
						got, err := fixture.template.decodeObservedMode(fixture.object.DeepCopy(), fixture.strict)
						if err != nil || !reflect.DeepEqual(got, want) {
							t.Error("promoted result differed from independent byte oracle")
							return
						}
						metadata := got.(metav1.Object)
						labels := metadata.GetLabels()
						if len(labels) == 0 {
							t.Error("fixture lacks existing nested metadata map")
							return
						}
						for key := range labels {
							labels[key] = "changed-return"
							break
						}
						metadata.SetAnnotations(map[string]string{"foreign": "changed-return"})
					}
				})
			}
			workers.Wait()
			got, err := fixture.template.decodeObservedMode(fixture.object.DeepCopy(), fixture.strict)
			after, _ := json.Marshal(fixture.object.Object)
			privateAfter, _ := json.Marshal(fixture.template.decoded.raw)
			if err != nil || !reflect.DeepEqual(got, want) || !bytes.Equal(before, after) || !bytes.Equal(privateBefore, privateAfter) || (fixture.template.decoded.raw != nil) != eligible {
				t.Fatal("promoted return mutation escaped into caller input or private operand")
			}
		})
	}
}

func TestObservedMemoPromotedStandardStrictNegativeClearsAll(t *testing.T) {
	for _, fixture := range observedDecodeBenchmarkFixtures(t) {
		if !fixture.strict {
			continue
		}
		t.Run(fixture.name, func(t *testing.T) {
			fixture.template.decoded.clear()
			input := fixture.object.DeepCopy()
			input.Object["Spec"] = input.Object["spec"]
			delete(input.Object, "spec")
			var reference observedByteMemoBaseline
			if _, err := reference.decode(fixture.template, input, false); err != nil {
				t.Fatal("case-variant control was not accepted by standard decoder")
			}
			for i := 0; i < 4; i++ {
				if _, err := fixture.template.decodeObservedMode(input, false); err != nil {
					t.Fatal(err)
				}
			}
			if fixture.template.decoded.raw == nil || fixture.template.decoded.strictAdmission {
				t.Fatal("case-variant standard operand was not promoted")
			}
			want, wantErr := reference.decode(fixture.template, input, true)
			got, err := fixture.template.decodeObservedMode(input, true)
			m := &fixture.template.decoded
			if wantErr != ErrDrift || err != wantErr || got != nil || want != nil || m.raw != nil || m.body != nil || m.object != nil || m.strictAdmission || m.rawCaptureHits != 0 {
				t.Fatal("promoted standard operand bypassed strict negative or complete clearing")
			}
		})
	}
}

// Source-bound process-wide post-GC net heap observation for current fixtures,
// not a universal cache bound, peak memory or RSS/native performance. Unrelated
// frees may mask growth. Populate original byte/typed memos before promotion.
func TestObservedMemoAggregateRetainedHeapBound(t *testing.T) {
	baseline, _ := fixtureBaselineContract(t)
	contracts := []*Contract{testContract(t, false), testContract(t, true), baseline}
	type entry struct {
		template *Template
		live     *unstructured.Unstructured
		strict   bool
	}
	var entries []entry
	for _, contract := range contracts {
		for _, template := range contract.templates {
			live := liveObject(t, template)
			strict := strings.HasPrefix(template.key.Kind, "ValidatingAdmission")
			if _, err := template.decodeObservedMode(live, strict); err != nil {
				t.Fatal(err)
			}
			entries = append(entries, entry{template, live, strict})
		}
	}
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	eligible := 0
	for _, entry := range entries {
		for i := 0; i < 2; i++ {
			if _, err := entry.template.decodeObservedMode(entry.live, entry.strict); err != nil {
				t.Fatal(err)
			}
		}
		if entry.template.decoded.raw != nil {
			eligible++
		}
	}
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	var retained uint64
	if after.HeapAlloc > before.HeapAlloc {
		retained = after.HeapAlloc - before.HeapAlloc
	}
	if eligible == 0 || retained > 16*1024*1024 {
		t.Fatal("aggregate graph retention unavailable or above16MiB ceiling")
	}
	t.Logf("pure graph promotion: templates=%d eligible=%d observed-extra-heap=%d bytes; not RSS or native latency", len(entries), eligible, retained)
	runtime.KeepAlive(entries)
}
