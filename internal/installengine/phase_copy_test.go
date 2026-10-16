// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installobserve"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

func phaseCopyJSON(t testing.TB, value any) []byte {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// Observe through the real sealed HTTP reader; never fabricate its private
// state. The time is fixed across both calculations, not across independent
// observations. This is a local calculation proof, not native cluster evidence.
func phaseCopyObservation(t *testing.T, warm [2]bool) (*installobserve.Observation, [2]admissionControllerState, time.Time) {
	t.Helper()
	plan := fixturePlan(t)
	v, ns, lists := readyControllerFixture(t, plan)
	pods := lists["Pod"].(*corev1.PodList).DeepCopy()
	d := admissionPauseFamilies(t, v, lists, warm)
	now := time.Now().UTC().Truncate(time.Microsecond)
	leases := &coordinationv1.LeaseList{}
	for i := range pods.Items {
		leases.Items = append(leases.Items, phaseLeaderFixture(&pods.Items[i], i, now))
	}
	lists["Lease"] = leases
	states, o, err := admissionClassifyObservationTest(t, v, ns, lists, d, plan, "")
	if err != nil {
		t.Fatal(err)
	}
	return o, states, now
}

func TestPhaseCopyBaselineEquivalence(t *testing.T) {
	for _, warm := range [][2]bool{{}, {true, false}, {false, true}, {true, true}} {
		t.Run(fmt.Sprint(warm), func(t *testing.T) {
			o, states, now := phaseCopyObservation(t, warm)
			for _, scenario := range []string{"valid", "nil", "unsealed", "zero-time", "wrong-family", "missing-leader", "late-leader"} {
				t.Run(scenario, func(t *testing.T) {
					input, families, at := o, states, now
					switch scenario {
					case "nil":
						input = nil
					case "unsealed":
						input = &installobserve.Observation{}
					case "zero-time":
						at = time.Time{}
					case "wrong-family":
						families[0].Name = "foreign"
					case "missing-leader":
						families[0].Executing = true
						families[0].Pods = nil
					case "late-leader":
						at = now.Add(time.Hour)
					}
					want, wantErr := phaseCopyLegacyBaseline(input, families, at)
					got, gotErr := capturePhaseBaseline(input, families, at)
					if wantErr != gotErr || !bytes.Equal(phaseCopyJSON(t, want), phaseCopyJSON(t, got)) {
						t.Fatal("baseline result/error differs from frozen calculation")
					}
					if scenario == "valid" && gotErr != nil {
						t.Fatal("positive control refused")
					}
					if scenario != "valid" && scenario != "late-leader" && gotErr == nil {
						t.Fatal("negative control accepted")
					}
				})
			}
		})
	}
}

// These deliberately malformed caller-owned pairs exercise the completeness
// boundary directly. The sealed reader refuses malformed HTTP collections
// earlier; this test does not pretend those reach accountPhaseWithAccounts.
func TestPhaseCopyProjectionAndCompleteness(t *testing.T) {
	o, _, _ := phaseCopyObservation(t, [2]bool{})
	sealed := phaseCopyJSON(t, []any{o.Snapshot(), o.Runtime()})
	if phaseCollections(nil) != nil || phaseCollectionsFromSnapshots(nil, o.Runtime()) != nil || phaseCollectionsFromSnapshots(o.Snapshot(), nil) != nil {
		t.Fatal("nil-pair projection changed")
	}
	for _, scenario := range []string{"valid", "nil-pods", "nil-jobs", "nil-deployments", "nil-endpoints", "rv", "continue", "remaining", "zero-remaining"} {
		t.Run(scenario, func(t *testing.T) {
			s, r := o.Snapshot(), o.Runtime()
			switch scenario {
			case "nil-pods":
				s.Pods = nil
			case "nil-jobs":
				s.Jobs = nil
			case "nil-deployments":
				r.Deployments = nil
			case "nil-endpoints":
				r.EndpointSlices = nil
			case "rv":
				r.Deployments.ResourceVersion = ""
			case "continue":
				s.Pods.Continue = "next"
			case "remaining", "zero-remaining":
				n := int64(1)
				if scenario == "zero-remaining" {
					n = 0
				}
				r.EndpointSlices.RemainingItemCount = &n
			}
			before := phaseCopyJSON(t, []any{s, r})
			if completeStoppedLists(s, r) != (scenario == "valid" || scenario == "zero-remaining") {
				t.Fatal("completeness boundary changed")
			}
			phaseCopyCompareCollections(t, phaseCopyLegacySnapshotCollections(s, r), phaseCollectionsFromSnapshots(s, r))
			if !bytes.Equal(before, phaseCopyJSON(t, []any{s, r})) {
				t.Fatal("completeness or projection mutated owned pair")
			}
		})
	}
	for _, count := range []int{0, 1, 8} {
		t.Run(fmt.Sprintf("populated-%d", count), func(t *testing.T) {
			s, r := o.Snapshot(), o.Runtime()
			// Seed through the independent literal mapping, so an omitted or
			// miswired optimized collection cannot disappear from the oracle.
			for _, collection := range phaseCopyLegacySnapshotCollections(s, r) {
				phaseCopyPopulate(t, collection, count)
			}
			want := phaseCopyLegacySnapshotCollections(s, r)
			got := phaseCollectionsFromSnapshots(s, r)
			phaseCopyCompareCollections(t, want, got)
			if len(got) != 19 {
				t.Fatal("not all nineteen ordered families projected")
			}
			before := phaseCopyJSON(t, []any{s, r})
			for _, collection := range got {
				beforeCollection := phaseCopyJSON(t, collection.list)
				items, err := meta.ExtractList(collection.list)
				if err != nil {
					t.Fatal(err)
				}
				for _, item := range items {
					phaseCopyMutate(reflect.ValueOf(item))
				}
				if count > 0 && bytes.Equal(beforeCollection, phaseCopyJSON(t, collection.list)) {
					t.Fatalf("%s mutation control did not exercise owned-pair alias", collection.kind)
				}
			}
			if count > 0 && bytes.Equal(before, phaseCopyJSON(t, []any{s, r})) {
				t.Fatal("mutation control did not exercise owned-pair alias")
			}
			// Projection intentionally shares the caller-owned pair, but not
			// the sealed observation used to obtain that pair.
			phaseCopyCompareCollections(t, phaseCopyLegacyCollections(o), phaseCollections(o))
			if !bytes.Equal(sealed, phaseCopyJSON(t, []any{o.Snapshot(), o.Runtime()})) {
				t.Fatal("owned-pair mutation escaped into sealed observation")
			}
		})
	}
}

func phaseCopyCompareCollections(t testing.TB, want, got []phaseCollection) {
	t.Helper()
	if (want == nil) != (got == nil) || len(want) != len(got) {
		t.Fatal("collection nilness/count changed")
	}
	for i := range want {
		if want[i].version != got[i].version || want[i].kind != got[i].kind || reflect.TypeOf(want[i].list) != reflect.TypeOf(got[i].list) || !reflect.DeepEqual(want[i].list, got[i].list) || !bytes.Equal(phaseCopyJSON(t, want[i].list), phaseCopyJSON(t, got[i].list)) {
			t.Fatalf("collection %d order/type/encoding changed", i)
		}
	}
}

// Populate concrete typed lists with nested metadata/spec/status. Unknown
// per-kind fields are ignored by JSON decoding, exactly as with typed reads.
func phaseCopyPopulate(t testing.TB, collection phaseCollection, count int) {
	t.Helper()
	listType := reflect.TypeOf(collection.list).Elem()
	field, ok := listType.FieldByName("Items")
	if !ok {
		t.Fatal("typed list lacks Items")
	}
	items := make([]runtime.Object, 0, count)
	for i := range count {
		item := reflect.New(field.Type.Elem()).Interface().(runtime.Object)
		body := fmt.Sprintf(`{"metadata":{"name":"sample-%d","namespace":"sample","uid":"sample-%d","resourceVersion":"91","labels":{"sample":"original"},"annotations":{"sample":"original"},"ownerReferences":[{"apiVersion":"v1","kind":"Pod","name":"parent","uid":"parent-uid","controller":true}],"managedFields":[{"manager":"sample","operation":"Update","apiVersion":"v1","fieldsType":"FieldsV1","fieldsV1":{"f:spec":{}}}],"finalizers":["sample"]},"spec":{"containers":[{"name":"sample","image":"original","env":[{"name":"SAMPLE","value":"original"}]}],"template":{"metadata":{"labels":{"sample":"original"}},"spec":{"containers":[{"name":"sample","image":"original"}]}},"holderIdentity":"original","storageClassName":"original"},"status":{"conditions":[{"type":"Ready","status":"True","reason":"Original","message":"original"}]} }`, i, i)
		if err := json.Unmarshal([]byte(body), item); err != nil {
			t.Fatal(err)
		}
		items = append(items, item)
	}
	if err := meta.SetList(collection.list, items); err != nil {
		t.Fatal(err)
	}
}

// Mutate all reachable settable mutable fields, including nested template
// containers, owner pointers, labels, managed FieldsV1 bytes and status slices.
func phaseCopyMutate(value reflect.Value) {
	if !value.IsValid() {
		return
	}
	switch value.Kind() {
	case reflect.Interface, reflect.Pointer:
		if !value.IsNil() {
			phaseCopyMutate(value.Elem())
		}
	case reflect.Struct:
		for i := range value.NumField() {
			if value.Field(i).CanSet() {
				phaseCopyMutate(value.Field(i))
			}
		}
	case reflect.Slice, reflect.Array:
		for i := range value.Len() {
			phaseCopyMutate(value.Index(i))
		}
	case reflect.Map:
		for _, key := range value.MapKeys() {
			if value.Type().Elem().Kind() == reflect.String {
				v := reflect.New(value.Type().Elem()).Elem()
				v.SetString("mutated")
				value.SetMapIndex(key, v)
			}
		}
	case reflect.String:
		if value.CanSet() {
			value.SetString("mutated")
		}
	case reflect.Uint8:
		// Preserve JSON punctuation in FieldsV1.Raw while changing its
		// mutable bytes, so post-mutation encoding remains a useful oracle.
		if value.CanSet() && (value.Uint() >= 'a' && value.Uint() <= 'z' || value.Uint() >= 'A' && value.Uint() <= 'Z') {
			value.SetUint('x')
		}
	case reflect.Bool:
		if value.CanSet() {
			value.SetBool(!value.Bool())
		}
	}
}

func TestPhaseCopyAccountEquivalence(t *testing.T) {
	for _, recipe := range []string{"cold-v2", "cold-v3", "warm-v2", "warm-v3"} {
		t.Run(recipe, func(t *testing.T) {
			v3 := strings.HasSuffix(recipe, "v3")
			factory := fixturePhaseFactory(t)
			if v3 {
				factory = fixtureV3PhaseFactory(t)
			}
			if strings.HasPrefix(recipe, "warm") {
				factory = fixtureWarmPhaseFactory(t)
				if v3 {
					factory = fixtureWarmPhaseFactory(t, func(h *fixturePhaseTest) {
						instrumentFreshFixtureRecipeV3(t, h.f.wire.ledger)
						h.extra = append(h.extra, &unstructured.Unstructured{Object: map[string]any{"apiVersion": "v1", "kind": "ServiceAccount", "metadata": map[string]any{"name": "default", "namespace": h.f.actor.request.Snapshot.Anchor().Namespace, "uid": "c0000000-0000-4000-8000-000000000001", "resourceVersion": "91"}, "automountServiceAccountToken": false}})
					})
				}
			}
			for _, state := range []string{"planned", "original"} {
				t.Run(state, func(t *testing.T) {
					h := factory(t)
					f := h.f.wire.ledger
					worlds, err := f.readOriginalWorlds(false)
					if err != nil || worlds.Phase == nil {
						t.Fatal("sealed floor unavailable", err)
					}
					floor := *worlds.Phase
					if strings.HasPrefix(recipe, "warm") && len(floor.Leaders) != 2 {
						t.Fatal("warm-account controls require both original leader chains")
					}
					now := time.Now().UTC().Truncate(time.Microsecond)
					if state == "original" {
						acknowledgeAllRecipeFixtures(t, f)
						for slot := range f.document.Entries {
							h.f.objects[slot] = fixtureResultExample(t, f, slot, fixtureStableResult, now.Truncate(time.Second).Add(-20*time.Second))
						}
					}
					a, request := h.f.actor.admission, h.f.actor.request
					o, err := a.prerequisites.observe(t.Context(), request)
					if err != nil {
						t.Fatal(err)
					}
					var accounts *phaseServiceAccounts
					if v3 {
						accounts, err = a.collectPhaseServiceAccounts(t.Context(), request)
						if err != nil {
							t.Fatal(err)
						}
					}
					before := phaseCopyJSON(t, []any{floor, o.Snapshot(), o.Runtime(), f.document, phaseCopyAccountSource(accounts)})
					requests := [3]int{h.lists, h.gets, h.publicGets}
					cases := []string{"valid", "nil", "unsealed", "journal-bytes", "journal-rv", "floor-version", "floor-row", "wrong-accounts", "fixture-replacement"}
					if len(floor.Leaders) > 0 {
						cases = append(cases, "leader-uid", "leader-floor")
					}
					for _, scenario := range cases {
						t.Run(scenario, func(t *testing.T) {
							input, basis, accountInput := o, floor, accounts
							ledger := &fixtureLedger{document: f.document}
							switch scenario {
							case "nil":
								input = nil
							case "unsealed":
								input = &installobserve.Observation{}
							case "journal-bytes":
								ledger.document.Journal = json.RawMessage(`{}`)
							case "journal-rv":
								ledger.document.JournalResourceVersion = "foreign"
							case "floor-version":
								basis.Version = "foreign"
							case "floor-row":
								basis.Rows = append([]fixtureWorldRow(nil), floor.Rows...)
								basis.Rows[0].SHA256 = "foreign"
							case "wrong-accounts":
								if v3 {
									accountInput = nil
								} else {
									accountInput = &phaseServiceAccounts{}
								}
							case "fixture-replacement":
								ledger.document.Entries = append([]fixtureEntry(nil), f.document.Entries...)
								ledger.document.Entries[0].State = fixtureOriginal
								ledger.document.Entries[0].OriginalUID = "10000000-0000-4000-8000-000000000099"
							case "leader-uid", "leader-floor":
								basis.Leaders = append([]fixturePhaseLeader(nil), floor.Leaders...)
								if scenario == "leader-uid" {
									basis.Leaders[0].PodUID = "10000000-0000-4000-8000-000000000099"
								} else {
									basis.Leaders[0].Row.ResourceVersion = "999999"
								}
							}
							oldTrace, newTrace := &admissionTrace{}, &admissionTrace{}
							want, wantFixtures, wantErr := ledger.phaseCopyLegacyAccount(context.WithValue(t.Context(), admissionTraceKey{}, oldTrace), input, basis, now, accountInput)
							got, gotFixtures, gotErr := ledger.accountPhaseWithAccounts(context.WithValue(t.Context(), admissionTraceKey{}, newTrace), input, basis, now, accountInput)
							if wantErr != gotErr || oldTrace.phase.Load() != newTrace.phase.Load() || !bytes.Equal(phaseCopyJSON(t, []any{want, wantFixtures}), phaseCopyJSON(t, []any{got, gotFixtures})) {
								t.Fatal("account result/error/refusal stage differs from frozen calculation")
							}
							if (scenario == "valid") != (gotErr == nil) {
								t.Fatal("positive/negative control failed", gotErr)
							}
							if scenario == "valid" {
								for _, fixture := range gotFixtures {
									if fixture != nil {
										phaseCopyMutate(reflect.ValueOf(fixture))
									}
								}
							}
						})
					}
					phaseCopyConcurrentAccounts(t, f, o, floor, now, accounts)
					if !bytes.Equal(before, phaseCopyJSON(t, []any{floor, o.Snapshot(), o.Runtime(), f.document, phaseCopyAccountSource(accounts)})) {
						t.Fatal("accounting/output mutation escaped into source or floor")
					}
					phaseCopyAccountAllocations(t, f, o, floor, now, accounts)
					if requests != [3]int{h.lists, h.gets, h.publicGets} {
						t.Fatal("local calculation unexpectedly issued remote requests")
					}
				})
			}
		})
	}
}

func TestPhaseCopyBaselineAllocationShapes(t *testing.T) {
	for _, shape := range []string{"workload-empty", "ordinary", "bounded-populated"} {
		t.Run(shape, func(t *testing.T) {
			plan := fixturePlan(t)
			v, ns, lists := readyControllerFixture(t, plan)
			d := admissionPauseFamilies(t, v, lists, [2]bool{})
			if shape == "workload-empty" {
				for _, list := range lists {
					if err := meta.SetList(list, []runtime.Object{}); err != nil {
						t.Fatal(err)
					}
				}
			}
			if shape == "bounded-populated" {
				leases := &coordinationv1.LeaseList{}
				for i := range 64 {
					leases.Items = append(leases.Items, coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{
						Name: fmt.Sprintf("tail-%d", i), Namespace: ns.Name,
						UID: types.UID(fmt.Sprintf("10000000-0000-4000-8000-%012d", i+100)), ResourceVersion: "91",
						Annotations: map[string]string{"local-test": "cold-tail"},
					}})
				}
				lists["Lease"] = leases
			}
			_, o, classifyErr := admissionClassifyObservationTest(t, v, ns, lists, d, plan, "")
			if o == nil || shape != "workload-empty" && classifyErr != nil {
				t.Fatal("sealed observation unavailable", classifyErr)
			}
			// Empty workload lists do not establish controller readiness or
			// zero baseline rows: the reader still observes Secret metadata.
			// These names exercise ONLY the local baseline calculation on a
			// sealed read, not admission or mutation permission.
			states := [2]admissionControllerState{{Name: controllerFamilies[0]}, {Name: controllerFamilies[1]}}
			now := time.Now().UTC().Truncate(time.Microsecond)
			want, err := phaseCopyLegacyBaseline(o, states, now)
			if err != nil {
				t.Fatal("old baseline control refused", err)
			}
			if shape == "workload-empty" {
				if len(want.Rows) == 0 {
					t.Fatal("workload-empty control lost retained Secret metadata")
				}
				for _, row := range want.Rows {
					if row.Key.Kind != "Secret" {
						t.Fatal("workload-empty control contains a non-Secret row")
					}
				}
			}
			got, err := capturePhaseBaseline(o, states, now)
			if err != nil || !bytes.Equal(phaseCopyJSON(t, want), phaseCopyJSON(t, got)) {
				t.Fatal("baseline encoding differs", err)
			}
			var sink fixturePhaseBaseline
			var oldAllocations float64
			for _, old := range []bool{true, false} {
				calculate := func() error {
					var err error
					if old {
						sink, err = phaseCopyLegacyBaseline(o, states, now)
					} else {
						sink, err = capturePhaseBaseline(o, states, now)
					}
					return err
				}
				allocations := testing.AllocsPerRun(20, func() {
					if err := calculate(); err != nil {
						t.Fatal(err)
					}
				})
				if old {
					oldAllocations = allocations
				} else if allocations >= oldAllocations {
					t.Fatal("baseline allocation reduction absent")
				}
				result := testing.Benchmark(func(b *testing.B) {
					b.ReportAllocs()
					for range b.N {
						if err := calculate(); err != nil {
							b.Fatal(err)
						}
					}
				})
				t.Logf("complete local %s baseline old=%t allocations/run=%.0f %s %s rows=%d", shape, old, allocations, result.String(), result.MemString(), len(sink.Rows))
			}
		})
	}
}

func phaseCopyAccountSource(accounts *phaseServiceAccounts) any {
	if accounts == nil || accounts.observation == nil {
		return nil
	}
	whole := make(map[string]*unstructured.Unstructured, len(accounts.whole))
	for key, object := range accounts.whole {
		whole[fixtureWorldOrder(key)] = object
	}
	return []any{accounts.observation.Accounts(), whole}
}

func phaseCopyConcurrentAccounts(t *testing.T, f *fixtureLedger, o *installobserve.Observation, floor fixturePhaseBaseline, now time.Time, accounts *phaseServiceAccounts) {
	t.Helper()
	want, fixtures, err := f.phaseCopyLegacyAccount(t.Context(), o, floor, now, accounts)
	if err != nil {
		t.Fatal(err)
	}
	encoded := phaseCopyJSON(t, []any{want, fixtures})
	var workers sync.WaitGroup
	for range 4 {
		workers.Go(func() {
			for range 3 {
				got, fixtures, err := f.accountPhaseWithAccounts(t.Context(), o, floor, now, accounts)
				if err != nil || !bytes.Equal(encoded, phaseCopyJSON(t, []any{got, fixtures})) {
					t.Error("concurrent independent account calculation changed")
					return
				}
				for _, fixture := range fixtures {
					if fixture != nil {
						phaseCopyMutate(reflect.ValueOf(fixture))
					}
				}
			}
		})
	}
	workers.Wait()
}

func phaseCopyAccountAllocations(t *testing.T, f *fixtureLedger, o *installobserve.Observation, floor fixturePhaseBaseline, now time.Time, accounts *phaseServiceAccounts) {
	t.Helper()
	var sink fixturePhaseBaseline
	for _, old := range []bool{true, false} {
		calculate := func() error {
			var err error
			if old {
				sink, _, err = f.phaseCopyLegacyAccount(t.Context(), o, floor, now, accounts)
			} else {
				sink, _, err = f.accountPhaseWithAccounts(t.Context(), o, floor, now, accounts)
			}
			return err
		}
		allocs := testing.AllocsPerRun(20, func() {
			if err := calculate(); err != nil {
				t.Fatal(err)
			}
		})
		if old {
			before := allocs
			after := testing.AllocsPerRun(20, func() {
				var err error
				sink, _, err = f.accountPhaseWithAccounts(t.Context(), o, floor, now, accounts)
				if err != nil {
					t.Fatal(err)
				}
			})
			if after >= before {
				t.Fatal("redundant-copy removal did not reduce calculation allocations")
			}
			t.Logf("complete local account allocations old=%.0f new=%.0f", before, after)
		}
		result := testing.Benchmark(func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				if err := calculate(); err != nil {
					b.Fatal(err)
				}
			}
		})
		t.Logf("complete local account old=%t %s %s rows=%d", old, result.String(), result.MemString(), len(sink.Rows))
	}
}

func TestPhaseCopyConcurrentIsolationAndBaselineAllocations(t *testing.T) {
	o, states, now := phaseCopyObservation(t, [2]bool{true, true})
	want, err := capturePhaseBaseline(o, states, now)
	if err != nil {
		t.Fatal(err)
	}
	source := phaseCopyJSON(t, []any{o.Snapshot(), o.Runtime(), states})
	encoded := phaseCopyJSON(t, want)
	var workers sync.WaitGroup
	for range 4 {
		workers.Go(func() {
			for range 5 {
				got, err := capturePhaseBaseline(o, states, now)
				if err != nil || !bytes.Equal(encoded, phaseCopyJSON(t, got)) {
					t.Error("concurrent independent calculation changed")
					return
				}
				s, r := o.Snapshot(), o.Runtime()
				for _, collection := range phaseCollectionsFromSnapshots(s, r) {
					items, err := meta.ExtractList(collection.list)
					if err != nil {
						t.Error(err)
						return
					}
					for _, item := range items {
						phaseCopyMutate(reflect.ValueOf(item))
					}
				}
			}
		})
	}
	workers.Wait()
	if !bytes.Equal(source, phaseCopyJSON(t, []any{o.Snapshot(), o.Runtime(), states})) {
		t.Fatal("independent copies mutated sealed source or controller families")
	}
	var sink fixturePhaseBaseline
	measure := func(old bool) float64 {
		return testing.AllocsPerRun(20, func() {
			var err error
			if old {
				sink, err = phaseCopyLegacyBaseline(o, states, now)
			} else {
				sink, err = capturePhaseBaseline(o, states, now)
			}
			if err != nil {
				t.Fatal(err)
			}
		})
	}
	old, current := measure(true), measure(false)
	if current >= old || !bytes.Equal(encoded, phaseCopyJSON(t, sink)) {
		t.Fatal("baseline allocation reduction/equivalence failed")
	}
	t.Logf("complete local warm baseline allocations old=%.0f new=%.0f", old, current)
}
