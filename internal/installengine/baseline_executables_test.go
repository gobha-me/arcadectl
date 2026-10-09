// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installobserve"
	"github.com/gobha-me/arcadectl/internal/installstate"
	authv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestBaselineExecutableSelectionMatchesReservedNamesAndBothAccountAliases(t *testing.T) {
	for _, c := range baselineExecutableCollections {
		for _, scenario := range []string{"ordinary", "reserved-name", "reserved-account", "reserved-alias", "both-aliases", "malformed-account", "wrong-key"} {
			t.Run(c.kind+"/"+scenario, func(t *testing.T) {
				key := installstate.Key{APIVersion: c.gv, Kind: c.kind, Namespace: "baseline-selection", Name: "foreign-producer"}
				if scenario == "reserved-name" {
					key.Name = "arcadectl-api"
				}
				object := &unstructured.Unstructured{Object: map[string]any{"apiVersion": key.APIVersion, "kind": key.Kind, "metadata": map[string]any{"name": key.Name, "namespace": key.Namespace}}}
				path := []string{"spec"}
				if c.kind == "CronJob" {
					path = []string{"spec", "jobTemplate", "spec", "template", "spec"}
				} else if c.kind != "Pod" {
					path = []string{"spec", "template", "spec"}
				}
				var account any = "default"
				if scenario == "reserved-account" {
					account = "arcadectl-destroy-controller"
				} else if scenario == "malformed-account" {
					account = true
				}
				if err := unstructured.SetNestedField(object.Object, account, append(path, "serviceAccountName")...); err != nil {
					t.Fatal(err)
				}
				if scenario == "reserved-alias" || scenario == "both-aliases" {
					if err := unstructured.SetNestedField(object.Object, "arcadectl-destroy-admin", append(path, "serviceAccount")...); err != nil {
						t.Fatal(err)
					}
				}
				if scenario == "both-aliases" {
					_ = unstructured.SetNestedField(object.Object, "arcadectl-controller", append(path, "serviceAccountName")...)
				}
				if scenario == "wrong-key" {
					object.SetNamespace("foreign")
				}
				selected, err := baselineGuardedExecutable(key, object)
				invalid := scenario == "malformed-account" || scenario == "wrong-key"
				if (err != nil) != invalid || !invalid && selected != (scenario != "ordinary") {
					t.Fatal("reserved executable selection omitted or promoted an object", selected, err)
				}
			})
		}
	}
}

// Real frozen HTTPS/SSAR/complete observer composition over explicit synthetic
// replies. This certifies only read-only dependency closure, not native VAP
// serving, original producer ownership, world coldness or effect authority.
func TestBaselineExecutableReadsCloseNativeCollectionsAndWholeGets(t *testing.T) {
	for _, scenario := range []string{"healthy", "empty", "native-omitted-types", "null-types", "empty-types", "partial-types", "unknown-list-field", "unknown-list-metadata", "invalid-continue", "invalid-remaining", "list-denied", "get-denied", "discovery-missing", "last-list-unavailable", "raw-null-changed", "get-replaced", "journal-change", "late-new-pod", "parent-receipt-closing-change"} {
		t.Run(scenario, func(t *testing.T) {
			f := seedBaselineAccessWitness(t)
			var pendingParent *unstructured.Unstructured
			var parentReceiptName string
			var parentPath string
			if scenario == "parent-receipt-closing-change" {
				d := f.snapshot.Document()
				key := deploymentKey(d.Namespace, "arcadectl-controller")
				template, err := f.engine.contracts[d.TargetPackage].Template(key, false)
				if err != nil {
					t.Fatal("unit signed pending parent unavailable")
				}
				d.Pending = &installstate.Pending{Action: installstate.Create, Key: key, CreateNonce: strings.Repeat("c", 32), AfterSHA256: template.Hash()}
				d.Revision++
				seedBaselineAccessUnitDocument(t, f, d)
				pendingParent = testBaselineParentLive(t, template, d.Pending.CreateNonce)
				pendingParent.SetUID("original-pending-parent")
				pendingParent.SetResourceVersion("18")
				if f.engine.prepareCreateReceipt(d) != nil || f.engine.saveCreateUID(d, pendingParent.GetUID()) != nil {
					t.Fatal("synthetic protected CREATE acknowledgement unavailable")
				}
				parentReceiptName = "create-" + d.Pending.CreateNonce + ".json"
				parentPath, _, err = baselineExecutableRead(key, "get")
				if err != nil {
					t.Fatal("unit original parent read route unavailable")
				}
			}
			ns, err := f.access.client.CoreV1().Namespaces().Get(t.Context(), f.plan.Namespace(), metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			objects := map[installstate.Key]*unstructured.Unstructured{}
			for _, c := range baselineExecutableCollections {
				key := installstate.Key{APIVersion: c.gv, Kind: c.kind, Namespace: ns.Name, Name: "foreign-" + c.plural}
				object := &unstructured.Unstructured{Object: map[string]any{"apiVersion": c.gv, "kind": c.kind, "metadata": map[string]any{"name": key.Name, "namespace": ns.Name, "uid": "observed-" + c.plural, "resourceVersion": "90", "annotations": nil}}}
				if c.kind == "Pod" {
					object.Object["spec"] = map[string]any{"serviceAccountName": "arcadectl-destroy-controller"}
					// A deleting foreign Pod remains read-only dependency evidence.
					_ = unstructured.SetNestedField(object.Object, "2026-10-09T00:00:00Z", "metadata", "deletionTimestamp")
				}
				if scenario != "empty" {
					objects[key] = object
				}
			}
			var mu sync.Mutex
			var listCalls, getCalls, reviewCalls atomic.Int32
			var parentStage atomic.Bool
			var parentReads atomic.Int32
			var newPod bool
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				if r.Header.Get("Authorization") != "Bearer FAKE-READ-ONLY" || r.Header.Get("Impersonate-User") != "" {
					t.Error("dependency read changed original admin identity")
				}
				if r.Method == http.MethodPost && r.URL.Path == "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" {
					reviewCalls.Add(1)
					var review authv1.SelfSubjectAccessReview
					if json.NewDecoder(r.Body).Decode(&review) != nil || review.Spec.ResourceAttributes == nil {
						t.Error("dependency permission unavailable")
						w.WriteHeader(500)
						return
					}
					valid := false
					for _, c := range baselineExecutableCollections {
						a := review.Spec.ResourceAttributes
						name := a.Name
						if a.Verb == "list" {
							name = "baseline-observation"
						}
						_, expected, e := baselineExecutableRead(installstate.Key{APIVersion: c.gv, Kind: c.kind, Namespace: ns.Name, Name: name}, a.Verb)
						if e == nil && reflect.DeepEqual(review.Spec, expected.spec) {
							valid = true
						}
					}
					if !valid {
						t.Error("dependency permission widened to another operation or resource")
					}
					verb := review.Spec.ResourceAttributes.Verb
					review.Status.Allowed = !(scenario == "list-denied" && verb == "list" || scenario == "get-denied" && verb == "get")
					_ = json.NewEncoder(w).Encode(review)
					return
				}
				if r.Method != http.MethodGet {
					t.Error("dependency observation attempted a mutation")
					w.WriteHeader(500)
					return
				}
				if r.URL.Path == "/version" {
					_ = json.NewEncoder(w).Encode(map[string]any{"major": "1", "minor": "35", "gitVersion": "v" + f.plan.Profile().KubernetesVersion})
					return
				}
				if r.URL.Path == "/api/v1/namespaces/"+ns.Name {
					copy := ns.DeepCopy()
					copy.APIVersion, copy.Kind = "v1", "Namespace"
					_ = json.NewEncoder(w).Encode(copy)
					if parentStage.Load() {
						reads := parentReads.Add(1)
						if scenario == "parent-receipt-closing-change" && reads == 3 {
							body, identity, err := f.engine.files.Read(parentReceiptName, 4096)
							if err != nil {
								t.Error("unit protected receipt opening unavailable")
							} else if _, err := f.engine.files.AtomicWrite(parentReceiptName, body, &identity); err != nil {
								t.Error("unit identical-body original receipt replacement unavailable")
							}
						} else if scenario != "parent-receipt-closing-change" && reads == 2 {
							ns.ResourceVersion = "9001" // after the opening original fence
						}
					}
					return
				}
				if pendingParent != nil && r.URL.Path == parentPath {
					getCalls.Add(1)
					_ = json.NewEncoder(w).Encode(pendingParent.Object)
					return
				}
				for _, gv := range []string{"v1", "apps/v1", "batch/v1"} {
					path, _ := discoveryPath(gv)
					if r.URL.Path != path {
						continue
					}
					resources := []metav1.APIResource{}
					for _, c := range baselineExecutableCollections {
						if c.gv == gv && !(scenario == "discovery-missing" && c.kind == "CronJob") {
							resources = append(resources, metav1.APIResource{Name: c.plural, Kind: c.kind, Namespaced: true, Verbs: metav1.Verbs{"get", "list"}})
						}
					}
					_ = json.NewEncoder(w).Encode(metav1.APIResourceList{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "APIResourceList"}, GroupVersion: gv, APIResources: resources})
					return
				}
				for _, c := range baselineExecutableCollections {
					key := installstate.Key{APIVersion: c.gv, Kind: c.kind, Namespace: ns.Name, Name: "foreign-" + c.plural}
					path, _, _ := baselineExecutableRead(key, "list")
					if r.URL.Path == path {
						listCalls.Add(1)
						q := r.URL.Query()
						if q.Get("limit") != "128" || len(q) > 2 || q.Has("timeout") && q.Get("timeout") != "30s" || q.Has("labelSelector") || q.Has("fieldSelector") || q.Has("resourceVersion") {
							t.Error("dependency read filtered, cached or omitted bounded pagination")
						}
						if scenario == "last-list-unavailable" && c.kind == "CronJob" {
							w.WriteHeader(403)
							return
						}
						items := []any{}
						if object := objects[key]; object != nil {
							item := object.DeepCopy()
							if c.kind == "Pod" {
								switch scenario {
								case "native-omitted-types":
									delete(item.Object, "apiVersion")
									delete(item.Object, "kind")
								case "null-types":
									item.Object["apiVersion"], item.Object["kind"] = nil, nil
								case "empty-types":
									item.Object["apiVersion"], item.Object["kind"] = "", ""
								case "partial-types":
									delete(item.Object, "kind")
								}
							}
							items = append(items, item.Object)
						}
						if newPod && c.kind == "Pod" {
							added := objects[key].DeepCopy()
							added.SetName("late-pod")
							added.SetUID("late-pod-uid")
							items = append(items, added.Object)
							objects[installstate.Key{APIVersion: "v1", Kind: "Pod", Namespace: ns.Name, Name: "late-pod"}] = added
						}
						if pendingParent != nil && c.kind == "Deployment" {
							items = append(items, pendingParent.DeepCopy().Object)
						}
						metadata := map[string]any{"resourceVersion": "100"}
						page := map[string]any{"apiVersion": c.gv, "kind": c.kind + "List", "metadata": metadata, "items": items}
						if c.kind == "CronJob" {
							switch scenario {
							case "unknown-list-field":
								page["private"] = true
							case "unknown-list-metadata":
								metadata["private"] = true
							case "invalid-continue":
								metadata["continue"] = 17
							case "invalid-remaining":
								metadata["remainingItemCount"] = "5"
							}
						}
						_ = json.NewEncoder(w).Encode(page)
						if scenario == "journal-change" && c.kind == "CronJob" {
							ns.ResourceVersion = "2"
						}
						return
					}
				}
				for key, object := range objects {
					path, _, _ := baselineExecutableRead(key, "get")
					if r.URL.Path == path {
						getCalls.Add(1)
						copy := object.DeepCopy()
						if key.Kind == "Pod" {
							if scenario == "get-replaced" {
								copy.SetUID("foreign-replacement")
							} else if scenario == "raw-null-changed" {
								unstructured.RemoveNestedField(copy.Object, "metadata", "annotations")
							}
						}
						_ = json.NewEncoder(w).Encode(copy.Object)
						return
					}
				}
				t.Error("dependency read escaped eight fixed families")
				w.WriteHeader(404)
			}))
			t.Cleanup(server.Close)
			config := serverConfig(server)
			config.BearerToken = "FAKE-READ-ONLY"
			access, err := NewDirectHTTPAccess(config)
			if err != nil {
				t.Fatal(err)
			}
			baseline := f.engine.baselinePlan()
			store, err := installstate.NewWithBaseline(access.Namespaces(), baseline, f.plan)
			if err != nil {
				t.Fatal(err)
			}
			engine, err := NewWithBaselineAccess(access, store, f.engine.files, baseline, f.plan)
			if err != nil {
				t.Fatal(err)
			}
			snapshot, err := store.Load(t.Context(), f.snapshot.Anchor())
			if err != nil {
				t.Fatal(err)
			}
			reader, err := NewClusterSecurityBaseline(engine, access)
			if err != nil {
				t.Fatal(err)
			}
			before, err := reader.collectExecutables(t.Context(), snapshot)
			positive := scenario == "healthy" || scenario == "empty" || scenario == "native-omitted-types" || scenario == "late-new-pod" || scenario == "parent-receipt-closing-change"
			if !positive {
				if err == nil || before != nil || strings.Contains(err.Error(), "FAKE") {
					t.Fatal("incomplete, unpermitted or changing dependency evidence escaped", err)
				}
				return
			}
			count := 8
			if scenario == "empty" {
				count = 0
			} else if pendingParent != nil {
				count++
			}
			if err != nil || before == nil || len(before.whole) != count || listCalls.Load() != 8 || getCalls.Load() != int32(count) || reviewCalls.Load() != int32(8+count) {
				t.Fatal("complete eight-family native reads were omitted", err, listCalls.Load(), getCalls.Load(), reviewCalls.Load())
			}
			guardedCount := 1
			if pendingParent != nil {
				guardedCount++
			}
			if count > 0 && len(before.guarded) != guardedCount {
				t.Fatal("foreign deleting reserved Pod was omitted or treated as owned")
			}
			if baselineDeniedObservation(snapshot, before) != nil {
				t.Fatal("complete original executable observation cannot bind denied catalog")
			}
			if count > 0 {
				incomplete := *before
				incomplete.whole = maps.Clone(before.whole)
				for key := range incomplete.whole {
					delete(incomplete.whole, key)
					break
				}
				if baselineDeniedObservation(snapshot, &incomplete) == nil {
					t.Fatal("denied catalog silently omitted complete LIST membership")
				}
				incomplete = *before
				incomplete.guarded = maps.Clone(before.guarded)
				for key := range incomplete.guarded {
					delete(incomplete.guarded, key)
					break
				}
				if baselineDeniedObservation(snapshot, &incomplete) == nil {
					t.Fatal("denied catalog silently omitted guarded generated identity")
				}
				changed := *before
				changed.whole = maps.Clone(before.whole)
				for key, object := range changed.whole {
					copy := object.DeepCopy()
					copy.SetResourceVersion("12345")
					changed.whole[key] = copy
					break
				}
				if baselineDeniedObservation(snapshot, &changed) == nil {
					t.Fatal("denied catalog accepted whole GET drift from its sealed LIST")
				}
			}
			mu.Lock()
			newPod = scenario == "late-new-pod"
			mu.Unlock()
			after, err := reader.collectExecutables(t.Context(), snapshot)
			if err != nil || sameBaselineExecutables(before, after) != (scenario != "late-new-pod") {
				t.Fatal("paired complete reads accepted a late producer or refused unchanged evidence", err)
			}
			closed, err := store.Load(t.Context(), snapshot.Anchor())
			if err != nil || !bytes.Equal(closed.Bytes(), snapshot.Bytes()) || closed.ResourceVersion() != snapshot.ResourceVersion() || engine.baseline.runtimeGuard != nil {
				t.Fatal("observation adopted inventory, changed journal or granted effects")
			}
			if scenario == "parent-receipt-closing-change" {
				parentStage.Store(true)
				if parents, err := reader.originalParents(t.Context(), snapshot, before); err == nil || parents != nil || parentReads.Load() < 4 {
					t.Fatal("parent wrapper accepted a protected receipt replaced during its closing reads")
				}
			}
			if scenario == "healthy" {
				guard := &baselineParentRefusingRuntimeGuard{}
				engine.baseline.runtimeGuard = guard // refusal instrumentation ONLY
				defer func() { engine.baseline.runtimeGuard = nil }()
				parents, err := reader.originalParents(t.Context(), snapshot, before)
				t.Cleanup(func() { releaseBaselineParents(parents) })
				if err != nil || len(parents) != 0 || guard.calls.Load() != 0 {
					t.Fatal("parent wrapper adopted foreign dependencies or recursively required runtime authority")
				}
				incomplete := *before
				incomplete.observation = &installobserve.ExecutablesObservation{}
				if parents, err := reader.originalParents(t.Context(), snapshot, &incomplete); err == nil || parents != nil {
					t.Fatal("parent wrapper accepted missing sealed observation identity")
				}
				mu.Lock()
				ns.ResourceVersion = "9000"
				mu.Unlock()
				fresh, err := store.Load(t.Context(), snapshot.Anchor())
				if err != nil {
					t.Fatal("unit fresh observation unavailable")
				}
				if parents, err := reader.originalParents(t.Context(), fresh, before); err == nil || parents != nil {
					t.Fatal("parent wrapper accepted an observation from a different original revision")
				}
				if parents, err := reader.originalParents(t.Context(), snapshot, before); err == nil || parents != nil {
					t.Fatal("parent wrapper accepted stale supplied original snapshot")
				}
				mu.Lock()
				ns.ResourceVersion = snapshot.ResourceVersion()
				mu.Unlock()
				parentStage.Store(true)
				if parents, err := reader.originalParents(t.Context(), snapshot, before); err == nil || parents != nil || parentReads.Load() < 3 || guard.calls.Load() != 0 {
					t.Fatal("parent wrapper omitted its closing original fence or recursed into runtime authority")
				}
			}
		})
	}
}

type baselineParentRefusingRuntimeGuard struct{ calls atomic.Int32 }

func (g *baselineParentRefusingRuntimeGuard) Verify(context.Context, *installstate.Snapshot) error {
	g.calls.Add(1)
	return ErrSecurityBaseline
}
