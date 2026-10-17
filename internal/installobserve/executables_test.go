// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installobserve

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installstate"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/rest"
	clienttesting "k8s.io/client-go/testing"
	"k8s.io/client-go/util/flowcontrol"
)

func TestExecutablesCompleteBoundedAndCopied(t *testing.T) {
	scenarios := []string{"empty", "all", "pages", "partial", "rv-drift", "cycle", "remaining", "duplicate-name", "duplicate-uid", "cross-kind-uid", "wrong-kind", "wrong-version", "wrong-namespace", "missing-uid", "missing-rv", "unknown", "cancelled", "journal-change"}
	for _, c := range executableCollections(&ExecutableCollections{}) {
		scenarios = append(scenarios, "unavailable-"+c.resource)
	}
	for _, scenario := range scenarios {
		t.Run(scenario, func(t *testing.T) {
			f := newFixture(t)
			kinds := map[schema.GroupVersionResource]string{}
			catalogue := map[string]collection{}
			for _, c := range executableCollections(&ExecutableCollections{}) {
				gv, err := schema.ParseGroupVersion(c.gv)
				if err != nil {
					t.Fatal(err)
				}
				kinds[gv.WithResource(c.resource)] = c.kind + "List"
				catalogue[c.resource] = c
			}
			f.dynamic = dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), kinds)
			f.o.clients.Dynamic = f.dynamic
			before, err := f.o.journal.Load(t.Context(), f.anchor)
			if err != nil {
				t.Fatal(err)
			}
			requests := map[string]int{}
			f.dynamic.PrependReactor("list", "*", func(action clienttesting.Action) (bool, runtime.Object, error) {
				resource := action.GetResource().Resource
				c, ok := catalogue[resource]
				if !ok {
					t.Fatal("executable observation requested another resource")
				}
				requests[resource]++
				opts := action.(clienttesting.ListActionImpl).ListOptions
				if action.GetNamespace() != f.anchor.Namespace || opts.Limit != pageLimit || opts.LabelSelector != "" || opts.FieldSelector != "" || opts.ResourceVersion != "" || opts.ResourceVersionMatch != "" {
					t.Fatal("executable read escaped complete current collection")
				}
				if scenario == "unavailable-"+resource {
					return true, nil, errors.New("private failure")
				}
				list := &unstructured.UnstructuredList{Object: map[string]any{"apiVersion": c.gv, "kind": c.kind + "List", "metadata": map[string]any{"resourceVersion": "100"}}, Items: []unstructured.Unstructured{}}
				item := unstructured.Unstructured{Object: map[string]any{"apiVersion": c.gv, "kind": c.kind, "metadata": map[string]any{"name": "observed-" + resource, "namespace": f.anchor.Namespace, "uid": "uid-" + resource, "resourceVersion": "90", "annotations": nil}}}
				if scenario != "empty" {
					list.Items = append(list.Items, item)
				}
				if resource == "pods" {
					switch scenario {
					case "pages", "partial", "rv-drift":
						if requests[resource] == 1 {
							list.SetContinue("page-two")
							list.SetRemainingItemCount(new(int64(1)))
						} else {
							if opts.Continue != "page-two" {
								t.Fatal("continuation discarded")
							}
							if scenario == "partial" {
								return true, nil, errors.New("private page failure")
							}
							list.Items[0].SetName("second-pod")
							list.Items[0].SetUID("second-uid")
							if scenario == "rv-drift" {
								list.SetResourceVersion("101")
							}
						}
					case "cycle":
						list.Items = nil
						list.SetContinue("same")
					case "remaining":
						list.SetRemainingItemCount(new(int64(1)))
					case "duplicate-name", "duplicate-uid":
						second := item.DeepCopy()
						if scenario == "duplicate-name" {
							second.SetUID("second-uid")
						} else {
							second.SetName("second-pod")
						}
						list.Items = append(list.Items, *second)
					case "wrong-kind":
						list.Items[0].SetKind("Job")
					case "wrong-version":
						list.Items[0].SetAPIVersion("unknown/v1")
					case "wrong-namespace":
						list.Items[0].SetNamespace("foreign")
					case "missing-uid":
						list.Items[0].SetUID("")
					case "missing-rv":
						list.Items[0].SetResourceVersion("")
					case "unknown":
						list.Items[0].Object["private"] = true
					}
				}
				if scenario == "cross-kind-uid" && resource == "jobs" {
					list.Items[0].SetUID("uid-pods")
				}
				if scenario == "journal-change" && resource == "cronjobs" {
					ns, e := f.core.CoreV1().Namespaces().Get(t.Context(), f.anchor.Namespace, metav1.GetOptions{})
					if e != nil {
						t.Fatal(e)
					}
					ns.ResourceVersion = "2"
					if _, e = f.core.CoreV1().Namespaces().Update(t.Context(), ns, metav1.UpdateOptions{}); e != nil {
						t.Fatal(e)
					}
				}
				return true, list, nil
			})
			ctx := t.Context()
			if scenario == "cancelled" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			observation, err := f.o.CollectExecutables(ctx, f.anchor)
			positive := scenario == "empty" || scenario == "all" || scenario == "pages"
			if !positive {
				if err == nil || observation != nil {
					t.Fatal("incomplete executables accepted")
				}
				return
			}
			if err != nil || observation == nil || observation.Journal().ResourceVersion() != before.ResourceVersion() || len(requests) != len(catalogue) {
				t.Fatal("complete executables refused", err)
			}
			count := len(catalogue)
			if scenario == "empty" {
				count = 0
			} else if scenario == "pages" {
				count++
			}
			if len(observation.Whole()) != count {
				t.Fatal("collection omitted members")
			}
			collections := observation.Collections()
			if collections.Pods == nil || collections.Jobs == nil || collections.Deployments == nil || collections.ReplicaSets == nil || collections.StatefulSets == nil || collections.DaemonSets == nil || collections.ReplicationControllers == nil || collections.CronJobs == nil {
				t.Fatal("missing typed complete collection")
			}
			if count > 0 {
				key := installstate.Key{APIVersion: "v1", Kind: "Pod", Namespace: f.anchor.Namespace, Name: "observed-pods"}
				whole := observation.Whole()
				if value, found, e := unstructured.NestedFieldNoCopy(whole[key].Object, "metadata", "annotations"); e != nil || !found || value != nil {
					t.Fatal("raw optional null was collapsed")
				}
				collections.Pods.Items[0].Name = "changed"
				for _, object := range whole {
					object.SetName("changed")
				}
				delete(whole, key)
				if observation.Collections().Pods.Items[0].Name != "observed-pods" || observation.Whole()[key].GetName() != "observed-pods" {
					t.Fatal("mutable alias escaped")
				}
			}
			for resource, requests := range requests {
				expected := 1
				if scenario == "pages" && resource == "pods" {
					expected = 2
				}
				if requests != expected {
					t.Fatal(fmt.Sprintf("unexpected %s replay count", resource))
				}
			}
		})
	}
}

type executableReadLimiter struct {
	flowcontrol.RateLimiter
	calls  atomic.Int32
	failAt int32
}

func (l *executableReadLimiter) Wait(ctx context.Context) error {
	if l.calls.Add(1) == l.failAt {
		return ErrRead
	}
	return ctx.Err()
}

func TestExecutablesNativeCapturePreservesSharedReadLimiter(t *testing.T) {
	for _, scenario := range []string{"shared", "refused"} {
		t.Run(scenario, func(t *testing.T) {
			f := newFixture(t)
			var requests atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer FAKE-NATIVE-READ" || r.Header.Get("Impersonate-User") != "" || r.URL.Query().Get("limit") != "128" || len(r.URL.Query()) != 1 {
					t.Error("literal executable capture changed identity, pagination or method")
				}
				w.Header().Set("Content-Type", "application/json")
				for _, c := range executableCollections(&ExecutableCollections{}) {
					prefix := "/apis/" + c.gv
					if c.gv == "v1" {
						prefix = "/api/v1"
					}
					if r.URL.Path == prefix+"/namespaces/"+f.anchor.Namespace+"/"+c.resource {
						_ = json.NewEncoder(w).Encode(map[string]any{"apiVersion": c.gv, "kind": c.kind + "List", "metadata": map[string]any{"resourceVersion": "100"}, "items": []any{}})
						return
					}
				}
				t.Error("literal capture escaped native executable list routes")
				w.WriteHeader(404)
			}))
			t.Cleanup(server.Close)
			limiter := &executableReadLimiter{RateLimiter: flowcontrol.NewFakeAlwaysRateLimiter()}
			if scenario == "refused" {
				limiter.failAt = 4
			}
			ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
			config := &rest.Config{Host: server.URL, BearerToken: "FAKE-NATIVE-READ", TLSClientConfig: rest.TLSClientConfig{CAData: ca}, RateLimiter: limiter}
			for pass := range 2 {
				observer, err := New(config, f.o.journal, f.o.plan)
				if err != nil {
					t.Fatal(err)
				}
				observation, err := observer.CollectExecutables(t.Context(), f.anchor)
				if scenario == "refused" {
					if err == nil || observation != nil || requests.Load() != 3 || limiter.calls.Load() != 4 {
						t.Fatal("capture bypassed a caller's refused rate-budget acquisition")
					}
					return
				}
				if err != nil || observation == nil || requests.Load() != int32(8*(pass+1)) || limiter.calls.Load() != requests.Load() {
					t.Fatal("reconstructing observer reset or bypassed the shared budget", err)
				}
			}
		})
	}
}
