// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installstate"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestCRDsRequireOriginalHealthyStorageAndCompleteServedDiscovery(t *testing.T) {
	v := newLifecycleFixture(t)
	v.fail = AdmissionConfigured
	s := v.f.snapshot
	for i := 0; i < 100; i++ {
		next, err := v.l.Step(context.Background(), s, v.opts)
		s = next
		if err != nil {
			if !errors.Is(err, ErrLifecycle) {
				t.Fatal(err)
			}
			break
		}
	}
	var crds []installstate.Key
	for _, resource := range v.f.plan.Resources() {
		if key := resourceKey(resource); key.Kind == "CustomResourceDefinition" {
			crds = append(crds, key)
		}
	}
	if len(crds) != 5 {
		t.Fatal("fixture lacks five CRDs")
	}
	baseline := metav1.APIResourceList{TypeMeta: metav1.TypeMeta{Kind: "APIResourceList", APIVersion: "v1"}, GroupVersion: "arcade.gobha.me/v1alpha1"}
	for _, key := range crds {
		live := v.f.access.objects[key]
		plural, _, _ := unstructured.NestedString(live.Object, "spec", "names", "plural")
		kind, _, _ := unstructured.NestedString(live.Object, "spec", "names", "kind")
		baseline.APIResources = append(baseline.APIResources, metav1.APIResource{Name: plural, Kind: kind, Namespaced: true, Verbs: metav1.Verbs{"list", "create"}})
	}
	before := v.f.access.writes
	for _, scenario := range []string{
		"healthy", "missing", "foreign-uid", "unsigned-spec", "unestablished", "stored-version", "conversion", "stale-generation", "deleting",
		"missing-discovery", "missing-resource", "missing-list", "missing-create", "foreign-kind", "foreign-scope", "foreign-version", "duplicate-resource",
		"crd-rv-race", "crd-uid-race", "namespace-race", "wrong-server-version", "stale-snapshot", "unrecorded", "journal-race",
	} {
		t.Run(scenario, func(t *testing.T) {
			current := v.f
			input := s
			if scenario == "unrecorded" {
				// A CURRENT sealed namespace journal with no recorded CRDs;
				// same-address healthy HTTP objects must never be adopted.
				current = newFixtureWithPlans(t, false, v.f.plan)
				input = current.snapshot
			}
			discovery := baseline.DeepCopy()
			reads := map[installstate.Key]int{}
			namespaceReads := 0
			if scenario == "missing-resource" {
				discovery.APIResources = discovery.APIResources[1:]
			}
			if scenario == "missing-list" {
				discovery.APIResources[0].Verbs = metav1.Verbs{"create"}
			}
			if scenario == "missing-create" {
				for i := range discovery.APIResources {
					if discovery.APIResources[i].Kind == "GameDestroy" {
						discovery.APIResources[i].Verbs = metav1.Verbs{"list"}
					}
				}
			}
			if scenario == "foreign-kind" {
				discovery.APIResources[0].Kind = "Foreign"
			}
			if scenario == "foreign-scope" {
				discovery.APIResources[0].Namespaced = false
			}
			if scenario == "foreign-version" {
				discovery.APIResources[0].Version = "v1beta1"
			}
			if scenario == "duplicate-resource" {
				discovery.APIResources = append(discovery.APIResources, discovery.APIResources[0])
			}
			access := proofServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.RawQuery != "" {
					t.Error("CRD proof mutated or used cached/filtered reads")
				}
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/version":
					version := v.f.plan.Profile().KubernetesVersion
					if scenario == "wrong-server-version" {
						version = "1.35.9"
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"major": "1", "minor": "35", "gitVersion": "v" + version})
					return
				case "/api/v1/namespaces/" + v.f.plan.Namespace():
					namespaceReads++
					ns, err := current.access.client.CoreV1().Namespaces().Get(r.Context(), v.f.plan.Namespace(), metav1.GetOptions{})
					if err != nil {
						t.Error(err)
						return
					}
					if scenario == "namespace-race" && namespaceReads > 1 {
						ns.ResourceVersion = "changed"
					}
					ns.APIVersion, ns.Kind = "v1", "Namespace"
					_ = json.NewEncoder(w).Encode(ns)
					return
				case "/apis/arcade.gobha.me/v1alpha1":
					if scenario == "missing-discovery" {
						w.WriteHeader(404)
						_, _ = w.Write([]byte("PRIVATE-CANARY"))
						return
					}
					_ = json.NewEncoder(w).Encode(discovery)
					if scenario == "journal-race" {
						ns, err := current.access.client.CoreV1().Namespaces().Get(r.Context(), v.f.plan.Namespace(), metav1.GetOptions{})
						if err != nil {
							t.Error(err)
							return
						}
						ns.ResourceVersion = "journal-changed-during-discovery"
						if err := current.access.client.Tracker().Update(corev1.SchemeGroupVersion.WithResource("namespaces"), ns, ""); err != nil {
							t.Error(err)
						}
					}
					return
				}
				for _, key := range crds {
					path, _ := resourcePath(key, false)
					if path != r.URL.Path {
						continue
					}
					reads[key]++
					live := v.f.access.objects[key].DeepCopy()
					if key == crds[0] {
						switch scenario {
						case "missing":
							w.WriteHeader(404)
							return
						case "foreign-uid":
							live.SetUID("foreign-same-named-CRD")
						case "unsigned-spec":
							_ = unstructured.SetNestedField(live.Object, "Foreign", "spec", "names", "kind")
						case "unestablished":
							unstructured.RemoveNestedField(live.Object, "status", "conditions")
						case "stored-version":
							_ = unstructured.SetNestedSlice(live.Object, []any{"v1beta1"}, "status", "storedVersions")
						case "conversion":
							_ = unstructured.SetNestedField(live.Object, "Webhook", "spec", "conversion", "strategy")
						case "stale-generation":
							_ = unstructured.SetNestedField(live.Object, int64(0), "status", "observedGeneration")
						case "deleting":
							live.SetDeletionTimestamp(&metav1.Time{Time: v.opts.Now})
						case "crd-rv-race":
							if reads[key] > 1 {
								live.SetResourceVersion("changed")
							}
						case "crd-uid-race":
							if reads[key] > 1 {
								live.SetUID("replacement-during-discovery")
							}
						}
					}
					_ = json.NewEncoder(w).Encode(live.Object)
					return
				}
				w.WriteHeader(404)
			})
			proof := &ClusterPrerequisites{engine: current.engine, access: access}
			request := LifecycleCheck{Checkpoint: CRDsAvailable, Snapshot: input, Mode: installstate.Install, Target: v.f.plan, Options: v.opts}
			if scenario == "stale-snapshot" {
				request.Snapshot = v.f.snapshot
			}
			err := proof.VerifyCRDs(context.Background(), request)
			if (err == nil) != (scenario == "healthy") || err != nil && (err != ErrCRDs || strings.Contains(err.Error(), "CANARY")) || v.f.access.writes != before {
				t.Fatalf("CRD gate accepted foreign/incomplete evidence or mutated: %v", err)
			}
			if scenario == "healthy" {
				for _, key := range crds {
					if reads[key] != 2 {
						t.Fatal("original identity/version not bracketed around discovery")
					}
				}
				request.Checkpoint = AdmissionEffective
				if proof.VerifyCRDs(context.Background(), request) != ErrInvalid {
					t.Fatal("CRD proof substituted for admission")
				}
				request.Checkpoint = CRDsAvailable
				for _, mode := range []installstate.Mode{"", "unknown"} {
					request.Mode = mode
					if proof.VerifyCRDs(context.Background(), request) != ErrInvalid {
						t.Fatal("invalid operation mode accepted")
					}
				}
				request.Mode = installstate.Install
				request.Target = nil
				if proof.VerifyCRDs(context.Background(), request) != ErrInvalid {
					t.Fatal("untrusted nil target accepted")
				}
				request.Target = fixturePlanProfile(t, "foreign-install", v.f.plan.Profile().ID)
				if proof.VerifyCRDs(context.Background(), request) != ErrInvalid {
					t.Fatal("foreign target accepted")
				}
				request.Target = v.f.plan
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				if proof.VerifyCRDs(ctx, request) != ErrCRDs {
					t.Fatal("canceled observation accepted")
				}
			}
		})
	}
}
