// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installbaseline"
	"github.com/gobha-me/arcadectl/internal/installstate"
	authv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Synthetic HTTPS protocol tests, not native policy serving. Policy status is
// explicitly supplied by this fixture; no runtime guard or lifecycle success
// is inferred from the fake replies.
func TestBaselineActorsRequireOriginalAuthorityAndCloseEachProbe(t *testing.T) {
	modes := []string{"healthy", "admin-denied", "actor-maintenance-allowed", "actor-cel-maintenance-allowed", "actor-producer-allowed", "negative-review-missing", "actor-operation-denied", "access-replaced", "baseline-drift", "late-access-rv", "late-policy-rv", "review-access-rv", "review-policy-rv", "closing-config-access-rv", "wrong-denial"}
	type grant struct {
		actor admissionActor
		row   int
		late  bool
	}
	grants := map[string]grant{}
	for _, actor := range []admissionActor{ordinaryControllerActor, destroyControllerActor} {
		for index := range testBaselineContainmentAttributes("unused") {
			for _, late := range []bool{false, true} {
				mode := fmt.Sprintf("grant-%s-%d-late-%t", actor.account(), index, late)
				modes = append(modes, mode)
				grants[mode] = grant{actor: actor, row: index, late: late}
			}
		}
	}
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			f := seedBaselineAccessWitness(t)
			objects := map[string]*unstructured.Unstructured{}
			accountPath, policyPath := "", ""
			for key, object := range f.access.objects {
				path, err := resourcePath(key, false)
				if err != nil {
					t.Fatal("unit original route unavailable")
				}
				live := object.DeepCopy()
				if key.Kind == "ValidatingAdmissionPolicy" {
					live.SetGeneration(1)
					live.Object["status"] = map[string]any{"observedGeneration": int64(1), "typeChecking": map[string]any{}}
					if policyPath == "" {
						policyPath = path
					}
				}
				if key == f.key {
					accountPath = path
				}
				objects[path] = live
			}
			if mode == "access-replaced" {
				objects[accountPath].SetUID("foreign-same-name")
			}
			if mode == "baseline-drift" {
				_ = unstructured.SetNestedField(objects[policyPath].Object, "Ignore", "spec", "failurePolicy")
			}
			var probes atomic.Int32
			var mu sync.Mutex
			catalog := testBaselineContainmentAttributes(f.plan.Namespace())
			seen := map[string]map[int]int{}
			lastResource := f.snapshot.Document().SecurityBaseline.Resources[len(f.snapshot.Document().SecurityBaseline.Resources)-1].Key
			lastConfigurationPath, pathErr := resourcePath(lastResource, false)
			if pathErr != nil {
				t.Fatal("unit closing configuration route unavailable")
			}
			catalogReviews, closingReads := 0, 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				if r.Header.Get("Authorization") != "Bearer FAKE-ADMIN-CANARY" {
					t.Error("baseline actor changed original administrator credentials")
				}
				if r.Method == http.MethodGet {
					if r.Header.Get("Impersonate-User") != "" {
						t.Error("actor used generic read access")
					}
					if r.URL.Path == "/version" {
						_ = json.NewEncoder(w).Encode(map[string]any{"major": "1", "minor": "35", "gitVersion": "v" + f.plan.Profile().KubernetesVersion})
						return
					}
					if r.URL.Path == "/apis/batch/v1" {
						_ = json.NewEncoder(w).Encode(map[string]any{"kind": "APIResourceList", "groupVersion": "batch/v1", "resources": []any{map[string]any{"name": "jobs", "kind": "Job", "namespaced": true, "verbs": []any{"create"}}}})
						return
					}
					if r.URL.Path == "/api/v1/namespaces/"+f.plan.Namespace() {
						ns, err := f.access.client.CoreV1().Namespaces().Get(r.Context(), f.plan.Namespace(), metav1.GetOptions{})
						if err != nil {
							w.WriteHeader(500)
							return
						}
						ns.APIVersion, ns.Kind = "v1", "Namespace"
						_ = json.NewEncoder(w).Encode(ns)
						return
					}
					if object := objects[r.URL.Path]; object != nil {
						_ = json.NewEncoder(w).Encode(object.Object)
						if mode == "closing-config-access-rv" && catalogReviews == 2*len(catalog) && r.URL.Path == lastConfigurationPath {
							closingReads++
							if closingReads == 2 {
								objects[accountPath].SetResourceVersion("9000")
							}
						}
						return
					}
				} else if r.URL.Path == "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" && r.Method == http.MethodPost {
					var review authv1.SelfSubjectAccessReview
					if json.NewDecoder(r.Body).Decode(&review) != nil || review.Spec.ResourceAttributes == nil {
						t.Error("baseline review malformed")
						w.WriteHeader(500)
						return
					}
					attributes := review.Spec.ResourceAttributes
					allowed := true
					if user := r.Header.Get("Impersonate-User"); user == "" {
						allowed = mode != "admin-denied"
						if attributes.Verb != "impersonate" || attributes.Resource != "serviceaccounts" || attributes.Namespace != f.plan.Namespace() || attributes.Version != "*" || attributes.Group != "" || attributes.Subresource != "" ||
							attributes.Name != "arcadectl-controller" && attributes.Name != "arcadectl-destroy-controller" || attributes.FieldSelector != nil || attributes.LabelSelector != nil || review.Spec.NonResourceAttributes != nil {
							t.Error("admin review widened authority")
						}
					} else {
						valid := false
						matchedActor := admissionActor(255)
						matchedRow := -1
						for _, actor := range []admissionActor{ordinaryControllerActor, destroyControllerActor} {
							if user != "system:serviceaccount:"+f.plan.Namespace()+":"+actor.account() {
								continue
							}
							matchedActor = actor
							for index, row := range catalog {
								if reflect.DeepEqual(*attributes, row) {
									valid, matchedRow = true, index
									if seen[user] == nil {
										seen[user] = map[int]int{}
									}
									seen[user][index]++
									catalogReviews++
									break
								}
							}
							if reflect.DeepEqual(*attributes, authv1.ResourceAttributes{Group: "batch", Version: "v1", Resource: "jobs", Verb: "create", Namespace: f.plan.Namespace()}) {
								valid = true
							}
						}
						if !valid {
							t.Error("actor review escaped closed baseline protocol")
						}
						if attributes.Verb == "impersonate" {
							// Model the real review handler: an empty version is
							// normalized to wildcard, NOT the header check's empty
							// authorizer domain. Never infer actual impersonation
							// containment from this synthetic SSAR server.
							version := attributes.Version
							if version == "" {
								version = "*"
							}
							allowed = mode == "actor-maintenance-allowed" ||
								mode == "actor-cel-maintenance-allowed" && version == "*" && attributes.Namespace == f.plan.Namespace() ||
								mode == "actor-producer-allowed" && version == "*" && attributes.Namespace == "kube-system" && attributes.Name == "job-controller"
							if change, ok := grants[mode]; ok && change.actor == matchedActor && change.row == matchedRow && (!change.late || probes.Load() > 0) {
								allowed = true
							}
							if mode == "review-access-rv" {
								objects[accountPath].SetResourceVersion("9000")
							}
							if mode == "review-policy-rv" {
								objects[policyPath].SetResourceVersion("9000")
							}
						} else {
							allowed = mode != "actor-operation-denied"
						}
					}
					body, _ := json.Marshal(review)
					var fields map[string]any
					_ = json.Unmarshal(body, &fields)
					fields["status"] = map[string]any{"allowed": allowed}
					if mode == "negative-review-missing" && r.Header.Get("Impersonate-User") != "" && attributes.Verb == "impersonate" {
						fields["status"] = map[string]any{}
					}
					_ = json.NewEncoder(w).Encode(fields)
					return
				} else if r.URL.Path == "/apis/batch/v1/namespaces/"+f.plan.Namespace()+"/jobs" && r.Method == http.MethodPost {
					probes.Add(1)
					if r.URL.RawQuery != "dryRun=All&fieldManager=arcadectl-installer&fieldValidation=Strict" {
						t.Error("baseline probe became persistent")
					}
					var object unstructured.Unstructured
					if json.NewDecoder(r.Body).Decode(&object.Object) != nil {
						t.Error("baseline probe body unavailable")
					}
					key := installstate.Key{APIVersion: "batch/v1", Kind: "Job", Namespace: f.plan.Namespace(), Name: object.GetName()}
					policy := "arcadectl-identity-template-" + f.plan.Namespace()
					status, _ := expectedBaselineProbeDenial(key, "jobs", policy, policy, installbaseline.DenialMessage)
					if mode == "wrong-denial" {
						status["message"] = "PRIVATE-CANARY"
					}
					w.WriteHeader(422)
					_ = json.NewEncoder(w).Encode(status)
					if mode == "late-access-rv" {
						objects[accountPath].SetResourceVersion("9000")
					}
					if mode == "late-policy-rv" {
						objects[policyPath].SetResourceVersion("9000")
					}
					return
				}
				t.Error("baseline authority escaped exact unit routes")
				w.WriteHeader(404)
			}))
			t.Cleanup(server.Close)
			config := serverConfig(server)
			config.BearerToken = "FAKE-ADMIN-CANARY"
			access, err := NewDirectHTTPAccess(config)
			if err != nil {
				t.Fatal("unit original native transport unavailable")
			}
			baseline := f.engine.baselinePlan()
			store, err := installstate.NewWithBaseline(access.Namespaces(), baseline, f.plan)
			if err != nil {
				t.Fatal("unit original store unavailable")
			}
			engine, err := NewWithBaselineAccess(access, store, f.engine.files, baseline, f.plan)
			if err != nil {
				t.Fatal("unit original engine unavailable")
			}
			snapshot, err := store.Load(t.Context(), f.snapshot.Anchor())
			if err != nil {
				t.Fatal("unit original snapshot unavailable")
			}
			configuration, err := NewClusterSecurityBaseline(engine, access)
			if err != nil {
				t.Fatal("unit original configuration unavailable")
			}
			actors, err := configuration.newBaselineActors(t.Context(), snapshot)
			change, grantMode := grants[mode]
			factoryRefuses := mode == "admin-denied" || strings.HasPrefix(mode, "actor-") && strings.HasSuffix(mode, "-allowed") || mode == "negative-review-missing" || mode == "access-replaced" || mode == "baseline-drift" || mode == "review-access-rv" || mode == "review-policy-rv" || mode == "closing-config-access-rv" || grantMode && !change.late
			if (err != nil) != factoryRefuses || factoryRefuses && (actors != nil || probes.Load() != 0) {
				t.Fatal("baseline factory did not refuse unproved original actor authority")
			}
			if factoryRefuses {
				return
			}
			// Independent table counts catch omitted producers and actors;
			// testing only whichever rows production chooses is circular.
			mu.Lock()
			for _, actor := range []admissionActor{ordinaryControllerActor, destroyControllerActor} {
				user := "system:serviceaccount:" + f.plan.Namespace() + ":" + actor.account()
				for index := range catalog {
					if seen[user][index] == 0 {
						t.Error("baseline factory omitted a literal containment row or actor")
					}
				}
			}
			mu.Unlock()
			object := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "batch/v1", "kind": "Job", "metadata": map[string]any{"name": "inert-unit-probe", "namespace": f.plan.Namespace()}}}
			policy := "arcadectl-identity-template-" + f.plan.Namespace()
			_, err = actors.probe(t.Context(), ordinaryControllerActor, probeCreateOperation, object, policy, policy, installbaseline.DenialMessage)
			if (err == nil) != (mode == "healthy") || err != nil && strings.Contains(err.Error(), "CANARY") || probes.Load() > 1 {
				t.Fatal("baseline probe accepted changed authority, wrong denial or replay")
			}
			if mode == "actor-operation-denied" && probes.Load() != 0 || mode != "actor-operation-denied" && probes.Load() != 1 {
				t.Fatal("unproved actor operation reached wire or proved dry-run was omitted")
			}
		})
	}
}

// Literal oracle independent of the production catalog. The wildcard is
// intentional. An empty wire version cannot test the impersonation filter's
// empty authorizer version on either supported Kubernetes profile.
func testBaselineContainmentAttributes(namespace string) []authv1.ResourceAttributes {
	return []authv1.ResourceAttributes{
		{Version: "*", Resource: "serviceaccounts", Namespace: namespace, Name: "arcadectl-destroy-controller", Verb: "impersonate"},
		{Version: "*", Resource: "serviceaccounts", Namespace: namespace, Name: "arcadectl-controller", Verb: "impersonate"},
		{Version: "*", Resource: "serviceaccounts", Namespace: namespace, Name: "arcadectl-api", Verb: "impersonate"},
		{Version: "*", Resource: "serviceaccounts", Namespace: namespace, Name: "arcadectl-destroy-admin", Verb: "impersonate"},
		{Version: "*", Resource: "users", Name: "system:kube-controller-manager", Verb: "impersonate"},
		{Version: "*", Resource: "serviceaccounts", Namespace: "kube-system", Name: "replicaset-controller", Verb: "impersonate"},
		{Version: "*", Resource: "serviceaccounts", Namespace: "kube-system", Name: "job-controller", Verb: "impersonate"},
		{Version: "*", Resource: "serviceaccounts", Namespace: "kube-system", Name: "replication-controller", Verb: "impersonate"},
		{Version: "*", Resource: "serviceaccounts", Namespace: "kube-system", Name: "daemon-set-controller", Verb: "impersonate"},
		{Version: "*", Resource: "serviceaccounts", Namespace: "kube-system", Name: "statefulset-controller", Verb: "impersonate"},
		{Version: "*", Resource: "serviceaccounts", Namespace: "kube-system", Name: "deployment-controller", Verb: "impersonate"},
		{Version: "*", Resource: "serviceaccounts", Namespace: "kube-system", Name: "cronjob-controller", Verb: "impersonate"},
		{Version: "*", Resource: "serviceaccounts", Namespace: "kube-system", Name: "generic-garbage-collector", Verb: "impersonate"},
	}
}
