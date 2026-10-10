// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installstate"
	authv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Actual frozen transports, original journal/configuration witnesses and the
// complete eight-family collector, over explicit synthetic HTTPS replies.
// This tests the finite SSAR provider, not native policy serving, descendant
// ownership, a wired runtime guard or the complete installer lifecycle.
func TestBaselineDeniedProviderClosesOriginalWholeEvidenceAndLateGrants(t *testing.T) {
	modes := []string{"healthy", "first-closing-new-pod", "second-closing-new-pod", "closing-pod-rv", "closing-pod-port", "closing-unselected-rv", "closing-access-rv", "closing-policy-rv", "closing-journal-rv", "missing-negative-result", "evaluation-error", "forbidden-negative-result", "dropped-guarded", "dropped-whole", "cancelled", "opening-noncanonical-proxy-rule", "closing-noncanonical-proxy-rule", "closing-harmless-rule-drift", "closing-incomplete-rules"}
	modes = append(modes, "opening-destroy-noncanonical-proxy-rule", "closing-destroy-noncanonical-proxy-rule", "second-closing-destroy-proxy-rule", "second-closing-destroy-incomplete-rules")
	modes = append(modes, "closing-deployment-status")
	type grant struct {
		actor admissionActor
		late  bool
	}
	grants := map[string]grant{}
	for _, actor := range []admissionActor{ordinaryControllerActor, destroyControllerActor} {
		for _, late := range []bool{false, true} {
			mode := fmt.Sprintf("grant-%s-late-%t", actor.account(), late)
			modes = append(modes, mode)
			grants[mode] = grant{actor: actor, late: late}
		}
	}
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			f, _, guarded := baselineDeniedFixture(t)
			ns, err := f.access.client.CoreV1().Namespaces().Get(t.Context(), f.plan.Namespace(), metav1.GetOptions{})
			if err != nil {
				t.Fatal("original provider namespace unavailable")
			}
			// Independent literal collections and independently pinned custom-
			// namespace cluster names, never whichever scope production returns.
			collections := [][3]string{{"v1", "Pod", "pods"}, {"batch/v1", "Job", "jobs"}, {"apps/v1", "Deployment", "deployments"}, {"apps/v1", "ReplicaSet", "replicasets"}, {"apps/v1", "StatefulSet", "statefulsets"}, {"apps/v1", "DaemonSet", "daemonsets"}, {"v1", "ReplicationController", "replicationcontrollers"}, {"batch/v1", "CronJob", "cronjobs"}}
			clusterKeys := []installstate.Key{}
			for _, kind := range []string{"ClusterRole", "ClusterRoleBinding"} {
				for _, name := range []string{"arcadectl-volumeattachment-reader-5d8927e3b78f", "arcadectl-destroy-volumeattachment-reader-5d8927e3b78f"} {
					clusterKeys = append(clusterKeys, installstate.Key{APIVersion: "rbac.authorization.k8s.io/v1", Kind: kind, Name: name})
				}
			}
			expected := map[admissionActor]map[authv1.ResourceAttributes]bool{}
			seen := map[admissionActor]map[authv1.ResourceAttributes]int{}
			for _, actor := range []admissionActor{ordinaryControllerActor, destroyControllerActor} {
				expected[actor] = testBaselineDeniedAttributes(ns.Name, actor, clusterKeys)
				seen[actor] = map[authv1.ResourceAttributes]int{}
				for _, alias := range []string{"generated-pods-bcdfg:8443", ":generated-pods-bcdfg:8443", "http:generated-pods-bcdfg:8443", "https:generated-pods-bcdfg:8443"} {
					for _, verb := range []string{"get", "create", "update", "patch", "delete"} {
						expected[actor][authv1.ResourceAttributes{Version: "v1", Resource: "pods", Subresource: "proxy", Namespace: ns.Name, Name: alias, Verb: verb}] = true
					}
				}
			}
			podKey := installstate.Key{APIVersion: "v1", Kind: "Pod", Namespace: ns.Name, Name: "generated-pods-bcdfg"}
			guarded[podKey].Object["spec"].(map[string]any)["containers"] = []any{map[string]any{"name": "api", "image": "test-only.invalid/api", "ports": []any{map[string]any{"containerPort": int64(8443)}}}}
			objects := maps.Clone(guarded)
			// An unselected object is still part of the original whole witness.
			unselectedKey := installstate.Key{APIVersion: "v1", Kind: "Pod", Namespace: ns.Name, Name: "unselected-pod"}
			unselected := guarded[podKey].DeepCopy()
			unselected.SetName(unselectedKey.Name)
			unselected.SetUID("original-unselected-pod")
			_ = unstructured.SetNestedField(unselected.Object, "default", "spec", "serviceAccountName")
			objects[unselectedKey] = unselected
			originals := map[string]*unstructured.Unstructured{}
			accountPath, policyPath := "", ""
			for key, original := range f.access.objects {
				path, pathErr := resourcePath(key, false)
				if pathErr != nil {
					t.Fatal("original provider object route unavailable")
				}
				live := original.DeepCopy()
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
				originals[path] = live
			}
			containment := testBaselineContainmentAttributes(ns.Name)
			var mu sync.Mutex
			var deniedReviews, podLists, grantedReplies, mutations int
			rulesReviews := map[admissionActor]int{}
			changed := false
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				if r.Header.Get("Authorization") != "Bearer FAKE-DENIED-PROVIDER" {
					t.Error("provider changed frozen original administrator credential")
				}
				user := r.Header.Get("Impersonate-User")
				if r.Method == http.MethodPost && r.URL.Path == "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews" {
					var request authv1.SelfSubjectRulesReview
					actor := admissionActor(255)
					for _, candidate := range []admissionActor{ordinaryControllerActor, destroyControllerActor} {
						if user == "system:serviceaccount:"+ns.Name+":"+candidate.account() {
							actor = candidate
						}
					}
					if actor == admissionActor(255) || json.NewDecoder(r.Body).Decode(&request) != nil || request.Spec.Namespace != ns.Name || r.URL.RawQuery != "fieldManager=arcadectl-installer&fieldValidation=Strict" {
						t.Error("effective rule request changed original scope or actor")
						w.WriteHeader(http.StatusInternalServerError)
						return
					}
					rulesReviews[actor]++
					rows := []any{map[string]any{"verbs": []any{"get"}, "apiGroups": []any{""}, "resources": []any{"pods"}}}
					status := map[string]any{"incomplete": false, "resourceRules": rows, "nonResourceRules": []any{}}
					proxyFault := mode == "opening-noncanonical-proxy-rule" || mode == "opening-destroy-noncanonical-proxy-rule" && actor == destroyControllerActor ||
						deniedReviews > 0 && (mode == "closing-noncanonical-proxy-rule" || mode == "closing-destroy-noncanonical-proxy-rule" && actor == destroyControllerActor) ||
						mode == "second-closing-destroy-proxy-rule" && actor == destroyControllerActor && rulesReviews[actor] == 3
					if proxyFault {
						status["resourceRules"] = append(rows, map[string]any{"verbs": []any{"get"}, "apiGroups": []any{""}, "resources": []any{"services/proxy"}, "resourceNames": []any{"https:arcadectl-api:+00443"}})
						changed = true
					} else if deniedReviews > 0 && mode == "closing-harmless-rule-drift" {
						status["resourceRules"] = append(rows, map[string]any{"verbs": []any{"get"}, "apiGroups": []any{""}, "resources": []any{"configmaps"}})
						changed = true
					} else if deniedReviews > 0 && mode == "closing-incomplete-rules" || mode == "second-closing-destroy-incomplete-rules" && actor == destroyControllerActor && rulesReviews[actor] == 3 {
						status["incomplete"] = true
						changed = true
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"apiVersion": "authorization.k8s.io/v1", "kind": "SelfSubjectRulesReview", "spec": map[string]any{}, "status": status})
					return
				}
				if r.Method == http.MethodPost && r.URL.Path == "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" {
					var review authv1.SelfSubjectAccessReview
					if json.NewDecoder(r.Body).Decode(&review) != nil || review.Spec.ResourceAttributes == nil || review.Spec.NonResourceAttributes != nil {
						t.Error("provider review shape unavailable")
						w.WriteHeader(http.StatusInternalServerError)
						return
					}
					a := *review.Spec.ResourceAttributes
					allowed, finite := false, false
					if user == "" {
						valid := a == (authv1.ResourceAttributes{Version: "*", Resource: "serviceaccounts", Namespace: ns.Name, Name: "arcadectl-controller", Verb: "impersonate"}) || a == (authv1.ResourceAttributes{Version: "*", Resource: "serviceaccounts", Namespace: ns.Name, Name: "arcadectl-destroy-controller", Verb: "impersonate"})
						for _, c := range collections {
							group := strings.TrimSuffix(c[0], "/v1")
							if c[0] == "v1" {
								group = ""
							}
							if a.Group == group && a.Version == "v1" && a.Resource == c[2] && a.Subresource == "" && a.Namespace == ns.Name && a.FieldSelector == nil && a.LabelSelector == nil && (a.Verb == "list" && a.Name == "" || a.Verb == "get" && objects[installstate.Key{APIVersion: c[0], Kind: c[1], Namespace: ns.Name, Name: a.Name}] != nil) {
								valid = true
							}
						}
						if !valid {
							t.Error("provider administrator review escaped original read/actor selection")
						}
						allowed = valid
					} else {
						actor := admissionActor(255)
						for _, candidate := range []admissionActor{ordinaryControllerActor, destroyControllerActor} {
							if user == "system:serviceaccount:"+ns.Name+":"+candidate.account() {
								actor = candidate
								break
							}
						}
						valid := false
						if actor != admissionActor(255) {
							for _, row := range containment {
								valid = valid || reflect.DeepEqual(a, row)
							}
							finite = expected[actor][a]
							valid = valid || finite
						}
						if !valid {
							t.Error("provider actor review escaped independent finite requirements")
						}
						if finite {
							deniedReviews++
							seen[actor][a]++
							if g, ok := grants[mode]; ok && g.actor == actor && a.Resource == "pods" && a.Subresource == "proxy" && a.Name == "https:generated-pods-bcdfg:8443" && a.Verb == "get" && (!g.late || podLists >= 2) {
								allowed = true
								grantedReplies++
							}
							if !changed {
								switch mode {
								case "closing-access-rv":
									originals[accountPath].SetResourceVersion("9001")
									changed = true
								case "closing-policy-rv":
									originals[policyPath].SetResourceVersion("9001")
									changed = true
								case "closing-journal-rv":
									ns.ResourceVersion = "9001"
									changed = true
								}
							}
						}
					}
					if finite && mode == "forbidden-negative-result" {
						w.WriteHeader(http.StatusForbidden)
						_ = json.NewEncoder(w).Encode(map[string]any{"apiVersion": "v1", "kind": "Status", "status": "Failure", "reason": "Forbidden", "code": 403})
						return
					}
					status := map[string]any{"allowed": allowed}
					if finite && mode == "missing-negative-result" {
						status = map[string]any{}
					} else if finite && mode == "evaluation-error" {
						status["evaluationError"] = "synthetic-unproved-authorizer"
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"apiVersion": "authorization.k8s.io/v1", "kind": "SelfSubjectAccessReview", "spec": review.Spec, "status": status})
					return
				}
				if r.Method != http.MethodGet || user != "" {
					mutations++
					t.Error("finite denied provider attempted mutation or generic actor read")
					w.WriteHeader(http.StatusInternalServerError)
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
					return
				}
				if object := originals[r.URL.Path]; object != nil {
					_ = json.NewEncoder(w).Encode(object.Object)
					return
				}
				for _, gv := range []string{"v1", "apps/v1", "batch/v1"} {
					prefix := "/apis/" + gv
					if gv == "v1" {
						prefix = "/api/v1"
					}
					if r.URL.Path != prefix {
						continue
					}
					resources := []metav1.APIResource{}
					for _, c := range collections {
						if c[0] == gv {
							resources = append(resources, metav1.APIResource{Name: c[2], Kind: c[1], Namespaced: true, Verbs: metav1.Verbs{"list", "get"}})
						}
					}
					_ = json.NewEncoder(w).Encode(metav1.APIResourceList{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "APIResourceList"}, GroupVersion: gv, APIResources: resources})
					return
				}
				for _, c := range collections {
					prefix := "/apis/" + c[0]
					if c[0] == "v1" {
						prefix = "/api/v1"
					}
					path := prefix + "/namespaces/" + ns.Name + "/" + c[2]
					if r.URL.Path != path && !strings.HasPrefix(r.URL.Path, path+"/") {
						continue
					}
					if r.URL.Path == path {
						q := r.URL.Query()
						if q.Get("limit") != "128" || len(q) > 2 || q.Has("timeout") && q.Get("timeout") != "30s" {
							t.Error("provider omitted complete bounded unfiltered LIST")
						}
						if c[1] == "Pod" {
							podLists++
							if deniedReviews > 0 && !changed {
								switch mode {
								case "first-closing-new-pod", "second-closing-new-pod":
									if mode == "first-closing-new-pod" || podLists >= 3 {
										added := guarded[podKey].DeepCopy()
										added.SetName("late-reserved-pod")
										added.SetUID("late-reserved-pod-uid")
										objects[installstate.Key{APIVersion: "v1", Kind: "Pod", Namespace: ns.Name, Name: added.GetName()}] = added
										changed = true
									}
								case "closing-pod-rv":
									objects[podKey].SetResourceVersion("9001")
									changed = true
								case "closing-pod-port":
									containers, _, _ := unstructured.NestedSlice(objects[podKey].Object, "spec", "containers")
									containers[0].(map[string]any)["ports"] = []any{map[string]any{"containerPort": int64(9443)}}
									_ = unstructured.SetNestedSlice(objects[podKey].Object, containers, "spec", "containers")
									changed = true
								case "closing-unselected-rv":
									objects[unselectedKey].SetResourceVersion("9001")
									changed = true
								case "closing-deployment-status":
									key := deploymentKey(ns.Name, "generated-deployments-bcdfg")
									objects[key].SetResourceVersion("9001")
									objects[key].Object["status"] = map[string]any{"replicas": int64(1), "readyReplicas": int64(1), "availableReplicas": int64(1)}
									changed = true
								}
							}
						}
						items := []any{}
						for key, object := range objects {
							if key.APIVersion == c[0] && key.Kind == c[1] {
								items = append(items, object.DeepCopy().Object)
							}
						}
						_ = json.NewEncoder(w).Encode(map[string]any{"apiVersion": c[0], "kind": c[1] + "List", "metadata": map[string]any{"resourceVersion": "100"}, "items": items})
						return
					}
					name := strings.TrimPrefix(r.URL.Path, path+"/")
					if object := objects[installstate.Key{APIVersion: c[0], Kind: c[1], Namespace: ns.Name, Name: name}]; object != nil {
						_ = json.NewEncoder(w).Encode(object.Object)
						return
					}
				}
				t.Error("provider escaped original reads and eight literal executable families")
				w.WriteHeader(http.StatusNotFound)
			}))
			t.Cleanup(server.Close)
			config := serverConfig(server)
			// High rates apply only to this in-process synthetic HTTPS server.
			config.BearerToken, config.QPS, config.Burst = "FAKE-DENIED-PROVIDER", 1000, 2000
			access, err := NewDirectHTTPAccess(config)
			if err != nil {
				t.Fatal("frozen provider transport unavailable")
			}
			baseline := f.engine.baselinePlan()
			store, err := installstate.NewWithBaseline(access.Namespaces(), baseline, f.plan)
			if err != nil {
				t.Fatal("original provider store unavailable")
			}
			engine, err := NewWithBaselineAccess(access, store, f.engine.files, baseline, f.plan)
			if err != nil {
				t.Fatal("original provider engine unavailable")
			}
			snapshot, err := store.Load(t.Context(), f.snapshot.Anchor())
			if err != nil {
				t.Fatal("sealed provider snapshot unavailable")
			}
			provider, err := NewClusterSecurityBaseline(engine, access)
			if err != nil {
				t.Fatal("original provider unavailable")
			}
			actors, err := provider.newBaselineActors(t.Context(), snapshot)
			if err != nil {
				t.Fatal("original provider actors unavailable")
			}
			executables, err := provider.collectExecutables(t.Context(), snapshot)
			if err != nil || len(executables.whole) != 9 || len(executables.guarded) != 8 {
				t.Fatal("original complete provider observation unavailable")
			}
			if mode == "dropped-guarded" {
				delete(executables.guarded, podKey)
			} else if mode == "dropped-whole" {
				delete(executables.whole, unselectedKey)
			}
			guard := &baselineParentRefusingRuntimeGuard{}
			engine.baseline.runtimeGuard = guard // detects accidental recursive use ONLY
			defer func() { engine.baseline.runtimeGuard = nil }()
			ctx, diagnostic := WithLifecycleDiagnostic(t.Context())
			if mode == "cancelled" {
				var cancel func()
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			err = actors.verifyDenied(ctx, executables)
			if (err == nil) != (mode == "healthy") || err != nil && strings.Contains(err.Error(), "FAKE") || guard.calls.Load() != 0 {
				t.Fatal("denied provider accepted changed/unproved evidence, refused healthy originals or recursed")
			}
			// Independent literal expectations for actual short-circuit points.
			// No raw review/object/provider error is included in the trace.
			wantBoundary := map[string]string{
				"healthy":               "denied-actors-final",
				"first-closing-new-pod": "denied-executables-stable", "second-closing-new-pod": "denied-executables-stable",
				"closing-pod-rv": "denied-executables-stable", "closing-pod-port": "denied-executables-stable", "closing-unselected-rv": "denied-executables-stable",
				"closing-deployment-status": "denied-executables-stable",
				"closing-access-rv":         "denied-actors-closing", "closing-policy-rv": "denied-actors-closing", "closing-journal-rv": "denied-executables-closing",
				"missing-negative-result": "denied-reviews", "evaluation-error": "denied-reviews", "forbidden-negative-result": "denied-reviews",
				"dropped-guarded": "unknown", "dropped-whole": "unknown", "cancelled": "denied-actors-opening",
				"opening-noncanonical-proxy-rule": "denied-rules-opening", "opening-destroy-noncanonical-proxy-rule": "denied-rules-opening",
				"closing-noncanonical-proxy-rule": "denied-rules-closing", "closing-destroy-noncanonical-proxy-rule": "denied-rules-closing", "second-closing-destroy-proxy-rule": "denied-rules-closing",
				"closing-harmless-rule-drift": "denied-rules-closing", "closing-incomplete-rules": "denied-rules-closing", "second-closing-destroy-incomplete-rules": "denied-rules-closing",
			}[mode]
			if _, ok := grants[mode]; ok {
				wantBoundary = "denied-reviews"
			}
			if wantBoundary == "" || diagnostic.BoundarySnapshot() != "operation=unknown baseline="+wantBoundary {
				t.Fatal("actual denied proof lost its fixed refusal boundary", diagnostic.BoundarySnapshot())
			}
			mu.Lock()
			defer mu.Unlock()
			if mutations != 0 {
				t.Fatal("finite denied provider performed an effect")
			}
			if mode == "healthy" {
				for _, actor := range []admissionActor{ordinaryControllerActor, destroyControllerActor} {
					if rulesReviews[actor] != 3 {
						t.Fatal("whole provider omitted complete opening or paired closing effective rules")
					}
				}
				for actor, rows := range expected {
					if len(seen[actor]) != len(rows) {
						t.Fatal("whole provider omitted independent actor catalog membership")
					}
					for row := range rows {
						if seen[actor][row] != 2 {
							t.Fatal("whole provider omitted one of its two independent complete negative passes")
						}
					}
				}
				if podLists != 3 || !bytes.Equal(snapshot.Bytes(), []byte(ns.Annotations[installstate.Annotation])) || ns.ResourceVersion != snapshot.ResourceVersion() {
					t.Fatal("whole provider omitted complete closing reads or changed the original journal")
				}
			} else if g, ok := grants[mode]; ok {
				target := authv1.ResourceAttributes{Version: "v1", Resource: "pods", Subresource: "proxy", Namespace: ns.Name, Name: "https:generated-pods-bcdfg:8443", Verb: "get"}
				want := 1
				if g.late {
					want = 2
				}
				if grantedReplies != 1 || seen[g.actor][target] != want || g.late && podLists < 2 {
					t.Fatal("grant refusal did not reach the intended original or late authorization decision")
				}
			} else if mode == "dropped-guarded" || mode == "dropped-whole" || mode == "cancelled" || strings.HasPrefix(mode, "opening-") {
				if deniedReviews != 0 {
					t.Fatal("unproved local evidence or cancellation reached finite denied wire")
				}
			} else if deniedReviews == 0 {
				t.Fatal("negative control refused before exercising its finite provider boundary")
			}
			if mode == "second-closing-new-pod" && podLists != 3 {
				t.Fatal("second-closing refusal did not reach the final complete observer window")
			}
			if strings.HasPrefix(mode, "second-closing-destroy-") && rulesReviews[destroyControllerActor] != 3 {
				t.Fatal("destroy-only rule refusal did not reach its final complete review")
			}
			if (strings.Contains(mode, "closing-") || strings.HasPrefix(mode, "opening-")) && !changed {
				t.Fatal("drift refusal did not exercise its intended original closing-window change")
			}
		})
	}
}
