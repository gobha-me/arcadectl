// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installstate"
	authv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func baselineDeniedFixture(t *testing.T) (*fixture, map[installstate.Key]admissionIdentity, map[installstate.Key]*unstructured.Unstructured) {
	t.Helper()
	f := seedBaselineAccessWitness(t)
	access, err := f.engine.baseline.runtimeAccessWitness(t.Context(), f.snapshot)
	if err != nil {
		t.Fatal("original denied-catalog access fixture unavailable")
	}
	objects := map[installstate.Key]*unstructured.Unstructured{}
	// Independent literal inventory, not the production collection table.
	for _, r := range [][3]string{{"v1", "Pod", "pods"}, {"batch/v1", "Job", "jobs"}, {"apps/v1", "Deployment", "deployments"}, {"apps/v1", "ReplicaSet", "replicasets"}, {"apps/v1", "StatefulSet", "statefulsets"}, {"apps/v1", "DaemonSet", "daemonsets"}, {"v1", "ReplicationController", "replicationcontrollers"}, {"batch/v1", "CronJob", "cronjobs"}} {
		key := installstate.Key{APIVersion: r[0], Kind: r[1], Namespace: f.plan.Namespace(), Name: "generated-" + r[2] + "-bcdfg"}
		object := &unstructured.Unstructured{Object: map[string]any{"apiVersion": r[0], "kind": r[1], "metadata": map[string]any{"name": key.Name, "namespace": key.Namespace, "uid": "original-" + r[2], "resourceVersion": "99"}}}
		path := []string{"spec", "template", "spec", "serviceAccountName"}
		if r[1] == "Pod" {
			path = []string{"spec", "serviceAccountName"}
		}
		if r[1] == "CronJob" {
			path = []string{"spec", "jobTemplate", "spec", "template", "spec", "serviceAccountName"}
		}
		if unstructured.SetNestedField(object.Object, "arcadectl-api", path...) != nil {
			t.Fatal("literal generated inventory unavailable")
		}
		objects[key] = object
	}
	return f, access, objects
}

// Independent literal review requirements; notably no fictitious bind/escalate
// on RoleBindings, Service deletecollection, scale create, or collection PATCH.
func testBaselineDeniedAttributes(ns string, actor admissionActor, clusterKeys []installstate.Key) map[authv1.ResourceAttributes]bool {
	rows := map[authv1.ResourceAttributes]bool{}
	add := func(group, resource, sub, namespace, name string, verbs ...string) {
		for _, verb := range verbs {
			rows[authv1.ResourceAttributes{Group: group, Version: "v1", Resource: resource, Subresource: sub, Namespace: namespace, Name: name, Verb: verb}] = true
		}
	}
	fixed := []string{"arcadectl-controller", "arcadectl-api", "arcadectl-destroy-controller", "arcadectl-destroy-admin"}
	for _, name := range fixed {
		add("", "serviceaccounts", "", ns, name, "update", "patch")
		add("", "serviceaccounts", "token", ns, name, "create")
		add("rbac.authorization.k8s.io", "roles", "", ns, name, "update", "patch", "bind", "escalate")
		add("rbac.authorization.k8s.io", "rolebindings", "", ns, name, "update", "patch")
		add("", "services", "status", ns, name, "update", "patch")
		if actor == destroyControllerActor {
			add("", "services", "", ns, name, "update", "patch", "delete")
		}
		for _, resource := range []string{"pods", "services"} {
			aliases := []string{name, name + ":", ":" + name + ":", "http:" + name + ":", "https:" + name + ":"}
			if resource == "services" && name == "arcadectl-api" {
				for _, port := range []string{"443", "https"} {
					aliases = append(aliases, name+":"+port, ":"+name+":"+port, "http:"+name+":"+port, "https:"+name+":"+port)
				}
			}
			for _, alias := range aliases {
				add("", resource, "proxy", ns, alias, "get", "create", "update", "patch", "delete")
			}
		}
	}
	for _, r := range [][3]string{{"", "serviceaccounts", "deletecollection"}, {"rbac.authorization.k8s.io", "roles", "deletecollection"}, {"rbac.authorization.k8s.io", "rolebindings", "deletecollection"}} {
		add(r[0], r[1], "", ns, "", r[2])
	}
	if actor == destroyControllerActor {
		add("", "services", "", ns, "", "create")
	}
	for _, r := range [][2]string{{"", "pods"}, {"batch", "jobs"}, {"apps", "deployments"}, {"apps", "replicasets"}, {"apps", "statefulsets"}, {"apps", "daemonsets"}, {"", "replicationcontrollers"}, {"batch", "cronjobs"}} {
		group, resource := r[0], r[1]
		add(group, resource, "", ns, "", "deletecollection")
		if resource != "jobs" && (resource != "deployments" || actor == destroyControllerActor) {
			add(group, resource, "", ns, "", "create")
		}
		names := append(append([]string{}, fixed...), "generated-"+resource+"-bcdfg")
		for _, name := range names {
			add(group, resource, "status", ns, name, "update", "patch")
			switch resource {
			case "pods":
				if strings.HasPrefix(name, "generated-") {
					for _, alias := range []string{name, name + ":", ":" + name + ":", "http:" + name + ":", "https:" + name + ":"} {
						add("", "pods", "proxy", ns, alias, "get", "create", "update", "patch", "delete")
					}
				}
				add("", "pods", "", ns, name, "patch", "delete")
				for _, sub := range []string{"resize", "ephemeralcontainers"} {
					add("", "pods", sub, ns, name, "update", "patch")
				}
				for _, sub := range []string{"binding", "eviction"} {
					add("", "pods", sub, ns, name, "create")
				}
				for _, sub := range []string{"exec", "attach", "portforward"} {
					add("", "pods", sub, ns, name, "get", "create")
				}
				add("", "pods", "log", ns, name, "get")
			case "jobs":
				add("batch", "jobs", "", ns, name, "patch")
			case "deployments":
				if actor == destroyControllerActor {
					add("apps", "deployments", "", ns, name, "update", "patch", "delete")
				}
			default:
				add(group, resource, "", ns, name, "update", "patch", "delete")
			}
			if resource == "deployments" || resource == "replicasets" || resource == "statefulsets" || resource == "replicationcontrollers" {
				add(group, resource, "scale", ns, name, "update", "patch")
			}
		}
	}
	for _, key := range clusterKeys {
		resource := "clusterrolebindings"
		verbs := []string{"update", "patch", "delete"}
		if key.Kind == "ClusterRole" {
			resource = "clusterroles"
			verbs = append(verbs, "bind", "escalate")
		}
		add("rbac.authorization.k8s.io", resource, "", "", "", "create", "deletecollection")
		add("rbac.authorization.k8s.io", resource, "", "", key.Name, verbs...)
	}
	return rows
}

func TestBaselineDeniedCatalogLiteralClosureAndCopies(t *testing.T) {
	f, access, objects := baselineDeniedFixture(t)
	scope, err := f.engine.baselineDeniedCatalog(f.snapshot.Document(), access, objects)
	if err != nil || scope == nil {
		t.Fatal("finite original denied catalog unavailable")
	}
	var clusterKeys []installstate.Key
	for key := range access {
		if key.Kind == "ClusterRole" || key.Kind == "ClusterRoleBinding" {
			clusterKeys = append(clusterKeys, key)
			if !strings.Contains(key.Name, "-") || key.Namespace != "" {
				t.Fatal("custom namespace cluster identity fixture unavailable")
			}
		}
	}
	clusterWant := map[installstate.Key]bool{}
	for _, kind := range []string{"ClusterRole", "ClusterRoleBinding"} {
		for _, name := range []string{"arcadectl-volumeattachment-reader-5d8927e3b78f", "arcadectl-destroy-volumeattachment-reader-5d8927e3b78f"} {
			clusterWant[installstate.Key{APIVersion: "rbac.authorization.k8s.io/v1", Kind: kind, Name: name}] = true
		}
	}
	clusterActual := map[installstate.Key]bool{}
	for _, key := range clusterKeys {
		clusterActual[key] = true
	}
	if !reflect.DeepEqual(clusterActual, clusterWant) {
		t.Fatal("native cluster access names lost independently pinned namespace suffix")
	}
	for _, actor := range []admissionActor{ordinaryControllerActor, destroyControllerActor} {
		want := testBaselineDeniedAttributes(f.plan.Namespace(), actor, clusterKeys)
		actual := map[authv1.ResourceAttributes]bool{}
		for _, row := range scope.rows[actor] {
			a := *row.attributes()
			if actual[a] {
				t.Fatal("denied catalog duplicates descriptor")
			}
			actual[a] = true
		}
		if !reflect.DeepEqual(want, actual) {
			t.Fatal("denied catalog differs from independent finite requirements")
		}
		identity := actorWireIdentity{actor: actor, purpose: baselineDeniedReviewPurpose, namespace: scope.namespace, username: "system:serviceaccount:" + scope.namespace + ":" + actor.account(), deniedScope: scope}
		for a := range want {
			review := &authv1.SelfSubjectAccessReview{TypeMeta: metav1.TypeMeta{APIVersion: "authorization.k8s.io/v1", Kind: "SelfSubjectAccessReview"}, Spec: authv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &a}}
			if !identity.allowsReview(review) {
				t.Fatal("literal finite denied review rejected")
			}
			changed := review.DeepCopy()
			changed.Spec.ResourceAttributes.Name = "unrecorded-foreign"
			if identity.allowsReview(changed) {
				t.Fatal("finite catalog widened to arbitrary named reviews")
			}
			changed = review.DeepCopy()
			changed.Spec.ResourceAttributes.Version = "*"
			if identity.allowsReview(changed) {
				t.Fatal("denied write review widened to wildcard version")
			}
			changed = review.DeepCopy()
			changed.Spec.ResourceAttributes.LabelSelector = &authv1.LabelSelectorAttributes{}
			if identity.allowsReview(changed) {
				t.Fatal("finite review admitted selector")
			}
			changedIdentity := identity
			changedIdentity.username = "foreign-user"
			if changedIdentity.allowsReview(review) {
				t.Fatal("descriptor client identity changed effective actor")
			}
		}
		before := append([]baselineDeniedDescriptor{}, scope.rows[actor]...)
		for key := range access {
			delete(access, key)
		}
		for key, o := range objects {
			o.SetName("changed-local-input")
			delete(objects, key)
		}
		if !reflect.DeepEqual(before, scope.rows[actor]) {
			t.Fatal("scope retained caller-owned mutable evidence")
		}
	}
}

func TestBaselineDeniedCatalogRefusesUnprovedScope(t *testing.T) {
	for _, scenario := range []string{"nil-access", "missing-account", "missing-rbac", "foreign-access", "replacement-access", "nil-inventory", "malformed-inventory", "unselected-inventory", "foreign-inventory", "stale-rv"} {
		t.Run(scenario, func(t *testing.T) {
			f, access, objects := baselineDeniedFixture(t)
			switch scenario {
			case "nil-access":
				access = nil
			case "missing-account":
				delete(access, installstate.Key{APIVersion: "v1", Kind: "ServiceAccount", Namespace: f.plan.Namespace(), Name: "arcadectl-api"})
			case "missing-rbac":
				for key := range access {
					if key.Kind == "Role" {
						delete(access, key)
						break
					}
				}
			case "foreign-access":
				access[installstate.Key{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRole", Name: "foreign-cluster-role"}] = admissionIdentity{UID: "foreign", ResourceVersion: "1"}
			case "replacement-access":
				for key, identity := range access {
					identity.UID = "foreign-replacement"
					access[key] = identity
					break
				}
			case "nil-inventory":
				objects = nil
			default:
				for _, o := range objects {
					switch scenario {
					case "malformed-inventory":
						o.SetUID("")
					case "unselected-inventory":
						o.SetName("unselected")
					case "foreign-inventory":
						o.SetNamespace("foreign")
					case "stale-rv":
						o.SetResourceVersion("opaque")
					}
					break
				}
			}
			if scope, err := f.engine.baselineDeniedCatalog(f.snapshot.Document(), access, objects); err == nil || scope != nil {
				t.Fatal("unproved original scope acquired denied-review client authority")
			}
		})
	}
}

func TestBaselineDeniedReviewWireOnlyAndStrictNegativeResult(t *testing.T) {
	f, access, objects := baselineDeniedFixture(t)
	scope, err := f.engine.baselineDeniedCatalog(f.snapshot.Document(), access, objects)
	if err != nil {
		t.Fatal("finite wire catalog unavailable")
	}
	for _, actor := range []admissionActor{ordinaryControllerActor, destroyControllerActor} {
		for _, mode := range []string{"denied", "allowed", "forbidden", "missing-allowed", "evaluation-error"} {
			t.Run(actor.account()+"-"+mode, func(t *testing.T) {
				var requests atomic.Int32
				server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					requests.Add(1)
					if r.Method != "POST" || r.URL.Path != "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" || r.URL.RawQuery != "fieldManager=arcadectl-installer&fieldValidation=Strict" || r.Header.Get("Impersonate-User") != "system:serviceaccount:"+scope.namespace+":"+actor.account() || r.Header.Get("Authorization") != "Bearer FAKE-ADMIN-CANARY" {
						t.Error("SSAR-only wire route or frozen actor changed")
					}
					var review authv1.SelfSubjectAccessReview
					if json.NewDecoder(r.Body).Decode(&review) != nil {
						t.Error("finite review body unavailable")
					}
					w.Header().Set("Content-Type", "application/json")
					if mode == "forbidden" {
						w.WriteHeader(403)
						return
					}
					status := map[string]any{"allowed": false}
					if mode == "allowed" {
						status["allowed"] = true
					}
					if mode == "missing-allowed" {
						delete(status, "allowed")
					}
					if mode == "evaluation-error" {
						status["evaluationError"] = "PRIVATE-CANARY"
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"apiVersion": review.APIVersion, "kind": review.Kind, "spec": review.Spec, "status": status})
				}))
				defer server.Close()
				config := serverConfig(server)
				config.BearerToken = "FAKE-ADMIN-CANARY"
				admin, err := NewDirectHTTPAccess(config)
				if err != nil {
					t.Fatal("frozen review test client unavailable")
				}
				client, err := admin.baselineDeniedClient(actor, scope)
				if err != nil {
					t.Fatal("closed SSAR-only client unavailable")
				}
				if generic, err := admin.actorClientForPurpose(ordinaryControllerActor, scope.namespace, baselineDeniedReviewPurpose); err == nil || generic != nil {
					t.Fatal("generic actor constructor selected private review scope")
				}
				row := scope.rows[actor][0]
				if result := client.authorizationDecision(t.Context(), authv1.SelfSubjectAccessReviewSpec{ResourceAttributes: row.attributes()}, false); (result == nil) != (mode == "denied") {
					t.Fatal("grant, missing explicit decision, API error or evaluation error counted as negative proof")
				}
				before := requests.Load()
				wrong := row.attributes()
				wrong.Name = "foreign-unlisted"
				_ = client.authorizationDecision(t.Context(), authv1.SelfSubjectAccessReviewSpec{ResourceAttributes: wrong}, false)
				if requests.Load() != before {
					t.Fatal("out-of-scope review reached wire")
				}
				for _, row := range [][2]string{{"v1", "Pod"}, {"batch/v1", "Job"}, {"apps/v1", "Deployment"}, {"v1", "ServiceAccount"}, {"rbac.authorization.k8s.io/v1", "Role"}, {"rbac.authorization.k8s.io/v1", "RoleBinding"}, {"v1", "Service"}, {"v1", "PersistentVolumeClaim"}, {"arcade.gobha.me/v1alpha1", "GameDestroy"}} {
					key := installstate.Key{APIVersion: row[0], Kind: row[1], Namespace: scope.namespace, Name: "arcadectl-controller"}
					for operation := admissionProbeOperation(0); operation <= probePatchMetadataOperation; operation++ {
						if client.actor.allows(key, operation) {
							t.Fatal("SSAR-only purpose admits executable mutation")
						}
						object := &unstructured.Unstructured{Object: map[string]any{"apiVersion": key.APIVersion, "kind": key.Kind, "metadata": map[string]any{"namespace": key.Namespace, "name": key.Name, "uid": "original", "resourceVersion": "17"}}}
						if _, err := client.probeOperation(t.Context(), operation, object, "", "", ""); err == nil || requests.Load() != before {
							t.Fatal("SSAR-only purpose reached mutation wire")
						}
					}
				}
				if _, err := client.proofRequest(t.Context(), http.MethodGet, "/version", nil, &metav1.APIResourceList{}); err == nil || requests.Load() != before {
					t.Fatal("SSAR-only client became a generic read client")
				}
				if unsupported, err := admin.baselineDeniedClient(destroyAdministratorActor, scope); err == nil || unsupported != nil {
					t.Fatal("administrator actor admitted to two-software-actor protocol")
				}
			})
		}
	}
}

func TestBaselineDeniedProxyPortsAndAliasScope(t *testing.T) {
	for _, port := range []int64{8443, 0, 65536} {
		f, access, objects := baselineDeniedFixture(t)
		key := installstate.Key{APIVersion: "v1", Kind: "Pod", Namespace: f.plan.Namespace(), Name: "generated-pods-bcdfg"}
		object := objects[key]
		if unstructured.SetNestedSlice(object.Object, []any{map[string]any{"name": "controller", "image": f.plan.Manifest().Images.Controller, "ports": []any{map[string]any{"name": "https", "containerPort": port}}}}, "spec", "containers") != nil {
			t.Fatal("literal declared-port fixture unavailable")
		}
		scope, err := f.engine.baselineDeniedCatalog(f.snapshot.Document(), access, objects)
		if port != 8443 {
			if err == nil || scope != nil {
				t.Fatal("invalid declared port supplied proxy scope")
			}
			continue
		}
		if err != nil {
			t.Fatal("declared native Pod port cannot derive proxy scope")
		}
		want := map[string]bool{"generated-pods-bcdfg": true, "generated-pods-bcdfg:": true, ":generated-pods-bcdfg:": true, "http:generated-pods-bcdfg:": true, "https:generated-pods-bcdfg:": true, "generated-pods-bcdfg:8443": true, ":generated-pods-bcdfg:8443": true, "http:generated-pods-bcdfg:8443": true, "https:generated-pods-bcdfg:8443": true}
		for _, actor := range []admissionActor{ordinaryControllerActor, destroyControllerActor} {
			actual := map[string]bool{}
			for _, row := range scope.rows[actor] {
				if row.resource == "pods" && row.subresource == "proxy" && strings.Contains(row.name, "generated-pods-bcdfg") && row.verb == "get" {
					actual[row.name] = true
				}
			}
			if !reflect.DeepEqual(actual, want) {
				t.Fatal("canonical declared-port proxy names differ from independent literal scope")
			}
			identity := actorWireIdentity{actor: actor, purpose: baselineDeniedReviewPurpose, namespace: scope.namespace, username: "system:serviceaccount:" + scope.namespace + ":" + actor.account(), deniedScope: scope}
			for _, name := range []string{"https:generated-pods-bcdfg:9443", "https:generated-pods-bcdfg:+8443", "https:foreign:8443"} {
				if scope.allows(identity, &authv1.ResourceAttributes{Group: "", Version: "v1", Resource: "pods", Subresource: "proxy", Namespace: scope.namespace, Name: name, Verb: "get"}) {
					t.Fatal("canonical scope falsely claims arbitrary port, textual alias or foreign-name coverage")
				}
			}
		}
	}
}
