// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installbaseline"
	"github.com/gobha-me/arcadectl/internal/installstate"
	authv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
)

func TestBaselineIdentityAndPatchFiniteNegativeProtocol(t *testing.T) {
	const namespace = "isolated-install"
	for _, actorID := range []admissionActor{ordinaryControllerActor, destroyControllerActor} {
		for _, name := range []string{"arcadectl-controller", "arcadectl-api", "arcadectl-destroy-controller", "arcadectl-destroy-admin"} {
			for _, row := range []struct {
				version, kind, group, plural, path, family string
				ops                                        []admissionProbeOperation
				ordinary                                   bool
			}{
				{"v1", "ServiceAccount", "", "serviceaccounts", "/api/v1", "identity", []admissionProbeOperation{probeCreateOperation, probeDeleteAccountOperation}, false},
				{"rbac.authorization.k8s.io/v1", "Role", "rbac.authorization.k8s.io", "roles", "/apis/rbac.authorization.k8s.io/v1", "identity", []admissionProbeOperation{probeCreateOperation, probeDeleteIdentityOperation}, false},
				{"rbac.authorization.k8s.io/v1", "RoleBinding", "rbac.authorization.k8s.io", "rolebindings", "/apis/rbac.authorization.k8s.io/v1", "identity", []admissionProbeOperation{probeCreateOperation, probeDeleteIdentityOperation}, false},
				{"v1", "Service", "", "services", "/api/v1", "identity", []admissionProbeOperation{probeCreateOperation, probeUpdateOperation, probePatchMetadataOperation, probeDeleteIdentityOperation}, true},
				{"apps/v1", "Deployment", "apps", "deployments", "/apis/apps/v1", "template", []admissionProbeOperation{probePatchMetadataOperation}, true},
			} {
				for _, operation := range row.ops {
					t.Run(fmt.Sprintf("%s-%s-%s-%d", actorID.account(), name, row.kind, operation), func(t *testing.T) {
						object := &unstructured.Unstructured{Object: map[string]any{"apiVersion": row.version, "kind": row.kind, "metadata": map[string]any{"namespace": namespace, "name": name, "annotations": map[string]any{"private-test-field": "PRIVATE-CANARY"}}, "spec": map[string]any{"private-test-field": "PRIVATE-CANARY"}}}
						if operation != probeCreateOperation {
							object.SetUID("original-uid")
							object.SetResourceVersion("17")
						}
						original := object.DeepCopy()
						policy := "arcadectl-identity-" + row.family + "-" + namespace
						var requests atomic.Int32
						var mode atomic.Value
						mode.Store("exact")
						server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
							requests.Add(1)
							path := row.path + "/namespaces/" + namespace + "/" + row.plural
							if operation != probeCreateOperation {
								path += "/" + name
							}
							method, typ, query := "POST", "application/json", "dryRun=All&fieldManager=arcadectl-installer&fieldValidation=Strict"
							if operation == probeUpdateOperation {
								method = "PUT"
							}
							if operation == probePatchMetadataOperation {
								method, typ = "PATCH", "application/merge-patch+json"
							}
							if operation == probeDeleteAccountOperation || operation == probeDeleteIdentityOperation {
								method, query = "DELETE", "dryRun=All"
							}
							if r.Method != method || r.URL.Path != path || r.URL.RawQuery != query || r.Header.Get("Content-Type") != typ || r.Header.Get("Accept") != "application/json" || r.Header.Get("Impersonate-User") != "system:serviceaccount:"+namespace+":"+actorID.account() || r.Header.Get("Authorization") != "Bearer FAKE-ADMIN-CANARY" {
								t.Error("identity protocol changed its fixed method, route, MIME or credentials")
							}
							body, _ := io.ReadAll(r.Body)
							var actual map[string]any
							if json.Unmarshal(body, &actual) != nil {
								t.Error("identity protocol body malformed")
							}
							var want any = object.Object
							if operation == probePatchMetadataOperation {
								want = map[string]any{"metadata": map[string]any{"uid": "original-uid", "resourceVersion": "17", "annotations": map[string]any{"arcade.gobha.me/identity-probe": "dry-run"}}}
							}
							if method == "DELETE" {
								want = map[string]any{"apiVersion": "v1", "kind": "DeleteOptions", "dryRun": []any{"All"}, "preconditions": map[string]any{"uid": "original-uid", "resourceVersion": "17"}}
							}
							if !reflect.DeepEqual(actual, want) {
								t.Error("identity protocol forwarded caller patch fields or lost whole body/preconditions")
							}
							cause := fmt.Sprintf("ValidatingAdmissionPolicy '%s' with binding '%s' denied request: %s", policy, policy, installbaseline.DenialMessage)
							resource := row.plural
							if row.group != "" {
								resource += "." + row.group
							}
							status := metav1.Status{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: "Failure", Code: 422, Reason: metav1.StatusReasonInvalid, Message: fmt.Sprintf("%s %q is forbidden: %s", resource, name, cause), Details: &metav1.StatusDetails{Group: row.group, Kind: row.plural, Name: name, Causes: []metav1.StatusCause{{Message: cause}}}}
							code := 422
							switch mode.Load().(string) {
							case "success":
								code = 200
							case "created":
								code = 201
							case "async":
								code = 202
							case "rbac":
								code = 403
							case "missing":
								code = 404
							case "conflict":
								code = 409
							case "wrong-group":
								status.Details.Group = "foreign"
							case "wrong-policy":
								status.Details.Causes[0].Message = "PRIVATE-CANARY"
							}
							w.Header().Set("Content-Type", "application/json")
							w.WriteHeader(code)
							_ = json.NewEncoder(w).Encode(status)
						}))
						defer server.Close()
						config := serverConfig(server)
						config.BearerToken = "FAKE-ADMIN-CANARY"
						admin, err := NewDirectHTTPAccess(config)
						if err != nil {
							t.Fatal("original identity protocol fixture unavailable")
						}
						actor, err := admin.actorClientForPurpose(actorID, namespace, baselineAdmissionPurpose)
						if err != nil {
							t.Fatal("closed identity actor unavailable")
						}
						allowed := !row.ordinary || actorID == ordinaryControllerActor
						key := installstate.Key{APIVersion: row.version, Kind: row.kind, Namespace: namespace, Name: name}
						permission, err := baselineActorPermission(actor.actor, key, operation)
						verb, reviewName := "update", name
						if operation == probeCreateOperation {
							verb, reviewName = "create", ""
						} else if operation == probePatchMetadataOperation {
							verb = "patch"
						} else if operation == probeDeleteAccountOperation || operation == probeDeleteIdentityOperation {
							verb = "delete"
						}
						want := authv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authv1.ResourceAttributes{Group: row.group, Version: "v1", Namespace: namespace, Resource: row.plural, Name: reviewName, Verb: verb}}
						if allowed && (err != nil || !reflect.DeepEqual(permission, want) || !actor.actor.baselineAllowsReview(want.ResourceAttributes)) || !allowed && err == nil {
							t.Fatal("identity actor permission differs from literal native operation")
						}
						for _, scenario := range []string{"exact", "success", "created", "async", "rbac", "missing", "conflict", "wrong-group", "wrong-policy"} {
							mode.Store(scenario)
							before := requests.Load()
							result, err := actor.probeOperation(t.Context(), operation, object, policy, policy, installbaseline.DenialMessage)
							if result != nil || (err == nil) != (allowed && scenario == "exact") || requests.Load()-before != map[bool]int32{true: 1, false: 0}[allowed] {
								t.Fatal("identity proof accepted success/foreign denial, widened a route or replayed")
							}
						}
						before := requests.Load()
						for _, attribution := range [][3]string{{"", "", ""}, {policy, "", ""}, {"foreign", policy, installbaseline.DenialMessage}, {policy, policy, "foreign"}} {
							if _, err := actor.probeOperation(t.Context(), operation, object, attribution[0], attribution[1], attribution[2]); err == nil || requests.Load() != before {
								t.Fatal("identity probe without exact attribution reached the wire")
							}
						}
						if operation != probeCreateOperation {
							for _, uid := range []string{"", "/invalid", "invalid uid", "\x00"} {
								bad := object.DeepCopy()
								bad.SetUID(types.UID(uid))
								if _, err := actor.probeOperation(t.Context(), operation, bad, policy, policy, installbaseline.DenialMessage); err == nil || requests.Load() != before {
									t.Fatal("identity probe accepted an invalid original UID")
								}
							}
							for _, rv := range []string{"", "0", "00", "017", "-1", "18446744073709551616"} {
								bad := object.DeepCopy()
								bad.SetResourceVersion(rv)
								if _, err := actor.probeOperation(t.Context(), operation, bad, policy, policy, installbaseline.DenialMessage); err == nil || requests.Load() != before {
									t.Fatal("identity probe accepted unpinned or noncanonical original")
								}
							}
						}
						if !reflect.DeepEqual(original.Object, object.Object) {
							t.Fatal("identity probe modified caller original")
						}
					})
				}
			}
		}
	}
}

func TestBaselineIdentityAndPatchUnsupportedRoutesZeroWire(t *testing.T) {
	var count atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { count.Add(1); w.WriteHeader(200) }))
	defer server.Close()
	admin, err := NewDirectHTTPAccess(serverConfig(server))
	if err != nil {
		t.Fatal("refusal fixture unavailable")
	}
	clients := []*HTTPAccess{admin}
	for _, actor := range []admissionActor{ordinaryControllerActor, destroyControllerActor} {
		for _, purpose := range []actorWirePurpose{runtimeAdmissionPurpose, baselineAdmissionPurpose} {
			client, err := admin.actorClientForPurpose(actor, "isolated-install", purpose)
			if err != nil {
				t.Fatal("refusal actor unavailable")
			}
			clients = append(clients, client)
		}
	}
	for _, row := range []struct {
		version, kind, name string
		op                  admissionProbeOperation
	}{
		{"v1", "ServiceAccount", "arcadectl-controller", probeUpdateOperation},
		{"v1", "ServiceAccount", "arcadectl-controller", probePatchMetadataOperation},
		{"v1", "ServiceAccount", "unreserved", probeCreateOperation},
		{"v1", "ServiceAccount", "unreserved", probeDeleteAccountOperation},
		{"rbac.authorization.k8s.io/v1", "Role", "arcadectl-controller", probeUpdateOperation},
		{"rbac.authorization.k8s.io/v1", "Role", "arcadectl-controller", probePatchMetadataOperation},
		{"rbac.authorization.k8s.io/v1", "RoleBinding", "arcadectl-controller", probeUpdateOperation},
		{"rbac.authorization.k8s.io/v1", "RoleBinding", "arcadectl-controller", probePatchMetadataOperation},
		{"rbac.authorization.k8s.io/v1", "ClusterRole", "arcadectl-controller", probeDeleteIdentityOperation},
		{"rbac.authorization.k8s.io/v1", "Role", "unreserved", probeDeleteIdentityOperation},
		{"v1", "Service", "unreserved", probePatchMetadataOperation},
		{"v1", "Secret", "arcadectl-controller", probeDeleteIdentityOperation},
		{"v1", "Pod", "arcadectl-controller", probePatchMetadataOperation},
		{"batch/v1", "Job", "arcadectl-controller", probePatchMetadataOperation},
		{"v1", "PersistentVolumeClaim", "arcadectl-controller", probePatchMetadataOperation},
	} {
		object := &unstructured.Unstructured{Object: map[string]any{"apiVersion": row.version, "kind": row.kind, "metadata": map[string]any{"namespace": "isolated-install", "name": row.name}}}
		if row.op != probeCreateOperation {
			object.SetUID("original-uid")
			object.SetResourceVersion("17")
		}
		for _, client := range clients {
			if _, err := client.probeOperation(t.Context(), row.op, object, "arcadectl-identity-identity-isolated-install", "arcadectl-identity-identity-isolated-install", installbaseline.DenialMessage); err == nil || count.Load() != 0 {
				t.Fatal("unsupported identity operation reached the wire")
			}
		}
	}
	for _, client := range clients {
		if client.actor != nil && client.actor.purpose == baselineAdmissionPurpose {
			continue
		}
		object := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "v1", "kind": "Service", "metadata": map[string]any{"namespace": "isolated-install", "name": "arcadectl-controller", "uid": "original-uid", "resourceVersion": "17"}}}
		if _, err := client.probeOperation(t.Context(), probePatchMetadataOperation, object, "arcadectl-identity-identity-isolated-install", "arcadectl-identity-identity-isolated-install", installbaseline.DenialMessage); err == nil || count.Load() != 0 {
			t.Fatal("no-actor or runtime-purpose request entered baseline PATCH")
		}
	}
}

func TestBaselinePatchAndJSONMIMEPinsBothCaptureLayers(t *testing.T) {
	for _, operation := range []admissionProbeOperation{probeUpdateOperation, probePatchMetadataOperation} {
		method, typ := "PUT", "application/json"
		if operation == probePatchMetadataOperation {
			method, typ = "PATCH", "application/merge-patch+json"
		}
		body := []byte(`{"metadata":{"uid":"original","resourceVersion":"17"}}`)
		url := "https://owned.example/api/v1/namespaces/isolated-install/services/arcadectl-api?dryRun=All&fieldManager=arcadectl-installer&fieldValidation=Strict"
		identity := actorWireIdentity{actor: ordinaryControllerActor, purpose: baselineAdmissionPurpose, namespace: "isolated-install", username: "system:serviceaccount:isolated-install:arcadectl-controller", authorization: "Bearer FAKE-CANARY"}
		probe := &probeCapture{method: method, url: url, body: body, operation: operation}
		actor := &actorRequestCapture{identity: identity, method: method, url: url, body: body, contentType: typ}
		for index, mutate := range []func(*http.Request){
			func(r *http.Request) {},
			func(r *http.Request) { r.Header["Content-Type"] = []string{typ, typ} },
			func(r *http.Request) { r.Header["content-type"] = []string{typ} },
			func(r *http.Request) { r.Header.Set("Content-Type", typ+"; charset=utf-8") },
			func(r *http.Request) {
				other := "application/merge-patch+json"
				if operation == probePatchMetadataOperation {
					other = "application/json"
				}
				r.Header.Set("Content-Type", other)
			},
			func(r *http.Request) { r.Header["Accept"] = []string{"application/json", "application/json"} },
			func(r *http.Request) { r.Header["accept"] = []string{"application/json"} },
			func(r *http.Request) { r.Header.Set("Accept", "*/*") },
			func(r *http.Request) { r.Method = "POST" },
			func(r *http.Request) { r.URL.RawQuery = "fieldManager=arcadectl-installer" },
		} {
			for _, guard := range []func(*http.Request) bool{probe.guard, actor.guard} {
				r, err := http.NewRequest(method, url, bytes.NewReader(body))
				if err != nil {
					t.Fatal("unit pinned request unavailable")
				}
				r.GetBody = nil
				r.Header.Set("Content-Type", typ)
				r.Header.Set("Accept", "application/json")
				r.Header.Set("Impersonate-User", identity.username)
				r.Header.Set("Authorization", identity.authorization)
				mutate(r)
				if guard(r) != (index == 0) {
					t.Fatal("capture accepted alias/duplicate MIME or changed pinned request")
				}
				_ = r.Body.Close()
			}
		}
	}
}
