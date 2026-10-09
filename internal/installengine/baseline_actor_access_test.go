// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installbaseline"
	"github.com/gobha-me/arcadectl/internal/installstate"
	authv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
)

func TestBaselineActorProtocolClosedAndHistoricalRoutesUnchanged(t *testing.T) {
	for _, actor := range []admissionActor{ordinaryControllerActor, destroyControllerActor, destroyAdministratorActor, 255} {
		for _, purpose := range []actorWirePurpose{runtimeAdmissionPurpose, baselineAdmissionPurpose, 255} {
			identity := actorWireIdentity{actor: actor, purpose: purpose, namespace: "isolated-install"}
			for _, row := range []struct {
				version, kind, name string
				op                  admissionProbeOperation
				baseline            bool
				ordinaryOnly        bool
			}{
				{"batch/v1", "Job", "inert-probe", probeCreateOperation, true, false},
				{"batch/v1", "Job", "original-probe", probeUpdateOperation, true, false},
				{"batch/v1", "Job", "original-probe", probeDeleteExecutableOperation, true, false},
				{"apps/v1", "Deployment", "inert-probe", probeCreateOperation, true, true},
				{"apps/v1", "Deployment", "arcadectl-controller", probeUpdateOperation, true, true},
				{"apps/v1", "Deployment", "arcadectl-controller", probeDeleteExecutableOperation, true, true},
				{"v1", "Pod", "inert-probe", probeUpdateOperation, true, false},
				{"v1", "ServiceAccount", "arcadectl-destroy-controller", probeDeleteAccountOperation, true, false},
				{"v1", "ServiceAccount", "default", probeDeleteAccountOperation, false, false},
				{"v1", "ServiceAccount", "arcadectl-api", probeCreateOperation, true, false},
				{"v1", "Service", "arcadectl-api", probeCreateOperation, true, true},
				{"v1", "Service", "arcadectl-api", probeUpdateOperation, true, true},
				{"v1", "Service", "arcadectl-api", probeDeleteIdentityOperation, true, true},
				{"v1", "Service", "arcadectl-api", probePatchMetadataOperation, true, true},
				{"apps/v1", "Deployment", "arcadectl-api", probePatchMetadataOperation, true, true},
				{"rbac.authorization.k8s.io/v1", "Role", "arcadectl-controller", probeCreateOperation, true, false},
				{"rbac.authorization.k8s.io/v1", "Role", "arcadectl-controller", probeDeleteIdentityOperation, true, false},
				{"rbac.authorization.k8s.io/v1", "RoleBinding", "arcadectl-controller", probeCreateOperation, true, false},
				{"rbac.authorization.k8s.io/v1", "RoleBinding", "arcadectl-controller", probeDeleteIdentityOperation, true, false},
				{"rbac.authorization.k8s.io/v1", "Role", "unreserved", probeCreateOperation, false, false},
				{"v1", "Service", "unreserved", probeCreateOperation, false, false},
				{"v1", "PersistentVolumeClaim", "world", probeDeletePVCOperation, false, false},
				{"v1", "PersistentVolumeClaim", "world", probeDeleteExecutableOperation, false, false},
				{"v1", "Pod", "original-probe", probeDeleteExecutableOperation, false, false},
				{"arcade.gobha.me/v1alpha1", "GameDestroy", "world", probeCreateOperation, false, false},
				{"v1", "Pod", "inert-probe", probeEphemeralOperation, false, false},
				{"v1", "Pod", "inert-probe", probeResizeOperation, false, false},
				{"batch/v1", "CronJob", "inert-probe", probeCreateOperation, false, false},
			} {
				key := installstate.Key{APIVersion: row.version, Kind: row.kind, Namespace: identity.namespace, Name: row.name}
				if purpose == baselineAdmissionPurpose {
					want := row.baseline && (actor == ordinaryControllerActor || actor == destroyControllerActor) && (!row.ordinaryOnly || actor == ordinaryControllerActor)
					if identity.allows(key, row.op) != want {
						t.Fatal("baseline operation matrix escaped its finite protocol")
					}
				} else if purpose == 255 && identity.allows(key, row.op) {
					t.Fatal("unknown wire purpose accepted")
				} else if purpose == runtimeAdmissionPurpose && (row.kind == "Job" || row.kind == "Deployment" || row.kind == "ServiceAccount") && identity.allows(key, row.op) {
					t.Fatal("baseline widened a historical runtime operation")
				}
				key.Namespace = "foreign"
				if identity.allows(key, row.op) {
					t.Fatal("foreign namespace admitted")
				}
			}
		}
	}
}

func TestBaselineActorReviewProtocolAndNegativeEvidence(t *testing.T) {
	identity := actorWireIdentity{actor: ordinaryControllerActor, purpose: baselineAdmissionPurpose, namespace: "isolated-install"}
	for _, row := range []authv1.ResourceAttributes{
		{Group: "batch", Resource: "jobs", Verb: "create"},
		{Group: "batch", Resource: "jobs", Name: "original-job", Verb: "update"},
		{Group: "batch", Resource: "jobs", Name: "original-job", Verb: "delete"},
		{Group: "batch", Resource: "jobs", Name: "arcadectl-controller", Verb: "patch"},
		{Group: "apps", Resource: "deployments", Verb: "create"},
		{Group: "apps", Resource: "deployments", Name: "original-deployment", Verb: "delete"},
		{Resource: "pods", Name: "original-pod", Verb: "update"},
		{Resource: "serviceaccounts", Name: "arcadectl-destroy-controller", Verb: "delete"},
		{Group: "apps", Resource: "replicasets", Verb: "create"},
		{Group: "apps", Resource: "daemonsets", Verb: "create"},
		{Group: "apps", Resource: "statefulsets", Name: "arcadectl-controller", Verb: "delete"},
		{Resource: "replicationcontrollers", Name: "arcadectl-controller", Verb: "update"},
		{Resource: "pods", Name: "arcadectl-controller", Verb: "patch"},
		{Group: "batch", Resource: "cronjobs", Name: "arcadectl-controller", Verb: "patch"},
		{Group: "apps", Resource: "deployments", Subresource: "scale", Name: "arcadectl-controller", Verb: "update"},
	} {
		row.Namespace, row.Version = identity.namespace, "v1"
		review := &authv1.SelfSubjectAccessReview{TypeMeta: metav1.TypeMeta{APIVersion: "authorization.k8s.io/v1", Kind: "SelfSubjectAccessReview"}, Spec: authv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &row}}
		if !identity.allowsReview(review) {
			t.Fatal("fixed baseline review refused")
		}
		for _, mutate := range []func(*authv1.SelfSubjectAccessReview){
			func(r *authv1.SelfSubjectAccessReview) { r.Spec.ResourceAttributes.Namespace = "foreign" },
			func(r *authv1.SelfSubjectAccessReview) { r.Spec.ResourceAttributes.Version = "v2" },
			func(r *authv1.SelfSubjectAccessReview) { r.Spec.ResourceAttributes.Subresource = "status" },
			func(r *authv1.SelfSubjectAccessReview) {
				r.Spec.ResourceAttributes.FieldSelector = &authv1.FieldSelectorAttributes{RawSelector: "metadata.name=x"}
			},
			func(r *authv1.SelfSubjectAccessReview) { r.Labels = map[string]string{"foreign": "authority"} },
		} {
			changed := review.DeepCopy()
			mutate(changed)
			if identity.allowsReview(changed) {
				t.Fatal("unscoped baseline review accepted")
			}
		}
	}
	for _, row := range []struct {
		name, body string
		valid      bool
	}{
		{"denied", `{"allowed":false}`, true},
		{"explicit-denied", `{"allowed":false,"denied":true}`, true},
		{"no-opinion", `{"allowed":false,"denied":false}`, true},
		{"allowed", `{"allowed":true}`, false},
		{"missing", `{}`, false},
		{"null", `{"allowed":null}`, false},
		{"malformed-denied", `{"allowed":false,"denied":null}`, false},
		{"evaluation-error", `{"allowed":false,"evaluationError":"PRIVATE-CANARY"}`, false},
		{"unknown", `{"allowed":false,"foreign":true}`, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			spec := authv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authv1.ResourceAttributes{Version: "v1", Resource: "serviceaccounts", Namespace: identity.namespace, Name: "arcadectl-destroy-controller", Verb: "impersonate"}}
			a := proofServer(t, func(w http.ResponseWriter, r *http.Request) {
				var body map[string]any
				_ = json.NewDecoder(r.Body).Decode(&body)
				var status map[string]any
				_ = json.Unmarshal([]byte(row.body), &status)
				body["status"] = status
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(body)
			})
			if err := a.authorizationDecision(t.Context(), spec, false); (err == nil) != row.valid || err != nil && strings.Contains(err.Error(), "CANARY") {
				t.Fatal("negative authorization mistook missing/error/allowed evidence for containment")
			}
		})
	}
}

func TestBaselineActorProbeExactGroupIdentityAndDryDelete(t *testing.T) {
	for _, actor := range []admissionActor{ordinaryControllerActor, destroyControllerActor} {
		for _, row := range []struct {
			version, kind, name, family string
			op                          admissionProbeOperation
		}{
			{"batch/v1", "Job", "inert-job", "template", probeCreateOperation},
			{"batch/v1", "Job", "original-job", "template", probeUpdateOperation},
			{"batch/v1", "Job", "original-job", "template", probeDeleteExecutableOperation},
			{"apps/v1", "Deployment", "inert-deployment", "template", probeCreateOperation},
			{"apps/v1", "Deployment", "arcadectl-controller", "template", probeUpdateOperation},
			{"apps/v1", "Deployment", "arcadectl-controller", "template", probeDeleteExecutableOperation},
			{"v1", "Pod", "original-pod", "pod", probeUpdateOperation},
			{"v1", "ServiceAccount", "arcadectl-destroy-controller", "identity", probeDeleteAccountOperation},
		} {
			if actor == destroyControllerActor && row.kind == "Deployment" {
				continue // independent zero-wire refusal controls below
			}
			t.Run(fmt.Sprintf("%s-%s-%d", actor.account(), row.kind, row.op), func(t *testing.T) {
				key := installstate.Key{APIVersion: row.version, Kind: row.kind, Namespace: "isolated-install", Name: row.name}
				object := &unstructured.Unstructured{Object: map[string]any{"apiVersion": key.APIVersion, "kind": key.Kind, "metadata": map[string]any{"name": key.Name, "namespace": key.Namespace}}}
				if row.op != probeCreateOperation {
					object.SetUID("original-uid")
					object.SetResourceVersion("17")
				}
				policy := "arcadectl-identity-" + row.family + "-" + key.Namespace
				var requests atomic.Int32
				server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					requests.Add(1)
					path, plural := "", ""
					switch row.kind {
					case "Job":
						path, plural = "/apis/batch/v1/namespaces/isolated-install/jobs", "jobs"
					case "Deployment":
						path, plural = "/apis/apps/v1/namespaces/isolated-install/deployments", "deployments"
					case "Pod":
						path, plural = "/api/v1/namespaces/isolated-install/pods", "pods"
					case "ServiceAccount":
						path, plural = "/api/v1/namespaces/isolated-install/serviceaccounts", "serviceaccounts"
					}
					if row.op != probeCreateOperation {
						path += "/" + key.Name
					}
					if r.URL.Path != path || r.Header.Get("Impersonate-User") != "system:serviceaccount:isolated-install:"+actor.account() || r.Header.Get("Authorization") != "Bearer FAKE-ADMIN-CANARY" {
						t.Error("baseline probe changed original identity or route")
					}
					body, _ := io.ReadAll(r.Body)
					if row.op == probeDeleteAccountOperation || row.op == probeDeleteExecutableOperation {
						var opts metav1.DeleteOptions
						if r.Method != "DELETE" || r.URL.RawQuery != "dryRun=All" || json.Unmarshal(body, &opts) != nil || !reflect.DeepEqual(opts.DryRun, []string{"All"}) || opts.Preconditions == nil || opts.Preconditions.UID == nil || *opts.Preconditions.UID != object.GetUID() || opts.Preconditions.ResourceVersion == nil || *opts.Preconditions.ResourceVersion != "17" {
							t.Error("account delete lost body dry-run or original preconditions")
						}
					} else if r.URL.RawQuery != "dryRun=All&fieldManager=arcadectl-installer&fieldValidation=Strict" {
						t.Error("baseline dry-run/strict fields removed")
					}
					if row.op == probeCreateOperation || row.op == probeUpdateOperation {
						method := "POST"
						if row.op == probeUpdateOperation {
							method = "PUT"
						}
						var decoded map[string]any
						if r.Method != method || json.Unmarshal(body, &decoded) != nil || !reflect.DeepEqual(decoded, object.Object) {
							t.Error("baseline probe changed original whole body or operation")
						}
					}
					// Independent literal native denial oracle, not the production
					// expected-denial constructor under test.
					group := ""
					if row.version == "batch/v1" {
						group = "batch"
					} else if row.version == "apps/v1" {
						group = "apps"
					}
					resource := plural
					if group != "" {
						resource += "." + group
					}
					cause := fmt.Sprintf("ValidatingAdmissionPolicy '%s' with binding '%s' denied request: %s", policy, policy, installbaseline.DenialMessage)
					status := metav1.Status{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: "Failure", Code: 422, Reason: metav1.StatusReasonInvalid,
						Message: fmt.Sprintf("%s %q is forbidden: %s", resource, key.Name, cause), Details: &metav1.StatusDetails{Group: group, Kind: plural, Name: key.Name, Causes: []metav1.StatusCause{{Message: cause}}}}
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(422)
					_ = json.NewEncoder(w).Encode(status)
				}))
				t.Cleanup(server.Close)
				config := serverConfig(server)
				config.BearerToken = "FAKE-ADMIN-CANARY"
				admin, err := NewDirectHTTPAccess(config)
				if err != nil {
					t.Fatal("original admin fixture unavailable")
				}
				client, err := admin.actorClientForPurpose(actor, key.Namespace, baselineAdmissionPurpose)
				if err != nil {
					t.Fatal("closed baseline actor unavailable")
				}
				if result, err := client.probeOperation(t.Context(), row.op, object, policy, policy, installbaseline.DenialMessage); err != nil || result != nil || requests.Load() != 1 {
					t.Fatal("exact baseline dry-run denial refused or replayed")
				}
				before := requests.Load()
				for _, wrong := range []string{"foreign-policy", "arcadectl-identity-pod-foreign"} {
					if _, err := client.probeOperation(t.Context(), row.op, object, wrong, wrong, installbaseline.DenialMessage); err != ErrInvalid {
						t.Fatal("foreign policy family accepted")
					}
				}
				if _, err := client.Get(t.Context(), key); err == nil || requests.Load() != before {
					t.Fatal("baseline actor exposed generic GET or sent unproved request")
				}
				if row.op == probeDeleteAccountOperation || row.op == probeDeleteExecutableOperation {
					if _, err := client.probeOperation(t.Context(), row.op, object, "", "", ""); err != ErrInvalid || requests.Load() != before {
						t.Fatal("account DELETE accepted a positive effect protocol")
					}
				}
			})
		}
	}
}

func TestBaselineExecutableDeletesArePinnedAttributedNegativeOnly(t *testing.T) {
	for _, actor := range []admissionActor{ordinaryControllerActor, destroyControllerActor} {
		for _, row := range []struct{ version, kind, plural, group, path string }{
			{"batch/v1", "Job", "jobs", "batch", "/apis/batch/v1/namespaces/isolated-install/jobs/original"},
			{"apps/v1", "Deployment", "deployments", "apps", "/apis/apps/v1/namespaces/isolated-install/deployments/original"},
		} {
			t.Run(actor.account()+"-"+row.kind, func(t *testing.T) {
				original := &unstructured.Unstructured{Object: map[string]any{"apiVersion": row.version, "kind": row.kind, "metadata": map[string]any{"namespace": "isolated-install", "name": "original", "uid": "original-uid", "resourceVersion": "17"}}}
				policy := "arcadectl-identity-template-isolated-install"
				var count atomic.Int32
				var responseMode atomic.Value
				responseMode.Store("valid")
				server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					mode := responseMode.Load().(string)
					count.Add(1)
					if r.Method != "DELETE" || r.URL.Path != row.path || r.URL.RawQuery != "dryRun=All" || r.Header.Get("Impersonate-User") != "system:serviceaccount:isolated-install:"+actor.account() {
						t.Error("executable denial escaped its literal exact route/identity")
					}
					var body map[string]any
					if json.NewDecoder(r.Body).Decode(&body) != nil || !reflect.DeepEqual(body, map[string]any{"apiVersion": "v1", "kind": "DeleteOptions", "dryRun": []any{"All"}, "preconditions": map[string]any{"uid": "original-uid", "resourceVersion": "17"}}) {
						t.Error("executable delete omitted dry-run or exact original preconditions")
					}
					code := 422
					switch mode {
					case "accepted":
						code = 200
					case "async":
						code = 202
					case "forbidden":
						code = 403
					case "missing":
						code = 404
					case "conflict":
						code = 409
					}
					cause := fmt.Sprintf("ValidatingAdmissionPolicy '%s' with binding '%s' denied request: %s", policy, policy, installbaseline.DenialMessage)
					status := metav1.Status{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: "Failure", Code: int32(code), Reason: metav1.StatusReasonInvalid,
						Message: fmt.Sprintf("%s.%s %q is forbidden: %s", row.plural, row.group, "original", cause), Details: &metav1.StatusDetails{Group: row.group, Kind: row.plural, Name: "original", Causes: []metav1.StatusCause{{Message: cause}}}}
					if mode == "wrong-group" {
						status.Details.Group = "foreign"
					}
					if mode == "wrong-policy" {
						status.Details.Causes[0].Message = "PRIVATE-CANARY"
					}
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(code)
					if mode == "malformed" {
						_, _ = w.Write([]byte(`{"kind":"Status","private":"PRIVATE-CANARY"}`))
						return
					}
					_ = json.NewEncoder(w).Encode(status)
				}))
				t.Cleanup(server.Close)
				admin, err := NewDirectHTTPAccess(serverConfig(server))
				if err != nil {
					t.Fatal("original transport unavailable")
				}
				client, err := admin.actorClientForPurpose(actor, "isolated-install", baselineAdmissionPurpose)
				if err != nil {
					t.Fatal("baseline actor unavailable")
				}
				for _, scenario := range []string{"valid", "accepted", "async", "forbidden", "missing", "conflict", "wrong-group", "wrong-policy", "malformed"} {
					responseMode.Store(scenario)
					before := count.Load()
					result, err := client.probeOperation(t.Context(), probeDeleteExecutableOperation, original, policy, policy, installbaseline.DenialMessage)
					allowed := actor == ordinaryControllerActor || row.kind == "Job"
					if result != nil || (err == nil) != (allowed && scenario == "valid") || count.Load()-before != map[bool]int32{true: 1, false: 0}[allowed] {
						t.Fatal("executable deletion mistook success/foreign failure/forbidden route for attributed denial")
					}
				}
				before := count.Load()
				if actor == destroyControllerActor && row.kind == "Deployment" {
					for _, operation := range []admissionProbeOperation{probeCreateOperation, probeUpdateOperation} {
						candidate := original.DeepCopy()
						if operation == probeCreateOperation {
							candidate.SetUID("")
							candidate.SetResourceVersion("")
						}
						if _, err := client.probeOperation(t.Context(), operation, candidate, policy, policy, installbaseline.DenialMessage); err != ErrInvalid {
							t.Fatal("destroy actor gained Deployment mutation route")
						}
					}
				}
				for _, rv := range []string{"", "0", "00", "017", "-1", "18446744073709551616", "0x11", "invalid"} {
					bad := original.DeepCopy()
					bad.SetResourceVersion(rv)
					if _, err := client.probeOperation(t.Context(), probeDeleteExecutableOperation, bad, policy, policy, installbaseline.DenialMessage); err != ErrInvalid {
						t.Fatal("unpinned executable deletion admitted")
					}
				}
				for _, uid := range []string{"", "invalid uid", "/foreign"} {
					bad := original.DeepCopy()
					bad.SetUID(types.UID(uid))
					if _, err := client.probeOperation(t.Context(), probeDeleteExecutableOperation, bad, policy, policy, installbaseline.DenialMessage); err != ErrInvalid {
						t.Fatal("unidentified executable deletion admitted")
					}
				}
				if _, err := client.probeOperation(t.Context(), probeDeleteExecutableOperation, original, "", "", ""); err != ErrInvalid {
					t.Fatal("positive executable DELETE primitive exposed")
				}
				runtimeClient, err := admin.actorClientForPurpose(actor, "isolated-install", runtimeAdmissionPurpose)
				if err != nil {
					t.Fatal("historical transport unavailable")
				}
				for _, other := range []*HTTPAccess{admin, runtimeClient} {
					if _, err := other.probeOperation(t.Context(), probeDeleteExecutableOperation, original, policy, policy, installbaseline.DenialMessage); err != ErrInvalid {
						t.Fatal("nonbaseline executable DELETE exposed")
					}
				}
				if count.Load() != before {
					t.Fatal("refused executable delete reached wire")
				}
			})
		}
	}
}
