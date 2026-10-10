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

func TestBaselineProxyRulesInspectActualNativeNamedAliases(t *testing.T) {
	guarded := map[installstate.Key]*unstructured.Unstructured{{APIVersion: "v1", Kind: "Pod", Namespace: "rules-proof", Name: "generated-controller-pod"}: {}}
	executables := &baselineExecutables{guarded: guarded}
	for _, resource := range []string{"pods/proxy", "services/proxy", "*/proxy", "*"} {
		for _, name := range []string{"arcadectl-api", "arcadectl-api:", ":arcadectl-api:", "http:arcadectl-api:", "https:arcadectl-api:+443", "arcadectl-api:00443", "https:arcadectl-api:https", "https:arcadectl-api:any-port"} {
			for _, verb := range []string{"get", "create", "update", "patch", "delete", "*"} {
				for _, group := range []string{"", "*"} {
					rule := authv1.ResourceRule{APIGroups: []string{group}, Resources: []string{resource}, Verbs: []string{verb}, ResourceNames: []string{name}}
					if baselineProxyRulesContained(&baselineRulesEvidence{rules: []authv1.ResourceRule{rule}}, executables) {
						t.Fatal("effective native rule hid a protected raw proxy address")
					}
				}
			}
		}
	}
	for _, resource := range []string{"pods/proxy", "*/proxy", "*"} {
		rule := authv1.ResourceRule{APIGroups: []string{""}, Resources: []string{resource}, Verbs: []string{"get"}, ResourceNames: []string{"https:generated-controller-pod:+008443"}}
		if baselineProxyRulesContained(&baselineRulesEvidence{rules: []authv1.ResourceRule{rule}}, executables) {
			t.Fatal("effective rule omitted a generated reserved-identity Pod")
		}
	}
	for _, names := range [][]string{nil, {}} {
		rule := authv1.ResourceRule{APIGroups: []string{""}, Resources: []string{"services/proxy"}, Verbs: []string{"get"}, ResourceNames: names}
		if baselineProxyRulesContained(&baselineRulesEvidence{rules: []authv1.ResourceRule{rule}}, executables) {
			t.Fatal("unrestricted native proxy grant was treated as named containment")
		}
	}
	for _, scenario := range []string{"foreign-name", "literal-star-name", "foreign-group", "resource-prefix-not-wildcard", "base-resource-not-subresource", "legacy-proxy-verb", "unsupported-verb", "invalid-scheme", "too-many-colons", "empty-target", "service-only-generated-pod"} {
		rule := authv1.ResourceRule{APIGroups: []string{""}, Resources: []string{"pods/proxy"}, Verbs: []string{"get"}, ResourceNames: []string{"arcadectl-api:443"}}
		switch scenario {
		case "foreign-name":
			rule.ResourceNames = []string{"https:foreign-api:+443"}
		case "literal-star-name":
			rule.ResourceNames = []string{"*"} // native RBAC resourceNames '*' is literal
		case "foreign-group":
			rule.APIGroups = []string{"foreign.example"}
		case "resource-prefix-not-wildcard":
			rule.Resources = []string{"pods/*"}
		case "base-resource-not-subresource":
			rule.Resources = []string{"pods"}
		case "legacy-proxy-verb":
			rule.Verbs = []string{"proxy"}
		case "unsupported-verb":
			rule.Verbs = []string{"watch"}
		case "invalid-scheme":
			rule.ResourceNames = []string{"ssh:arcadectl-api:443"}
		case "too-many-colons":
			rule.ResourceNames = []string{"https:arcadectl-api:443:extra"}
		case "empty-target":
			rule.ResourceNames = []string{"https::443"}
		case "service-only-generated-pod":
			rule.Resources = []string{"services/proxy"}
			rule.ResourceNames = []string{"generated-controller-pod:8443"}
		}
		if !baselineProxyRulesContained(&baselineRulesEvidence{rules: []authv1.ResourceRule{rule}}, executables) {
			t.Fatal("effective rules invented a native proxy permission")
		}
	}
}

func TestBaselineRulesOnlyWireAndCompleteRawEvidence(t *testing.T) {
	for _, scenario := range []string{"healthy", "reordered", "changed-raw-alias", "duplicate-rule", "duplicate-element", "incomplete", "missing-incomplete", "null-incomplete", "evaluation-error", "null-evaluation-error", "missing-resource-rules", "null-resource-rules", "missing-nonresource-rules", "null-nonresource-rules", "missing-verbs", "null-verbs", "null-names", "empty-groups", "unknown-rule-field", "unknown-status-field", "duplicate-status-field", "echoed-namespace", "missing-spec", "null-spec", "foreign-kind", "foreign-metadata", "forbidden"} {
		for _, actor := range []admissionActor{ordinaryControllerActor, destroyControllerActor} {
			t.Run(scenario+"/"+actor.account(), func(t *testing.T) {
				var calls atomic.Int32
				server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					call := calls.Add(1)
					w.Header().Set("Content-Type", "application/json")
					if r.Method != http.MethodPost || r.URL.Path != "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews" || r.URL.RawQuery != "fieldManager=arcadectl-installer&fieldValidation=Strict" || r.Header.Get("Authorization") != "Bearer FAKE-RULES-ONLY" || r.Header.Get("Impersonate-User") != "system:serviceaccount:rules-proof:"+actor.account() {
						t.Error("rules-only transport widened route, operation or identity")
					}
					var request map[string]any
					if json.NewDecoder(r.Body).Decode(&request) != nil || !reflect.DeepEqual(request["spec"], map[string]any{"namespace": "rules-proof"}) {
						t.Error("rules-only request widened beyond the original namespace")
					}
					rule := map[string]any{"verbs": []any{"get", "watch"}, "apiGroups": []any{""}, "resources": []any{"pods/proxy"}, "resourceNames": []any{"https:foreign-pod:+443", "foreign-pod:00443"}}
					nonrule := map[string]any{"verbs": []any{"get", "head"}, "nonResourceURLs": []any{"/version", "/healthz"}}
					other := map[string]any{"verbs": []any{"list"}, "apiGroups": []any{"batch"}, "resources": []any{"jobs"}}
					otherNonresource := map[string]any{"verbs": []any{"get"}, "nonResourceURLs": []any{"/livez"}}
					status := map[string]any{"incomplete": false, "resourceRules": []any{rule, other}, "nonResourceRules": []any{nonrule, otherNonresource}}
					reply := map[string]any{"apiVersion": "authorization.k8s.io/v1", "kind": "SelfSubjectRulesReview", "metadata": map[string]any{"creationTimestamp": nil}, "spec": map[string]any{}, "status": status}
					if call > 1 {
						switch scenario {
						case "reordered":
							status["resourceRules"], status["nonResourceRules"] = []any{other, rule}, []any{otherNonresource, nonrule}
							rule["verbs"] = []any{"watch", "get"}
							rule["resourceNames"] = []any{"foreign-pod:00443", "https:foreign-pod:+443"}
							nonrule["verbs"], nonrule["nonResourceURLs"] = []any{"head", "get"}, []any{"/healthz", "/version"}
						case "changed-raw-alias":
							rule["resourceNames"] = []any{"https:foreign-pod:443", "foreign-pod:00443"}
						case "duplicate-rule":
							status["resourceRules"] = []any{rule, other, rule}
						case "duplicate-element":
							rule["resourceNames"] = []any{"https:foreign-pod:+443", "foreign-pod:00443", "foreign-pod:00443"}
						case "incomplete":
							status["incomplete"] = true
						case "missing-incomplete":
							delete(status, "incomplete")
						case "null-incomplete":
							status["incomplete"] = nil
						case "evaluation-error":
							status["evaluationError"] = "PRIVATE-ERROR-CANARY"
						case "null-evaluation-error":
							status["evaluationError"] = nil
						case "missing-resource-rules":
							delete(status, "resourceRules")
						case "null-resource-rules":
							status["resourceRules"] = nil
						case "missing-nonresource-rules":
							delete(status, "nonResourceRules")
						case "null-nonresource-rules":
							status["nonResourceRules"] = nil
						case "missing-verbs":
							delete(rule, "verbs")
						case "null-verbs":
							rule["verbs"] = nil
						case "null-names":
							rule["resourceNames"] = nil
						case "empty-groups":
							rule["apiGroups"] = []any{}
						case "unknown-rule-field":
							rule["foreign"] = "PRIVATE-FIELD-CANARY"
						case "unknown-status-field":
							status["foreign"] = "PRIVATE-FIELD-CANARY"
						case "duplicate-status-field":
							_, _ = w.Write([]byte(`{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectRulesReview","spec":{},"status":{"incomplete":true,"incomplete":false,"resourceRules":[],"nonResourceRules":[]}}`))
							return
						case "echoed-namespace":
							reply["spec"] = map[string]any{"namespace": "rules-proof"}
						case "missing-spec":
							delete(reply, "spec")
						case "null-spec":
							reply["spec"] = nil
						case "foreign-kind":
							reply["kind"] = "SelfSubjectAccessReview"
						case "foreign-metadata":
							reply["metadata"] = map[string]any{"name": "persistent-review"}
						case "forbidden":
							w.WriteHeader(http.StatusForbidden)
							reply = map[string]any{"message": "PRIVATE-ERROR-CANARY"}
						}
					}
					_ = json.NewEncoder(w).Encode(reply)
				}))
				t.Cleanup(server.Close)
				config := serverConfig(server)
				config.BearerToken = "FAKE-RULES-ONLY"
				admin, err := NewDirectHTTPAccess(config)
				if err != nil {
					t.Fatal("rules-only test original transport unavailable")
				}
				client, err := admin.baselineRulesClient(actor, "rules-proof")
				if err != nil {
					t.Fatal("rules-only closed client unavailable")
				}
				before, err := client.baselineRules(t.Context())
				if err != nil || before == nil {
					t.Fatal("rules-only complete opening reply refused")
				}
				after, err := client.baselineRules(t.Context())
				valid := scenario == "healthy" || scenario == "reordered" || scenario == "changed-raw-alias" || scenario == "duplicate-rule" || scenario == "duplicate-element"
				if (err == nil) != valid || err != nil && strings.Contains(err.Error(), "CANARY") || valid && sameBaselineRules(before, after) != (scenario == "healthy" || scenario == "reordered") {
					t.Fatal("rules-only reply lost completeness, raw names or duplicate multiplicity")
				}
				requests := calls.Load()
				if client.authorize(t.Context(), authv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authv1.ResourceAttributes{Version: "v1", Resource: "pods", Verb: "get", Namespace: "rules-proof"}}) == nil {
					t.Fatal("rules-only client acquired SSAR capability")
				}
				request := &authv1.SelfSubjectRulesReview{TypeMeta: metav1.TypeMeta{APIVersion: "authorization.k8s.io/v1", Kind: "SelfSubjectRulesReview"}, Spec: authv1.SelfSubjectRulesReviewSpec{Namespace: "foreign"}}
				var reply authv1.SelfSubjectRulesReview
				if _, err := client.proofRequest(t.Context(), http.MethodPost, "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews", request, &reply); err == nil {
					t.Fatal("rules-only client changed namespace")
				}
				if err := client.checkVersion(t.Context(), fixturePlan(t).Profile()); err == nil {
					t.Fatal("rules-only client acquired generic reads")
				}
				key := installstate.Key{APIVersion: "batch/v1", Kind: "Job", Namespace: "rules-proof", Name: "unprivileged"}
				object := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "batch/v1", "kind": "Job", "metadata": map[string]any{"namespace": key.Namespace, "name": key.Name}}}
				if _, err := client.Create(t.Context(), key, object, true); err == nil {
					t.Fatal("rules-only client acquired a dry-run write")
				}
				if _, err := client.probeCreate(t.Context(), object, "", "", ""); err == nil {
					t.Fatal("rules-only client acquired admission mutation protocol")
				}
				for _, kind := range [][2]string{{"v1", "Pod"}, {"v1", "PersistentVolumeClaim"}, {"v1", "ServiceAccount"}, {"v1", "Service"}, {"rbac.authorization.k8s.io/v1", "Role"}, {"rbac.authorization.k8s.io/v1", "RoleBinding"}, {"batch/v1", "Job"}, {"apps/v1", "Deployment"}, {"arcade.gobha.me/v1alpha1", "GameDestroy"}} {
					candidate := object.DeepCopy()
					candidate.SetAPIVersion(kind[0])
					candidate.SetKind(kind[1])
					for op := admissionProbeOperation(0); op <= probePatchMetadataOperation; op++ {
						if _, err := client.probeOperation(t.Context(), op, candidate, "", "", ""); err == nil {
							t.Fatal("rules-only client acquired another probe opcode")
						}
					}
				}
				request.Spec.Namespace = "rules-proof"
				for _, purpose := range []actorWirePurpose{runtimeAdmissionPurpose, baselineAdmissionPurpose} {
					old, err := admin.actorClientForPurpose(actor, "rules-proof", purpose)
					if err != nil {
						t.Fatal("historical test actor unavailable")
					}
					if _, err := old.proofRequest(t.Context(), http.MethodPost, "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews", request, &reply); err == nil {
						t.Fatal("historical purpose acquired rules-review capability")
					}
				}
				if _, err := admin.actorClientForPurpose(actor, "rules-proof", baselineRulesReviewPurpose); err == nil {
					t.Fatal("generic constructor selected private rules purpose")
				}
				if _, err := admin.baselineRulesClient(destroyAdministratorActor, "rules-proof"); err == nil || calls.Load() != requests {
					t.Fatal("refused capability reached wire or additional actor acquired rules scope")
				}
			})
		}
	}
}
