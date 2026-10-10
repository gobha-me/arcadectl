// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	authv1 "k8s.io/api/authorization/v1"
)

func proofServer(t *testing.T, handler http.HandlerFunc) *HTTPAccess {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	a, err := NewHTTPAccess(serverConfig(server))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestProofVersionExactEffectiveProfileAndStrictScalarPresence(t *testing.T) {
	profile := fixturePlan(t).Profile()
	for _, test := range []struct {
		name   string
		change func(map[string]any)
		valid  bool
	}{
		{"basic", func(map[string]any) {}, true},
		{"effective-with-older-minimum", func(m map[string]any) {
			m["emulationMajor"], m["emulationMinor"], m["minCompatibilityMajor"], m["minCompatibilityMinor"] = "1", "35", "1", "34"
		}, true},
		{"wrong-patch", func(m map[string]any) { m["gitVersion"] = "v1.35.9" }, false},
		{"minor-range", func(m map[string]any) { m["minor"] = "35+" }, false},
		{"null", func(m map[string]any) { m["gitCommit"] = nil }, false},
		{"foreign-emulation", func(m map[string]any) { m["emulationMajor"], m["emulationMinor"] = "1", "34" }, false},
		{"one-sided-emulation", func(m map[string]any) { m["emulationMajor"] = "1" }, false},
		{"noncanonical-compatibility", func(m map[string]any) { m["minCompatibilityMajor"], m["minCompatibilityMinor"] = "1", "034" }, false},
		{"higher-minimum", func(m map[string]any) { m["minCompatibilityMajor"], m["minCompatibilityMinor"] = "1", "36" }, false},
		{"unknown", func(m map[string]any) { m["unreviewed"] = "PRIVATE-CANARY" }, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := map[string]any{"major": "1", "minor": "35", "gitVersion": "v1.35.8"}
			test.change(body)
			a := proofServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/version" || r.Method != http.MethodGet || r.URL.RawQuery != "" {
					t.Error("unexpected version route")
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(body)
			})
			err := a.checkVersion(context.Background(), profile)
			if (err == nil) != test.valid || err != nil && strings.Contains(err.Error(), "CANARY") {
				t.Fatal("version proof accepted malformed/foreign evidence or leaked body")
			}
		})
	}
}

func TestProofAuthorizationStrictEchoAllowedDeniedAndMetadata(t *testing.T) {
	spec := authv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authv1.ResourceAttributes{Version: "v1", Resource: "namespaces", Name: "isolated-install", Verb: "update"}}
	managed := func(m map[string]any) map[string]any {
		attributes := m["spec"].(map[string]any)["resourceAttributes"].(map[string]any)
		set := map[string]any{".": map[string]any{}}
		for key := range attributes {
			set["f:"+key] = map[string]any{}
		}
		entry := map[string]any{"manager": "arcadectl-installer", "operation": "Update", "apiVersion": "authorization.k8s.io/v1", "fieldsType": "FieldsV1", "time": "2026-10-05T21:00:00Z", "fieldsV1": map[string]any{"f:spec": map[string]any{"f:resourceAttributes": set}}}
		m["metadata"] = map[string]any{"managedFields": []any{entry}}
		return entry
	}
	for _, test := range []struct {
		name   string
		change func(map[string]any)
		valid  bool
	}{
		{"allowed", func(map[string]any) {}, true},
		{"explicit-false-denied", func(m map[string]any) { m["status"].(map[string]any)["denied"] = false }, true},
		{"null-timestamp", func(m map[string]any) { m["metadata"] = map[string]any{"creationTimestamp": nil} }, true},
		{"native-managed-fields", func(m map[string]any) { managed(m) }, true},
		{"native-managed-fields-with-null-timestamp", func(m map[string]any) {
			managed(m)
			m["metadata"].(map[string]any)["creationTimestamp"] = nil
		}, true},
		{"foreign-manager", func(m map[string]any) { managed(m)["manager"] = "foreign" }, false},
		{"null-manager", func(m map[string]any) { managed(m)["manager"] = nil }, false},
		{"foreign-operation", func(m map[string]any) { managed(m)["operation"] = "Apply" }, false},
		{"foreign-fieldset", func(m map[string]any) { managed(m)["fieldsV1"] = map[string]any{"f:status": map[string]any{}} }, false},
		{"extra-field-authority", func(m map[string]any) { managed(m)["subresource"] = "status" }, false},
		{"null-managed-time", func(m map[string]any) { managed(m)["time"] = nil }, false},
		{"noncanonical-managed-time", func(m map[string]any) { managed(m)["time"] = "2026-10-05T21:00:00+00:00" }, false},
		{"null-fieldset", func(m map[string]any) { managed(m)["fieldsV1"] = nil }, false},
		{"null-managed-fields", func(m map[string]any) { m["metadata"] = map[string]any{"managedFields": nil} }, false},
		{"duplicate-managed-authority", func(m map[string]any) {
			entry := managed(m)
			m["metadata"].(map[string]any)["managedFields"] = []any{entry, entry}
		}, false},
		{"missing-allowed", func(m map[string]any) { delete(m["status"].(map[string]any), "allowed") }, false},
		{"null-allowed", func(m map[string]any) { m["status"].(map[string]any)["allowed"] = nil }, false},
		{"denied", func(m map[string]any) { m["status"].(map[string]any)["denied"] = true }, false},
		{"null-denied", func(m map[string]any) { m["status"].(map[string]any)["denied"] = nil }, false},
		{"evaluation-error", func(m map[string]any) { m["status"].(map[string]any)["evaluationError"] = "PRIVATE-CANARY" }, false},
		{"null-evaluation", func(m map[string]any) { m["status"].(map[string]any)["evaluationError"] = nil }, false},
		{"different-spec", func(m map[string]any) {
			m["spec"].(map[string]any)["resourceAttributes"].(map[string]any)["verb"] = "delete"
		}, false},
		{"null-scope", func(m map[string]any) {
			m["spec"].(map[string]any)["resourceAttributes"].(map[string]any)["namespace"] = nil
		}, false},
		{"unknown", func(m map[string]any) { m["status"].(map[string]any)["unknown"] = "PRIVATE-CANARY" }, false},
		{"null-metadata", func(m map[string]any) { m["metadata"] = nil }, false},
		{"null-uid", func(m map[string]any) { m["metadata"] = map[string]any{"uid": nil} }, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			a := proofServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.ProtoMajor != 1 || r.URL.Path != "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" || r.URL.RawQuery != "fieldManager=arcadectl-installer&fieldValidation=Strict" {
					t.Error("unexpected authorization route/protocol")
				}
				var body map[string]any
				if json.NewDecoder(r.Body).Decode(&body) != nil {
					t.Error("missing nonreplayable body")
				}
				body["status"] = map[string]any{"allowed": true}
				test.change(body)
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(body)
			})
			err := a.authorize(context.Background(), spec)
			if (err == nil) != test.valid || err != nil && strings.Contains(err.Error(), "CANARY") {
				t.Fatal("authorization accepted malformed/foreign evidence or leaked body")
			}
		})
	}
}

func TestProofDiscoveryVersionOmissionIsNotNullEmptyOrForeignVersion(t *testing.T) {
	for _, test := range []struct {
		name, version string
		omit, null    bool
		valid         bool
	}{
		{name: "native-omission", omit: true, valid: true},
		{name: "literal-v1", version: "v1", valid: true},
		{name: "null", null: true}, {name: "empty"}, {name: "foreign", version: "v2"},
	} {
		t.Run(test.name, func(t *testing.T) {
			access := proofServer(t, func(w http.ResponseWriter, r *http.Request) {
				body := map[string]any{"kind": "APIResourceList", "groupVersion": "v1", "resources": []any{map[string]any{"name": "pods", "kind": "Pod", "namespaced": true, "verbs": []any{"get", "list"}}}}
				if !test.omit {
					body["apiVersion"] = test.version
					if test.null {
						body["apiVersion"] = nil
					}
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(body)
			})
			if _, err := access.discover(context.Background(), "v1"); (err == nil) != test.valid {
				t.Fatal("native version omission conflated with malformed version")
			}
		})
	}
}

func TestProofNoRetryRedirectRawErrorOrUnboundedJSON(t *testing.T) {
	spec := authv1.SelfSubjectAccessReviewSpec{NonResourceAttributes: &authv1.NonResourceAttributes{Path: "/version", Verb: "get"}}
	for _, response := range []struct {
		code int
		body string
	}{
		{429, "PRIVATE-CANARY"}, {503, "PRIVATE-CANARY"}, {307, "PRIVATE-CANARY"},
		{200, `{"apiVersion":"authorization.k8s.io/v1","apiVersion":"authorization.k8s.io/v1"}`},
		{200, strings.Repeat("[", 65) + strings.Repeat("]", 65)},
		{200, strings.Repeat(" ", 1024*1024+1)}, {200, "{}{}"},
		{200, `{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectAccessReview","metadata":{"managedFields":[{"manager":"arcadectl-installer","operation":"Update","apiVersion":"authorization.k8s.io/v1","fieldsType":"FieldsV1","time":"2026-10-05T21:00:00Z","fieldsV1":{"f:spec":{"f:nonResourceAttributes":{".":{},"f:path":{},"f:verb":{},"f:verb":{}}}}}]},"spec":{"nonResourceAttributes":{"path":"/version","verb":"get"}},"status":{"allowed":true}}`},
	} {
		t.Run(fmt.Sprint(response.code)+"/"+fmt.Sprint(len(response.body)), func(t *testing.T) {
			var attempts atomic.Int32
			a := proofServer(t, func(w http.ResponseWriter, r *http.Request) {
				attempts.Add(1)
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Retry-After", "0")
				w.Header().Set("Warning", "PRIVATE-CANARY")
				w.Header().Set("Location", "/unreviewed")
				w.WriteHeader(response.code)
				_, _ = io.WriteString(w, response.body)
			})
			if err := a.authorize(context.Background(), spec); err == nil || strings.Contains(err.Error(), "CANARY") || attempts.Load() != 1 {
				t.Fatal("proof retried/followed/reflected malformed response")
			}
		})
	}
}

func TestProofDiscoveryRequiresLiteralScopeAndExactGroup(t *testing.T) {
	for _, test := range []struct {
		name  string
		scope any
		omit  bool
		valid bool
	}{
		{"cluster", false, false, true}, {"namespace", true, false, true},
		{"null", nil, false, false}, {"omitted", false, true, false}, {"string", "false", false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			a := proofServer(t, func(w http.ResponseWriter, r *http.Request) {
				resource := map[string]any{"name": "customresourcedefinitions", "kind": "CustomResourceDefinition", "namespaced": test.scope, "verbs": []string{"get"}}
				if test.omit {
					delete(resource, "namespaced")
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"apiVersion": "v1", "kind": "APIResourceList", "groupVersion": "apiextensions.k8s.io/v1", "resources": []any{resource}})
			})
			_, err := a.discover(context.Background(), "apiextensions.k8s.io/v1")
			if (err == nil) != test.valid {
				t.Fatal("discovery silently defaulted resource scope")
			}
			if _, err := a.discover(context.Background(), "unreviewed/v1"); err == nil {
				t.Fatal("arbitrary discovery route accepted")
			}
		})
	}
}
