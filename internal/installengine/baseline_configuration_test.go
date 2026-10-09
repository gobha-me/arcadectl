// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installstate"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Unit-only HTTPS fixtures supply synthetic native status to exercise strict
// configuration/refusal predicates. These are NOT actual Kind typechecking or
// effective-enforcement evidence. Native envtest separately refuses absent
// real typechecker status instead of filling it in.
func TestBaselineConfigurationOriginalShapesHealthAndRepeatedIdentity(t *testing.T) {
	for _, mode := range []string{"healthy", "runtime-pending", "unobserved-generation", "missing-typecheck", "typecheck-warning", "weak-policy", "wrong-namespace", "replacement", "deleting", "between-pass-rv", "journal-drift", "late-fixture"} {
		t.Run(mode, func(t *testing.T) {
			f := newBaselineFixture(t)
			completeBaselineFixture(t, f)
			baseline := f.engine.baselinePlan()
			if mode == "runtime-pending" {
				document := f.snapshot.Document()
				template, _ := f.engine.contracts[f.plan.Digest()].Template(f.key, false)
				document.Pending = &installstate.Pending{Action: installstate.Create, Key: f.key, CreateNonce: strings.Repeat("b", 32), AfterSHA256: template.Hash()}
				body, err := installstate.EncodeWithBaseline(document, baseline, f.plan)
				if err != nil {
					t.Fatal("runtime-pending fixture encoding failed")
				}
				namespace, _ := f.access.client.CoreV1().Namespaces().Get(t.Context(), f.plan.Namespace(), metav1.GetOptions{})
				namespace.Annotations[installstate.Annotation] = string(body)
				if f.access.client.Tracker().Update(corev1.SchemeGroupVersion.WithResource("namespaces"), namespace, "") != nil {
					t.Fatal("runtime-pending fixture seed failed")
				}
			}
			objects := make(map[string]*unstructured.Unstructured)
			policyPath, bindingPath := "", ""
			for key, original := range f.access.objects {
				path, err := resourcePath(key, false)
				if err != nil {
					t.Fatal("baseline route unavailable")
				}
				object := original.DeepCopy()
				if key.Kind == "ValidatingAdmissionPolicy" {
					object.SetGeneration(1)
					object.Object["status"] = map[string]any{"observedGeneration": int64(1), "typeChecking": map[string]any{}}
					if policyPath == "" {
						policyPath = path
					}
				} else if bindingPath == "" {
					bindingPath = path
				}
				objects[path] = object
			}
			policy, binding := objects[policyPath], objects[bindingPath]
			switch mode {
			case "unobserved-generation":
				policy.SetGeneration(2)
			case "missing-typecheck":
				unstructured.RemoveNestedField(policy.Object, "status", "typeChecking")
			case "typecheck-warning":
				_ = unstructured.SetNestedSlice(policy.Object, []any{map[string]any{"fieldRef": "spec.validations[0].expression", "warning": "PRIVATE-STATUS-CANARY"}}, "status", "typeChecking", "expressionWarnings")
			case "weak-policy":
				_ = unstructured.SetNestedField(policy.Object, "Ignore", "spec", "failurePolicy")
			case "wrong-namespace":
				_ = unstructured.SetNestedField(binding.Object, "foreign", "spec", "matchResources", "namespaceSelector", "matchLabels", "kubernetes.io/metadata.name")
			case "replacement":
				policy.SetUID("replacement")
			case "deleting":
				now := metav1.Now()
				policy.SetDeletionTimestamp(&now)
			}
			reads := make(map[string]int)
			var mu sync.Mutex
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				if request.Method != http.MethodGet {
					t.Error("configuration observation attempted mutation")
					w.WriteHeader(500)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				if request.URL.Path == "/api/v1/namespaces/"+f.plan.Namespace() {
					namespace, err := f.access.client.CoreV1().Namespaces().Get(request.Context(), f.plan.Namespace(), metav1.GetOptions{})
					if err != nil {
						w.WriteHeader(500)
						return
					}
					namespace.APIVersion, namespace.Kind = "v1", "Namespace"
					if mode == "journal-drift" && reads[policyPath] != 0 {
						namespace.ResourceVersion = "999"
					}
					_ = json.NewEncoder(w).Encode(namespace)
					return
				}
				object := objects[request.URL.Path]
				if object == nil {
					t.Error("configuration observation escaped closed routes")
					w.WriteHeader(404)
					return
				}
				reads[request.URL.Path]++
				if request.URL.Path == policyPath && reads[policyPath] == 2 && mode == "between-pass-rv" {
					object = object.DeepCopy()
					object.SetResourceVersion("999")
				}
				if request.URL.Path == policyPath && mode == "late-fixture" && reads[policyPath] == 1 {
					if _, err := f.engine.files.CreateExclusive(fixtureLedgerName(f.snapshot), []byte("uncertain active fixture")); err != nil {
						t.Error("late fixture seed failed")
					}
				}
				_ = json.NewEncoder(w).Encode(object)
			}))
			t.Cleanup(server.Close)
			access, err := NewDirectHTTPAccess(serverConfig(server))
			if err != nil {
				t.Fatal("closed fixture HTTP access unavailable")
			}
			store, err := installstate.NewWithBaseline(access.Namespaces(), baseline, f.plan)
			if err != nil {
				t.Fatal("closed fixture store unavailable")
			}
			engine, err := NewWithBaselineAccess(access, store, f.engine.files, baseline, f.plan)
			if err != nil {
				t.Fatal("closed fixture engine unavailable")
			}
			snapshot, err := store.Load(t.Context(), f.snapshot.Anchor())
			if err != nil {
				t.Fatal("original fixture snapshot unavailable")
			}
			configuration, err := NewClusterSecurityBaseline(engine, access)
			if err != nil {
				t.Fatal("closed configuration factory refused")
			}
			if mode == "healthy" {
				foreign, err := NewDirectHTTPAccess(serverConfig(server))
				if err != nil {
					t.Fatal("foreign access fixture unavailable")
				}
				for _, pair := range []struct {
					engine *Engine
					access *HTTPAccess
				}{{nil, access}, {engine, nil}, {f.engine, access}, {engine, foreign}} {
					if got, err := NewClusterSecurityBaseline(pair.engine, pair.access); err != ErrInvalid || got != nil {
						t.Fatal("configuration factory accepted foreign or missing composition")
					}
				}
				originalStore := engine.journal
				foreignPlan := baselineFixturePlan(t, f.plan.Namespace(), f.plan.Profile().ID, 'e')
				foreignStore, err := installstate.NewWithBaseline(access.Namespaces(), foreignPlan, f.plan)
				if err != nil {
					t.Fatal("foreign baseline store fixture unavailable")
				}
				engine.journal = foreignStore
				if got, err := NewClusterSecurityBaseline(engine, access); err != ErrInvalid || got != nil {
					t.Fatal("configuration factory accepted foreign baseline store")
				}
				engine.journal = originalStore
			}
			err = configuration.VerifyConfigured(t.Context(), snapshot)
			if mode == "healthy" || mode == "runtime-pending" {
				if err != nil {
					t.Fatal("strict configured fixture refused")
				}
				mu.Lock()
				for _, count := range reads {
					if count != 2 {
						t.Fatal("configured verification skipped complete repeated original observations")
					}
				}
				mu.Unlock()
			} else if err != ErrSecurityBaseline || strings.Contains(err.Error(), "CANARY") {
				t.Fatal("unhealthy/replaced/drifted baseline became configured proof or leaked private error")
			}
			if engine.baseline.runtimeGuard != nil {
				t.Fatal("configuration proof alone supplied runtime enforcement authority")
			}
		})
	}
}
