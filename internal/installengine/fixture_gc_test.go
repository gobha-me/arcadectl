// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installobserve"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	authv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// Independent fake HTTPS/WAL actors prove only the read-only seam; they do not
// establish native discovery, cold/inertness, delete or recovery authority.
func TestFixtureGCMetadataExactAuthorizationAndOriginalBarriers(t *testing.T) {
	newWire := fixturePreviewFactory(t)
	for _, scenario := range []string{"complete", "deny-list", "review-account", "list-account", "list-policy", "list-journal", "list-wal", "cancelled"} {
		t.Run(scenario, func(t *testing.T) {
			f := newWire(t)
			unchanged := fixturePreviewUnchanged(t, f)
			before := f.wire.ledger.identity
			namespace := f.actor.request.Snapshot.Anchor().Namespace
			source := installobserve.GCResource{GVR: schema.GroupVersionResource{Group: "gc.example.test", Version: "v1", Resource: "widgets"}, Kind: "Widget"}
			reviews, lists := 0, 0
			mutate := func(kind string) {
				for key, object := range f.actor.v.f.access.objects {
					if key.Kind == kind {
						object.SetResourceVersion("999")
						return
					}
				}
				t.Error("missing original mutation witness")
			}
			base := f.actor.fixtureHandler
			f.actor.fixtureHandler = func(w http.ResponseWriter, r *http.Request) bool {
				if r.Method == http.MethodGet && r.URL.Path == "/api/v1/namespaces/"+namespace {
					ns, err := f.actor.v.f.access.client.CoreV1().Namespaces().Get(r.Context(), namespace, metav1.GetOptions{})
					if err != nil {
						t.Error(err)
						w.WriteHeader(500)
						return true
					}
					ns.APIVersion, ns.Kind = "v1", "Namespace"
					_ = json.NewEncoder(w).Encode(ns)
					return true
				}
				if r.Method == http.MethodGet && r.URL.Path == "/api" {
					_ = json.NewEncoder(w).Encode(metav1.APIVersions{TypeMeta: metav1.TypeMeta{Kind: "APIVersions"}, Versions: []string{"v1"}})
					return true
				}
				if r.Method == http.MethodGet && r.URL.Path == "/apis" {
					groups := []metav1.APIGroup{}
					for _, group := range []string{"batch", "arcade.gobha.me", source.GVR.Group} {
						version := "v1"
						if group == "arcade.gobha.me" {
							version = "v1alpha1"
						}
						v := metav1.GroupVersionForDiscovery{GroupVersion: group + "/" + version, Version: version}
						groups = append(groups, metav1.APIGroup{Name: group, Versions: []metav1.GroupVersionForDiscovery{v}, PreferredVersion: v})
					}
					_ = json.NewEncoder(w).Encode(metav1.APIGroupList{TypeMeta: metav1.TypeMeta{Kind: "APIGroupList", APIVersion: "v1"}, Groups: groups})
					return true
				}
				if r.Method == http.MethodGet && r.URL.Path == "/apis/gc.example.test/v1" {
					_ = json.NewEncoder(w).Encode(metav1.APIResourceList{TypeMeta: metav1.TypeMeta{Kind: "APIResourceList", APIVersion: "v1"}, GroupVersion: "gc.example.test/v1", APIResources: []metav1.APIResource{{Name: "widgets", Kind: "Widget", Namespaced: true, Verbs: metav1.Verbs{"delete", "list", "watch"}}}})
					return true
				}
				if r.URL.Path == "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" {
					body, err := io.ReadAll(r.Body)
					if err != nil {
						t.Error(err)
						return false
					}
					r.Body = io.NopCloser(bytes.NewReader(body))
					var review authv1.SelfSubjectAccessReview
					if json.Unmarshal(body, &review) != nil {
						t.Error("invalid GC SSAR")
						return false
					}
					if a := review.Spec.ResourceAttributes; a != nil && a.Group == source.GVR.Group {
						reviews++
						if r.Method != http.MethodPost || r.Header.Get("Impersonate-User") != "" || r.URL.RawQuery != "fieldManager=arcadectl-installer&fieldValidation=Strict" || !reflect.DeepEqual(review.Spec, gcMetadataPermission(source, namespace).spec) {
							t.Error("GC LIST authorization escaped original namespace/GVR/admin")
						}
						review.Status.Allowed = scenario != "deny-list"
						_ = json.NewEncoder(w).Encode(review)
						if scenario == "review-account" {
							mutate("ServiceAccount")
						}
						return true
					}
				}
				if r.URL.Path == "/apis/gc.example.test/v1/namespaces/"+namespace+"/widgets" {
					lists++
					if r.Method != http.MethodGet || r.Header.Get("Impersonate-User") != "" || r.Header.Get("Accept") != "application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1" || r.URL.Query().Get("limit") != "128" || strings.Contains(r.URL.RawQuery, "Selector") {
						t.Error("GC metadata escaped read-only original scope")
					}
					page := metav1.PartialObjectMetadataList{TypeMeta: metav1.TypeMeta{Kind: "PartialObjectMetadataList", APIVersion: "meta.k8s.io/v1"}, ListMeta: metav1.ListMeta{ResourceVersion: "11"}, Items: []metav1.PartialObjectMetadata{{TypeMeta: metav1.TypeMeta{Kind: "PartialObjectMetadata", APIVersion: "meta.k8s.io/v1"}, ObjectMeta: metav1.ObjectMeta{Name: "custom", Namespace: namespace, UID: "custom-uid", ResourceVersion: "21", Annotations: map[string]string{"private": "PRIVATE-GC-CANARY"}}}}}
					_ = json.NewEncoder(w).Encode(page)
					switch scenario {
					case "list-account":
						mutate("ServiceAccount")
					case "list-policy":
						mutate("ValidatingAdmissionPolicy")
					case "list-journal":
						ns, err := f.actor.v.f.access.client.CoreV1().Namespaces().Get(r.Context(), namespace, metav1.GetOptions{})
						if err != nil {
							t.Error(err)
							return true
						}
						ns.ResourceVersion = "999"
						if err := f.actor.v.f.access.client.Tracker().Update(corev1.SchemeGroupVersion.WithResource("namespaces"), ns, ""); err != nil {
							t.Error(err)
						}
					case "list-wal":
						f.wire.ledger.identity = privatefs.FileIdentity{}
					}
					return true
				}
				return base(w, r)
			}
			ctx := t.Context()
			if scenario == "cancelled" {
				var cancel func()
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			observation, err := f.wire.gcMetadata(ctx)
			if scenario == "complete" {
				if err != nil || observation == nil || len(observation.Objects()) != 1 || observation.Objects()[0].Metadata.Annotations != nil || reviews != 1 || lists != 1 {
					t.Fatal("original authorized metadata proof failed", err)
				}
			} else if err != ErrFixtures || observation != nil {
				t.Fatal("drift/denial/cancellation supplied GC evidence", err)
			}
			if (scenario == "deny-list" || scenario == "review-account" || scenario == "cancelled") && lists != 0 {
				t.Fatal("known unauthorized/drifted state sent metadata LIST")
			}
			if f.creates != 0 || f.deletes != 0 || f.previews != 0 || f.seeds != 0 || f.wire.ledger.engine.fixtureFence(f.actor.request.Snapshot) != ErrFixtures {
				t.Fatal("metadata observation mutated or retired fixture authority")
			}
			f.wire.ledger.identity = before // Restore only the deliberate test corruption.
			unchanged()
		})
	}
}
