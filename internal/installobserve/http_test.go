// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installobserve

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

func TestProductionFactoryPagedMetadataAndDomainHTTP(t *testing.T) {
	f := newFixture(t)
	var secretPages, domainPages, requests atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodGet {
			t.Error("observer tried a mutation")
			w.WriteHeader(400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Warning", "private-warning-canary")
		path, q := r.URL.Path, r.URL.Query()
		if path == "/api/v1" {
			_ = json.NewEncoder(w).Encode(&metav1.APIResourceList{GroupVersion: "v1", APIResources: []metav1.APIResource{{Name: "namespaces", Kind: "Namespace", Namespaced: false, Verbs: metav1.Verbs{"get", "list"}}}})
			return
		}
		if path == "/api/v1/namespaces/"+f.anchor.Namespace {
			if r.Header.Get("Accept") != "application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1" {
				t.Error("metadata GET fallback permitted")
			}
			object := f.objects[address("namespaces", "", f.anchor.Namespace)].DeepCopy()
			object.APIVersion, object.Kind = "meta.k8s.io/v1", "PartialObjectMetadata"
			object.Annotations = map[string]string{"private": "secret-canary"}
			_ = json.NewEncoder(w).Encode(object)
			return
		}
		if q.Get("limit") != "128" || q.Has("resourceVersion") || q.Has("labelSelector") || q.Has("fieldSelector") || q.Has("watch") {
			t.Error("incomplete or cached list request")
		}
		if strings.HasSuffix(path, "/secrets") {
			secretPages.Add(1)
			if r.Header.Get("Accept") != "application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1" {
				t.Error("full Secret list fallback permitted")
			}
			list := &metav1.PartialObjectMetadataList{TypeMeta: metav1.TypeMeta{APIVersion: "meta.k8s.io/v1", Kind: "PartialObjectMetadataList"}, ListMeta: metav1.ListMeta{ResourceVersion: "secret-rv"}, Items: []metav1.PartialObjectMetadata{}}
			if q.Get("continue") == "" {
				list.Continue = "secret-page-2"
				list.Items = append(list.Items, metav1.PartialObjectMetadata{TypeMeta: metav1.TypeMeta{APIVersion: "meta.k8s.io/v1", Kind: "PartialObjectMetadata"}, ObjectMeta: metav1.ObjectMeta{Name: "retained-admin", Namespace: f.anchor.Namespace, UID: "retained-admin-uid", ResourceVersion: "secret-object-rv", Annotations: map[string]string{"private": "secret-canary"}}})
			} else if q.Get("continue") != "secret-page-2" {
				t.Error("Secret page skipped")
			}
			_ = json.NewEncoder(w).Encode(list)
			return
		}
		for _, c := range f.cs {
			if !strings.HasSuffix(path, "/"+c.resource) {
				continue
			}
			list := map[string]any{"apiVersion": c.gv, "kind": c.kind + "List", "metadata": map[string]any{"resourceVersion": "list-rv"}, "items": []any{}}
			if c.kind == "GameServer" {
				domainPages.Add(1)
				if q.Get("continue") == "" {
					list["metadata"].(map[string]any)["continue"] = "game-page-2"
					list["items"] = []any{map[string]any{"apiVersion": c.gv, "kind": c.kind, "metadata": map[string]any{"name": "stopped-world", "namespace": f.anchor.Namespace, "uid": "game-uid", "resourceVersion": "game-object-rv", "generation": int64(1)}}}
				} else if q.Get("continue") != "game-page-2" {
					t.Error("domain page skipped")
				}
			}
			_ = json.NewEncoder(w).Encode(list)
			return
		}
		t.Error("unexpected resource requested")
		w.WriteHeader(404)
	}))
	defer srv.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	o, err := New(&rest.Config{Host: srv.URL, TLSClientConfig: rest.TLSClientConfig{CAData: ca}}, f.o.journal, f.o.plan)
	if err != nil {
		t.Fatal(err)
	}
	observation, err := o.Collect(context.Background(), f.anchor)
	if err != nil {
		t.Fatal(err)
	}
	s := observation.Snapshot()
	if len(s.GameServers.Items) != 1 || len(s.Secrets.Items) != 1 || s.GameServers.ResourceVersion != "list-rv" || s.Secrets.ResourceVersion != "secret-rv" || s.GameServers.Continue != "" || s.Secrets.Continue != "" || s.Secrets.Items[0].Annotations != nil || secretPages.Load() != 2 || domainPages.Load() != 2 || requests.Load() != 24 || observation.Runtime().Attachments.ResourceVersion != "list-rv" || observation.Runtime().EndpointSlices.ResourceVersion != "list-rv" {
		t.Fatal("production factory did not establish complete paged evidence")
	}
}

func TestProductionFactoryNeverFollowsRedirects(t *testing.T) {
	var targetCalls atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { targetCalls.Add(1) }))
	defer target.Close()
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer origin.Close()
	f := newFixture(t)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: origin.Certificate().Raw})
	o, err := New(&rest.Config{Host: origin.URL, TLSClientConfig: rest.TLSClientConfig{CAData: ca}}, f.o.journal, f.o.plan)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := o.Collect(context.Background(), f.anchor); result != nil || !errors.Is(err, ErrRead) || targetCalls.Load() != 0 {
		t.Fatal("observation followed redirect or accepted partial reads")
	}
}
