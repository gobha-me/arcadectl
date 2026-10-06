// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installstate"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

func TestSafetyObservationUsesFrozenMutationIdentityAndExactJournal(t *testing.T) {
	f := newFixture(t, false)
	ns, err := f.access.client.CoreV1().Namespaces().Get(context.Background(), f.plan.Namespace(), metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	original := ns.DeepCopy()
	scenario, requests := "", 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer original-fake-token" || r.Header.Get("Impersonate-User") != "original-fake-user" || !reflect.DeepEqual(r.Header.Values("Impersonate-Group"), []string{"original-fake-group"}) || r.Header.Get("Impersonate-Extra-Scope") != "original-fake-scope" {
			t.Error("read changed frozen identity or issued a mutation")
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1":
			_ = json.NewEncoder(w).Encode(metav1.APIResourceList{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "APIResourceList"}, GroupVersion: "v1", APIResources: []metav1.APIResource{{Name: "namespaces", Kind: "Namespace", Verbs: metav1.Verbs{"get"}}}})
			return
		case "/api/v1/namespaces/" + f.plan.Namespace():
			if strings.Contains(r.Header.Get("Accept"), "as=PartialObjectMetadata;") {
				meta := ns.ObjectMeta.DeepCopy()
				meta.Annotations["private"] = "PRIVATE-CANARY"
				_ = json.NewEncoder(w).Encode(metav1.PartialObjectMetadata{TypeMeta: metav1.TypeMeta{APIVersion: "meta.k8s.io/v1", Kind: "PartialObjectMetadata"}, ObjectMeta: *meta})
				return
			}
			copy := ns.DeepCopy()
			copy.APIVersion, copy.Kind = "v1", "Namespace"
			_ = json.NewEncoder(w).Encode(copy)
			return
		}
		for _, collection := range proofCollections {
			prefix := "/apis/" + collection.gv
			if collection.gv == "v1" {
				prefix = "/api/v1"
			}
			if collection.namespaced {
				prefix += "/namespaces/" + f.plan.Namespace()
			}
			if r.URL.Path != prefix+"/"+collection.plural {
				continue
			}
			query := r.URL.Query()
			if query.Get("limit") != "128" || len(query["limit"]) != 1 || len(query) > 2 || query.Has("timeout") && query.Get("timeout") != "30s" {
				t.Error("observation used filtered/cached or incomplete reads")
			}
			for key := range query {
				if key != "limit" && key != "timeout" {
					t.Error("observation used an unreviewed list option")
				}
			}
			if collection.kind == "Secret" {
				if r.Header.Get("Accept") != "application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1" {
					t.Error("full Secret fallback requested")
				}
				_ = json.NewEncoder(w).Encode(metav1.PartialObjectMetadataList{TypeMeta: metav1.TypeMeta{APIVersion: "meta.k8s.io/v1", Kind: "PartialObjectMetadataList"}, ListMeta: metav1.ListMeta{ResourceVersion: "list-rv"}, Items: []metav1.PartialObjectMetadata{}})
				return
			}
			if collection.kind == "GameServer" {
				if scenario == "malformed-wire" {
					_, _ = w.Write([]byte(`{"apiVersion":"arcade.gobha.me/v1alpha1","kind":"GameServerList","metadata":{"resourceVersion":"list-rv"},"items":[],"items":[]}`))
					return
				}
				if scenario == "journal-race" {
					ns.ResourceVersion = "journal-changed"
				}
				if scenario == "namespace-race" {
					ns.UID = "replacement-namespace"
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"apiVersion": collection.gv, "kind": collection.kind + "List", "metadata": map[string]any{"resourceVersion": "list-rv"}, "items": []any{}})
			return
		}
		t.Error("unexpected observation route")
		w.WriteHeader(404)
	}))
	defer server.Close()
	config := serverConfig(server)
	config.Impersonate = rest.ImpersonationConfig{UserName: "original-fake-user", Groups: []string{"original-fake-group"}, Extra: map[string][]string{"scope": {"original-fake-scope"}}}
	tokenDirectory := t.TempDir()
	if err := os.Chmod(tokenDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	tokenFile := filepath.Join(tokenDirectory, "fake-token")
	if err := os.WriteFile(tokenFile, []byte("original-fake-token"), 0600); err != nil {
		t.Fatal(err)
	}
	config.BearerTokenFile = tokenFile
	access, err := NewHTTPAccess(config)
	if err != nil {
		t.Fatal(err)
	}
	// These source changes must affect neither mutation nor read identity.
	config.Host, config.BearerToken = "https://foreign.invalid", "changed-fake-token"
	config.CAData[0] = '!'
	config.Impersonate.Groups[0], config.Impersonate.Extra["scope"][0] = "changed-group", "changed-scope"
	if err := os.Remove(tokenFile); err != nil { // exact task-owned fake source
		t.Fatal(err)
	}
	store, err := installstate.New(access.Namespaces(), f.plan)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewWithAccess(access, store, f.engine.files, f.plan)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := NewClusterPrerequisites(engine, access)
	if err != nil {
		t.Fatal(err)
	}
	s, err := store.Load(context.Background(), f.snapshot.Anchor())
	if err != nil {
		t.Fatal(err)
	}
	request := LifecycleCheck{Checkpoint: ColdSafety, Snapshot: s, Mode: installstate.Install, Target: f.plan, Options: LifecycleOptions{Now: time.Now().UTC()}}
	for _, test := range []string{"healthy", "stale-snapshot", "malformed-wire", "journal-race", "namespace-race"} {
		t.Run(test, func(t *testing.T) {
			scenario = test
			ns = original.DeepCopy()
			if test == "stale-snapshot" {
				ns.ResourceVersion = "already-changed"
			}
			observation, err := proof.observe(context.Background(), request)
			if (err == nil) != (test == "healthy") || err != nil && (observation != nil || err != ErrPrerequisites) {
				t.Fatal("read accepted stale/foreign/incomplete evidence")
			}
			if err == nil && (observation.Journal().ResourceVersion() != s.ResourceVersion() || len(observation.Snapshot().GameServers.Items) != 0 || len(observation.Snapshot().Owners) != 1) {
				t.Fatal("read lost exact journal/complete owner evidence")
			}
		})
	}
	before := requests
	engine.access = &HTTPAccess{}
	if observation, err := proof.observe(context.Background(), request); observation != nil || err != ErrInvalid || requests != before {
		t.Fatal("wrong mutation access identity accepted or queried")
	}
}
