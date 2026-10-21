// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installstate"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
)

func slicePage(name, uid, continuation string) discoveryv1.EndpointSliceList {
	return discoveryv1.EndpointSliceList{TypeMeta: metav1.TypeMeta{APIVersion: "discovery.k8s.io/v1", Kind: "EndpointSliceList"}, ListMeta: metav1.ListMeta{ResourceVersion: "100", Continue: continuation}, Items: []discoveryv1.EndpointSlice{{ObjectMeta: metav1.ObjectMeta{Namespace: "isolated-install", Name: name, UID: types.UID(uid), ResourceVersion: "10"}, AddressType: discoveryv1.AddressTypeIPv4, Endpoints: []discoveryv1.Endpoint{}, Ports: []discoveryv1.EndpointPort{}}}}
}

func TestServingHTTPReadsCompleteUnfilteredOriginalSnapshot(t *testing.T) {
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		requests++
		if r.Method != http.MethodGet || r.URL.Path != "/apis/discovery.k8s.io/v1/namespaces/isolated-install/endpointslices" || r.URL.Query().Get("limit") != "100" || r.URL.Query().Get("labelSelector") != "" || r.URL.Query().Get("fieldSelector") != "" || r.URL.Query().Get("resourceVersion") != "" {
			t.Error("not a complete fresh unfiltered read")
		}
		page := slicePage("first", "first-uid", "opaque-next")
		if requests == 2 {
			if r.URL.Query().Get("continue") != "opaque-next" {
				t.Error("continuation lost")
			}
			page = slicePage("second", "second-uid", "")
			page.RemainingItemCount = ptr.To[int64](0)
		} else if requests != 1 || r.URL.Query().Get("continue") != "" {
			t.Error("unexpected request replay")
		}
		_ = json.NewEncoder(w).Encode(page)
	}))
	defer server.Close()
	a, err := NewHTTPAccess(serverConfig(server))
	if err != nil {
		t.Fatal(err)
	}
	list, err := a.Serving().ListEndpointSlices(context.Background(), "isolated-install")
	if err != nil || len(list.Items) != 2 || list.ResourceVersion != "100" || list.Continue != "" || requests != 2 {
		t.Fatal("complete snapshot unproved", err)
	}
}

func TestServingHTTPRejectsAmbiguousAndUnboundedListEvidence(t *testing.T) {
	for _, change := range []string{"rv-change", "uid-duplicate", "name-duplicate", "foreign-namespace", "missing-uid", "missing-rv", "remaining", "negative-remaining", "repeat-token", "long-token", "unknown-field", "duplicate-json", "too-many-pages", "too-many-items"} {
		t.Run(change, func(t *testing.T) {
			requests := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				requests++
				page := slicePage("first", "first-uid", "opaque-next")
				if requests > 1 {
					page = slicePage("second", "second-uid", "")
					switch change {
					case "rv-change":
						page.ResourceVersion = "101"
					case "uid-duplicate":
						page.Items[0].UID = "first-uid"
					case "name-duplicate":
						page.Items[0].Name = "first"
					case "foreign-namespace":
						page.Items[0].Namespace = "foreign"
					case "missing-uid":
						page.Items[0].UID = ""
					case "missing-rv":
						page.ResourceVersion = ""
					case "remaining":
						page.RemainingItemCount = ptr.To[int64](1)
					case "negative-remaining":
						page.RemainingItemCount = ptr.To[int64](-1)
					case "repeat-token":
						page.Continue = "opaque-next"
					case "long-token":
						page.Continue = strings.Repeat("x", 2049)
					case "unknown-field":
						raw := servingObject(t, &page).Object
						raw["unsigned"] = "PRIVATE-CANARY"
						_ = json.NewEncoder(w).Encode(raw)
						return
					case "duplicate-json":
						_, _ = w.Write([]byte(`{"apiVersion":"discovery.k8s.io/v1","kind":"EndpointSliceList","metadata":{"resourceVersion":"100","resourceVersion":"PRIVATE-CANARY"},"items":[]}`))
						return
					}
				}
				if change == "too-many-pages" {
					page.Items = nil
					page.Continue = strings.Repeat("x", requests)
				}
				if change == "too-many-items" {
					page.Items = make([]discoveryv1.EndpointSlice, 1001)
				}
				_ = json.NewEncoder(w).Encode(page)
			}))
			defer server.Close()
			a, err := NewHTTPAccess(serverConfig(server))
			if err != nil {
				t.Fatal(err)
			}
			list, err := a.Serving().ListEndpointSlices(context.Background(), "isolated-install")
			if !errors.Is(err, ErrRead) || list != nil || strings.Contains(err.Error(), "CANARY") || requests > 32 {
				t.Fatal("partial or ambiguous snapshot accepted")
			}
		})
	}
}

func TestServingHTTPHasReadOnlyDerivedPodAndReplicaSetRoutes(t *testing.T) {
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		requests++
		version, kind, path := "v1", "Pod", "/api/v1/namespaces/isolated-install/pods/original-pod"
		if requests == 2 {
			version, kind, path = "apps/v1", "ReplicaSet", "/apis/apps/v1/namespaces/isolated-install/replicasets/original-rs"
		}
		if r.Method != http.MethodGet || r.URL.Path != path || r.URL.RawQuery != "" {
			t.Error("unexpected serving route")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"apiVersion": version, "kind": kind, "metadata": map[string]any{"name": path[strings.LastIndex(path, "/")+1:], "namespace": "isolated-install"}})
	}))
	defer server.Close()
	a, err := NewHTTPAccess(serverConfig(server))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Serving().GetPod(context.Background(), "isolated-install", "original-pod"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Serving().GetReplicaSet(context.Background(), "isolated-install", "original-rs"); err != nil {
		t.Fatal(err)
	}
	key := installstate.Key{APIVersion: "v1", Kind: "Pod", Namespace: "isolated-install", Name: "original-pod"}
	if _, err := a.Get(context.Background(), key); !errors.Is(err, ErrInvalid) || requests != 2 {
		t.Fatal("Pod escaped trusted read-only seam")
	}
	if _, err := a.Serving().GetPod(context.Background(), "isolated-install", "../foreign"); !errors.Is(err, ErrInvalid) || requests != 2 {
		t.Fatal("path injection escaped derived route")
	}
}
