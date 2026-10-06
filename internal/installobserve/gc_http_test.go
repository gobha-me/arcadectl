// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installobserve

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
)

type gcHTTPFixture struct {
	f         *fixture
	g         *GCReader
	lists     int
	reads     map[string]int
	fault     string
	afterRead func(string)
}

func newGCHTTPFixture(t *testing.T, fault string) *gcHTTPFixture {
	t.Helper()
	h := &gcHTTPFixture{f: newFixture(t), fault: fault, reads: map[string]int{}}
	catalogue := gcTestCatalogue(t)
	if strings.HasPrefix(fault, "event-") {
		core := catalogue.Lists["v1"]
		core.APIResources = append(core.APIResources, metav1.APIResource{Name: "events", Kind: "Event", Namespaced: true, Verbs: metav1.Verbs{"delete", "list", "watch"}})
		catalogue.Lists["v1"] = core
		version := metav1.GroupVersionForDiscovery{GroupVersion: "events.k8s.io/v1", Version: "v1"}
		catalogue.Groups = append(catalogue.Groups, gcGroup{Name: "events.k8s.io", Versions: []metav1.GroupVersionForDiscovery{version}, Preferred: version})
		catalogue.Lists[version.GroupVersion] = metav1.APIResourceList{TypeMeta: metav1.TypeMeta{Kind: "APIResourceList", APIVersion: "v1"}, GroupVersion: version.GroupVersion, APIResources: []metav1.APIResource{{Name: "events", Kind: "Event", Namespaced: true, Verbs: metav1.Verbs{"delete", "list", "watch"}}}}
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.reads[r.URL.Path]++
		if h.afterRead != nil {
			h.afterRead(r.URL.Path)
		}
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer fake-gc-admin" {
			t.Error("GC observer changed method or original identity")
			w.WriteHeader(400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Warning", "PRIVATE-GC-CANARY")
		path, q := r.URL.Path, r.URL.Query()
		if path == "/api" {
			_ = json.NewEncoder(w).Encode(metav1.APIVersions{TypeMeta: metav1.TypeMeta{Kind: "APIVersions"}, Versions: []string{"v1"}})
			return
		}
		if path == "/apis" {
			groups := metav1.APIGroupList{TypeMeta: metav1.TypeMeta{Kind: "APIGroupList", APIVersion: "v1"}}
			for _, group := range catalogue.Groups {
				if group.Name != "" {
					groups.Groups = append(groups.Groups, metav1.APIGroup{Name: group.Name, Versions: group.Versions, PreferredVersion: group.Preferred})
				}
			}
			if strings.HasSuffix(h.fault, "-groups") {
				writeGCDiscoveryFault(t, w, groups, "groups", h.fault)
			} else {
				_ = json.NewEncoder(w).Encode(groups)
			}
			return
		}
		gv := strings.TrimPrefix(path, "/apis/")
		if path == "/api/v1" {
			gv = "v1"
		}
		if list, exists := catalogue.Lists[gv]; exists {
			if gv == "v1" && strings.HasPrefix(h.fault, "field-") && !strings.HasSuffix(h.fault, "-groups") {
				field := strings.TrimPrefix(strings.TrimPrefix(h.fault, "field-missing-"), "field-null-")
				writeGCDiscoveryFault(t, w, list, field, h.fault)
				return
			}
			if h.fault == "partial-discovery" && gv == "example.test/v1" {
				w.WriteHeader(503)
				_, _ = io.WriteString(w, "PRIVATE-GC-CANARY")
				return
			}
			if h.fault == "discovery-drift" && h.reads[path] > 2 && gv == "v1" {
				list.APIResources[0].Verbs = metav1.Verbs{"get", "list"}
			}
			_ = json.NewEncoder(w).Encode(list)
			return
		}
		h.lists++
		// The real metadata client carries the constructor's bounded timeout
		// alongside Limit and (on later pages) Continue. Admit no other query.
		queryValid := q.Get("limit") == "128" && (!q.Has("timeout") || q.Get("timeout") == "30s")
		for key, values := range q {
			if key != "limit" && key != "continue" && key != "timeout" || len(values) != 1 {
				queryValid = false
			}
		}
		if r.Header.Get("Accept") != "application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1" || !queryValid || !strings.Contains(path, "/namespaces/"+h.f.anchor.Namespace+"/") {
			t.Error("GC metadata scope/negotiation/pagination changed")
			w.WriteHeader(400)
			return
		}
		if h.fault == "denied" || h.fault == "unsupported-metadata" {
			code := 403
			if h.fault == "unsupported-metadata" {
				code = 406
			}
			w.WriteHeader(code)
			_, _ = io.WriteString(w, "PRIVATE-GC-CANARY")
			return
		}
		if h.fault == "full-secret" {
			_, _ = io.WriteString(w, `{"kind":"SecretList","apiVersion":"v1","metadata":{"resourceVersion":"11"},"items":[{"kind":"Secret","data":{"password":"PRIVATE-GC-CANARY"}}]}`)
			return
		}
		if h.fault == "duplicate-json" {
			_, _ = io.WriteString(w, `{"kind":"PartialObjectMetadataList","kind":"SecretList","apiVersion":"meta.k8s.io/v1","metadata":{"resourceVersion":"11"},"items":[]}`)
			return
		}
		makeObject := func(name, uid string, owners ...metav1.OwnerReference) metav1.PartialObjectMetadata {
			return metav1.PartialObjectMetadata{TypeMeta: metav1.TypeMeta{APIVersion: "meta.k8s.io/v1", Kind: "PartialObjectMetadata"}, ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: h.f.anchor.Namespace, UID: types.UID(uid), ResourceVersion: "21", Generation: 1, OwnerReferences: owners, Annotations: map[string]string{"private": "PRIVATE-GC-CANARY"}, Labels: map[string]string{"private": "PRIVATE-GC-CANARY"}}}
		}
		page := metav1.PartialObjectMetadataList{TypeMeta: metav1.TypeMeta{APIVersion: "meta.k8s.io/v1", Kind: "PartialObjectMetadataList"}, ListMeta: metav1.ListMeta{ResourceVersion: "11"}, Items: []metav1.PartialObjectMetadata{}}
		switch {
		case strings.HasSuffix(path, "/events"):
			page.Items = append(page.Items, makeObject("event", "event-uid"))
			if strings.HasPrefix(path, "/apis/events.k8s.io/") {
				switch h.fault {
				case "event-rv":
					page.Items[0].ResourceVersion = "22"
				case "event-owner":
					page.Items[0].OwnerReferences = []metav1.OwnerReference{{APIVersion: "v1", Kind: "Secret", Name: "root", UID: "root-uid"}}
				case "event-name":
					page.Items[0].Name = "other"
				case "event-duplicate":
					page.Items = append(page.Items, page.Items[0])
				}
			}
		case strings.HasSuffix(path, "/secrets"):
			if h.fault != "absent-root" {
				page.Items = append(page.Items, makeObject("root", "root-uid"))
			}
		case strings.HasSuffix(path, "/legacywidgets"):
			page.Items = append(page.Items, makeObject("bridge", "bridge-uid", metav1.OwnerReference{APIVersion: "v1", Kind: "Secret", Name: "root", UID: "root-uid"}))
			if h.fault == "owner-cycle" {
				page.Items[0].OwnerReferences = append(page.Items[0].OwnerReferences, metav1.OwnerReference{APIVersion: "example.test/v2", Kind: "Widget", Name: "child", UID: "child-uid"})
			}
		case strings.HasSuffix(path, "/widgets"):
			if q.Get("continue") == "" {
				page.Items = append(page.Items, makeObject("child", "child-uid", metav1.OwnerReference{APIVersion: "example.test/v1", Kind: "LegacyWidget", Name: "bridge", UID: "bridge-uid"}))
				for index := 0; index < 127; index++ {
					page.Items = append(page.Items, makeObject("benign-"+strconv.Itoa(index), "benign-uid-"+strconv.Itoa(index)))
				}
				page.Continue = "widgets-next"
			} else if q.Get("continue") == "widgets-next" {
				if h.fault == "expired-page" {
					w.WriteHeader(410)
					return
				}
				if h.fault == "page-rv-drift" {
					page.ResourceVersion = "12"
				}
				if h.fault == "repeated-page" {
					page.Continue = "widgets-next"
				}
				for index := 127; index < 129; index++ {
					page.Items = append(page.Items, makeObject("benign-"+strconv.Itoa(index), "benign-uid-"+strconv.Itoa(index)))
				}
			} else {
				t.Error("unknown continuation used")
				w.WriteHeader(400)
				return
			}
		default:
			t.Error("unknown metadata resource requested")
			w.WriteHeader(404)
			return
		}
		if h.fault == "foreign-namespace" && len(page.Items) != 0 {
			page.Items[0].Namespace = "foreign"
		}
		if h.fault == "duplicate-name" && len(page.Items) != 0 {
			page.Items = append(page.Items, page.Items[0])
		}
		if h.fault == "uid-alias" && strings.HasSuffix(path, "/legacywidgets") {
			page.Items[0].UID = "root-uid"
		}
		if h.fault == "owner-route" && strings.HasSuffix(path, "/legacywidgets") {
			page.Items[0].OwnerReferences[0].APIVersion = "../v1"
		}
		if h.fault == "generation" && len(page.Items) != 0 {
			page.Items[0].Generation = -1
		}
		_ = json.NewEncoder(w).Encode(page)
	}))
	t.Cleanup(srv.Close)
	config := &rest.Config{Host: srv.URL, BearerToken: "fake-gc-admin", TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})}}
	config.WrapTransport = func(next http.RoundTripper) http.RoundTripper {
		return roundTripFunc(func(r *http.Request) (*http.Response, error) {
			response, err := next.RoundTrip(r)
			if response != nil && strings.Contains(r.URL.Path, "/namespaces/") {
				body, readErr := io.ReadAll(response.Body)
				_ = response.Body.Close()
				if readErr != nil || strings.Contains(string(body), "PRIVATE-GC-CANARY") || response.Header.Get("Warning") != "" || len(response.Trailer) != 0 {
					t.Error("private metadata reached outer instrumentation")
				}
				response.Body = io.NopCloser(strings.NewReader(string(body)))
			}
			return response, err
		})
	}
	var err error
	h.g, err = NewGCReader(config, h.f.o.journal, h.f.o.plan)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func writeGCDiscoveryFault(t *testing.T, w http.ResponseWriter, value any, field, fault string) {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if json.Unmarshal(body, &object) != nil {
		t.Fatal("invalid test discovery")
	}
	target := object
	if field == "namespaced" || field == "verbs" {
		target = object["resources"].([]any)[0].(map[string]any)
	}
	if strings.HasPrefix(fault, "field-missing-") {
		delete(target, field)
	} else {
		target[field] = nil
	}
	_ = json.NewEncoder(w).Encode(object)
}

func TestGCReaderDiscoveryRequiresExplicitDecisionFields(t *testing.T) {
	for _, field := range []string{"groups", "resources", "namespaced", "verbs"} {
		for _, state := range []string{"missing", "null"} {
			t.Run(state+"-"+field, func(t *testing.T) {
				h := newGCHTTPFixture(t, "field-"+state+"-"+field)
				discovery, err := h.g.Discover(t.Context(), h.f.anchor)
				if err != ErrRead || discovery != nil || h.lists != 0 {
					t.Fatal("missing discovery decision silently omitted GC sources", err)
				}
			})
		}
	}
}

func TestGCReaderEventsRequireExactKnownAliasMetadata(t *testing.T) {
	for _, fault := range []string{"event-identical", "event-rv", "event-owner", "event-name", "event-duplicate"} {
		t.Run(fault, func(t *testing.T) {
			h := newGCHTTPFixture(t, fault)
			discovery, err := h.g.Discover(t.Context(), h.f.anchor)
			if err != nil || len(discovery.Resources()) != 5 {
				t.Fatal("complete Event alias catalogue unproved", err)
			}
			observation, err := h.g.Collect(t.Context(), discovery)
			if fault != "event-identical" {
				if err == nil || observation != nil {
					t.Fatal("conflicting alias or same-source duplicate accepted")
				}
				return
			}
			if err != nil || observation == nil || len(observation.Objects()) != 134 || h.lists != 6 {
				t.Fatal("identical known Event alias was not completely observed", err)
			}
		})
	}
}

func TestGCReaderJournalDriftAndCancellationInvalidateSeals(t *testing.T) {
	for _, barrier := range []string{"discovery", "before-collection", "during-pages", "after-pages", "cancel-discovery", "cancel-collection"} {
		t.Run(barrier, func(t *testing.T) {
			h := newGCHTTPFixture(t, "")
			drift := func() {
				ns, err := h.f.core.CoreV1().Namespaces().Get(t.Context(), h.f.anchor.Namespace, metav1.GetOptions{})
				if err != nil {
					t.Fatal(err)
				}
				ns.ResourceVersion = "2"
				if _, err := h.f.core.CoreV1().Namespaces().Update(t.Context(), ns, metav1.UpdateOptions{}); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if barrier == "cancel-discovery" {
				cancel()
			}
			if barrier == "discovery" {
				h.afterRead = func(path string) {
					if path == "/apis" {
						drift()
					}
				}
			}
			discovery, err := h.g.Discover(ctx, h.f.anchor)
			if barrier == "discovery" || barrier == "cancel-discovery" {
				if err == nil || discovery != nil || h.lists != 0 {
					t.Fatal("invalid discovery supplied a seal", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if barrier == "before-collection" {
				drift()
			}
			if barrier == "cancel-collection" {
				cancel()
			}
			h.afterRead = func(path string) {
				if barrier == "during-pages" && strings.HasSuffix(path, "/widgets") || barrier == "after-pages" && path == "/api" && h.reads[path] == 3 {
					drift()
				}
			}
			observation, err := h.g.Collect(ctx, discovery)
			if err == nil || observation != nil {
				t.Fatal("journal drift/cancellation left observation usable")
			}
			if (barrier == "before-collection" || barrier == "cancel-collection") && h.lists != 0 {
				t.Fatal("known invalid seal sent metadata LIST")
			}
		})
	}
}

func TestGCReaderCompletePagedPrivateMetadataAndTransitiveChildren(t *testing.T) {
	h := newGCHTTPFixture(t, "")
	discovery, err := h.g.Discover(t.Context(), h.f.anchor)
	if err != nil || discovery == nil || len(discovery.Resources()) != 3 {
		t.Fatal("complete GC discovery unproved", err)
	}
	copy := discovery.Resources()
	copy[0].GVR.Resource = "foreign"
	observation, err := h.g.Collect(t.Context(), discovery)
	if err != nil || observation == nil || h.lists != 4 || len(observation.Objects()) != 132 {
		t.Fatal("complete paged metadata observation unproved", err)
	}
	children, err := observation.Descendants([]types.UID{"root-uid"})
	if err != nil || len(children) != 2 {
		t.Fatal("custom intermediary descendant omitted", err)
	}
	for _, object := range children {
		if object.Metadata.UID != "bridge-uid" && object.Metadata.UID != "child-uid" || object.Metadata.Annotations != nil || object.Metadata.Labels != nil {
			t.Fatal("metadata privacy or exact descendant selection failed")
		}
	}
	children[0].Metadata.OwnerReferences[0].UID = "foreign"
	objects := observation.Objects()
	objects[0].Metadata.UID = "foreign"
	again, err := observation.Descendants([]types.UID{"root-uid"})
	if err != nil || len(again) != 2 || observation.Objects()[0].Metadata.UID == "foreign" {
		t.Fatal("mutable accessor changed sealed GC evidence")
	}
	if _, err := observation.Descendants(nil); err != ErrInvalid {
		t.Fatal("empty roots supplied descendant evidence")
	}
	foreign := newGCHTTPFixture(t, "")
	if _, err := foreign.g.Collect(t.Context(), discovery); err != ErrInvalid || foreign.lists != 0 {
		t.Fatal("another reader adopted discovery seal")
	}
}

func TestGCReaderRefusesIncompleteAmbiguousAndUnsafeWireWithoutFallback(t *testing.T) {
	for _, fault := range []string{"partial-discovery", "discovery-drift", "denied", "unsupported-metadata", "full-secret", "duplicate-json", "expired-page", "page-rv-drift", "repeated-page", "foreign-namespace", "duplicate-name", "uid-alias", "owner-route", "generation"} {
		t.Run(fault, func(t *testing.T) {
			h := newGCHTTPFixture(t, fault)
			discovery, err := h.g.Discover(t.Context(), h.f.anchor)
			if fault == "partial-discovery" {
				if err != ErrRead || discovery != nil || h.lists != 0 {
					t.Fatal("failed discovery supplied partial catalogue", err)
				}
				return
			}
			if err != nil {
				t.Fatal("initial complete discovery unexpectedly failed", err)
			}
			observation, err := h.g.Collect(t.Context(), discovery)
			if err == nil || observation != nil || strings.Contains(err.Error(), "PRIVATE") || h.lists > 4 {
				t.Fatal("partial/unsafe metadata became sealed evidence or retried", err)
			}
		})
	}
}

func TestGCReaderDescendantsKeepAbsentRootAndBoundCyclesWithoutOwnershipGrant(t *testing.T) {
	for _, scenario := range []string{"absent-root", "owner-cycle"} {
		t.Run(scenario, func(t *testing.T) {
			h := newGCHTTPFixture(t, scenario)
			discovery, err := h.g.Discover(t.Context(), h.f.anchor)
			if err != nil {
				t.Fatal(err)
			}
			observation, err := h.g.Collect(t.Context(), discovery)
			if err != nil {
				t.Fatal(err)
			}
			children, err := observation.Descendants([]types.UID{"root-uid"})
			if err != nil || len(children) != 2 {
				t.Fatal("absent-root/cyclic metadata lost complete UID descendants", err)
			}
			seen := map[types.UID]bool{}
			for _, object := range children {
				seen[object.Metadata.UID] = true
			}
			if !seen["bridge-uid"] || !seen["child-uid"] {
				t.Fatal("wrong UID descendants")
			}
			if _, err := observation.Descendants([]types.UID{"root-uid", "root-uid"}); err != ErrInvalid {
				t.Fatal("duplicate root accepted")
			}
			for _, invalid := range []types.UID{"", "root\nuid", "root\x00uid", types.UID(strings.Repeat("a", 129))} {
				if _, err := observation.Descendants([]types.UID{invalid}); err != ErrInvalid {
					t.Fatal("invalid opaque root accepted")
				}
			}
			// UIDs are opaque identities, never URL/name components. A slash
			// does not supply a route or ownership; it simply matches no edge.
			opaque, err := observation.Descendants([]types.UID{"../root"})
			if err != nil || len(opaque) != 0 {
				t.Fatal("opaque UID acquired route/ownership semantics", err)
			}
			unrelated, err := observation.Descendants([]types.UID{"unrelated-uid"})
			if err != nil || len(unrelated) != 0 {
				t.Fatal("unrelated root adopted descendants", err)
			}
		})
	}
}
