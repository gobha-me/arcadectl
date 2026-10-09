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
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
)

type gcHTTPFixture struct {
	f          *fixture
	g          *GCReader
	lists      int
	reads      map[string]int
	fault      string
	afterRead  func(string)
	wholeFault string
	wholeReads int
	eventRV    int
}

func newGCHTTPFixture(t *testing.T, fault string) *gcHTTPFixture {
	t.Helper()
	h := &gcHTTPFixture{f: newFixture(t), fault: fault, reads: map[string]int{}, eventRV: 21}
	catalogue := gcTestCatalogue(t)
	if strings.HasPrefix(fault, "lease-last") || fault == "event-between-reads-with-leases" {
		version := metav1.GroupVersionForDiscovery{GroupVersion: "coordination.k8s.io/v1", Version: "v1"}
		catalogue.Groups = append(catalogue.Groups, gcGroup{Name: "coordination.k8s.io", Versions: []metav1.GroupVersionForDiscovery{version}, Preferred: version})
		catalogue.Lists[version.GroupVersion] = metav1.APIResourceList{TypeMeta: metav1.TypeMeta{Kind: "APIResourceList", APIVersion: "v1"}, GroupVersion: version.GroupVersion, APIResources: []metav1.APIResource{{Name: "leases", Kind: "Lease", Namespaced: true, Verbs: metav1.Verbs{"delete", "get", "list", "watch"}}}}
	}
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
			if (h.fault == "discovery-drift" && h.reads[path] > 2 || strings.HasSuffix(h.wholeFault, "post-discovery") && h.wholeReads > 0) && gv == "v1" {
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
		wholeLease := strings.HasSuffix(path, "/leases") && r.Header.Get("Accept") == "application/json"
		if !wholeLease && r.Header.Get("Accept") != "application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1" || !queryValid || !strings.Contains(path, "/namespaces/"+h.f.anchor.Namespace+"/") {
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
		if wholeLease {
			h.wholeReads++
			page := coordinationv1.LeaseList{TypeMeta: metav1.TypeMeta{APIVersion: "coordination.k8s.io/v1", Kind: "LeaseList"}, ListMeta: metav1.ListMeta{ResourceVersion: "11"}, Items: []coordinationv1.Lease{}}
			start, end := 0, 128
			if q.Get("continue") == "" {
				page.Continue = "whole-leases-next"
			} else if q.Get("continue") == "whole-leases-next" {
				start, end = 128, 129
			} else {
				t.Error("unknown whole Lease continuation")
				w.WriteHeader(400)
				return
			}
			if start == 128 && h.wholeFault == "late-denial" {
				w.WriteHeader(403)
				return
			}
			if start == 128 && h.wholeFault == "page-rv" {
				page.ResourceVersion = "12"
			}
			for index := start; index < end; index++ {
				m := makeObject("lease-"+strconv.Itoa(index), "lease-uid-"+strconv.Itoa(index)).ObjectMeta
				// Whole public Lease fixtures carry no private metadata canary;
				// metadata-only sources still prove transport-boundary sanitation.
				m.Labels = map[string]string{"public-label": "whole-value"}
				m.Annotations = map[string]string{"public-annotation": "whole-value"}
				if index == 128 {
					switch h.wholeFault {
					case "missing":
						continue
					case "rv", "rv-post-discovery", "rv-post-journal":
						m.ResourceVersion = "22"
					case "rv-back":
						m.ResourceVersion = "20"
					case "generation":
						m.Generation++
					case "uid":
						m.UID = "foreign-uid"
					case "name":
						m.Name = "foreign-name"
					case "owner":
						m.OwnerReferences = []metav1.OwnerReference{{APIVersion: "v1", Kind: "Pod", Name: "foreign", UID: "foreign"}}
					}
				}
				page.Items = append(page.Items, coordinationv1.Lease{TypeMeta: metav1.TypeMeta{APIVersion: "coordination.k8s.io/v1", Kind: "Lease"}, ObjectMeta: m})
			}
			if h.wholeFault == "unknown-field" {
				body, _ := json.Marshal(page)
				var object map[string]any
				_ = json.Unmarshal(body, &object)
				object["items"].([]any)[0].(map[string]any)["unexpected"] = true
				_ = json.NewEncoder(w).Encode(object)
			} else {
				_ = json.NewEncoder(w).Encode(page)
			}
			return
		}
		page := metav1.PartialObjectMetadataList{TypeMeta: metav1.TypeMeta{APIVersion: "meta.k8s.io/v1", Kind: "PartialObjectMetadataList"}, ListMeta: metav1.ListMeta{ResourceVersion: "11"}, Items: []metav1.PartialObjectMetadata{}}
		switch {
		case strings.HasSuffix(path, "/leases"):
			if q.Get("continue") == "" {
				for index := 0; index < 128; index++ {
					page.Items = append(page.Items, makeObject("lease-"+strconv.Itoa(index), "lease-uid-"+strconv.Itoa(index)))
				}
				page.Continue = "leases-next"
			} else if q.Get("continue") == "leases-next" {
				if h.fault == "lease-last-late-denial" {
					w.WriteHeader(403)
					return
				}
				if h.fault == "lease-last-page-rv" {
					page.ResourceVersion = "12"
				}
				page.Items = append(page.Items, makeObject("lease-128", "lease-uid-128"))
			} else {
				t.Error("unknown Lease continuation used")
				w.WriteHeader(400)
				return
			}
		case strings.HasSuffix(path, "/events"):
			page.Items = append(page.Items, makeObject("event", "event-uid"))
			page.Items[0].ResourceVersion = strconv.Itoa(h.eventRV)
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
				if h.fault == "event-foreign-uid" {
					page.Items[0].UID = "event-uid"
				}
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

func TestGCReaderLeasePagesReadLastWithoutChangingSealedCatalogue(t *testing.T) {
	for _, fault := range []string{"lease-last", "lease-last-late-denial", "lease-last-page-rv"} {
		t.Run(fault, func(t *testing.T) {
			h := newGCHTTPFixture(t, fault)
			discovery, err := h.g.Discover(t.Context(), h.f.anchor)
			if err != nil {
				t.Fatal(err)
			}
			original := discovery.Resources()
			order := []string{}
			h.afterRead = func(path string) {
				if strings.Contains(path, "/namespaces/"+h.f.anchor.Namespace+"/") {
					order = append(order, path)
				}
			}
			observation, err := h.g.Collect(t.Context(), discovery)
			if (err == nil) != (fault == "lease-last") || !reflect.DeepEqual(original, discovery.Resources()) {
				t.Fatal("read scheduling changed the catalogue or accepted an incomplete Lease page", err)
			}
			if len(order) != len(original)+2 || !strings.HasSuffix(order[len(order)-1], "/leases") || !strings.HasSuffix(order[len(order)-2], "/leases") {
				t.Fatal("all source/pages were not read with both Lease pages last")
			}
			for _, path := range order[:len(order)-2] {
				if strings.HasSuffix(path, "/leases") {
					t.Fatal("Lease page aged behind another metadata source")
				}
			}
			if err == nil {
				last := ""
				counts := map[GCResource]int{}
				for _, row := range observation.Objects() {
					if row.Source.GVR.String() < last {
						t.Fatal("public observation source order changed")
					}
					last = row.Source.GVR.String()
					counts[row.Source]++
				}
				for _, source := range original {
					if counts[source] == 0 || source.Kind == "Lease" && counts[source] != 129 {
						t.Fatal("complete original source membership lost")
					}
				}
			}
		})
	}
}

func TestGCReaderPairedLeasesCompleteStrictAndSealed(t *testing.T) {
	stages := map[string]string{
		"": "complete", "late-denial": "lease-pages", "page-rv": "lease-pages",
		"missing": "lease-membership", "rv": "lease-correlation", "uid": "lease-correlation",
		"name": "lease-correlation", "owner": "lease-correlation", "unknown-field": "lease-pages",
		"post-discovery": "closing", "post-journal": "closing",
	}
	for _, fault := range []string{"", "late-denial", "page-rv", "missing", "rv", "uid", "name", "owner", "unknown-field", "post-discovery", "post-journal"} {
		t.Run("paired-"+fault, func(t *testing.T) {
			h := newGCHTTPFixture(t, "lease-last")
			h.wholeFault = fault
			discovery, err := h.g.Discover(t.Context(), h.f.anchor)
			if err != nil {
				t.Fatal(err)
			}
			if fault == "post-journal" {
				h.afterRead = func(path string) {
					if path != "/api" || h.wholeReads == 0 {
						return
					}
					ns, err := h.f.core.CoreV1().Namespaces().Get(t.Context(), h.f.anchor.Namespace, metav1.GetOptions{})
					if err != nil {
						t.Fatal(err)
					}
					ns.ResourceVersion = "2"
					if _, err := h.f.core.CoreV1().Namespaces().Update(t.Context(), ns, metav1.UpdateOptions{}); err != nil {
						t.Fatal(err)
					}
				}
			}
			before := time.Now().UTC()
			observation, err := h.g.CollectWithLeases(t.Context(), discovery)
			if (err == nil) != (fault == "") || err != nil && observation != nil {
				t.Fatal("incomplete/inconsistent whole Lease pages became sealed evidence", err)
			}
			if h.g.DiagnosticStage() != stages[fault] {
				t.Fatal("fixed diagnostic did not identify the actual collection boundary", h.g.DiagnosticStage())
			}
			if err != nil {
				return
			}
			leases, readAt := observation.PairedLeases()
			if leases == nil || len(leases.Items) != 129 || h.wholeReads != 2 || leases.Continue != "" || leases.RemainingItemCount != nil || readAt.Before(before) || readAt.After(time.Now().UTC()) || leases.Items[0].Labels["public-label"] != "whole-value" || leases.Items[0].Annotations["public-annotation"] != "whole-value" {
				t.Fatal("paired full Lease evidence missing or not bounded")
			}
			leases.Items[0].ResourceVersion = "forged"
			again, sameTime := observation.PairedLeases()
			if again.Items[0].ResourceVersion != "21" || !sameTime.Equal(readAt) {
				t.Fatal("accessor mutated sealed Lease evidence")
			}
			metadataOnly, err := h.g.Collect(t.Context(), discovery)
			if err != nil {
				t.Fatal(err)
			}
			if leases, stamp := metadataOnly.PairedLeases(); leases != nil || !stamp.IsZero() || h.wholeReads != 2 {
				t.Fatal("ordinary metadata-only collector acquired whole Lease authority")
			}
		})
	}
}

func TestGCReaderPairedLeasesRequiresCanonicalDiscoveredSource(t *testing.T) {
	h := newGCHTTPFixture(t, "")
	discovery, err := h.g.Discover(t.Context(), h.f.anchor)
	if err != nil {
		t.Fatal(err)
	}
	if observation, err := h.g.CollectWithLeases(t.Context(), discovery); err == nil || observation != nil || h.wholeReads != 0 {
		t.Fatal("missing canonical Lease source produced paired evidence")
	}
	if h.g.DiagnosticStage() != "lease-source" {
		t.Fatal("missing Lease source diagnostic unavailable")
	}
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
	for _, fault := range []string{"event-identical", "event-between-reads", "event-between-reads-with-leases", "event-between-aliases", "event-rv", "event-owner", "event-name", "event-duplicate", "event-foreign-uid"} {
		t.Run(fault, func(t *testing.T) {
			h := newGCHTTPFixture(t, fault)
			var order []string
			eventReads := 0
			churn := strings.HasPrefix(fault, "event-between-reads")
			pairLeases := fault == "event-between-reads-with-leases"
			h.afterRead = func(path string) {
				if strings.Contains(path, "/namespaces/") {
					order = append(order, path)
					if strings.HasSuffix(path, "/events") {
						eventReads++
						// An actual update after the first response and before
						// the second snapshot must still refuse, even adjacent.
						if fault == "event-between-aliases" && eventReads == 2 {
							h.eventRV++
						}
					}
					if churn && (strings.HasSuffix(path, "/secrets") || strings.HasSuffix(path, "/legacywidgets") || strings.HasSuffix(path, "/widgets")) {
						h.eventRV++
					}
				}
			}
			discovery, err := h.g.Discover(t.Context(), h.f.anchor)
			sources := 5
			if pairLeases {
				sources++
			}
			if err != nil || len(discovery.Resources()) != sources {
				t.Fatal("complete Event alias catalogue unproved", err)
			}
			original := discovery.Resources()
			var observation *GCObservation
			if pairLeases {
				observation, err = h.g.CollectWithLeases(t.Context(), discovery)
			} else {
				observation, err = h.g.Collect(t.Context(), discovery)
			}
			if fault != "event-identical" && !churn {
				if err != ErrOwnership || observation != nil {
					t.Fatal("conflicting alias or same-source duplicate accepted")
				}
				expected := "metadata-uid-correlation"
				if fault == "event-duplicate" {
					expected = "metadata-shape"
				} else if fault == "event-rv" || fault == "event-between-aliases" {
					expected = "event-alias-rv-conflict"
				} else if fault == "event-name" || fault == "event-owner" {
					expected = "event-alias-metadata-conflict"
				}
				if h.g.DiagnosticStage() != expected {
					t.Fatal("Event refusal diagnostic unavailable", h.g.DiagnosticStage())
				}
				if fault == "event-between-aliases" && (eventReads != 2 || h.lists != 6 || h.eventRV != 22 || !strings.HasSuffix(order[len(order)-1], "/events") || !strings.HasSuffix(order[len(order)-2], "/events")) {
					t.Fatal("adjacent alias conflict was retried, separated or normalized")
				}
				return
			}
			objects, lists := 134, 6
			if pairLeases {
				objects += 129
				lists += 4 // two complete metadata pages plus two whole Lease pages
			}
			if err != nil || observation == nil || len(observation.Objects()) != objects || h.lists != lists {
				t.Fatal("identical known Event alias was not completely observed", err)
			}
			if !reflect.DeepEqual(original, discovery.Resources()) {
				t.Fatal("read scheduling changed the original sealed catalogue")
			}
			observed := observation.Objects()
			for index, object := range observed {
				if index > 0 && observed[index-1].Source.GVR.String() > object.Source.GVR.String() {
					t.Fatal("read scheduling changed canonical observation order")
				}
			}
			if churn {
				events := []int{}
				for index, path := range order {
					if strings.HasSuffix(path, "/events") {
						events = append(events, index)
					}
				}
				if len(events) != 2 || events[1] != events[0]+1 || h.eventRV != 25 {
					t.Fatal("known Event aliases were separated by unrelated metadata reads", order)
				}
				for _, source := range original {
					prefix := "/apis/" + source.GVR.GroupVersion().String()
					if source.GVR.Group == "" {
						prefix = "/api/" + source.GVR.Version
					}
					path := prefix + "/namespaces/" + h.f.anchor.Namespace + "/" + source.GVR.Resource
					pages := 1
					if source.GVR.Resource == "widgets" {
						pages = 2
					} else if source.GVR.Resource == "leases" {
						pages = 4
					}
					if h.reads[path] != pages {
						t.Fatal("scheduled collection skipped or repeated a source/page", source.GVR, h.reads[path])
					}
				}
				if pairLeases {
					for _, path := range order[len(order)-4:] {
						if !strings.HasSuffix(path, "/leases") {
							t.Fatal("paired Lease reads no longer finish the collection")
						}
					}
				}
			}
		})
	}
}

func TestGCReaderDiagnosticClosedStagesAndInvalidAttemptReset(t *testing.T) {
	labels := map[uint32]string{
		gcStageOpening: "opening", gcStageMetadataPages: "metadata-pages",
		gcStageMetadataShape: "metadata-shape", gcStageMetadataUIDs: "metadata-uid-correlation",
		gcStageEventAliasRV: "event-alias-rv-conflict", gcStageEventAliasMetadata: "event-alias-metadata-conflict",
		gcStageGraphBound: "metadata-graph-bound",
		gcStageLeasePages: "lease-pages", gcStageLeaseMembership: "lease-membership",
		gcStageLeaseCorrelation: "lease-correlation", gcStageLeaseSource: "lease-source",
		gcStageClosing: "closing", gcStageComplete: "complete",
	}
	g := &GCReader{}
	for value := range uint32(256) {
		g.diagnostic.Store(value)
		expected := labels[value]
		if expected == "" {
			expected = "unknown"
		}
		if g.DiagnosticStage() != expected {
			t.Fatal("diagnostic escaped its fixed labels")
		}
	}
	g.diagnostic.Store(^uint32(0))
	if g.DiagnosticStage() != "unknown" || (*GCReader)(nil).DiagnosticStage() != "unknown" {
		t.Fatal("corrupt or absent diagnostic manufactured a label")
	}
	g.diagnostic.Store(gcStageComplete)
	if observation, err := g.Collect(nil, nil); observation != nil || err != ErrInvalid || g.DiagnosticStage() != "unknown" {
		t.Fatal("invalid attempt retained stale progress or changed public refusal")
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
