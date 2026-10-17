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
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installsafety"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/flowcontrol"
)

// The constructor, TLS, bounded strict native transports and complete observer
// are real. Only public API payloads and optional scheduling hooks are synthetic.
func pairedNativeFixture(t *testing.T, f *fixture, hook func(http.ResponseWriter, *http.Request, map[string]any) bool) *rest.Config {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet {
			t.Error("observer attempted mutation")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.URL.Path == "/api/v1" {
			_ = json.NewEncoder(w).Encode(&metav1.APIResourceList{GroupVersion: "v1", APIResources: []metav1.APIResource{
				{Name: "namespaces", Kind: "Namespace", Verbs: metav1.Verbs{"get", "list"}},
				{Name: "secrets", Kind: "Secret", Namespaced: true, Verbs: metav1.Verbs{"get", "list"}},
				{Name: "configmaps", Kind: "ConfigMap", Namespaced: true, Verbs: metav1.Verbs{"get", "list"}},
			}})
			return
		}
		for _, object := range f.objects {
			if strings.HasSuffix(r.URL.Path, "/"+object.Name) {
				if r.Header.Get("Accept") != "application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1" {
					t.Error("owner read is not metadata-only")
				}
				copy := object.DeepCopy()
				copy.APIVersion, copy.Kind = "meta.k8s.io/v1", "PartialObjectMetadata"
				_ = json.NewEncoder(w).Encode(copy)
				return
			}
		}
		q := r.URL.Query()
		if q.Get("limit") != "128" || q.Has("resourceVersion") || q.Has("resourceVersionMatch") || q.Has("labelSelector") || q.Has("fieldSelector") || q.Has("watch") {
			t.Error("collection options changed")
		}
		for _, c := range f.cs {
			prefix := "/apis/" + c.gv
			if c.gv == "v1" {
				prefix = "/api/v1"
			}
			if c.namespaced {
				prefix += "/namespaces/" + f.anchor.Namespace
			}
			if r.URL.Path != prefix+"/"+c.resource {
				continue
			}
			page := map[string]any{"apiVersion": c.gv, "kind": c.kind + "List", "metadata": map[string]any{"resourceVersion": "100"}, "items": []any{}}
			if c.kind == "Secret" {
				if r.Header.Get("Accept") != "application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1" {
					t.Error("full Secret read attempted")
				}
				page["apiVersion"], page["kind"], page["items"] = "meta.k8s.io/v1", "PartialObjectMetadataList", f.secrets
			} else {
				items := make([]any, 0, len(f.lists[c.resource]))
				for _, item := range f.lists[c.resource] {
					items = append(items, item.DeepCopy().Object)
				}
				page["items"] = items
			}
			if hook != nil && hook(w, r, page) {
				return
			}
			_ = json.NewEncoder(w).Encode(page)
			return
		}
		t.Error("unexpected native route")
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(server.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	return &rest.Config{Host: server.URL, TLSClientConfig: rest.TLSClientConfig{CAData: ca}, RateLimiter: flowcontrol.NewFakeAlwaysRateLimiter()}
}

func pairedObserver(t *testing.T, f *fixture, config *rest.Config, paired bool) *Observer {
	t.Helper()
	newObserver := New
	if paired {
		newObserver = NewWithPairedCollectionReads
	}
	o, err := newObserver(config, f.o.journal, f.o.plan)
	if err != nil || o.pairedCollections != paired {
		t.Fatal("native scheduling constructor failed", err)
	}
	return o
}

func pairedWait(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(10 * time.Second):
		t.Fatal("collection scheduling barrier not reached")
	}
}

func TestPairedCollectionsEqualSerialWholeObservation(t *testing.T) {
	f := newFixture(t)
	config := pairedNativeFixture(t, f, func(w http.ResponseWriter, r *http.Request, page map[string]any) bool {
		if strings.HasSuffix(r.URL.Path, "/gameservers") || strings.HasSuffix(r.URL.Path, "/gamebackups") {
			if r.URL.Query().Get("continue") == "" {
				page["metadata"].(map[string]any)["continue"] = "second-page"
			} else if r.URL.Query().Get("continue") != "second-page" {
				t.Error("continuation not preserved")
			} else {
				page["items"] = []any{map[string]any{"apiVersion": "arcade.gobha.me/v1alpha1", "kind": strings.TrimSuffix(page["kind"].(string), "List"), "metadata": map[string]any{"name": "retained", "namespace": f.anchor.Namespace, "uid": page["kind"], "resourceVersion": "90"}}}
			}
		}
		return false
	})
	want, err := pairedObserver(t, f, config, false).Collect(t.Context(), f.anchor)
	if err != nil {
		t.Fatal("serial oracle failed", err)
	}
	got, err := pairedObserver(t, f, config, true).Collect(t.Context(), f.anchor)
	if err != nil || !reflect.DeepEqual(want.Snapshot(), got.Snapshot()) || !reflect.DeepEqual(want.Runtime(), got.Runtime()) || !reflect.DeepEqual(want.Journal(), got.Journal()) {
		t.Fatal("paired complete evidence differs from serial", err)
	}
	if len(got.Snapshot().GameServers.Items) != 1 || len(got.Snapshot().Backups.Items) != 1 {
		t.Fatal("paged retained membership omitted")
	}
}

func TestPairedCollectionsBoundFullRequestsAndKeepContinuationsCanonical(t *testing.T) {
	f := newFixture(t)
	var mu sync.Mutex
	var trace []string
	config := pairedNativeFixture(t, f, func(w http.ResponseWriter, r *http.Request, page map[string]any) bool {
		if strings.HasSuffix(r.URL.Path, "/gameservers") && r.URL.Query().Get("continue") == "" {
			page["metadata"].(map[string]any)["continue"] = "next"
		}
		mu.Lock()
		trace = append(trace, r.URL.Path+"?"+r.URL.Query().Get("continue"))
		mu.Unlock()
		return false
	})
	var active, maximum atomic.Int32
	var once [2]sync.Once
	var entered, release, exited [2]chan struct{}
	for i := range 2 {
		entered[i], release[i], exited[i] = make(chan struct{}), make(chan struct{}), make(chan struct{})
	}
	config.WrapTransport = func(next http.RoundTripper) http.RoundTripper {
		return roundTripFunc(func(r *http.Request) (*http.Response, error) {
			n := active.Add(1)
			defer active.Add(-1)
			for old := maximum.Load(); n > old && !maximum.CompareAndSwap(old, n); old = maximum.Load() {
			}
			response, err := next.RoundTrip(r)
			for i, resource := range []string{"gameservers", "gamebackups"} {
				if strings.HasSuffix(r.URL.Path, "/"+resource) && r.URL.Query().Get("continue") == "" {
					close(entered[i])
					<-release[i] // Includes the strict transport's whole body read.
					close(exited[i])
				}
			}
			return response, err
		})
	}
	o := pairedObserver(t, f, config, true)
	done := make(chan error, 1)
	joined := false
	defer func() {
		for i := range 2 {
			once[i].Do(func() { close(release[i]) })
		}
		if !joined {
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Error("collector leaked")
			}
		}
	}()
	go func() { _, err := o.Collect(t.Context(), f.anchor); done <- err }()
	for i := range 2 {
		pairedWait(t, entered[i])
	}
	once[0].Do(func() { close(release[0]) })
	pairedWait(t, exited[0])
	select {
	case <-done:
		t.Fatal("collector outran pending second first page")
	case <-time.After(100 * time.Millisecond):
	}
	if maximum.Load() != 2 || active.Load() != 1 {
		t.Fatal("prefetch did not remain bounded with one pending body")
	}
	once[1].Do(func() { close(release[1]) })
	pairedWait(t, exited[1])
	if err := <-done; err != nil {
		joined = true
		t.Fatal(err)
	}
	joined = true
	if active.Load() != 0 || maximum.Load() != 2 {
		t.Fatal("requests escaped fixed pair")
	}
	mu.Lock()
	defer mu.Unlock()
	firstPages, continuation := map[string]int{}, -1
	for i, entry := range trace {
		if strings.HasSuffix(entry, "/gameservers?next") {
			continuation = i
		}
		for _, resource := range []string{"gameservers", "gamebackups"} {
			if strings.HasSuffix(entry, "/"+resource+"?") {
				firstPages[resource]++
			}
		}
	}
	if firstPages["gameservers"] != 1 || firstPages["gamebackups"] != 1 || continuation < 2 || len(trace) != 21 {
		t.Fatal("first page replayed, continuation omitted or collection missing")
	}
}

func TestPairedCollectionsPreserveAggregateBudgetAtCanonicalBoundary(t *testing.T) {
	f := newFixture(t)
	config := pairedNativeFixture(t, f, func(w http.ResponseWriter, r *http.Request, page map[string]any) bool {
		if strings.HasSuffix(r.URL.Path, "/gameservers") && r.URL.Query().Get("continue") == "" {
			page["metadata"].(map[string]any)["continue"] = "next"
		}
		return false
	})
	o := pairedObserver(t, f, config, true)
	var total, firstTotal int
	for _, c := range f.cs[:2] {
		for _, token := range []string{"", "next"} {
			if c.kind != "GameServer" && token != "" {
				continue
			}
			page, err := o.collectionPage(t.Context(), c, metav1.ListOptions{Limit: pageLimit, Continue: token})
			if err != nil {
				t.Fatal(err)
			}
			body, err := json.Marshal(page)
			if err != nil {
				t.Fatal(err)
			}
			total += len(body)
			if c.kind == "GameServer" {
				firstTotal += len(body)
			}
		}
	}
	for _, limit := range []int{0, firstTotal - 1, firstTotal, total - 1, total} {
		var wantError error
		var wantBudget int
		for _, paired := range []bool{false, true} {
			s, r := &installsafety.Snapshot{}, &installsafety.RuntimeSnapshot{}
			cs := append(collections(s), runtimeCollections(r)...)
			g := newOwnerGraph(o, nil, cs)
			budget := limit
			var err error
			if paired {
				err = o.collectPair(t.Context(), cs[0], cs[1], g, &budget)
			} else {
				err = o.collectList(t.Context(), cs[0], g, &budget)
				if err == nil {
					err = o.collectList(t.Context(), cs[1], g, &budget)
				}
				wantError, wantBudget = err, budget
			}
			if paired && (err != wantError || budget != wantBudget) || (limit == total) != (err == nil) {
				t.Fatal("aggregate budget or canonical refusal changed", limit, paired, err, budget)
			}
		}
	}
}

func TestPairedCollectionsSecretNeverOverlapsAdjacentLists(t *testing.T) {
	f := newFixture(t)
	config := pairedNativeFixture(t, f, nil)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	var active, claimsExited, policiesEntered atomic.Int32
	var secretActive atomic.Bool
	config.WrapTransport = func(next http.RoundTripper) http.RoundTripper {
		return roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.Query().Get("limit") == "" {
				return next.RoundTrip(r)
			}
			n := active.Add(1)
			defer active.Add(-1)
			secret := strings.HasSuffix(r.URL.Path, "/secrets")
			if secret {
				if n != 1 || claimsExited.Load() != 1 || !secretActive.CompareAndSwap(false, true) {
					t.Error("Secret overlapped prior collection")
				}
				defer secretActive.Store(false)
			} else if secretActive.Load() {
				t.Error("another collection overlapped Secret metadata")
			}
			if strings.HasSuffix(r.URL.Path, "/validatingadmissionpolicies") {
				policiesEntered.Add(1)
			}
			response, err := next.RoundTrip(r)
			if strings.HasSuffix(r.URL.Path, "/persistentvolumeclaims") {
				claimsExited.Add(1)
			}
			if secret {
				close(entered)
				<-release
			}
			return response, err
		})
	}
	o := pairedObserver(t, f, config, true)
	done := make(chan error, 1)
	joined := false
	defer func() {
		once.Do(func() { close(release) })
		if !joined {
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Error("Secret scheduling collector leaked")
			}
		}
	}()
	go func() { _, err := o.Collect(t.Context(), f.anchor); done <- err }()
	pairedWait(t, entered)
	select {
	case <-done:
		t.Fatal("collector outran pending Secret metadata")
	case <-time.After(100 * time.Millisecond):
	}
	if active.Load() != 1 || policiesEntered.Load() != 0 || !secretActive.Load() {
		t.Fatal("Secret isolation boundary was not preserved")
	}
	once.Do(func() { close(release) })
	err := <-done
	joined = true
	if err != nil || active.Load() != 0 || policiesEntered.Load() != 1 || secretActive.Load() {
		t.Fatal("isolated metadata collection did not finish normally", err)
	}
}

func TestPairedCollectionsRejectNativeDriftLikeSerial(t *testing.T) {
	for _, scenario := range []string{"second-read-error", "unknown-first", "unknown-second", "duplicate-uid", "rv-change", "token-cycle", "closing-journal", "listed-owner-drift"} {
		t.Run(scenario, func(t *testing.T) {
			f := newFixture(t)
			if scenario == "listed-owner-drift" {
				f.claim("world", owner("Secret", "parent"))
				f.owner("secrets", "Secret", "parent")
				parent := f.objects[address("secrets", f.anchor.Namespace, "parent")]
				f.secrets = append(f.secrets, *parent.DeepCopy())
				parent.ResourceVersion = "31"
			}
			config := pairedNativeFixture(t, f, func(w http.ResponseWriter, r *http.Request, page map[string]any) bool {
				second := strings.HasSuffix(r.URL.Path, "/gamebackups")
				first := strings.HasSuffix(r.URL.Path, "/gameservers")
				switch {
				case scenario == "second-read-error" && second:
					w.WriteHeader(http.StatusForbidden)
					return true
				case scenario == "unknown-first" && first || scenario == "unknown-second" && second:
					page["items"] = []any{map[string]any{"apiVersion": "arcade.gobha.me/v1alpha1", "kind": strings.TrimSuffix(page["kind"].(string), "List"), "metadata": map[string]any{"name": "unknown-field", "namespace": f.anchor.Namespace, "uid": "unknown-uid", "resourceVersion": "90"}, "spec": map[string]any{"privateUnknownField": true}}}
				case scenario == "duplicate-uid" && (first || second):
					page["items"] = []any{map[string]any{"apiVersion": "arcade.gobha.me/v1alpha1", "kind": strings.TrimSuffix(page["kind"].(string), "List"), "metadata": map[string]any{"name": "collision", "namespace": f.anchor.Namespace, "uid": "same-uid", "resourceVersion": "90"}}}
				case (scenario == "rv-change" || scenario == "token-cycle") && second:
					page["metadata"].(map[string]any)["continue"] = "next"
					if scenario == "rv-change" && r.URL.Query().Get("continue") != "" {
						page["metadata"].(map[string]any)["resourceVersion"] = "101"
					}
				case scenario == "closing-journal" && strings.HasSuffix(r.URL.Path, "/endpointslices"):
					ns, err := f.core.CoreV1().Namespaces().Get(r.Context(), f.anchor.Namespace, metav1.GetOptions{})
					if err != nil {
						t.Error(err)
						return true
					}
					ns.ResourceVersion += "2"
					if _, err := f.core.CoreV1().Namespaces().Update(r.Context(), ns, metav1.UpdateOptions{}); err != nil {
						t.Error(err)
					}
				}
				return false
			})
			var want error
			for _, paired := range []bool{false, true} {
				got, err := pairedObserver(t, f, config, paired).Collect(t.Context(), f.anchor)
				if got != nil || err == nil {
					t.Fatal("partial or drifted native evidence accepted", paired)
				}
				if !paired {
					want = err
				} else if !errors.Is(err, want) {
					t.Fatal("paired refusal differs from original serial", want, err)
				}
			}
		})
	}
}

func TestPairedCollectionsRefusalAndCancellationJoinLatePrefetch(t *testing.T) {
	for _, scenario := range []string{"first-refusal", "caller-cancel"} {
		t.Run(scenario, func(t *testing.T) {
			f := newFixture(t)
			config := pairedNativeFixture(t, f, func(w http.ResponseWriter, r *http.Request, page map[string]any) bool {
				if scenario == "first-refusal" && strings.HasSuffix(r.URL.Path, "/gameservers") {
					w.WriteHeader(http.StatusForbidden)
					return true
				}
				return false
			})
			var entered, release, exited [2]chan struct{}
			var once [2]sync.Once
			for i := range 2 {
				entered[i], release[i], exited[i] = make(chan struct{}), make(chan struct{}), make(chan struct{})
			}
			config.WrapTransport = func(next http.RoundTripper) http.RoundTripper {
				return roundTripFunc(func(r *http.Request) (*http.Response, error) {
					response, err := next.RoundTrip(r)
					for i, resource := range []string{"gameservers", "gamebackups"} {
						if strings.HasSuffix(r.URL.Path, "/"+resource) {
							close(entered[i])
							<-release[i] // Deliberately later than cancellation.
							close(exited[i])
						}
					}
					return response, err
				})
			}
			o := pairedObserver(t, f, config, true)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			joined := false
			defer func() {
				for i := range 2 {
					once[i].Do(func() { close(release[i]) })
				}
				if !joined {
					select {
					case <-done:
					case <-time.After(10 * time.Second):
						t.Error("refused collector leaked")
					}
				}
			}()
			go func() {
				result, err := o.Collect(ctx, f.anchor)
				if result != nil {
					t.Error("refused invocation returned partial evidence")
				}
				done <- err
			}()
			for i := range 2 {
				pairedWait(t, entered[i])
			}
			if scenario == "caller-cancel" {
				cancel()
			}
			once[0].Do(func() { close(release[0]) })
			pairedWait(t, exited[0])
			select {
			case <-done:
				t.Fatal("refusal returned before late worker joined")
			case <-time.After(100 * time.Millisecond):
			}
			once[1].Do(func() { close(release[1]) })
			pairedWait(t, exited[1])
			err := <-done
			joined = true
			if !errors.Is(err, ErrRead) {
				t.Fatal("expected refused complete observation", err)
			}
		})
	}
}

func TestPairedCollectionsSecondFailureDoesNotCancelFirstContinuation(t *testing.T) {
	f := newFixture(t)
	var continued atomic.Bool
	secondFailed := make(chan struct{})
	config := pairedNativeFixture(t, f, func(w http.ResponseWriter, r *http.Request, page map[string]any) bool {
		if strings.HasSuffix(r.URL.Path, "/gamebackups") {
			w.WriteHeader(http.StatusForbidden)
			return true
		}
		if strings.HasSuffix(r.URL.Path, "/gameservers") {
			if r.URL.Query().Get("continue") == "" {
				page["metadata"].(map[string]any)["continue"] = "next"
			} else {
				select {
				case <-secondFailed:
				case <-r.Context().Done():
					t.Error("first continuation cancelled before second error was observed")
					return true
				}
				select {
				case <-r.Context().Done():
					t.Error("second prefetch failure cancelled first collection")
				case <-time.After(100 * time.Millisecond):
				}
				continued.Store(true)
			}
		}
		return false
	})
	config.WrapTransport = func(next http.RoundTripper) http.RoundTripper {
		return roundTripFunc(func(r *http.Request) (*http.Response, error) {
			response, err := next.RoundTrip(r)
			if strings.HasSuffix(r.URL.Path, "/gamebackups") {
				if err == nil {
					t.Error("second page did not actually fail native transport")
				}
				close(secondFailed)
			}
			return response, err
		})
	}
	result, err := pairedObserver(t, f, config, true).Collect(t.Context(), f.anchor)
	if result != nil || !errors.Is(err, ErrRead) || !continued.Load() {
		t.Fatal("second failure changed first collection's canonical read boundary", err)
	}
}
