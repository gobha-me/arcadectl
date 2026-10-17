// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installstate"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Synthetic healthy native status tests scheduling and strict configuration
// closure only; it is not evidence of effective native admission enforcement.
func testConfiguredReadLanes(t *testing.T) (*ClusterSecurityBaseline, *installstate.Snapshot, [2][]string) {
	t.Helper()
	f := newBaselineFixture(t)
	completeBaselineFixture(t, f)
	objects := make(map[string]*unstructured.Unstructured)
	var paths [2][]string
	for _, resource := range f.snapshot.Document().SecurityBaseline.Resources {
		path, err := resourcePath(resource.Key, false)
		if err != nil {
			t.Fatal("configuration lane route unavailable")
		}
		object := f.access.objects[resource.Key].DeepCopy()
		lane := 1
		if resource.Key.Kind == "ValidatingAdmissionPolicy" {
			lane = 0
			object.SetGeneration(1)
			object.Object["status"] = map[string]any{"observedGeneration": int64(1), "typeChecking": map[string]any{}}
		}
		paths[lane] = append(paths[lane], path)
		objects[path] = object
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Error("configuration lane attempted mutation")
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/namespaces/"+f.plan.Namespace() {
			namespace, err := f.access.client.CoreV1().Namespaces().Get(r.Context(), f.plan.Namespace(), metav1.GetOptions{})
			if err != nil {
				w.WriteHeader(500)
				return
			}
			namespace.APIVersion, namespace.Kind = "v1", "Namespace"
			_ = json.NewEncoder(w).Encode(namespace)
			return
		}
		object := objects[r.URL.Path]
		if object == nil {
			t.Error("configuration lane escaped exact signed routes")
			w.WriteHeader(404)
			return
		}
		_ = json.NewEncoder(w).Encode(object)
	}))
	t.Cleanup(server.Close)
	access, err := NewDirectHTTPAccess(serverConfig(server))
	if err != nil {
		t.Fatal("configuration lane access unavailable")
	}
	store, err := installstate.NewWithBaseline(access.Namespaces(), f.engine.baselinePlan(), f.plan)
	if err != nil {
		t.Fatal("configuration lane store unavailable")
	}
	engine, err := NewWithBaselineAccess(access, store, f.engine.files, f.engine.baselinePlan(), f.plan)
	if err != nil {
		t.Fatal("configuration lane engine unavailable")
	}
	snapshot, err := store.Load(t.Context(), f.snapshot.Anchor())
	if err != nil {
		t.Fatal("configuration lane snapshot unavailable")
	}
	configuration, err := NewClusterSecurityBaseline(engine, access)
	if err != nil {
		t.Fatal("configuration lane composition refused")
	}
	return configuration, snapshot, paths
}

func TestBaselineConfigurationTwoLanesPreserveCompletePassesAndClosingJoin(t *testing.T) {
	configuration, snapshot, paths := testConfiguredReadLanes(t)
	var entered, release [2][2]chan struct{}
	var once [2][2]sync.Once
	for pass := range entered {
		for lane := range entered[pass] {
			entered[pass][lane], release[pass][lane] = make(chan struct{}), make(chan struct{})
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	done := make(chan error, 1)
	joined := false
	defer func() {
		cancel()
		for pass := range release {
			for lane := range release[pass] {
				once[pass][lane].Do(func() { close(release[pass][lane]) })
			}
		}
		if !joined {
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Error("configuration lane invocation leaked")
			}
		}
	}()
	var active, maximum, blocked, closes atomic.Int32
	var finished [2]atomic.Int32
	var mu sync.Mutex
	var seen [2][]string
	next := configuration.access.client.Transport
	configuration.access.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		lane := -1
		for i := range paths {
			for _, path := range paths[i] {
				if r.URL.Path == path {
					lane = i
				}
			}
		}
		if lane < 0 {
			closes.Add(1)
			if blocked.Load() != 0 {
				t.Error("closing journal read or second pass outran configuration lane")
				return nil, ErrRead
			}
			return next.RoundTrip(r)
		}
		n := active.Add(1)
		defer active.Add(-1)
		for old := maximum.Load(); n > old && !maximum.CompareAndSwap(old, n); old = maximum.Load() {
		}
		mu.Lock()
		index := len(seen[lane])
		seen[lane] = append(seen[lane], r.URL.Path)
		mu.Unlock()
		pass := index / len(paths[lane])
		if pass >= 2 {
			t.Error("configuration lane replayed a complete pass")
			return nil, ErrRead
		}
		if pass != 0 && (finished[0].Load() < 6 || finished[1].Load() < 6) {
			t.Error("second configuration pass outran an original read lane")
			return nil, ErrRead
		}
		if index%len(paths[lane]) == 0 && closes.Load() != int32(2+4*pass) {
			t.Error("configuration read pass skipped its original closing/opening fences")
			return nil, ErrRead
		}
		response, err := next.RoundTrip(r)
		if index%len(paths[lane]) == len(paths[lane])-1 {
			blocked.Add(1)
			close(entered[pass][lane])
			select {
			case <-release[pass][lane]:
			case <-r.Context().Done():
			}
			blocked.Add(-1)
		}
		finished[lane].Add(1)
		return response, err
	})
	go func() { done <- configuration.VerifyConfigured(ctx, snapshot) }()
	for pass := range entered {
		for lane := range entered[pass] {
			select {
			case <-entered[pass][lane]:
			case <-done:
				joined = true
				t.Fatal("configuration returned before both final reads overlapped")
			case <-ctx.Done():
				t.Fatal("configuration failed to overlap two bounded lanes")
			}
		}
		once[pass][0].Do(func() { close(release[pass][0]) })
		select {
		case <-done:
			joined = true
			t.Fatal("configuration returned before its second lane joined")
		case <-time.After(100 * time.Millisecond):
		}
		once[pass][1].Do(func() { close(release[pass][1]) })
	}
	select {
	case err := <-done:
		joined = true
		if err != nil {
			t.Fatal("complete joined configuration proof refused")
		}
	case <-ctx.Done():
		t.Fatal("released configuration lanes failed to join")
	}
	if active.Load() != 0 || maximum.Load() != 2 || blocked.Load() != 0 || closes.Load() != 8 {
		t.Fatal("configuration changed lane bound, leaked readers or skipped original fences")
	}
	for lane := range paths {
		want := append(append([]string(nil), paths[lane]...), paths[lane]...)
		if len(paths[lane]) != 6 || finished[lane].Load() != 12 || !reflect.DeepEqual(seen[lane], want) {
			t.Fatal("configuration omitted, replayed or reordered signed lane membership")
		}
	}
}

func TestBaselineConfigurationTwoLanesCancelAndJoinEitherRefusedSibling(t *testing.T) {
	for refused := range 2 {
		t.Run([]string{"policy", "binding"}[refused], func(t *testing.T) {
			configuration, snapshot, paths := testConfiguredReadLanes(t)
			started, canceled, exited, release := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
			var once sync.Once
			var seen [2]atomic.Int32
			var closes atomic.Int32
			next := configuration.access.client.Transport
			configuration.access.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				lane := -1
				for i := range paths {
					if r.URL.Path == paths[i][0] {
						lane = i
					}
				}
				if lane < 0 {
					closes.Add(1)
					return next.RoundTrip(r)
				}
				if seen[lane].Add(1) != 1 {
					t.Error("configuration refusal replayed original read")
					return nil, ErrRead
				}
				if lane == refused {
					select {
					case <-started:
					case <-r.Context().Done():
					}
					return nil, ErrRead
				}
				close(started)
				defer close(exited)
				<-r.Context().Done()
				close(canceled)
				<-release // Deliberately delay reader exit AFTER cancellation.
				return nil, ErrRead
			})
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			done := make(chan error, 1)
			joined := false
			defer func() {
				cancel()
				once.Do(func() { close(release) })
				if !joined {
					select {
					case <-done:
					case <-time.After(2 * time.Second):
						t.Error("configuration refusal leaked sibling")
					}
				}
			}()
			go func() { done <- configuration.VerifyConfigured(ctx, snapshot) }()
			select {
			case <-canceled:
			case <-done:
				joined = true
				t.Fatal("configuration refusal returned before sibling cancellation")
			case <-ctx.Done():
				t.Fatal("configuration refusal did not cancel its sibling")
			}
			select {
			case <-done:
				joined = true
				t.Fatal("configuration refusal returned before canceled sibling exit")
			case <-time.After(100 * time.Millisecond):
			}
			once.Do(func() { close(release) })
			select {
			case err := <-done:
				joined = true
				if err != ErrSecurityBaseline {
					t.Fatal("configuration refusal changed fixed error")
				}
			case <-ctx.Done():
				t.Fatal("configuration refusal failed to join released sibling")
			}
			select {
			case <-exited:
			default:
				t.Fatal("configuration refusal outran sibling exit")
			}
			if ctx.Err() != nil || seen[0].Load() != 1 || seen[1].Load() != 1 || closes.Load() != 2 {
				t.Fatal("configuration refusal canceled caller, replayed, or reached closing fence")
			}
		})
	}
}
