// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
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
func testConfiguredReadLanes(t *testing.T) (*ClusterSecurityBaseline, *installstate.Snapshot, [8][]string) {
	t.Helper()
	f := newBaselineFixture(t)
	completeBaselineFixture(t, f)
	objects := make(map[string]*unstructured.Unstructured)
	var paths [8][]string
	var policies, bindings int
	for _, resource := range f.snapshot.Document().SecurityBaseline.Resources {
		path, err := resourcePath(resource.Key, false)
		if err != nil {
			t.Fatal("configuration lane route unavailable")
		}
		object := f.access.objects[resource.Key].DeepCopy()
		lane := 4 + bindings%4
		if resource.Key.Kind == "ValidatingAdmissionPolicy" {
			lane = policies % 4
			policies++
			object.SetGeneration(1)
			object.Object["status"] = map[string]any{"observedGeneration": int64(1), "typeChecking": map[string]any{}}
		} else {
			bindings++
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

func TestBaselineConfigurationEightLanesPreserveCompletePassesAndClosingJoin(t *testing.T) {
	configuration, snapshot, paths := testConfiguredReadLanes(t)
	var entered, release [2][8]chan struct{}
	var once [2][8]sync.Once
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
	var finished [8]atomic.Int32
	var mu sync.Mutex
	var seen [8][]string
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
		if pass != 0 {
			for sibling := range 8 {
				if finished[sibling].Load() < int32(len(paths[sibling])) {
					t.Error("second configuration pass outran an original read lane")
					return nil, ErrRead
				}
			}
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
				t.Fatal("configuration returned before all eight final reads overlapped")
			case <-ctx.Done():
				t.Fatal("configuration failed to overlap eight bounded lanes")
			}
		}
		for lane := range 7 {
			once[pass][lane].Do(func() { close(release[pass][lane]) })
		}
		select {
		case <-done:
			joined = true
			t.Fatal("configuration returned before its eighth lane joined")
		case <-time.After(100 * time.Millisecond):
		}
		once[pass][7].Do(func() { close(release[pass][7]) })
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
	if active.Load() != 0 || maximum.Load() != 8 || blocked.Load() != 0 || closes.Load() != 8 {
		t.Fatal("configuration changed lane bound, leaked readers or skipped original fences")
	}
	for lane := range paths {
		want := append(append([]string(nil), paths[lane]...), paths[lane]...)
		wantLength := []int{2, 2, 1, 1, 2, 2, 1, 1}[lane]
		if len(paths[lane]) != wantLength || finished[lane].Load() != int32(2*wantLength) || !reflect.DeepEqual(seen[lane], want) {
			t.Fatal("configuration omitted, replayed or reordered signed lane membership")
		}
	}
}

func TestBaselineConfigurationEightLanesCancelAndJoinEveryRefusedSibling(t *testing.T) {
	for _, mode := range []string{"request", "body"} {
		for refused := range 8 {
			t.Run(mode+"/"+strconv.Itoa(refused), func(t *testing.T) {
				configuration, snapshot, paths := testConfiguredReadLanes(t)
				testBaselineEightReadLaneRefusal(t, configuration.access, paths, mode, refused, 2, func(ctx context.Context) error {
					return configuration.VerifyConfigured(ctx, snapshot)
				})
			})
		}
	}
}

func TestBaselineConfigurationEightLanesCallerCancellationJoinsEveryReader(t *testing.T) {
	configuration, snapshot, paths := testConfiguredReadLanes(t)
	testBaselineEightReadLaneRefusal(t, configuration.access, paths, "caller", -1, 2, func(ctx context.Context) error {
		return configuration.VerifyConfigured(ctx, snapshot)
	})
}

func TestBaselineConfigurationEightLanesRejectUnhealthyPolicyInEveryPolicyLane(t *testing.T) {
	for unhealthy := range 4 {
		t.Run(strconv.Itoa(unhealthy), func(t *testing.T) {
			configuration, snapshot, paths := testConfiguredReadLanes(t)
			next := configuration.access.client.Transport
			var injected atomic.Bool
			configuration.access.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				response, err := next.RoundTrip(r)
				if r.URL.Path != paths[unhealthy][0] || err != nil || response == nil || response.Body == nil {
					return response, err
				}
				defer response.Body.Close()
				var object unstructured.Unstructured
				if json.NewDecoder(response.Body).Decode(&object.Object) != nil {
					t.Error("unhealthy policy fixture could not decode native response")
					return nil, ErrRead
				}
				// Generation-current status is mandatory in all four policy lanes,
				// not only lane zero from the former policy/binding split.
				object.Object["status"] = map[string]any{"observedGeneration": int64(0), "typeChecking": map[string]any{}}
				body, encodeErr := json.Marshal(object.Object)
				if encodeErr != nil {
					t.Error("unhealthy policy fixture could not encode response")
					return nil, ErrRead
				}
				injected.Store(true)
				copyResponse := *response
				copyResponse.Body = io.NopCloser(bytes.NewReader(body))
				copyResponse.ContentLength = int64(len(body))
				return &copyResponse, nil
			})
			if err := configuration.VerifyConfigured(t.Context(), snapshot); err != ErrSecurityBaseline || !injected.Load() {
				t.Fatal("configuration accepted an unhealthy policy outside lane zero")
			}
		})
	}
}
