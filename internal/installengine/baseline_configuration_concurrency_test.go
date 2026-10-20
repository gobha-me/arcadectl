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
func testConfiguredReadLanes(t *testing.T) (*ClusterSecurityBaseline, *installstate.Snapshot, [2][]string) {
	t.Helper()
	f := newBaselineFixture(t)
	completeBaselineFixture(t, f)
	objects := make(map[string]*unstructured.Unstructured)
	paths := [2][]string{{"/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies"}, {"/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicybindings"}}
	for _, resource := range f.snapshot.Document().SecurityBaseline.Resources {
		path, err := resourcePath(resource.Key, false)
		if err != nil {
			t.Fatal("configuration lane route unavailable")
		}
		object := f.access.objects[resource.Key].DeepCopy()
		if resource.Key.Kind == "ValidatingAdmissionPolicy" {
			object.SetGeneration(1)
			object.Object["status"] = map[string]any{"observedGeneration": int64(1), "typeChecking": map[string]any{}}
		}
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
		if !testBaselineConfigurationList(t, w, r, objects) {
			t.Error("configuration lane escaped exact signed routes")
			w.WriteHeader(404)
		}
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

func TestBaselineConfigurationTwoListsPreserveCompletePassesAndClosingJoin(t *testing.T) {
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
		if pass != 0 {
			for sibling := range 2 {
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
	go func() {
		witness, err := configuration.configured(ctx, snapshot)
		if err == nil {
			if len(witness) != 12 {
				t.Error("configured LIST witness omitted signed members")
			}
			for _, original := range snapshot.Document().SecurityBaseline.Resources {
				identity, found := witness[original.Key]
				if !found || identity.UID != original.UID || identity.TemplateSHA256 != original.TemplateSHA256 || identity.ResourceVersion == "" {
					t.Error("configured LIST witness changed original signed membership")
				}
			}
		}
		done <- err
	}()
	for pass := range entered {
		for lane := range entered[pass] {
			select {
			case <-entered[pass][lane]:
			case <-done:
				joined = true
				t.Fatal("configuration returned before both final LIST reads overlapped")
			case <-ctx.Done():
				t.Fatal("configuration failed to overlap two bounded LIST readers")
			}
		}
		for lane := range 1 {
			once[pass][lane].Do(func() { close(release[pass][lane]) })
		}
		select {
		case <-done:
			joined = true
			t.Fatal("configuration returned before its second LIST joined")
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
		wantLength := 1
		if len(paths[lane]) != wantLength || finished[lane].Load() != int32(2*wantLength) || !reflect.DeepEqual(seen[lane], want) {
			t.Fatal("configuration omitted, replayed or reordered signed lane membership")
		}
	}
}

func TestBaselineConfigurationTwoListsCancelAndJoinEveryRefusedSibling(t *testing.T) {
	for _, mode := range []string{"request", "body"} {
		for refused := range 2 {
			t.Run(mode+"/"+strconv.Itoa(refused), func(t *testing.T) {
				configuration, snapshot, paths := testConfiguredReadLanes(t)
				testBaselineReadLaneRefusal(t, configuration.access, paths[:], mode, refused, 2, func(ctx context.Context) error {
					return configuration.VerifyConfigured(ctx, snapshot)
				})
			})
		}
	}
}

func TestBaselineConfigurationTwoListsCallerCancellationJoinsEveryReader(t *testing.T) {
	configuration, snapshot, paths := testConfiguredReadLanes(t)
	testBaselineReadLaneRefusal(t, configuration.access, paths[:], "caller", -1, 2, func(ctx context.Context) error {
		return configuration.VerifyConfigured(ctx, snapshot)
	})
}

func TestBaselineConfigurationTwoListsRejectEveryUnhealthyPolicy(t *testing.T) {
	for unhealthy := range 6 {
		t.Run(strconv.Itoa(unhealthy), func(t *testing.T) {
			configuration, snapshot, paths := testConfiguredReadLanes(t)
			next := configuration.access.client.Transport
			var injected atomic.Bool
			configuration.access.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				response, err := next.RoundTrip(r)
				if r.URL.Path != paths[0][0] || err != nil || response == nil || response.Body == nil {
					return response, err
				}
				defer response.Body.Close()
				var object unstructured.Unstructured
				if json.NewDecoder(response.Body).Decode(&object.Object) != nil {
					t.Error("unhealthy policy fixture could not decode native response")
					return nil, ErrRead
				}
				items, ok := object.Object["items"].([]any)
				if !ok || len(items) != 6 {
					t.Error("unhealthy policy LIST fixture lost membership")
					return nil, ErrRead
				}
				items[unhealthy].(map[string]any)["status"] = map[string]any{"observedGeneration": int64(0), "typeChecking": map[string]any{}}
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
