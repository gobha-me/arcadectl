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

// Synthetic signed originals exercise scheduling and identity closure only,
// not native admission enforcement or historical enrollment eligibility.
func testOriginalAccessReadLanes(t *testing.T) (*baselineWorkflow, *installstate.Snapshot, [2][]string) {
	t.Helper()
	f := seedBaselineAccessWitness(t)
	objects := make(map[string]*unstructured.Unstructured)
	var paths [2][]string
	index := 0
	for _, resource := range f.snapshot.Document().Resources {
		if !accessRetirementKey(resource.Key) {
			continue
		}
		path, err := resourcePath(resource.Key, false)
		if err != nil {
			t.Fatal("original access route unavailable")
		}
		paths[index%2] = append(paths[index%2], path)
		index++
		objects[path] = f.access.objects[resource.Key].DeepCopy()
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Error("original access reader attempted mutation")
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
			t.Error("original access reader escaped signed membership")
			w.WriteHeader(404)
			return
		}
		_ = json.NewEncoder(w).Encode(object)
	}))
	t.Cleanup(server.Close)
	access, err := NewDirectHTTPAccess(serverConfig(server))
	if err != nil {
		t.Fatal("original access transport unavailable")
	}
	store, err := installstate.NewWithBaseline(access.Namespaces(), f.engine.baselinePlan(), f.plan)
	if err != nil {
		t.Fatal("original access store unavailable")
	}
	engine, err := NewWithBaselineAccess(access, store, f.engine.files, f.engine.baselinePlan(), f.plan)
	if err != nil {
		t.Fatal("original access engine unavailable")
	}
	snapshot, err := store.Load(t.Context(), f.snapshot.Anchor())
	if err != nil {
		t.Fatal("original access snapshot unavailable")
	}
	return engine.baseline, snapshot, paths
}

func TestBaselineAccessTwoLanesPreserveWholeMembershipAndClosingJoin(t *testing.T) {
	baseline, snapshot, paths := testOriginalAccessReadLanes(t)
	var entered, release [2]chan struct{}
	var once [2]sync.Once
	for lane := range paths {
		entered[lane], release[lane] = make(chan struct{}), make(chan struct{})
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	done := make(chan error, 1)
	joined := false
	defer func() {
		cancel()
		for lane := range release {
			once[lane].Do(func() { close(release[lane]) })
		}
		if !joined {
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Error("original access invocation leaked")
			}
		}
	}()
	var active, maximum, blocked, closes atomic.Int32
	var mu sync.Mutex
	var seen [2][]string
	access := baseline.engine.access.(*HTTPAccess)
	next := access.client.Transport
	access.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
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
				t.Error("original Namespace close outran access reader")
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
		response, err := next.RoundTrip(r)
		if index == len(paths[lane])-1 {
			blocked.Add(1)
			close(entered[lane])
			select {
			case <-release[lane]:
			case <-r.Context().Done():
			}
			blocked.Add(-1)
		}
		return response, err
	})
	go func() {
		witness, err := baseline.readOriginalRuntimeAccess(ctx, snapshot)
		if err == nil && len(witness) != len(paths[0])+len(paths[1]) {
			t.Error("original access witness omitted signed membership")
		}
		done <- err
	}()
	for lane := range entered {
		select {
		case <-entered[lane]:
		case <-done:
			joined = true
			t.Fatal("original access returned before both final reads overlapped")
		case <-ctx.Done():
			t.Fatal("original access failed to overlap two fixed lanes")
		}
	}
	once[0].Do(func() { close(release[0]) })
	select {
	case <-done:
		joined = true
		t.Fatal("original access returned before second reader joined")
	case <-time.After(100 * time.Millisecond):
	}
	once[1].Do(func() { close(release[1]) })
	select {
	case err := <-done:
		joined = true
		if err != nil {
			t.Fatal("joined original access witness refused")
		}
	case <-ctx.Done():
		t.Fatal("released access readers failed to join")
	}
	if active.Load() != 0 || maximum.Load() != 2 || blocked.Load() != 0 || closes.Load() != 2 {
		t.Fatal("original access changed lane bound or closing fences")
	}
	for lane := range paths {
		if len(paths[lane]) != 8 || !reflect.DeepEqual(seen[lane], paths[lane]) {
			t.Fatal("original access omitted, replayed or reordered signed membership")
		}
	}
}

func TestBaselineAccessTwoLanesCancelAndJoinEitherRefusedSibling(t *testing.T) {
	for refused := range 2 {
		t.Run([]string{"even", "odd"}[refused], func(t *testing.T) {
			baseline, snapshot, paths := testOriginalAccessReadLanes(t)
			started, canceled, exited, release := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
			var once sync.Once
			var seen [2]atomic.Int32
			var closes atomic.Int32
			access := baseline.engine.access.(*HTTPAccess)
			next := access.client.Transport
			access.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
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
					t.Error("refused access reader replayed a request")
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
				<-release // Joining must include a canceled but still live reader.
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
						t.Error("refused access invocation leaked")
					}
				}
			}()
			go func() { _, err := baseline.readOriginalRuntimeAccess(ctx, snapshot); done <- err }()
			select {
			case <-canceled:
			case <-done:
				joined = true
				t.Fatal("access refusal returned before sibling cancellation")
			case <-ctx.Done():
				t.Fatal("access refusal failed to cancel sibling")
			}
			select {
			case <-done:
				joined = true
				t.Fatal("access refusal returned before canceled sibling exited")
			case <-time.After(100 * time.Millisecond):
			}
			once.Do(func() { close(release) })
			select {
			case err := <-done:
				joined = true
				if err != ErrSecurityBaseline {
					t.Fatal("access refusal changed fixed public error")
				}
			case <-ctx.Done():
				t.Fatal("released access sibling failed to join")
			}
			select {
			case <-exited:
			default:
				t.Fatal("access refusal escaped live reader")
			}
			if ctx.Err() != nil || seen[0].Load() != 1 || seen[1].Load() != 1 || closes.Load() != 0 {
				t.Fatal("access refusal canceled caller or reached closing fence")
			}
		})
	}
}
