// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"net/http"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type publicInventorySerialAccess struct{ Access }

type publicInventoryResult struct {
	rows []fixtureWorldRow
	err  error
}

func publicInventoryTestPaths(t *testing.T, request LifecycleCheck) ([2][]string, []string) {
	t.Helper()
	var paths [2][]string
	var serial []string
	for _, entry := range request.Snapshot.Document().Resources {
		if entry.Key.Kind == "Secret" || phaseCollectionKey(entry.Key) {
			continue
		}
		path, err := resourcePath(entry.Key, false)
		if err != nil {
			t.Fatal("original public route unavailable")
		}
		lane := len(serial) % 2
		paths[lane] = append(paths[lane], path)
		serial = append(serial, path)
	}
	if len(paths[0]) < 2 || len(paths[1]) < 2 {
		t.Fatal("genuine checkpoint lacks both public lanes")
	}
	return paths, serial
}

func publicInventoryWait(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(10 * time.Second):
		t.Fatal("public inventory scheduling barrier not reached")
	}
}

// Genuine original journal/compiled plan over native TLS fixtures. These tests
// certify scheduling/validation, not effective admission or Kubernetes behavior.
func TestPublicInventoryNativeLanesMatchSerialAndJoin(t *testing.T) {
	h := fixturePhaseFactory(t)(t)
	a, request := h.f.actor.admission, h.f.actor.request
	e := a.prerequisites.engine
	if e.access != a.prerequisites.access || !a.prerequisites.access.actorCompatible() {
		t.Fatal("fixture is not eligible native access")
	}
	if rows, err := a.phasePublicInventory(nil, request); rows != nil || err != ErrFixtures {
		t.Fatal("eligible nil context did not fail closed")
	}
	paths, serial := publicInventoryTestPaths(t, request)
	original := e.access
	e.access = publicInventorySerialAccess{original}
	want, err := a.phasePublicInventory(t.Context(), request)
	e.access = original
	if err != nil || len(want) != len(serial) {
		t.Fatal("serial public oracle unavailable", err)
	}
	var entered, release, finished [2]chan struct{}
	var once [2]sync.Once
	for lane := range 2 {
		entered[lane], release[lane], finished[lane] = make(chan struct{}), make(chan struct{}), make(chan struct{})
	}
	done := make(chan publicInventoryResult, 1)
	joined := false
	defer func() {
		for lane := range 2 {
			once[lane].Do(func() { close(release[lane]) })
		}
		if !joined {
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Error("public inventory invocation leaked")
			}
		}
	}()
	var active, maximum atomic.Int32
	var mu sync.Mutex
	var seen [2][]string
	access := a.prerequisites.access
	copyClient := *access.client
	next := copyClient.Transport
	copyClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		lane, position := -1, -1
		for i := range paths {
			for j, path := range paths[i] {
				if r.URL.Path == path {
					lane, position = i, j
				}
			}
		}
		if lane < 0 || r.Method != http.MethodGet || r.URL.RawQuery != "" {
			t.Error("public lane escaped its complete original GET membership")
			return nil, ErrRead
		}
		n := active.Add(1)
		for old := maximum.Load(); n > old && !maximum.CompareAndSwap(old, n); old = maximum.Load() {
		}
		mu.Lock()
		seen[lane] = append(seen[lane], r.URL.Path)
		mu.Unlock()
		last := position == len(paths[lane])-1
		if last {
			close(entered[lane])
			select {
			case <-release[lane]:
			case <-r.Context().Done():
				active.Add(-1)
				return nil, ErrRead
			}
		}
		var closeOnce sync.Once
		finish := func() {
			closeOnce.Do(func() {
				active.Add(-1)
				if last {
					close(finished[lane])
				}
			})
		}
		response, err := next.RoundTrip(r)
		if err != nil || response == nil || response.Body == nil {
			finish()
			return response, err
		}
		copyResponse := *response
		copyResponse.Body = &testContainmentFlightBody{ReadCloser: response.Body, finish: finish}
		return &copyResponse, nil
	})
	access.client = &copyClient
	go func() {
		rows, err := a.phasePublicInventory(t.Context(), request)
		done <- publicInventoryResult{rows, err}
	}()
	for lane := range 2 {
		publicInventoryWait(t, entered[lane])
	}
	once[0].Do(func() { close(release[0]) })
	publicInventoryWait(t, finished[0])
	select {
	case <-done:
		joined = true
		t.Fatal("public inventory returned before sibling joined")
	case <-time.After(100 * time.Millisecond):
	}
	if active.Load() != 1 {
		t.Fatal("blocked sibling did not remain in flight")
	}
	once[1].Do(func() { close(release[1]) })
	var result publicInventoryResult
	select {
	case result = <-done:
		joined = true
	case <-time.After(10 * time.Second):
		t.Fatal("joined public inventory did not return")
	}
	if result.err != nil || !reflect.DeepEqual(result.rows, want) || maximum.Load() != 2 || active.Load() != 0 || !reflect.DeepEqual(seen, paths) {
		t.Fatal("native public rows/membership/order/bound differ from serial oracle", result.err)
	}
}

func TestPublicInventoryNativeLanesCancelAndJoin(t *testing.T) {
	newPhase := fixturePhaseFactory(t)
	for _, failing := range []int{-1, 0, 1} {
		t.Run(map[int]string{-1: "caller", 0: "first-lane", 1: "second-lane"}[failing], func(t *testing.T) {
			h := newPhase(t)
			a, request := h.f.actor.admission, h.f.actor.request
			paths, _ := publicInventoryTestPaths(t, request)
			var entered, cancelled, release, exited [2]chan struct{}
			var once [2]sync.Once
			for lane := range 2 {
				entered[lane], cancelled[lane], release[lane] = make(chan struct{}), make(chan struct{}), make(chan struct{})
				exited[lane] = make(chan struct{})
			}
			trigger := make(chan struct{})
			var triggerOnce sync.Once
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan publicInventoryResult, 1)
			joined := false
			defer func() {
				cancel()
				triggerOnce.Do(func() { close(trigger) })
				for lane := range 2 {
					once[lane].Do(func() { close(release[lane]) })
				}
				if !joined {
					select {
					case <-done:
					case <-time.After(10 * time.Second):
						t.Error("cancelled public reader leaked")
					}
				}
			}()
			access := a.prerequisites.access
			copyClient := *access.client
			copyClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				lane := -1
				for i := range paths {
					if r.URL.Path == paths[i][0] {
						lane = i
					}
				}
				if lane < 0 || r.Method != http.MethodGet {
					t.Error("refused lane retried or read a later resource")
					return nil, ErrRead
				}
				close(entered[lane])
				defer close(exited[lane])
				if lane == failing {
					<-trigger
					return nil, ErrRead
				}
				<-r.Context().Done()
				close(cancelled[lane])
				<-release[lane] // Deliberately late exit after observing cancellation.
				return nil, ErrRead
			})
			access.client = &copyClient
			go func() {
				rows, err := a.phasePublicInventory(ctx, request)
				done <- publicInventoryResult{rows, err}
			}()
			for lane := range 2 {
				publicInventoryWait(t, entered[lane])
			}
			if failing < 0 {
				cancel()
			} else {
				triggerOnce.Do(func() { close(trigger) })
			}
			for lane := range 2 {
				if lane != failing {
					publicInventoryWait(t, cancelled[lane])
				}
			}
			select {
			case <-done:
				joined = true
				t.Fatal("refusal escaped before cancelled reader joined")
			case <-time.After(100 * time.Millisecond):
			}
			if failing < 0 {
				once[0].Do(func() { close(release[0]) })
				publicInventoryWait(t, exited[0])
				select {
				case <-done:
					joined = true
					t.Fatal("caller cancellation returned with one sibling still live")
				case <-time.After(100 * time.Millisecond):
				}
			}
			for lane := range 2 {
				once[lane].Do(func() { close(release[lane]) })
			}
			select {
			case result := <-done:
				joined = true
				for lane := range 2 {
					select {
					case <-exited[lane]:
					default:
						t.Fatal("cancelled inventory returned before a transport exited")
					}
				}
				if result.rows != nil || result.err != ErrFixtures {
					t.Fatal("cancelled public inventory accepted partial evidence")
				}
			case <-time.After(10 * time.Second):
				t.Fatal("cancelled joined readers did not return")
			}
		})
	}
}

func TestPublicInventoryIneligibleStaysSerial(t *testing.T) {
	newPhase := fixturePhaseFactory(t)
	for _, mode := range []string{"wrapped-engine", "non-direct", "wrapped-config"} {
		t.Run(mode, func(t *testing.T) {
			h := newPhase(t)
			a, request := h.f.actor.admission, h.f.actor.request
			_, want := publicInventoryTestPaths(t, request)
			access := a.prerequisites.access
			switch mode {
			case "wrapped-engine":
				a.prerequisites.engine.access = publicInventorySerialAccess{access}
			case "non-direct":
				access.direct = false
			case "wrapped-config":
				access.frozen.WrapTransport = func(next http.RoundTripper) http.RoundTripper { return next }
			}
			var mu sync.Mutex
			var seen []string
			var active, maximum atomic.Int32
			testContainmentTrackFlights(access, &active, &maximum)
			copyClient := *access.client
			next := copyClient.Transport
			copyClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				mu.Lock()
				seen = append(seen, r.URL.Path)
				mu.Unlock()
				return next.RoundTrip(r)
			})
			access.client = &copyClient
			rows, err := a.phasePublicInventory(t.Context(), request)
			if err != nil || len(rows) != len(want) || maximum.Load() != 1 || active.Load() != 0 || !reflect.DeepEqual(seen, want) {
				t.Fatal("generic public access lost original serial behavior", err)
			}
			if rows, err := a.phasePublicInventory(nil, request); rows != nil || err != ErrFixtures {
				t.Fatal("nil context did not fail closed")
			}
		})
	}
}
