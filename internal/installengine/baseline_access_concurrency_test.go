// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
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

// Synthetic signed originals exercise scheduling and identity closure only,
// not native admission enforcement or historical enrollment eligibility.
func testOriginalAccessReadLanes(t *testing.T) (*baselineWorkflow, *installstate.Snapshot, [8][]string) {
	t.Helper()
	f := seedBaselineAccessWitness(t)
	objects := make(map[string]*unstructured.Unstructured)
	var paths [8][]string
	index := 0
	for _, resource := range f.snapshot.Document().Resources {
		if !accessRetirementKey(resource.Key) {
			continue
		}
		path, err := resourcePath(resource.Key, false)
		if err != nil {
			t.Fatal("original access route unavailable")
		}
		paths[index%8] = append(paths[index%8], path)
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

func TestBaselineAccessEightLanesPreserveWholeMembershipAndClosingJoin(t *testing.T) {
	baseline, snapshot, paths := testOriginalAccessReadLanes(t)
	var entered, release [8]chan struct{}
	var once [8]sync.Once
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
	var seen [8][]string
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
		if err == nil && len(witness) != 16 {
			t.Error("original access witness omitted signed membership")
		}
		done <- err
	}()
	for lane := range entered {
		select {
		case <-entered[lane]:
		case <-done:
			joined = true
			t.Fatal("original access returned before all eight final reads overlapped")
		case <-ctx.Done():
			t.Fatal("original access failed to overlap eight fixed lanes")
		}
	}
	for lane := range 7 {
		once[lane].Do(func() { close(release[lane]) })
	}
	select {
	case <-done:
		joined = true
		t.Fatal("original access returned before its eighth reader joined")
	case <-time.After(100 * time.Millisecond):
	}
	once[7].Do(func() { close(release[7]) })
	select {
	case err := <-done:
		joined = true
		if err != nil {
			t.Fatal("joined original access witness refused")
		}
	case <-ctx.Done():
		t.Fatal("released access readers failed to join")
	}
	if active.Load() != 0 || maximum.Load() != 8 || blocked.Load() != 0 || closes.Load() != 2 {
		t.Fatal("original access changed lane bound or closing fences")
	}
	for lane := range paths {
		if len(paths[lane]) != 2 || !reflect.DeepEqual(seen[lane], paths[lane]) {
			t.Fatal("original access omitted, replayed or reordered signed membership")
		}
	}
}

func TestBaselineAccessEightLanesCancelAndJoinEveryRefusedSibling(t *testing.T) {
	for _, mode := range []string{"request", "body"} {
		for refused := range 8 {
			t.Run(mode+"/"+strconv.Itoa(refused), func(t *testing.T) {
				baseline, snapshot, paths := testOriginalAccessReadLanes(t)
				testBaselineEightReadLaneRefusal(t, baseline.engine.access.(*HTTPAccess), paths, mode, refused, 0, func(ctx context.Context) error {
					_, err := baseline.readOriginalRuntimeAccess(ctx, snapshot)
					return err
				})
			})
		}
	}
}

func TestBaselineAccessEightLanesCallerCancellationJoinsEveryReader(t *testing.T) {
	baseline, snapshot, paths := testOriginalAccessReadLanes(t)
	testBaselineEightReadLaneRefusal(t, baseline.engine.access.(*HTTPAccess), paths, "caller", -1, 0, func(ctx context.Context) error {
		_, err := baseline.readOriginalRuntimeAccess(ctx, snapshot)
		return err
	})
}

// The independent eight-lane oracle is shared by both reader test files. A
// refused lane waits until every sibling has entered. All siblings observe
// cancellation, but one deliberately stays alive until the test releases it.
// Body mode returns real native headers first and refuses from a delayed body
// read, proving that joining headers alone cannot publish a witness.
func testBaselineEightReadLaneRefusal(t *testing.T, access *HTTPAccess, paths [8][]string, mode string, refused int, openingCloses int32, invoke func(context.Context) error) {
	t.Helper()
	var entered, canceled, exited [8]chan struct{}
	for lane := range 8 {
		if len(paths[lane]) == 0 {
			t.Fatal("eight-lane refusal oracle has an empty lane")
		}
		entered[lane], canceled[lane], exited[lane] = make(chan struct{}), make(chan struct{}), make(chan struct{})
	}
	release := make(chan struct{})
	var once sync.Once
	var seen [8]atomic.Int32
	var closes atomic.Int32
	delayed := (refused + 1) % 8
	if refused < 0 {
		delayed = 7
	}
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
			return next.RoundTrip(r)
		}
		if r.Method != http.MethodGet || r.URL.Path != paths[lane][0] || seen[lane].Add(1) != 1 {
			t.Error("refused reader mutated, reordered or replayed its catalog")
			return nil, ErrRead
		}
		wait := func() (int, error) {
			if lane == refused {
				for _, sibling := range entered {
					select {
					case <-sibling:
					case <-r.Context().Done():
						return 0, ErrRead
					}
				}
				return 0, ErrRead
			}
			<-r.Context().Done()
			close(canceled[lane])
			if lane == delayed {
				<-release
			}
			return 0, ErrRead
		}
		if mode == "body" {
			response, err := next.RoundTrip(r)
			if err != nil || response == nil || response.Body == nil {
				close(entered[lane])
				close(exited[lane])
				t.Error("native body refusal fixture could not obtain headers")
				return nil, ErrRead
			}
			body := response.Body
			response.Body = &baselineEightLaneRefusalBody{read: wait, close: func() error {
				defer close(exited[lane])
				return body.Close()
			}}
			close(entered[lane])
			return response, nil
		}
		defer close(exited[lane])
		close(entered[lane])
		_, err := wait()
		return nil, err
	})
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	done := make(chan error, 1)
	joined := false
	defer func() {
		cancel()
		once.Do(func() { close(release) })
		if !joined {
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Error("eight-lane refusal invocation leaked")
			}
		}
	}()
	go func() { done <- invoke(ctx) }()
	for _, sibling := range entered {
		select {
		case <-sibling:
		case <-done:
			joined = true
			t.Fatal("reader refused before all eight lanes entered")
		case <-ctx.Done():
			t.Fatal("eight-lane refusal did not reach every sibling")
		}
	}
	if mode == "caller" {
		cancel()
	}
	for lane, sibling := range canceled {
		if lane == refused {
			continue
		}
		select {
		case <-sibling:
		case <-done:
			joined = true
			t.Fatal("refusal returned before every sibling observed cancellation")
		case <-time.After(2 * time.Second):
			t.Fatal("refusal did not cancel every sibling")
		}
	}
	select {
	case <-done:
		joined = true
		t.Fatal("refusal returned while its canceled delayed reader was alive")
	case <-time.After(100 * time.Millisecond):
	}
	once.Do(func() { close(release) })
	select {
	case err := <-done:
		joined = true
		if err != ErrSecurityBaseline {
			t.Fatal("eight-lane refusal changed its fixed public error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("refusal did not join released readers")
	}
	for lane := range 8 {
		select {
		case <-exited[lane]:
		default:
			t.Fatal("refusal escaped a live reader")
		}
		if seen[lane].Load() != 1 {
			t.Fatal("refusal omitted or replayed a lane")
		}
	}
	if (mode == "caller") != (ctx.Err() != nil) || closes.Load() != openingCloses {
		t.Fatal("refusal changed caller cancellation or reached a closing fence")
	}
}

type baselineEightLaneRefusalBody struct {
	read  func() (int, error)
	close func() error
}

func (b *baselineEightLaneRefusalBody) Read([]byte) (int, error) { return b.read() }
func (b *baselineEightLaneRefusalBody) Close() error             { return b.close() }

var _ io.ReadCloser = (*baselineEightLaneRefusalBody)(nil)

func TestBaselineAccessEightLanesFreezeAllSignedEntriesBeforeReads(t *testing.T) {
	baseline, snapshot, _ := testOriginalAccessReadLanes(t)
	var last installstate.Resource
	for _, resource := range snapshot.Document().Resources {
		if accessRetirementKey(resource.Key) {
			last = resource
		}
	}
	if last.UID == "" || baseline.engine.templates[last.Key][last.TemplateSHA256] == nil {
		t.Fatal("last signed original unavailable")
	}
	// Private instrumentation removes the last trusted template, not a live
	// object or a journal record. No earlier membership may issue a GET first.
	delete(baseline.engine.templates[last.Key], last.TemplateSHA256)
	var calls atomic.Int32
	access := baseline.engine.access.(*HTTPAccess)
	next := access.client.Transport
	access.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		return next.RoundTrip(r)
	})
	if witness, err := baseline.readOriginalRuntimeAccess(t.Context(), snapshot); err != ErrSecurityBaseline || witness != nil || calls.Load() != 0 {
		t.Fatal("incomplete frozen signed membership issued reads or supplied authority")
	}
}

func TestBaselineAccessEightLanesCloseLateProtectedFileFence(t *testing.T) {
	baseline, snapshot, paths := testOriginalAccessReadLanes(t)
	var injected atomic.Bool
	access := baseline.engine.access.(*HTTPAccess)
	next := access.client.Transport
	access.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		response, err := next.RoundTrip(r)
		if r.URL.Path == paths[1][len(paths[1])-1] && injected.CompareAndSwap(false, true) {
			if _, createErr := baseline.engine.files.CreateExclusive(fixtureLedgerName(snapshot), []byte("unresolved late fixture")); createErr != nil {
				t.Error("late protected-file fence unavailable")
			}
		}
		return response, err
	})
	if witness, err := baseline.readOriginalRuntimeAccess(t.Context(), snapshot); err != ErrSecurityBaseline || witness != nil || !injected.Load() {
		t.Fatal("joined signed access reader ignored its trailing protected-file fence")
	}
}
