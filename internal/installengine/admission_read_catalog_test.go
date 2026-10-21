// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"net/http"
	"reflect"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installstate"
)

// Real frozen HTTP clients/templates with synthetic original responses; not
// native Kubernetes behavior or a completed installer journey. Paths derive
// independently from the sealed input catalog, not the worker implementation.
func testAdmissionReadCatalog(t *testing.T, kind string) (*actorFixture, [8][]string, int32, error, func(context.Context) error) {
	t.Helper()
	f := newActorFixture(t)
	var keys []installstate.Key
	var opening int32
	expectedError := ErrAdmission
	var invoke func(context.Context) error
	switch kind {
	case "access":
		opening = 2
		for _, resource := range f.request.Target.ResourceMetadata() {
			key := installstate.Key{APIVersion: resource.APIVersion, Kind: resource.Kind, Namespace: resource.Namespace, Name: resource.Name}
			if accessRetirementKey(key) {
				keys = append(keys, key)
			}
		}
		invoke = func(ctx context.Context) error {
			witness, err := f.admission.actorAccessWitness(ctx, f.request)
			if err == nil && len(witness) != len(keys) {
				t.Error("access reader omitted an original catalog member")
			}
			return err
		}
	case "configuration":
		opening = 2
		for _, resource := range f.request.Target.ResourceMetadata() {
			if resource.Kind == "ValidatingAdmissionPolicy" || resource.Kind == "ValidatingAdmissionPolicyBinding" {
				keys = append(keys, installstate.Key{APIVersion: resource.APIVersion, Kind: resource.Kind, Namespace: resource.Namespace, Name: resource.Name})
			}
		}
		invoke = func(ctx context.Context) error {
			witness, err := f.admission.configured(ctx, f.request)
			if err == nil && (len(witness.objects) != 12 || len(witness.policies) != 6 || len(witness.bindings) != 6) {
				t.Error("configuration reader omitted original policies or bindings")
			}
			return err
		}
	case "public":
		expectedError = ErrFixtures
		for _, resource := range f.request.Snapshot.Document().Resources {
			if resource.Key.Kind != "Secret" && !phaseCollectionKey(resource.Key) {
				keys = append(keys, resource.Key)
			}
		}
		invoke = func(ctx context.Context) error {
			rows, err := f.admission.phasePublicInventory(ctx, f.request)
			if err == nil && len(rows) != len(keys) {
				t.Error("public reader omitted original whole-object inventory")
			}
			return err
		}
	default:
		t.Fatal("unknown test catalog")
	}
	var paths [8][]string
	for index, key := range keys {
		path, err := resourcePath(key, false)
		if err != nil {
			t.Fatal("original catalog address unavailable")
		}
		paths[index%8] = append(paths[index%8], path)
	}
	for _, lane := range paths {
		if len(lane) == 0 {
			t.Fatal("fixture lacks eight independent catalog lanes")
		}
	}
	return f, paths, opening, expectedError, invoke
}

func TestAdmissionNamedCatalogEightLanesPreserveWholeMembershipAndClosingJoin(t *testing.T) {
	for _, kind := range []string{"access", "configuration", "public"} {
		t.Run(kind, func(t *testing.T) {
			f, paths, opening, _, invoke := testAdmissionReadCatalog(t, kind)
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
						t.Error("named catalog invocation leaked")
					}
				}
			}()
			var active, maximum, blocked, fences atomic.Int32
			var mu sync.Mutex
			var seen [8][]string
			access := f.admission.prerequisites.access
			next := access.client.Transport
			access.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				lane := -1
				for candidate := range paths {
					for _, path := range paths[candidate] {
						if r.URL.Path == path {
							lane = candidate
						}
					}
				}
				if lane < 0 {
					fences.Add(1)
					if blocked.Load() != 0 {
						t.Error("original closing fence escaped an unfinished reader")
						return nil, ErrRead
					}
					return next.RoundTrip(r)
				}
				if r.Method != http.MethodGet || r.URL.RawQuery != "" {
					t.Error("catalog changed its exact named GET route")
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
			go func() { done <- invoke(ctx) }()
			for _, lane := range entered {
				select {
				case <-lane:
				case <-done:
					joined = true
					t.Fatal("catalog returned before eight final reads overlapped")
				case <-ctx.Done():
					t.Fatal("catalog failed to overlap eight bounded readers")
				}
			}
			for lane := range 7 {
				once[lane].Do(func() { close(release[lane]) })
			}
			select {
			case <-done:
				joined = true
				t.Fatal("catalog escaped its delayed eighth reader")
			case <-time.After(100 * time.Millisecond):
			}
			once[7].Do(func() { close(release[7]) })
			select {
			case err := <-done:
				joined = true
				if err != nil {
					t.Fatal("complete joined catalog refused", err)
				}
			case <-ctx.Done():
				t.Fatal("released catalog readers failed to join")
			}
			wantFences := opening
			if kind == "configuration" {
				wantFences += 2
			}
			if active.Load() != 0 || blocked.Load() != 0 || maximum.Load() != 8 || fences.Load() != wantFences {
				t.Fatal("catalog changed lane bound, reader join or original fences")
			}
			for lane := range paths {
				if !reflect.DeepEqual(seen[lane], paths[lane]) {
					t.Fatal("catalog omitted, replayed or reordered a lane member")
				}
			}
		})
	}
}

func TestAdmissionNamedCatalogEightLanesCancelAndJoinEverySibling(t *testing.T) {
	for _, kind := range []string{"access", "configuration", "public"} {
		for _, mode := range []string{"request", "body"} {
			for refused := range 8 {
				t.Run(kind+"/"+mode+"/"+strconv.Itoa(refused), func(t *testing.T) {
					f, paths, opening, expectedError, invoke := testAdmissionReadCatalog(t, kind)
					testNamedReadLaneRefusal(t, f.admission.prerequisites.access, paths[:], mode, refused, opening, expectedError, invoke)
				})
			}
		}
	}
}

func TestAdmissionNamedCatalogEightLanesCallerCancellationJoinsEveryReader(t *testing.T) {
	for _, kind := range []string{"access", "configuration", "public"} {
		t.Run(kind, func(t *testing.T) {
			f, paths, opening, expectedError, invoke := testAdmissionReadCatalog(t, kind)
			testNamedReadLaneRefusal(t, f.admission.prerequisites.access, paths[:], "caller", -1, opening, expectedError, invoke)
		})
	}
}

func TestAdmissionNamedCatalogFreezesEveryTemplateBeforeReads(t *testing.T) {
	for _, kind := range []string{"access", "configuration", "public"} {
		t.Run(kind, func(t *testing.T) {
			f, paths, _, expectedError, invoke := testAdmissionReadCatalog(t, kind)
			selected := paths[7][len(paths[7])-1]
			engine := f.admission.prerequisites.engine
			removed := false
			for _, resource := range f.request.Snapshot.Document().Resources {
				path, err := resourcePath(resource.Key, false)
				if err == nil && path == selected {
					if engine.templates[resource.Key][resource.TemplateSHA256] == nil {
						t.Fatal("original frozen template unavailable")
					}
					delete(engine.templates[resource.Key], resource.TemplateSHA256)
					removed = true
				}
			}
			if !removed {
				t.Fatal("fixture did not remove a selected original template")
			}
			var calls atomic.Int32
			access := f.admission.prerequisites.access
			next := access.client.Transport
			access.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				for _, lane := range paths {
					for _, path := range lane {
						if r.URL.Path == path {
							calls.Add(1)
						}
					}
				}
				return next.RoundTrip(r)
			})
			if err := invoke(t.Context()); err != expectedError || calls.Load() != 0 {
				t.Fatal("incomplete signed catalog issued reads or supplied evidence")
			}
		})
	}
}

func TestAdmissionPublicCatalogFreezesRequiredCRDTargetBeforeReads(t *testing.T) {
	f, _, _, _, invoke := testAdmissionReadCatalog(t, "public")
	engine := f.admission.prerequisites.engine
	// Private instrumentation removes the required sealed target contract;
	// even the earlier original Namespace member must not be read first.
	engine.contracts[f.request.Snapshot.Document().TargetPackage] = nil
	var calls atomic.Int32
	access := f.admission.prerequisites.access
	next := access.client.Transport
	access.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		return next.RoundTrip(r)
	})
	if err := invoke(t.Context()); err != ErrFixtures || calls.Load() != 0 {
		t.Fatal("unavailable CRD comparison target issued catalog reads")
	}
}
