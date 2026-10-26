// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	authv1 "k8s.io/api/authorization/v1"
)

// Abruptly stop the calling worker after a real response reaches EOF. The
// caller's existing deferred body Close must still run during Goexit.
type testBaselineWorkerGoexitBody struct {
	io.ReadCloser
	ctx     context.Context
	entered chan<- struct{}
	trigger <-chan struct{}
}

func (body *testBaselineWorkerGoexitBody) Read(p []byte) (int, error) {
	n, err := body.ReadCloser.Read(p)
	if err == io.EOF {
		body.entered <- struct{}{}
		select {
		case <-body.trigger:
			runtime.Goexit()
		case <-body.ctx.Done():
			return 0, body.ctx.Err()
		}
	}
	return n, err
}

func TestBaselineDeniedWorkersRejectGoexit(t *testing.T) {
	testBaselineCatalogWorkerGoexit(t, true)
}

func TestBaselineContainmentWorkersRejectGoexit(t *testing.T) {
	testBaselineCatalogWorkerGoexit(t, false)
}

func testBaselineCatalogWorkerGoexit(t *testing.T, denied bool) {
	t.Helper()
	for _, blocked := range []bool{false, true} {
		name := "all-workers"
		if blocked {
			name = "blocked-siblings"
		}
		t.Run(name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var review authv1.SelfSubjectAccessReview
				if r.Method != http.MethodPost || r.URL.Path != "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" || json.NewDecoder(r.Body).Decode(&review) != nil || review.Spec.ResourceAttributes == nil {
					t.Error("worker control escaped its fixed review route")
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				review.Status = authv1.SubjectAccessReviewStatus{Allowed: false}
				_ = json.NewEncoder(w).Encode(review)
			}))
			t.Cleanup(server.Close)
			var clients map[admissionActor]*HTTPAccess
			var invoke func(context.Context) error
			if denied {
				scope, _ := testDeniedLaneScope(t)
				clients = testDeniedLaneClients(t, server, scope)
				invoke = func(ctx context.Context) error { return baselineDeniedReviews(ctx, scope, clients) }
			} else {
				f := newFixture(t, false)
				config := serverConfig(server)
				config.BearerToken = "FAKE-WORKER-COMPLETION"
				access, err := NewDirectHTTPAccess(config)
				if err != nil {
					t.Fatal("worker control access unavailable")
				}
				actors := &baselineActors{snapshot: f.snapshot, clients: map[admissionActor]*HTTPAccess{}}
				for _, actor := range []admissionActor{ordinaryControllerActor, destroyControllerActor} {
					actors.clients[actor], err = access.actorClientForPurpose(actor, f.plan.Namespace(), baselineAdmissionPurpose)
					if err != nil {
						t.Fatal("worker control actor unavailable")
					}
				}
				clients, invoke = actors.clients, actors.verifyContainment
			}
			testBaselineWorkerGoexit(t, []*HTTPAccess{clients[ordinaryControllerActor], clients[destroyControllerActor]}, func(*http.Request) bool { return true }, invoke, ErrSecurityBaseline, blocked)
		})
	}
}

func TestAdmissionAccessWorkersRejectGoexit(t *testing.T) {
	for _, blocked := range []bool{false, true} {
		name := "all-workers"
		if blocked {
			name = "blocked-siblings"
		}
		t.Run(name, func(t *testing.T) {
			f, paths, _, _, _ := testAdmissionReadCatalog(t, "access")
			selected := make(map[string]bool)
			for _, lane := range paths {
				for _, path := range lane {
					selected[path] = true
				}
			}
			invoke := func(ctx context.Context) error {
				witness, err := f.admission.actorAccessWitness(ctx, f.request)
				if err != nil && witness != nil {
					t.Error("refused access worker returned partial identity evidence")
				}
				return err
			}
			testBaselineWorkerGoexit(t, []*HTTPAccess{f.admission.prerequisites.access}, func(r *http.Request) bool { return selected[r.URL.Path] }, invoke, ErrAdmission, blocked)
		})
	}
}

// Existing literal-catalog tests cover healthy rows and ordering. This focused
// control holds the first eight genuine replies, so no later row/fence can hide
// an abruptly terminated worker. All fixture cleanup follows invocation join.
func testBaselineWorkerGoexit(t *testing.T, clients []*HTTPAccess, selected func(*http.Request) bool, invoke func(context.Context) error, want error, blocked bool) {
	t.Helper()
	entered, canceled := make(chan struct{}, 8), make(chan struct{}, 8)
	trigger, release := make(chan struct{}), make(chan struct{})
	var triggerOnce, releaseOnce sync.Once
	var requests, bodies, closed, active, maximum atomic.Int32
	for _, client := range clients {
		copyClient := *client.client
		next := copyClient.Transport
		copyClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if !selected(r) {
				return next.RoundTrip(r)
			}
			ordinal := requests.Add(1)
			response, err := next.RoundTrip(r)
			if err != nil || response == nil || response.Body == nil {
				return response, err
			}
			bodies.Add(1)
			if blocked && ordinal != 1 {
				_ = response.Body.Close()
				response.Body = &testBaselineReviewBlockedBody{ctx: r.Context(), entered: entered, canceled: canceled, release: release}
			} else {
				response.Body = &testBaselineWorkerGoexitBody{ReadCloser: response.Body, ctx: r.Context(), entered: entered, trigger: trigger}
			}
			response.Body = &testContainmentFlightBody{ReadCloser: response.Body, finish: func() { closed.Add(1) }}
			return response, nil
		})
		client.client = &copyClient
		testContainmentTrackFlights(client, &active, &maximum)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	done := make(chan error, 1)
	joined := false
	defer func() {
		cancel()
		triggerOnce.Do(func() { close(trigger) })
		releaseOnce.Do(func() { close(release) })
		if !joined {
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Error("worker control did not join during cleanup")
				<-done // Never tear down the fixture while its worker remains active.
			}
		}
		// An invoke return alone is not body quiescence. Drain every observed
		// flight before teardown; this cannot join workers that have not yet
		// entered the transport, so private controls must retain a real Wait.
		tick := time.NewTicker(time.Millisecond)
		defer tick.Stop()
		limit := time.NewTimer(3 * time.Second)
		defer limit.Stop()
		warning := limit.C
		for active.Load() != 0 || closed.Load() != bodies.Load() {
			select {
			case <-tick.C:
			case <-warning:
				t.Error("worker body flights did not quiesce during cleanup")
				warning = nil // Record failure, then keep joining before teardown.
			}
		}
	}()
	go func() { done <- invoke(ctx) }()
	for range 8 {
		select {
		case <-entered:
		case <-done:
			joined = true
			t.Fatal("worker control returned before eight replies were held")
		case <-ctx.Done():
			t.Fatal("worker control failed to reach eight replies")
		}
	}
	if requests.Load() != 8 || active.Load() != 8 || maximum.Load() != 8 {
		t.Fatal("worker control changed its fixed first-flight census")
	}
	triggerOnce.Do(func() { close(trigger) })
	if blocked {
		timer := time.NewTimer(3 * time.Second)
		defer timer.Stop()
		for range 7 {
			select {
			case <-canceled:
			case <-timer.C:
				t.Fatal("Goexit did not cancel every unfinished sibling")
			}
		}
		if ctx.Err() != nil || active.Load() != 7 {
			t.Fatal("Goexit canceled its caller or released unfinished bodies")
		}
		select {
		case <-done:
			joined = true
			t.Fatal("Goexit returned before canceled response bodies joined")
		case <-time.After(100 * time.Millisecond):
		}
		releaseOnce.Do(func() { close(release) })
	}
	select {
	case err := <-done:
		joined = true
		if err != want {
			t.Fatal("Goexit reported successful worker completion")
		}
	case <-ctx.Done():
		t.Fatal("Goexit workers did not join within their caller bound")
	}
	if ctx.Err() != nil || active.Load() != 0 || bodies.Load() != 8 || closed.Load() != 8 || requests.Load() != 8 {
		t.Fatal("Goexit refusal lost caller context, body closure or exact request census")
	}
}
