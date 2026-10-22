// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	authv1 "k8s.io/api/authorization/v1"
)

type testContainmentFlightBody struct {
	io.ReadCloser
	finish func()
}

func (body *testContainmentFlightBody) Close() error {
	err := body.ReadCloser.Close()
	body.finish()
	return err
}

// Count the entire client request through response-body closure, not server
// handler lifetime or merely receipt of response headers.
func testContainmentTrackFlights(client *HTTPAccess, active, maximum *atomic.Int32) {
	copyClient := *client.client
	inner := copyClient.Transport
	copyClient.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		count := active.Add(1)
		for previous := maximum.Load(); count > previous; previous = maximum.Load() {
			if maximum.CompareAndSwap(previous, count) {
				break
			}
		}
		var once sync.Once
		finish := func() { once.Do(func() { active.Add(-1) }) }
		response, err := inner.RoundTrip(request)
		if err != nil || response == nil || response.Body == nil {
			finish()
			return response, err
		}
		copyResponse := *response
		copyResponse.Body = &testContainmentFlightBody{ReadCloser: response.Body, finish: finish}
		return &copyResponse, nil
	})
	client.client = &copyClient
}

// Component transport test only: this does not replace the actual whole
// actor/probe tests or establish runtime authority, effects or native timing.
func TestBaselineContainmentEightLanesKeepEveryOriginalRow(t *testing.T) {
	f := newFixture(t, false)
	catalog := testBaselineContainmentAttributes(f.plan.Namespace())
	entered := make(chan string, 8)
	release := make(chan struct{})
	var releaseOnce sync.Once
	var active, maximum atomic.Int32
	var mu sync.Mutex
	seen := map[string]map[int]int{}
	last := map[string][4]int{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		actor := strings.TrimPrefix(r.Header.Get("Impersonate-User"), "system:serviceaccount:"+f.plan.Namespace()+":")
		var review authv1.SelfSubjectAccessReview
		if r.Method != http.MethodPost || r.URL.Path != "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" || r.URL.RawQuery != "fieldManager=arcadectl-installer&fieldValidation=Strict" || r.Header.Get("Authorization") != "Bearer FAKE-CONTAINMENT" || actor != "arcadectl-controller" && actor != "arcadectl-destroy-controller" || json.NewDecoder(r.Body).Decode(&review) != nil || review.Spec.NonResourceAttributes != nil || review.Spec.ResourceAttributes == nil {
			t.Error("catalog changed frozen actor, exact review or read-only route")
			w.WriteHeader(500)
			return
		}
		row := -1
		for i, attributes := range catalog {
			if reflect.DeepEqual(*review.Spec.ResourceAttributes, attributes) {
				row = i
				break
			}
		}
		mu.Lock()
		if seen[actor] == nil {
			seen[actor] = map[int]int{}
			last[actor] = [4]int{-4, -3, -2, -1}
		}
		seen[actor][row]++
		count := seen[actor][row]
		ordered := false
		if row >= 0 {
			indices := last[actor]
			ordered = row == indices[row%4]+4
			indices[row%4] = row
			last[actor] = indices
		}
		mu.Unlock()
		if row < 0 || count != 1 || !ordered {
			t.Error("catalog repeated, escaped or reordered a fixed lane's literal row")
			w.WriteHeader(500)
			return
		}
		if row < 4 {
			entered <- actor
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		review.Status.Allowed = false
		_ = json.NewEncoder(w).Encode(review)
	}))
	t.Cleanup(server.Close)
	config := serverConfig(server)
	config.BearerToken = "FAKE-CONTAINMENT"
	access, err := NewDirectHTTPAccess(config)
	if err != nil {
		t.Fatal("catalog transport unavailable")
	}
	actors := &baselineActors{snapshot: f.snapshot, clients: map[admissionActor]*HTTPAccess{}}
	for _, actor := range []admissionActor{ordinaryControllerActor, destroyControllerActor} {
		client, err := access.actorClientForPurpose(actor, f.plan.Namespace(), baselineAdmissionPurpose)
		if err != nil {
			t.Fatal("frozen catalog actor unavailable")
		}
		testContainmentTrackFlights(client, &active, &maximum)
		actors.clients[actor] = client
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	done := make(chan struct{})
	var result error
	go func() {
		result = actors.verifyContainment(ctx)
		close(done)
	}()
	defer func() {
		cancel()
		releaseOnce.Do(func() { close(release) })
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("catalog worker outlived canceled invocation")
		}
	}()
	started := map[string]int{}
	for range 8 {
		select {
		case actor := <-entered:
			started[actor]++
			if started[actor] > 4 {
				t.Fatal("one actor exceeded four fixed catalog lanes")
			}
		case <-ctx.Done():
			t.Fatal("independent actor catalogs remained serial")
		}
	}
	if maximum.Load() != 8 || started["arcadectl-controller"] != 4 || started["arcadectl-destroy-controller"] != 4 {
		t.Fatal("catalog did not open exactly four bounded lanes per actor")
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("complete catalog did not join within its caller bound")
	}
	if result != nil || active.Load() != 0 || maximum.Load() != 8 {
		t.Fatal("catalog returned before completion or exceeded its eight-lane limit")
	}
	mu.Lock()
	defer mu.Unlock()
	for _, actor := range []string{"arcadectl-controller", "arcadectl-destroy-controller"} {
		if len(seen[actor]) != 13 {
			t.Fatal("catalog omitted an actor or a literal containment row")
		}
	}
}

func TestBaselineContainmentEightLanesRejectInvalidClientsBeforeLaunch(t *testing.T) {
	f := newFixture(t, false)
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(500) }))
	t.Cleanup(server.Close)
	access, err := NewDirectHTTPAccess(serverConfig(server))
	if err != nil {
		t.Fatal("frozen administrator unavailable")
	}
	original := map[admissionActor]*HTTPAccess{}
	for _, actor := range []admissionActor{ordinaryControllerActor, destroyControllerActor} {
		original[actor], err = access.actorClientForPurpose(actor, f.plan.Namespace(), baselineAdmissionPurpose)
		if err != nil {
			t.Fatal("frozen containment client unavailable")
		}
	}
	for _, broken := range []admissionActor{ordinaryControllerActor, destroyControllerActor} {
		t.Run(broken.account(), func(t *testing.T) {
			for _, mode := range []string{"nil-client", "nil-http", "nil-base", "nil-actor", "actor", "namespace", "username", "purpose", "scope", "missing-client", "extra-client", "nil-context", "cancelled-context", "nil-snapshot"} {
				t.Run(mode, func(t *testing.T) {
					actors := &baselineActors{snapshot: f.snapshot, clients: map[admissionActor]*HTTPAccess{}}
					for actor, client := range original {
						copyClient, identity := *client, *client.actor
						copyClient.actor = &identity
						actors.clients[actor] = &copyClient
					}
					client := actors.clients[broken]
					ctx := t.Context()
					switch mode {
					case "nil-client":
						actors.clients[broken] = nil
					case "nil-http":
						client.client = nil
					case "nil-base":
						client.base = nil
					case "nil-actor":
						client.actor = nil
					case "actor":
						client.actor.actor = destroyAdministratorActor
					case "namespace":
						client.actor.namespace = "foreign"
					case "username":
						client.actor.username = "PRIVATE-CANARY"
					case "purpose":
						client.actor.purpose = runtimeAdmissionPurpose
					case "scope":
						client.actor.deniedScope = &baselineDeniedScope{}
					case "missing-client":
						delete(actors.clients, broken)
					case "extra-client":
						actors.clients[destroyAdministratorActor] = client
					case "nil-context":
						ctx = nil
					case "cancelled-context":
						var cancel context.CancelFunc
						ctx, cancel = context.WithCancel(ctx)
						cancel()
					case "nil-snapshot":
						actors.snapshot = nil
					}
					if actors.verifyContainment(ctx) != ErrSecurityBaseline || requests.Load() != 0 {
						t.Fatal("invalid sibling allowed a review before complete validation")
					}
				})
			}
		})
	}
}

func TestBaselineContainmentRefusalCancelsAndJoinsAllLanes(t *testing.T) {
	testBaselineReviewRefusalJoins(t, func(t *testing.T, server *httptest.Server) (map[admissionActor]*HTTPAccess, func(context.Context) error) {
		f := newFixture(t, false)
		config := serverConfig(server)
		config.BearerToken = "FAKE-REVIEW-JOIN"
		access, err := NewDirectHTTPAccess(config)
		if err != nil {
			t.Fatal("catalog transport unavailable")
		}
		actors := &baselineActors{snapshot: f.snapshot, clients: map[admissionActor]*HTTPAccess{}}
		for _, actor := range []admissionActor{ordinaryControllerActor, destroyControllerActor} {
			client, err := access.actorClientForPurpose(actor, f.plan.Namespace(), baselineAdmissionPurpose)
			if err != nil {
				t.Fatal("frozen catalog actor unavailable")
			}
			actors.clients[actor] = client
		}
		return actors.clients, actors.verifyContainment
	})
}

// A deliberately hostile test body reports cancellation but does not return
// until released. A canceled context alone must not retire an unfinished read.
type testBaselineReviewBlockedBody struct {
	ctx               context.Context
	entered, canceled chan<- struct{}
	release           <-chan struct{}
	once              sync.Once
}

func (body *testBaselineReviewBlockedBody) Read([]byte) (int, error) {
	body.once.Do(func() {
		if body.entered != nil {
			body.entered <- struct{}{}
		}
		<-body.ctx.Done()
		body.canceled <- struct{}{}
		<-body.release
	})
	return 0, errors.New("PRIVATE-CANARY")
}

func (*testBaselineReviewBlockedBody) Close() error { return nil }

// Transport/body lifetime control only. Genuine TLS actor credentials, exact
// request captures and every literal row are checked by the complete catalogs
// above and in the denied-catalog test, not inferred from these hostile bodies.
func testBaselineReviewRefusalJoins(t *testing.T, makeClients func(*testing.T, *httptest.Server) (map[admissionActor]*HTTPAccess, func(context.Context) error)) {
	t.Helper()
	for _, mode := range []string{"grant", "missing-result", "evaluation-error", "wrong-spec", "parent-canceled"} {
		t.Run(mode, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var review authv1.SelfSubjectAccessReview
				if r.Method != http.MethodPost || r.URL.Path != "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" || json.NewDecoder(r.Body).Decode(&review) != nil || review.Spec.ResourceAttributes == nil {
					t.Error("refusal control escaped the finite review route")
					w.WriteHeader(500)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				switch mode {
				case "grant":
					review.Status.Allowed = true
				case "missing-result":
					_ = json.NewEncoder(w).Encode(map[string]any{"apiVersion": review.APIVersion, "kind": review.Kind, "spec": review.Spec, "status": map[string]any{}})
					return
				case "evaluation-error":
					review.Status.EvaluationError = "PRIVATE-CANARY"
				case "wrong-spec":
					review.Spec.ResourceAttributes.Name = "foreign"
				}
				_ = json.NewEncoder(w).Encode(review)
			}))
			t.Cleanup(server.Close)
			clients, invoke := makeClients(t, server)
			entered, canceled := make(chan struct{}, 8), make(chan struct{}, 8)
			refuse, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			var active, maximum, requests atomic.Int32
			for actor, client := range clients {
				copyClient := *client.client
				inner := copyClient.Transport
				var ordinal atomic.Int32
				copyClient.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
					requests.Add(1)
					first := ordinal.Add(1) == 1
					// One ordinary request supplies the actual refused HTTPS
					// reply; seven other complete response bodies stay blocked.
					if actor == ordinaryControllerActor && first {
						entered <- struct{}{}
						select {
						case <-refuse:
							return inner.RoundTrip(request)
						case <-request.Context().Done():
							// Parent cancellation is a separate negative control.
						}
						_ = request.Body.Close()
						return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: &testBaselineReviewBlockedBody{ctx: request.Context(), canceled: canceled, release: release}}, nil
					}
					_ = request.Body.Close()
					return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: &testBaselineReviewBlockedBody{ctx: request.Context(), entered: entered, canceled: canceled, release: release}}, nil
				})
				client.client = &copyClient
				testContainmentTrackFlights(client, &active, &maximum)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			done := make(chan error, 1)
			go func() { done <- invoke(ctx) }()
			joined := false
			defer func() {
				cancel()
				releaseOnce.Do(func() { close(release) })
				if !joined {
					select {
					case <-done:
					case <-time.After(2 * time.Second):
						t.Error("refused review worker leaked")
					}
				}
			}()
			for range 8 {
				select {
				case <-entered:
				case err := <-done:
					joined = true
					t.Fatal("catalog refused before all controlled readers started", err)
				case <-ctx.Done():
					t.Fatal("catalog failed to overlap eight fixed readers")
				}
			}
			if active.Load() != 8 || maximum.Load() != 8 || requests.Load() != 8 {
				t.Fatal("catalog changed its fixed request/body concurrency")
			}
			wantCanceled := 7
			if mode == "parent-canceled" {
				wantCanceled = 8
				cancel()
			} else {
				close(refuse)
			}
			wait := time.NewTimer(3 * time.Second)
			defer wait.Stop()
			for range wantCanceled {
				select {
				case <-canceled:
				case <-wait.C:
					t.Fatal("refusal did not cancel every blocked response body")
				}
			}
			if active.Load() != int32(wantCanceled) || mode != "parent-canceled" && ctx.Err() != nil {
				t.Fatal("catalog refusal canceled its caller or lost body lifetime")
			}
			select {
			case <-done:
				joined = true
				t.Fatal("catalog returned before all canceled bodies joined")
			case <-time.After(100 * time.Millisecond):
			}
			releaseOnce.Do(func() { close(release) })
			select {
			case err := <-done:
				joined = true
				if err != ErrSecurityBaseline {
					t.Fatal("joined refusal changed the fixed sentinel")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("released response bodies did not join")
			}
			if active.Load() != 0 || maximum.Load() != 8 || requests.Load() != 8 || mode != "parent-canceled" && ctx.Err() != nil {
				t.Fatal("joined refusal replayed requests, leaked bodies or changed caller context")
			}
		})
	}
}
