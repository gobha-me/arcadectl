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
func TestBaselineContainmentTwoLanesKeepEveryOriginalRow(t *testing.T) {
	f := newFixture(t, false)
	catalog := testBaselineContainmentAttributes(f.plan.Namespace())
	entered := make(chan string, 2)
	release := make(chan struct{})
	var releaseOnce sync.Once
	var active, maximum atomic.Int32
	var mu sync.Mutex
	seen := map[string][]int{}
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
		ordinal := len(seen[actor])
		seen[actor] = append(seen[actor], row)
		mu.Unlock()
		if row != ordinal || row < 0 {
			t.Error("catalog reordered, repeated or omitted a literal per-actor row")
			w.WriteHeader(500)
			return
		}
		if row == 0 {
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
	first := ""
	for range 2 {
		select {
		case actor := <-entered:
			if actor == first {
				t.Fatal("one actor opened both catalog lanes")
			}
			first = actor
		case <-ctx.Done():
			t.Fatal("independent actor catalogs remained serial")
		}
	}
	if maximum.Load() != 2 {
		t.Fatal("catalog concurrency is not exactly two bounded lanes")
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("complete catalog did not join within its caller bound")
	}
	if result != nil || active.Load() != 0 || maximum.Load() > 2 {
		t.Fatal("catalog returned before completion or exceeded its two-lane limit")
	}
	mu.Lock()
	defer mu.Unlock()
	for _, actor := range []string{"arcadectl-controller", "arcadectl-destroy-controller"} {
		if len(seen[actor]) != 13 {
			t.Fatal("catalog omitted an actor or a literal containment row")
		}
	}
}

func TestBaselineContainmentRefusalCancelsAndJoinsBothLanes(t *testing.T) {
	f := newFixture(t, false)
	destroyStarted, destroyCanceled, destroyExited := make(chan struct{}), make(chan struct{}), make(chan struct{})
	releaseDestroy := make(chan struct{})
	var releaseOnce sync.Once
	var ordinaryReviews, destroyReviews, inFlight atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var review authv1.SelfSubjectAccessReview
		if ordinaryReviews.Add(1) != 1 || r.Method != http.MethodPost || r.URL.Path != "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" || r.URL.RawQuery != "fieldManager=arcadectl-installer&fieldValidation=Strict" || r.Header.Get("Authorization") != "Bearer FAKE-CONTAINMENT" || r.Header.Get("Impersonate-User") != "system:serviceaccount:"+f.plan.Namespace()+":arcadectl-controller" || json.NewDecoder(r.Body).Decode(&review) != nil || review.Spec.NonResourceAttributes != nil || review.Spec.ResourceAttributes == nil || !reflect.DeepEqual(*review.Spec.ResourceAttributes, testBaselineContainmentAttributes(f.plan.Namespace())[0]) {
			t.Error("refusal changed the one literal ordinary catalog review")
			w.WriteHeader(500)
			return
		}
		select {
		case <-destroyStarted:
		case <-r.Context().Done():
			return
		}
		w.Header().Set("Content-Type", "application/json")
		review.Status.Allowed = true // A prohibited grant must cancel its sibling.
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
		actors.clients[actor] = client
	}
	// Explicit hostile test transport: observe cancellation, then deliberately
	// delay returning. Canceling alone must not let the caller outrun its worker.
	client := actors.clients[destroyControllerActor]
	copyClient := *client.client
	copyClient.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if destroyReviews.Add(1) != 1 {
			t.Error("refused catalog repeated its sibling request")
			return nil, errors.New("PRIVATE-CANARY")
		}
		inFlight.Add(1)
		defer inFlight.Add(-1)
		defer close(destroyExited)
		close(destroyStarted)
		<-request.Context().Done()
		close(destroyCanceled)
		<-releaseDestroy
		return nil, errors.New("PRIVATE-CANARY")
	})
	client.client = &copyClient
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	done := make(chan struct{})
	var result error
	go func() {
		result = actors.verifyContainment(ctx)
		close(done)
	}()
	defer func() {
		cancel()
		releaseOnce.Do(func() { close(releaseDestroy) })
		for _, completion := range []<-chan struct{}{done, destroyExited} {
			select {
			case <-completion:
			case <-time.After(2 * time.Second):
				t.Error("refused catalog leaked an invocation or worker")
			}
		}
	}()
	select {
	case <-destroyCanceled:
	case <-ctx.Done():
		t.Fatal("prohibited grant did not cancel its concurrent sibling")
	}
	if ctx.Err() != nil || inFlight.Load() != 1 || ordinaryReviews.Load() != 1 {
		t.Fatal("caller deadline, not catalog refusal, stopped the sibling")
	}
	select {
	case <-done:
		t.Fatal("catalog returned before its canceled worker was joined")
	case <-time.After(200 * time.Millisecond):
		// Keep the transport blocked while an incorrectly early caller return
		// has an opportunity to run, rather than sampling just one instant.
	}
	releaseOnce.Do(func() { close(releaseDestroy) })
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("released catalog worker was not joined")
	}
	if result != ErrSecurityBaseline || inFlight.Load() != 0 || destroyReviews.Load() != 1 || ordinaryReviews.Load() != 1 || ctx.Err() != nil {
		t.Fatal("joined refusal changed fixed error, caller context or replayed reviews")
	}
}
