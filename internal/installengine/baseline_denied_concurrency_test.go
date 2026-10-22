// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installstate"
	authv1 "k8s.io/api/authorization/v1"
)

func testDeniedLaneScope(t *testing.T) (*baselineDeniedScope, map[admissionActor][]authv1.ResourceAttributes) {
	t.Helper()
	f, access, guarded := baselineDeniedFixture(t)
	scope, err := f.engine.baselineDeniedCatalog(f.snapshot.Document(), access, guarded)
	if err != nil {
		t.Fatal("original frozen denied catalog unavailable")
	}
	clusterKeys := []installstate.Key{}
	for key := range access {
		if key.Kind == "ClusterRole" || key.Kind == "ClusterRoleBinding" {
			clusterKeys = append(clusterKeys, key)
		}
	}
	literal := map[admissionActor][]authv1.ResourceAttributes{}
	for _, actor := range []admissionActor{ordinaryControllerActor, destroyControllerActor} {
		for row := range testBaselineDeniedAttributes(scope.namespace, actor, clusterKeys) {
			literal[actor] = append(literal[actor], row)
		}
		slices.SortFunc(literal[actor], func(a, b authv1.ResourceAttributes) int {
			// Independent scalar tuple ordering; no production descriptors used.
			for i, av := range []string{a.Group, a.Version, a.Resource, a.Subresource, a.Namespace, a.Name, a.Verb} {
				bv := []string{b.Group, b.Version, b.Resource, b.Subresource, b.Namespace, b.Name, b.Verb}[i]
				if compared := strings.Compare(av, bv); compared != 0 {
					return compared
				}
			}
			return 0
		})
	}
	return scope, literal
}

func testDeniedLaneClients(t *testing.T, server *httptest.Server, scope *baselineDeniedScope) map[admissionActor]*HTTPAccess {
	t.Helper()
	config := serverConfig(server)
	config.BearerToken = "FAKE-DENIED-LANES"
	admin, err := NewDirectHTTPAccess(config)
	if err != nil {
		t.Fatal("frozen administrator unavailable")
	}
	clients := map[admissionActor]*HTTPAccess{}
	for _, actor := range []admissionActor{ordinaryControllerActor, destroyControllerActor} {
		client, err := admin.baselineDeniedClient(actor, scope)
		if err != nil {
			t.Fatal("private denied client unavailable")
		}
		clients[actor] = client
	}
	return clients
}

func TestBaselineDeniedSixteenLanesKeepLiteralCatalog(t *testing.T) {
	scope, literal := testDeniedLaneScope(t)
	entered := make(chan admissionActor, 16)
	release := make(chan struct{})
	var releaseOnce sync.Once
	var active, maximum atomic.Int32
	var mu sync.Mutex
	seen := map[admissionActor]map[int]int{}
	last := map[admissionActor][8]int{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		actor := admissionActor(255)
		for _, candidate := range []admissionActor{ordinaryControllerActor, destroyControllerActor} {
			if r.Header.Get("Impersonate-User") == "system:serviceaccount:"+scope.namespace+":"+candidate.account() {
				actor = candidate
			}
		}
		var review authv1.SelfSubjectAccessReview
		if actor == 255 || r.Method != http.MethodPost || r.URL.Path != "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" || r.URL.RawQuery != "fieldManager=arcadectl-installer&fieldValidation=Strict" || r.Header.Get("Authorization") != "Bearer FAKE-DENIED-LANES" || json.NewDecoder(r.Body).Decode(&review) != nil || review.Spec.ResourceAttributes == nil || review.Spec.NonResourceAttributes != nil {
			t.Error("denied lane changed frozen scope or request")
			w.WriteHeader(500)
			return
		}
		row := -1
		for index, attributes := range literal[actor] {
			if reflect.DeepEqual(*review.Spec.ResourceAttributes, attributes) {
				row = index
				break
			}
		}
		mu.Lock()
		if seen[actor] == nil {
			seen[actor] = map[int]int{}
			last[actor] = [8]int{-8, -7, -6, -5, -4, -3, -2, -1}
		}
		seen[actor][row]++
		count := seen[actor][row]
		ordered := false
		if row >= 0 {
			indices := last[actor]
			ordered = row == indices[row%8]+8
			indices[row%8] = row
			last[actor] = indices
		}
		mu.Unlock()
		if row < 0 || count != 1 || !ordered {
			t.Error("denied lane repeated, escaped or reordered its literal row")
			w.WriteHeader(500)
			return
		}
		if row < 8 {
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
	clients := testDeniedLaneClients(t, server, scope)
	for _, client := range clients {
		testContainmentTrackFlights(client, &active, &maximum)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	done := make(chan error, 1)
	go func() { done <- baselineDeniedReviews(ctx, scope, clients) }()
	joined := false
	defer func() {
		cancel()
		releaseOnce.Do(func() { close(release) })
		if !joined {
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Error("denied lane outlived invocation")
			}
		}
	}()
	started := map[admissionActor]int{}
	for range 16 {
		select {
		case <-done:
			joined = true
			t.Fatal("valid private catalogs refused before both lanes opened")
		case actor := <-entered:
			started[actor]++
			if started[actor] > 8 {
				t.Fatal("one actor exceeded eight fixed lanes")
			}
		case <-ctx.Done():
			t.Fatal("denied catalogs remained serial")
		}
	}
	if maximum.Load() != 16 || started[ordinaryControllerActor] != 8 || started[destroyControllerActor] != 8 {
		t.Fatal("denied catalog did not open eight fixed flights per actor")
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case err := <-done:
		joined = true
		if err != nil {
			t.Fatal("complete literal catalogs refused")
		}
	case <-ctx.Done():
		t.Fatal("denied catalogs did not join")
	}
	if active.Load() != 0 || maximum.Load() != 16 {
		t.Fatal("denied catalog exceeded lane bound or left a body unclosed")
	}
	mu.Lock()
	defer mu.Unlock()
	for actor, rows := range literal {
		if len(seen[actor]) != len(rows) {
			t.Fatal("denied catalog lost literal rows")
		}
	}
}

func TestBaselineDeniedSixteenLanesRejectInvalidClientsBeforeLaunch(t *testing.T) {
	scope, _ := testDeniedLaneScope(t)
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(500) }))
	defer server.Close()
	original := testDeniedLaneClients(t, server, scope)
	for _, broken := range []admissionActor{ordinaryControllerActor, destroyControllerActor} {
		t.Run(broken.account(), func(t *testing.T) {
			for _, mode := range []string{"nil-client", "nil-http", "nil-base", "nil-actor", "actor", "namespace", "username", "purpose", "scope", "empty-rows", "missing-client", "extra-client", "nil-context", "cancelled-context", "nil-scope", "invalid-namespace"} {
				t.Run(mode, func(t *testing.T) {
					clients := map[admissionActor]*HTTPAccess{}
					for actor, client := range original {
						copyClient := *client
						identity := *client.actor
						copyClient.actor = &identity
						clients[actor] = &copyClient
					}
					client := clients[broken]
					ctx := t.Context()
					selected := scope
					rows := scope.rows[broken]
					namespace := scope.namespace
					defer func() { scope.rows[broken] = rows; scope.namespace = namespace }()
					switch mode {
					case "nil-client":
						clients[broken] = nil
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
						client.actor.purpose = baselineAdmissionPurpose
					case "scope":
						copyScope := *scope
						client.actor.deniedScope = &copyScope
					case "empty-rows":
						scope.rows[broken] = nil
					case "missing-client":
						delete(clients, broken)
					case "extra-client":
						clients[destroyAdministratorActor] = client
					case "nil-context":
						ctx = nil
					case "cancelled-context":
						var cancel context.CancelFunc
						ctx, cancel = context.WithCancel(ctx)
						cancel()
					case "nil-scope":
						selected = nil
					case "invalid-namespace":
						scope.namespace = "PRIVATE-CANARY"
					}
					if baselineDeniedReviews(ctx, selected, clients) != ErrSecurityBaseline || requests.Load() != 0 {
						t.Fatal("unfrozen sibling reached wire or changed refusal")
					}
				})
			}
		})
	}
}

func TestBaselineDeniedSixteenLanesCancelAndJoinRefusedSiblings(t *testing.T) {
	testBaselineReviewRefusalJoins(t, 16, func(t *testing.T, server *httptest.Server) (map[admissionActor]*HTTPAccess, func(context.Context) error) {
		scope, _ := testDeniedLaneScope(t)
		clients := testDeniedLaneClients(t, server, scope)
		return clients, func(ctx context.Context) error {
			return baselineDeniedReviews(ctx, scope, clients)
		}
	})
}
