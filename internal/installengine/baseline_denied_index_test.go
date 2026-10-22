// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	authv1 "k8s.io/api/authorization/v1"
)

func cloneDeniedIndexScope(s *baselineDeniedScope) *baselineDeniedScope {
	copyScope := &baselineDeniedScope{namespace: s.namespace, rows: map[admissionActor][]baselineDeniedDescriptor{}, index: map[admissionActor]map[baselineDeniedDescriptor]int{}}
	for actor, rows := range s.rows {
		copyScope.rows[actor] = append([]baselineDeniedDescriptor(nil), rows...)
	}
	for actor, index := range s.index {
		copyScope.index[actor] = map[baselineDeniedDescriptor]int{}
		for row, slot := range index {
			copyScope.index[actor][row] = slot
		}
	}
	return copyScope
}

func deniedIndexIdentity(scope *baselineDeniedScope, actor admissionActor) actorWireIdentity {
	return actorWireIdentity{actor: actor, purpose: baselineDeniedReviewPurpose, namespace: scope.namespace, username: "system:serviceaccount:" + scope.namespace + ":" + actor.account(), deniedScope: scope}
}

func TestBaselineDeniedIndexLiteralMembershipAndCopies(t *testing.T) {
	scope, literal := testDeniedLaneScope(t)
	if !scope.valid() || (*baselineDeniedScope)(nil).valid() {
		t.Fatal("production catalog lacks a complete private index")
	}
	for _, actor := range []admissionActor{ordinaryControllerActor, destroyControllerActor} {
		want := 621
		if actor == destroyControllerActor {
			want = 650
		}
		if len(literal[actor]) != want || len(scope.rows[actor]) != want || len(scope.index[actor]) != want {
			t.Fatal("independent original fixture row census changed")
		}
		identity := deniedIndexIdentity(scope, actor)
		for _, attributes := range literal[actor] {
			if !scope.allows(identity, &attributes) {
				t.Fatal("indexed lookup omitted an independent literal tuple")
			}
			changed := attributes
			changed.Name = "unrecorded-foreign"
			if scope.allows(identity, &changed) {
				t.Fatal("index widened finite descriptor authority")
			}
		}
		attributes := scope.rows[actor][0].attributes()
		foreign := identity
		foreign.deniedScope = cloneDeniedIndexScope(scope)
		if scope.allows(foreign, attributes) || (*baselineDeniedScope)(nil).allows(identity, attributes) || scope.allows(identity, nil) {
			t.Fatal("index accepted nil or pointer-foreign scope")
		}
		for _, selector := range []string{"field", "label"} {
			changed := *attributes
			if selector == "field" {
				changed.FieldSelector = &authv1.FieldSelectorAttributes{}
			} else {
				changed.LabelSelector = &authv1.LabelSelectorAttributes{}
			}
			if scope.allows(identity, &changed) {
				t.Fatal("index accepted a selector-bearing descriptor")
			}
		}
	}
	// Copies are independent of both private backing structures, not aliases.
	copyScope := cloneDeniedIndexScope(scope)
	delete(copyScope.index[ordinaryControllerActor], copyScope.rows[ordinaryControllerActor][0])
	copyScope.rows[destroyControllerActor][0].name = "changed-private-copy"
	if !scope.valid() || copyScope.valid() {
		t.Fatal("descriptor index copy aliased the original catalog")
	}
}

func TestBaselineDeniedIndexMalformedScopesRefuseBeforeEitherActor(t *testing.T) {
	original, _ := testDeniedLaneScope(t)
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	admin, err := NewDirectHTTPAccess(serverConfig(server))
	if err != nil {
		t.Fatal("original administrator unavailable")
	}
	modes := []string{"nil-rows", "missing-row-actor", "extra-row-actor", "nil-index", "missing-actor", "extra-actor", "nil-actor-index", "missing-tuple", "extra-tuple", "negative-slot", "past-end-slot", "duplicate-slot", "wrong-slot", "reordered-rows", "mutated-row", "removed-row", "duplicated-row", "foreign-namespace"}
	for _, broken := range []admissionActor{ordinaryControllerActor, destroyControllerActor} {
		for _, mode := range modes {
			t.Run(broken.account()+"/"+mode, func(t *testing.T) {
				scope := cloneDeniedIndexScope(original)
				clients := testDeniedLaneClients(t, server, scope)
				rows, index := scope.rows[broken], scope.index[broken]
				last := len(rows) - 1
				attributes := rows[last].attributes()
				switch mode {
				case "nil-rows":
					scope.rows = nil
				case "missing-row-actor":
					delete(scope.rows, broken)
				case "extra-row-actor":
					scope.rows[destroyAdministratorActor] = rows
				case "nil-index":
					scope.index = nil
				case "missing-actor":
					delete(scope.index, broken)
				case "extra-actor":
					scope.index[destroyAdministratorActor] = index
				case "nil-actor-index":
					scope.index[broken] = nil
				case "missing-tuple":
					delete(index, rows[last])
				case "extra-tuple":
					foreign := rows[last]
					foreign.name = "unrecorded-foreign"
					index[foreign] = last
				case "negative-slot":
					index[rows[last]] = -1
				case "past-end-slot":
					index[rows[last]] = len(rows)
				case "duplicate-slot":
					index[rows[last]] = 0
				case "wrong-slot":
					index[rows[last]], index[rows[0]] = 0, last
				case "reordered-rows":
					rows[0], rows[last] = rows[last], rows[0]
				case "mutated-row":
					rows[last].name = "changed-private-row"
				case "removed-row":
					scope.rows[broken] = rows[:last]
				case "duplicated-row":
					rows[last] = rows[0]
				case "foreign-namespace":
					for _, row := range rows {
						if row.namespace != "" {
							attributes = row.attributes()
							break
						}
					}
					scope.namespace = "foreign-valid"
				}
				if scope.valid() {
					t.Fatal("malformed private row/index bijection accepted")
				}
				for _, actor := range []admissionActor{ordinaryControllerActor, destroyControllerActor} {
					if client, err := admin.baselineDeniedClient(actor, scope); err == nil || client != nil {
						t.Fatal("constructor accepted a malformed sibling catalog")
					}
				}
				if baselineDeniedReviews(t.Context(), scope, clients) != ErrSecurityBaseline || requests.Load() != 0 {
					t.Fatal("malformed actor catalog reached wire before complete validation")
				}
				if scope.allows(deniedIndexIdentity(scope, broken), attributes) {
					t.Fatal("stale requested tuple survived constant-time membership guards")
				}
			})
		}
	}
}

func TestBaselineDeniedIndexConcurrentReadOnlyMembership(t *testing.T) {
	scope, literal := testDeniedLaneScope(t)
	var group sync.WaitGroup
	var refused atomic.Bool
	for _, actor := range []admissionActor{ordinaryControllerActor, destroyControllerActor} {
		identity := deniedIndexIdentity(scope, actor)
		for lane := range 4 {
			group.Go(func() {
				for slot := lane; slot < len(literal[actor]); slot += 4 {
					attributes := literal[actor][slot]
					if !scope.allows(identity, &attributes) {
						refused.Store(true)
					}
				}
			})
		}
	}
	group.Wait()
	if refused.Load() || !scope.valid() {
		t.Fatal("concurrent immutable lookups lost catalog membership")
	}
}

// Preserve the old complete request-side predicate as an independent benchmark
// reference; both implementations below receive the SAME frozen literal rows.
func linearDeniedIndexReference(s *baselineDeniedScope, identity actorWireIdentity, a *authv1.ResourceAttributes) bool {
	if s == nil || identity.purpose != baselineDeniedReviewPurpose || identity.deniedScope != s || identity.namespace != s.namespace || !installrender.ValidNamespace(s.namespace) ||
		identity.username != "system:serviceaccount:"+s.namespace+":"+identity.actor.account() ||
		identity.actor != ordinaryControllerActor && identity.actor != destroyControllerActor || a == nil || a.FieldSelector != nil || a.LabelSelector != nil {
		return false
	}
	row := baselineDeniedDescriptor{a.Group, a.Version, a.Resource, a.Subresource, a.Namespace, a.Name, a.Verb}
	for _, allowed := range s.rows[identity.actor] {
		if row == allowed {
			return true
		}
	}
	return false
}

func BenchmarkBaselineDeniedDescriptorMembership(b *testing.B) {
	const namespace = "arcadectl"
	clusterKeys := []installstate.Key{}
	for _, kind := range []string{"ClusterRole", "ClusterRoleBinding"} {
		for _, name := range []string{"arcadectl-volumeattachment-reader-5d8927e3b78f", "arcadectl-destroy-volumeattachment-reader-5d8927e3b78f"} {
			clusterKeys = append(clusterKeys, installstate.Key{APIVersion: "rbac.authorization.k8s.io/v1", Kind: kind, Name: name})
		}
	}
	scope := &baselineDeniedScope{namespace: namespace, rows: map[admissionActor][]baselineDeniedDescriptor{}, index: map[admissionActor]map[baselineDeniedDescriptor]int{}}
	for _, actor := range []admissionActor{ordinaryControllerActor, destroyControllerActor} {
		for a := range testBaselineDeniedAttributes(namespace, actor, clusterKeys) {
			scope.rows[actor] = append(scope.rows[actor], baselineDeniedDescriptor{a.Group, a.Version, a.Resource, a.Subresource, a.Namespace, a.Name, a.Verb})
		}
		sort.Slice(scope.rows[actor], func(i, j int) bool {
			a, c := scope.rows[actor][i], scope.rows[actor][j]
			return strings.Join([]string{a.group, a.version, a.resource, a.subresource, a.namespace, a.name, a.verb}, "\x00") < strings.Join([]string{c.group, c.version, c.resource, c.subresource, c.namespace, c.name, c.verb}, "\x00")
		})
		scope.index[actor] = map[baselineDeniedDescriptor]int{}
		for slot, row := range scope.rows[actor] {
			scope.index[actor][row] = slot
		}
	}
	if !scope.valid() || len(scope.rows[ordinaryControllerActor]) != 621 || len(scope.rows[destroyControllerActor]) != 650 {
		b.Fatal("benchmark lost independent realistic literal catalogs")
	}
	for _, actor := range []admissionActor{ordinaryControllerActor, destroyControllerActor} {
		rows := scope.rows[actor]
		attributes := make([]authv1.ResourceAttributes, len(rows))
		for slot, row := range rows {
			attributes[slot] = *row.attributes()
		}
		identity := deniedIndexIdentity(scope, actor)
		for _, algorithm := range []string{"indexed", "linear-reference"} {
			lookup := scope.allows
			if algorithm == "linear-reference" {
				lookup = func(identity actorWireIdentity, a *authv1.ResourceAttributes) bool {
					return linearDeniedIndexReference(scope, identity, a)
				}
			}
			b.Run(fmt.Sprintf("rows-%d/%s/full-pass", len(rows), algorithm), func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					for slot := range attributes {
						if !lookup(identity, &attributes[slot]) {
							b.Fatal("literal benchmark member rejected")
						}
					}
				}
			})
			for _, position := range []int{0, len(rows) / 2, len(rows) - 1, len(rows)} {
				attributes := *rows[position%len(rows)].attributes()
				want := position != len(rows)
				if !want {
					attributes.Name = "unrecorded-foreign"
				}
				b.Run(fmt.Sprintf("rows-%d/%s/position-%d", len(rows), algorithm, position), func(b *testing.B) {
					b.ReportAllocs()
					for b.Loop() {
						if lookup(identity, &attributes) != want {
							b.Fatal("benchmark changed finite membership")
						}
					}
				})
			}
		}
	}
}
