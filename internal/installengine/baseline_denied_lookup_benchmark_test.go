// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	authv1 "k8s.io/api/authorization/v1"
)

// Test-only prototype: membership changes, never identity guards, catalog
// authority, requests, fresh observations, or fences. No production caller uses it.
type testDeniedLookupIndex struct {
	scope *baselineDeniedScope
	rows  map[admissionActor]map[baselineDeniedDescriptor]struct{}
}

func testNewDeniedLookupIndex(scope *baselineDeniedScope) *testDeniedLookupIndex {
	x := &testDeniedLookupIndex{scope: scope, rows: map[admissionActor]map[baselineDeniedDescriptor]struct{}{}}
	if scope != nil {
		for actor, rows := range scope.rows {
			x.rows[actor] = make(map[baselineDeniedDescriptor]struct{}, len(rows))
			for _, row := range rows {
				x.rows[actor][row] = struct{}{}
			}
		}
	}
	return x
}

func (x *testDeniedLookupIndex) allows(identity actorWireIdentity, a *authv1.ResourceAttributes) bool {
	if x == nil {
		return false
	}
	s := x.scope
	if s == nil || identity.purpose != baselineDeniedReviewPurpose || identity.deniedScope != s || identity.namespace != s.namespace || !installrender.ValidNamespace(s.namespace) ||
		identity.username != "system:serviceaccount:"+s.namespace+":"+identity.actor.account() ||
		identity.actor != ordinaryControllerActor && identity.actor != destroyControllerActor || a == nil || a.FieldSelector != nil || a.LabelSelector != nil {
		return false
	}
	_, ok := x.rows[identity.actor][baselineDeniedDescriptor{a.Group, a.Version, a.Resource, a.Subresource, a.Namespace, a.Name, a.Verb}]
	return ok
}

func testDeniedLookupIdentity(scope *baselineDeniedScope, actor admissionActor) actorWireIdentity {
	return actorWireIdentity{actor: actor, purpose: baselineDeniedReviewPurpose, namespace: scope.namespace, username: "system:serviceaccount:" + scope.namespace + ":" + actor.account(), deniedScope: scope}
}

func testDeniedLookupRowsCopy(scope *baselineDeniedScope) map[admissionActor][]baselineDeniedDescriptor {
	result := map[admissionActor][]baselineDeniedDescriptor{}
	for actor, rows := range scope.rows {
		result[actor] = append([]baselineDeniedDescriptor(nil), rows...)
	}
	return result
}

func TestBaselineDeniedLookupPrototypeParity(t *testing.T) {
	f, access, objects := baselineDeniedFixture(t)
	scope, err := f.engine.baselineDeniedCatalog(f.snapshot.Document(), access, objects)
	if err != nil || scope == nil {
		t.Fatal("actual denied catalog unavailable")
	}
	before := testDeniedLookupRowsCopy(scope)
	benchmarkScope := testDeniedLookupBenchmarkScope()
	if benchmarkScope.namespace != scope.namespace || !reflect.DeepEqual(benchmarkScope.rows, scope.rows) {
		t.Fatal("benchmark fixture differs from actual catalog namespace, rows, or order")
	}
	index := testNewDeniedLookupIndex(scope)
	var clusterKeys []installstate.Key
	for key := range access {
		if key.Kind == "ClusterRole" || key.Kind == "ClusterRoleBinding" {
			clusterKeys = append(clusterKeys, key)
		}
	}
	check := func(identity actorWireIdentity, a *authv1.ResourceAttributes) {
		t.Helper()
		var original *authv1.ResourceAttributes
		if a != nil {
			original = a.DeepCopy()
		}
		if index.allows(identity, a) != scope.allows(identity, a) {
			t.Fatal("indexed and linear decisions differ")
		}
		if !reflect.DeepEqual(original, a) {
			t.Fatal("lookup mutated attributes")
		}
	}
	for _, actor := range []admissionActor{ordinaryControllerActor, destroyControllerActor} {
		identity := testDeniedLookupIdentity(scope, actor)
		literal := testBaselineDeniedAttributes(scope.namespace, actor, clusterKeys)
		if len(literal) != len(scope.rows[actor]) {
			t.Fatal("actual catalog row count differs from independent literal requirements")
		}
		for row := range literal {
			if !scope.allows(identity, &row) || !index.allows(identity, &row) {
				t.Fatal("literal member rejected")
			}
			check(identity, &row)
			// Some changed descriptors may be other valid members: compare the
			// actual decisions, rather than assuming every mutation is denied.
			for field := 0; field < 7; field++ {
				changed := row
				fields := []*string{&changed.Group, &changed.Version, &changed.Resource, &changed.Subresource, &changed.Namespace, &changed.Name, &changed.Verb}
				*fields[field] += "-different"
				check(identity, &changed)
			}
		}
		a := scope.rows[actor][0].attributes()
		check(identity, nil)
		for _, purpose := range []actorWirePurpose{0, runtimeAdmissionPurpose, baselineAdmissionPurpose, baselineRulesReviewPurpose} {
			changed := identity
			changed.purpose = purpose
			check(changed, a)
		}
		for _, other := range []admissionActor{0, ordinaryControllerActor, destroyControllerActor, destroyAdministratorActor, 255} {
			changed := identity
			changed.actor = other
			check(changed, a)
			changed.username = "system:serviceaccount:" + scope.namespace + ":" + other.account()
			check(changed, a)
		}
		for _, change := range []func(*actorWireIdentity){
			func(i *actorWireIdentity) { i.username = "foreign-user" },
			func(i *actorWireIdentity) { i.namespace = "foreign-namespace" },
			func(i *actorWireIdentity) { i.deniedScope = nil },
			func(i *actorWireIdentity) { clone := *scope; i.deniedScope = &clone },
		} {
			changed := identity
			change(&changed)
			check(changed, a)
		}
		selector := a.DeepCopy()
		selector.FieldSelector = &authv1.FieldSelectorAttributes{}
		check(identity, selector)
		selector = a.DeepCopy()
		selector.LabelSelector = &authv1.LabelSelectorAttributes{}
		check(identity, selector)
	}
	var wg sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for actor, rows := range before {
				identity := testDeniedLookupIdentity(scope, actor)
				for _, row := range rows {
					if !index.allows(identity, row.attributes()) {
						t.Error("concurrent immutable lookup rejected member")
						return
					}
				}
			}
		}()
	}
	wg.Wait()
	if !reflect.DeepEqual(before, scope.rows) {
		t.Fatal("lookup/index construction changed original rows or row order")
	}
	for _, namespace := range []string{"", "INVALID", "foreign-namespace"} {
		other := &baselineDeniedScope{namespace: namespace, rows: before}
		i := testDeniedLookupIdentity(other, ordinaryControllerActor)
		a := before[ordinaryControllerActor][0].attributes()
		if testNewDeniedLookupIndex(other).allows(i, a) != other.allows(i, a) {
			t.Fatal("namespace guard differs")
		}
	}
	var nilIndex *testDeniedLookupIndex
	if nilIndex.allows(actorWireIdentity{}, nil) || testNewDeniedLookupIndex(nil).allows(actorWireIdentity{}, nil) {
		t.Fatal("nil prototype accepted lookup")
	}
}

// Independent literal finite catalog, with the four real fixture cluster keys.
// Benchmark setup is deterministic and performs no HTTP or cluster operations.
func testDeniedLookupBenchmarkScope() *baselineDeniedScope {
	var keys []installstate.Key
	for _, kind := range []string{"ClusterRole", "ClusterRoleBinding"} {
		for _, name := range []string{"arcadectl-volumeattachment-reader-5d8927e3b78f", "arcadectl-destroy-volumeattachment-reader-5d8927e3b78f"} {
			keys = append(keys, installstate.Key{APIVersion: "rbac.authorization.k8s.io/v1", Kind: kind, Name: name})
		}
	}
	scope := &baselineDeniedScope{namespace: "isolated-install", rows: map[admissionActor][]baselineDeniedDescriptor{}}
	for _, actor := range []admissionActor{ordinaryControllerActor, destroyControllerActor} {
		for a := range testBaselineDeniedAttributes(scope.namespace, actor, keys) {
			scope.rows[actor] = append(scope.rows[actor], baselineDeniedDescriptor{a.Group, a.Version, a.Resource, a.Subresource, a.Namespace, a.Name, a.Verb})
		}
		sort.Slice(scope.rows[actor], func(i, j int) bool {
			a, b := scope.rows[actor][i], scope.rows[actor][j]
			return strings.Join([]string{a.group, a.version, a.resource, a.subresource, a.namespace, a.name, a.verb}, "\x00") < strings.Join([]string{b.group, b.version, b.resource, b.subresource, b.namespace, b.name, b.verb}, "\x00")
		})
	}
	return scope
}

var testDeniedLookupHits int
var testDeniedLookupBuilt *testDeniedLookupIndex

func BenchmarkBaselineDeniedLookupPrototype(b *testing.B) {
	scope := testDeniedLookupBenchmarkScope()
	index := testNewDeniedLookupIndex(scope)
	for _, actor := range []admissionActor{ordinaryControllerActor, destroyControllerActor} {
		identity := testDeniedLookupIdentity(scope, actor)
		var queries []*authv1.ResourceAttributes
		for _, row := range scope.rows[actor] {
			queries = append(queries, row.attributes())
		}
		queries = append(queries, &authv1.ResourceAttributes{Group: "missing.example", Version: "v1", Resource: "missing", Namespace: scope.namespace, Verb: "get"})
		for n, query := range queries {
			want := n < len(queries)-1
			if scope.allows(identity, query) != want || index.allows(identity, query) != want {
				b.Fatal("benchmark query sequence is not equivalent")
			}
		}
		for _, order := range []string{"linear-first", "index-first"} {
			b.Run(actor.account()+"/"+order, func(b *testing.B) {
				methods := []struct {
					name string
					call func(actorWireIdentity, *authv1.ResourceAttributes) bool
				}{{"linear", scope.allows}, {"indexed", index.allows}}
				if order == "index-first" {
					methods[0], methods[1] = methods[1], methods[0]
				}
				for _, method := range methods {
					b.Run(method.name, func(b *testing.B) {
						b.ReportAllocs()
						b.ResetTimer()
						hits := 0
						for n := 0; n < b.N; n++ {
							for _, query := range queries {
								if method.call(identity, query) {
									hits++
								}
							}
						}
						b.StopTimer()
						testDeniedLookupHits = hits
						b.ReportMetric(float64(len(scope.rows[actor])), "rows/pass")
						b.ReportMetric(float64(len(queries)), "queries/pass")
					})
				}
			})
		}
	}
	b.Run("build", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for n := 0; n < b.N; n++ {
			testDeniedLookupBuilt = testNewDeniedLookupIndex(scope)
		}
		b.StopTimer()
		b.ReportMetric(float64(len(scope.rows[ordinaryControllerActor])+len(scope.rows[destroyControllerActor])), "rows/build")
	})
}
