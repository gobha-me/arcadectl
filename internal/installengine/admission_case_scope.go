// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"maps"
	"reflect"
	"sync"

	"github.com/gobha-me/arcadectl/internal/installstate"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

type admissionCaseScopeKey struct{}

// One fixed nonpersistent case, never a fixture effect or reusable proof.
// Full phases and first/final unchanged guards remain outside this scope.
type admissionCaseScope struct {
	mu                  sync.Mutex
	self                *admissionCaseScope
	driver              *fixtureAdmissionDriver
	wire                *fixtureWire
	ledger              *fixtureLedger
	actors              *admissionActors
	admission           *ClusterAdmission
	prerequisites       *ClusterPrerequisites
	engine              *Engine
	access              *HTTPAccess
	clients             map[admissionActor]*HTTPAccess
	fixtureClients      map[admissionActor]*HTTPAccess
	request             LifecycleCheck
	seal                fixtureDriverSeal
	worldIdentity       *privatefs.FileIdentity
	lock                *privatefs.Lock
	before              *fixturePhaseObservation
	number              fixtureAdmissionCase
	probe               fixtureAdmissionRequest
	binding, validation string
	witness             map[installstate.Key]admissionIdentity
	configuration       map[installstate.Key]admissionIdentity
	root                context.Context
	cancel              context.CancelFunc
	busy                chan struct{}
	closed, poisoned    bool
}

func newAdmissionCaseScope(ctx context.Context, d *fixtureAdmissionDriver, number fixtureAdmissionCase, seal fixtureDriverSeal, before *fixturePhaseObservation) (context.Context, *admissionCaseScope, error) {
	if ctx == nil || ctx.Err() != nil || ctx.Value(admissionCaseScopeKey{}) != nil || d == nil || d.wire == nil || d.wire.ledger == nil || d.wire.actors == nil || before == nil || number == 39 || number == 45 || number >= fixtureAdmissionCaseCount {
		return nil, nil, ErrFixtures
	}
	w, f := d.wire, d.wire.ledger
	if w.actors.admission == nil || w.actors.admission.prerequisites == nil || w.actors.policies == nil || f.worldIdentity == nil || f.lock == nil {
		return nil, nil, ErrFixtures
	}
	r, err := w.admissionRequest(number, before)
	if err != nil || r.object == nil {
		return nil, nil, ErrFixtures
	}
	r.object = r.object.DeepCopy()
	s := &admissionCaseScope{driver: d, wire: w, ledger: f, actors: w.actors, request: w.actors.request, seal: seal, worldIdentity: f.worldIdentity, lock: f.lock, before: before, number: number, probe: r, witness: maps.Clone(w.actors.witness), configuration: maps.Clone(w.actors.policies.objects)}
	s.admission, s.prerequisites = w.actors.admission, w.actors.admission.prerequisites
	s.engine, s.access = s.prerequisites.engine, s.prerequisites.access
	s.clients, s.fixtureClients = maps.Clone(w.actors.clients), maps.Clone(w.clients)
	s.self = s
	s.seal.body = bytes.Clone(seal.body)
	if r.policy != "" {
		policy := w.actors.policies.policies[r.policy]
		if policy == nil || r.index < 0 || r.index >= len(policy.Spec.Validations) {
			return nil, nil, ErrFixtures
		}
		s.validation = policy.Spec.Validations[r.index].Message
		for name, binding := range w.actors.policies.bindings {
			if binding != nil && binding.Spec.PolicyName == r.policy {
				if s.binding != "" {
					return nil, nil, ErrFixtures
				}
				s.binding = name
			}
		}
		if s.binding == "" {
			return nil, nil, ErrFixtures
		}
	}
	s.root, s.cancel = context.WithCancel(ctx)
	caseCtx := context.WithValue(s.root, admissionCaseScopeKey{}, s)
	if !s.bound(caseCtx) || s.local(caseCtx, false) != nil {
		s.cancel()
		return nil, nil, ErrFixtures
	}
	return caseCtx, s, nil
}

// Caller owns wireMu throughout the case; closed scopes stop reading its
// mutable fields before the driver can advance the case prefix.
func (s *admissionCaseScope) bound(ctx context.Context) bool {
	if s == nil || s.self != s || ctx == nil || ctx.Err() != nil || s.root == nil || s.root.Err() != nil || ctx.Value(admissionCaseScopeKey{}) != s || s.driver == nil || s.wire == nil || s.ledger == nil || s.actors == nil || s.admission == nil || s.prerequisites == nil || s.engine == nil || s.access == nil || s.before == nil || s.probe.object == nil || s.number >= fixtureAdmissionCaseCount {
		return false
	}
	d, w, f := s.driver, s.wire, s.ledger
	return d.wire == w && w.ledger == f && w.actors == s.actors && !d.failed && d.next == s.number && d.completed == (uint64(1)<<s.number)-1 &&
		s.actors.admission == s.admission && s.admission.prerequisites == s.prerequisites && s.prerequisites.engine == s.engine && s.engine != nil && f.engine == s.engine && s.prerequisites.access == s.access && s.engine.access == s.access &&
		maps.Equal(s.actors.clients, s.clients) && maps.Equal(w.clients, s.fixtureClients) &&
		s.number != 39 && s.number != 45 && f.lock == s.lock && s.lock != nil && f.worldIdentity == s.worldIdentity && s.worldIdentity != nil && *s.worldIdentity == s.seal.worldID &&
		f.identity == s.seal.identity && f.document.Revision == s.seal.revision && bytes.Equal(f.body, s.seal.body) &&
		s.request.Snapshot != nil && s.request.Target != nil && s.actors.request.Snapshot == s.request.Snapshot && s.actors.request.Target == s.request.Target &&
		reflect.DeepEqual(s.actors.request, s.request) && reflect.DeepEqual(s.actors.witness, s.witness) && s.actors.policies != nil && reflect.DeepEqual(s.actors.policies.objects, s.configuration)
}

func (s *admissionCaseScope) begin(ctx context.Context) error {
	if s == nil || s.self != s {
		return ErrFixtures
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.poisoned || s.busy != nil || !s.bound(ctx) || ctx.Done() != s.root.Done() {
		s.closed, s.poisoned = true, true
		if s.cancel != nil {
			s.cancel()
		}
		return ErrFixtures
	}
	s.busy = make(chan struct{})
	return nil
}

func (s *admissionCaseScope) current(ctx context.Context) bool {
	if s == nil || s.self != s {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.closed && !s.poisoned && s.busy != nil && s.bound(ctx)
}

func (s *admissionCaseScope) local(ctx context.Context, leased bool) error {
	if s == nil || s.self != s {
		return ErrFixtures
	}
	if leased {
		if !s.current(ctx) {
			return ErrFixtures
		}
	} else if !s.bound(ctx) {
		return ErrFixtures
	}
	if !s.wire.phaseReadable() || s.wire.localCurrent() != nil || !s.bound(ctx) {
		return ErrFixtures
	}
	return nil
}

// Replace only original-access/configuration catalog collection. Keep every
// original Namespace/journal fence formerly inside verify: actor opening,
// configured opening and configured closing, plus both pure eligibility checks.
func (s *admissionCaseScope) guard(ctx context.Context, actors *admissionActors) error {
	if s == nil || s.self != s || actors != s.actors || s.local(ctx, true) != nil || actors.admission == nil || actors.admission.prerequisites == nil {
		return ErrFixtures
	}
	p := actors.admission.prerequisites
	if p.original(ctx, s.request.Snapshot) != nil || s.local(ctx, true) != nil {
		return ErrFixtures
	}
	if _, err := p.permissions(s.request); err != nil {
		return ErrFixtures
	}
	if _, err := p.permissions(s.request); err != nil {
		return ErrFixtures
	}
	if p.original(ctx, s.request.Snapshot) != nil || s.local(ctx, true) != nil {
		return ErrFixtures
	}
	if p.original(ctx, s.request.Snapshot) != nil || s.local(ctx, true) != nil {
		return ErrFixtures
	}
	return nil
}

func (s *admissionCaseScope) matchesProbe(actor admissionActor, operation admissionProbeOperation, object *unstructured.Unstructured, policy, binding, validation string) bool {
	return s != nil && s.self == s && object != nil && s.probe.object != nil && actor == s.probe.actor && operation == s.probe.operation && policy == s.probe.policy && binding == s.binding && validation == s.validation && reflect.DeepEqual(object.Object, s.probe.object.Object)
}

func (s *admissionCaseScope) finish(err error) error {
	if s == nil || s.self != s {
		return ErrFixtures
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil || s.closed || s.poisoned || s.root == nil || s.root.Err() != nil || s.busy == nil {
		s.closed, s.poisoned = true, true
		if s.cancel != nil {
			s.cancel()
		}
	}
	if s.busy != nil {
		close(s.busy)
		s.busy = nil
	}
	if s.poisoned {
		return ErrFixtures
	}
	return nil
}

func (s *admissionCaseScope) finishLease(err *error, complete *bool) {
	// A copied scope may contain a copied locked mutex and the ORIGINAL busy
	// channel/cancel function. Refuse before touching any of those resources.
	if s == nil || s.self != s {
		if err != nil {
			*err = ErrFixtures
		}
		return
	}
	if err == nil || complete == nil {
		s.refuse()
		return
	}
	failure := *err
	if !*complete && failure == nil {
		failure = ErrFixtures
	}
	if s.finish(failure) != nil && *err == nil {
		*err = ErrFixtures
	}
}

// An outer refusal cannot finish somebody else's in-flight helper lease.
func (s *admissionCaseScope) refuse() {
	if s == nil || s.self != s {
		return
	}
	s.mu.Lock()
	s.closed, s.poisoned = true, true
	if s.cancel != nil {
		s.cancel()
	}
	s.mu.Unlock()
}

func (s *admissionCaseScope) close() error {
	if s == nil || s.self != s {
		return ErrFixtures
	}
	s.mu.Lock()
	if !s.closed && (s.busy != nil || s.root == nil || s.root.Err() != nil) {
		s.poisoned = true
	}
	s.closed = true
	if s.cancel != nil {
		s.cancel()
	}
	done := s.busy
	s.mu.Unlock()
	if done != nil {
		<-done
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.poisoned {
		return ErrFixtures
	}
	return nil
}

func (actors *admissionActors) verifyCaseBoundary(ctx context.Context, scope *admissionCaseScope) error {
	if scope == nil {
		return actors.verify(ctx)
	}
	return scope.guard(ctx, actors)
}

func (w *fixtureWire) currentCaseBoundary(ctx context.Context, scope *admissionCaseScope) error {
	if scope == nil {
		return w.current(ctx)
	}
	if w != scope.wire {
		return ErrFixtures
	}
	return scope.guard(ctx, w.actors)
}

func (d *fixtureAdmissionDriver) unchangedCaseLocked(ctx context.Context, seal fixtureDriverSeal, scope *admissionCaseScope) (err error) {
	if scope == nil || scope.begin(ctx) != nil {
		return ErrFixtures
	}
	complete := false
	defer scope.finishLease(&err, &complete)
	if scope.driver != d || !reflect.DeepEqual(seal, scope.seal) {
		return ErrFixtures
	}
	err = d.unchangedWithCaseLocked(ctx, seal, scope)
	complete = err == nil
	return err
}

// Parent-actor cases also need a joined lease around their one dry-run. This
// adds no global witness and grants no generic actor/operation selection.
func (w *fixtureWire) probeParentCase(ctx context.Context, operation admissionProbeOperation, object *unstructured.Unstructured, policy, binding, validation string, scope *admissionCaseScope) (result *unstructured.Unstructured, err error) {
	if scope == nil || scope.begin(ctx) != nil {
		return nil, ErrFixtures
	}
	complete := false
	defer func() {
		scope.finishLease(&err, &complete)
		if err != nil {
			result = nil
		}
	}()
	if scope.wire != w || object == nil {
		return nil, ErrFixtures
	}
	object = object.DeepCopy()
	if !scope.matchesProbe(0, operation, object, policy, binding, validation) || scope.local(ctx, true) != nil {
		return nil, ErrFixtures
	}
	result, err = w.actors.admission.prerequisites.access.probeOperation(ctx, operation, object, policy, binding, validation)
	if err != nil || scope.local(ctx, true) != nil {
		return nil, ErrFixtures
	}
	complete = true
	return result, nil
}
