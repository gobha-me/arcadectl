// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"errors"
	"net/http"
	"runtime"
	"testing"
	"time"
)

func testAdmissionCaseOwner(t *testing.T) (*testAdmissionCaseProtocol, context.Context, *admissionCaseScope) {
	t.Helper()
	p := testAdmissionCaseProtocolFixture(t, 17)
	// The constructor is private and cannot claim opening proof by itself.
	if p.d.unchangedLocked(t.Context(), p.seal) != nil {
		t.Fatal("case opening full original fence refused")
	}
	ctx, scope, err := newAdmissionCaseScope(t.Context(), p.d, p.number, p.seal, p.before)
	if err != nil || ctx == nil || scope == nil {
		t.Fatal("original exact case capability unavailable")
	}
	// Failure cleanup must not itself hang on a deliberately unfinished lease.
	// Assertions below run before this fallback and prove the actual join.
	t.Cleanup(func() { _ = scope.finish(ErrFixtures); _ = scope.close() })
	return p, ctx, scope
}

func TestAdmissionCaseScopeSerialOwnerCannotOutliveCase(t *testing.T) {
	p, ctx, scope := testAdmissionCaseOwner(t)
	if scope.current(ctx) || scope.begin(ctx) != nil || !scope.current(ctx) {
		t.Fatal("case owner granted unleased authority or refused original serial entry")
	}
	child, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	if !scope.current(child) || scope.finish(nil) != nil || scope.current(child) || scope.begin(ctx) != nil || scope.finish(nil) != nil || scope.close() != nil || scope.close() != nil || scope.begin(ctx) != ErrFixtures || scope.current(ctx) {
		t.Fatal("case close revived authority or changed serial lease semantics")
	}
	p.assertCustody(t)
}

func TestAdmissionCaseScopeForeignContextCannotBorrowOwner(t *testing.T) {
	_, ctx, scope := testAdmissionCaseOwner(t)
	forged := context.WithValue(context.Background(), admissionCaseScopeKey{}, scope)
	if scope.begin(forged) != ErrFixtures || scope.begin(ctx) != ErrFixtures {
		t.Fatal("foreign root borrowed the marker or invalid entry failed to poison")
	}
}

func TestAdmissionCaseScopeCanceledAndExpiredEntriesNeverRevive(t *testing.T) {
	for _, expired := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancelled", true: "expired"}[expired], func(t *testing.T) {
			_, ctx, scope := testAdmissionCaseOwner(t)
			var trial context.Context
			var cancel context.CancelFunc
			if expired {
				trial, cancel = context.WithDeadline(ctx, time.Now().Add(-time.Second))
			} else {
				trial, cancel = context.WithCancel(ctx)
				cancel()
			}
			defer cancel()
			if scope.begin(trial) != ErrFixtures || scope.begin(ctx) != ErrFixtures || scope.current(ctx) {
				t.Fatal("cancelled or expired case entry left reusable authority")
			}
		})
	}
}

func TestAdmissionCaseScopeChangedCaseAndSnapshotPoisonOwner(t *testing.T) {
	for _, fault := range []string{"next-case", "prefix", "failed-driver", "snapshot", "seal-revision", "seal-body", "world-identity"} {
		t.Run(fault, func(t *testing.T) {
			p, ctx, scope := testAdmissionCaseOwner(t)
			switch fault {
			case "next-case":
				p.d.next++
			case "prefix":
				p.d.completed--
			case "failed-driver":
				p.d.failed = true
			case "snapshot":
				p.h.f.wire.actors.request.Snapshot = nil
			case "seal-revision":
				p.h.f.wire.ledger.document.Revision++
			case "seal-body":
				p.h.f.wire.ledger.body = append(p.h.f.wire.ledger.body, ' ')
			case "world-identity":
				p.h.f.wire.ledger.worldIdentity = nil
			}
			if scope.begin(ctx) != ErrFixtures || scope.current(ctx) {
				t.Fatal("changed exact case/snapshot/seal supplied authority")
			}
		})
	}
}

func TestAdmissionCaseScopeByteIdenticalSnapshotIsAnotherInvocation(t *testing.T) {
	p, ctx, scope := testAdmissionCaseOwner(t)
	original := p.h.f.wire.actors.request.Snapshot
	reloaded, err := p.h.f.wire.ledger.engine.journal.Load(t.Context(), original.Anchor())
	if err != nil || reloaded == original || !reloaded.SameJournalBytes(original) || reloaded.ResourceVersion() != original.ResourceVersion() {
		t.Fatal("independent same-byte snapshot control unavailable")
	}
	p.h.f.wire.actors.request.Snapshot = reloaded
	if scope.begin(ctx) != ErrFixtures || scope.current(ctx) {
		t.Fatal("scope accepted a byte-identical snapshot from another invocation")
	}
}

func TestAdmissionCaseScopeNestedOwnerCannotMintAnotherOwner(t *testing.T) {
	p, ctx, scope := testAdmissionCaseOwner(t)
	if nested, next, err := newAdmissionCaseScope(ctx, p.d, p.number, p.seal, p.before); nested != nil || next != nil || err != ErrFixtures {
		t.Fatal("nested case minted reusable owner")
	}
	if scope.begin(ctx) != nil || scope.finish(nil) != nil {
		t.Fatal("nested rejection damaged independent original owner")
	}
}

func TestAdmissionCaseScopeEntireExcludedCaseCannotMintOwner(t *testing.T) {
	for _, number := range []fixtureAdmissionCase{39, 45} {
		t.Run(map[fixtureAdmissionCase]string{39: "seed", 45: "marker"}[number], func(t *testing.T) {
			p := testAdmissionCaseProtocolFixture(t, number)
			if next, owner, err := newAdmissionCaseScope(t.Context(), p.d, number, p.seal, p.before); next != nil || owner != nil || err != ErrFixtures {
				t.Fatal("valid original entire seed/marker case accepted reduced witnesses")
			}
		})
	}
}

func TestAdmissionCaseScopeOtherDriverCannotUseOriginalOwner(t *testing.T) {
	p, ctx, scope := testAdmissionCaseOwner(t)
	foreign := &fixtureAdmissionDriver{wire: p.d.wire, previous: p.before, next: p.number, completed: p.d.completed}
	beforePolicies, beforeBindings := p.policies, p.bindings
	if foreign.unchangedCaseLocked(ctx, p.seal, scope) != ErrFixtures || p.policies != beforePolicies || p.bindings != beforeBindings {
		t.Fatal("other driver used exact owner's authority or reached global wire")
	}
	if scope.begin(ctx) != ErrFixtures || scope.current(ctx) {
		t.Fatal("foreign driver attempt did not poison the leased owner")
	}
}

func TestAdmissionCaseScopeCopiedOwnerCannotBorrowOriginalSeal(t *testing.T) {
	_, ctx, scope := testAdmissionCaseOwner(t)
	// Construct only a foreign self identity; never copy sync.Mutex fields.
	copy := &admissionCaseScope{self: scope}
	forged := context.WithValue(ctx, admissionCaseScopeKey{}, copy)
	if copy.begin(forged) != ErrFixtures || copy.current(forged) {
		t.Fatal("copied owner borrowed original scope identity")
	}
	if scope.begin(ctx) != nil || scope.finish(nil) != nil {
		t.Fatal("foreign copy revoked original owner without holding its lease")
	}
}

func testAdmissionCaseForgedCopyStateEntry(t *testing.T, operation string) {
	t.Helper()
	_, ctx, original := testAdmissionCaseOwner(t)
	if original.begin(ctx) != nil {
		t.Fatal("original active lease unavailable")
	}
	busy := original.busy
	// Deliberately copy only reference fields. Copying the mutex itself would
	// make this a copylocks bug in the TEST rather than a hostile identity.
	forged := &admissionCaseScope{self: original, root: original.root, cancel: original.cancel, busy: busy}
	forgedCtx := context.WithValue(ctx, admissionCaseScopeKey{}, forged)
	forged.mu.Lock()
	type outcome struct {
		refused    bool
		panicValue any
	}
	done := make(chan outcome, 1)
	go func() {
		result := outcome{}
		defer func() { result.panicValue = recover(); done <- result }()
		switch operation {
		case "begin":
			result.refused = forged.begin(forgedCtx) == ErrFixtures
		case "current":
			result.refused = !forged.current(forgedCtx)
		case "finish":
			result.refused = forged.finish(nil) == ErrFixtures
		case "close":
			result.refused = forged.close() == ErrFixtures
		case "refuse":
			forged.refuse()
			result.refused = true
		case "finish-lease":
			var err error
			complete := true
			forged.finishLease(&err, &complete)
			result.refused = err == ErrFixtures
		}
	}()
	var result outcome
	blocked := false
	select {
	case result = <-done:
	case <-time.After(200 * time.Millisecond):
		blocked = true
	}
	// ALWAYS unlock and join a broken pre-fix implementation before reporting
	// failure. A bad close may be waiting on the original's shared busy channel.
	forged.mu.Unlock()
	if blocked && operation == "close" {
		_ = original.finish(ErrFixtures)
	}
	if blocked {
		select {
		case result = <-done:
		case <-time.After(2 * time.Second):
			_ = original.finish(ErrFixtures)
			select {
			case result = <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("forged state entry failed to join after unlocking/cancelling its shared lease")
			}
		}
	}
	closedByCopy := false
	select {
	case <-busy:
		closedByCopy = true
	default:
	}
	cancelledByCopy := ctx.Err() != nil
	if closedByCopy {
		// TEST failure cleanup only: detach the already-closed channel so the
		// valid owner's cleanup cannot panic by closing it a second time.
		original.mu.Lock()
		if original.busy == busy {
			original.busy = nil
		}
		original.mu.Unlock()
	}
	originalWasLive := original.current(ctx)
	finishErr := original.finish(nil)
	if blocked || !result.refused || result.panicValue != nil || closedByCopy || cancelledByCopy || !originalWasLive || finishErr != nil {
		t.Fatal("forged copied owner touched mutex, cancelled original context, closed shared lease, or prevented original-only finish")
	}
	select {
	case <-busy:
	default:
		t.Fatal("original finish failed to close its own active lease")
	}
}

func TestAdmissionCaseScopeForgedCopyBeginRejectsBeforeMutex(t *testing.T) {
	testAdmissionCaseForgedCopyStateEntry(t, "begin")
}
func TestAdmissionCaseScopeForgedCopyCurrentRejectsBeforeMutex(t *testing.T) {
	testAdmissionCaseForgedCopyStateEntry(t, "current")
}
func TestAdmissionCaseScopeForgedCopyFinishCannotCloseOriginalLease(t *testing.T) {
	testAdmissionCaseForgedCopyStateEntry(t, "finish")
}
func TestAdmissionCaseScopeForgedCopyCloseCannotCancelOriginalOwner(t *testing.T) {
	testAdmissionCaseForgedCopyStateEntry(t, "close")
}
func TestAdmissionCaseScopeForgedCopyRefuseCannotCancelOriginalOwner(t *testing.T) {
	testAdmissionCaseForgedCopyStateEntry(t, "refuse")
}
func TestAdmissionCaseScopeForgedCopyFinishLeaseCannotCloseOriginalLease(t *testing.T) {
	testAdmissionCaseForgedCopyStateEntry(t, "finish-lease")
}

func TestAdmissionCaseScopeStandaloneMethodsKeepFullWitnesses(t *testing.T) {
	p, ctx, scope := testAdmissionCaseOwner(t)
	beforePolicies, beforeBindings := p.policies, p.bindings
	// Supplying the private marker does not change default semantics. Only
	// explicit selected helpers can spend the capability; a full actor guard
	// still performs its actual access/configuration observations here.
	if p.h.f.wire.actors.verify(ctx) != nil || p.policies != beforePolicies+1 || p.bindings != beforeBindings+1 {
		t.Fatal("ambient marker bypassed a standalone full actor witness")
	}
	if scope.begin(ctx) != nil || scope.finish(nil) != nil {
		t.Fatal("standalone full witness consumed private helper lease")
	}
	p.assertCustody(t)
}

func TestAdmissionCaseScopeChangedProbeObjectPoisonsBeforeHTTP(t *testing.T) {
	p, ctx, scope := testAdmissionCaseOwner(t)
	r, err := p.h.f.wire.admissionRequest(p.number, p.before)
	if err != nil {
		t.Fatal("fixed original actor request unavailable")
	}
	r.object.SetNamespace("foreign-case-namespace")
	policy := p.h.f.wire.actors.policies.policies[r.policy]
	binding := ""
	for name, b := range p.h.f.wire.actors.policies.bindings {
		if b.Spec.PolicyName == r.policy {
			binding = name
		}
	}
	beforePolicies, beforeBindings := p.policies, p.bindings
	if result, err := p.h.f.wire.actors.probeCase(ctx, r.actor, r.operation, r.object, r.policy, binding, policy.Spec.Validations[3].Message, scope); result != nil || err != ErrFixtures || p.probes != 0 || p.exactReviews != 0 || p.policies != beforePolicies || p.bindings != beforeBindings {
		t.Fatal("changed closed candidate reached HTTP or produced a result")
	}
	if scope.begin(ctx) != ErrFixtures || scope.current(ctx) {
		t.Fatal("changed candidate left reusable authority")
	}
	p.assertCustody(t)
}

func TestAdmissionCaseScopeSuccessfulCaseCannotAuthorizeNextCase(t *testing.T) {
	p := testAdmissionCaseProtocolFixture(t, 1)
	client := p.h.f.wire.actors.admission.prerequisites.access
	original := client.client.Transport
	var spent *admissionCaseScope
	var sentCtx context.Context
	client.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Query().Get("dryRun") == "All" {
			spent, _ = r.Context().Value(admissionCaseScopeKey{}).(*admissionCaseScope)
			sentCtx = r.Context()
		}
		return original.RoundTrip(r)
	})
	if err := p.run(t.Context()); err != nil || spent == nil || p.d.next != 2 || p.d.completed != 3 {
		t.Fatal("completed case failed to revoke its exact owner", err)
	}
	if spent.begin(sentCtx) != ErrFixtures || spent.current(sentCtx) {
		t.Fatal("completed case owner survived into the next prefix")
	}
	if p.d.unchangedLocked(t.Context(), p.seal) != nil {
		t.Fatal("fresh next-case original opening unavailable")
	}
	ctx, scope, err := newAdmissionCaseScope(t.Context(), p.d, 2, p.seal, p.d.previous)
	if err != nil || ctx == nil || scope == nil {
		t.Fatal("old owner poisoned an independently opened next case")
	}
	defer scope.close()
	if scope.begin(ctx) != nil || scope.finish(nil) != nil {
		t.Fatal("fresh next-case owner refused its own serial context")
	}
	p.assertCustody(t)
}

func TestAdmissionCaseScopeStandalonePhaseKeepsSixFullConfigurationChecks(t *testing.T) {
	p, ctx, scope := testAdmissionCaseOwner(t)
	policies, bindings := p.policies, p.bindings
	if result, err := p.h.f.wire.observePhase(ctx); result == nil || err != nil || p.policies != policies+6 || p.bindings != bindings+6 {
		t.Fatal("ambient case context changed the standalone phase's six full configuration checks")
	}
	if scope.begin(ctx) != nil || scope.finish(nil) != nil {
		t.Fatal("standalone phase consumed another helper's case authority")
	}
	p.assertCustody(t)
}

func TestAdmissionCaseScopeStandaloneGCDoesNotRecognizeAmbientOwner(t *testing.T) {
	p, ctx, scope := testAdmissionCaseOwner(t)
	policies, bindings := p.policies, p.bindings
	if result, err := p.h.f.wire.gcMetadata(t.Context()); result == nil || err != nil {
		t.Fatal("default complete GC control unavailable")
	}
	wantPolicies, wantBindings := p.policies-policies, p.bindings-bindings
	policies, bindings = p.policies, p.bindings
	if result, err := p.h.f.wire.gcMetadata(ctx); result == nil || err != nil || wantPolicies == 0 || p.policies-policies != wantPolicies || p.bindings-bindings != wantBindings {
		t.Fatal("ambient case context reduced standalone GC's complete remote fences")
	}
	if scope.begin(ctx) != nil || scope.finish(nil) != nil {
		t.Fatal("standalone GC consumed case helper lease")
	}
	p.assertCustody(t)
}

func TestAdmissionCaseScopeClosedOwnerCannotCrossReload(t *testing.T) {
	p, ctx, scope := testAdmissionCaseOwner(t)
	if scope.close() != nil {
		t.Fatal("original unused owner did not revoke")
	}
	old := p.h.f.wire.ledger
	if old.close() != nil {
		t.Fatal("original fixture WAL did not release")
	}
	loaded, err := old.engine.loadFixtureLedger(t.Context(), p.originalJournal)
	if err != nil || loaded.driverFresh {
		t.Fatal("fixture reload reissued driver freshness")
	}
	t.Cleanup(func() { _ = loaded.close() })
	if _, err = loaded.loadOriginalWorlds(); err != nil {
		t.Fatal("same original world evidence unavailable after reload")
	}
	wire, err := p.h.f.wire.actors.fixtures(t.Context(), loaded)
	if err != nil {
		t.Fatal("full original wire reconstruction refused")
	}
	p.h.f.wire = wire
	p.d.wire = wire
	policies, bindings := p.policies, p.bindings
	if scope.begin(ctx) != ErrFixtures || scope.current(ctx) || p.d.unchangedCaseLocked(ctx, p.seal, scope) != ErrFixtures || p.policies != policies || p.bindings != bindings {
		t.Fatal("closed old owner authorized a rebuilt wire or replayed remote evidence")
	}
}

func TestAdmissionCaseScopeConcurrentEntryPoisonsAndJoins(t *testing.T) {
	_, ctx, scope := testAdmissionCaseOwner(t)
	if scope.begin(ctx) != nil {
		t.Fatal("original lease unavailable")
	}
	done := make(chan error, 1)
	go func() { done <- scope.begin(ctx) }()
	select {
	case err := <-done:
		if err != ErrFixtures {
			t.Fatal("overlapping helper entered")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("concurrent entry did not refuse")
	}
	closed := make(chan error, 1)
	go func() { closed <- scope.close() }()
	select {
	case <-closed:
		t.Fatal("close returned before outstanding helper joined")
	case <-time.After(100 * time.Millisecond):
	}
	if scope.finish(nil) != ErrFixtures {
		t.Fatal("overlap did not poison original helper")
	}
	select {
	case err := <-closed:
		if err != ErrFixtures {
			t.Fatal("poisoned close returned success")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("close failed to join completed helper")
	}
	if scope.current(ctx) || scope.begin(ctx) != ErrFixtures {
		t.Fatal("joined poisoned owner revived")
	}
}

func TestAdmissionCaseScopeCloseCancelsActiveHTTPBeforeReturning(t *testing.T) {
	p := testAdmissionCaseProtocolFixture(t, 17)
	parentCtx, parentCancel := context.WithCancel(t.Context())
	defer parentCancel()
	if p.d.unchangedLocked(parentCtx, p.seal) != nil {
		t.Fatal("case opening full original fence refused")
	}
	ctx, scope, err := newAdmissionCaseScope(parentCtx, p.d, p.number, p.seal, p.before)
	if err != nil || scope == nil {
		t.Fatal("original active HTTP case owner unavailable")
	}
	client := p.h.f.wire.actors.clients[destroyControllerActor]
	original := client.client.Transport
	entered := make(chan struct{})
	release := make(chan struct{})
	client.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Query().Get("dryRun") == "All" {
			close(entered)
			select {
			case <-r.Context().Done():
				return nil, r.Context().Err()
			case <-release:
				return nil, ErrRead // independent failure-cleanup escape
			}
		}
		return original.RoundTrip(r)
	})
	r, err := p.h.f.wire.admissionRequest(p.number, p.before)
	if err != nil {
		_ = scope.close()
		t.Fatal("fixed actor request unavailable")
	}
	policy := p.h.f.wire.actors.policies.policies[r.policy]
	binding := ""
	for name, b := range p.h.f.wire.actors.policies.bindings {
		if b.Spec.PolicyName == r.policy {
			binding = name
		}
	}
	done := make(chan error, 1)
	closed := make(chan error, 1)
	workerJoined, closerStarted, closerJoined := false, false, false
	var activeLease chan struct{}
	var workerErr, closeErr error
	startCloser := func() {
		if !closerStarted {
			closerStarted = true
			go func() { closed <- scope.close() }()
		}
	}
	// This owner deliberately has no generic forced-finish cleanup. On EVERY
	// failure path cancel the parent and release the independent transport gate,
	// then join BOTH actual goroutines before any fallback state cleanup. This
	// also unblocks a pre-fix close that waits but forgets to cancel its request.
	defer func() {
		parentCancel()
		close(release)
		if !workerJoined {
			select {
			case workerErr = <-done:
				workerJoined = true
			case <-time.After(5 * time.Second):
				t.Error("active HTTP worker failed cleanup join after parent cancellation and gate release")
			}
		}
		startCloser()
		if !closerJoined {
			select {
			case closeErr = <-closed:
				closerJoined = true
			case <-time.After(5 * time.Second):
				t.Error("active HTTP closer failed cleanup join after worker cancellation")
				if workerJoined {
					// Failure is already recorded and the actual HTTP helper has
					// returned. Repair ONLY the test's abandoned lease so a broken
					// finish cannot leak its waiting closer. Do not call finish:
					// that is the state transition whose regression is under test.
					scope.mu.Lock()
					abandoned := scope.busy
					scope.busy = nil
					for _, lease := range []chan struct{}{abandoned, activeLease} {
						if lease != nil {
							select {
							case <-lease:
							default:
								close(lease)
							}
						}
					}
					scope.mu.Unlock()
					select {
					case closeErr = <-closed:
						closerJoined = true
					case <-time.After(5 * time.Second):
						t.Error("active HTTP closer failed to join after test-only abandoned lease repair")
					}
				}
			}
		}
		if workerJoined && closerJoined {
			_ = scope.finish(ErrFixtures)
			_ = scope.close()
		}
	}()
	go func() {
		_, e := p.h.f.wire.actors.probeCase(ctx, r.actor, r.operation, r.object, r.policy, binding, policy.Spec.Validations[3].Message, scope)
		done <- e
	}()
	select {
	case <-entered:
		scope.mu.Lock()
		activeLease = scope.busy
		scope.mu.Unlock()
	case <-time.After(5 * time.Second):
		t.Error("leased helper did not reach blocked HTTP request")
		return
	}
	startCloser()
	select {
	case closeErr = <-closed:
		closerJoined = true
		if closeErr != ErrFixtures {
			t.Error("closing an in-flight helper claimed completed success")
		}
	case <-time.After(2 * time.Second):
		t.Error("close did not cancel and join active HTTP")
		return
	}
	select {
	case workerErr = <-done:
		workerJoined = true
		if workerErr == nil {
			t.Error("cancelled helper returned successful proof")
		}
	case <-time.After(2 * time.Second):
		t.Error("close returned before its HTTP worker joined")
		return
	}
	if scope.begin(ctx) != ErrFixtures {
		t.Fatal("cancelled HTTP helper owner replayed")
	}
	p.assertCustody(t)
}

func TestAdmissionCaseScopePanicPoisonsDriverAndRevokesLease(t *testing.T) {
	p := testAdmissionCaseProtocolFixture(t, 17)
	client := p.h.f.wire.actors.clients[destroyControllerActor]
	original := client.client.Transport
	sentinel := errors.New("TEST-ONLY-CASE-PANIC")
	var spent *admissionCaseScope
	var sentCtx context.Context
	client.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Query().Get("dryRun") == "All" {
			spent, _ = r.Context().Value(admissionCaseScopeKey{}).(*admissionCaseScope)
			sentCtx = r.Context()
			panic(sentinel)
		}
		return original.RoundTrip(r)
	})
	func() {
		defer func() {
			if recover() != sentinel {
				t.Fatal("case panic swallowed or replaced")
			}
		}()
		_ = p.run(t.Context())
	}()
	if spent == nil || !p.d.failed || p.d.next != 17 || p.d.completed != (uint64(1)<<17)-1 || spent.begin(sentCtx) != ErrFixtures || spent.current(sentCtx) {
		t.Fatal("panic retained case bit, driver authority or serial lease")
	}
	p.assertCustody(t)
}

func TestAdmissionCaseScopeGoexitPoisonsDriverAndReleasesLease(t *testing.T) {
	p := testAdmissionCaseProtocolFixture(t, 17)
	client := p.h.f.wire.actors.clients[destroyControllerActor]
	original := client.client.Transport
	var spent *admissionCaseScope
	var sentCtx context.Context
	client.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Query().Get("dryRun") == "All" {
			spent, _ = r.Context().Value(admissionCaseScopeKey{}).(*admissionCaseScope)
			sentCtx = r.Context()
			runtime.Goexit()
		}
		return original.RoundTrip(r)
	})
	done := make(chan struct{})
	go func() { defer close(done); _ = p.run(t.Context()) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Goexit did not unwind the exact case and wire lock")
	}
	if spent == nil || !p.d.failed || p.d.next != 17 || p.d.completed != (uint64(1)<<17)-1 || spent.begin(sentCtx) != ErrFixtures || spent.current(sentCtx) {
		t.Fatal("Goexit retained a case bit, driver authority or helper lease")
	}
	p.assertCustody(t)
}
