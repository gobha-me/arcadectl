// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/privatefs"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestFixtureTypedCollectionDiagnosticActualHTTPSRefusal(t *testing.T) {
	h := unmarkedRecoveryPhaseFactory(t)(t)
	f, ledger := h.f, h.f.wire.ledger
	before, identity := bytes.Clone(ledger.body), ledger.identity
	base := f.actor.fixtureHandler
	var requests, rejected atomic.Int32
	f.actor.fixtureHandler = func(w http.ResponseWriter, r *http.Request) bool {
		requests.Add(1)
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/gameservers") && r.URL.Query().Get("limit") == "128" && !strings.Contains(r.Header.Get("Accept"), "PartialObjectMetadata") {
			rejected.Add(1)
			w.Header().Set("Warning", "PRIVATE-token-canary")
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, "PRIVATE-token=canary world/save namespace")
			return true
		}
		return base(w, r)
	}
	// Compare the same real failure with and without instrumentation. Diagnostics
	// must not add requests, repair a refusal, or advance an accepted floor.
	if observation, err := f.wire.observePhase(t.Context()); observation != nil || err != ErrFixtures {
		t.Fatal("control typed LIST refusal unavailable", err)
	}
	wantRequests := requests.Load()
	requests.Store(0)
	ctx, diagnostic := WithLifecycleDiagnostic(t.Context())
	if observation, err := f.wire.observePhase(ctx); observation != nil || err != ErrFixtures {
		t.Fatal("instrumentation changed typed LIST refusal", err)
	}
	want := "stage=collection reason=refused state=active observer-stage=list-pages observer-collection=GameServer observer-reason=read observer-pages=fetch-unclassified observer-inner=active observer-caller=active"
	if diagnostic.TypedCollectionSnapshot() != want || rejected.Load() != 2 || requests.Load() != wantRequests {
		t.Fatal("typed refusal diagnostic or request census changed", diagnostic.TypedCollectionSnapshot(), rejected.Load(), requests.Load(), wantRequests)
	}
	phaseBarrierUnchanged(t, h, before, identity)
	if ledger.phaseFloor != nil {
		t.Fatal("failed typed read published a floor")
	}
}

func TestFixtureTypedCollectionDiagnosticHTTPChildDeadlineOuterActive(t *testing.T) {
	h := unmarkedRecoveryPhaseFactory(t)(t)
	f, ledger := h.f, h.f.wire.ledger
	before, identity := bytes.Clone(ledger.body), ledger.identity
	base := f.actor.fixtureHandler
	release, joined := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	releaseHandler := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseHandler)
	var rejected atomic.Int32
	f.actor.fixtureHandler = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/gameservers") && r.URL.Query().Get("limit") == "128" && !strings.Contains(r.Header.Get("Accept"), "PartialObjectMetadata") {
			if rejected.Add(1) != 1 {
				w.WriteHeader(http.StatusForbidden)
				return true
			}
			defer close(joined)
			select {
			case <-r.Context().Done():
			case <-release:
			}
			return true
		}
		return base(w, r)
	}
	outer, diagnostic := WithLifecycleDiagnostic(t.Context())
	// This independently shorter caller child demonstrates context distinction;
	// it does not claim to reproduce the native90s settlement failure.
	child, cancel := context.WithTimeout(outer, 5*time.Second)
	defer cancel()
	observation, err := f.wire.observePhase(child)
	releaseHandler()
	if rejected.Load() != 0 {
		select {
		case <-joined:
		case <-time.After(5 * time.Second):
			t.Error("deadline HTTP handler did not join")
		}
	}
	if observation != nil || err != ErrFixtures || rejected.Load() != 1 || outer.Err() != nil || child.Err() != context.DeadlineExceeded {
		t.Fatal("HTTP child deadline did not preserve active outer/refusal", err, rejected.Load(), outer.Err(), child.Err())
	}
	want := "stage=collection reason=refused state=deadline observer-stage=list-pages observer-collection=GameServer observer-reason=read observer-pages=fetch-unclassified observer-inner=deadline observer-caller=deadline"
	if diagnostic.TypedCollectionSnapshot() != want {
		t.Fatal("child deadline was confused with active outer or deferred cancel", diagnostic.TypedCollectionSnapshot())
	}
	phaseBarrierUnchanged(t, h, before, identity)
}

func TestFixtureAdmissionSettleRefusalNeverRetriesAcknowledgedCreate(t *testing.T) {
	h := fixtureV3PhaseFactory(t)(t)
	f, ledger := h.f, h.f.wire.ledger
	before, err := f.wire.observePhase(t.Context())
	if err != nil || before == nil {
		t.Fatal("sealed original setup phase unavailable", err)
	}
	// The factory has already sealed original world/account evidence. The
	// driver consumes this actual complete initial phase, not synthetic case bits.
	driver := &fixtureAdmissionDriver{wire: f.wire, initial: &initialAdmissionPhase{journal: f.actor.request.Snapshot, baseline: before.phase}}
	created := time.Now().UTC().Truncate(time.Second).Add(-20 * time.Second)
	var acknowledged atomic.Bool
	f.reply = func(w http.ResponseWriter, object *unstructured.Unstructured) {
		if ledger.document.Entries[11].State == fixturePlanned {
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(object.Object)
			return
		}
		ack := fixtureResultExample(t, ledger, 11, fixtureAcknowledgedResult, created)
		ack.SetUID(object.GetUID())
		stable := fixtureResultExample(t, ledger, 11, fixtureStableResult, created)
		stable.SetUID(object.GetUID())
		f.objects[11] = stable
		acknowledged.Store(true)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(ack.Object)
	}
	outer, diagnostic := WithLifecycleDiagnostic(t.Context())
	child, cancel := context.WithCancel(outer)
	defer cancel()
	base := f.actor.fixtureHandler
	var afterACK []byte
	var afterACKIdentity privatefs.FileIdentity
	var afterACKMu sync.Mutex
	var rejected atomic.Int32
	f.actor.fixtureHandler = func(w http.ResponseWriter, r *http.Request) bool {
		if acknowledged.Load() && r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/gameservers") && r.URL.Query().Get("limit") == "128" && !strings.Contains(r.Header.Get("Accept"), "PartialObjectMetadata") {
			rejected.Add(1)
			afterACKMu.Lock()
			afterACK, afterACKIdentity = bytes.Clone(ledger.body), ledger.identity
			afterACKMu.Unlock()
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, "PRIVATE-token=canary")
			// Explicit caller cancellation ends the observation-only settlement
			// wait promptly. It does not alter the production90s child budget or
			// claim to reproduce the native failure's unknown cause.
			cancel()
			return true
		}
		return base(w, r)
	}
	if err := driver.run(child); err != ErrFixtures || !driver.failed || driver.completed != 0 || driver.next != 0 || outer.Err() != nil {
		t.Fatal("setup refusal retained driver authority or cancelled outer", err)
	}
	afterACKMu.Lock()
	ackBody, ackIdentity := bytes.Clone(afterACK), afterACKIdentity
	afterACKMu.Unlock()
	if rejected.Load() != 1 || f.previews != 1 || f.creates != 1 || f.deletes != 0 || f.seeds != 0 || len(f.objects) != 1 || ledger.document.Entries[11].State != fixtureOriginal || ledger.document.Entries[11].OriginalUID == "" {
		t.Fatal("setup refusal retried/adopted CREATE or sent dependent work", rejected.Load(), f.previews, f.creates, f.deletes, f.seeds)
	}
	for slot, entry := range ledger.document.Entries {
		if slot != 11 && entry.State != fixturePlanned {
			t.Fatal("dependent setup acquired durable intent after refusal", slot)
		}
	}
	if len(ackBody) == 0 || !bytes.Equal(ackBody, ledger.body) || ackIdentity != ledger.identity || ledger.behaviorCompletion != nil || ledger.effectSlot != -1 || ledger.ackSlot != -1 {
		t.Fatal("settlement refusal changed acknowledged WAL or gained effect authority")
	}
	journal, err := ledger.engine.journal.Load(outer, f.actor.request.Snapshot.Anchor())
	if err != nil || !journal.SameJournalBytes(f.actor.request.Snapshot) || journal.ResourceVersion() != f.actor.request.Snapshot.ResourceVersion() {
		t.Fatal("setup diagnostic changed original journal")
	}
	if got := diagnostic.TypedCollectionSnapshot(); !strings.Contains(got, "stage=collection reason=refused") || !strings.Contains(got, "observer-stage=list-pages observer-collection=GameServer observer-reason=read") || strings.Contains(got, "PRIVATE") {
		t.Fatal("real setup refusal lost typed diagnostic", got)
	}
	if got := diagnostic.AdmissionSettleSnapshot(); !strings.HasPrefix(got, "attempts=1 ") || !strings.HasSuffix(got, "state=cancelled caller=cancelled outcome=refused") {
		t.Fatal("setup wait did not capture its actual child state", got)
	}
	writes := f.creates
	if driver.run(outer) != ErrFixtures || f.creates != writes || !bytes.Equal(ackBody, ledger.body) {
		t.Fatal("failed driver replayed acknowledged setup")
	}
}

func TestFixtureTypedCollectionDiagnosticProtectedWALRefusal(t *testing.T) {
	h := unmarkedRecoveryPhaseFactory(t)(t)
	f, ledger := h.f, h.f.wire.ledger
	before, identity := bytes.Clone(ledger.body), ledger.identity
	base := f.actor.fixtureHandler
	ctx, diagnostic := WithLifecycleDiagnostic(t.Context())
	var replaced atomic.Bool
	f.actor.fixtureHandler = func(w http.ResponseWriter, r *http.Request) bool {
		handled := base(w, r)
		// Complete the actual observer's last typed collection before replacing
		// the protected WAL with identical bytes and a new inode. Remote evidence
		// remains valid; only the existing following local closure must refuse.
		if !replaced.Load() && r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/endpointslices") && r.URL.Query().Get("limit") == "128" && !strings.Contains(r.Header.Get("Accept"), "PartialObjectMetadata") {
			if _, err := ledger.engine.files.AtomicWrite(ledger.name, before, &identity); err != nil {
				t.Error("same-byte WAL replacement unavailable")
			}
			replaced.Store(true)
		}
		return handled
	}
	if observation, err := f.wire.observePhase(ctx); observation != nil || err != ErrFixtures || !replaced.Load() {
		t.Fatal("typed local closure accepted replaced WAL", err)
	}
	want := "stage=local-closing reason=local-current state=active observer-stage=complete observer-collection=unknown observer-reason=complete observer-pages=unknown observer-inner=active observer-caller=active"
	if diagnostic.TypedCollectionSnapshot() != want {
		t.Fatal("local refusal overwrote or concealed complete remote observation", diagnostic.TypedCollectionSnapshot())
	}
	phaseBarrierUnchanged(t, h, before, identity)
}

func TestFixtureObservationDiagnosticAttemptIsolationAndReset(t *testing.T) {
	ctx, diagnostic := WithLifecycleDiagnostic(t.Context())
	old := beginTypedCollectionDiagnostic(ctx)
	traceTypedCollection(old, typedCollectionObserve, 1)
	oldSettle := beginAdmissionSettleDiagnostic(ctx)
	current := beginTypedCollectionDiagnostic(ctx)
	traceTypedCollection(current, typedCollectionComplete, 2)
	currentSettle := beginAdmissionSettleDiagnostic(ctx)
	currentSettle(1, 7*time.Nanosecond, ctx, ctx, true)
	want := diagnostic.TypedCollectionSnapshot()
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		for range 100 {
			finishTypedCollection(old, true)
			oldSettle(99, time.Hour, ctx, ctx, false)
		}
	}()
	go func() {
		defer workers.Done()
		for range 100 {
			if diagnostic.TypedCollectionSnapshot() != want || diagnostic.AdmissionSettleSnapshot() != "attempts=1 elapsed-ns=7 state=active caller=active outcome=settled" {
				t.Error("late completion contaminated the latest attempt")
			}
		}
	}()
	workers.Wait()
	traceLifecycleCheckpoint(ctx, AdmissionEffective, lifecycleDiagnosticEntered)
	finishTypedCollection(old, true)
	oldSettle(99, time.Hour, ctx, ctx, false)
	if diagnostic.TypedCollectionSnapshot() != "" || diagnostic.AdmissionSettleSnapshot() != "" {
		t.Fatal("late completion republished diagnostics after checkpoint reset")
	}
	freshCtx, fresh := WithLifecycleDiagnostic(ctx)
	traceTypedCollection(beginTypedCollectionDiagnostic(freshCtx), typedCollectionStage(255), 255)
	if got := fresh.TypedCollectionSnapshot(); !strings.HasPrefix(got, "stage=unknown reason=unknown state=active observer-stage=unknown") || strings.Contains(got, "PRIVATE") || diagnostic.TypedCollectionSnapshot() != "" {
		t.Fatal("unknown labels or another attempt entered output", got)
	}
}

func TestFixtureAdmissionSettleDiagnosticActualPollAndAbnormalExit(t *testing.T) {
	for _, outcome := range []string{"settled", "refused", "deadline", "cancelled", "panic", "goexit"} {
		t.Run(outcome, func(t *testing.T) {
			outer, diagnostic := WithLifecycleDiagnostic(t.Context())
			ctx := outer
			cancelCaller := func() {}
			if outcome == "deadline" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(outer, 20*time.Millisecond)
				defer cancel()
			}
			if outcome == "cancelled" {
				ctx, cancelCaller = context.WithCancel(outer)
				defer cancelCaller()
			}
			calls := 0
			condition := func(child context.Context) (bool, error) {
				calls++
				switch outcome {
				case "settled":
					return true, nil
				case "deadline":
					<-child.Done()
					return false, nil
				case "cancelled":
					cancelCaller()
					return false, nil
				case "panic":
					panic("PRIVATE-token=canary")
				case "goexit":
					runtime.Goexit()
				}
				return false, ErrFixtures
			}
			if outcome == "panic" {
				func() {
					defer func() {
						if recover() == nil {
							t.Error("poll swallowed panic")
						}
					}()
					_ = pollFixtureAdmissionSettle(ctx, condition)
				}()
			} else if outcome == "goexit" {
				joined := make(chan struct{})
				go func() { defer close(joined); _ = pollFixtureAdmissionSettle(ctx, condition) }()
				select {
				case <-joined:
				case <-time.After(5 * time.Second):
					t.Fatal("Goexit poll did not join")
				}
			} else {
				err := pollFixtureAdmissionSettle(ctx, condition)
				if (err == nil) != (outcome == "settled") {
					t.Fatal("diagnostics changed poll outcome", err)
				}
			}
			var attempts uint32
			var elapsed int64
			var state, caller, result string
			got := diagnostic.AdmissionSettleSnapshot()
			if n, err := fmt.Sscanf(got, "attempts=%d elapsed-ns=%d state=%s caller=%s outcome=%s", &attempts, &elapsed, &state, &caller, &result); err != nil || n != 5 || attempts != 1 || calls != 1 || elapsed < 0 || outer.Err() != nil {
				t.Fatal("poll lost bounded same-attempt measurements", got)
			}
			wantState, wantResult := "active", "refused"
			if outcome == "settled" {
				wantResult = "settled"
			}
			if outcome == "deadline" {
				wantState = "deadline"
			}
			if outcome == "cancelled" {
				wantState = "cancelled"
			}
			if state != wantState || caller != wantState || result != wantResult {
				t.Fatal("poll sampled after deferred cancel or accepted abnormal exit", got)
			}
		})
	}
}

func TestFixtureAdmissionSettleDiagnosticOwnedChildVersusImmediateCaller(t *testing.T) {
	outer := t.Context()
	caller, diagnostic := WithLifecycleDiagnostic(outer)
	finish := beginAdmissionSettleDiagnostic(caller)
	// Exercise the recorder with a genuinely owned shorter child. This is a
	// state-capture test, not an execution of the production90s deadline or a
	// reproduction of the unexplained native failure.
	child, cancelChild := context.WithTimeout(caller, time.Millisecond)
	defer cancelChild()
	<-child.Done()
	finish(3, 11*time.Nanosecond, child, caller, false)
	want := "attempts=3 elapsed-ns=11 state=deadline caller=active outcome=refused"
	if diagnostic.AdmissionSettleSnapshot() != want || caller.Err() != nil || outer.Err() != nil {
		t.Fatal("owned child expiry was attributed to its active immediate caller", diagnostic.AdmissionSettleSnapshot())
	}
	caller, cancelCaller := context.WithCancel(caller)
	finish = beginAdmissionSettleDiagnostic(caller)
	child, cancelChild2 := context.WithTimeout(caller, time.Minute)
	defer cancelChild2()
	cancelCaller()
	<-child.Done()
	finish(1, -time.Second, child, caller, false)
	if got := diagnostic.AdmissionSettleSnapshot(); got != "attempts=1 elapsed-ns=0 state=cancelled caller=cancelled outcome=refused" || outer.Err() != nil {
		t.Fatal("immediate caller cancellation or bounded elapsed projection was lost", got)
	}
	// Snapshot holds values, not contexts: later cancellation of a previously
	// sampled active caller cannot rewrite that earlier diagnostic.
	independentCaller, independentCancel := context.WithCancel(outer)
	defer independentCancel()
	independentCtx, independent := WithLifecycleDiagnostic(independentCaller)
	independentFinish := beginAdmissionSettleDiagnostic(independentCtx)
	independentFinish(1, time.Nanosecond, independentCtx, independentCaller, true)
	independentCancel()
	if got := independent.AdmissionSettleSnapshot(); got != "attempts=1 elapsed-ns=1 state=active caller=active outcome=settled" {
		t.Fatal("post-return cancellation changed recorded context states", got)
	}
}
