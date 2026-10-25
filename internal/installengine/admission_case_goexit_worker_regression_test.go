// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"net/http"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestAdmissionCaseGoexitWaitDelayedOpeningRetainsWholeCase(t *testing.T) {
	p := testAdmissionCaseProtocolFixture(t, 17)
	parentCtx, parentCancel := context.WithCancel(t.Context())
	parent := p.h.f.wire.actors.admission.prerequisites.access
	actor := p.h.f.wire.actors.clients[destroyControllerActor]
	parentTransport, actorTransport := parent.client.Transport, actor.client.Transport
	openingEntered, releaseOpening, injected := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseOpening) }) }
	var blocked, premature, wrongDuration, workerExited atomic.Bool
	var timerCalls atomic.Int32
	var spent *admissionCaseScope
	var sentCtx, workerCtx context.Context
	type outcome struct {
		complete bool
		cancel   context.CancelFunc
	}
	done := make(chan outcome, 1)
	joined := false
	var result outcome
	// Register before launching either goroutine. Release/cancel and join the
	// real helper (which joins the actual p.run worker) BEFORE fixture teardown
	// or restoring any transport. Never force-finish an in-flight scope.
	defer func() {
		parentCancel()
		release()
		if !joined {
			result = <-done
			joined = true
		}
		if result.cancel != nil {
			result.cancel()
		}
		parent.client.Transport, actor.client.Transport = parentTransport, actorTransport
	}()
	parent.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodGet && r.URL.Path == p.accessPath && blocked.CompareAndSwap(false, true) {
			close(openingEntered)
			select {
			case <-releaseOpening:
			case <-r.Context().Done():
				return nil, r.Context().Err()
			}
		}
		return parentTransport.RoundTrip(r)
	})
	actor.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Query().Get("dryRun") == "All" {
			spent, _ = r.Context().Value(admissionCaseScopeKey{}).(*admissionCaseScope)
			sentCtx = r.Context()
			close(injected)
			runtime.Goexit()
		}
		return actorTransport.RoundTrip(r)
	})
	expired := make(chan time.Time)
	close(expired)
	after := func(duration time.Duration) <-chan time.Time {
		timerCalls.Add(1)
		if duration != 5*time.Second {
			wrongDuration.Store(true)
			return expired
		}
		select {
		case <-injected:
			return time.After(duration) // preserve the REAL five-second unwind bound
		default:
			premature.Store(true)
			return expired // deterministic refusal if opening arms the unwind timer
		}
	}
	go func() {
		ok, cancel := testAdmissionCaseGoexitWorker(parentCtx, injected, func(ctx context.Context) error {
			workerCtx = ctx
			defer workerExited.Store(true)
			return p.run(ctx) // keep the complete original case and wire lock
		}, after)
		done <- outcome{ok, cancel}
	}()
	select {
	case <-openingEntered:
	case result = <-done:
		joined = true
		if premature.Load() {
			t.Fatal("Goexit unwind timer was armed before actual transport injection")
		}
		t.Fatal("actual whole case failed before its controlled opening GET")
	case <-parentCtx.Done():
		t.Fatal("caller ended before the controlled whole-case opening")
	}
	// Hold an ACTUAL opening GET for exactly the old erroneous unwind budget.
	// This is below the unchanged 30s HTTP request and 5m phase limits. No
	// deadline is increased, no source opening/read is skipped, and no >5s sleep
	// is used. A launch-start timer's fake expiry fails while this gate is shut.
	hold := time.NewTimer(5 * time.Second)
	defer hold.Stop()
	select {
	case result = <-done:
		joined = true
		if premature.Load() {
			t.Fatal("Goexit unwind timer consumed controlled opening latency")
		}
		t.Fatal("whole-case worker returned while its original GET remained gated")
	case <-hold.C:
		if timerCalls.Load() != 0 {
			t.Fatal("Goexit unwind timer was created during original opening reads")
		}
		release()
	case <-parentCtx.Done():
		t.Fatal("caller ended during the controlled opening interval")
	}
	select {
	case result = <-done:
		joined = true
	case <-parentCtx.Done():
		t.Fatal("caller ended before the actual Goexit worker joined")
	}
	defer result.cancel()
	if !result.complete || !workerExited.Load() || workerCtx == nil || workerCtx.Err() != nil || parentCtx.Err() != nil || premature.Load() || wrongDuration.Load() || timerCalls.Load() != 1 {
		t.Fatal("actual joined Goexit changed timer, completion or active-parent ownership")
	}
	if spent == nil {
		t.Fatal("delayed whole-case Goexit did not capture its actual scope")
	}
	// Check the original revocation state before a deliberate rejected replay:
	// begin may itself poison a refused scope and must not create this evidence.
	spent.mu.Lock()
	revoked := spent.closed && spent.poisoned && spent.busy == nil
	spent.mu.Unlock()
	if !revoked || !p.h.f.wire.ledger.wireMu.TryLock() {
		t.Fatal("actual Goexit failed to revoke its scope or release the wire lock")
	}
	p.h.f.wire.ledger.wireMu.Unlock()
	if !p.d.failed || p.d.next != 17 || p.d.completed != (uint64(1)<<17)-1 || spent.begin(sentCtx) != ErrFixtures || spent.current(sentCtx) {
		t.Fatal("delayed whole-case Goexit retained bit, driver authority or lease")
	}
	// All counts are sampled AFTER the real worker joins and under the existing
	// responder mutex. Injection happens before the dry-run reaches the server:
	// one complete opening phase (6 configuration/9 access), one full opening
	// fence (1/1), and the driver+actor exact SSARs must still execute.
	p.h.f.actor.withState(func() {
		if p.policies != 7 || p.bindings != 7 || p.accessGets != 10 || p.exactReviews != 2 || p.probes != 0 || p.postPhaseLists != 0 || p.persistent != 0 {
			t.Error("delayed Goexit changed the independent opening/request census")
		}
	})
	p.assertCustody(t)
}

func TestAdmissionCaseGoexitWaitSuccessTransfersActiveCancel(t *testing.T) {
	injected := make(chan struct{})
	var workerCtx context.Context
	var exited, wrongTimer atomic.Bool
	never := make(chan time.Time)
	complete, cancel := testAdmissionCaseGoexitWorker(t.Context(), injected, func(ctx context.Context) error {
		workerCtx = ctx
		defer exited.Store(true)
		close(injected)
		runtime.Goexit()
		return nil
	}, func(duration time.Duration) <-chan time.Time {
		if duration != 5*time.Second {
			wrongTimer.Store(true)
		}
		return never
	})
	defer cancel()
	if !complete || !exited.Load() || wrongTimer.Load() || workerCtx == nil || workerCtx.Err() != nil || t.Context().Err() != nil {
		t.Fatal("successful joined Goexit cancelled its parent before caller postconditions")
	}
	cancel()
	if workerCtx.Err() != context.Canceled || t.Context().Err() != nil {
		t.Fatal("owned explicit cancellation failed or cancelled the caller")
	}
	cancel() // transferred ownership remains idempotent
}

func TestAdmissionCaseGoexitWaitFailureCancelsAndJoins(t *testing.T) {
	for _, mode := range []string{"opening-cancel", "unwind-cancel", "unwind-timeout"} {
		t.Run(mode, func(t *testing.T) {
			parent, parentCancel := context.WithCancel(t.Context())
			injected, ready, cancelled, exited, releaseExit := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
			timerArmed, expire := make(chan struct{}), make(chan time.Time)
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(releaseExit) }) }
			var order, exitOrder, returnOrder atomic.Uint32
			var wrongTimer, cancellationObserved atomic.Bool
			type outcome struct {
				complete bool
				cancel   context.CancelFunc
			}
			done := make(chan outcome, 1)
			joined := false
			var result outcome
			defer func() {
				parentCancel()
				release()
				if !joined {
					result = <-done
				}
				<-exited // also join an intentionally broken helper's leaked worker
				if result.cancel != nil {
					result.cancel()
				}
			}()
			go func() {
				ok, cancel := testAdmissionCaseGoexitWorker(parent, injected, func(ctx context.Context) error {
					defer func() { exitOrder.Store(order.Add(1)); close(exited) }()
					if mode != "opening-cancel" {
						close(injected)
					}
					close(ready)
					<-ctx.Done()
					cancellationObserved.Store(ctx.Err() == context.Canceled)
					close(cancelled)
					<-releaseExit // cancellation alone must not count as a joined worker
					return ErrFixtures
				}, func(duration time.Duration) <-chan time.Time {
					if duration != 5*time.Second {
						wrongTimer.Store(true)
					}
					close(timerArmed)
					return expire
				})
				returnOrder.Store(order.Add(1))
				done <- outcome{ok, cancel}
			}()
			<-ready
			if mode != "opening-cancel" {
				<-timerArmed
			}
			if mode == "unwind-timeout" {
				close(expire)
			} else {
				parentCancel()
			}
			select {
			case <-cancelled:
			case <-time.After(5 * time.Second):
				t.Fatal("failure path did not cancel the actual worker")
			}
			// Give the failed helper a chance to return while actual worker exit
			// is still independently withheld. A correct helper cannot return.
			probe := time.NewTimer(100 * time.Millisecond)
			select {
			case result = <-done:
				joined = true
				t.Error("failed Goexit helper returned before actual worker exit")
			case <-probe.C:
			}
			probe.Stop()
			release()
			if !joined {
				result = <-done
				joined = true
			}
			<-exited
			if result.complete || wrongTimer.Load() || !cancellationObserved.Load() || exitOrder.Load() == 0 || returnOrder.Load() <= exitOrder.Load() {
				t.Fatal("failure path changed five-second bound or cancel/worker-exit/return order")
			}
			if mode == "unwind-timeout" && parent.Err() != nil {
				t.Fatal("owned unwind timeout cancelled the independent caller")
			}
		})
	}
}
