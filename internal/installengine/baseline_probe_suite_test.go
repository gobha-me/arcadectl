// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installstate"
)

// These owners contain no clients or transports. The tests exercise only the
// invocation capsule; they cannot establish baseline or mutation authority.
func testBaselineProbeSuiteActors() *baselineActors {
	return &baselineActors{baseline: &ClusterSecurityBaseline{}, snapshot: &installstate.Snapshot{}}
}

func testBaselineProbeSuite(t *testing.T) (context.Context, *baselineProbeSuite, *baselineActors) {
	t.Helper()
	actors := testBaselineProbeSuiteActors()
	ctx, suite, err := newBaselineProbeSuite(t.Context(), actors)
	if err != nil || ctx == nil || suite == nil {
		t.Fatal("local suite owner unavailable")
	}
	t.Cleanup(func() {
		// A failing assertion must not leave close waiting for the test's lease.
		_ = suite.finish(errors.New("test cleanup"))
		_ = suite.close()
	})
	return ctx, suite, actors
}

func TestBaselineProbeSuiteConstructorRejectsIncompleteOrNestedOwner(t *testing.T) {
	for _, mode := range []string{"nil-context", "canceled", "expired", "nil-actors", "nil-baseline", "nil-snapshot", "nested", "malformed-nested"} {
		t.Run(mode, func(t *testing.T) {
			ctx, actors := t.Context(), testBaselineProbeSuiteActors()
			switch mode {
			case "nil-context":
				ctx = nil
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "expired":
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadline(ctx, time.Now().Add(-time.Second))
				defer cancel()
			case "nil-actors":
				actors = nil
			case "nil-baseline":
				actors.baseline = nil
			case "nil-snapshot":
				actors.snapshot = nil
			case "nested":
				var outer *baselineProbeSuite
				var err error
				ctx, outer, err = newBaselineProbeSuite(ctx, actors)
				if err != nil {
					t.Fatal("outer local owner unavailable")
				}
				defer outer.close()
			case "malformed-nested":
				ctx = context.WithValue(ctx, baselineProbeSuiteKey{}, true)
			}
			child, suite, err := newBaselineProbeSuite(ctx, actors)
			if err == nil || child != nil || suite != nil {
				t.Fatal("incomplete or nested owner acquired suite authority")
			}
		})
	}
}

func TestBaselineProbeSuiteSerialLeasesAndIdempotentClose(t *testing.T) {
	ctx, suite, actors := testBaselineProbeSuite(t)
	if suite.current(ctx, actors) {
		t.Fatal("idle suite claimed an active probe")
	}
	for range 2 {
		// Entry diagnostics preserve the invocation's cancellation identity.
		entry := context.WithValue(ctx, struct{ label string }{"diagnostic"}, true)
		if suite.begin(entry, actors) != nil || !suite.current(entry, actors) {
			t.Fatal("fresh serial lease refused its diagnostic context")
		}
		// The probe's shorter deadline is introduced after acquiring its lease.
		child, cancel := context.WithTimeout(entry, time.Minute)
		if !suite.current(child, actors) {
			cancel()
			t.Fatal("active lease refused its probe deadline context")
		}
		if suite.finish(nil) != nil || suite.current(child, actors) {
			cancel()
			t.Fatal("successful lease remained active or poisoned its owner")
		}
		cancel()
	}
	if suite.close() != nil || suite.close() != nil || ctx.Err() == nil {
		t.Fatal("clean close was not idempotent or did not cancel its child")
	}
	if suite.current(ctx, actors) || suite.begin(ctx, actors) == nil {
		t.Fatal("revoked invocation acquired another lease")
	}
}

func TestBaselineProbeSuiteRejectsChangedBindingsAndCrossInvocationContexts(t *testing.T) {
	for _, mode := range []string{"nil-context", "unscoped", "malformed-context", "other-suite-context", "copied-private-value", "without-cancel", "live-cancel-derived", "live-timeout-derived", "nil-actors", "other-actors", "changed-baseline", "changed-snapshot", "canceled-derived"} {
		t.Run(mode, func(t *testing.T) {
			ctx, suite, actors := testBaselineProbeSuite(t)
			candidateCtx, candidateActors := ctx, actors
			switch mode {
			case "nil-context":
				candidateCtx = nil
			case "unscoped":
				candidateCtx = t.Context()
			case "malformed-context":
				candidateCtx = context.WithValue(ctx, baselineProbeSuiteKey{}, true)
			case "other-suite-context":
				otherCtx, other, err := newBaselineProbeSuite(t.Context(), actors)
				if err != nil {
					t.Fatal("second invocation unavailable")
				}
				defer other.close()
				candidateCtx = otherCtx
			case "copied-private-value":
				candidateCtx = context.WithValue(t.Context(), baselineProbeSuiteKey{}, suite)
			case "without-cancel":
				candidateCtx = context.WithoutCancel(ctx)
			case "live-cancel-derived":
				var cancel context.CancelFunc
				candidateCtx, cancel = context.WithCancel(ctx)
				defer cancel()
			case "live-timeout-derived":
				var cancel context.CancelFunc
				candidateCtx, cancel = context.WithTimeout(ctx, time.Minute)
				defer cancel()
			case "nil-actors":
				candidateActors = nil
			case "other-actors":
				copyActors := *actors
				candidateActors = &copyActors
			case "changed-baseline":
				actors.baseline = &ClusterSecurityBaseline{}
			case "changed-snapshot":
				actors.snapshot = &installstate.Snapshot{}
			case "canceled-derived":
				var cancel context.CancelFunc
				candidateCtx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if suite.begin(candidateCtx, candidateActors) == nil || suite.current(ctx, actors) || ctx.Err() == nil {
				t.Fatal("changed binding acquired a lease or failed to revoke its owner")
			}
			if suite.begin(ctx, actors) == nil || suite.close() == nil {
				t.Fatal("refused binding became reusable or closed successfully")
			}
		})
	}
}

func TestBaselineProbeSuiteConcurrentBeginPoisonsOutstandingLease(t *testing.T) {
	ctx, suite, actors := testBaselineProbeSuite(t)
	if suite.begin(ctx, actors) != nil {
		t.Fatal("first lease unavailable")
	}
	refused := make(chan error, 1)
	go func() { refused <- suite.begin(ctx, actors) }()
	select {
	case err := <-refused:
		if err == nil {
			t.Fatal("concurrent probe acquired a second lease")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("concurrent begin blocked instead of refusing")
	}
	if suite.current(ctx, actors) || ctx.Err() == nil || suite.finish(nil) == nil || suite.close() == nil {
		t.Fatal("concurrent refusal did not poison and cancel the outstanding lease")
	}
}

func TestBaselineProbeSuiteCloseRevokesAndJoinsUntilFinish(t *testing.T) {
	ctx, suite, actors := testBaselineProbeSuite(t)
	if suite.begin(ctx, actors) != nil {
		t.Fatal("first lease unavailable")
	}
	closed := make(chan error, 1)
	go func() { closed <- suite.close() }()
	// Cancellation is the close operation's observable revocation point. It
	// happens before waiting for the lease, without timing-dependent sleeps.
	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("close failed to revoke its active child")
	}
	if suite.current(ctx, actors) {
		t.Fatal("closing owner still supplied probe authority")
	}
	select {
	case <-closed:
		t.Fatal("close returned before the outstanding lease finished")
	default:
	}
	if suite.finish(nil) == nil {
		t.Fatal("revoked outstanding lease reported success")
	}
	select {
	case err := <-closed:
		if err == nil {
			t.Fatal("close of an outstanding probe reported success")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("close did not join the finished lease")
	}
}

func TestBaselineProbeSuiteFailureAndCanceledOwnerRemainPoisoned(t *testing.T) {
	for _, mode := range []string{"probe-error", "owner-canceled-idle", "owner-canceled-active", "finish-without-lease"} {
		t.Run(mode, func(t *testing.T) {
			owner, cancel := context.WithCancel(t.Context())
			defer cancel()
			actors := testBaselineProbeSuiteActors()
			ctx, suite, err := newBaselineProbeSuite(owner, actors)
			if err != nil {
				t.Fatal("local owner unavailable")
			}
			defer func() {
				_ = suite.finish(errors.New("test cleanup"))
				_ = suite.close()
			}()
			if mode == "owner-canceled-idle" {
				cancel()
				// Detaching cancellation cannot revive a canceled owner.
				if suite.begin(context.WithoutCancel(ctx), actors) == nil {
					t.Fatal("detached context revived canceled owner")
				}
			} else if mode == "finish-without-lease" {
				if suite.finish(nil) == nil {
					t.Fatal("finish fabricated a successful lease")
				}
			} else {
				if suite.begin(ctx, actors) != nil {
					t.Fatal("first lease unavailable")
				}
				var probeErr error
				if mode == "probe-error" {
					probeErr = errors.New("synthetic probe refusal")
				} else {
					cancel()
				}
				if suite.finish(probeErr) == nil {
					t.Fatal("failed or canceled lease reported success")
				}
			}
			if suite.current(ctx, actors) || suite.begin(ctx, actors) == nil || suite.close() == nil {
				t.Fatal("poisoned invocation became reusable or closed successfully")
			}
		})
	}
}

func TestBaselineProbeSuiteNilOwnerAndBehaviorRejectMissingCapability(t *testing.T) {
	var suite *baselineProbeSuite
	actors := testBaselineProbeSuiteActors()
	if suite.begin(t.Context(), actors) == nil || suite.current(t.Context(), actors) || suite.close() == nil {
		t.Fatal("nil suite supplied authority")
	}
	behavior := &baselineBehavior{actors: actors}
	for _, ctx := range []context.Context{nil, t.Context(), context.WithValue(t.Context(), baselineProbeSuiteKey{}, true), context.WithValue(t.Context(), baselineProbeSuiteKey{}, (*baselineProbeSuite)(nil))} {
		if result, err := behavior.probe(ctx, ordinaryControllerActor, probeCreateOperation, nil, "", "", ""); err == nil || result != nil {
			t.Fatal("behavior accepted absent or malformed suite authority")
		}
	}
}

func TestBaselineProbeSuiteInvalidCandidatePoisonsBeforeAnyTransport(t *testing.T) {
	ctx, suite, actors := testBaselineProbeSuite(t)
	behavior := &baselineBehavior{actors: actors}
	// These owners have no transport. A local candidate refusal must still
	// revoke the capsule rather than leave a reusable narrowed probe scope.
	if result, err := behavior.probe(ctx, ordinaryControllerActor, probeCreateOperation, nil, "", "", ""); err != ErrInvalid || result != nil {
		t.Fatal("invalid candidate changed its local refusal")
	}
	if suite.begin(ctx, actors) == nil || suite.close() == nil || ctx.Err() == nil {
		t.Fatal("invalid candidate left its suite reusable")
	}
}
