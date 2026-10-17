// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/flowcontrol"
)

type sdkWaitFixtureLimiter struct {
	flowcontrol.RateLimiter
	wait func(context.Context) error
}

func (l sdkWaitFixtureLimiter) Wait(ctx context.Context) error { return l.wait(ctx) }

func TestSDKWaitDiagnosticPreservesDelegationAndCommandIsolation(t *testing.T) {
	ctx, costs := WithLifecycleCosts(t.Context())
	private := errors.New("PRIVATE-CANARY")
	var delegated atomic.Uint64
	limiter := &sdkWaitDiagnosticLimiter{RateLimiter: sdkWaitFixtureLimiter{
		RateLimiter: flowcontrol.NewFakeAlwaysRateLimiter(),
		wait: func(got context.Context) error {
			delegated.Add(1)
			if got != ctx {
				t.Error("diagnostic replaced delegate context")
			}
			return private
		},
	}}
	if err := limiter.Wait(ctx); err != private || delegated.Load() != 1 || costs.metrics[costSDKWait].calls.Load() != 1 || costs.metrics[costSDKWait].returned.Load() != 1 {
		t.Fatal("Wait diagnostic altered result or repeated delegation")
	}
	ctx, next := WithLifecycleCosts(ctx)
	if limiter.Wait(ctx) != private || costs.metrics[costSDKWait].calls.Load() != 1 || next.metrics[costSDKWait].calls.Load() != 1 {
		t.Fatal("new command inherited another command's wait costs")
	}
	ctx, _ = WithLifecycleDiagnostic(ctx)
	if limiter.Wait(ctx) != private || next.metrics[costSDKWait].calls.Load() != 2 {
		t.Fatal("step-local diagnostics erased command wait costs")
	}
	ctx = t.Context() // No command recorder: delegation still occurs unchanged.
	if limiter.Wait(ctx) != private || next.metrics[costSDKWait].calls.Load() != 2 || delegated.Load() != 4 {
		t.Fatal("unrecorded Wait changed delegation or old command costs")
	}
	cancelled, cancel := context.WithCancelCause(t.Context())
	cancel(private)
	ctx, cancelledCosts := WithLifecycleCosts(cancelled)
	var calls atomic.Uint64
	limiter.RateLimiter = sdkWaitFixtureLimiter{
		RateLimiter: flowcontrol.NewFakeAlwaysRateLimiter(),
		wait: func(got context.Context) error {
			calls.Add(1)
			if got != ctx || got.Err() != context.Canceled || context.Cause(got) != private {
				t.Error("Wait diagnostic changed parent cancellation/cause")
			}
			return got.Err()
		},
	}
	var group sync.WaitGroup
	for range 8 {
		group.Go(func() {
			for range 20 {
				if limiter.Wait(ctx) != context.Canceled {
					t.Error("cancelled Wait result changed")
				}
			}
		})
	}
	group.Wait()
	if calls.Load() != 160 || cancelledCosts.metrics[costSDKWait].calls.Load() != 160 || cancelledCosts.metrics[costSDKWait].returned.Load() != 160 || strings.Contains(cancelledCosts.Snapshot(), "PRIVATE") || len(cancelledCosts.Snapshot()) > 2048 {
		t.Fatal("concurrent cancelled Wait escaped bounded numeric counters")
	}
}

func TestSDKWaitDiagnosticKeepsDefaultReadBucketShared(t *testing.T) {
	t.Run("whole-prerequisite-sdk-census", func(t *testing.T) {
		testBaselinePrerequisiteCompleteDiscovery(t, "sdk-wait-census")
	})
	access, err := NewDirectHTTPAccess(&rest.Config{Host: "https://cluster.example", BearerToken: "FAKE-SDK-WAIT"})
	if err != nil {
		t.Fatal("default read access unavailable")
	}
	wrapped, ok := access.readLimiter.(*sdkWaitDiagnosticLimiter)
	if !ok || wrapped.RateLimiter == nil || wrapped.QPS() != installerReadQPS {
		t.Fatal("default bucket lacks the one delegating diagnostic wrapper")
	}
	derived, err := access.derivedDirectAccess(rest.ImpersonationConfig{}, func(next http.RoundTripper) http.RoundTripper { return next })
	if err != nil {
		t.Fatal("derived read access unavailable")
	}
	// A zero-refill test delegate avoids wall-clock replenishment races. It is
	// not the production default: only that one already-shared delegate changes.
	wrapped.RateLimiter = flowcontrol.NewTokenBucketRateLimiter(0, 1)
	one, two, child := access.readConfig(), access.readConfig(), derived.readConfig()
	if one.RateLimiter != access.readLimiter || two.RateLimiter != one.RateLimiter || child.RateLimiter != one.RateLimiter || !one.RateLimiter.TryAccept() || two.RateLimiter.TryAccept() || child.RateLimiter.TryAccept() {
		t.Fatal("reconstructed or derived readers minted independent token buckets")
	}
	bounded, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	ctx, costs := WithLifecycleCosts(bounded)
	if costs.metrics[costSDKWait].calls.Load() != 0 {
		t.Fatal("TryAccept fabricated measured Wait costs")
	}
	if one.RateLimiter.Wait(ctx) == nil || costs.metrics[costSDKWait].calls.Load() != 1 || costs.metrics[costSDKWait].returned.Load() != 1 {
		t.Fatal("exhausted zero-refill budget was bypassed or unmeasured")
	}
}
