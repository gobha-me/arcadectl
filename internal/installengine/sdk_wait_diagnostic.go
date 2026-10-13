// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"

	"k8s.io/client-go/util/flowcontrol"
)

// Only the internally created aggregate SDK read limiter is wrapped. Caller
// settings and explicit limiter pointers stay unchanged. Every other method
// delegates directly; there is no new bucket, stored recorder, context or error.
// This measures inclusive Wait-call wall time, including cancelled/refused
// returns, not sleeping time, CPU time, success or mutation authority. Explicit
// configurations, non-Wait methods and unrecorded contexts remain unmeasured.
type sdkWaitDiagnosticLimiter struct{ flowcontrol.RateLimiter }

func (l *sdkWaitDiagnosticLimiter) Wait(ctx context.Context) error {
	defer beginLifecycleCost(ctx, costSDKWait)()
	return l.RateLimiter.Wait(ctx)
}
