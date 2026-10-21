// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"sync/atomic"
)

// Private opt-in diagnostic for the SAME attempt. No callbacks, error/body
// retention, identity/credential values, public error changes or retries. Only
// the first actual refusal stage is recorded; callers cannot supply a message.
type activationTraceKey struct{}
type activationTrace struct{ step atomic.Uint32 }
type activationStep uint32

const (
	activationOriginalBefore activationStep = iota + 1
	activationServingBefore
	activationBindingBefore
	activationClientLoad
	activationConnectionOpen
	activationServingDialRead
	activationServingDialMatch
	activationBindingDialRead
	activationBindingDialMatch
	activationSelf
	activationSelfIdentity
	activationServingAfterRead
	activationServingAfterMatch
	activationBindingAfterRead
	activationBindingAfterMatch
	activationOriginalAfter
	activationComplete
)

func traceActivation(ctx context.Context, step activationStep) {
	if ctx == nil {
		return
	}
	if trace, ok := ctx.Value(activationTraceKey{}).(*activationTrace); ok && trace != nil {
		for {
			previous := trace.step.Load()
			if previous != 0 && previous != uint32(activationComplete) {
				return // do not replace an inner refusal with a generic outer one
			}
			if trace.step.CompareAndSwap(previous, uint32(step)) {
				return
			}
		}
	}
}

func (trace *activationTrace) stage() string {
	if trace == nil {
		return "unknown"
	}
	switch activationStep(trace.step.Load()) {
	case activationOriginalBefore:
		return "original-before"
	case activationServingBefore:
		return "serving-before"
	case activationBindingBefore:
		return "binding-before"
	case activationClientLoad:
		return "bound-client-load"
	case activationConnectionOpen:
		return "connection-open"
	case activationServingDialRead:
		return "serving-dial-read"
	case activationServingDialMatch:
		return "serving-dial-mismatch"
	case activationBindingDialRead:
		return "binding-dial-read"
	case activationBindingDialMatch:
		return "binding-dial-mismatch"
	case activationSelf:
		return "auth-self"
	case activationSelfIdentity:
		return "auth-self-identity"
	case activationServingAfterRead:
		return "serving-after-read"
	case activationServingAfterMatch:
		return "serving-after-mismatch"
	case activationBindingAfterRead:
		return "binding-after-read"
	case activationBindingAfterMatch:
		return "binding-after-mismatch"
	case activationOriginalAfter:
		return "original-after"
	case activationComplete:
		return "complete"
	}
	return "unknown"
}
