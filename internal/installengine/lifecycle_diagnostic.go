// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"fmt"
	"sync/atomic"
)

type lifecycleDiagnosticKey struct{}
type lifecycleDiagnosticState uint8

const (
	lifecycleDiagnosticEntered lifecycleDiagnosticState = iota + 1
	lifecycleDiagnosticPassed
	lifecycleDiagnosticRefused
)

// LifecycleDiagnostic records fixed progress from ONE actual Step. It retains
// no context, callback, provider error, object, identity, path or credential.
// It is not proof, root-cause classification, recovery or retry authority.
type LifecycleDiagnostic struct {
	checkpoint atomic.Uint32
	admission  admissionTrace
	activation activationTrace
}

// WithLifecycleDiagnostic creates a fresh opaque recorder, superseding any
// prior attempt's trace. Call Snapshot only AFTER that same Step returns.
// A nil parent stays nil, never becoming a usable execution context.
func WithLifecycleDiagnostic(ctx context.Context) (context.Context, *LifecycleDiagnostic) {
	if ctx == nil {
		return nil, nil
	}
	diagnostic := &LifecycleDiagnostic{}
	ctx = context.WithValue(ctx, lifecycleDiagnosticKey{}, diagnostic)
	ctx = context.WithValue(ctx, admissionTraceKey{}, &diagnostic.admission)
	ctx = context.WithValue(ctx, activationTraceKey{}, &diagnostic.activation)
	return ctx, diagnostic
}

func lifecycleDiagnosticCheckpoint(kind Checkpoint) string {
	switch kind {
	case Prerequisites:
		return "prerequisites"
	case CRDsAvailable:
		return "crds-available"
	case AdmissionEffective:
		return "admission-effective"
	case ColdSafety:
		return "cold-safety"
	case APIStopped:
		return "api-stopped"
	case RuntimeStopped:
		return "runtime-stopped"
	case ControllersAvailable:
		return "controllers-available"
	case TargetAuthenticated:
		return "target-authenticated"
	case AdmissionConfigured:
		return "admission-configured"
	case RetainedAdmission:
		return "retained-admission"
	case BootstrapAdmission:
		return "bootstrap-admission"
	}
	return "unknown"
}

func traceLifecycleCheckpoint(ctx context.Context, kind Checkpoint, state lifecycleDiagnosticState) {
	if ctx == nil || lifecycleDiagnosticCheckpoint(kind) == "unknown" || state < lifecycleDiagnosticEntered || state > lifecycleDiagnosticRefused {
		return
	}
	if diagnostic, ok := ctx.Value(lifecycleDiagnosticKey{}).(*LifecycleDiagnostic); ok && diagnostic != nil {
		if state == lifecycleDiagnosticEntered {
			// Inner progress must belong to the CURRENT checkpoint, not a
			// previous successful checkpoint within this same Step.
			diagnostic.admission.position.Store(0)
			diagnostic.admission.phase.Store(0)
			diagnostic.activation.step.Store(0)
		}
		diagnostic.checkpoint.Store(uint32(kind)<<8 | uint32(state))
	}
}

// Snapshot contains only closed labels and validated bounded indices. Passed
// means that checkpoint completed, NOT that a later inventory/effect succeeded.
// The fields are diagnostic progress, not an atomic multi-goroutine proof.
func (diagnostic *LifecycleDiagnostic) Snapshot() string {
	kind, state, admission, phase, activation := "unknown", "unknown", "unknown", "unknown", "unknown"
	index, slot := -1, -1
	if diagnostic != nil {
		position := diagnostic.checkpoint.Load()
		if position>>8 <= 255 {
			candidate := lifecycleDiagnosticCheckpoint(Checkpoint(position >> 8))
			if candidate != "unknown" {
				switch lifecycleDiagnosticState(position & 255) {
				case lifecycleDiagnosticEntered:
					kind, state = candidate, "entered"
				case lifecycleDiagnosticPassed:
					kind, state = candidate, "passed"
				case lifecycleDiagnosticRefused:
					kind, state = candidate, "refused"
				}
			}
		}
		admission, index = diagnostic.admission.snapshot()
		phase, slot = diagnostic.admission.phaseSnapshot()
		activation = diagnostic.activation.stage()
	}
	return fmt.Sprintf("checkpoint=%s checkpoint-status=%s admission=%s index=%d phase=%s slot=%d activation=%s", kind, state, admission, index, phase, slot, activation)
}
