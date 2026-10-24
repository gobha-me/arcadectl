// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gobha-me/arcadectl/internal/installobserve"
)

type typedCollectionDiagnosticKey struct{}
type typedCollectionDiagnostic struct {
	observer *installobserve.CollectionDiagnostic
	value    atomic.Pointer[typedCollectionValue]
}
type typedCollectionValue struct{ stage, reason, state uint32 }
type typedCollectionStage uint32

const (
	typedCollectionEligibility typedCollectionStage = iota + 1
	typedCollectionOriginalOpening
	typedCollectionConstructor
	typedCollectionObserve
	typedCollectionJournalMatch
	typedCollectionOriginalClosing
	typedCollectionLocalClosing
	typedCollectionComplete
)

var typedCollectionStages = [...]string{"unknown", "eligibility", "original-opening", "constructor", "collection", "journal-match", "original-closing", "local-closing", "complete"}
var typedCollectionReasons = [...]string{"unknown", "refused", "complete", "local-context", "local-binding", "local-phase", "local-identity", "local-bytes", "local-current"}

func diagnosticContextState(ctx context.Context) uint32 {
	if ctx == nil {
		return 0
	}
	switch ctx.Err() {
	case nil:
		return 1
	case context.Canceled:
		return 2
	case context.DeadlineExceeded:
		return 3
	}
	return 0
}

func diagnosticContextLabel(state uint32) string {
	switch state {
	case 1:
		return "active"
	case 2:
		return "cancelled"
	case 3:
		return "deadline"
	}
	return "unknown"
}

// Only the typed-collection phase creates this optional recorder. Each attempt
// owns its pointer, so late completion cannot republish into a newer attempt or
// checkpoint. Context values carry diagnostics, never authority or evidence.
func beginTypedCollectionDiagnostic(ctx context.Context) context.Context {
	if ctx == nil {
		return ctx
	}
	d, _ := ctx.Value(lifecycleDiagnosticKey{}).(*LifecycleDiagnostic)
	if d == nil {
		return ctx
	}
	ctx, observer := installobserve.WithCollectionDiagnostic(ctx)
	recorder := &typedCollectionDiagnostic{observer: observer}
	d.typedCollection.Store(recorder)
	return context.WithValue(ctx, typedCollectionDiagnosticKey{}, recorder)
}

func traceTypedCollection(ctx context.Context, stage typedCollectionStage, reason uint32) {
	if ctx == nil {
		return
	}
	if recorder, _ := ctx.Value(typedCollectionDiagnosticKey{}).(*typedCollectionDiagnostic); recorder != nil {
		recorder.value.Store(&typedCollectionValue{uint32(stage), reason, diagnosticContextState(ctx)})
	}
}

func finishTypedCollection(ctx context.Context, refused bool) {
	if ctx == nil {
		return
	}
	if recorder, _ := ctx.Value(typedCollectionDiagnosticKey{}).(*typedCollectionDiagnostic); recorder != nil {
		if before := recorder.value.Load(); before != nil {
			reason := uint32(2)
			if refused {
				reason = 1
			}
			recorder.value.Store(&typedCollectionValue{before.stage, reason, diagnosticContextState(ctx)})
		}
	}
}

// TypedCollectionSnapshot is progress from the latest actual typed attempt,
// not a cause, partial observation, acceptance exception or permission to retry.
func (d *LifecycleDiagnostic) TypedCollectionSnapshot() string {
	if d == nil {
		return ""
	}
	recorder := d.typedCollection.Load()
	if recorder == nil {
		return ""
	}
	stage, reason, state := "unknown", "unknown", "unknown"
	if v := recorder.value.Load(); v != nil {
		if v.stage < uint32(len(typedCollectionStages)) {
			stage = typedCollectionStages[v.stage]
		}
		if v.reason < uint32(len(typedCollectionReasons)) {
			reason = typedCollectionReasons[v.reason]
		}
		state = diagnosticContextLabel(v.state)
	}
	return fmt.Sprintf("stage=%s reason=%s state=%s observer-", stage, reason, state) + strings.ReplaceAll(recorder.observer.Snapshot(), " ", " observer-")
}

type admissionSettleDiagnostic struct {
	value atomic.Pointer[admissionSettleValue]
}
type admissionSettleValue struct {
	attempts uint32
	elapsed  int64
	state    uint32
	caller   uint32
	settled  bool
}

func beginAdmissionSettleDiagnostic(ctx context.Context) func(uint32, time.Duration, context.Context, context.Context, bool) {
	if ctx == nil {
		return func(uint32, time.Duration, context.Context, context.Context, bool) {}
	}
	d, _ := ctx.Value(lifecycleDiagnosticKey{}).(*LifecycleDiagnostic)
	if d == nil {
		return func(uint32, time.Duration, context.Context, context.Context, bool) {}
	}
	recorder := &admissionSettleDiagnostic{}
	d.admissionSettle.Store(recorder)
	return func(attempts uint32, elapsed time.Duration, child, caller context.Context, settled bool) {
		if elapsed < 0 {
			elapsed = 0
		}
		// Caller snapshots BEFORE cancelling its owned child; only fixed state
		// and numeric measurements survive. The context itself is never held.
		recorder.value.Store(&admissionSettleValue{attempts, int64(elapsed), diagnosticContextState(child), diagnosticContextState(caller), settled})
	}
}

func (d *LifecycleDiagnostic) AdmissionSettleSnapshot() string {
	if d == nil {
		return ""
	}
	recorder := d.admissionSettle.Load()
	if recorder == nil {
		return ""
	}
	v := recorder.value.Load()
	if v == nil {
		return ""
	}
	outcome := "refused"
	if v.settled {
		outcome = "settled"
	}
	return fmt.Sprintf("attempts=%d elapsed-ns=%d state=%s caller=%s outcome=%s", v.attempts, v.elapsed, diagnosticContextLabel(v.state), diagnosticContextLabel(v.caller), outcome)
}
