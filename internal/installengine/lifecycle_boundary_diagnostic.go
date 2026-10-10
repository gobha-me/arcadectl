// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"fmt"
)

type operationBoundary uint8

const (
	boundaryRetainedOpening operationBoundary = iota + 1
	boundaryRetainedRead
	boundaryRetainedClosing
	boundaryRetainedComplete
	boundaryApplyOpening
	boundaryApplyCandidate
	boundaryApplyPreview
	boundaryApplyPreviewResult
	boundaryApplyAfterPreview
	boundaryApplyIntent
	boundaryApplyReceipt
	boundaryApplyEffectOpening
	boundaryApplyEffectRequest
	boundaryApplyEffectResult
	boundaryRecoveryOpening
	boundaryRecoveryRead
	boundaryRecoveryReceipt
	boundaryRecoverySettlement
	boundaryRecoveryComplete
)

func (b operationBoundary) label() string {
	switch b {
	case boundaryRetainedOpening:
		return "retained-opening"
	case boundaryRetainedRead:
		return "retained-read"
	case boundaryRetainedClosing:
		return "retained-closing"
	case boundaryRetainedComplete:
		return "retained-complete"
	case boundaryApplyOpening:
		return "apply-opening"
	case boundaryApplyCandidate:
		return "apply-candidate"
	case boundaryApplyPreview:
		return "apply-preview"
	case boundaryApplyPreviewResult:
		return "apply-preview-result"
	case boundaryApplyAfterPreview:
		return "apply-after-preview"
	case boundaryApplyIntent:
		return "apply-intent"
	case boundaryApplyReceipt:
		return "apply-receipt"
	case boundaryApplyEffectOpening:
		return "apply-effect-opening"
	case boundaryApplyEffectRequest:
		return "apply-effect-request"
	case boundaryApplyEffectResult:
		return "apply-effect-result"
	case boundaryRecoveryOpening:
		return "recovery-opening"
	case boundaryRecoveryRead:
		return "recovery-read"
	case boundaryRecoveryReceipt:
		return "recovery-receipt"
	case boundaryRecoverySettlement:
		return "recovery-settlement"
	case boundaryRecoveryComplete:
		return "recovery-complete"
	}
	return "unknown"
}

type baselineBoundary uint8

const (
	baselineBoundaryScope baselineBoundary = iota + 1
	baselineBoundarySource
	baselineBoundaryActors
	baselineBoundaryExecutables
	baselineBoundaryMetadata
	baselineBoundaryParents
	baselineBoundaryFamily
	baselineBoundaryActorClose
	baselineBoundaryDeniedOpening
	baselineBoundaryProducerBefore
	baselineBoundaryProducerWire
	baselineBoundaryProducerResult
	baselineBoundaryProducerAfter
	baselineBoundaryProducerNegative
	baselineBoundaryIdentity
	baselineBoundaryParentProbe
	baselineBoundaryPodProbe
	baselineBoundaryClosing
	baselineBoundarySourceClose
	baselineBoundaryRetired
	baselineBoundaryComplete
	baselineBoundaryDeniedActorsOpening
	baselineBoundaryDeniedCatalog
	baselineBoundaryDeniedRulesOpening
	baselineBoundaryDeniedClients
	baselineBoundaryDeniedReviews
	baselineBoundaryDeniedExecutablesClosing
	baselineBoundaryDeniedExecutablesStable
	baselineBoundaryDeniedOriginalsClosing
	baselineBoundaryDeniedActorsClosing
	baselineBoundaryDeniedRulesClosing
	baselineBoundaryDeniedActorsFinal
	baselineBoundaryClosingMetadata
	baselineBoundaryClosingParents
	baselineBoundaryClosingFamily
	baselineBoundaryRuntimeDeadline
)

func (b baselineBoundary) label() string {
	switch b {
	case baselineBoundaryScope:
		return "scope"
	case baselineBoundarySource:
		return "source"
	case baselineBoundaryActors:
		return "actors"
	case baselineBoundaryExecutables:
		return "executables"
	case baselineBoundaryMetadata:
		return "metadata"
	case baselineBoundaryParents:
		return "parents"
	case baselineBoundaryFamily:
		return "family"
	case baselineBoundaryActorClose:
		return "actor-close"
	case baselineBoundaryDeniedOpening:
		return "denied-opening"
	case baselineBoundaryProducerBefore:
		return "producer-before"
	case baselineBoundaryProducerWire:
		return "producer-wire"
	case baselineBoundaryProducerResult:
		return "producer-result"
	case baselineBoundaryProducerAfter:
		return "producer-after"
	case baselineBoundaryProducerNegative:
		return "producer-negative"
	case baselineBoundaryIdentity:
		return "identity-probe"
	case baselineBoundaryParentProbe:
		return "parent-probe"
	case baselineBoundaryPodProbe:
		return "pod-probe"
	case baselineBoundaryClosing:
		return "closing"
	case baselineBoundarySourceClose:
		return "source-close"
	case baselineBoundaryRetired:
		return "retired"
	case baselineBoundaryComplete:
		return "complete"
	case baselineBoundaryDeniedActorsOpening:
		return "denied-actors-opening"
	case baselineBoundaryDeniedCatalog:
		return "denied-catalog"
	case baselineBoundaryDeniedRulesOpening:
		return "denied-rules-opening"
	case baselineBoundaryDeniedClients:
		return "denied-clients"
	case baselineBoundaryDeniedReviews:
		return "denied-reviews"
	case baselineBoundaryDeniedExecutablesClosing:
		return "denied-executables-closing"
	case baselineBoundaryDeniedExecutablesStable:
		return "denied-executables-stable"
	case baselineBoundaryDeniedOriginalsClosing:
		return "denied-originals-closing"
	case baselineBoundaryDeniedActorsClosing:
		return "denied-actors-closing"
	case baselineBoundaryDeniedRulesClosing:
		return "denied-rules-closing"
	case baselineBoundaryDeniedActorsFinal:
		return "denied-actors-final"
	case baselineBoundaryClosingMetadata:
		return "closing-metadata"
	case baselineBoundaryClosingParents:
		return "closing-parents"
	case baselineBoundaryClosingFamily:
		return "closing-family"
	case baselineBoundaryRuntimeDeadline:
		return "runtime-deadline"
	}
	return "unknown"
}

func traceOperationBoundary(ctx context.Context, step operationBoundary) {
	if ctx == nil || step.label() == "unknown" {
		return
	}
	if d, ok := ctx.Value(lifecycleDiagnosticKey{}).(*LifecycleDiagnostic); ok && d != nil {
		d.baselineBoundary.Store(0)
		d.operationBoundary.Store(uint32(step))
	}
}

func traceBaselineBoundary(ctx context.Context, step baselineBoundary) {
	if ctx == nil || step.label() == "unknown" {
		return
	}
	if d, ok := ctx.Value(lifecycleDiagnosticKey{}).(*LifecycleDiagnostic); ok && d != nil {
		d.baselineBoundary.Store(uint32(step))
	}
}

// BoundarySnapshot is separate from the existing bounded checkpoint record.
// It reports fixed progress or an observed proof-context deadline expiration,
// never a provider cause, proof, deadline override, retry instruction or
// provider response. Read it
// after the SAME Step returns. No pathname, UID, nonce or private bytes escape.
func (d *LifecycleDiagnostic) BoundarySnapshot() string {
	operation, baseline := "unknown", "unknown"
	if d != nil {
		if value := d.operationBoundary.Load(); value <= 255 {
			operation = operationBoundary(value).label()
		}
		if value := d.baselineBoundary.Load(); value <= 255 {
			baseline = baselineBoundary(value).label()
		}
	}
	return fmt.Sprintf("operation=%s baseline=%s", operation, baseline)
}
