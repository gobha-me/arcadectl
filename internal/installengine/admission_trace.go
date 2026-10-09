// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"sync/atomic"
)

// Private, opt-in progress from the SAME attempt. No callback, object, error,
// identity or credential is retained. This is neither proof nor a retry route;
// the public sentinel errors and all required observations remain unchanged.
type admissionTraceKey struct{}
type admissionTrace struct {
	position atomic.Uint32
	phase    atomic.Uint32
}
type admissionStep uint8

const (
	admissionInitialPhase admissionStep = iota + 1
	admissionActorWitnesses
	admissionLedger
	admissionInitialSeal
	admissionWire
	admissionSetupObservation
	admissionSetupPreview
	admissionSetupCreate
	admissionSetupSettle
	admissionCaseObservation
	admissionCaseRequest
	admissionCaseAuthorization
	admissionCaseProbe
	admissionCasePostObservation
	admissionCaseShape
	admissionSeed
	admissionMarker
	admissionFinish
	admissionCleanup
	admissionRetire
	admissionFinalWitness
	admissionComplete
)

func (step admissionStep) String() string {
	switch step {
	case admissionInitialPhase:
		return "initial-phase"
	case admissionActorWitnesses:
		return "actors"
	case admissionLedger:
		return "ledger"
	case admissionInitialSeal:
		return "initial-seal"
	case admissionWire:
		return "wire"
	case admissionSetupObservation:
		return "setup-observation"
	case admissionSetupPreview:
		return "setup-preview-and-witness"
	case admissionSetupCreate:
		return "setup-create"
	case admissionSetupSettle:
		return "setup-settle"
	case admissionCaseObservation:
		return "case-observation"
	case admissionCaseRequest:
		return "case-request"
	case admissionCaseAuthorization:
		return "case-authorization"
	case admissionCaseProbe:
		return "case-probe"
	case admissionCasePostObservation:
		return "case-post-observation"
	case admissionCaseShape:
		return "case-shape"
	case admissionSeed:
		return "seed"
	case admissionMarker:
		return "marker"
	case admissionFinish:
		return "finish"
	case admissionCleanup:
		return "cleanup"
	case admissionRetire:
		return "retire"
	case admissionFinalWitness:
		return "final-witness"
	case admissionComplete:
		return "complete"
	}
	return "unknown"
}

func traceAdmission(ctx context.Context, step admissionStep, index int) {
	if ctx == nil || !validAdmissionPosition(step, index) {
		return
	}
	if trace, ok := ctx.Value(admissionTraceKey{}).(*admissionTrace); ok && trace != nil {
		// One atomic snapshot avoids pairing a stage with another stage's index.
		trace.phase.Store(0)
		trace.position.Store(uint32(step)<<8 | uint32(index+1))
	}
}

// Substage is separate from the outer case/slot. Only read it once the actual
// attempt has returned: it is not an atomic cross-goroutine combined proof.
type admissionPhaseStep uint8

const (
	admissionPhaseOriginal admissionPhaseStep = iota + 1
	admissionPhaseWorlds
	admissionPhaseConfigured
	admissionPhaseOpening
	admissionPhaseTyped
	admissionPhaseRows
	admissionPhasePublicBefore
	admissionPhaseNamedGet
	admissionPhaseWholeFixture
	admissionPhaseStorage
	admissionPhaseGC
	admissionPhaseLeaders
	admissionPhaseOwners
	admissionPhasePublicAfter
	admissionPhaseFixtureCorrelation
	admissionPhaseFinalConfigured
	admissionPhaseFinalPublic
	admissionPhaseGCOpening
	admissionPhaseGCMetadataPages
	admissionPhaseGCMetadataShape
	admissionPhaseGCMetadataUIDs
	admissionPhaseGCLeasePages
	admissionPhaseGCLeaseMembership
	admissionPhaseGCLeaseCorrelation
	admissionPhaseGCLeaseSource
	admissionPhaseGCClosing
	admissionPhaseGCEventAliasRV
	admissionPhaseGCEventAliasMetadata
	admissionPhaseGCGraphBound
	admissionPhaseComplete
)

func (step admissionPhaseStep) String() string {
	switch step {
	case admissionPhaseOriginal:
		return "original-witness"
	case admissionPhaseWorlds:
		return "sealed-worlds"
	case admissionPhaseConfigured:
		return "configured"
	case admissionPhaseOpening:
		return "pass-opening"
	case admissionPhaseTyped:
		return "typed-collections"
	case admissionPhaseRows:
		return "original-rows"
	case admissionPhasePublicBefore:
		return "public-before"
	case admissionPhaseNamedGet:
		return "named-get"
	case admissionPhaseWholeFixture:
		return "whole-fixture"
	case admissionPhaseStorage:
		return "storage"
	case admissionPhaseGC:
		return "gc-collections"
	case admissionPhaseLeaders:
		return "original-leaders"
	case admissionPhaseOwners:
		return "owner-closure"
	case admissionPhasePublicAfter:
		return "public-after"
	case admissionPhaseFixtureCorrelation:
		return "fixture-correlation"
	case admissionPhaseFinalConfigured:
		return "final-configured"
	case admissionPhaseFinalPublic:
		return "final-public"
	case admissionPhaseGCOpening:
		return "gc-opening"
	case admissionPhaseGCMetadataPages:
		return "gc-metadata-pages"
	case admissionPhaseGCMetadataShape:
		return "gc-metadata-shape"
	case admissionPhaseGCMetadataUIDs:
		return "gc-metadata-uid-correlation"
	case admissionPhaseGCLeasePages:
		return "gc-lease-pages"
	case admissionPhaseGCLeaseMembership:
		return "gc-lease-membership"
	case admissionPhaseGCLeaseCorrelation:
		return "gc-lease-correlation"
	case admissionPhaseGCLeaseSource:
		return "gc-lease-source"
	case admissionPhaseGCClosing:
		return "gc-closing"
	case admissionPhaseGCEventAliasRV:
		return "gc-event-alias-rv-conflict"
	case admissionPhaseGCEventAliasMetadata:
		return "gc-event-alias-metadata-conflict"
	case admissionPhaseGCGraphBound:
		return "gc-metadata-graph-bound"
	case admissionPhaseComplete:
		return "complete"
	}
	return "unknown"
}

func validAdmissionPhasePosition(step admissionPhaseStep, slot int) bool {
	if step == admissionPhaseNamedGet || step == admissionPhaseWholeFixture {
		return slot >= 0 && slot < len(fixtureCatalogV2)
	}
	return step >= admissionPhaseOriginal && step <= admissionPhaseComplete && slot == -1
}

func traceAdmissionPhase(ctx context.Context, step admissionPhaseStep, slot int) {
	if ctx == nil || !validAdmissionPhasePosition(step, slot) {
		return
	}
	if trace, ok := ctx.Value(admissionTraceKey{}).(*admissionTrace); ok && trace != nil {
		trace.phase.Store(uint32(step)<<8 | uint32(slot+1))
	}
}

func (trace *admissionTrace) phaseSnapshot() (string, int) {
	if trace == nil {
		return "unknown", -1
	}
	position := trace.phase.Load()
	step, slot := admissionPhaseStep(position>>8), int(position&255)-1
	if position>>8 > 255 || !validAdmissionPhasePosition(step, slot) {
		return "unknown", -1
	}
	return step.String(), slot
}

func (trace *admissionTrace) snapshot() (string, int) {
	if trace == nil {
		return "unknown", -1
	}
	position := trace.position.Load()
	step, index := admissionStep(position>>8), int(position&255)-1
	if position>>8 > 255 || !validAdmissionPosition(step, index) {
		return "unknown", -1
	}
	return step.String(), index
}

func validAdmissionPosition(step admissionStep, index int) bool {
	switch step {
	case admissionInitialPhase, admissionActorWitnesses, admissionLedger, admissionInitialSeal, admissionWire, admissionFinish, admissionRetire, admissionFinalWitness, admissionComplete:
		return index == -1
	case admissionSetupObservation:
		return index >= -1 && index < len(fixtureCatalogV2)
	case admissionSetupPreview, admissionSetupCreate, admissionSetupSettle, admissionCleanup:
		return index >= 0 && index < len(fixtureCatalogV2)
	case admissionCaseObservation, admissionCaseRequest, admissionCaseAuthorization, admissionCaseProbe, admissionCasePostObservation, admissionCaseShape:
		return index >= 0 && index < int(fixtureAdmissionCaseCount)
	case admissionSeed:
		return index == 39
	case admissionMarker:
		return index == 45
	}
	return false
}
