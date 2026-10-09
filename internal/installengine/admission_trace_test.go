// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"sync"
	"testing"
)

func TestAdmissionTraceClosedStagesAndPositions(t *testing.T) {
	labels := map[admissionStep]string{
		admissionInitialPhase: "initial-phase", admissionActorWitnesses: "actors", admissionLedger: "ledger",
		admissionInitialSeal: "initial-seal", admissionWire: "wire", admissionSetupObservation: "setup-observation",
		admissionSetupPreview: "setup-preview-and-witness", admissionSetupCreate: "setup-create", admissionSetupSettle: "setup-settle",
		admissionCaseObservation: "case-observation", admissionCaseRequest: "case-request", admissionCaseAuthorization: "case-authorization",
		admissionCaseProbe: "case-probe", admissionCasePostObservation: "case-post-observation", admissionCaseShape: "case-shape",
		admissionSeed: "seed", admissionMarker: "marker", admissionFinish: "finish", admissionCleanup: "cleanup",
		admissionRetire: "retire", admissionFinalWitness: "final-witness", admissionComplete: "complete",
	}
	for value := range 256 {
		step := admissionStep(value)
		expected, known := labels[step]
		if !known {
			expected = "unknown"
		}
		if step.String() != expected {
			t.Fatal("diagnostic escaped closed labels")
		}
		for index := -2; index <= int(fixtureAdmissionCaseCount); index++ {
			valid := false
			switch step {
			case admissionInitialPhase, admissionActorWitnesses, admissionLedger, admissionInitialSeal, admissionWire, admissionFinish, admissionRetire, admissionFinalWitness, admissionComplete:
				valid = index == -1
			case admissionSetupObservation:
				valid = index >= -1 && index <= 10
			case admissionSetupPreview, admissionSetupCreate, admissionSetupSettle, admissionCleanup:
				valid = index >= 0 && index <= 10
			case admissionCaseObservation, admissionCaseRequest, admissionCaseAuthorization, admissionCaseProbe, admissionCasePostObservation, admissionCaseShape:
				valid = index >= 0 && index <= 54
			case admissionSeed:
				valid = index == 39
			case admissionMarker:
				valid = index == 45
			}
			trace := &admissionTrace{}
			traceAdmission(context.WithValue(t.Context(), admissionTraceKey{}, trace), step, index)
			got, gotIndex := trace.snapshot()
			if valid {
				if got != expected || gotIndex != index {
					t.Fatal("bounded progress snapshot disagreed")
				}
			} else if got != "unknown" || gotIndex != -1 {
				t.Fatal("invalid position manufactured progress")
			}
		}
	}
	var absent *admissionTrace
	if stage, index := absent.snapshot(); stage != "unknown" || index != -1 {
		t.Fatal("nil trace manufactured progress")
	}
}

func TestAdmissionTraceCannotRetainArbitraryValuesOrAlterErrors(t *testing.T) {
	trace := &admissionTrace{}
	ctx := context.WithValue(t.Context(), admissionTraceKey{}, trace)
	traceAdmission(ctx, admissionCaseProbe, 54)
	for _, position := range []uint32{0, 255, 0xffffffff, uint32(admissionCleanup)<<8 | 55, uint32(admissionCaseProbe) << 8, uint32(admissionSeed)<<8 | 41} {
		trace.position.Store(position)
		if stage, index := trace.snapshot(); stage != "unknown" || index != -1 {
			t.Fatal("corrupted snapshot exposed an unbounded diagnostic")
		}
	}
	trace.position.Store(0)
	traceAdmission(nil, admissionActorWitnesses, -1)
	traceAdmission(context.WithValue(t.Context(), admissionTraceKey{}, "private-token-canary"), admissionActorWitnesses, -1)
	traceAdmission(context.WithValue(t.Context(), "private-token-canary", trace), admissionActorWitnesses, -1)
	traceAdmission(ctx, admissionStep(255), 0)
	traceAdmission(ctx, admissionCaseProbe, 1000000)
	var admission *ClusterAdmission
	if admission.VerifyEffective(ctx, LifecycleCheck{}) != ErrInvalid {
		t.Fatal("diagnostic changed public refusal")
	}
	if stage, index := trace.snapshot(); stage != "unknown" || index != -1 {
		t.Fatal("untrusted value or invalid proof manufactured progress")
	}
}

func TestAdmissionTraceConcurrentSnapshot(t *testing.T) {
	trace := &admissionTrace{}
	ctx := context.WithValue(t.Context(), admissionTraceKey{}, trace)
	var group sync.WaitGroup
	for worker := range 8 {
		group.Go(func() {
			for range 1000 {
				traceAdmission(ctx, admissionCaseProbe, worker)
				stage, index := trace.snapshot()
				if stage != "case-probe" || index < 0 || index >= 8 {
					t.Error("concurrent snapshot mixed progress fields")
					return
				}
			}
		})
	}
	group.Wait()
}

func TestAdmissionPhaseTraceClosedStagesAndNoArbitraryValues(t *testing.T) {
	labels := map[admissionPhaseStep]string{
		admissionPhaseOriginal: "original-witness", admissionPhaseWorlds: "sealed-worlds", admissionPhaseConfigured: "configured",
		admissionPhaseOpening: "pass-opening", admissionPhaseTyped: "typed-collections", admissionPhaseRows: "original-rows",
		admissionPhasePublicBefore: "public-before", admissionPhaseNamedGet: "named-get", admissionPhaseWholeFixture: "whole-fixture",
		admissionPhaseStorage: "storage", admissionPhaseGC: "gc-collections", admissionPhaseLeaders: "original-leaders",
		admissionPhaseOwners: "owner-closure", admissionPhasePublicAfter: "public-after", admissionPhaseFixtureCorrelation: "fixture-correlation",
		admissionPhaseFinalConfigured: "final-configured", admissionPhaseFinalPublic: "final-public", admissionPhaseComplete: "complete",
		admissionPhaseGCOpening: "gc-opening", admissionPhaseGCMetadataPages: "gc-metadata-pages",
		admissionPhaseGCMetadataShape: "gc-metadata-shape", admissionPhaseGCMetadataUIDs: "gc-metadata-uid-correlation",
		admissionPhaseGCLeasePages: "gc-lease-pages", admissionPhaseGCLeaseMembership: "gc-lease-membership",
		admissionPhaseGCLeaseCorrelation: "gc-lease-correlation", admissionPhaseGCLeaseSource: "gc-lease-source",
		admissionPhaseGCClosing:            "gc-closing",
		admissionPhaseGCEventAliasRV:       "gc-event-alias-rv-conflict",
		admissionPhaseGCEventAliasMetadata: "gc-event-alias-metadata-conflict",
		admissionPhaseGCGraphBound:         "gc-metadata-graph-bound",
	}
	for value := range 256 {
		step := admissionPhaseStep(value)
		expected, known := labels[step]
		if !known {
			expected = "unknown"
		}
		if step.String() != expected {
			t.Fatal("phase diagnostic escaped closed labels")
		}
		for slot := -2; slot <= 11; slot++ {
			valid := known && slot == -1
			if step == admissionPhaseNamedGet || step == admissionPhaseWholeFixture {
				valid = slot >= 0 && slot <= 10
			}
			trace := &admissionTrace{}
			traceAdmissionPhase(context.WithValue(t.Context(), admissionTraceKey{}, trace), step, slot)
			stage, gotSlot := trace.phaseSnapshot()
			if valid {
				if stage != expected || gotSlot != slot {
					t.Fatal("closed phase position disagreed")
				}
			} else if stage != "unknown" || gotSlot != -1 {
				t.Fatal("invalid phase position manufactured a diagnostic")
			}
		}
	}
	var absent *admissionTrace
	if stage, slot := absent.phaseSnapshot(); stage != "unknown" || slot != -1 {
		t.Fatal("nil phase trace manufactured a diagnostic")
	}
	trace := &admissionTrace{}
	ctx := context.WithValue(t.Context(), admissionTraceKey{}, trace)
	traceAdmissionPhase(nil, admissionPhaseGC, -1)
	traceAdmissionPhase(context.WithValue(t.Context(), admissionTraceKey{}, "private-token-canary"), admissionPhaseGC, -1)
	traceAdmissionPhase(ctx, admissionPhaseGC, 1000000)
	for _, position := range []uint32{0, 255, 0xffffffff, uint32(admissionPhaseGC)<<8 | 1, uint32(admissionPhaseNamedGet) << 8, uint32(admissionPhaseWholeFixture)<<8 | 12} {
		trace.phase.Store(position)
		if stage, slot := trace.phaseSnapshot(); stage != "unknown" || slot != -1 {
			t.Fatal("corrupted phase snapshot exposed an unbounded diagnostic")
		}
	}
	traceAdmissionPhase(ctx, admissionPhaseWholeFixture, 10)
	traceAdmission(ctx, admissionCaseProbe, 54)
	if stage, slot := trace.phaseSnapshot(); stage != "unknown" || slot != -1 {
		t.Fatal("new outer operation retained stale phase progress")
	}
}
