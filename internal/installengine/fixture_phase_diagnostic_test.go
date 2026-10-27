// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installobserve"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Only the warm test aggregates retries. Keep each gate's last substage so a
// final cancelled attempt cannot erase the repeated refusal that preceded it.
type warmPhaseReadDiagnostic struct {
	attempts int
	last     fixturePhaseGate
	counts   [phaseGateLeaders + 1]int
	stages   [phaseGateLeaders + 1]string
	slots    [phaseGateLeaders + 1]int
}

func (d *warmPhaseReadDiagnostic) record(gate fixturePhaseGate, trace *admissionTrace) {
	if gate > phaseGateLeaders {
		gate = phaseGateUnknown
	}
	d.last = gate
	d.counts[gate]++
	d.stages[gate], d.slots[gate] = trace.phaseSnapshot()
}

func (d *warmPhaseReadDiagnostic) String() string {
	var out strings.Builder
	fmt.Fprintf(&out, "attempts=%d last-gate=%s", d.attempts, d.last)
	for gate := phaseGateUnknown; gate <= phaseGateLeaders; gate++ {
		if d.counts[gate] != 0 {
			fmt.Fprintf(&out, " %s=%d[last-stage=%s slot=%d]", gate, d.counts[gate], d.stages[gate], d.slots[gate])
		}
	}
	return out.String()
}

func TestFixturePhaseGateDiagnosticActualRefusals(t *testing.T) {
	newPhase := fixturePhaseFactory(t)
	for _, fault := range []string{"healthy", "phaseReadable", "current", "localBarrier", "remote", "baseline"} {
		t.Run(fault, func(t *testing.T) {
			h := newPhase(t)
			f := h.f.wire.ledger
			body, identity := bytes.Clone(f.body), f.identity
			trace := &admissionTrace{}
			ctx := context.WithValue(t.Context(), admissionTraceKey{}, trace)
			injected := false
			if fault == "phaseReadable" {
				f.ackSlot, injected = 0, true
			}
			if fault == "baseline" {
				f.phaseFloor = &fixturePhaseBaseline{} // incompatible with sealed floor
				injected = true
			}
			base := h.f.actor.fixtureHandler
			h.f.actor.fixtureHandler = func(w http.ResponseWriter, r *http.Request) bool {
				stage, _ := trace.phaseSnapshot()
				if testRuntimeConfigurationRequest(r) && (fault == "current" && stage == "original-witness" || fault == "remote" && stage == "configured") {
					injected = true
					w.WriteHeader(http.StatusForbidden)
					return true
				}
				handled := base(w, r)
				if fault == "localBarrier" && stage == "configured" && !injected {
					f.identity = privatefs.FileIdentity{} // refuse pinned local evidence after successful read
					injected = true
				}
				return handled
			}
			observation, err := h.f.wire.observePhase(ctx)
			gate := trace.phaseGateSnapshot()
			stage, slot := trace.phaseSnapshot()
			wantStage := "configured"
			if fault == "healthy" {
				wantStage = "complete"
				if err != nil || observation == nil || gate != phaseGateUnknown || f.phaseFloor == nil || h.gets != 2*len(f.document.Entries) {
					t.Fatal("diagnostic changed complete read acceptance or census")
				}
			} else {
				if fault == "phaseReadable" || fault == "current" {
					wantStage = "original-witness"
				}
				if err != ErrFixtures || observation != nil || !injected || gate.String() != fault || h.gets != 0 {
					t.Fatal("actual refusal was accepted or misattributed", gate, stage)
				}
				if fault != "baseline" && f.phaseFloor != nil {
					t.Fatal("refused read advanced its floor")
				}
			}
			if stage != wantStage || slot != -1 {
				t.Fatal("gate attribution lost existing substage", stage, slot)
			}
			f.identity, f.ackSlot = identity, -1 // restore only injected test memory
			phaseBarrierUnchanged(t, h, body, identity)
			// The same recorder must not carry an earlier gate into a later read.
			if fault != "healthy" {
				f.phaseFloor = nil
				h.f.actor.fixtureHandler = base
				if observation, err := h.f.wire.observePhase(ctx); err != nil || observation == nil || trace.phaseGateSnapshot() != phaseGateUnknown {
					t.Fatal("later complete invocation inherited a failed gate")
				}
			}
		})
	}
}

func TestFixturePhaseGateDiagnosticWorlds(t *testing.T) {
	f := newFixtureWireTest(t)
	if f.wire.ledger.sealOriginalWorlds([]fixtureWorldRow{}) != nil {
		t.Fatal("legacy companion setup unavailable")
	}
	trace := &admissionTrace{}
	if observation, err := f.wire.observePhase(context.WithValue(t.Context(), admissionTraceKey{}, trace)); observation != nil || err != ErrFixtures || trace.phaseGateSnapshot() != phaseGateWorlds || f.wire.ledger.phaseFloor != nil {
		t.Fatal("legacy companion refusal was lost or misattributed")
	}
}

func TestFixturePhaseGateDiagnosticLeaders(t *testing.T) {
	h := fixtureWarmPhaseFactory(t)(t)
	f := h.f.wire.ledger
	body, identity := bytes.Clone(f.body), f.identity
	injected := false
	h.gcRows = func(source installobserve.GCResource, rows []metav1.PartialObjectMetadata) []metav1.PartialObjectMetadata {
		if source.Kind == "Lease" {
			for _, object := range h.extra {
				if object.GetKind() == "Lease" {
					// Coherent whole/metadata reads still must refuse a changed
					// holder against the sealed original controller chain.
					if unstructured.SetNestedField(object.Object, "foreign-holder", "spec", "holderIdentity") != nil {
						t.Error("leader fault setup unavailable")
					}
					injected = true
				}
			}
		}
		return rows
	}
	trace := &admissionTrace{}
	observation, err := h.f.wire.observePhase(context.WithValue(t.Context(), admissionTraceKey{}, trace))
	stage, _ := trace.phaseSnapshot()
	if observation != nil || err != ErrFixtures || !injected || trace.phaseGateSnapshot() != phaseGateLeaders || stage != "original-leaders" || f.phaseFloor != nil {
		t.Fatal("changed leader holder was accepted or misattributed", trace.phaseGateSnapshot(), stage)
	}
	phaseBarrierUnchanged(t, h, body, identity)
}

func TestFixturePhaseGateDiagnosticAggregationAndOptIn(t *testing.T) {
	for _, ctx := range []context.Context{nil, t.Context(), context.WithValue(t.Context(), admissionTraceKey{}, "private-canary"), context.WithValue(t.Context(), admissionTraceKey{}, (*admissionTrace)(nil))} {
		if !phaseGateFailed(ctx, phaseGateCurrent, true) || phaseGateFailed(ctx, phaseGateCurrent, false) {
			t.Fatal("optional diagnostic changed predicate")
		}
	}
	trace := &admissionTrace{}
	ctx := context.WithValue(t.Context(), admissionTraceKey{}, trace)
	var d warmPhaseReadDiagnostic
	for range 2 {
		traceAdmissionPhase(ctx, admissionPhaseOriginal, -1)
		traceAdmissionPhase(ctx, admissionPhaseConfigured, -1)
		phaseGateFailed(ctx, phaseGateLocalBarrier, true)
		phaseGateFailed(ctx, phaseGateRemote, true) // preserve the helper's first refusal
		d.attempts++
		d.record(trace.phaseGateSnapshot(), trace)
	}
	traceAdmissionPhase(ctx, admissionPhaseOriginal, -1)
	phaseGateFailed(ctx, phaseGateCurrent, true) // final cancelled attempt
	d.attempts++
	d.record(trace.phaseGateSnapshot(), trace)
	want := "attempts=3 last-gate=current current=1[last-stage=original-witness slot=-1] localBarrier=2[last-stage=configured slot=-1]"
	if d.String() != want {
		t.Fatal("poll diagnostics lost earlier repeated failures", d.String())
	}
	traceAdmission(ctx, admissionSetupObservation, -1)
	if trace.phaseGateSnapshot() != phaseGateUnknown || (*admissionTrace)(nil).phaseGateSnapshot() != phaseGateUnknown {
		t.Fatal("outer reset or absent recorder retained a gate")
	}
	ctx, lifecycle := WithLifecycleDiagnostic(t.Context())
	phaseGateFailed(ctx, phaseGateBaseline, true)
	traceLifecycleCheckpoint(ctx, AdmissionEffective, lifecycleDiagnosticEntered)
	if lifecycle.admission.phaseGateSnapshot() != phaseGateUnknown {
		t.Fatal("new checkpoint retained a prior phase gate")
	}
}
