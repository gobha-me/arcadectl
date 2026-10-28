// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installobserve"
	coordinationv1 "k8s.io/api/coordination/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestFixturePhaseGateClosedLabelsAndSnapshotBounds(t *testing.T) {
	wantLabels := map[fixturePhaseGate]string{
		phaseGateUnknown:      "unknown",
		phaseGateReadable:     "phaseReadable",
		phaseGateCurrent:      "current",
		phaseGateWorlds:       "worlds",
		phaseGateLocalBarrier: "localBarrier",
		phaseGateRemote:       "remote",
		phaseGateBaseline:     "baseline",
		phaseGateLeaders:      "leaders",
	}
	for raw := range 256 {
		gate := fixturePhaseGate(raw)
		want, ok := wantLabels[gate]
		if !ok {
			want = "unknown"
		}
		if got := gate.String(); got != want {
			t.Fatalf("gate %d String() = %q, want %q", raw, got, want)
		}
	}
	if got := (^fixturePhaseGate(0)).String(); got != "unknown" {
		t.Fatalf("max uint32 gate String() = %q, want unknown", got)
	}

	var nilTrace *admissionTrace
	if got := nilTrace.phaseGateSnapshot(); got != phaseGateUnknown || got.String() != "unknown" {
		t.Fatalf("nil trace phaseGateSnapshot() = %v (%q), want unknown", got, got.String())
	}

	trace := &admissionTrace{}
	if got := trace.phaseGateSnapshot(); got != phaseGateUnknown {
		t.Fatalf("zero trace phaseGateSnapshot() = %v, want unknown", got)
	}
	for gate := phaseGateReadable; gate <= phaseGateLeaders; gate++ {
		trace.phaseGate.Store(uint32(gate))
		if got := trace.phaseGateSnapshot(); got != gate || got.String() != wantLabels[gate] {
			t.Fatalf("stored gate %v snapshot = %v (%q), want %v (%q)", gate, got, got.String(), gate, wantLabels[gate])
		}
	}
	for _, outOfBounds := range []uint32{uint32(phaseGateLeaders + 1), 8, 255, 0xffffffff} {
		trace.phaseGate.Store(outOfBounds)
		if got := trace.phaseGateSnapshot(); got != phaseGateUnknown || got.String() != "unknown" {
			t.Fatalf("corrupted phaseGate %#x snapshot = %v (%q), want unknown", outOfBounds, got, got.String())
		}
	}
}

func TestPhaseGateFailedPassThroughNilEmptyAndFirstRefusalWins(t *testing.T) {
	var nilTrace *admissionTrace
	untracedContexts := []context.Context{
		nil,
		t.Context(),
		context.WithValue(t.Context(), admissionTraceKey{}, nilTrace),
		context.WithValue(t.Context(), admissionTraceKey{}, "PRIVATE-CANARY"),
	}
	candidateGates := []fixturePhaseGate{
		phaseGateUnknown,
		phaseGateReadable,
		phaseGateCurrent,
		phaseGateWorlds,
		phaseGateLocalBarrier,
		phaseGateRemote,
		phaseGateBaseline,
		phaseGateLeaders,
		phaseGateLeaders + 1,
		fixturePhaseGate(255),
		^fixturePhaseGate(0),
	}
	for _, ctx := range untracedContexts {
		for _, gate := range candidateGates {
			if phaseGateFailed(ctx, gate, false) {
				t.Fatalf("phaseGateFailed(false) returned true for gate %d", gate)
			}
			if !phaseGateFailed(ctx, gate, true) {
				t.Fatalf("phaseGateFailed(true) returned false for gate %d", gate)
			}
		}
	}

	trace := &admissionTrace{}
	ctx := context.WithValue(t.Context(), admissionTraceKey{}, trace)
	for _, gate := range candidateGates {
		if phaseGateFailed(ctx, gate, false) {
			t.Fatalf("traced phaseGateFailed(false) returned true for gate %d", gate)
		}
		if got := trace.phaseGateSnapshot(); got != phaseGateUnknown {
			t.Fatalf("false predicate recorded gate %v", got)
		}
	}
	for _, invalidGate := range []fixturePhaseGate{phaseGateUnknown, phaseGateLeaders + 1, fixturePhaseGate(255), ^fixturePhaseGate(0)} {
		if !phaseGateFailed(ctx, invalidGate, true) {
			t.Fatalf("phaseGateFailed(true) returned false for invalid gate %d", invalidGate)
		}
		if got := trace.phaseGateSnapshot(); got != phaseGateUnknown {
			t.Fatalf("invalid gate %d recorded %v", invalidGate, got)
		}
	}

	validGates := []fixturePhaseGate{
		phaseGateReadable,
		phaseGateCurrent,
		phaseGateWorlds,
		phaseGateLocalBarrier,
		phaseGateRemote,
		phaseGateBaseline,
		phaseGateLeaders,
	}
	for _, first := range validGates {
		for _, second := range validGates {
			pairTrace := &admissionTrace{}
			pairCtx := context.WithValue(t.Context(), admissionTraceKey{}, pairTrace)
			if !phaseGateFailed(pairCtx, first, true) {
				t.Fatalf("first refusal %v returned false", first)
			}
			if got := pairTrace.phaseGateSnapshot(); got != first {
				t.Fatalf("first refusal snapshot = %v, want %v", got, first)
			}
			if phaseGateFailed(pairCtx, second, false) {
				t.Fatalf("subsequent false predicate for %v returned true", second)
			}
			if !phaseGateFailed(pairCtx, second, true) {
				t.Fatalf("second refusal %v returned false", second)
			}
			if got := pairTrace.phaseGateSnapshot(); got != first {
				t.Fatalf("second refusal %v overwrote first refusal %v (got %v)", second, first, got)
			}
		}
	}

	// Concurrent CAS verification: pre-seeded refusal is never overwritten,
	// and unseeded concurrent refusals converge on a single valid winner.
	pinnedTrace := &admissionTrace{}
	pinnedCtx := context.WithValue(t.Context(), admissionTraceKey{}, pinnedTrace)
	if !phaseGateFailed(pinnedCtx, phaseGateReadable, true) {
		t.Fatal("initial refusal returned false")
	}
	var wg sync.WaitGroup
	for worker, gate := range validGates {
		wg.Go(func() {
			for iter := range 300 {
				if phaseGateFailed(pinnedCtx, gate, false) {
					t.Errorf("worker %d iter %d false predicate returned true", worker, iter)
					return
				}
				if !phaseGateFailed(pinnedCtx, gate, true) {
					t.Errorf("worker %d iter %d true predicate returned false", worker, iter)
					return
				}
				if got := pinnedTrace.phaseGateSnapshot(); got != phaseGateReadable {
					t.Errorf("worker %d iter %d concurrent refusal overwrote first gate: got %v", worker, iter, got)
					return
				}
			}
		})
	}
	wg.Wait()

	for round := range 50 {
		raceTrace := &admissionTrace{}
		raceCtx := context.WithValue(t.Context(), admissionTraceKey{}, raceTrace)
		start := make(chan struct{})
		var raceGroup sync.WaitGroup
		for index, gate := range validGates {
			nextGate := validGates[(index+1)%len(validGates)]
			raceGroup.Go(func() {
				<-start
				if !phaseGateFailed(raceCtx, gate, true) || !phaseGateFailed(raceCtx, nextGate, true) {
					t.Errorf("round %d concurrent true predicate returned false", round)
				}
			})
		}
		close(start)
		raceGroup.Wait()
		winner := raceTrace.phaseGateSnapshot()
		if winner < phaseGateReadable || winner > phaseGateLeaders || winner.String() == "unknown" {
			t.Fatalf("round %d concurrent CAS produced invalid gate %v (%q)", round, winner, winner.String())
		}
		for _, gate := range validGates {
			if !phaseGateFailed(raceCtx, gate, true) || raceTrace.phaseGateSnapshot() != winner {
				t.Fatalf("round %d winner %v mutated by post-race refusal %v", round, winner, gate)
			}
		}
	}
}

func TestPhaseGateTraceResetsAcrossOuterStepPhaseAndCheckpoint(t *testing.T) {
	trace := &admissionTrace{}
	ctx := context.WithValue(t.Context(), admissionTraceKey{}, trace)

	// traceAdmission resets phaseGate only on valid outer step transitions.
	phaseGateFailed(ctx, phaseGateRemote, true)
	traceAdmission(nil, admissionCaseProbe, 0)
	traceAdmission(ctx, admissionStep(255), 0)
	traceAdmission(ctx, admissionCaseProbe, 999)
	if got := trace.phaseGateSnapshot(); got != phaseGateRemote {
		t.Fatalf("invalid traceAdmission cleared phaseGate: got %v, want remote", got)
	}
	traceAdmission(ctx, admissionCaseProbe, 0)
	if got := trace.phaseGateSnapshot(); got != phaseGateUnknown {
		t.Fatalf("valid traceAdmission did not reset phaseGate: got %v, want unknown", got)
	}

	// traceAdmissionPhase resets phaseGate on admissionPhaseOriginal only,
	// preserving inner gate attribution across later substages.
	phaseGateFailed(ctx, phaseGateLocalBarrier, true)
	for _, preserved := range []struct {
		step admissionPhaseStep
		slot int
	}{
		{admissionPhaseWorlds, -1},
		{admissionPhaseConfigured, -1},
		{admissionPhaseOpening, -1},
		{admissionPhaseTyped, -1},
		{admissionPhaseRows, -1},
		{admissionPhasePublicBefore, -1},
		{admissionPhaseNamedGet, 0},
		{admissionPhaseWholeFixture, 0},
		{admissionPhaseStorage, -1},
		{admissionPhaseGC, -1},
		{admissionPhaseLeaders, -1},
		{admissionPhaseOwners, -1},
		{admissionPhaseOwnerLocalClosing, -1},
		{admissionPhasePublicAfter, -1},
		{admissionPhaseFixtureCorrelation, -1},
		{admissionPhaseFinalConfigured, -1},
		{admissionPhaseFinalPublic, -1},
		{admissionPhaseComplete, -1},
		{admissionPhaseOriginal, 0}, // invalid slot for admissionPhaseOriginal
	} {
		traceAdmissionPhase(ctx, preserved.step, preserved.slot)
		if got := trace.phaseGateSnapshot(); got != phaseGateLocalBarrier {
			t.Fatalf("substage %v (slot %d) cleared phaseGate: got %v, want localBarrier", preserved.step, preserved.slot, got)
		}
	}
	traceAdmissionPhase(ctx, admissionPhaseOriginal, -1)
	if got := trace.phaseGateSnapshot(); got != phaseGateUnknown {
		t.Fatalf("admissionPhaseOriginal did not reset phaseGate: got %v, want unknown", got)
	}

	// traceLifecycleCheckpoint resets phaseGate on lifecycleDiagnosticEntered,
	// while preserving it on lifecycleDiagnosticRefused and lifecycleDiagnosticPassed.
	lifeCtx, diagnostic := WithLifecycleDiagnostic(t.Context())
	traceLifecycleCheckpoint(lifeCtx, AdmissionEffective, lifecycleDiagnosticEntered)
	phaseGateFailed(lifeCtx, phaseGateLeaders, true)
	if got := diagnostic.admission.phaseGateSnapshot(); got != phaseGateLeaders {
		t.Fatalf("lifecycle admission trace did not record gate: got %v, want leaders", got)
	}
	traceLifecycleCheckpoint(lifeCtx, AdmissionEffective, lifecycleDiagnosticRefused)
	if got := diagnostic.admission.phaseGateSnapshot(); got != phaseGateLeaders {
		t.Fatalf("lifecycleDiagnosticRefused cleared phaseGate: got %v, want leaders", got)
	}
	traceLifecycleCheckpoint(lifeCtx, AdmissionEffective, lifecycleDiagnosticPassed)
	if got := diagnostic.admission.phaseGateSnapshot(); got != phaseGateLeaders {
		t.Fatalf("lifecycleDiagnosticPassed cleared phaseGate: got %v, want leaders", got)
	}
	traceLifecycleCheckpoint(lifeCtx, Checkpoint(255), lifecycleDiagnosticEntered)
	if got := diagnostic.admission.phaseGateSnapshot(); got != phaseGateLeaders {
		t.Fatalf("invalid checkpoint cleared phaseGate: got %v, want leaders", got)
	}
	traceLifecycleCheckpoint(lifeCtx, ColdSafety, lifecycleDiagnosticEntered)
	if got := diagnostic.admission.phaseGateSnapshot(); got != phaseGateUnknown {
		t.Fatalf("entering new checkpoint did not reset phaseGate: got %v, want unknown", got)
	}
}

func TestObservePhaseRefusalGateAttributionAndNamedSlots(t *testing.T) {
	// Nil/empty receiver and context guards.
	nilTrace := &admissionTrace{}
	nilTraceCtx := context.WithValue(t.Context(), admissionTraceKey{}, nilTrace)
	var nilWire *fixtureWire
	if obs, err := nilWire.observePhase(nilTraceCtx); obs != nil || err != ErrFixtures || nilTrace.phaseGateSnapshot() != phaseGateUnknown {
		t.Fatalf("nil wire observePhase = (%v, %v), gate=%v", obs, err, nilTrace.phaseGateSnapshot())
	}
	emptyWire := &fixtureWire{}
	if obs, err := emptyWire.observePhase(nilTraceCtx); obs != nil || err != ErrFixtures || nilTrace.phaseGateSnapshot() != phaseGateUnknown {
		t.Fatalf("empty wire observePhase = (%v, %v), gate=%v", obs, err, nilTrace.phaseGateSnapshot())
	}

	// Legacy world-only companion has a valid WAL + companion seal (so original-witness
	// passes) and nil worlds.Phase, refusing at sealed-worlds with phaseGateWorlds.
	t.Run("worlds-legacy-companion", func(t *testing.T) {
		f := newFixtureWireTest(t)
		if f.wire.ledger.sealOriginalWorlds([]fixtureWorldRow{}) != nil {
			t.Fatal("legacy world companion unavailable")
		}
		trace := &admissionTrace{}
		obs, err := f.wire.observePhase(context.WithValue(t.Context(), admissionTraceKey{}, trace))
		if obs != nil || err != ErrFixtures {
			t.Fatalf("worlds-legacy-companion: observePhase = (%v, %v), want (nil, ErrFixtures)", obs, err)
		}
		gotGate := trace.phaseGateSnapshot()
		gotStep, gotSlot := trace.phaseSnapshot()
		if gotGate != phaseGateWorlds || gotStep != "sealed-worlds" || gotSlot != -1 {
			t.Fatalf("worlds-legacy-companion: trace = (gate=%v, step=%q, slot=%d), want (gate=worlds, step=sealed-worlds, slot=-1)",
				gotGate, gotStep, gotSlot)
		}
	})

	newPhase := fixturePhaseFactory(t)
	control := newPhase(t)
	if obs, err := control.f.wire.observePhase(nil); obs != nil || err != ErrFixtures {
		t.Fatalf("nil context observePhase = (%v, %v), want (nil, ErrFixtures)", obs, err)
	}
	controlTrace := &admissionTrace{}
	controlCtx := context.WithValue(t.Context(), admissionTraceKey{}, controlTrace)
	phaseGateFailed(controlCtx, phaseGateLeaders, true)
	if obs, err := control.f.wire.observePhase(controlCtx); obs == nil || err != nil {
		t.Fatalf("control observePhase failed: %v", err)
	}
	if stage, slot := controlTrace.phaseSnapshot(); stage != "complete" || slot != -1 || controlTrace.phaseGateSnapshot() != phaseGateUnknown {
		t.Fatalf("control observePhase trace = (%q, %d, %v), want (complete, -1, unknown)", stage, slot, controlTrace.phaseGateSnapshot())
	}
	publicGetsPerSweep := len(control.f.wire.ledger.phaseFloor.Public) - 1
	if publicGetsPerSweep <= 0 {
		t.Fatal("expected non-empty public inventory floor")
	}

	replaceWAL := func(t *testing.T, ledger *fixtureLedger) {
		t.Helper()
		id := ledger.identity
		if _, err := ledger.engine.files.AtomicWrite(ledger.name, bytes.Clone(ledger.body), &id); err != nil {
			t.Fatalf("atomic WAL replacement failed: %v", err)
		}
	}
	mutatePublicServiceRV := func(h *fixturePhaseTest, rv string) {
		for key, obj := range h.f.actor.v.f.access.objects {
			if key.Kind == "Service" {
				obj.SetResourceVersion(rv)
				return
			}
		}
	}

	cases := []struct {
		name     string
		wantGate fixturePhaseGate
		wantStep string
		wantSlot int
	}{
		{name: "readable-initial", wantGate: phaseGateReadable, wantStep: "original-witness", wantSlot: -1},
		{name: "current-initial", wantGate: phaseGateCurrent, wantStep: "original-witness", wantSlot: -1},
		{name: "configured-remote", wantGate: phaseGateRemote, wantStep: "configured", wantSlot: -1},
		{name: "configured-local-barrier", wantGate: phaseGateLocalBarrier, wantStep: "configured", wantSlot: -1},
		{name: "configured-baseline-floor", wantGate: phaseGateBaseline, wantStep: "configured", wantSlot: -1},
		{name: "typed-remote", wantGate: phaseGateRemote, wantStep: "typed-collections", wantSlot: -1},
		{name: "typed-local-barrier", wantGate: phaseGateLocalBarrier, wantStep: "typed-collections", wantSlot: -1},
		{name: "rows-remote", wantGate: phaseGateRemote, wantStep: "original-row-missing-fixture", wantSlot: -1},
		{name: "public-before-baseline-first-wins", wantGate: phaseGateBaseline, wantStep: "public-before", wantSlot: -1},
		{name: "public-before-remote", wantGate: phaseGateRemote, wantStep: "public-before", wantSlot: -1},
		{name: "public-before-local-barrier", wantGate: phaseGateLocalBarrier, wantStep: "public-before", wantSlot: -1},
		{name: "named-get-remote-slot", wantGate: phaseGateRemote, wantStep: "named-result", wantSlot: fixturePlainPod},
		{name: "named-get-absent-baseline-slot", wantGate: phaseGateBaseline, wantStep: "named-result", wantSlot: fixturePlainPod},
		{name: "named-get-local-barrier-slot", wantGate: phaseGateLocalBarrier, wantStep: "named-result", wantSlot: fixturePlainPod},
		{name: "whole-fixture-validate-baseline-slot", wantGate: phaseGateBaseline, wantStep: "whole-fixture", wantSlot: fixturePlainPod},
		{name: "whole-fixture-decode-baseline-slot", wantGate: phaseGateBaseline, wantStep: "whole-fixture", wantSlot: fixturePlainPod},
		{name: "gc-remote", wantGate: phaseGateRemote, wantStep: "gc-metadata-pages", wantSlot: -1},
		{name: "owners-baseline", wantGate: phaseGateBaseline, wantStep: "owner-typed-metadata", wantSlot: -1},
		{name: "public-after-baseline", wantGate: phaseGateBaseline, wantStep: "public-after", wantSlot: -1},
		{name: "public-after-current", wantGate: phaseGateCurrent, wantStep: "public-after", wantSlot: -1},
		{name: "fixture-correlation-baseline", wantGate: phaseGateBaseline, wantStep: "fixture-correlation", wantSlot: -1},
		{name: "final-configured-remote", wantGate: phaseGateRemote, wantStep: "final-configured", wantSlot: -1},
		{name: "final-configured-baseline", wantGate: phaseGateBaseline, wantStep: "final-configured", wantSlot: -1},
		{name: "final-configured-local-barrier", wantGate: phaseGateLocalBarrier, wantStep: "final-configured", wantSlot: -1},
		{name: "final-public-remote", wantGate: phaseGateRemote, wantStep: "final-public", wantSlot: -1},
		{name: "final-public-baseline", wantGate: phaseGateBaseline, wantStep: "final-public", wantSlot: -1},
		{name: "final-public-current", wantGate: phaseGateCurrent, wantStep: "final-public", wantSlot: -1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newPhase(t)
			f := h.f
			ledger := f.wire.ledger
			acknowledgeAllRecipeFixtures(t, ledger)
			created := time.Now().UTC().Truncate(time.Second).Add(-20 * time.Second)
			for slot := range fixtureCatalog {
				f.objects[slot] = fixtureResultExample(t, ledger, slot, fixtureStableResult, created)
			}

			trace := &admissionTrace{}
			base := f.actor.fixtureHandler
			stagePublicGets := map[string]int{}

			updatedIdentity := false
			switch tc.name {
			case "readable-initial":
				ledger.seedAck = true
			case "current-initial":
				for key, obj := range f.actor.v.f.access.objects {
					if key.Kind == "ServiceAccount" {
						obj.SetUID("replaced-uid")
						break
					}
				}
			case "configured-remote":
				policyCalls := 0
				f.actor.fixtureHandler = func(w http.ResponseWriter, r *http.Request) bool {
					if testRuntimeConfigurationRequest(r) && strings.HasSuffix(r.URL.Path, "/validatingadmissionpolicies") {
						policyCalls++
						if policyCalls == 2 {
							w.WriteHeader(http.StatusForbidden)
							return true
						}
					}
					return base(w, r)
				}
			case "configured-local-barrier":
				replaced := false
				f.actor.fixtureHandler = func(w http.ResponseWriter, r *http.Request) bool {
					handled := base(w, r)
					stage, _ := trace.phaseSnapshot()
					if stage == "configured" && !replaced && testRuntimeConfigurationRequest(r) && strings.HasSuffix(r.URL.Path, "/validatingadmissionpolicybindings") {
						replaceWAL(t, ledger)
						replaced = true
					}
					return handled
				}
			case "configured-baseline-floor":
				ledger.phaseFloor = &fixturePhaseBaseline{Version: "corrupt-floor"}
			case "typed-remote":
				f.actor.fixtureHandler = func(w http.ResponseWriter, r *http.Request) bool {
					stage, _ := trace.phaseSnapshot()
					if stage == "typed-collections" && r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/pods") {
						w.WriteHeader(http.StatusInternalServerError)
						return true
					}
					return base(w, r)
				}
			case "typed-local-barrier":
				h.afterList = func(n int) {
					if n == 1 {
						replaceWAL(t, ledger)
					}
				}
			case "rows-remote":
				h.hide[fixturePlainPod] = true
			case "public-before-baseline-first-wins":
				mutatePublicServiceRV(h, "999")
			case "public-before-remote":
				for key, obj := range f.actor.v.f.access.objects {
					if key.Kind == "Service" {
						_ = unstructured.SetNestedField(obj.Object, "ExternalName", "spec", "type")
						break
					}
				}
			case "public-before-local-barrier":
				h.afterPublicGet = func(int) {
					stage, _ := trace.phaseSnapshot()
					stagePublicGets[stage]++
					if stage == "public-before" && stagePublicGets[stage] == publicGetsPerSweep {
						replaceWAL(t, ledger)
					}
				}
			case "named-get-remote-slot":
				h.afterPublicGet = func(int) {
					stage, _ := trace.phaseSnapshot()
					stagePublicGets[stage]++
					if stage == "public-before" && stagePublicGets[stage] == publicGetsPerSweep {
						f.objects[fixturePlainPod].SetUID("b0000000-0000-4000-8000-000000000001")
					}
				}
			case "named-get-absent-baseline-slot":
				h.extra = append(h.extra, f.objects[fixturePlainPod].DeepCopy())
				delete(f.objects, fixturePlainPod)
			case "named-get-local-barrier-slot":
				h.afterGet = func(slot int) {
					if slot == fixturePlainPod {
						id := ledger.identity
						newID, err := ledger.engine.files.AtomicWrite(ledger.name, bytes.Clone(ledger.body), &id)
						if err != nil {
							t.Fatalf("atomic WAL rewrite failed: %v", err)
						}
						ledger.identity = newID
						updatedIdentity = true
						h.afterGet = nil
					}
				}
			case "whole-fixture-validate-baseline-slot":
				_ = unstructured.SetNestedField(f.objects[fixturePlainPod].Object, "default", "spec", "nodeName")
			case "whole-fixture-decode-baseline-slot":
				h.afterList = func(n int) {
					if n == 7 {
						f.objects[fixturePlainPod].SetResourceVersion("999")
					}
				}
			case "gc-remote":
				h.gcRows = func(source installobserve.GCResource, rows []metav1.PartialObjectMetadata) []metav1.PartialObjectMetadata {
					if source.Kind == "Widget" {
						rows = append(rows, metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{
							Name:            "orphan-widget",
							Namespace:       ledger.document.Entries[fixturePlainPod].Key.Namespace,
							UID:             "custom-child",
							ResourceVersion: "101",
							OwnerReferences: []metav1.OwnerReference{{
								APIVersion: "v1",
								Kind:       "Pod",
								Name:       ledger.document.Entries[fixturePlainPod].Key.Name,
								UID:        ledger.document.Entries[fixturePlainPod].OriginalUID,
							}},
						}})
					}
					return rows
				}
			case "owners-baseline":
				h.gcRows = func(source installobserve.GCResource, rows []metav1.PartialObjectMetadata) []metav1.PartialObjectMetadata {
					if source.Kind == "Pod" && len(rows) > 0 {
						rows[0].ResourceVersion = "999"
					}
					return rows
				}
			case "public-after-baseline":
				h.afterGet = func(slot int) {
					if slot == fixtureCancelledDestroy {
						mutatePublicServiceRV(h, "999")
						h.afterGet = nil
					}
				}
			case "public-after-current":
				h.afterPublicGet = func(int) {
					stage, _ := trace.phaseSnapshot()
					stagePublicGets[stage]++
					if stage == "public-after" && stagePublicGets[stage] == publicGetsPerSweep {
						replaceWAL(t, ledger)
					}
				}
			case "fixture-correlation-baseline":
				mutated := false
				f.actor.fixtureHandler = func(w http.ResponseWriter, r *http.Request) bool {
					stage, _ := trace.phaseSnapshot()
					if stage == "typed-collections" && !mutated && ledger.phaseFloor != nil {
						f.objects[fixturePlainPod].SetResourceVersion("102")
						mutated = true
					}
					return base(w, r)
				}
			case "final-configured-remote":
				policyCalls := 0
				f.actor.fixtureHandler = func(w http.ResponseWriter, r *http.Request) bool {
					if testRuntimeConfigurationRequest(r) && strings.HasSuffix(r.URL.Path, "/validatingadmissionpolicies") {
						policyCalls++
						if policyCalls == 5 {
							w.WriteHeader(http.StatusForbidden)
							return true
						}
					}
					return base(w, r)
				}
			case "final-configured-baseline":
				policyCalls := 0
				f.actor.fixtureHandler = func(w http.ResponseWriter, r *http.Request) bool {
					if testRuntimeConfigurationRequest(r) && strings.HasSuffix(r.URL.Path, "/validatingadmissionpolicies") {
						policyCalls++
						if policyCalls == 5 {
							for key, obj := range f.actor.v.f.access.objects {
								if key.Kind == "ValidatingAdmissionPolicy" {
									obj.SetResourceVersion("999")
									break
								}
							}
						}
					}
					return base(w, r)
				}
			case "final-configured-local-barrier":
				replaced := false
				f.actor.fixtureHandler = func(w http.ResponseWriter, r *http.Request) bool {
					handled := base(w, r)
					stage, _ := trace.phaseSnapshot()
					if stage == "final-configured" && !replaced && testRuntimeConfigurationRequest(r) && strings.HasSuffix(r.URL.Path, "/validatingadmissionpolicybindings") {
						replaceWAL(t, ledger)
						replaced = true
					}
					return handled
				}
			case "final-public-remote":
				mutated := false
				f.actor.fixtureHandler = func(w http.ResponseWriter, r *http.Request) bool {
					stage, _ := trace.phaseSnapshot()
					if stage == "final-public" && !mutated {
						for key, obj := range f.actor.v.f.access.objects {
							if key.Kind == "Service" {
								_ = unstructured.SetNestedField(obj.Object, "ExternalName", "spec", "type")
								break
							}
						}
						mutated = true
					}
					return base(w, r)
				}
			case "final-public-baseline":
				mutated := false
				f.actor.fixtureHandler = func(w http.ResponseWriter, r *http.Request) bool {
					stage, _ := trace.phaseSnapshot()
					if stage == "final-public" && !mutated {
						mutatePublicServiceRV(h, "999")
						mutated = true
					}
					return base(w, r)
				}
			case "final-public-current":
				h.afterPublicGet = func(int) {
					stage, _ := trace.phaseSnapshot()
					stagePublicGets[stage]++
					if stage == "final-public" && stagePublicGets[stage] == publicGetsPerSweep {
						replaceWAL(t, ledger)
					}
				}
			}

			beforeBody := bytes.Clone(ledger.body)
			beforeIdentity := ledger.identity
			obs, err := f.wire.observePhase(context.WithValue(t.Context(), admissionTraceKey{}, trace))
			if obs != nil || err != ErrFixtures {
				t.Fatalf("%s: observePhase = (%v, %v), want (nil, ErrFixtures)", tc.name, obs != nil, err)
			}
			gotGate := trace.phaseGateSnapshot()
			gotStep, gotSlot := trace.phaseSnapshot()
			if gotGate != tc.wantGate || gotStep != tc.wantStep || gotSlot != tc.wantSlot {
				t.Fatalf("%s: trace = (gate=%v, step=%q, slot=%d), want (gate=%v, step=%q, slot=%d)",
					tc.name, gotGate, gotStep, gotSlot, tc.wantGate, tc.wantStep, tc.wantSlot)
			}
			if updatedIdentity {
				beforeIdentity = ledger.identity
			}
			if !bytes.Equal(beforeBody, ledger.body) || beforeIdentity != ledger.identity || f.creates != 0 || f.deletes != 0 || f.seeds != 0 {
				t.Fatalf("%s: refusal mutated ledger or issued an effect", tc.name)
			}
		})
	}
}

func TestObservePhaseV3AndLeadersGateAttribution(t *testing.T) {
	newV3 := fixtureV3PhaseFactory(t)
	control := newV3(t)
	if obs, err := control.f.wire.observePhase(t.Context()); obs == nil || err != nil {
		t.Fatalf("v3 control observePhase failed: %v", err)
	}
	publicGetsPerSweep := len(control.f.wire.ledger.phaseFloor.Public) - 1
	if publicGetsPerSweep <= 0 {
		t.Fatal("expected non-empty v3 public inventory floor")
	}

	replaceWAL := func(t *testing.T, ledger *fixtureLedger) {
		t.Helper()
		id := ledger.identity
		if _, err := ledger.engine.files.AtomicWrite(ledger.name, bytes.Clone(ledger.body), &id); err != nil {
			t.Fatalf("atomic WAL replacement failed: %v", err)
		}
	}

	for _, scenario := range []struct {
		name     string
		wantGate fixturePhaseGate
		wantStep string
	}{
		{name: "v3-rows-accounts-remote", wantGate: phaseGateRemote, wantStep: "original-rows"},
		{name: "v3-public-after-local-barrier", wantGate: phaseGateLocalBarrier, wantStep: "public-after"},
		{name: "v3-public-after-accounts-baseline", wantGate: phaseGateBaseline, wantStep: "public-after"},
		{name: "v3-public-after-accounts-current", wantGate: phaseGateCurrent, wantStep: "public-after"},
		{name: "v3-final-public-local-barrier", wantGate: phaseGateLocalBarrier, wantStep: "final-public"},
		{name: "v3-final-public-accounts-baseline", wantGate: phaseGateBaseline, wantStep: "final-public"},
		{name: "v3-final-public-accounts-current", wantGate: phaseGateCurrent, wantStep: "final-public"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			h := newV3(t)
			ledger := h.f.wire.ledger
			acknowledgeAllRecipeFixtures(t, ledger)
			created := time.Now().UTC().Truncate(time.Second).Add(-20 * time.Second)
			for slot := range ledger.document.Entries {
				h.f.objects[slot] = fixtureResultExample(t, ledger, slot, fixtureStableResult, created)
			}
			trace := &admissionTrace{}
			stagePublicGets := map[string]int{}
			switch scenario.name {
			case "v3-rows-accounts-remote":
				h.extra[0].Object["automountServiceAccountToken"] = "invalid-type"
			case "v3-public-after-local-barrier":
				h.afterPublicGet = func(int) {
					stage, _ := trace.phaseSnapshot()
					stagePublicGets[stage]++
					if stage == "public-after" && stagePublicGets[stage] == publicGetsPerSweep {
						replaceWAL(t, ledger)
					}
				}
			case "v3-public-after-accounts-baseline":
				h.afterPublicGet = func(int) {
					stage, _ := trace.phaseSnapshot()
					stagePublicGets[stage]++
					if stage == "public-after" && stagePublicGets[stage] == publicGetsPerSweep {
						h.extra[0].SetResourceVersion("999")
					}
				}
			case "v3-public-after-accounts-current":
				h.afterPublicGet = func(int) {
					stage, _ := trace.phaseSnapshot()
					stagePublicGets[stage]++
					if stage == "public-after" && stagePublicGets[stage] == publicGetsPerSweep+1 {
						replaceWAL(t, ledger)
					}
				}
			case "v3-final-public-local-barrier":
				h.afterPublicGet = func(int) {
					stage, _ := trace.phaseSnapshot()
					stagePublicGets[stage]++
					if stage == "final-public" && stagePublicGets[stage] == publicGetsPerSweep {
						replaceWAL(t, ledger)
					}
				}
			case "v3-final-public-accounts-baseline":
				h.afterPublicGet = func(int) {
					stage, _ := trace.phaseSnapshot()
					stagePublicGets[stage]++
					if stage == "final-public" && stagePublicGets[stage] == publicGetsPerSweep {
						h.extra[0].SetResourceVersion("999")
					}
				}
			case "v3-final-public-accounts-current":
				h.afterPublicGet = func(int) {
					stage, _ := trace.phaseSnapshot()
					stagePublicGets[stage]++
					if stage == "final-public" && stagePublicGets[stage] == publicGetsPerSweep+1 {
						replaceWAL(t, ledger)
					}
				}
			}

			obs, err := h.f.wire.observePhase(context.WithValue(t.Context(), admissionTraceKey{}, trace))
			if obs != nil || err != ErrFixtures {
				t.Fatalf("%s: observePhase = (%v, %v), want (nil, ErrFixtures)", scenario.name, obs != nil, err)
			}
			gotGate := trace.phaseGateSnapshot()
			gotStep, gotSlot := trace.phaseSnapshot()
			if gotGate != scenario.wantGate || gotStep != scenario.wantStep || gotSlot != -1 {
				t.Fatalf("%s: trace = (gate=%v, step=%q, slot=%d), want (gate=%v, step=%q, slot=-1)",
					scenario.name, gotGate, gotStep, gotSlot, scenario.wantGate, scenario.wantStep)
			}
		})
	}

	t.Run("warm-leaders-gate", func(t *testing.T) {
		newWarm := fixtureWarmPhaseFactory(t)
		h := newWarm(t)
		collections := 0
		regressed := false
		h.afterPublicGet = func(int) {
			if collections != 1 || regressed {
				return
			}
			regressed = true
			for _, object := range h.extra {
				if object.GetKind() == "Lease" {
					object.SetResourceVersion("101")
				}
			}
		}
		h.gcRows = func(source installobserve.GCResource, rows []metav1.PartialObjectMetadata) []metav1.PartialObjectMetadata {
			if source.Kind != "Lease" {
				return rows
			}
			collections++
			if collections == 1 {
				for _, object := range h.extra {
					if object.GetKind() != "Lease" {
						continue
					}
					lease := &coordinationv1.Lease{}
					if decodeServing(object, lease) != nil {
						t.Fatal("whole original Lease unavailable")
					}
					lease.ResourceVersion = "102"
					renew := metav1.NewMicroTime(time.Now().UTC().Truncate(time.Microsecond))
					lease.Spec.RenewTime = &renew
					managed := metav1.NewTime(renew.Time.Truncate(time.Second))
					lease.ManagedFields[0].Time = &managed
					object.Object = servingObject(t, lease).Object
				}
			}
			return rows
		}
		trace := &admissionTrace{}
		obs, err := h.f.wire.observePhase(context.WithValue(t.Context(), admissionTraceKey{}, trace))
		if obs != nil || err != ErrFixtures {
			t.Fatalf("warm-leaders-gate: observePhase = (%v, %v), want (nil, ErrFixtures)", obs != nil, err)
		}
		gotGate := trace.phaseGateSnapshot()
		gotStep, gotSlot := trace.phaseSnapshot()
		if gotGate != phaseGateLeaders || gotStep != "original-leaders" || gotSlot != -1 {
			t.Fatalf("warm-leaders-gate: trace = (gate=%v, step=%q, slot=%d), want (gate=leaders, step=original-leaders, slot=-1)",
				gotGate, gotStep, gotSlot)
		}
	})
}
