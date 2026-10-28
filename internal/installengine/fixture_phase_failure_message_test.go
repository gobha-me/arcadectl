// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installobserve"
	coordinationv1 "k8s.io/api/coordination/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestWarmPhaseReadFailureMessageNamesRefusedGateAcrossRealObservePhase(t *testing.T) {
	const wantPrefix = "complete original phase did not converge with both renewing native leaders"

	allGates := []fixturePhaseGate{
		phaseGateReadable,
		phaseGateCurrent,
		phaseGateWorlds,
		phaseGateLocalBarrier,
		phaseGateRemote,
		phaseGateBaseline,
		phaseGateLeaders,
		phaseGateUnknown,
	}

	assertDiagnosticAndMessage := func(t *testing.T, d *warmPhaseReadDiagnostic, wantCalls uint32, wantGate fixturePhaseGate, wantStep string, wantSlot int) {
		t.Helper()
		if d.attempts != wantCalls {
			t.Fatalf("attempts = %d, want %d", d.attempts, wantCalls)
		}
		if d.lastGate != wantGate {
			t.Fatalf("lastGate = %v (%q), want %v (%q)", d.lastGate, d.lastGate.String(), wantGate, wantGate.String())
		}
		if d.substage != wantStep || d.substage == "" || d.substage == "unknown" {
			t.Fatalf("substage = %q, want non-unknown %q", d.substage, wantStep)
		}
		if d.slot != wantSlot {
			t.Fatalf("slot = %d, want %d", d.slot, wantSlot)
		}
		if wantSlot >= 0 && d.slot == -1 {
			t.Fatalf("named-slot refusal lost slot: got -1, want %d", wantSlot)
		}
		for _, gate := range allGates {
			got := d.refusals[gate]
			if gate == wantGate {
				if got != wantCalls || got < 1 {
					t.Fatalf("refusals[%s] = %d, want %d (>=1)", gate, got, wantCalls)
				}
			} else if got != 0 {
				t.Fatalf("refusals[%s] = %d, want 0 (only %s should be counted)", gate, got, wantGate)
			}
		}

		msg := warmPhaseReadFailureMessage(d)
		if !strings.Contains(msg, wantPrefix) {
			t.Fatalf("failure message %q missing prefix %q", msg, wantPrefix)
		}
		if wantWrapped := wantPrefix + " (" + d.String() + ")"; msg != wantWrapped {
			t.Fatalf("failure message = %q, want %q", msg, wantWrapped)
		}
		for _, token := range []string{
			fmt.Sprintf("attempts=%d", wantCalls),
			"last_gate=" + wantGate.String(),
			"substage=" + wantStep,
			fmt.Sprintf("slot=%d", wantSlot),
			fmt.Sprintf("%s=%d", wantGate.String(), wantCalls),
		} {
			if !strings.Contains(msg, token) {
				t.Fatalf("failure message %q missing token %q", msg, token)
			}
		}
		for _, gate := range allGates {
			if gate == wantGate {
				continue
			}
			zeroToken := gate.String() + "=0"
			if !strings.Contains(msg, zeroToken) {
				t.Fatalf("failure message %q missing zero refusal token %q", msg, zeroToken)
			}
		}
	}

	// Gate: worlds (legacy world-only companion sealed without phase baseline).
	t.Run("worlds-gate", func(t *testing.T) {
		f := newFixtureWireTest(t)
		if f.wire.ledger.sealOriginalWorlds([]fixtureWorldRow{}) != nil {
			t.Fatal("legacy world companion unavailable")
		}
		var d warmPhaseReadDiagnostic
		const calls = 2
		for range calls {
			obs, err := f.wire.observePhaseAttributed(t.Context(), &d)
			if obs != nil || err != ErrFixtures {
				t.Fatalf("observePhaseAttributed = (%v, %v), want (nil, ErrFixtures)", obs, err)
			}
		}
		assertDiagnosticAndMessage(t, &d, calls, phaseGateWorlds, "sealed-worlds", -1)
	})

	plainFactory := fixturePhaseFactory(t)
	v3Factory := fixtureV3PhaseFactory(t)

	replaceWAL := func(t *testing.T, ledger *fixtureLedger) {
		t.Helper()
		id := ledger.identity
		if _, err := ledger.engine.files.AtomicWrite(ledger.name, bytes.Clone(ledger.body), &id); err != nil {
			t.Fatalf("atomic WAL replacement failed: %v", err)
		}
	}

	cases := []struct {
		name      string
		v3        bool
		calls     uint32
		wantGate  fixturePhaseGate
		wantStep  string
		wantSlot  int
		configure func(t *testing.T, h *fixturePhaseTest)
	}{
		{
			name:     "phaseReadable-gate",
			calls:    2,
			wantGate: phaseGateReadable,
			wantStep: "original-witness",
			wantSlot: -1,
			configure: func(_ *testing.T, h *fixturePhaseTest) {
				h.f.wire.ledger.seedAck = true
			},
		},
		{
			name:     "current-gate-initial-witness",
			calls:    2,
			wantGate: phaseGateCurrent,
			wantStep: "original-witness",
			wantSlot: -1,
			configure: func(_ *testing.T, h *fixturePhaseTest) {
				for key, obj := range h.f.actor.v.f.access.objects {
					if key.Kind == "ServiceAccount" {
						obj.SetUID("replaced-uid")
						break
					}
				}
			},
		},
		{
			name:     "localBarrier-gate-named-slot",
			calls:    1,
			wantGate: phaseGateLocalBarrier,
			wantStep: "named-result",
			wantSlot: fixturePlainPod,
			configure: func(t *testing.T, h *fixturePhaseTest) {
				ledger := h.f.wire.ledger
				h.afterGet = func(slot int) {
					if slot == fixturePlainPod {
						id := ledger.identity
						newID, err := ledger.engine.files.AtomicWrite(ledger.name, bytes.Clone(ledger.body), &id)
						if err != nil {
							t.Fatalf("atomic WAL rewrite failed: %v", err)
						}
						ledger.identity = newID
						h.afterGet = nil
					}
				}
			},
		},
		{
			name:     "localBarrier-gate-typed-collections",
			calls:    1,
			wantGate: phaseGateLocalBarrier,
			wantStep: "typed-collections",
			wantSlot: -1,
			configure: func(t *testing.T, h *fixturePhaseTest) {
				ledger := h.f.wire.ledger
				h.afterList = func(n int) {
					if n == 1 {
						replaceWAL(t, ledger)
					}
				}
			},
		},
		{
			name:     "remote-gate-named-slot",
			calls:    2,
			wantGate: phaseGateRemote,
			wantStep: "named-request",
			wantSlot: fixturePlainPod,
			configure: func(t *testing.T, h *fixturePhaseTest) {
				path, _, err := fixturePath(h.f.wire.ledger.document.Entries[fixturePlainPod].Key, false)
				if err != nil {
					t.Fatal("named path unavailable", err)
				}
				base := h.f.actor.fixtureHandler
				h.f.actor.fixtureHandler = func(w http.ResponseWriter, r *http.Request) bool {
					if r.Method == http.MethodGet && r.URL.Path == path {
						w.WriteHeader(http.StatusForbidden)
						return true
					}
					return base(w, r)
				}
			},
		},
		{
			name:     "remote-gate-accounting-missing-row",
			calls:    2,
			wantGate: phaseGateRemote,
			wantStep: "original-row-missing-fixture",
			wantSlot: -1,
			configure: func(_ *testing.T, h *fixturePhaseTest) {
				h.hide[fixturePlainPod] = true
			},
		},
		{
			name:     "remote-gate-v3-accounting-floor",
			v3:       true,
			calls:    2,
			wantGate: phaseGateRemote,
			wantStep: "original-row-floor",
			wantSlot: -1,
			configure: func(_ *testing.T, h *fixturePhaseTest) {
				h.extra = nil
			},
		},
		{
			name:     "baseline-gate-named-slot-absent",
			calls:    2,
			wantGate: phaseGateBaseline,
			wantStep: "named-result",
			wantSlot: fixturePlainPod,
			configure: func(_ *testing.T, h *fixturePhaseTest) {
				o := h.f.objects[fixturePlainPod]
				delete(h.f.objects, fixturePlainPod)
				h.extra = append(h.extra, o)
			},
		},
		{
			name:     "baseline-gate-whole-fixture-slot",
			calls:    2,
			wantGate: phaseGateBaseline,
			wantStep: "whole-fixture",
			wantSlot: fixturePlainPod,
			configure: func(_ *testing.T, h *fixturePhaseTest) {
				_ = unstructured.SetNestedField(h.f.objects[fixturePlainPod].Object, "default", "spec", "nodeName")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			factory := plainFactory
			if tc.v3 {
				factory = v3Factory
			}
			h := factory(t)
			prepareOriginalPhaseFixtures(t, h, len(h.f.wire.ledger.document.Entries))
			tc.configure(t, h)

			var d warmPhaseReadDiagnostic
			for range tc.calls {
				obs, err := h.f.wire.observePhaseAttributed(t.Context(), &d)
				if obs != nil || err != ErrFixtures {
					t.Fatalf("%s: observePhaseAttributed = (%v, %v), want (nil, ErrFixtures)", tc.name, obs != nil, err)
				}
			}
			assertDiagnosticAndMessage(t, &d, tc.calls, tc.wantGate, tc.wantStep, tc.wantSlot)
		})
	}

	// Gate: leaders (warm Lease renewal regression across paired whole/metadata GC reads).
	t.Run("leaders-gate", func(t *testing.T) {
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
					managed := metav1.NewTime(renew.Truncate(time.Second))
					lease.ManagedFields[0].Time = &managed
					object.Object = servingObject(t, lease).Object
				}
			}
			return rows
		}
		var d warmPhaseReadDiagnostic
		obs, err := h.f.wire.observePhaseAttributed(t.Context(), &d)
		if obs != nil || err != ErrFixtures {
			t.Fatalf("leaders-gate: observePhaseAttributed = (%v, %v), want (nil, ErrFixtures)", obs != nil, err)
		}
		assertDiagnosticAndMessage(t, &d, 1, phaseGateLeaders, "original-leaders", -1)
	})
}

func TestObservePhaseAttributedSuccessEquivalenceAndBounds(t *testing.T) {
	newPhase := fixturePhaseFactory(t)
	h := newPhase(t)
	prepareOriginalPhaseFixtures(t, h, len(h.f.wire.ledger.document.Entries))

	directObs, directErr := h.f.wire.observePhase(t.Context())
	if directErr != nil || directObs == nil {
		t.Fatalf("direct observePhase failed: (%v, %v)", directObs, directErr)
	}

	var d warmPhaseReadDiagnostic
	attrObs, attrErr := h.f.wire.observePhaseAttributed(t.Context(), &d)
	if attrErr != nil || attrObs == nil {
		t.Fatalf("observePhaseAttributed failed: (%v, %v)", attrObs, attrErr)
	}
	if !reflect.DeepEqual(attrObs.objects, directObs.objects) || !reflect.DeepEqual(attrObs.phase, directObs.phase) || !samePhaseBaseline(directObs.phase, attrObs.phase) || attrObs.gc == nil || len(attrObs.gc.Objects()) != len(directObs.gc.Objects()) {
		t.Fatal("observePhaseAttributed observation differed from direct observePhase")
	}
	if d.attempts != 1 || d.lastGate != phaseGateUnknown || d.substage != "" || d.slot != 0 {
		t.Fatalf("after 1 success diagnostic = %+v, want attempts=1 and untouched refusal fields", d)
	}
	if d.refusals != ([phaseGateLeaders + 1]uint32{}) {
		t.Fatalf("after success refusals = %v, want all 0", d.refusals)
	}

	secondObs, secondErr := h.f.wire.observePhaseAttributed(t.Context(), &d)
	if secondErr != nil || secondObs == nil || d.attempts != 2 || d.refusals != ([phaseGateLeaders + 1]uint32{}) {
		t.Fatalf("after 2nd success diagnostic = %+v, err = %v", d, secondErr)
	}
	wantSuccessDiag := "attempts=2 last_gate=unknown substage=unknown slot=-1; refusals: phaseReadable=0 current=0 worlds=0 localBarrier=0 remote=0 baseline=0 leaders=0 unknown=0"
	if got := d.String(); got != wantSuccessDiag {
		t.Fatalf("success d.String() = %q, want %q", got, wantSuccessDiag)
	}

	// Caller-level leader/baseline refusal attribution after a succeeded observePhaseAttributed
	// (mirrors the Kind phaseRead closure's leader-renewal and baseline checks).
	d.record(phaseGateLeaders, nil)
	if d.attempts != 2 || d.lastGate != phaseGateLeaders || d.substage != "unknown" || d.slot != -1 || d.refusals[phaseGateLeaders] != 1 {
		t.Fatalf("after caller leaders record diagnostic = %+v", d)
	}
	leaderMsg := warmPhaseReadFailureMessage(&d)
	if !strings.Contains(leaderMsg, "last_gate=leaders") || !strings.Contains(leaderMsg, "leaders=1") || !strings.Contains(leaderMsg, "attempts=2") {
		t.Fatalf("leader failure message = %q, missing expected attribution", leaderMsg)
	}

	// Nil diagnostic bounds: safe on record, String, warmPhaseReadFailureMessage, and observePhaseAttributed.
	var nilDiag *warmPhaseReadDiagnostic
	nilDiag.record(phaseGateRemote, nil)
	wantZeroDiag := "attempts=0 last_gate=unknown substage=unknown slot=-1; refusals: phaseReadable=0 current=0 worlds=0 localBarrier=0 remote=0 baseline=0 leaders=0 unknown=0"
	if got := nilDiag.String(); got != wantZeroDiag {
		t.Fatalf("nil diagnostic String() = %q, want %q", got, wantZeroDiag)
	}
	if got := warmPhaseReadFailureMessage(nil); got != "complete original phase did not converge with both renewing native leaders ("+wantZeroDiag+")" {
		t.Fatalf("nil warmPhaseReadFailureMessage = %q", got)
	}
	if obs, err := h.f.wire.observePhaseAttributed(t.Context(), nil); err != nil || obs == nil {
		t.Fatalf("observePhaseAttributed with nil diagnostic on valid fixture = (%v, %v)", obs, err)
	}
	h.hide[fixturePlainPod] = true
	if obs, err := h.f.wire.observePhaseAttributed(t.Context(), nil); obs != nil || err != ErrFixtures {
		t.Fatalf("observePhaseAttributed with nil diagnostic on refusing fixture = (%v, %v), want (nil, ErrFixtures)", obs, err)
	}

	// Unknown and out-of-range gates are counted as unknown.
	var boundsDiag warmPhaseReadDiagnostic
	var nilCtx context.Context
	if obs, err := h.f.wire.observePhaseAttributed(nilCtx, &boundsDiag); obs != nil || err != ErrFixtures {
		t.Fatalf("nil context observePhaseAttributed = (%v, %v), want (nil, ErrFixtures)", obs, err)
	}
	if boundsDiag.attempts != 1 || boundsDiag.lastGate != phaseGateUnknown || boundsDiag.refusals[phaseGateUnknown] != 1 {
		t.Fatalf("nil context diagnostic = %+v, want attempts=1 lastGate=unknown unknown=1", boundsDiag)
	}
	// First set a valid gate so we can prove out-of-range gates overwrite lastGate back to unknown.
	boundsDiag.record(phaseGateRemote, nil)
	if boundsDiag.lastGate != phaseGateRemote || boundsDiag.refusals[phaseGateRemote] != 1 {
		t.Fatalf("expected remote gate recorded, got %+v", boundsDiag)
	}
	for i, invalidGate := range []fixturePhaseGate{
		phaseGateUnknown,
		phaseGateLeaders + 1,
		fixturePhaseGate(255),
		^fixturePhaseGate(0),
	} {
		boundsDiag.record(invalidGate, nil)
		wantUnknownCount := uint32(i + 2)
		if boundsDiag.lastGate != phaseGateUnknown || boundsDiag.refusals[phaseGateUnknown] != wantUnknownCount || boundsDiag.refusals[phaseGateRemote] != 1 {
			t.Fatalf("invalid gate %d: diagnostic = %+v, want lastGate=unknown and unknown=%d", invalidGate, boundsDiag, wantUnknownCount)
		}
		if !strings.Contains(warmPhaseReadFailureMessage(&boundsDiag), fmt.Sprintf("last_gate=unknown substage=unknown slot=-1; refusals: phaseReadable=0 current=0 worlds=0 localBarrier=0 remote=1 baseline=0 leaders=0 unknown=%d", wantUnknownCount)) {
			t.Fatalf("invalid gate %d message = %q", invalidGate, warmPhaseReadFailureMessage(&boundsDiag))
		}
	}

	// Counter saturation at ^uint32(0).
	satDiag := warmPhaseReadDiagnostic{
		attempts: ^uint32(0),
		refusals: [phaseGateLeaders + 1]uint32{phaseGateRemote: ^uint32(0)},
	}
	if obs, err := h.f.wire.observePhaseAttributed(t.Context(), &satDiag); obs != nil || err != ErrFixtures {
		t.Fatalf("saturated observePhaseAttributed = (%v, %v), want (nil, ErrFixtures)", obs, err)
	}
	if satDiag.attempts != ^uint32(0) || satDiag.refusals[phaseGateRemote] != ^uint32(0) {
		t.Fatalf("counter wrapped on saturation: attempts=%d remote=%d", satDiag.attempts, satDiag.refusals[phaseGateRemote])
	}
}
