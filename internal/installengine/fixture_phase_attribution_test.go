// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"net/http"
	"testing"
	"time"
)

// phaseAttributionCase is one actual observePhase refusal together with the
// exact gate, substage and slot the diagnostic must retain for it.
type phaseAttributionCase struct {
	name  string
	v3    bool
	setup func(t *testing.T, h *fixturePhaseTest)
	gate  fixturePhaseGate
	stage string
	slot  int
}

func prepareOriginalPhaseFixtures(t *testing.T, h *fixturePhaseTest, entries int) {
	t.Helper()
	ledger := h.f.wire.ledger
	acknowledgeAllRecipeFixtures(t, ledger)
	created := time.Now().UTC().Truncate(time.Second).Add(-20 * time.Second)
	for slot := range entries {
		h.f.objects[slot] = fixtureResultExample(t, ledger, slot, fixtureStableResult, created)
	}
}

// Pins the #104 attribution rule at the real observePhase boundary: a refusal
// produced by accountPhaseWithAccounts reaches the remote gate (first refusal
// wins), and genuine baseline/named-read refusals keep their own gate, substage
// and slot. The previous discarded phaseGateFailed(baseline, err != nil) call
// made every accounting error read "baseline" and fails the remote rows below.
func TestFixturePhaseGateAttributionPinsAccountingRemoteAndNamedSlots(t *testing.T) {
	plain, v3 := fixturePhaseFactory(t), fixtureV3PhaseFactory(t)
	cases := []phaseAttributionCase{
		// accountPhaseWithAccounts refusals (legacy accounts == nil path).
		{name: "accounting-missing-list", setup: func(_ *testing.T, h *fixturePhaseTest) { h.hide[fixturePlainPod] = true }, gate: phaseGateRemote, stage: "original-row-missing-fixture", slot: -1},
		{name: "accounting-foreign-same-name", setup: func(_ *testing.T, h *fixturePhaseTest) {
			h.f.objects[fixturePlainPod].SetUID("b0000000-0000-4000-8000-000000000001")
		}, gate: phaseGateRemote, stage: "original-row-fixture-identity", slot: -1},
		{name: "accounting-extra-workload", setup: func(_ *testing.T, h *fixturePhaseTest) {
			o := h.f.objects[fixturePlainPod].DeepCopy()
			o.SetName("untracked")
			o.SetUID("b0000000-0000-4000-8000-000000000001")
			h.extra = append(h.extra, o)
		}, gate: phaseGateRemote, stage: "original-row-floor", slot: -1},
		// accountPhaseWithAccounts refusals with collected service accounts.
		{name: "accounting-v3-default-missing", v3: true, setup: func(_ *testing.T, h *fixturePhaseTest) { h.extra = nil }, gate: phaseGateRemote, stage: "original-row-floor", slot: -1},
		{name: "accounting-v3-extra-account", v3: true, setup: func(_ *testing.T, h *fixturePhaseTest) {
			extra := h.extra[0].DeepCopy()
			extra.SetName("foreign")
			extra.SetUID("c0000000-0000-4000-8000-000000000002")
			h.extra = append(h.extra, extra)
		}, gate: phaseGateRemote, stage: "original-row-floor", slot: -1},
		// Real baseline comparisons must not be relabelled remote.
		{name: "baseline-named-get-absent-but-listed", setup: func(_ *testing.T, h *fixturePhaseTest) {
			o := h.f.objects[fixturePlainPod]
			delete(h.f.objects, fixturePlainPod)
			h.extra = append(h.extra, o)
		}, gate: phaseGateBaseline, stage: "named-result", slot: fixturePlainPod},
		// Remote refusal of a named GET keeps its stage and slot.
		{name: "remote-named-get", setup: func(t *testing.T, h *fixturePhaseTest) {
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
		}, gate: phaseGateRemote, stage: "named-request", slot: fixturePlainPod},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			newPhase := plain
			if test.v3 {
				newPhase = v3
			}
			h := newPhase(t)
			f := h.f.wire.ledger
			prepareOriginalPhaseFixtures(t, h, len(f.document.Entries))
			test.setup(t, h)
			body, identity := bytes.Clone(f.body), f.identity
			trace := &admissionTrace{}
			observation, err := h.f.wire.observePhase(context.WithValue(t.Context(), admissionTraceKey{}, trace))
			gate := trace.phaseGateSnapshot()
			stage, slot := trace.phaseSnapshot()
			if err != ErrFixtures || observation != nil {
				t.Fatal("refusal was accepted", err)
			}
			if gate == phaseGateUnknown {
				t.Fatal("known refusal recorded no gate", stage, slot)
			}
			if gate != test.gate {
				t.Fatalf("misattributed gate: got %s want %s at %s/%d", gate, test.gate, stage, slot)
			}
			if stage != test.stage || slot != test.slot {
				t.Fatalf("lost substage or slot: got %s/%d want %s/%d", stage, slot, test.stage, test.slot)
			}
			if f.phaseFloor != nil || !bytes.Equal(body, f.body) || identity != f.identity || h.f.creates != 0 || h.f.deletes != 0 || h.f.seeds != 0 {
				t.Fatal("attributed refusal advanced the floor or changed WAL/effects")
			}
		})
	}
}

// A refused accounting calculation attributes nothing by itself: the gate is
// only recorded by the observePhase predicate that consumes its error. This
// prevents a helper from pre-empting the first-refusal-wins slot with a
// different label.
func TestFixturePhaseGateAccountingHelperRecordsNoGateOnItsOwn(t *testing.T) {
	h := fixtureV3PhaseFactory(t)(t)
	f := h.f.wire.ledger
	worlds, err := f.readOriginalWorlds(false)
	if err != nil || worlds.Phase == nil {
		t.Fatal("sealed floor unavailable", err)
	}
	a, request := h.f.actor.admission, h.f.actor.request
	o, err := a.prerequisites.observe(t.Context(), request)
	if err != nil {
		t.Fatal("sealed observation unavailable", err)
	}
	accounts, err := a.collectPhaseServiceAccounts(t.Context(), request)
	if err != nil {
		t.Fatal("sealed account collection unavailable", err)
	}
	floor := *worlds.Phase
	floor.Version = "invalid-floor-version" // first accounting guard refuses
	trace := &admissionTrace{}
	_, _, err = f.accountPhaseWithAccounts(context.WithValue(t.Context(), admissionTraceKey{}, trace), o, floor, time.Now().UTC(), accounts)
	if err != ErrFixtures || trace.phaseGateSnapshot() != phaseGateUnknown {
		t.Fatal("accounting helper refused without leaving gate attribution to its caller", err, trace.phaseGateSnapshot())
	}
}
