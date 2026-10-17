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

// Fake HTTPS with the actual protected ledger, production transport and whole
// phase observer. These tests do not certify native policy or installer CI.
func unmarkedRecoveryPhaseFactory(t *testing.T) func(*testing.T) *fixturePhaseTest {
	t.Helper()
	newPhase := fixturePhaseFactoryWithSetup(t, func(h *fixturePhaseTest) {
		instrumentFreshFixtureRecipeV2(t, h.f.wire.ledger)
	})
	return func(t *testing.T) *fixturePhaseTest {
		t.Helper()
		h := newPhase(t)
		f := h.f.wire.ledger
		acknowledgeAllRecipeFixtures(t, f)
		created := time.Now().UTC().Truncate(time.Second).Add(-40 * time.Second)
		for slot := range f.document.Entries {
			h.f.objects[slot] = fixtureResultExample(t, f, slot, fixtureStableResult, created)
		}
		return h
	}
}

func TestFixtureRecoveryUnmarkedOriginalsDrainWithoutSetupOrBehavior(t *testing.T) {
	h := unmarkedRecoveryPhaseFactory(t)(t)
	f, ledger := h.f, h.f.wire.ledger
	if f.wire.removeAcknowledgedMarkerOriginal(t.Context(), 10) != ErrFixtures {
		t.Fatal("unmarked run gained marked cleanup route")
	}
	for slot := len(ledger.document.Entries) - 1; slot >= 0; slot-- {
		if f.wire.removeUnmarkedOriginal(t.Context(), slot) != nil || ledger.document.Entries[slot].State != fixtureAbsent {
			t.Fatalf("unmarked original cleanup refused at fixed slot %d", slot)
		}
	}
	if f.deletes != len(ledger.document.Entries) || f.creates != 0 || f.seeds != 0 || ledger.document.DestroySeed != nil || ledger.document.RetainedMarker != nil || ledger.document.Behavior != nil || f.wire.retireDrained(t.Context()) != nil || ledger.engine.fixtureFence(f.actor.request.Snapshot) != nil {
		t.Fatal("unmarked drain invented setup/behavior or failed exact retirement")
	}
}

func TestFixtureRecoveryUnmarkedLostDeleteReloadNeverResends(t *testing.T) {
	newPhase := unmarkedRecoveryPhaseFactory(t)
	for _, present := range []bool{false, true} {
		t.Run(map[bool]string{false: "absent", true: "present"}[present], func(t *testing.T) {
			h := newPhase(t)
			f, old := h.f, h.f.wire.ledger
			original := f.objects[10].DeepCopy()
			getsAtSend, listsAtSend := -1, -1
			f.deleteReply = func(w http.ResponseWriter) {
				getsAtSend, listsAtSend = h.gets, h.lists
				w.WriteHeader(500)
			}
			if present {
				f.afterEffect = func() { f.objects[10] = original.DeepCopy() }
			}
			if f.wire.removeUnmarkedOriginal(t.Context(), 10) != ErrOutcomeUnknown || f.deletes != 1 || old.effectSlot != -1 || old.document.Entries[10].State != fixtureDeleteAttempted || getsAtSend < 0 || listsAtSend < 0 || h.lists <= listsAtSend || !present && h.gets <= getsAtSend {
				t.Fatal("lost DELETE failed single-send/post-attempt observation")
			}
			actors := f.wire.actors
			if old.close() != nil {
				t.Fatal("old WAL lock unavailable")
			}
			loaded, err := old.engine.loadFixtureLedger(t.Context(), f.actor.request.Snapshot)
			if err != nil {
				t.Fatal("attempted original reload refused")
			}
			defer loaded.close()
			if _, err := loaded.loadOriginalWorlds(); err != nil || !fixtureRecoveryEligible(loaded) {
				t.Fatal("known original companion/eligibility refused")
			}
			f.wire, err = actors.fixtures(t.Context(), loaded)
			if err != nil {
				t.Fatal("closed original wire reload refused")
			}
			before := bytes.Clone(loaded.body)
			err = f.wire.removeUnmarkedOriginal(t.Context(), 10)
			if f.deletes != 1 || loaded.effectSlot != -1 || loaded.driverFresh || present && (err != ErrFixtures || !bytes.Equal(before, loaded.body)) || !present && (err != nil || loaded.document.Entries[10].State != fixtureAbsent) {
				t.Fatal("loaded DELETE replayed, refreshed identity or adopted presence")
			}
		})
	}
}

func TestFixtureRecoveryProductionEntryRejectsUnknownBeforeHTTP(t *testing.T) {
	newPhase := fixturePhaseFactory(t)
	for _, state := range []string{"planned", "create-unknown", "seed-unknown", "marker-unknown"} {
		t.Run(state, func(t *testing.T) {
			h := newPhase(t)
			f, ledger := h.f, h.f.wire.ledger
			switch state {
			case "create-unknown":
				next, _ := ledger.nextDocument()
				next.Entries[0].State = fixtureCreateAttempted
				if ledger.advance(next) != nil {
					t.Fatal("unknown CREATE intent unavailable")
				}
			case "seed-unknown", "marker-unknown":
				acknowledgeAllRecipeFixtures(t, ledger)
				next := fixtureSeedIntent(t, ledger)
				if state == "marker-unknown" {
					next = fixtureMarkerIntent(t, ledger)
				}
				if ledger.advance(next) != nil {
					t.Fatal("unknown setup intent unavailable")
				}
			}
			body := bytes.Clone(ledger.body)
			if ledger.close() != nil {
				t.Fatal("original lock close refused")
			}
			reads, reviews := f.reads, f.actor.adminReviews+f.actor.actorReviews
			if f.actor.admission.resumeFixtures(t.Context(), f.actor.request) != ErrFixtures || f.creates != 0 || f.deletes != 0 || f.seeds != 0 || f.reads != reads || f.actor.adminReviews+f.actor.actorReviews != reviews {
				t.Fatal("unknown fixture run contacted actor routes or sent cleanup")
			}
			after, _, err := ledger.engine.files.Read(ledger.name, fixtureLedgerMaxBytes)
			if err != nil || !bytes.Equal(body, after) || ledger.engine.fixtureFence(f.actor.request.Snapshot) != ErrFixtures {
				t.Fatal("unknown evidence was rewritten or unfenced")
			}
		})
	}
}

func TestFixtureRecoveryProductionEntryFinishesPinnedRetirement(t *testing.T) {
	newPhase := unmarkedRecoveryPhaseFactory(t)
	for _, state := range []string{"active", "intent-before-unlink", "intent-after-unlink"} {
		t.Run(state, func(t *testing.T) {
			h := newPhase(t)
			f, ledger := h.f, h.f.wire.ledger
			// Model previously completed original DELETE/absence receipts, NOT
			// ownership adoption. Every immutable original UID remains captured.
			for slot := len(ledger.document.Entries) - 1; slot >= 0; slot-- {
				next, _ := ledger.nextDocument()
				next.Entries[slot].State = fixtureDeleteAttempted
				next.Entries[slot].DeleteResourceVersion = f.objects[slot].GetResourceVersion()
				if ledger.advance(next) != nil {
					t.Fatal("original DELETE receipt unavailable")
				}
				ledger.effectSlot = -1 // lost process; no resend capability
				delete(f.objects, slot)
				next, _ = ledger.nextDocument()
				next.Entries[slot].State = fixtureAbsent
				if ledger.advance(next) != nil {
					t.Fatal("original absence receipt unavailable")
				}
			}
			if state != "active" {
				fixtureRetirementIntent(t, h)
				if state == "intent-after-unlink" && ledger.engine.files.Remove(ledger.name, ledger.identity) != nil {
					t.Fatal("original WAL unlink unavailable")
				}
			}
			if ledger.close() != nil {
				t.Fatal("old WAL lock close refused")
			}
			p := f.actor.admission.prerequisites
			l := &Lifecycle{engine: ledger.engine, checks: &clusterLifecycleChecks{prerequisites: p, admission: f.actor.admission}}
			if l.ResumeFixtures(t.Context(), f.actor.request.Snapshot, f.actor.request.Options) != nil || ledger.engine.fixtureFence(f.actor.request.Snapshot) != nil || f.creates != 0 || f.deletes != 0 || f.seeds != 0 {
				t.Fatal("closed production recovery failed retirement or sent an effect")
			}
			retired, err := ledger.engine.readFixtureRetirement(f.actor.request.Snapshot.Anchor())
			if err != nil || retired.record.State != fixtureRetired || ledger.driverFresh || ledger.document.Behavior != nil {
				t.Fatal("retirement history became current behavior/fresh authority")
			}
			if l.ResumeFixtures(context.Background(), f.actor.request.Snapshot, f.actor.request.Options) != nil {
				t.Fatal("retired disposition failed no-effect recovery")
			}
		})
	}
}

func TestFixtureRecoveryProductionEntryDrainsMixedOriginalsWithoutReplay(t *testing.T) {
	newUnmarked := unmarkedRecoveryPhaseFactory(t)
	newMarked := markedCleanupPhaseFactory(t, fixtureRecipeV2, false)
	for _, marked := range []bool{false, true} {
		t.Run(map[bool]string{false: "unmarked", true: "marked"}[marked], func(t *testing.T) {
			var h *fixturePhaseTest
			if marked {
				h = newMarked(t)
			} else {
				h = newUnmarked(t)
			}
			f, ledger := h.f, h.f.wire.ledger
			// The previous process captured UID/RV for its two last DELETEs.
			originals := append([]fixtureEntry(nil), ledger.document.Entries...)
			originalRVs := make([]string, len(originals))
			for slot := range originals {
				originalRVs[slot] = f.objects[slot].GetResourceVersion()
			}
			// One absence was durable; the other reply was lost but the actual
			// original is now absent. Neither DELETE may be re-sent on resume.
			for _, slot := range []int{10, 9} {
				next, _ := ledger.nextDocument()
				next.Entries[slot].State = fixtureDeleteAttempted
				next.Entries[slot].DeleteResourceVersion = f.objects[slot].GetResourceVersion()
				if ledger.advance(next) != nil {
					t.Fatal("previous original DELETE intent unavailable")
				}
				ledger.effectSlot = -1
				delete(f.objects, slot)
				if slot == 10 {
					next, _ = ledger.nextDocument()
					next.Entries[slot].State = fixtureAbsent
					if ledger.advance(next) != nil {
						t.Fatal("previous actual absence receipt unavailable")
					}
				}
			}
			if ledger.close() != nil {
				t.Fatal("previous process lock close refused")
			}
			p := f.actor.admission.prerequisites
			l := &Lifecycle{engine: ledger.engine, checks: &clusterLifecycleChecks{prerequisites: p, admission: f.actor.admission}}
			if l.ResumeFixtures(t.Context(), f.actor.request.Snapshot, f.actor.request.Options) != nil || f.deletes != 9 || f.creates != 0 || f.seeds != 0 || ledger.engine.fixtureFence(f.actor.request.Snapshot) != nil {
				t.Fatal("actual production reverse loop refused or replayed a previous DELETE")
			}
			retired, err := ledger.engine.readFixtureRetirement(f.actor.request.Snapshot.Anchor())
			if err != nil || retired.record.State != fixtureRetired {
				t.Fatal("production mixed-state recovery failed exact retirement")
			}
			terminal, err := ledger.engine.decodeFixtureLedger(retired.archive)
			if err != nil || terminal.Behavior != nil {
				t.Fatal("recovery archive invented admission effectiveness")
			}
			for slot, entry := range terminal.Entries {
				if entry.State != fixtureAbsent || entry.Key != originals[slot].Key || entry.OriginalUID != originals[slot].OriginalUID || entry.DeleteResourceVersion != originalRVs[slot] {
					t.Fatal("mixed recovery changed original key/UID/RV or left an unresolved fixture")
				}
			}
		})
	}
}
