// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/privatefs"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func removeOriginalWorldsTest(t *testing.T, ledger *fixtureLedger) {
	t.Helper()
	name, err := ledger.originalWorldsName()
	if err != nil || ledger.worldIdentity == nil || ledger.engine.files.RemoveEvidence(name, *ledger.worldIdentity) != nil {
		t.Fatal("original companion loss injection failed")
	}
}

func TestFixtureOriginalWorldsDirectWireMissingCompanionZeroSend(t *testing.T) {
	newWire := fixturePreviewFactory(t)
	for _, operation := range []fixtureRequest{fixtureCreateRequest, fixtureDeleteRequest, fixtureDryRunRequest} {
		t.Run(map[fixtureRequest]string{fixtureCreateRequest: "create", fixtureDeleteRequest: "delete", fixtureDryRunRequest: "dry-run"}[operation], func(t *testing.T) {
			f := newWire(t)
			ledger := f.wire.ledger
			if ledger.sealOriginalWorlds([]fixtureWorldRow{}) != nil {
				t.Fatal("original companion unavailable")
			}
			slot := 0
			if operation == fixtureDeleteRequest {
				acknowledgeAllRecipeFixtures(t, ledger)
				slot = 1
			}
			if operation != fixtureDryRunRequest {
				next, _ := ledger.nextDocument()
				if operation == fixtureCreateRequest {
					next.Entries[slot].State = fixtureCreateAttempted
				} else {
					next.Entries[slot].State, next.Entries[slot].DeleteResourceVersion = fixtureDeleteAttempted, "101"
				}
				if ledger.advance(next) != nil {
					t.Fatal("original effect intent unavailable")
				}
			}
			removeOriginalWorldsTest(t, ledger)
			before := bytes.Clone(ledger.body)
			ledger.wireMu.Lock()
			_, err := f.wire.request(t.Context(), slot, operation)
			ledger.wireMu.Unlock()
			if err != ErrFixtures || f.creates != 0 || f.deletes != 0 || f.previews != 0 || !bytes.Equal(before, ledger.body) {
				t.Fatal("direct enum sent without original companion")
			}
		})
	}
}

func TestFixtureOriginalWorldsCreateAckSurvivesLateCompanionLoss(t *testing.T) {
	newWire := fixturePreviewFactory(t)
	for _, fault := range []string{"reliable-ack", "partial-unknown", "same-byte-replacement"} {
		t.Run(fault, func(t *testing.T) {
			f := newWire(t)
			ledger := f.wire.ledger
			if ledger.sealOriginalWorlds([]fixtureWorldRow{}) != nil {
				t.Fatal("original companion unavailable")
			}
			next, _ := ledger.nextDocument()
			next.Entries[0].State = fixtureCreateAttempted
			if ledger.advance(next) != nil {
				t.Fatal("original CREATE intent unavailable")
			}
			f.afterEffect = func() {
				if fault != "same-byte-replacement" {
					removeOriginalWorldsTest(t, ledger)
					return
				}
				name, _ := ledger.originalWorldsName()
				body, id, err := ledger.engine.files.ReadEvidence(name, privatefs.MaxEvidenceFileBytes)
				if err != nil {
					t.Fatal("original companion unavailable during send")
				}
				if _, err := ledger.engine.files.AtomicWrite(name, body, &id); err != nil {
					t.Fatal("same-byte replacement injection failed")
				}
			}
			reliable := fault != "partial-unknown"
			if !reliable {
				f.reply = func(w http.ResponseWriter, _ *unstructured.Unstructured) { _, _ = w.Write([]byte(`{"kind":"Job"}`)) }
			}
			result, err := f.wire.create(t.Context(), 0)
			if result != nil || err == nil || f.creates != 1 || ledger.ackSlot != -1 || ledger.effectSlot != -1 {
				t.Fatal("late loss did not refuse once-only CREATE")
			}
			state := ledger.document.Entries[0]
			if reliable && (state.State != fixtureOriginal || state.OriginalUID == "") || !reliable && (state.State != fixtureCreateAttempted || state.OriginalUID != "") {
				t.Fatal("reliable ACK lost or unknown CREATE adopted")
			}
			protected, _, err := ledger.engine.files.Read(ledger.name, fixtureLedgerMaxBytes)
			if err != nil || !bytes.Equal(protected, ledger.body) {
				t.Fatal("ACK not durably pinned before refusal")
			}
			if ledger.close() != nil {
				t.Fatal("close failed")
			}
			loaded, err := ledger.engine.loadFixtureLedger(t.Context(), f.actor.request.Snapshot)
			if err != nil {
				t.Fatal("original WAL reload failed")
			}
			defer loaded.close()
			if loaded.document.Entries[0] != state || loaded.ackSlot != -1 || loaded.effectSlot != -1 {
				t.Fatal("reload changed known result or restored send capability")
			}
			if _, err := f.wire.actors.fixtures(t.Context(), loaded); err != ErrFixtures || f.creates != 1 {
				t.Fatal("missing companion allowed rebuilt wire")
			}
			if fault == "same-byte-replacement" {
				if _, err := loaded.loadOriginalWorlds(); err != nil {
					t.Fatal("sealed same-byte evidence could not be confirmed in new session")
				}
				rebuilt, err := f.wire.actors.fixtures(t.Context(), loaded)
				if err != nil {
					t.Fatal("read-only original wire unavailable after verified evidence reload")
				}
				if _, err := rebuilt.create(t.Context(), 0); err != ErrFixtures || f.creates != 1 {
					t.Fatal("reload restored same-attempt CREATE despite original ACK")
				}
			}
		})
	}
}

func TestFixtureOriginalWorldsStatusIntentMissingCompanionZeroSend(t *testing.T) {
	newWire := fixturePreviewFactory(t)
	for _, mode := range []fixtureDestroySeedMode{fixtureDestroySeedCold, fixtureDestroySeedWarmCancelled} {
		t.Run(string(mode), func(t *testing.T) {
			f := newWire(t)
			ledger := f.wire.ledger
			if ledger.sealOriginalWorlds([]fixtureWorldRow{}) != nil {
				t.Fatal("original companion unavailable")
			}
			acknowledgeAllRecipeFixtures(t, ledger)
			created := time.Now().UTC().Truncate(time.Second).Add(-20 * time.Second)
			for slot := range fixtureCatalog {
				f.objects[slot] = fixtureResultExample(t, ledger, slot, fixtureStableResult, created)
			}
			if mode == fixtureDestroySeedWarmCancelled {
				f.objects[fixtureCancelledDestroy] = fixtureWarmCancelledExample(t, ledger, created, [3]time.Duration{time.Second, time.Second, time.Second})
			}
			next := fixtureSeedIntent(t, ledger)
			next.DestroySeed.Mode = mode
			if ledger.advance(next) != nil || mode == fixtureDestroySeedCold && !ledger.destroySeedReady() || mode == fixtureDestroySeedWarmCancelled && !ledger.destroyWarmSeedReady() {
				t.Fatal("correct live status intent unavailable")
			}
			removeOriginalWorldsTest(t, ledger)
			before := bytes.Clone(ledger.body)
			operation := fixtureSeedStatusRequest
			if mode == fixtureDestroySeedWarmCancelled {
				operation = fixtureWarmSeedStatusRequest
			}
			ledger.wireMu.Lock()
			_, err := f.wire.request(t.Context(), fixtureCancelledDestroy, operation)
			ledger.wireMu.Unlock()
			if err != ErrFixtures || f.seeds != 0 {
				t.Fatal("direct status enum sent without companion")
			}
			if mode == fixtureDestroySeedCold {
				_, err = f.wire.seedDestroyStatus(t.Context())
			} else {
				_, err = f.wire.seedWarmDestroyStatus(t.Context())
			}
			if err != ErrFixtures || f.seeds != 0 || !bytes.Equal(before, ledger.body) || ledger.document.DestroySeed.State != fixtureDestroySeedAttempted {
				t.Fatal("outer status route sent or ACKed without companion")
			}
		})
	}
	marker := retainedMarkerLearningFactoryWithWorlds(t, true)(t)
	ledger := marker.f.wire.ledger
	if !retainedMarkerReady(ledger) {
		t.Fatal("correct marker intent unavailable")
	}
	removeOriginalWorldsTest(t, ledger)
	before := bytes.Clone(ledger.body)
	if _, err := marker.f.wire.markRetainedPVC(t.Context()); err != ErrFixtures || marker.updates != 0 || !bytes.Equal(before, ledger.body) || ledger.document.RetainedMarker.State != fixtureRetainedMarkerAttempted {
		t.Fatal("marker sent or ACKed without companion")
	}
}

func TestFixtureOriginalWorldsSeedAckSurvivesLateCompanionLoss(t *testing.T) {
	f := fixtureSeedWireFactoryWithWorlds(t, true)(t)
	ledger := f.wire.ledger
	f.afterSeed = func() { removeOriginalWorldsTest(t, ledger) }
	result, err := f.wire.seedDestroyStatus(t.Context())
	if result != nil || err != ErrFixtures || f.seeds != 1 || ledger.document.DestroySeed.State != fixtureDestroySeedAcknowledged || ledger.document.DestroySeed.AcknowledgedResourceVersion != "102" || ledger.seedAck || ledger.seedEffect {
		t.Fatal("reliable seed ACK not durable before late original-evidence refusal")
	}
	if _, err := f.wire.seedDestroyStatus(t.Context()); err != ErrFixtures || f.seeds != 1 {
		t.Fatal("seed replayed after late witness refusal")
	}
}

func TestFixtureOriginalWorldsMarkerAckSurvivesLateCompanionLoss(t *testing.T) {
	h := retainedMarkerLearningFactoryWithWorlds(t, true)(t)
	fixtureMarkerWireNativeReply(t, h)
	ledger := h.f.wire.ledger
	h.after = func() { removeOriginalWorldsTest(t, ledger) }
	result, err := h.f.wire.markRetainedPVC(t.Context())
	if result != nil || err != ErrFixtures || h.updates != 1 || ledger.document.RetainedMarker.State != fixtureRetainedMarkerAcknowledged || ledger.document.RetainedMarker.AcknowledgedResourceVersion == "" || ledger.markerAck || ledger.markerEffect {
		t.Fatal("reliable marker ACK not durable before late original-evidence refusal")
	}
	protected, _, err := ledger.engine.files.Read(ledger.name, fixtureLedgerMaxBytes)
	var raw fixtureLedgerDocument
	if err != nil || json.Unmarshal(protected, &raw) != nil || raw.RetainedMarker == nil || raw.RetainedMarker.State != fixtureRetainedMarkerAcknowledged {
		t.Fatal("marker reliable ACK absent from protected WAL")
	}
}
