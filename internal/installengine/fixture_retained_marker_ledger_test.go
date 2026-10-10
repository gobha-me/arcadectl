// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"encoding/json"
	"net/http"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/gobha-me/arcadectl/internal/canonicaljson"
)

func fixtureMarkerIntent(t *testing.T, ledger *fixtureLedger) fixtureLedgerDocument {
	t.Helper()
	next, err := ledger.nextDocument()
	if err != nil {
		t.Fatal("original marker intent unavailable")
	}
	next.RetainedMarker = &fixtureRetainedMarkerReceipt{State: fixtureRetainedMarkerAttempted, BeforeResourceVersion: "101"}
	return next
}

func TestFixtureMarkerCapabilitiesReloadAndOrderedCleanup(t *testing.T) {
	f := newFixture(t, false)
	ledger, err := f.engine.prepareFixtureLedger(t.Context(), f.snapshot)
	if err != nil {
		t.Fatal("original ledger unavailable")
	}
	defer func() { _ = ledger.close() }()
	if ledger.advance(fixtureMarkerIntent(t, ledger)) != ErrFixtures || ledger.markerAck || ledger.markerEffect {
		t.Fatal("marker intent granted before every original acknowledgement")
	}
	acknowledgeAllRecipeFixtures(t, ledger)
	if ledger.advance(fixtureMarkerIntent(t, ledger)) != nil || !ledger.markerAck || !ledger.markerEffect {
		t.Fatal("durable intent failed to grant separate same-instance capabilities")
	}
	if ledger.advance(fixtureMarkerAcknowledgement(t, ledger)) != ErrFixtures {
		t.Fatal("marker ACK accepted before send")
	}
	unknown := bytes.Clone(ledger.body)
	for slot := range fixtureCatalog {
		next, _ := ledger.nextDocument()
		next.Entries[slot].State, next.Entries[slot].DeleteResourceVersion = fixtureDeleteAttempted, "200"
		if ledger.advance(next) != ErrFixtures || !bytes.Equal(ledger.body, unknown) {
			t.Fatal("unknown marker allowed cleanup")
		}
	}
	if ledger.advance(fixtureSeedIntent(t, ledger)) != ErrFixtures {
		t.Fatal("unknown marker permitted a seed intent")
	}
	// Abstract state-machine instrumentation, not a native send or wire ACK.
	ledger.markerEffect = false
	for _, rv := range []string{"", "101", "0", "0102", "18446744073709551616", "foreign"} {
		next := fixtureMarkerAcknowledgement(t, ledger)
		next.RetainedMarker.AcknowledgedResourceVersion = rv
		if ledger.advance(next) != ErrFixtures {
			t.Fatal("invalid marker acknowledged RV accepted")
		}
	}
	if ledger.advance(fixtureMarkerAcknowledgement(t, ledger)) != nil || ledger.markerAck || ledger.markerEffect {
		t.Fatal("marker ACK failed or restored capabilities")
	}
	receipt := *ledger.document.RetainedMarker
	if ledger.close() != nil {
		t.Fatal("marker ledger close unavailable")
	}
	ledger, err = f.engine.loadFixtureLedger(t.Context(), f.snapshot)
	if err != nil || ledger.markerAck || ledger.markerEffect || *ledger.document.RetainedMarker != receipt {
		t.Fatal("marker reload changed receipt or granted capabilities")
	}
	for _, mutate := range []func(*fixtureLedgerDocument){
		func(d *fixtureLedgerDocument) { d.RetainedMarker = nil },
		func(d *fixtureLedgerDocument) { d.RetainedMarker.BeforeResourceVersion = "103" },
		func(d *fixtureLedgerDocument) { d.RetainedMarker.AcknowledgedResourceVersion = "104" },
		func(d *fixtureLedgerDocument) { d.RetainedMarker.State = fixtureRetainedMarkerAttempted },
	} {
		next, _ := ledger.nextDocument()
		mutate(&next)
		if ledger.advance(next) != ErrFixtures {
			t.Fatal("acknowledged marker removed, changed or replayed")
		}
	}
	for slot := len(fixtureCatalog) - 1; slot >= 0; slot-- {
		next, _ := ledger.nextDocument()
		next.Entries[slot].State, next.Entries[slot].DeleteResourceVersion = fixtureDeleteAttempted, "200"
		if ledger.advance(next) != nil {
			t.Fatal("pure ordered cleanup transition refused")
		}
		next, _ = ledger.nextDocument()
		next.Entries[slot].State = fixtureAbsent
		if ledger.advance(next) != nil || *ledger.document.RetainedMarker != receipt {
			t.Fatal("pure cleanup changed marker receipt")
		}
	}
	if f.engine.fixtureFence(f.snapshot) != ErrFixtures || f.access.writes != 0 || f.nsUpdates != 0 {
		t.Fatal("terminal marker retired fence or performed cluster mutation")
	}
}

func TestFixtureMarkerUnknownReloadAndFailedDurabilityGrantNothing(t *testing.T) {
	for _, replace := range []bool{false, true} {
		t.Run(map[bool]string{false: "unknown-reload", true: "protected-replacement"}[replace], func(t *testing.T) {
			f := newFixture(t, false)
			ledger, err := f.engine.prepareFixtureLedger(t.Context(), f.snapshot)
			if err != nil {
				t.Fatal("original ledger unavailable")
			}
			defer func() { _ = ledger.close() }()
			acknowledgeAllRecipeFixtures(t, ledger)
			if replace {
				if _, err := f.engine.files.AtomicWrite(ledger.name, bytes.Clone(ledger.body), &ledger.identity); err != nil {
					t.Fatal("test replacement unavailable")
				}
				if ledger.advance(fixtureMarkerIntent(t, ledger)) != ErrFixtures || ledger.markerAck || ledger.markerEffect {
					t.Fatal("failed protected intent granted capabilities")
				}
				return
			}
			if ledger.advance(fixtureMarkerIntent(t, ledger)) != nil {
				t.Fatal("marker intent unavailable")
			}
			before := bytes.Clone(ledger.body)
			if ledger.close() != nil || ledger.markerAck || ledger.markerEffect {
				t.Fatal("close retained marker capabilities")
			}
			ledger, err = f.engine.loadFixtureLedger(t.Context(), f.snapshot)
			if err != nil || ledger.markerAck || ledger.markerEffect || !bytes.Equal(before, ledger.body) {
				t.Fatal("unknown reload granted capabilities or changed WAL")
			}
			if ledger.advance(fixtureMarkerAcknowledgement(t, ledger)) != ErrFixtures || ledger.advance(fixtureMarkerIntent(t, ledger)) != ErrFixtures || ledger.advance(fixtureSeedIntent(t, ledger)) != ErrFixtures {
				t.Fatal("reload adopted ACK or replayed an effect")
			}
		})
	}
}

func TestFixtureMarkerCanonicalLegacyAndStrictDecode(t *testing.T) {
	f := newFixture(t, false)
	ledger, err := f.engine.prepareFixtureLedger(t.Context(), f.snapshot)
	if err != nil {
		t.Fatal("original ledger unavailable")
	}
	defer ledger.close()
	acknowledgeAllRecipeFixtures(t, ledger)
	var legacy map[string]any
	if json.Unmarshal(ledger.body, &legacy) != nil {
		t.Fatal("legacy body unavailable")
	}
	if _, present := legacy["retainedMarker"]; present {
		t.Fatal("optional marker changed legacy encoding")
	}
	reencoded, err := f.engine.fixtureLedgerBody(ledger.document)
	if err != nil || !bytes.Equal(reencoded, ledger.body) {
		t.Fatal("legacy canonical bytes changed")
	}
	intent := fixtureMarkerIntent(t, ledger)
	for _, malformed := range []any{
		nil, "PRIVATE-CANARY", map[string]any{},
		map[string]any{"state": "attempted", "beforeResourceVersion": "101", "acknowledgedResourceVersion": "", "extra": "PRIVATE-CANARY"},
		map[string]any{"state": "attempted", "beforeResourceVersion": "101"},
	} {
		body, _ := json.Marshal(legacy)
		var mutated map[string]any
		_ = json.Unmarshal(body, &mutated)
		mutated["retainedMarker"] = malformed
		body, _ = json.Marshal(mutated)
		body, _ = canonicaljson.CanonicalJSON(body)
		if _, err := f.engine.decodeFixtureLedger(body); err != ErrFixtures {
			t.Fatal("noncanonical or unknown marker decoded")
		}
	}
	for slot := range fixtureCatalog {
		next := intent
		next.Entries = append([]fixtureEntry(nil), intent.Entries...)
		next.Entries[slot].OriginalUID = ""
		if _, err := f.engine.fixtureLedgerBody(next); err != ErrFixtures {
			t.Fatal("partial originals permitted marker intent")
		}
	}
	if !reflect.DeepEqual(ledger.document.RetainedMarker, (*fixtureRetainedMarkerReceipt)(nil)) || f.access.writes != 0 {
		t.Fatal("strict decoding mutated state")
	}
}

func TestFixtureMarkerCompetingReceiptsAndSequentialBookkeeping(t *testing.T) {
	for _, markerFirst := range []bool{false, true} {
		f := newFixture(t, false)
		ledger, err := f.engine.prepareFixtureLedger(t.Context(), f.snapshot)
		if err != nil {
			t.Fatal("original ledger unavailable")
		}
		defer ledger.close()
		acknowledgeAllRecipeFixtures(t, ledger)
		if markerFirst {
			if ledger.advance(fixtureMarkerIntent(t, ledger)) != nil {
				t.Fatal("marker intent unavailable")
			}
			if ledger.advance(fixtureSeedIntent(t, ledger)) != ErrFixtures {
				t.Fatal("unknown marker allowed seed")
			}
			ledger.markerEffect = false // abstract send-consumption, not transport
			coupled := fixtureMarkerAcknowledgement(t, ledger)
			coupled.DestroySeed = &fixtureDestroySeedReceipt{State: fixtureDestroySeedAttempted, BeforeResourceVersion: "101"}
			if ledger.advance(coupled) != ErrFixtures {
				t.Fatal("marker ACK plus seed intent accepted")
			}
			if ledger.advance(fixtureMarkerAcknowledgement(t, ledger)) != nil || ledger.advance(fixtureSeedIntent(t, ledger)) != nil {
				t.Fatal("separate marker ACK then seed intent bookkeeping refused")
			}
			ledger.seedEffect = false
			if ledger.advance(fixtureSeedAcknowledgement(t, ledger)) != nil {
				t.Fatal("separate seed ACK bookkeeping refused")
			}
		} else {
			if ledger.advance(fixtureSeedIntent(t, ledger)) != nil {
				t.Fatal("seed intent unavailable")
			}
			if ledger.advance(fixtureMarkerIntent(t, ledger)) != ErrFixtures {
				t.Fatal("unknown seed allowed marker")
			}
			ledger.seedEffect = false
			coupled := fixtureSeedAcknowledgement(t, ledger)
			coupled.RetainedMarker = &fixtureRetainedMarkerReceipt{State: fixtureRetainedMarkerAttempted, BeforeResourceVersion: "101"}
			if ledger.advance(coupled) != ErrFixtures {
				t.Fatal("seed ACK plus marker intent accepted")
			}
			if ledger.advance(fixtureSeedAcknowledgement(t, ledger)) != nil || ledger.advance(fixtureMarkerIntent(t, ledger)) != nil {
				t.Fatal("separate seed ACK then marker intent bookkeeping refused")
			}
			ledger.markerEffect = false
			if ledger.advance(fixtureMarkerAcknowledgement(t, ledger)) != nil {
				t.Fatal("separate marker ACK bookkeeping refused")
			}
		}
		if ledger.markerAck || ledger.markerEffect || ledger.seedAck || ledger.seedEffect || f.access.writes != 0 {
			t.Fatal("bookkeeping granted lingering capability or cluster write")
		}
	}
}

func TestFixtureMarkerAckProtectedReplacementRemainsUnknown(t *testing.T) {
	f := newFixture(t, false)
	ledger, err := f.engine.prepareFixtureLedger(t.Context(), f.snapshot)
	if err != nil {
		t.Fatal("original ledger unavailable")
	}
	defer func() { _ = ledger.close() }()
	acknowledgeAllRecipeFixtures(t, ledger)
	if ledger.advance(fixtureMarkerIntent(t, ledger)) != nil {
		t.Fatal("marker intent unavailable")
	}
	ledger.markerEffect = false // abstract send-consumption, not transport
	before := bytes.Clone(ledger.body)
	if _, err := f.engine.files.AtomicWrite(ledger.name, before, &ledger.identity); err != nil {
		t.Fatal("test replacement unavailable")
	}
	if ledger.advance(fixtureMarkerAcknowledgement(t, ledger)) != ErrFixtures || !bytes.Equal(before, ledger.body) || ledger.document.RetainedMarker.State != fixtureRetainedMarkerAttempted || ledger.markerEffect {
		t.Fatal("failed ACK durability fabricated acknowledgement/send capability")
	}
	if ledger.advance(fixtureMarkerAcknowledgement(t, ledger)) != ErrFixtures {
		t.Fatal("replacement repaired failed ACK")
	}
	if ledger.close() != nil {
		t.Fatal("unknown ledger close unavailable")
	}
	ledger, err = f.engine.loadFixtureLedger(t.Context(), f.snapshot)
	if err != nil || ledger.markerAck || ledger.markerEffect || ledger.advance(fixtureMarkerAcknowledgement(t, ledger)) != ErrFixtures {
		t.Fatal("failed ACK adopted after protected reload")
	}
}

func TestFixtureMarkerOldRoutesRefuseBeforeAnyHTTP(t *testing.T) {
	newPreview := fixturePreviewFactory(t)
	for _, scenario := range []string{"attempted", "acknowledged", "stale-ack", "stale-send"} {
		t.Run(scenario, func(t *testing.T) {
			f := newPreview(t)
			ledger := f.wire.ledger
			acknowledgeAllRecipeFixtures(t, ledger)
			switch scenario {
			case "attempted", "acknowledged":
				if ledger.advance(fixtureMarkerIntent(t, ledger)) != nil {
					t.Fatal("marker intent unavailable")
				}
				if scenario == "acknowledged" {
					ledger.markerEffect = false // abstract send, no native effect
					if ledger.advance(fixtureMarkerAcknowledgement(t, ledger)) != nil {
						t.Fatal("abstract marker ACK unavailable")
					}
				}
			case "stale-ack":
				ledger.markerAck = true
			case "stale-send":
				ledger.markerEffect = true
			}
			var calls atomic.Int64
			original := f.actor.fixtureHandler
			f.actor.fixtureHandler = func(w http.ResponseWriter, r *http.Request) bool { calls.Add(1); return original(w, r) }
			before, identity, revision := bytes.Clone(ledger.body), ledger.identity, ledger.document.Revision
			ack, send := ledger.markerAck, ledger.markerEffect
			if f.wire.prepareDestroySeed(t.Context()) != ErrFixtures || f.wire.prepareWarmDestroySeed(t.Context()) != ErrFixtures {
				t.Fatal("marked state entered seed preparation")
			}
			if _, err := f.wire.destroySeedPayload(t.Context()); err != ErrFixtures {
				t.Fatal("marked state entered cold seed payload")
			}
			if _, err := f.wire.warmDestroySeedPayload(t.Context()); err != ErrFixtures {
				t.Fatal("marked state entered warm seed payload")
			}
			if _, err := f.wire.seedDestroyStatus(t.Context()); err != ErrFixtures {
				t.Fatal("marked state entered cold seed send")
			}
			if _, err := f.wire.seedWarmDestroyStatus(t.Context()); err != ErrFixtures {
				t.Fatal("marked state entered warm seed send")
			}
			if _, err := f.wire.settledFixtures(t.Context()); err != ErrFixtures {
				t.Fatal("marked state became settled proof")
			}
			for _, operation := range []fixtureRequest{fixtureCreateRequest, fixtureDeleteRequest, fixtureDryRunRequest, fixtureSeedStatusRequest, fixtureWarmSeedStatusRequest} {
				if _, err := f.wire.request(t.Context(), fixtureCancelledDestroy, operation); err != ErrFixtures {
					t.Fatal("marked state entered old direct enum")
				}
			}
			if calls.Load() != 0 || f.creates != 0 || f.deletes != 0 || f.reads != 0 || f.seeds != 0 || !bytes.Equal(before, ledger.body) || ledger.identity != identity || ledger.document.Revision != revision || ledger.markerAck != ack || ledger.markerEffect != send {
				t.Fatal("marker refusal reached HTTP, changed WAL or capabilities")
			}
		})
	}
}

// Unlike the broad refusal matrix, these seed routes have their own complete
// durable intent/send prerequisites. Removing the marker guard would admit
// them. The ACK and flag instrumentation does not claim any native effect.
func TestFixtureMarkerOtherwiseReadySeedRoutesAndDeleteRefuse(t *testing.T) {
	newPreview := fixturePreviewFactory(t)
	for _, warm := range []bool{false, true} {
		for _, scenario := range []string{"acknowledged", "stale-ack", "stale-send"} {
			name := "cold-" + scenario
			if warm {
				name = "warm-" + scenario
			}
			t.Run(name, func(t *testing.T) {
				f := newPreview(t)
				ledger := f.wire.ledger
				acknowledgeAllRecipeFixtures(t, ledger)
				if scenario == "acknowledged" {
					if ledger.advance(fixtureMarkerIntent(t, ledger)) != nil {
						t.Fatal("marker intent unavailable")
					}
					ledger.markerEffect = false
					if ledger.advance(fixtureMarkerAcknowledgement(t, ledger)) != nil {
						t.Fatal("abstract marker ACK unavailable")
					}
				}
				intent := fixtureSeedIntent(t, ledger)
				if warm {
					intent.DestroySeed.Mode = fixtureDestroySeedWarmCancelled
				}
				if ledger.advance(intent) != nil || !ledger.seedAck || !ledger.seedEffect {
					t.Fatal("qualified seed intent unavailable")
				}
				if scenario != "acknowledged" {
					ready := ledger.destroySeedReady()
					if warm {
						ready = ledger.destroyWarmSeedReady()
					}
					if !ready {
						t.Fatal("control seed route was not otherwise ready")
					}
					if scenario == "stale-ack" {
						ledger.markerAck = true
					} else {
						ledger.markerEffect = true
					}
				}
				// Independently prove constructor/document and own capabilities are
				// valid even in the ACK-marker case, where the marker itself blocks.
				_, recipeErr := ledger.destroySeedStatus()
				if warm {
					_, recipeErr = ledger.destroyWarmSeedStatus()
				}
				if recipeErr != nil || ledger.ackSlot != -1 || ledger.effectSlot != -1 {
					t.Fatal("qualified seed control invalid")
				}
				var calls atomic.Int64
				original := f.actor.fixtureHandler
				f.actor.fixtureHandler = func(w http.ResponseWriter, r *http.Request) bool { calls.Add(1); return original(w, r) }
				before, identity := bytes.Clone(ledger.body), ledger.identity
				if ledger.destroySeedReady() || ledger.destroyWarmSeedReady() {
					t.Fatal("marker admitted an otherwise-ready seed")
				}
				if f.wire.prepareDestroySeed(t.Context()) != ErrFixtures || f.wire.prepareWarmDestroySeed(t.Context()) != ErrFixtures {
					t.Fatal("marker admitted seed preparation")
				}
				if _, err := f.wire.destroySeedPayload(t.Context()); err != ErrFixtures {
					t.Fatal("marker admitted cold payload")
				}
				if _, err := f.wire.warmDestroySeedPayload(t.Context()); err != ErrFixtures {
					t.Fatal("marker admitted warm payload")
				}
				if _, err := f.wire.seedDestroyStatus(t.Context()); err != ErrFixtures {
					t.Fatal("marker admitted cold seed send")
				}
				if _, err := f.wire.seedWarmDestroyStatus(t.Context()); err != ErrFixtures {
					t.Fatal("marker admitted warm seed send")
				}
				for _, op := range []fixtureRequest{fixtureSeedStatusRequest, fixtureWarmSeedStatusRequest} {
					if _, err := f.wire.request(t.Context(), fixtureCancelledDestroy, op); err != ErrFixtures {
						t.Fatal("marker admitted seed enum")
					}
				}
				if calls.Load() != 0 || f.seeds != 0 || !ledger.seedAck || !ledger.seedEffect || !bytes.Equal(before, ledger.body) || ledger.identity != identity {
					t.Fatal("marker refusal used HTTP or changed seed/WAL")
				}
			})
		}
	}
	t.Run("otherwise-ready-delete", func(t *testing.T) {
		f := newPreview(t)
		ledger := f.wire.ledger
		acknowledgeAllRecipeFixtures(t, ledger)
		if ledger.advance(fixtureMarkerIntent(t, ledger)) != nil {
			t.Fatal("marker intent unavailable")
		}
		ledger.markerEffect = false
		if ledger.advance(fixtureMarkerAcknowledgement(t, ledger)) != nil {
			t.Fatal("abstract marker ACK unavailable")
		}
		next, _ := ledger.nextDocument()
		next.Entries[fixtureCancelledDestroy].State, next.Entries[fixtureCancelledDestroy].DeleteResourceVersion = fixtureDeleteAttempted, "200"
		if ledger.advance(next) != nil || ledger.effectSlot != fixtureCancelledDestroy {
			t.Fatal("qualified delete intent unavailable")
		}
		if _, err := fixtureDeleteOptions(ledger.document.Entries[fixtureCancelledDestroy]); err != nil {
			t.Fatal("qualified delete options unavailable")
		}
		var calls atomic.Int64
		original := f.actor.fixtureHandler
		f.actor.fixtureHandler = func(w http.ResponseWriter, r *http.Request) bool { calls.Add(1); return original(w, r) }
		before, identity := bytes.Clone(ledger.body), ledger.identity
		if _, err := f.wire.request(t.Context(), fixtureCancelledDestroy, fixtureDeleteRequest); err != ErrFixtures || f.wire.delete(t.Context(), fixtureCancelledDestroy) != ErrFixtures {
			t.Fatal("marker admitted qualified delete")
		}
		if calls.Load() != 0 || f.deletes != 0 || ledger.effectSlot != fixtureCancelledDestroy || !bytes.Equal(before, ledger.body) || ledger.identity != identity {
			t.Fatal("marker delete refusal reached HTTP or spent capability")
		}
	})
}

func TestFixtureMarkerStaleCapabilitiesBlockReadyCreateAndPreview(t *testing.T) {
	newPreview := fixturePreviewFactory(t)
	for _, intent := range []bool{false, true} {
		f := newPreview(t)
		ledger := f.wire.ledger
		if !ledger.dryRunReady(0) {
			t.Fatal("control preview was not otherwise ready")
		}
		if intent {
			next, _ := ledger.nextDocument()
			next.Entries[0].State = fixtureCreateAttempted
			if ledger.advance(next) != nil || ledger.ackSlot != 0 || ledger.effectSlot != 0 {
				t.Fatal("qualified create intent unavailable")
			}
		}
		ledger.markerAck = true // independent stale flag, no durable marker receipt
		var calls atomic.Int64
		original := f.actor.fixtureHandler
		f.actor.fixtureHandler = func(w http.ResponseWriter, r *http.Request) bool { calls.Add(1); return original(w, r) }
		before := bytes.Clone(ledger.body)
		if intent {
			if _, err := f.wire.create(t.Context(), 0); err != ErrFixtures {
				t.Fatal("marker admitted qualified create")
			}
			if _, err := f.wire.request(t.Context(), 0, fixtureCreateRequest); err != ErrFixtures {
				t.Fatal("marker admitted direct create")
			}
		} else {
			if ledger.dryRunReady(0) {
				t.Fatal("marker admitted otherwise-ready preview")
			}
			if _, err := f.wire.dryRun(t.Context(), 0); err != ErrFixtures {
				t.Fatal("marker admitted preview send")
			}
		}
		if calls.Load() != 0 || f.creates != 0 || f.previews != 0 || !bytes.Equal(before, ledger.body) || !ledger.markerAck {
			t.Fatal("marker create/preview refusal reached HTTP or changed evidence")
		}
	}
}

func fixtureMarkerAcknowledgement(t *testing.T, ledger *fixtureLedger) fixtureLedgerDocument {
	t.Helper()
	next, err := ledger.nextDocument()
	if err != nil || next.RetainedMarker == nil {
		t.Fatal("original marker attempt unavailable")
	}
	next.RetainedMarker.State = fixtureRetainedMarkerAcknowledged
	next.RetainedMarker.AcknowledgedResourceVersion = "102"
	return next
}

// Pure schema/transition instrumentation, never a native effect or wire ACK.
func TestFixtureMarkerSchemaRejectsMalformedAndCoupledEffects(t *testing.T) {
	f := newFixture(t, false)
	ledger, err := f.engine.prepareFixtureLedger(t.Context(), f.snapshot)
	if err != nil {
		t.Fatal("original ledger unavailable")
	}
	defer ledger.close()
	acknowledgeAllRecipeFixtures(t, ledger)
	unchanged := bytes.Clone(ledger.body)
	for _, rv := range []string{"", "0", "01", "18446744073709551616", "foreign"} {
		next := fixtureMarkerIntent(t, ledger)
		next.RetainedMarker.BeforeResourceVersion = rv
		if _, err := f.engine.fixtureLedgerBody(next); err != ErrFixtures {
			t.Error("malformed marker intent RV accepted", rv)
		}
	}
	for _, state := range []fixtureRetainedMarkerState{"", "observed", "PRIVATE-CANARY", fixtureRetainedMarkerAcknowledged} {
		next := fixtureMarkerIntent(t, ledger)
		next.RetainedMarker.State = state
		if _, err := f.engine.fixtureLedgerBody(next); err != ErrFixtures {
			t.Error("unknown or unacknowledged marker state accepted")
		}
	}
	before, err := f.engine.decodeFixtureLedger(ledger.body)
	if err != nil {
		t.Fatal("pure original document unavailable")
	}
	before.RetainedMarker = &fixtureRetainedMarkerReceipt{State: fixtureRetainedMarkerAttempted, BeforeResourceVersion: "101"}
	for _, acknowledge := range []bool{false, true} {
		after := before
		after.Revision++
		after.Entries = append([]fixtureEntry(nil), before.Entries...)
		after.Entries[fixtureCancelledDestroy].State = fixtureDeleteAttempted
		after.Entries[fixtureCancelledDestroy].DeleteResourceVersion = "101"
		if acknowledge {
			after.RetainedMarker = &fixtureRetainedMarkerReceipt{State: fixtureRetainedMarkerAcknowledged, BeforeResourceVersion: "101", AcknowledgedResourceVersion: "102"}
		}
		if validFixtureTransition(before, after) {
			t.Error("unknown marker or combined ACK permitted cleanup")
		}
	}
	next := fixtureMarkerIntent(t, ledger)
	next.DestroySeed = &fixtureDestroySeedReceipt{State: fixtureDestroySeedAttempted, BeforeResourceVersion: "101"}
	if _, err := f.engine.fixtureLedgerBody(next); err != ErrFixtures || validFixtureTransition(ledger.document, next) {
		t.Error("both pending receipts or coupled receipt transition accepted")
	}
	if !bytes.Equal(unchanged, ledger.body) || f.access.writes != 0 || ledger.markerAck || ledger.markerEffect {
		t.Fatal("pure marker refusal mutated WAL or granted effects")
	}
}
