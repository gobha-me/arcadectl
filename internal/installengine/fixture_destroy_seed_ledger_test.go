// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/gobha-me/arcadectl/internal/canonicaljson"
)

func fixtureSeedIntent(t *testing.T, ledger *fixtureLedger) fixtureLedgerDocument {
	t.Helper()
	next, err := ledger.nextDocument()
	if err != nil {
		t.Fatal(err)
	}
	next.DestroySeed = &fixtureDestroySeedReceipt{State: fixtureDestroySeedAttempted, BeforeResourceVersion: "101"}
	return next
}

func fixtureSeedAcknowledgement(t *testing.T, ledger *fixtureLedger) fixtureLedgerDocument {
	t.Helper()
	next, err := ledger.nextDocument()
	if err != nil || next.DestroySeed == nil {
		t.Fatal("seed intent unavailable")
	}
	next.DestroySeed.State = fixtureDestroySeedAcknowledged
	next.DestroySeed.AcknowledgedResourceVersion = "102"
	return next
}

// WAL/capability instrumentation only. No status write or reliable native ACK
// is fabricated; the future closed wire must consume send before transport and
// receive a reliable original UID/RV ACK before attempting this transition.
func TestFixtureDestroySeedLedgerTransitionsAndCleanupFence(t *testing.T) {
	f := newFixture(t, false)
	ledger, err := f.engine.prepareFixtureLedger(t.Context(), f.snapshot)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.close()
	if ledger.advance(fixtureSeedIntent(t, ledger)) != ErrFixtures || ledger.seedAck || ledger.seedEffect {
		t.Fatal("seed intent allowed before all original acknowledgements")
	}
	acknowledgeAllRecipeFixtures(t, ledger)
	before := bytes.Clone(ledger.body)
	intent := fixtureSeedIntent(t, ledger)
	for _, rv := range []string{"", "0", "01", "18446744073709551616", "foreign"} {
		intent.DestroySeed.BeforeResourceVersion = rv
		if ledger.advance(intent) != ErrFixtures || !bytes.Equal(before, ledger.body) || ledger.seedAck || ledger.seedEffect {
			t.Fatal("malformed intent advanced or granted seed capabilities")
		}
	}
	intent = fixtureSeedIntent(t, ledger)
	intent.DestroySeed.State = fixtureDestroySeedAcknowledged
	intent.DestroySeed.AcknowledgedResourceVersion = "102"
	if ledger.advance(intent) != ErrFixtures {
		t.Fatal("seed acknowledgement skipped durable attempted state")
	}
	intent = fixtureSeedIntent(t, ledger)
	intent.Entries[fixturePlainPVC].State = fixtureDeleteAttempted
	intent.Entries[fixturePlainPVC].DeleteResourceVersion = "101"
	if ledger.advance(intent) != ErrFixtures {
		t.Fatal("combined seed and entry transition accepted")
	}
	intent = fixtureSeedIntent(t, ledger)
	if ledger.advance(intent) != nil || !ledger.seedAck || !ledger.seedEffect || ledger.ackSlot != -1 || ledger.effectSlot != -1 {
		t.Fatal("durable intent did not grant only separate same-instance capabilities")
	}
	if ledger.advance(fixtureSeedAcknowledgement(t, ledger)) != ErrFixtures {
		t.Fatal("ACK accepted before send capability consumed")
	}
	for slot := range fixtureCatalog {
		next, _ := ledger.nextDocument()
		next.Entries[slot].State = fixtureDeleteAttempted
		next.Entries[slot].DeleteResourceVersion = "101"
		if ledger.advance(next) != ErrFixtures {
			t.Fatal("unknown seed allowed ordinary cleanup transition")
		}
	}
	for _, change := range []func(*fixtureLedgerDocument){
		func(d *fixtureLedgerDocument) { d.DestroySeed = nil },
		func(d *fixtureLedgerDocument) { d.DestroySeed.BeforeResourceVersion = "103" },
		func(d *fixtureLedgerDocument) { d.DestroySeed.State = "observed" },
		func(d *fixtureLedgerDocument) { d.DestroySeed.AcknowledgedResourceVersion = "102" },
		func(d *fixtureLedgerDocument) {},
	} {
		next, _ := ledger.nextDocument()
		change(&next)
		if ledger.advance(next) != ErrFixtures {
			t.Fatal("unknown seed cleared, replaced, settled or replayed")
		}
	}
	// Test-only simulation of pre-Do capability consumption. No HTTP request or
	// live acknowledgement is claimed by this state-machine test.
	ledger.seedEffect = false
	ack := fixtureSeedAcknowledgement(t, ledger)
	for _, rv := range []string{"", "101", "0", "0102", "18446744073709551616", "foreign"} {
		ack.DestroySeed.AcknowledgedResourceVersion = rv
		if ledger.advance(ack) != ErrFixtures {
			t.Fatal("unchanged or malformed acknowledged RV accepted")
		}
	}
	if ledger.advance(fixtureSeedAcknowledgement(t, ledger)) != nil || ledger.seedAck || ledger.seedEffect {
		t.Fatal("same-attempt ACK failed or restored send/ACK capabilities")
	}
	receipt := *ledger.document.DestroySeed
	if ledger.close() != nil {
		t.Fatal("acknowledged ledger close unavailable")
	}
	ledger, err = f.engine.loadFixtureLedger(t.Context(), f.snapshot)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.close()
	if ledger.seedAck || ledger.seedEffect || *ledger.document.DestroySeed != receipt {
		t.Fatal("acknowledged reload restored capabilities or changed receipt")
	}
	for _, slot := range []int{9, 8, 7, 6, 5, 4, 3, 2, 1, 0} {
		next, _ := ledger.nextDocument()
		next.Entries[slot].State, next.Entries[slot].DeleteResourceVersion = fixtureDeleteAttempted, "200"
		if ledger.advance(next) != nil {
			t.Fatal("acknowledged seed incorrectly blocked original cleanup ordering")
		}
		next, _ = ledger.nextDocument()
		next.Entries[slot].State = fixtureAbsent
		if ledger.advance(next) != nil || *ledger.document.DestroySeed != receipt || ledger.seedAck || ledger.seedEffect {
			t.Fatal("cleanup lost original seed receipt or revived capabilities")
		}
	}
	for _, change := range []func(*fixtureLedgerDocument){
		func(d *fixtureLedgerDocument) { d.DestroySeed = nil },
		func(d *fixtureLedgerDocument) {
			d.DestroySeed.State = fixtureDestroySeedAttempted
			d.DestroySeed.AcknowledgedResourceVersion = ""
		},
		func(d *fixtureLedgerDocument) { d.DestroySeed.AcknowledgedResourceVersion = "103" },
		func(d *fixtureLedgerDocument) { d.DestroySeed.BeforeResourceVersion = "100" },
	} {
		next, _ := ledger.nextDocument()
		change(&next)
		if ledger.advance(next) != ErrFixtures {
			t.Fatal("acknowledged receipt removed, replaced or reseeded")
		}
	}
	if f.engine.fixtureFence(f.snapshot) != ErrFixtures || f.access.writes != 0 || f.nsUpdates != 0 {
		t.Fatal("state primitive performed cluster effects or retired unresolved fixture fence")
	}
}

func TestFixtureDestroySeedLedgerCanonicalLegacyAndMalformedReceipts(t *testing.T) {
	f := newFixture(t, false)
	ledger, err := f.engine.prepareFixtureLedger(t.Context(), f.snapshot)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.close()
	legacy := bytes.Clone(ledger.body)
	d, err := f.engine.decodeFixtureLedger(legacy)
	if err != nil || d.DestroySeed != nil {
		t.Fatal("canonical pre-seed v1 document refused")
	}
	roundTrip, err := f.engine.fixtureLedgerBody(d)
	if err != nil || !bytes.Equal(legacy, roundTrip) || bytes.Contains(roundTrip, []byte("destroySeed")) {
		t.Fatal("optional seed field rewrote legacy canonical v1 bytes")
	}
	acknowledgeAllRecipeFixtures(t, ledger)
	if ledger.advance(fixtureSeedIntent(t, ledger)) != nil {
		t.Fatal("intent unavailable")
	}
	valid := bytes.Clone(ledger.body)
	for _, raw := range []string{
		`null`, `{}`, `"PRIVATE-CANARY"`,
		`{"state":"attempted","beforeResourceVersion":"101","acknowledgedResourceVersion":"","private":"PRIVATE-CANARY"}`,
		`{"state":"attempted","beforeResourceVersion":"101","acknowledgedResourceVersion":null}`,
		`{"state":"attempted","beforeResourceVersion":"101"}`,
		`{"state":"attempted","beforeResourceVersion":"101","acknowledgedResourceVersion":"102"}`,
		`{"state":"observed","beforeResourceVersion":"101","acknowledgedResourceVersion":"102"}`,
		`{"state":"acknowledged","beforeResourceVersion":"101","acknowledgedResourceVersion":"101"}`,
		`{"state":"acknowledged","beforeResourceVersion":"01","acknowledgedResourceVersion":"102"}`,
	} {
		var object map[string]json.RawMessage
		if json.Unmarshal(valid, &object) != nil {
			t.Fatal("test document unavailable")
		}
		object["destroySeed"] = json.RawMessage(raw)
		body, err := json.Marshal(object)
		if err != nil {
			t.Fatal(err)
		}
		body, err = canonicaljson.CanonicalJSON(body)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.engine.decodeFixtureLedger(body); err != ErrFixtures {
			t.Fatal("malformed/noncanonical receipt accepted")
		}
	}
	for slot := range fixtureCatalog {
		for _, state := range []fixtureState{fixturePlanned, fixtureCreateAttempted, fixtureDeleteAttempted, fixtureAbsent} {
			d, _ := f.engine.decodeFixtureLedger(valid)
			d.Entries[slot].State = state
			if state == fixturePlanned || state == fixtureCreateAttempted {
				d.Entries[slot].OriginalUID = ""
			} else {
				d.Entries[slot].DeleteResourceVersion = "101"
			}
			if _, err := f.engine.fixtureLedgerBody(d); err != ErrFixtures {
				t.Fatal("attempted seed admitted partial creation or cleanup inventory")
			}
		}
		d, _ := f.engine.decodeFixtureLedger(valid)
		d.Entries[slot].OriginalUID = "receipt-valid-but-not-native"
		if _, err := f.engine.fixtureLedgerBody(d); err != ErrFixtures {
			t.Fatal("seed receipt admitted non-native original UID")
		}
	}
	next, _ := ledger.nextDocument()
	next.DestroySeed.BeforeResourceVersion = "999"
	if ledger.document.DestroySeed.BeforeResourceVersion != "101" || reflect.DeepEqual(next.DestroySeed, ledger.document.DestroySeed) {
		t.Fatal("next document aliases protected receipt")
	}
}

func TestFixtureDestroySeedLedgerUnknownReloadCannotAcknowledgeOrClean(t *testing.T) {
	f := newFixture(t, false)
	ledger, err := f.engine.prepareFixtureLedger(t.Context(), f.snapshot)
	if err != nil {
		t.Fatal(err)
	}
	acknowledgeAllRecipeFixtures(t, ledger)
	if ledger.advance(fixtureSeedIntent(t, ledger)) != nil {
		t.Fatal("intent unavailable")
	}
	// An uncertain send consumes both capabilities and MUST NOT be inferred from
	// a later observed body/RV. The closed wire will revoke ACK on every outcome.
	ledger.seedAck, ledger.seedEffect = false, false
	before := bytes.Clone(ledger.body)
	if ledger.advance(fixtureSeedAcknowledgement(t, ledger)) != ErrFixtures {
		t.Fatal("uncertain same-instance status effect fabricated an ACK")
	}
	if ledger.close() != nil {
		t.Fatal("ledger close unavailable")
	}
	loaded, err := f.engine.loadFixtureLedger(t.Context(), f.snapshot)
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.close()
	if loaded.seedAck || loaded.seedEffect || !bytes.Equal(before, loaded.body) || loaded.document.DestroySeed.State != fixtureDestroySeedAttempted {
		t.Fatal("protected reload restored send/ACK capability or settled unknown outcome")
	}
	if loaded.advance(fixtureSeedAcknowledgement(t, loaded)) != ErrFixtures {
		t.Fatal("reloaded ledger converted a guessed/observed RV into original ACK")
	}
	// An in-memory receipt accidentally cleared by future provider code must
	// not turn the still-durable attempted record into a new send capability.
	receipt := loaded.document.DestroySeed
	loaded.document.DestroySeed = nil
	next, _ := loaded.nextDocument()
	if loaded.advance(next) != ErrFixtures || loaded.seedAck || loaded.seedEffect {
		t.Fatal("document/body drift reset unknown seed for a second attempt")
	}
	loaded.document.DestroySeed = receipt
	for slot := range fixtureCatalog {
		next, _ := loaded.nextDocument()
		next.Entries[slot].State, next.Entries[slot].DeleteResourceVersion = fixtureDeleteAttempted, "200"
		if loaded.advance(next) != ErrFixtures {
			t.Fatal("reloaded unknown seed permitted cleanup")
		}
	}
	if !bytes.Equal(before, loaded.body) || f.engine.fixtureFence(f.snapshot) != ErrFixtures || f.access.writes != 0 || f.nsUpdates != 0 {
		t.Fatal("unknown seed transitioned, changed cluster or retired fence")
	}
}

func TestFixtureDestroySeedLedgerProtectedReplacementCannotGrantCapabilities(t *testing.T) {
	for _, stage := range []string{"intent", "ack", "closed-store", "closed-ledger"} {
		t.Run(stage, func(t *testing.T) {
			f := newFixture(t, false)
			ledger, err := f.engine.prepareFixtureLedger(t.Context(), f.snapshot)
			if err != nil {
				t.Fatal(err)
			}
			defer ledger.close()
			acknowledgeAllRecipeFixtures(t, ledger)
			next := fixtureSeedIntent(t, ledger)
			if stage == "ack" || stage == "closed-ledger" {
				if ledger.advance(next) != nil {
					t.Fatal("intent unavailable")
				}
				if stage == "closed-ledger" {
					if !ledger.seedAck || !ledger.seedEffect || ledger.close() != nil || ledger.seedAck || ledger.seedEffect || ledger.advance(fixtureLedgerDocument{}) != ErrFixtures {
						t.Fatal("close failed to revoke active seed capabilities/transition access")
					}
					return
				}
				ledger.seedEffect = false
				next = fixtureSeedAcknowledgement(t, ledger)
			}
			before := bytes.Clone(ledger.body)
			if stage == "closed-store" {
				if f.engine.files.Close() != nil || ledger.advance(next) != ErrFixtures || ledger.seedAck || ledger.seedEffect || !bytes.Equal(before, ledger.body) {
					t.Fatal("unavailable protected store advanced intent or granted capabilities")
				}
				return
			}
			if _, err := f.engine.files.AtomicWrite(ledger.name, before, &ledger.identity); err != nil {
				t.Fatal(err)
			}
			if ledger.advance(next) != ErrFixtures || !bytes.Equal(before, ledger.body) || stage == "intent" && (ledger.seedAck || ledger.seedEffect) || stage == "ack" && ledger.document.DestroySeed.State != fixtureDestroySeedAttempted {
				t.Fatal("byte-identical protected inode replacement admitted seed transition")
			}
		})
	}
}
