// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestFixtureOriginalWorldsSealLegacyCanonicalAndImmutable(t *testing.T) {
	f := newFixture(t, false)
	ledger, err := f.engine.prepareFixtureLedger(t.Context(), f.snapshot)
	if err != nil {
		t.Fatal("original ledger unavailable")
	}
	defer ledger.close()
	var legacy map[string]any
	if json.Unmarshal(ledger.body, &legacy) != nil {
		t.Fatal("canonical legacy unavailable")
	}
	if _, present := legacy["originalWorldsSHA256"]; present {
		t.Fatal("optional world seal changed legacy encoding")
	}
	for _, raw := range []string{"null", "42", `{}`, `[]`, `"not-a-digest"`} {
		malformed := append([]byte(`{"originalWorldsSHA256":`+raw+`,`), ledger.body[1:]...)
		if _, err := f.engine.decodeFixtureLedger(malformed); err != ErrFixtures {
			t.Fatal("explicit null/malformed seal accepted")
		}
	}
	body, err := f.engine.fixtureLedgerBody(ledger.document)
	if err != nil || !bytes.Equal(body, ledger.body) {
		t.Fatal("legacy canonical bytes changed")
	}
	for _, hash := range []string{"foreign", strings.Repeat("A", 64), strings.Repeat("a", 63), strings.Repeat("a", 65)} {
		next, _ := ledger.nextDocument()
		next.OriginalWorldsSHA256 = hash
		if ledger.advance(next) != ErrFixtures || ledger.worldPublication {
			t.Fatal("invalid world seal granted publication")
		}
	}
	next, _ := ledger.nextDocument()
	next.OriginalWorldsSHA256 = strings.Repeat("a", 64)
	combined := next
	combined.Entries = append([]fixtureEntry(nil), next.Entries...)
	combined.Entries[0].State = fixtureCreateAttempted
	if ledger.advance(combined) != ErrFixtures {
		t.Fatal("combined world seal and CREATE intent accepted")
	}
	if ledger.advance(next) != nil || !ledger.worldPublication || ledger.ackSlot != -1 || ledger.effectSlot != -1 || ledger.seedAck || ledger.seedEffect || ledger.markerAck || ledger.markerEffect {
		t.Fatal("durable seal granted anything except one file publication")
	}
	create, _ := ledger.nextDocument()
	create.Entries[0].State = fixtureCreateAttempted
	if ledger.advance(create) != ErrFixtures {
		t.Fatal("pending file publication permitted entry effect preparation")
	}
	sealed := bytes.Clone(ledger.body)
	if ledger.close() != nil || ledger.worldPublication {
		t.Fatal("close retained baseline publication capability")
	}
	loaded, err := f.engine.loadFixtureLedger(t.Context(), f.snapshot)
	if err != nil || loaded.worldPublication || !bytes.Equal(loaded.body, sealed) {
		t.Fatal("reload changed seal or restored publication")
	}
	defer loaded.close()
	for _, hash := range []string{"", strings.Repeat("b", 64), strings.Repeat("a", 64)} {
		replay, _ := loaded.nextDocument()
		replay.OriginalWorldsSHA256 = hash
		if loaded.advance(replay) != ErrFixtures {
			t.Fatal("world seal removed/changed/replayed")
		}
	}
	if f.engine.fixtureFence(f.snapshot) != ErrFixtures || f.access.writes != 0 || f.nsUpdates != 0 {
		t.Fatal("baseline intent retired fence or mutated cluster")
	}
}

func TestFixtureOriginalWorldsSealAfterEffectsAndStaleCapabilitiesRefused(t *testing.T) {
	for _, state := range []string{"create-intent", "original", "seed-cap", "marker-cap", "effect-cap", "file-replacement"} {
		t.Run(state, func(t *testing.T) {
			f := newFixture(t, false)
			ledger, err := f.engine.prepareFixtureLedger(t.Context(), f.snapshot)
			if err != nil {
				t.Fatal("original ledger unavailable")
			}
			defer ledger.close()
			switch state {
			case "create-intent":
				next, _ := ledger.nextDocument()
				next.Entries[0].State = fixtureCreateAttempted
				if ledger.advance(next) != nil {
					t.Fatal("CREATE intent setup failed")
				}
			case "original":
				acknowledgeAllRecipeFixtures(t, ledger)
			case "seed-cap":
				ledger.seedAck, ledger.seedEffect = true, true
			case "marker-cap":
				ledger.markerAck, ledger.markerEffect = true, true
			case "effect-cap":
				ledger.ackSlot, ledger.effectSlot = 0, 0
			case "file-replacement":
				if _, err := f.engine.files.AtomicWrite(ledger.name, bytes.Clone(ledger.body), &ledger.identity); err != nil {
					t.Fatal("protected replacement injection failed")
				}
			}
			next, _ := ledger.nextDocument()
			next.OriginalWorldsSHA256 = strings.Repeat("a", 64)
			before := bytes.Clone(ledger.body)
			if ledger.advance(next) != ErrFixtures || ledger.worldPublication || !bytes.Equal(before, ledger.body) {
				t.Fatal("late/unproved original baseline seal accepted")
			}
		})
	}
}
