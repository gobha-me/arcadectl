// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"encoding/json"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/canonicaljson"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Ledger instrumentation and fake replies only, never native status/coldness,
// acknowledgement, confirmation or cleanup authority.
func TestFixtureSeedModesCanonicalImmutableAndColdGuards(t *testing.T) {
	for _, mode := range []fixtureDestroySeedMode{fixtureDestroySeedCold, fixtureDestroySeedWarmCancelled} {
		t.Run(string(mode), func(t *testing.T) {
			f := newFixture(t, false)
			ledger, err := f.engine.prepareFixtureLedger(t.Context(), f.snapshot)
			if err != nil {
				t.Fatal("original ledger unavailable")
			}
			defer ledger.close()
			acknowledgeAllRecipeFixtures(t, ledger)
			created := time.Now().UTC().Truncate(time.Second).Add(-20 * time.Second)
			seed := fixtureDestroySeedExample(t, ledger, created)
			if ledger.validateDestroySeedResult(seed, time.Now().UTC()) != nil {
				t.Fatal("nil-receipt pure cold contract changed")
			}
			confirmation := seed.DeepCopy()
			confirmation.SetResourceVersion("102")
			confirmation.SetGeneration(2)
			_ = unstructured.SetNestedField(confirmation.Object, ledger.document.RunID, "spec", "confirmationChallenge")
			fields := confirmation.Object["metadata"].(map[string]any)["managedFields"].([]any)
			fields[0].(map[string]any)["fieldsV1"].(map[string]any)["f:spec"].(map[string]any)["f:confirmationChallenge"] = map[string]any{}
			fields[0].(map[string]any)["time"] = created.Add(12 * time.Second).Format(time.RFC3339)
			fields[0], fields[1] = fields[1], fields[0]
			before := bytes.Clone(ledger.body)
			for _, bad := range []fixtureDestroySeedMode{"cold", "warm", "warm-cancelled-v2", "UNKNOWN", "PRIVATE-MODE-CANARY"} {
				intent := fixtureSeedIntent(t, ledger)
				intent.DestroySeed.Mode = bad
				if _, err := ledger.engine.fixtureLedgerBody(intent); err != ErrFixtures || !bytes.Equal(before, ledger.body) {
					t.Fatal("unknown mode accepted or changed protected state")
				}
			}
			intent := fixtureSeedIntent(t, ledger)
			intent.DestroySeed.Mode = mode
			if ledger.advance(intent) != nil {
				t.Fatal("closed mode intent refused")
			}
			var encoded map[string]json.RawMessage
			if json.Unmarshal(ledger.body, &encoded) != nil {
				t.Fatal("canonical ledger unavailable")
			}
			expected := `{"acknowledgedResourceVersion":"","beforeResourceVersion":"101","state":"attempted"}`
			if mode == fixtureDestroySeedWarmCancelled {
				expected = `{"acknowledgedResourceVersion":"","beforeResourceVersion":"101","mode":"warm-cancelled-v1","state":"attempted"}`
			}
			if string(encoded["destroySeed"]) != expected {
				t.Fatal("cold legacy bytes or closed warm encoding changed")
			}
			for _, raw := range []string{`""`, `null`, `"cold"`, `"warm"`, `"warm-cancelled-v2"`, `1`, `[]`, `{}`} {
				var receipt map[string]json.RawMessage
				_ = json.Unmarshal(encoded["destroySeed"], &receipt)
				receipt["mode"] = json.RawMessage(raw)
				changed, _ := json.Marshal(receipt)
				copyDoc := map[string]json.RawMessage{}
				for key, value := range encoded {
					copyDoc[key] = value
				}
				copyDoc["destroySeed"] = changed
				body, _ := json.Marshal(copyDoc)
				body, _ = canonicaljson.CanonicalJSON(body)
				if _, err := ledger.engine.decodeFixtureLedger(body); err != ErrFixtures {
					t.Fatal("unknown, null, explicit empty or mistyped mode accepted")
				}
			}
			want := error(nil)
			if mode == fixtureDestroySeedWarmCancelled {
				want = ErrFixtures
			}
			_, recipeErr := ledger.destroySeedStatus()
			if recipeErr != want || ledger.validateDestroySeedResult(seed, time.Now().UTC()) != want {
				t.Fatal("pure cold route accepted warm intent or rejected cold intent")
			}
			// Test-only send-consumption simulation, not a reliable native ACK.
			ledger.seedEffect = false
			other := fixtureDestroySeedWarmCancelled
			if mode == other {
				other = fixtureDestroySeedCold
			}
			for _, combined := range []bool{false, true} {
				ack := fixtureSeedAcknowledgement(t, ledger)
				ack.DestroySeed.Mode = other
				if combined {
					ack.Entries[fixtureCancelledDestroy].State, ack.Entries[fixtureCancelledDestroy].DeleteResourceVersion = fixtureDeleteAttempted, "101"
				}
				if ledger.advance(ack) != ErrFixtures || ledger.document.DestroySeed.Mode != mode || !ledger.seedAck {
					t.Fatal("mode replacement crossed acknowledgement boundary")
				}
			}
			if ledger.advance(fixtureSeedAcknowledgement(t, ledger)) != nil {
				t.Fatal("same-mode ACK instrumentation refused")
			}
			if ledger.validateDestroyConfirmationResult(confirmation, time.Now().UTC()) != want {
				t.Fatal("cold confirmation accepted warm receipt or rejected cold receipt")
			}
			if (&fixtureWire{ledger: ledger}).fixturesSettled() != (mode == fixtureDestroySeedCold) {
				t.Fatal("cold settled composition accepted warm receipt")
			}
			ack := fixtureSeedAcknowledgement(t, ledger)
			ack.DestroySeed.Mode = other
			if ledger.advance(ack) != ErrFixtures {
				t.Fatal("acknowledged mode replaced")
			}
			if ledger.close() != nil {
				t.Fatal("acknowledged receipt close unavailable")
			}
			loaded, err := f.engine.loadFixtureLedger(t.Context(), f.snapshot)
			if err != nil {
				t.Fatal("acknowledged receipt reload unavailable")
			}
			defer loaded.close()
			_, loadedRecipeErr := loaded.destroySeedStatus()
			if loaded.document.DestroySeed.Mode != mode || loaded.seedAck || loaded.seedEffect || loadedRecipeErr != want || loaded.validateDestroySeedResult(seed, time.Now().UTC()) != want || loaded.validateDestroyConfirmationResult(confirmation, time.Now().UTC()) != want || (&fixtureWire{ledger: loaded}).fixturesSettled() != (mode == fixtureDestroySeedCold) {
				t.Fatal("acknowledged reload erased mode, granted capabilities or entered cold composition")
			}
			// Abstract original-only cleanup transitions preserve mode; this is
			// NOT native absence or permission to send a DELETE.
			next, _ := loaded.nextDocument()
			next.Entries[fixtureCancelledDestroy].State, next.Entries[fixtureCancelledDestroy].DeleteResourceVersion = fixtureDeleteAttempted, "102"
			if loaded.advance(next) != nil {
				t.Fatal("acknowledged mode blocked abstract original cleanup")
			}
			next, _ = loaded.nextDocument()
			next.Entries[fixtureCancelledDestroy].State = fixtureAbsent
			if loaded.advance(next) != nil || loaded.document.DestroySeed.Mode != mode || loaded.seedAck || loaded.seedEffect {
				t.Fatal("abstract cleanup replaced receipt mode or granted seed capabilities")
			}
			if f.engine.fixtureFence(f.snapshot) != ErrFixtures || f.access.writes != 0 || f.nsUpdates != 0 {
				t.Fatal("mode bookkeeping granted effects or retired fence")
			}
		})
	}
}

func TestFixtureSeedModesUnknownReloadStaysFenced(t *testing.T) {
	for _, mode := range []fixtureDestroySeedMode{fixtureDestroySeedCold, fixtureDestroySeedWarmCancelled} {
		t.Run(string(mode), func(t *testing.T) {
			f := newFixture(t, false)
			ledger, err := f.engine.prepareFixtureLedger(t.Context(), f.snapshot)
			if err != nil {
				t.Fatal("original ledger unavailable")
			}
			acknowledgeAllRecipeFixtures(t, ledger)
			intent := fixtureSeedIntent(t, ledger)
			intent.DestroySeed.Mode = mode
			if ledger.advance(intent) != nil || ledger.close() != nil {
				t.Fatal("unknown intent persistence unavailable")
			}
			loaded, err := f.engine.loadFixtureLedger(t.Context(), f.snapshot)
			if err != nil {
				t.Fatal("protected unknown intent reload unavailable")
			}
			defer loaded.close()
			if loaded.document.DestroySeed.Mode != mode || loaded.seedAck || loaded.seedEffect || loaded.advance(fixtureSeedAcknowledgement(t, loaded)) != ErrFixtures {
				t.Fatal("reload restored or replaced status acknowledgement capability")
			}
			next, _ := loaded.nextDocument()
			next.Entries[fixtureCancelledDestroy].State, next.Entries[fixtureCancelledDestroy].DeleteResourceVersion = fixtureDeleteAttempted, "101"
			if loaded.advance(next) != ErrFixtures || f.engine.fixtureFence(f.snapshot) != ErrFixtures || f.access.writes != 0 {
				t.Fatal("unknown mode permitted cleanup or ordinary effects")
			}
		})
	}
}

func TestFixtureWarmSeedModeRefusesColdRoutesBeforeAnyHTTP(t *testing.T) {
	f := fixturePreviewFactory(t)(t)
	ledger := f.wire.ledger
	acknowledgeAllRecipeFixtures(t, ledger)
	created := time.Now().UTC().Truncate(time.Second).Add(-20 * time.Second)
	for slot := range fixtureCatalog {
		f.objects[slot] = fixtureResultExample(t, ledger, slot, fixtureStableResult, created)
	}
	intent := fixtureSeedIntent(t, ledger)
	intent.DestroySeed.Mode = fixtureDestroySeedWarmCancelled
	if ledger.advance(intent) != nil {
		t.Fatal("warm intent unavailable")
	}
	before, identity, revision := bytes.Clone(ledger.body), ledger.identity, ledger.document.Revision
	var calls atomic.Int64
	original := f.actor.fixtureHandler
	f.actor.fixtureHandler = func(w http.ResponseWriter, r *http.Request) bool { calls.Add(1); return original(w, r) }
	if f.wire.prepareDestroySeed(t.Context()) != ErrFixtures {
		t.Fatal("cold preparation accepted warm intent")
	}
	if _, err := f.wire.destroySeedPayload(t.Context()); err != ErrFixtures {
		t.Fatal("cold payload accepted warm intent")
	}
	if _, err := f.wire.seedDestroyStatus(t.Context()); err != ErrFixtures {
		t.Fatal("cold entrypoint accepted warm intent")
	}
	if _, err := f.wire.request(t.Context(), fixtureCancelledDestroy, fixtureSeedStatusRequest); err != ErrFixtures {
		t.Fatal("cold enum accepted warm intent")
	}
	body, currentID, err := ledger.engine.files.Read(ledger.name, fixtureLedgerMaxBytes)
	if err != nil || currentID != identity || !bytes.Equal(body, before) || !bytes.Equal(ledger.body, before) || ledger.document.Revision != revision || !ledger.seedAck || !ledger.seedEffect || calls.Load() != 0 || f.reads != 0 || f.seeds != 0 || ledger.engine.fixtureFence(f.actor.request.Snapshot) != ErrFixtures {
		t.Fatal("cross-mode refusal sent a request or changed protected state/capabilities")
	}
}
