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

// Pure WAL/capability instrumentation. No HTTP effect, complete behavior
// matrix, native result or current AdmissionEffective proof is fabricated.
func fixtureBehaviorPrerequisites(t *testing.T, ledger *fixtureLedger, mode fixtureDestroySeedMode) {
	t.Helper()
	acknowledgeAllRecipeFixtures(t, ledger)
	seed := fixtureSeedIntent(t, ledger)
	seed.DestroySeed.Mode = mode
	if ledger.advance(seed) != nil {
		t.Fatal("seed intent unavailable")
	}
	ledger.seedEffect = false // test-only simulation of send consumption
	if ledger.advance(fixtureSeedAcknowledgement(t, ledger)) != nil || ledger.advance(fixtureMarkerIntent(t, ledger)) != nil {
		t.Fatal("seed ACK or marker intent unavailable")
	}
	ledger.markerEffect = false // no wire/native ACK is claimed
	if ledger.advance(fixtureMarkerAcknowledgement(t, ledger)) != nil {
		t.Fatal("marker ACK unavailable")
	}
}

func fixtureBehaviorIntent(t *testing.T, ledger *fixtureLedger) fixtureLedgerDocument {
	t.Helper()
	next, err := ledger.nextDocument()
	if err != nil {
		t.Fatal(err)
	}
	next.Behavior = &fixtureBehaviorReceipt{fixtureBehaviorVersion, next.Revision}
	return next
}

func instrumentFixtureBehaviorCompletion(ledger *fixtureLedger) *fixtureBehaviorCompletion {
	return &fixtureBehaviorCompletion{ledger: ledger, revision: ledger.document.Revision, bodySHA: fixtureWorldDigest(ledger.body), identity: ledger.identity}
}

func TestFixtureBehaviorStrictSchemaAndStandaloneTransition(t *testing.T) {
	f := newFixture(t, false)
	ledger, err := f.engine.prepareFixtureLedger(t.Context(), f.snapshot)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.close()
	legacy := bytes.Clone(ledger.body)
	if bytes.Contains(legacy, []byte(`"behavior"`)) {
		t.Fatal("optional receipt changed legacy canonical bytes")
	}
	if ledger.sealOriginalWorlds([]fixtureWorldRow{}) != nil {
		t.Fatal("original seal unavailable")
	}
	fixtureBehaviorPrerequisites(t, ledger, fixtureDestroySeedCold)
	good := fixtureBehaviorIntent(t, ledger)
	if !validFixtureTransition(ledger.document, good) {
		t.Fatal("standalone schema transition rejected")
	}
	for name, mutate := range map[string]func(*fixtureLedgerDocument){
		"version":            func(d *fixtureLedgerDocument) { d.Behavior.Version = "future" },
		"zero-revision":      func(d *fixtureLedgerDocument) { d.Behavior.Revision = 0 },
		"future-revision":    func(d *fixtureLedgerDocument) { d.Behavior.Revision = d.Revision + 1 },
		"unbounded-revision": func(d *fixtureLedgerDocument) { d.Behavior.Revision = 9007199254740992 },
		"missing-worlds":     func(d *fixtureLedgerDocument) { d.OriginalWorldsSHA256 = "" },
		"missing-seed":       func(d *fixtureLedgerDocument) { d.DestroySeed = nil },
		"unknown-seed": func(d *fixtureLedgerDocument) {
			d.DestroySeed.State = fixtureDestroySeedAttempted
			d.DestroySeed.AcknowledgedResourceVersion = ""
		},
		"missing-marker": func(d *fixtureLedgerDocument) { d.RetainedMarker = nil },
		"unknown-marker": func(d *fixtureLedgerDocument) {
			d.RetainedMarker.State = fixtureRetainedMarkerAttempted
			d.RetainedMarker.AcknowledgedResourceVersion = ""
		},
		"missing-original":   func(d *fixtureLedgerDocument) { d.Entries[9].OriginalUID = "" },
		"duplicate-original": func(d *fixtureLedgerDocument) { d.Entries[9].OriginalUID = d.Entries[8].OriginalUID },
		"cleanup-at-publication-revision": func(d *fixtureLedgerDocument) {
			d.Entries[9].State, d.Entries[9].DeleteResourceVersion = fixtureDeleteAttempted, "200"
		},
		"absence-at-publication-revision": func(d *fixtureLedgerDocument) {
			d.Entries[9].State, d.Entries[9].DeleteResourceVersion = fixtureAbsent, "200"
		},
		"unknown-create": func(d *fixtureLedgerDocument) {
			d.Entries[9].State = fixtureCreateAttempted
			d.Entries[9].OriginalUID = ""
		},
	} {
		t.Run(name, func(t *testing.T) {
			d := fixtureBehaviorIntent(t, ledger)
			mutate(&d)
			if _, err := f.engine.fixtureLedgerBody(d); err != ErrFixtures || validFixtureTransition(ledger.document, d) {
				t.Fatal("invalid behavior receipt accepted")
			}
		})
	}
	for _, mutate := range []func(*fixtureLedgerDocument){
		func(d *fixtureLedgerDocument) { d.Behavior.Revision-- },
		func(d *fixtureLedgerDocument) { d.DestroySeed.BeforeResourceVersion = "100" },
		func(d *fixtureLedgerDocument) { d.RetainedMarker.BeforeResourceVersion = "100" },
		func(d *fixtureLedgerDocument) {
			d.Entries[9].State = fixtureDeleteAttempted
			d.Entries[9].DeleteResourceVersion = "200"
		},
	} {
		d := fixtureBehaviorIntent(t, ledger)
		mutate(&d)
		if validFixtureTransition(ledger.document, d) {
			t.Fatal("combined or late receipt transition accepted")
		}
	}
	body, err := f.engine.fixtureLedgerBody(good)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{
		bytes.Replace(body, []byte(`"version":"admission-behavior-v1"`), []byte(`"extra":true,"version":"admission-behavior-v1"`), 1),
		bytes.Replace(body, []byte(`"behavior":{`), []byte(`"behavior":null,"duplicateBehavior":{`), 1),
	} {
		bad, err = canonicaljson.CanonicalJSON(bad)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.engine.decodeFixtureLedger(bad); err != ErrFixtures {
			t.Fatal("unknown nested receipt field accepted")
		}
	}
	var raw map[string]any
	if json.Unmarshal(body, &raw) != nil {
		t.Fatal("canonical receipt unavailable")
	}
	raw["behavior"] = nil
	bad, _ := json.Marshal(raw)
	bad, _ = canonicaljson.CanonicalJSON(bad)
	if _, err := f.engine.decodeFixtureLedger(bad); err != ErrFixtures {
		t.Fatal("explicit null receipt accepted")
	}
}

func TestFixtureBehaviorPublicationRequiresPinnedSameInstanceCompletion(t *testing.T) {
	f := newFixture(t, false)
	ledger, err := f.engine.prepareFixtureLedger(t.Context(), f.snapshot)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.close()
	if ledger.sealOriginalWorlds([]fixtureWorldRow{}) != nil {
		t.Fatal("original seal unavailable")
	}
	fixtureBehaviorPrerequisites(t, ledger, fixtureDestroySeedWarmCancelled)
	before := bytes.Clone(ledger.body)
	next := fixtureBehaviorIntent(t, ledger)
	for _, mutate := range []func(*fixtureBehaviorCompletion){
		func(c *fixtureBehaviorCompletion) { c.ledger = &fixtureLedger{} },
		func(c *fixtureBehaviorCompletion) { c.revision-- },
		func(c *fixtureBehaviorCompletion) { c.bodySHA = "" },
		func(c *fixtureBehaviorCompletion) { c.identity = fixtureLedger{}.identity },
	} {
		ledger.behaviorCompletion = instrumentFixtureBehaviorCompletion(ledger)
		mutate(ledger.behaviorCompletion)
		if ledger.advance(next) != ErrFixtures || !bytes.Equal(before, ledger.body) {
			t.Fatal("foreign or stale completion advanced")
		}
	}
	ledger.behaviorCompletion = nil
	if ledger.advance(next) != ErrFixtures || !bytes.Equal(before, ledger.body) {
		t.Fatal("durable prerequisites became behavior capability")
	}
	for _, flag := range []*bool{&ledger.seedAck, &ledger.seedEffect, &ledger.markerAck, &ledger.markerEffect, &ledger.worldPublication} {
		ledger.behaviorCompletion = instrumentFixtureBehaviorCompletion(ledger)
		*flag = true
		if ledger.advance(next) != ErrFixtures || !bytes.Equal(before, ledger.body) {
			t.Fatal("outstanding effect/ACK/publication admitted completion")
		}
		*flag = false
	}
	for _, slot := range []*int{&ledger.ackSlot, &ledger.effectSlot} {
		ledger.behaviorCompletion = instrumentFixtureBehaviorCompletion(ledger)
		*slot = 0
		if ledger.advance(next) != ErrFixtures || !bytes.Equal(before, ledger.body) {
			t.Fatal("outstanding original CREATE capability admitted completion")
		}
		*slot = -1
	}
	ledger.behaviorCompletion = instrumentFixtureBehaviorCompletion(ledger)
	cleanup, _ := ledger.nextDocument()
	cleanup.Entries[9].State, cleanup.Entries[9].DeleteResourceVersion = fixtureDeleteAttempted, "200"
	if ledger.advance(cleanup) != ErrFixtures {
		t.Fatal("unrelated cleanup carried an unspent completion")
	}
	if ledger.advance(next) != nil || ledger.behaviorCompletion != nil || !reflect.DeepEqual(ledger.document.Behavior, next.Behavior) || f.access.writes != 0 {
		t.Fatal("standalone durable publication failed or retained capability")
	}
	for _, mutate := range []func(*fixtureLedgerDocument){
		func(d *fixtureLedgerDocument) { d.Behavior = nil },
		func(d *fixtureLedgerDocument) { d.Behavior.Revision++ },
		func(d *fixtureLedgerDocument) { d.Behavior.Version = "future" },
	} {
		d, _ := ledger.nextDocument()
		mutate(&d)
		if ledger.advance(d) != ErrFixtures {
			t.Fatal("published behavior receipt changed")
		}
	}
	receipt := *ledger.document.Behavior
	if ledger.close() != nil {
		t.Fatal("close failed")
	}
	loaded, err := f.engine.loadFixtureLedger(t.Context(), f.snapshot)
	if err != nil || loaded.behaviorCompletion != nil || *loaded.document.Behavior != receipt || f.engine.fixtureFence(f.snapshot) != ErrFixtures {
		t.Fatal("receipt reload restored permission or bypassed active fence", err)
	}
	defer loaded.close()
	if _, err := loaded.loadOriginalWorlds(); err != nil {
		t.Fatal("original companion unavailable")
	}
	for slot := len(fixtureCatalog) - 1; slot >= 0; slot-- {
		d, _ := loaded.nextDocument()
		d.Entries[slot].State, d.Entries[slot].DeleteResourceVersion = fixtureDeleteAttempted, "200"
		if loaded.advance(d) != nil {
			t.Fatal("receipt blocked original reverse cleanup")
		}
		d, _ = loaded.nextDocument()
		d.Entries[slot].State = fixtureAbsent
		if loaded.advance(d) != nil || *loaded.document.Behavior != receipt || loaded.behaviorCompletion != nil {
			t.Fatal("cleanup changed receipt or granted completion")
		}
	}
}

func TestFixtureBehaviorUnpublishedCompletionDoesNotSurviveReload(t *testing.T) {
	f := newFixture(t, false)
	ledger, err := f.engine.prepareFixtureLedger(t.Context(), f.snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if ledger.sealOriginalWorlds([]fixtureWorldRow{}) != nil {
		t.Fatal("seal unavailable")
	}
	fixtureBehaviorPrerequisites(t, ledger, fixtureDestroySeedCold)
	ledger.behaviorCompletion = instrumentFixtureBehaviorCompletion(ledger)
	if ledger.close() != nil || ledger.behaviorCompletion != nil {
		t.Fatal("close retained completion")
	}
	loaded, err := f.engine.loadFixtureLedger(t.Context(), f.snapshot)
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.close()
	if loaded.behaviorCompletion != nil || loaded.document.Behavior != nil || loaded.advance(fixtureBehaviorIntent(t, loaded)) != ErrFixtures {
		t.Fatal("reload inferred completion from prerequisites")
	}
}

func TestFixtureBehaviorHistoricalArchivesRemainReadOnly(t *testing.T) {
	newPhase := fixturePhaseFactory(t)
	for _, completed := range []bool{false, true} {
		name := "aborted-without-receipt"
		if completed {
			name = "historical-completion"
		}
		t.Run(name, func(t *testing.T) {
			h := newPhase(t)
			ledger, s := h.f.wire.ledger, h.f.actor.request.Snapshot
			if completed {
				fixtureBehaviorPrerequisites(t, ledger, fixtureDestroySeedCold)
				ledger.behaviorCompletion = instrumentFixtureBehaviorCompletion(ledger)
				if ledger.advance(fixtureBehaviorIntent(t, ledger)) != nil {
					t.Fatal("instrumented historical completion unavailable")
				}
				for slot := len(fixtureCatalog) - 1; slot >= 0; slot-- {
					next, _ := ledger.nextDocument()
					next.Entries[slot].State, next.Entries[slot].DeleteResourceVersion = fixtureDeleteAttempted, "200"
					if ledger.advance(next) != nil {
						t.Fatal("original cleanup intent unavailable")
					}
					next, _ = ledger.nextDocument()
					next.Entries[slot].State = fixtureAbsent
					if ledger.advance(next) != nil {
						t.Fatal("original cleanup acknowledgement unavailable")
					}
				}
			} else {
				terminalFixturePhase(t, h)
			}
			fixtureRetirementIntent(t, h)
			archive := bytes.Clone(ledger.body)
			evidence, err := ledger.engine.readFixtureRetirement(s.Anchor())
			if err != nil || !bytes.Equal(evidence.archive, archive) {
				t.Fatal("intrinsic historical receipt validation refused", err)
			}
			if ledger.engine.files.Remove(ledger.name, ledger.identity) != nil || ledger.close() != nil {
				t.Fatal("simulated interrupted unlink unavailable")
			}
			loaded, err := ledger.engine.loadFixtureRetirement(t.Context(), s)
			if err != nil {
				t.Fatal(err)
			}
			if !loaded.retirementArchive || loaded.behaviorCompletion != nil || !bytes.Equal(loaded.body, archive) || (loaded.document.Behavior != nil) != completed || loaded.advance(fixtureBehaviorIntent(t, loaded)) != ErrFixtures || ledger.engine.fixtureFence(s) != ErrFixtures {
				t.Fatal("historical archive restored capability or cleared Intent fence")
			}
			if loaded.close() != nil {
				t.Fatal("archive close unavailable")
			}
			// Malformed chronology/null remain invalid with canonical bytes and
			// recomputed archive hash/sentinel; validation is intrinsic.
			mutations := []func(map[string]any){func(raw map[string]any) { raw["behavior"] = nil }}
			if completed {
				mutations = append(mutations, func(raw map[string]any) { raw["behavior"].(map[string]any)["revision"] = raw["revision"] })
			}
			archiveID, sentinelID := evidence.archiveIdentity, evidence.identity
			for _, mutate := range mutations {
				var raw map[string]any
				if json.Unmarshal(archive, &raw) != nil {
					t.Fatal("original archive unavailable")
				}
				mutate(raw)
				bad, _ := json.Marshal(raw)
				bad, _ = canonicaljson.CanonicalJSON(bad)
				archiveID, err = ledger.engine.files.AtomicWrite(fixtureArchiveName(s.Anchor(), ledger.document.RunID), bad, &archiveID)
				if err != nil {
					t.Fatal(err)
				}
				record := evidence.record
				record.LedgerSHA256 = fixtureWorldDigest(bad)
				body, err := fixtureRetirementBody(record, s.Anchor())
				if err != nil {
					t.Fatal(err)
				}
				sentinelID, err = ledger.engine.files.AtomicWrite(fixtureRetirementName(s.Anchor()), body, &sentinelID)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := ledger.engine.readFixtureRetirement(s.Anchor()); err != ErrFixtures || ledger.engine.fixtureFence(s) != ErrFixtures {
					t.Fatal("rehashing promoted malformed historical receipt")
				}
			}
		})
	}
}
