// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/gobha-me/arcadectl/internal/canonicaljson"
	"github.com/gobha-me/arcadectl/internal/installstate"
	"github.com/gobha-me/arcadectl/internal/privatefs"
)

// These exercise the production wire/provider on complete sealed fake HTTPS
// observations. They are not native admission or signed-binary certification.
func terminalFixturePhase(t *testing.T, h *fixturePhaseTest) {
	t.Helper()
	f := h.f.wire.ledger
	for slot := len(fixtureCatalog) - 1; slot >= 0; slot-- {
		next, err := f.nextDocument()
		if err != nil {
			t.Fatal(err)
		}
		next.Entries[slot].State = fixtureAbsent
		if err := f.advance(next); err != nil {
			t.Fatal(err)
		}
	}
}

func fixtureRetirementIntent(t *testing.T, h *fixturePhaseTest) privatefs.FileIdentity {
	t.Helper()
	f, s := h.f.wire.ledger, h.f.actor.request.Snapshot
	a := s.Anchor()
	if _, err := f.engine.files.CreateExclusive(fixtureArchiveName(a, f.document.RunID), f.body); err != nil {
		t.Fatal(err)
	}
	r := fixtureRetirementRecord{"fixture-retirement-v1", fixtureRetiring, a.Namespace, a.UID, a.InstallationID, f.document.RunID, fixtureWorldDigest(f.body), f.document.OriginalWorldsSHA256, fixtureWorldDigest(f.document.Journal), f.document.JournalResourceVersion}
	body, err := fixtureRetirementBody(r, a)
	if err != nil {
		t.Fatal(err)
	}
	id, err := f.engine.files.CreateExclusive(fixtureRetirementName(a), body)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestFixtureRetirementFreshAndInterruptedUnlink(t *testing.T) {
	newPhase := fixturePhaseFactory(t)
	for _, scenario := range []string{"fresh", "intent-wal-present", "intent-wal-absent"} {
		t.Run(scenario, func(t *testing.T) {
			h := newPhase(t)
			terminalFixturePhase(t, h)
			f, s := h.f.wire.ledger, h.f.actor.request.Snapshot
			original := bytes.Clone(f.body)
			if scenario != "fresh" {
				fixtureRetirementIntent(t, h)
				if scenario == "intent-wal-absent" {
					if f.engine.files.Remove(f.name, f.identity) != nil {
						t.Fatal("simulated durable unlink refused")
					}
				}
				if f.engine.fixtureFence(s) != ErrFixtures || f.close() != nil {
					t.Fatal("Intent lost the fence or original lock")
				}
				loaded, err := f.engine.loadFixtureRetirement(t.Context(), s)
				if err != nil || loaded.ackSlot != -1 || loaded.effectSlot != -1 || loaded.seedAck || loaded.seedEffect || loaded.markerAck || loaded.markerEffect || !bytes.Equal(loaded.body, original) || loaded.retirementArchive != (scenario == "intent-wal-absent") {
					t.Fatal("resume changed terminal evidence or restored capability", err)
				}
				defer loaded.close()
				h.f.wire.ledger, f = loaded, loaded
			}
			if err := h.f.wire.retireDrained(t.Context()); err != nil {
				t.Fatal("complete original retirement refused", err)
			}
			if f.engine.fixtureFence(s) != nil || !f.retirementArchive || h.f.creates != 0 || h.f.deletes != 0 || h.f.seeds != 0 {
				t.Fatal("retirement failed to retire the fence or sent a fixture effect")
			}
			if _, _, err := f.engine.files.Read(fixtureLedgerName(s), fixtureLedgerMaxBytes); !errors.Is(err, privatefs.ErrNotFound) {
				t.Fatal("active WAL was recreated")
			}
			evidence, err := f.engine.readFixtureRetirement(s.Anchor())
			if err != nil || evidence.record.State != fixtureRetired || !bytes.Equal(evidence.archive, original) {
				t.Fatal("exact terminal archive/sentinel not durable", err)
			}
			next, _ := f.nextDocument()
			if f.advance(next) != ErrFixtures || h.f.wire.retireDrained(t.Context()) != ErrFixtures {
				t.Fatal("historical retirement was promoted into current capability")
			}
			// Reappearance contradicts this retired run; names/bytes are not an
			// authorization to unlink again or restore fixture capabilities.
			if _, err := f.engine.files.CreateExclusive(fixtureLedgerName(s), original); err != nil || f.engine.fixtureFence(s) != ErrFixtures {
				t.Fatal("reappearing active WAL bypassed the fence")
			}
		})
	}
}

func TestFixtureRetirementRefusesUnprovedAndChangedEvidence(t *testing.T) {
	newPhase := fixturePhaseFactory(t)
	for _, scenario := range []string{"not-terminal", "missing-companion", "intent-archive-drift", "intent-companion-drift", "late-wal-replacement", "late-sentinel-replacement", "malformed-sentinel-absent-wal"} {
		t.Run(scenario, func(t *testing.T) {
			h := newPhase(t)
			f, s := h.f.wire.ledger, h.f.actor.request.Snapshot
			if scenario != "not-terminal" {
				terminalFixturePhase(t, h)
			}
			switch scenario {
			case "missing-companion":
				name, _ := f.originalWorldsName()
				if f.engine.files.Remove(name, *f.worldIdentity) != nil {
					t.Fatal("companion removal unavailable")
				}
			case "intent-archive-drift", "intent-companion-drift":
				fixtureRetirementIntent(t, h)
				name := fixtureArchiveName(s.Anchor(), f.document.RunID)
				if scenario == "intent-companion-drift" {
					name, _ = f.originalWorldsName()
				}
				_, id, err := f.engine.files.Read(name, fixtureLedgerMaxBytes)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := f.engine.files.AtomicWrite(name, []byte("{}"), &id); err != nil {
					t.Fatal(err)
				}
			case "late-wal-replacement":
				h.afterGet = func(int) {
					if _, err := f.engine.files.AtomicWrite(f.name, f.body, &f.identity); err != nil {
						t.Error(err)
					}
					h.afterGet = nil
				}
			case "late-sentinel-replacement":
				id := fixtureRetirementIntent(t, h)
				name := fixtureRetirementName(s.Anchor())
				body, _, _ := f.engine.files.Read(name, fixtureLedgerMaxBytes)
				h.afterGet = func(int) {
					if _, err := f.engine.files.AtomicWrite(name, body, &id); err != nil {
						t.Error(err)
					}
					h.afterGet = nil
				}
			case "malformed-sentinel-absent-wal":
				if _, err := f.engine.files.CreateExclusive(fixtureRetirementName(s.Anchor()), []byte("{}")); err != nil || f.engine.files.Remove(f.name, f.identity) != nil {
					t.Fatal("malformed sentinel setup unavailable")
				}
			}
			if h.f.wire.retireDrained(t.Context()) != ErrFixtures || f.engine.fixtureFence(s) != ErrFixtures || h.f.creates != 0 || h.f.deletes != 0 || h.f.seeds != 0 {
				t.Fatal("unproved/changed evidence retired the fence or issued effect")
			}
		})
	}
}

func TestFixtureRetirementLoadedSessionPinsSentinelAndArchive(t *testing.T) {
	newPhase := fixturePhaseFactory(t)
	for _, scenario := range []string{"sentinel", "archive"} {
		t.Run(scenario, func(t *testing.T) {
			h := newPhase(t)
			terminalFixturePhase(t, h)
			f, s := h.f.wire.ledger, h.f.actor.request.Snapshot
			fixtureRetirementIntent(t, h)
			if f.close() != nil {
				t.Fatal("original lock unavailable")
			}
			loaded, err := f.engine.loadFixtureRetirement(t.Context(), s)
			if err != nil {
				t.Fatal(err)
			}
			defer loaded.close()
			h.f.wire.ledger = loaded
			name := fixtureRetirementName(s.Anchor())
			if scenario == "archive" {
				name = fixtureArchiveName(s.Anchor(), loaded.document.RunID)
			}
			body, id, err := loaded.engine.files.Read(name, fixtureLedgerMaxBytes)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := loaded.engine.files.AtomicWrite(name, body, &id); err != nil {
				t.Fatal(err)
			}
			if h.f.wire.retireDrained(t.Context()) != ErrFixtures || loaded.engine.fixtureFence(s) != ErrFixtures {
				t.Fatal("same loaded session repinned replaced evidence")
			}
		})
	}
}

func TestFixtureRetirementHistoricalMalformedArchiveStaysFenced(t *testing.T) {
	newPhase := fixturePhaseFactory(t)
	for _, scenario := range []string{"unknown-seed", "unknown-marker", "broken-prefix", "invalid-world-row"} {
		t.Run(scenario, func(t *testing.T) {
			h := newPhase(t)
			terminalFixturePhase(t, h)
			f, s := h.f.wire.ledger, h.f.actor.request.Snapshot
			a := s.Anchor()
			fixtureRetirementIntent(t, h)
			evidence, err := f.engine.readFixtureRetirement(a)
			if err != nil {
				t.Fatal(err)
			}
			d := f.document
			switch scenario {
			case "unknown-seed":
				d.DestroySeed = &fixtureDestroySeedReceipt{State: fixtureDestroySeedAttempted, BeforeResourceVersion: "101"}
			case "unknown-marker":
				d.RetainedMarker = &fixtureRetainedMarkerReceipt{State: fixtureRetainedMarkerAttempted, BeforeResourceVersion: "101"}
			case "broken-prefix":
				d.Entries = append([]fixtureEntry{}, d.Entries...)
				d.Entries[fixturePlainPod].OriginalUID = "late-original-after-never-created"
				d.Entries[fixturePlainPod].DeleteResourceVersion = "101"
			case "invalid-world-row":
				world, err := f.readOriginalWorlds(false)
				if err != nil {
					t.Fatal(err)
				}
				world.Rows = append(world.Rows, fixtureWorldRow{Key: installstate.Key{APIVersion: "v1", Kind: "Pod", Namespace: a.Namespace, Name: "not-a-world"}, UID: "foreign-row", ResourceVersion: "100", SHA256: fixtureWorldDigest([]byte("{}"))})
				body, _ := json.Marshal(world)
				body, _ = canonicaljson.CanonicalEvidenceJSON(body)
				name, _ := f.originalWorldsName()
				if _, err := f.engine.files.AtomicWrite(name, body, f.worldIdentity); err != nil {
					t.Fatal(err)
				}
				d.OriginalWorldsSHA256 = fixtureWorldDigest(body)
			}
			// Recompute every public hash so this tests the intrinsic schema and
			// receipt invariants, not merely digest mismatch detection.
			archive, _ := json.Marshal(d)
			archive, _ = canonicaljson.CanonicalJSON(archive)
			if _, err := f.engine.files.AtomicWrite(fixtureArchiveName(a, d.RunID), archive, &evidence.archiveIdentity); err != nil {
				t.Fatal(err)
			}
			r := evidence.record
			r.State, r.LedgerSHA256, r.OriginalWorldsSHA256 = fixtureRetired, fixtureWorldDigest(archive), d.OriginalWorldsSHA256
			body, err := fixtureRetirementBody(r, a)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.engine.files.AtomicWrite(fixtureRetirementName(a), body, &evidence.identity); err != nil || f.engine.files.Remove(f.name, f.identity) != nil {
				t.Fatal("historical malformed chain setup unavailable", err)
			}
			if f.engine.fixtureFence(s) != ErrFixtures {
				t.Fatal("malformed historical chain cleared absent-WAL fence")
			}
		})
	}
}

func TestFixtureRetirementPartialPublicationRemainsFenced(t *testing.T) {
	newPhase := fixturePhaseFactory(t)
	for _, scenario := range []string{"acquired-sentinel-replaced", "missing-pinned-archive", "unknown-publication"} {
		t.Run(scenario, func(t *testing.T) {
			h := newPhase(t)
			terminalFixturePhase(t, h)
			f, s := h.f.wire.ledger, h.f.actor.request.Snapshot
			archiveName := fixtureArchiveName(s.Anchor(), f.document.RunID)
			switch scenario {
			case "acquired-sentinel-replaced":
				id := fixtureRetirementIntent(t, h)
				f.retirementSentinelIdentity = &id // acquisition before later durability barrier
				name := fixtureRetirementName(s.Anchor())
				body, _, err := f.engine.files.Read(name, fixtureLedgerMaxBytes)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := f.engine.files.AtomicWrite(name, body, &id); err != nil {
					t.Fatal(err)
				}
			case "missing-pinned-archive":
				id, err := f.engine.files.CreateExclusive(archiveName, f.body)
				if err != nil {
					t.Fatal(err)
				}
				f.retirementArchiveIdentity = &id
				if f.engine.files.Remove(archiveName, id) != nil {
					t.Fatal("pinned archive removal unavailable")
				}
			case "unknown-publication":
				f.retirementPublicationUnknown = true // no reliable publication identity
			}
			if h.f.wire.retireDrained(t.Context()) != ErrFixtures || f.engine.fixtureFence(s) != ErrFixtures {
				t.Fatal("partial publication silently repinned or cleared fence")
			}
			if scenario == "missing-pinned-archive" {
				if _, _, err := f.engine.files.Read(archiveName, fixtureLedgerMaxBytes); !errors.Is(err, privatefs.ErrNotFound) {
					t.Fatal("missing immutable witness was reconstructed")
				}
			}
		})
	}
}

func TestFixtureRetirementHistoricalEvidenceAndNextRun(t *testing.T) {
	h := fixturePhaseFactory(t)(t)
	terminalFixturePhase(t, h)
	f, s := h.f.wire.ledger, h.f.actor.request.Snapshot
	if h.f.wire.retireDrained(t.Context()) != nil || f.close() != nil {
		t.Fatal("original retirement unavailable")
	}
	// Old package contracts are unnecessary for HISTORICAL cleanup. This
	// deliberately cannot produce a resume ledger or behavioral success.
	plans := f.engine.plans
	f.engine.plans = nil
	if f.engine.fixtureFence(s) != nil {
		t.Fatal("historical retired evidence required unavailable old package")
	}
	f.engine.plans = plans
	foreign := s.Anchor()
	foreign.UID = "replacement-namespace"
	if _, err := f.engine.readFixtureRetirement(foreign); err != ErrFixtures {
		t.Fatal("same installation name adopted a replacement namespace")
	}
	if _, err := f.engine.loadFixtureRetirement(t.Context(), s); err != ErrFixtures {
		t.Fatal("retired history reloaded as a current retirement intent")
	}
	previous, err := f.engine.readFixtureRetirement(s.Anchor())
	if err != nil {
		t.Fatal(err)
	}
	next, err := f.engine.prepareFixtureLedger(t.Context(), s)
	if err != nil || next.document.RunID == f.document.RunID || f.engine.fixtureFence(s) != ErrFixtures {
		t.Fatal("retired history failed to permit a distinct fresh fenced run", err)
	}
	defer next.close()
	// Retired record cannot authorize deleting this NEW run, nor promote its
	// Planned addresses into absence, fixture ownership or admission proof.
	if _, err := f.engine.loadFixtureRetirement(t.Context(), &installstate.Snapshot{}); err == nil {
		t.Fatal("unrelated snapshot admitted retirement recovery")
	}
	initial, err := h.f.actor.admission.captureInitialPhase(t.Context(), h.f.actor.request)
	if err != nil || initial.seal(next) != nil {
		t.Fatal("distinct fresh original baseline unavailable", err)
	}
	wire, err := h.f.wire.actors.fixtures(t.Context(), next)
	if err != nil {
		t.Fatal(err)
	}
	h.f.wire = wire
	terminalFixturePhase(t, h)
	if wire.retireDrained(t.Context()) != nil || f.engine.fixtureFence(s) != nil {
		t.Fatal("distinct original run could not CAS prior retired sentinel")
	}
	current, err := f.engine.readFixtureRetirement(s.Anchor())
	if err != nil || current.record.RunID != next.document.RunID || current.record.RunID == previous.record.RunID {
		t.Fatal("new disposition lost its own run identity", err)
	}
	oldBody, oldID, err := f.engine.files.Read(fixtureArchiveName(s.Anchor(), previous.record.RunID), fixtureLedgerMaxBytes)
	if err != nil || oldID != previous.archiveIdentity || !bytes.Equal(oldBody, previous.archive) {
		t.Fatal("new run altered immutable historical archive", err)
	}
}
