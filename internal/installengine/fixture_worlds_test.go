// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	arcade "github.com/gobha-me/arcadectl/api/v1alpha1"
	"github.com/gobha-me/arcadectl/internal/installsafety"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func originalWorldRowsExample(t *testing.T, ledger *fixtureLedger) []fixtureWorldRow {
	t.Helper()
	ns := ledger.document.Entries[0].Key.Namespace
	tuple := &coldWorldTuple{
		Servers: []arcade.GameServer{{ObjectMeta: metav1.ObjectMeta{Name: "original-world", Namespace: ns, UID: "original-world-uid", ResourceVersion: "11"}}},
		Claims: []corev1.PersistentVolumeClaim{
			{ObjectMeta: metav1.ObjectMeta{Name: "orphan-retained", Namespace: ns, UID: "original-orphan-uid", ResourceVersion: "12", Annotations: map[string]string{"private-test-value": "PRIVATE-WORLD-CANARY"}}, Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimPending}},
			{ObjectMeta: metav1.ObjectMeta{Name: "bound-world", Namespace: ns, UID: "original-bound-uid", ResourceVersion: "13"}, Spec: corev1.PersistentVolumeClaimSpec{VolumeName: "original-pv"}},
		},
		Volumes: []*corev1.PersistentVolume{{ObjectMeta: metav1.ObjectMeta{Name: "original-pv", UID: "original-pv-uid", ResourceVersion: "14"}}},
	}
	rows, err := tuple.fixtureWorldRows()
	if err != nil {
		t.Fatal("original tuple rows unavailable")
	}
	return rows
}

func TestFixtureOriginalWorldsPublicationResumeAndPrivateIdentity(t *testing.T) {
	f := newFixture(t, false)
	ledger, err := f.engine.prepareFixtureLedger(t.Context(), f.snapshot)
	if err != nil {
		t.Fatal("original ledger unavailable")
	}
	rows := originalWorldRowsExample(t, ledger)
	if ledger.sealOriginalWorlds(rows) != nil || ledger.worldPublication || ledger.worldIdentity == nil || ledger.effectSlot != -1 || ledger.ackSlot != -1 {
		t.Fatal("original publication lost durability or granted fixture effects")
	}
	name, err := ledger.originalWorldsName()
	if err != nil || name != "admission-worlds-"+f.snapshot.Anchor().InstallationID+"-"+ledger.document.RunID+".json" {
		t.Fatal("companion address not bound to original installation/run")
	}
	body, _, err := f.engine.files.ReadEvidence(name, privatefs.MaxEvidenceFileBytes)
	if err != nil || bytes.Contains(body, []byte("CANARY")) || bytes.Contains(body, []byte("private-test-value")) || ledger.matchesOriginalWorlds(rows) != nil {
		t.Fatal("original evidence exposed raw settings or lost exact tuple")
	}
	for _, mutate := range []func([]fixtureWorldRow) []fixtureWorldRow{
		func(r []fixtureWorldRow) []fixtureWorldRow { return r[:len(r)-1] },
		func(r []fixtureWorldRow) []fixtureWorldRow { r[0].UID = "replacement"; return r },
		func(r []fixtureWorldRow) []fixtureWorldRow { r[0].ResourceVersion = "99"; return r },
		func(r []fixtureWorldRow) []fixtureWorldRow { r[0].SHA256 = strings.Repeat("b", 64); return r },
	} {
		if ledger.matchesOriginalWorlds(mutate(append([]fixtureWorldRow{}, rows...))) != ErrFixtures {
			t.Fatal("changed/lost original world accepted")
		}
	}
	if ledger.sealOriginalWorlds(rows) != ErrFixtures || ledger.close() != nil {
		t.Fatal("original baseline resealed or close failed")
	}
	loaded, err := f.engine.loadFixtureLedger(t.Context(), f.snapshot)
	if err != nil {
		t.Fatal("original WAL reload failed")
	}
	defer loaded.close()
	next, _ := loaded.nextDocument()
	next.Entries[0].State = fixtureCreateAttempted
	if loaded.advance(next) != ErrFixtures || loaded.effectSlot != -1 {
		t.Fatal("unverified companion restored effect capability")
	}
	witness, err := loaded.loadOriginalWorlds()
	if err != nil || !reflect.DeepEqual(witness.Rows, rows) || loaded.advance(next) != nil {
		t.Fatal("exact durable original companion could not be pinned")
	}
	// Replacement bytes alone cannot preserve this loaded session's inode.
	id := *loaded.worldIdentity
	if _, err := f.engine.files.AtomicWrite(name, body, &id); err != nil {
		t.Fatal("same-byte replacement injection failed")
	}
	if loaded.originalWorldsCurrent() != ErrFixtures {
		t.Fatal("same-byte replacement became original session evidence")
	}
	if _, err := loaded.loadOriginalWorlds(); err != ErrFixtures {
		t.Fatal("same-session reload adopted replacement inode")
	}
	if f.engine.fixtureFence(f.snapshot) != ErrFixtures || f.access.writes != 0 || f.nsUpdates != 0 {
		t.Fatal("companion observation granted ordinary effects or retired fence")
	}
}

func TestFixtureOriginalWorldsClosedCanonicalShape(t *testing.T) {
	f := newFixture(t, false)
	ledger, err := f.engine.prepareFixtureLedger(t.Context(), f.snapshot)
	if err != nil {
		t.Fatal("original ledger unavailable")
	}
	defer ledger.close()
	rows := originalWorldRowsExample(t, ledger)
	d := fixtureWorldsDocument{"original-worlds-v1", ledger.document.RunID, bytes.Clone(ledger.document.Journal), ledger.document.JournalResourceVersion, rows, nil}
	body, err := ledger.worldsBody(d)
	if err != nil {
		t.Fatal("original evidence encoding failed")
	}
	for _, field := range []string{"version", "runId", "journal", "journalResourceVersion", "rows"} {
		var raw map[string]any
		if json.Unmarshal(body, &raw) != nil {
			t.Fatal("canonical body unavailable")
		}
		raw[field] = nil
		changed, _ := json.Marshal(raw)
		if _, err := ledger.decodeWorlds(changed); err != ErrFixtures {
			t.Fatal("explicit null original evidence accepted")
		}
	}
	for _, fault := range []string{"unknown", "whitespace", "duplicate", "foreign-run", "foreign-journal-rv", "foreign-kind", "foreign-namespace", "pv-namespace", "bad-uid", "duplicate-uid", "duplicate-address", "unsorted", "bad-rv", "bad-hash"} {
		t.Run(fault, func(t *testing.T) {
			changed := d
			changed.Rows = append([]fixtureWorldRow{}, rows...)
			switch fault {
			case "unknown":
				if _, err := ledger.decodeWorlds(append([]byte(`{"unknown":true,`), body[1:]...)); err != ErrFixtures {
					t.Fatal("unknown original evidence accepted")
				}
				return
			case "whitespace":
				if _, err := ledger.decodeWorlds(append(body, '\n')); err != ErrFixtures {
					t.Fatal("noncanonical original evidence accepted")
				}
				return
			case "duplicate":
				if _, err := ledger.decodeWorlds(append([]byte(`{"version":"original-worlds-v1",`), body[1:]...)); err != ErrFixtures {
					t.Fatal("duplicate original evidence key accepted")
				}
				return
			case "foreign-run":
				changed.RunID = strings.Repeat("b", 12)
			case "foreign-journal-rv":
				changed.JournalResourceVersion = "999"
			case "foreign-kind":
				changed.Rows[0].Key.Kind = "Secret"
			case "foreign-namespace":
				changed.Rows[0].Key.Namespace = "foreign"
			case "pv-namespace":
				changed.Rows[1].Key.Namespace = "foreign"
			case "bad-uid":
				changed.Rows[0].UID = ""
			case "duplicate-uid":
				changed.Rows[1].UID = changed.Rows[0].UID
			case "duplicate-address":
				changed.Rows[1].Key = changed.Rows[0].Key
			case "unsorted":
				changed.Rows[0], changed.Rows[1] = changed.Rows[1], changed.Rows[0]
			case "bad-rv":
				changed.Rows[0].ResourceVersion = "01"
			case "bad-hash":
				changed.Rows[0].SHA256 = strings.Repeat("A", 64)
			}
			if _, err := ledger.worldsBody(changed); err != ErrFixtures {
				t.Fatal("foreign/malformed original evidence accepted")
			}
		})
	}
}

func TestFixtureOriginalWorldsMissingCompanionCannotPrepareAnyEffect(t *testing.T) {
	for _, effect := range []string{"create", "delete", "seed", "marker"} {
		t.Run(effect, func(t *testing.T) {
			f := newFixture(t, false)
			ledger, err := f.engine.prepareFixtureLedger(t.Context(), f.snapshot)
			if err != nil || ledger.sealOriginalWorlds([]fixtureWorldRow{}) != nil {
				t.Fatal("original evidence setup failed")
			}
			if effect != "create" {
				acknowledgeAllRecipeFixtures(t, ledger)
			}
			name, _ := ledger.originalWorldsName()
			if f.engine.files.RemoveEvidence(name, *ledger.worldIdentity) != nil || ledger.close() != nil {
				t.Fatal("missing-companion injection failed")
			}
			loaded, err := f.engine.loadFixtureLedger(t.Context(), f.snapshot)
			if err != nil {
				t.Fatal("original WAL unavailable")
			}
			defer loaded.close()
			if _, err := loaded.loadOriginalWorlds(); err != ErrFixtures {
				t.Fatal("missing original baseline adopted")
			}
			next, _ := loaded.nextDocument()
			switch effect {
			case "create":
				next.Entries[0].State = fixtureCreateAttempted
			case "delete":
				next.Entries[1].State, next.Entries[1].DeleteResourceVersion = fixtureDeleteAttempted, "101"
			case "seed":
				next = fixtureSeedIntent(t, loaded)
			case "marker":
				next = fixtureMarkerIntent(t, loaded)
			}
			before := bytes.Clone(loaded.body)
			if loaded.advance(next) != ErrFixtures || !bytes.Equal(before, loaded.body) || loaded.effectSlot != -1 || loaded.seedEffect || loaded.markerEffect || loaded.worldPublication {
				t.Fatal("missing companion restored a persistent effect capability")
			}
			if loaded.sealOriginalWorlds([]fixtureWorldRow{}) != ErrFixtures || f.access.writes != 0 {
				t.Fatal("reload rebaselined worlds or mutated cluster")
			}
		})
	}
}

func TestFixtureOriginalWorldsInMemorySealCannotSubstituteProtectedWAL(t *testing.T) {
	f := newFixture(t, false)
	ledger, err := f.engine.prepareFixtureLedger(t.Context(), f.snapshot)
	if err != nil || ledger.sealOriginalWorlds([]fixtureWorldRow{}) != nil {
		t.Fatal("original evidence setup failed")
	}
	original := ledger.document.OriginalWorldsSHA256
	name, _ := ledger.originalWorldsName()
	id := *ledger.worldIdentity
	if ledger.close() != nil {
		t.Fatal("original close failed")
	}
	loaded, err := f.engine.loadFixtureLedger(t.Context(), f.snapshot)
	if err != nil || loaded.worldIdentity != nil {
		t.Fatal("unpinned original reload unavailable")
	}
	defer loaded.close()
	// B really is canonical, valid for this journal/run, and has a matching
	// substituted in-memory digest. Only the original protected WAL distinguishes
	// it from A; neither missing bytes nor an old inode can mask this regression.
	rowsB := originalWorldRowsExample(t, loaded)
	d := fixtureWorldsDocument{"original-worlds-v1", loaded.document.RunID, bytes.Clone(loaded.document.Journal), loaded.document.JournalResourceVersion, rowsB, nil}
	bodyB, err := loaded.worldsBody(d)
	if err != nil {
		t.Fatal("canonical substitute unavailable")
	}
	if _, err := f.engine.files.AtomicWrite(name, bodyB, &id); err != nil {
		t.Fatal("companion substitution injection failed")
	}
	loaded.document.OriginalWorldsSHA256 = fixtureWorldDigest(bodyB)
	if _, err := loaded.loadOriginalWorlds(); err != ErrFixtures || loaded.worldIdentity != nil || loaded.matchesOriginalWorlds(rowsB) != ErrFixtures {
		t.Fatal("in-memory seal substituted protected WAL")
	}
	loaded.document.OriginalWorldsSHA256 = original
	if _, err := loaded.loadOriginalWorlds(); err != ErrFixtures || loaded.worldIdentity != nil {
		t.Fatal("substituted companion was adopted after restoring original seal")
	}
}

func TestFixtureOriginalWorldsSealImmutableAcrossCleanupBookkeeping(t *testing.T) {
	f := newFixture(t, false)
	ledger, err := f.engine.prepareFixtureLedger(t.Context(), f.snapshot)
	if err != nil || ledger.sealOriginalWorlds([]fixtureWorldRow{}) != nil {
		t.Fatal("original evidence setup failed")
	}
	defer ledger.close()
	acknowledgeAllRecipeFixtures(t, ledger)
	hash := ledger.document.OriginalWorldsSHA256
	for _, state := range []fixtureState{fixtureDeleteAttempted, fixtureAbsent} {
		next, _ := ledger.nextDocument()
		next.Entries[1].State, next.Entries[1].DeleteResourceVersion = state, "101"
		for _, substitute := range []string{"", strings.Repeat("b", 64)} {
			changed := next
			changed.OriginalWorldsSHA256 = substitute
			if ledger.advance(changed) != ErrFixtures {
				t.Fatal("cleanup resealed original worlds")
			}
		}
		if ledger.advance(next) != nil || ledger.document.OriginalWorldsSHA256 != hash || ledger.originalWorldsCurrent() != nil {
			t.Fatal("valid cleanup bookkeeping changed original baseline")
		}
	}
	if ledger.engine.fixtureFence(f.snapshot) != ErrFixtures {
		t.Fatal("cleanup bookkeeping retired fixture fence")
	}
}

func TestFixtureOriginalWorldsPreexistingPublicationCannotBeReplayed(t *testing.T) {
	f := newFixture(t, false)
	ledger, err := f.engine.prepareFixtureLedger(t.Context(), f.snapshot)
	if err != nil {
		t.Fatal("original WAL unavailable")
	}
	defer ledger.close()
	d := fixtureWorldsDocument{"original-worlds-v1", ledger.document.RunID, bytes.Clone(ledger.document.Journal), ledger.document.JournalResourceVersion, []fixtureWorldRow{}, nil}
	body, err := ledger.worldsBody(d)
	name, nameErr := ledger.originalWorldsName()
	if err != nil || nameErr != nil {
		t.Fatal("original companion body unavailable")
	}
	id, err := ledger.engine.files.CreateEvidenceExclusive(name, body)
	if err != nil {
		t.Fatal("visible publication injection failed")
	}
	if ledger.sealOriginalWorlds([]fixtureWorldRow{}) != ErrFixtures || ledger.worldPublication || ledger.worldIdentity != nil || ledger.effectSlot != -1 || ledger.document.OriginalWorldsSHA256 != fixtureWorldDigest(body) {
		t.Fatal("uncertain publication granted effects or lost sealed intent")
	}
	if ledger.publishOriginalWorlds(body) != ErrFixtures {
		t.Fatal("publication capability replayed")
	}
	if _, err := ledger.loadOriginalWorlds(); err != nil || ledger.worldIdentity == nil || *ledger.worldIdentity != id {
		t.Fatal("exact visible sealed companion could not be confirmed durable")
	}
	if ledger.engine.fixtureFence(f.snapshot) != ErrFixtures {
		t.Fatal("visible evidence retired active WAL")
	}
}

func TestFixtureOriginalWorldsPerKindBoundsAndLargeEvidence(t *testing.T) {
	f := newFixture(t, false)
	ledger, err := f.engine.prepareFixtureLedger(t.Context(), f.snapshot)
	if err != nil {
		t.Fatal("original WAL unavailable")
	}
	defer ledger.close()
	rows := make([]fixtureWorldRow, installsafety.MaxObjectsPerList)
	ns := ledger.document.Entries[0].Key.Namespace
	key := originalWorldRowsExample(t, ledger)[2].Key
	for i := range rows {
		rows[i] = fixtureWorldRow{Key: key, UID: types.UID(fmt.Sprintf("claim-uid-%05d", i)), ResourceVersion: "1", SHA256: strings.Repeat("a", 64)}
		rows[i].Key.Namespace, rows[i].Key.Name = ns, fmt.Sprintf("claim-%05d", i)
	}
	sortFixtureWorlds(rows)
	if ledger.sealOriginalWorlds(rows) != nil {
		t.Fatal("valid original inventory exceeding ordinary file limit refused")
	}
	name, _ := ledger.originalWorldsName()
	body, _, err := ledger.engine.files.ReadEvidence(name, privatefs.MaxEvidenceFileBytes)
	if err != nil || int64(len(body)) <= privatefs.MaxFileBytes {
		t.Fatal("large companion did not exercise distinct evidence limit")
	}
	d, err := ledger.loadOriginalWorlds()
	if err != nil || len(d.Rows) != installsafety.MaxObjectsPerList {
		t.Fatal("large original inventory lost members")
	}
	extra := rows[len(rows)-1]
	extra.Key.Name, extra.UID = "claim-extra", "claim-extra-uid"
	d.Rows = append(d.Rows, extra)
	sortFixtureWorlds(d.Rows)
	if _, err := ledger.worldsBody(d); err != ErrFixtures {
		t.Fatal("per-kind inventory bound widened to aggregate bound")
	}
}
