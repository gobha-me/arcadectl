// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/privatefs"
)

// Subtests belong to an existing whole-root race shard; no new root or native
// proof is introduced. This tests pure materialization, never a live permit.
func testFixtureWorldsShapeCache(t *testing.T) {
	for _, recipe := range []string{"v1", "v2"} {
		t.Run(recipe, func(t *testing.T) {
			var h *fixturePhaseTest
			if recipe == "v1" {
				h = fixturePhaseFactory(t)(t)
			} else {
				h = unmarkedRecoveryPhaseFactory(t)(t)
			}
			f := h.f.wire.ledger
			name, err := f.originalWorldsName()
			if err != nil {
				t.Fatal("legacy phase address unavailable")
			}
			body, _, err := f.engine.files.ReadEvidence(name, privatefs.MaxEvidenceFileBytes)
			if err != nil {
				t.Fatal("legacy companion unavailable")
			}
			want, err := decodeFixtureWorldsShape(body, h.f.actor.request.Snapshot.Anchor().Namespace)
			if err != nil || want.Phase == nil || want.Phase.Accounts != nil {
				t.Fatal("strict legacy phase unavailable")
			}
			for repeat := 0; repeat < 2; repeat++ {
				got, err := f.decodeWorlds(body)
				if err != nil || !reflect.DeepEqual(got, want) {
					t.Fatal("legacy miss/hit differs from strict decoder")
				}
			}
		})
	}
	h := fixtureV3PhaseFactory(t)(t)
	f := h.f.wire.ledger
	name, err := f.originalWorldsName()
	if err != nil {
		t.Fatal("companion address unavailable")
	}
	body, _, err := f.engine.files.ReadEvidence(name, privatefs.MaxEvidenceFileBytes)
	if err != nil {
		t.Fatal("companion unavailable")
	}
	ns := h.f.actor.request.Snapshot.Anchor().Namespace
	want, err := decodeFixtureWorldsShape(body, ns)
	if err != nil || want.Phase == nil || want.Phase.Accounts == nil {
		t.Fatal("v3 strict companion unavailable")
	}
	got, err := f.decodeWorlds(body)
	if err != nil || !reflect.DeepEqual(want, got) || !bytes.Equal(f.decodeCache.worldsBody, body) {
		t.Fatal("bound companion differs from strict parse")
	}
	pin := &f.decodeCache.worldsBody[0]
	poison := func(d *fixtureWorldsDocument) {
		d.Journal[0] = '!'
		if len(d.Rows) != 0 {
			d.Rows[0].UID = "foreign"
		}
		d.Phase.Version = "foreign"
		if len(d.Phase.Rows) != 0 {
			d.Phase.Rows[0].UID = "foreign"
		}
		if len(d.Phase.Public) != 0 {
			d.Phase.Public[0].UID = "foreign"
		}
		for i := range d.Phase.Leaders {
			d.Phase.Leaders[i].Row.UID = "foreign"
			if len(d.Phase.Leaders[i].ManagedTimes) != 0 {
				d.Phase.Leaders[i].ManagedTimes[0] = "foreign"
			}
		}
		d.Phase.Accounts.Version = "foreign"
		if len(d.Phase.Accounts.Rows) != 0 {
			d.Phase.Accounts.Rows[0].UID = "foreign"
		}
	}
	for repeat := 0; repeat < 3; repeat++ {
		poison(&got)
		got, err = f.decodeWorlds(body)
		if err != nil || !reflect.DeepEqual(want, got) || &f.decodeCache.worldsBody[0] != pin {
			t.Fatal("miss/hit result poisoned owned shape or exact hit not reused")
		}
	}
	body[0] = '!'
	if bytes.Equal(body, f.decodeCache.worldsBody) {
		t.Fatal("input aliases cache key")
	}
	if _, err := f.decodeWorlds(body); err != ErrFixtures {
		t.Fatal("changed malformed input reused a prior hit")
	}
	body[0] = '{'
	for _, malformed := range [][]byte{nil, []byte("null"), append(bytes.Clone(body), ' '), append([]byte(`{"unknown":true,`), body[1:]...), append([]byte(`{"version":"original-worlds-v1",`), body[1:]...)} {
		for repeat := 0; repeat < 2; repeat++ {
			if _, err := f.decodeWorlds(malformed); err != ErrFixtures || !bytes.Equal(f.decodeCache.worldsBody, body) {
				t.Fatal("malformed/noncanonical parse remembered or accepted")
			}
		}
	}
	if _, err := f.decodeCurrentWorldsShape(body, "foreign-namespace"); err != ErrFixtures || f.decodeCache.worldsNS != ns {
		t.Fatal("same bytes reused across namespace or refused parse replaced entry")
	}
	// Foreign bindings can have a valid canonical SHAPE. Even after that shape
	// is warm, each call must refuse version/run/journal/RV/recipe mismatches.
	for _, field := range []string{"version", "run", "journal", "rv", "accounts"} {
		changed := cloneFixtureWorldsDocument(want)
		switch field {
		case "version":
			changed.Version = "foreign"
		case "run":
			changed.RunID = strings.Repeat("b", 32)
		case "journal":
			changed.Journal = []byte(`{"foreign":true}`)
		case "rv":
			changed.JournalResourceVersion = "999"
		case "accounts":
			changed.Phase.Accounts = nil
		}
		foreign, err := fixtureWorldsShapeBody(changed, ns)
		if err != nil {
			t.Fatal("foreign binding shape control unavailable", field)
		}
		for repeat := 0; repeat < 2; repeat++ {
			if _, err := f.decodeWorlds(foreign); err != ErrFixtures {
				t.Fatal("warm pure shape bypassed current binding", field)
			}
		}
	}
	// A valid, changed CURRENT WAL must also invalidate old run/RV bindings,
	// not just a substituted in-memory document rejected by worldsJournal.
	originalBody, originalDocument := bytes.Clone(f.body), cloneFixtureLedgerDocument(f.document)
	for _, field := range []string{"run", "rv", "recipe"} {
		next := cloneFixtureLedgerDocument(originalDocument)
		if field == "run" {
			next.RunID = strings.Repeat("b", 32)
			for i := range next.Entries {
				next.Entries[i].Key.Name = strings.Replace(next.Entries[i].Key.Name, originalDocument.RunID, next.RunID, 1)
			}
		} else if field == "rv" {
			next.JournalResourceVersion = "999"
		} else {
			next.Recipe, next.Entries = fixtureRecipeV2, next.Entries[:fixtureTokenlessAccount]
		}
		nextBody, err := f.engine.fixtureLedgerBody(next)
		if err != nil {
			t.Fatal("valid changed WAL control unavailable", field)
		}
		f.body, f.document = nextBody, next
		if _, err := f.worldsJournal(); err != nil {
			t.Fatal("fresh changed WAL/journal control did not reach binding", field)
		}
		if _, err := f.decodeWorlds(body); err != ErrFixtures {
			t.Fatal("changed current WAL reused original companion binding", field)
		}
		f.body, f.document = originalBody, originalDocument
	}
	if _, err := f.decodeWorlds(body); err != nil {
		t.Fatal("restored binding refused")
	}
	// Same owned shape, distinct engine/plan registry/catalog: no prior entry
	// may survive rebinding even where the pure shape itself remains valid.
	originalEngine := f.engine
	originalV1, originalV2, originalV3 := fixtureCatalog, fixtureCatalogV2, fixtureCatalogV3
	defer func() {
		f.engine = originalEngine
		fixtureCatalog, fixtureCatalogV2, fixtureCatalogV3 = originalV1, originalV2, originalV3
	}()
	for _, mutate := range []func(){
		func() { f.engine = &Engine{plans: originalEngine.plans, baseline: originalEngine.baseline} },
		func() {
			f.engine = &Engine{plans: make(map[string]*installrender.Plan), baseline: originalEngine.baseline}
			for key, plan := range originalEngine.plans {
				f.engine.plans[key] = plan
			}
			f.engine.plans["extra"] = originalEngine.plans[h.f.actor.request.Snapshot.Document().TargetPackage]
		},
		func() { fixtureCatalog[0].suffix = "foreign" },
		func() { fixtureCatalogV2[0].suffix = "foreign" },
		func() { fixtureCatalogV3[0].suffix = "foreign" },
	} {
		f.engine, fixtureCatalog, fixtureCatalogV2, fixtureCatalogV3 = originalEngine, originalV1, originalV2, originalV3
		if _, err := f.decodeCurrentWorldsShape(body, ns); err != nil {
			t.Fatal("shape prime unavailable")
		}
		oldPin := &f.decodeCache.worldsBody[0]
		mutate()
		if got, err := f.decodeCurrentWorldsShape(body, ns); err != nil || !reflect.DeepEqual(got, want) || &f.decodeCache.worldsBody[0] == oldPin {
			t.Fatal("changed owner/catalog/registry retained a prior shape entry")
		}
	}
	f.engine, fixtureCatalog, fixtureCatalogV2, fixtureCatalogV3 = originalEngine, originalV1, originalV2, originalV3
	// The retention ceiling is NOT a reduced acceptance ceiling. Construct
	// canonical pure shapes of exact sizes; these foreign journal bytes still
	// cannot pass the outer current-journal binding, regardless of cache warmth.
	for _, size := range []int{fixtureWorldsDecodeRetentionBytes - 1, fixtureWorldsDecodeRetentionBytes, fixtureWorldsDecodeRetentionBytes + 1} {
		d := cloneFixtureWorldsDocument(want)
		d.Journal = json.RawMessage(`""`)
		base, err := fixtureWorldsShapeBody(d, ns)
		if err != nil {
			t.Fatal("retention-boundary shape unavailable")
		}
		d.Journal, _ = json.Marshal(strings.Repeat("x", size-len(base)))
		large, err := fixtureWorldsShapeBody(d, ns)
		if err != nil || len(large) != size {
			t.Fatal("exact retention boundary unavailable")
		}
		for repeat := 0; repeat < 2; repeat++ {
			if got, err := f.decodeCurrentWorldsShape(large, ns); err != nil || !reflect.DeepEqual(got, d) || (f.decodeCache.worldsBody != nil) != (size <= fixtureWorldsDecodeRetentionBytes) {
				t.Fatal("retention ceiling changed pure decoding or accumulated entries")
			}
			if _, err := f.decodeWorlds(large); err != ErrFixtures {
				t.Fatal("large shape acquired journal binding")
			}
		}
	}
	oversize := make([]byte, privatefs.MaxEvidenceFileBytes+1)
	if _, err := f.decodeWorlds(oversize); err != ErrFixtures {
		t.Fatal("evidence validity ceiling expanded")
	}
	if _, err := f.decodeWorlds(body); err != nil || !bytes.Equal(f.decodeCache.worldsBody, body) {
		t.Fatal("restored small shape did not replace the one-entry cache")
	}
	f.decodeCache.clearWAL()
	if f.decodeCache.worldsBody != nil || f.decodeCache.worldsNS != "" || !reflect.DeepEqual(f.decodeCache.worlds, fixtureWorldsDocument{}) {
		t.Fatal("WAL invalidation retained companion materialization")
	}
	// Deep clones preserve nil/empty distinctions at all nested slice levels.
	for _, empty := range []bool{false, true} {
		d := fixtureWorldsDocument{Phase: &fixturePhaseBaseline{Accounts: &fixtureAccountBaseline{}}}
		if empty {
			d.Journal, d.Rows = []byte{}, []fixtureWorldRow{}
			d.Phase.Rows, d.Phase.Public, d.Phase.Leaders, d.Phase.Accounts.Rows = []fixtureWorldRow{}, []fixtureWorldRow{}, []fixturePhaseLeader{}, []fixtureWorldRow{}
		}
		if !reflect.DeepEqual(d, cloneFixtureWorldsDocument(d)) {
			t.Fatal("clone changed nil versus empty materialization")
		}
	}
	// Exercise every nested alias even if a real initial inventory is empty.
	d := fixtureWorldsDocument{Journal: json.RawMessage(`{}`), Rows: []fixtureWorldRow{{UID: "original"}}, Phase: &fixturePhaseBaseline{Rows: []fixtureWorldRow{{UID: "original"}}, Public: []fixtureWorldRow{{UID: "original"}}, Leaders: []fixturePhaseLeader{{ManagedTimes: []string{"original"}}}, Accounts: &fixtureAccountBaseline{Rows: []fixtureWorldRow{{UID: "original"}}}}}
	copy := cloneFixtureWorldsDocument(d)
	poison(&copy)
	if d.Journal[0] != '{' || d.Rows[0].UID != "original" || d.Phase.Rows[0].UID != "original" || d.Phase.Public[0].UID != "original" || d.Phase.Leaders[0].ManagedTimes[0] != "original" || d.Phase.Accounts.Rows[0].UID != "original" || d.Phase.Version != "" || d.Phase.Accounts.Version != "" {
		t.Fatal("nested clone retained aliases")
	}
	ack, effect := f.ackSlot, f.effectSlot
	publication, completion, floor := f.worldPublication, f.behaviorCompletion, f.phaseFloor
	for repeat := 0; repeat < 3; repeat++ {
		if _, err := f.decodeWorlds(body); err != nil {
			t.Fatal("pure bound hit unavailable")
		}
	}
	if f.ackSlot != ack || f.effectSlot != effect || f.worldPublication != publication || f.behaviorCompletion != completion || f.phaseFloor != floor || h.f.creates != 0 || h.f.deletes != 0 || h.f.seeds != 0 || f.seedEffect || f.markerEffect {
		t.Fatal("pure materialization gained effect or completion capabilities")
	}
	if f.close() != nil || f.decodeCache.worldsBody != nil || f.decodeCache.worldsNS != "" || !reflect.DeepEqual(f.decodeCache.worlds, fixtureWorldsDocument{}) {
		t.Fatal("close retained companion materialization")
	}
	if _, err := f.decodeWorlds(body); err != ErrFixtures {
		t.Fatal("closed ledger acquired cached evidence")
	}
}
