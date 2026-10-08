// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
)

func TestFixtureDecodeCacheExactBytesCopiesAndBoundedLifetime(t *testing.T) {
	h := newFixture(t, false)
	f, err := h.engine.prepareFixtureLedger(t.Context(), h.snapshot)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if f.lock != nil {
			_ = f.close()
		}
	}()
	if f.sealOriginalWorlds([]fixtureWorldRow{}) != nil {
		t.Fatal("world seal unavailable")
	}
	fixtureBehaviorPrerequisites(t, f, fixtureDestroySeedWarmCancelled)
	f.behaviorCompletion = instrumentFixtureBehaviorCompletion(f) // test-only, not a native proof
	if f.advance(fixtureBehaviorIntent(t, f)) != nil {
		t.Fatal("receipt instrumentation unavailable")
	}
	body := bytes.Clone(f.body)
	d, err := f.decodeCurrentWAL(body)
	if err != nil || !reflect.DeepEqual(d, f.document) {
		t.Fatal("strict original decode unavailable")
	}
	pinned := &f.decodeCache.walBody[0]
	d.Journal[0] = '!'
	d.Entries[0].Key.Name = "foreign"
	d.DestroySeed.State = fixtureDestroySeedAttempted
	d.RetainedMarker.State = fixtureRetainedMarkerAttempted
	d.Behavior.Version = "foreign"
	again, err := f.decodeCurrentWAL(body)
	if err != nil || !reflect.DeepEqual(again, f.document) || &f.decodeCache.walBody[0] != pinned {
		t.Fatal("returned mutable WAL poisoned cached value or exact hit was not reused")
	}
	// A hit returns independent slices AND every optional receipt pointer.
	again.Journal[0] = '!'
	again.Entries[0].State = fixturePlanned
	again.DestroySeed.BeforeResourceVersion = "foreign"
	again.RetainedMarker.BeforeResourceVersion = "foreign"
	again.Behavior.Revision = 0
	if third, err := f.decodeCurrentWAL(body); err != nil || !reflect.DeepEqual(third, f.document) {
		t.Fatal("hit result aliased cached WAL")
	}
	j, err := f.decodeCurrentJournal(f.document.Journal)
	if err != nil || len(j.Resources) == 0 {
		t.Fatal("strict journal decode unavailable")
	}
	journalPin := &f.decodeCache.journalBody[0]
	j.Resources[0].Key.Name = "foreign"
	j.Revision++
	j2, err := f.decodeCurrentJournal(f.document.Journal)
	if err != nil || !reflect.DeepEqual(j2, h.snapshot.Document()) || &f.decodeCache.journalBody[0] != journalPin {
		t.Fatal("journal result poisoned cache or exact hit was not reused")
	}
	j2.Resources[0].UID = "foreign"
	if j3, err := f.decodeCurrentJournal(f.document.Journal); err != nil || !reflect.DeepEqual(j3, h.snapshot.Document()) {
		t.Fatal("journal hit result aliased retained resources")
	}
	for _, malformed := range [][]byte{nil, []byte("null"), append(bytes.Clone(body), ' '), append([]byte(" "), body...)} {
		for repeat := 0; repeat < 2; repeat++ {
			if _, err := f.decodeCurrentWAL(malformed); err != ErrFixtures {
				t.Fatal("nonidentical invalid WAL reused cache")
			}
		}
	}
	if _, err := f.decodeCurrentJournal(append(bytes.Clone(f.document.Journal), ' ')); err != ErrFixtures {
		t.Fatal("nonidentical invalid journal reused cache")
	}
	// A new valid body replaces rather than accumulates cache entries.
	next := cloneFixtureLedgerDocument(f.document)
	next.Revision++
	next.Entries[len(next.Entries)-1].State = fixtureDeleteAttempted
	next.Entries[len(next.Entries)-1].DeleteResourceVersion = "200"
	newBody, err := f.engine.fixtureLedgerBody(next)
	if err != nil {
		t.Fatal("next strict schema unavailable")
	}
	if got, err := f.decodeCurrentWAL(newBody); err != nil || !reflect.DeepEqual(got, next) || !bytes.Equal(f.decodeCache.walBody, newBody) {
		t.Fatal("different valid bytes failed to replace cache")
	}
	newBody[0] = '!'
	if bytes.Equal(f.decodeCache.walBody, newBody) {
		t.Fatal("input aliases retained bytes")
	}
	journalBody := bytes.Clone(f.document.Journal)
	if f.close() != nil || f.decodeCache.engine != nil || f.decodeCache.plans != nil || f.decodeCache.walBody != nil || f.decodeCache.journalBody != nil || !reflect.DeepEqual(f.decodeCache.wal, fixtureLedgerDocument{}) || !reflect.DeepEqual(f.decodeCache.journal, installstate.Document{}) {
		t.Fatal("closed ledger retained decoded evidence")
	}
	if _, err := f.decodeCurrentWAL(body); err != ErrFixtures {
		t.Fatal("closed ledger acquired cache")
	}
	if _, err := f.decodeCurrentJournal(journalBody); err != ErrFixtures {
		t.Fatal("closed journal acquired cache")
	}
}

func TestFixtureDecodeCachePinsEntireRegistryAndCatalogs(t *testing.T) {
	h := newFixture(t, false)
	f, err := h.engine.prepareFixtureLedger(t.Context(), h.snapshot)
	if err != nil {
		t.Fatal(err)
	}
	defer f.close()
	target := h.snapshot.Document().TargetPackage
	original := h.engine.plans[target]
	foreign := fixturePlanProfile(t, "foreign", installrender.Profile135)
	for _, mutate := range []func(){
		func() { h.engine.plans[target] = foreign },
		func() { h.engine.plans[target] = nil },
		func() { delete(h.engine.plans, target) },
		func() { delete(h.engine.plans, target); h.engine.plans["foreign-key"] = original },
	} {
		h.engine.plans[target] = original
		delete(h.engine.plans, "foreign-key")
		if _, err := f.decodeCurrentWAL(f.body); err != nil {
			t.Fatal("cache prime failed")
		}
		if _, err := f.decodeCurrentJournal(f.document.Journal); err != nil {
			t.Fatal("journal cache prime failed")
		}
		walPin := &f.decodeCache.walBody[0]
		mutate()
		strict, strictErr := h.engine.decodeFixtureLedger(f.body)
		cached, cachedErr := f.decodeCurrentWAL(f.body)
		if strictErr != cachedErr || !reflect.DeepEqual(strict, cached) || f.decodeCache.journalBody != nil || strictErr != nil && f.decodeCache.walBody != nil || strictErr == nil && &f.decodeCache.walBody[0] == walPin {
			t.Fatal("changed registry reused prior strict result")
		}
		plans := make([]*installrender.Plan, 0, len(h.engine.plans))
		for _, plan := range h.engine.plans {
			plans = append(plans, plan)
		}
		strictJournal, journalErr := installstate.Decode(f.document.Journal, plans...)
		cachedJournal, cachedJournalErr := f.decodeCurrentJournal(f.document.Journal)
		if (journalErr == nil) != (cachedJournalErr == nil) || !reflect.DeepEqual(strictJournal, cachedJournal) {
			t.Fatal("changed registry journal differs from fresh strict decode")
		}
		if _, err := f.object(0); err != ErrFixtures {
			t.Fatal("foreign or missing registered target became object authority")
		}
	}
	h.engine.plans[target] = original
	delete(h.engine.plans, "foreign-key")
	if _, err := f.decodeCurrentWAL(f.body); err != nil {
		t.Fatal("restore registry failed")
	}
	if _, err := f.decodeCurrentJournal(f.document.Journal); err != nil {
		t.Fatal("restore journal failed")
	}
	oldPin := &f.decodeCache.walBody[0]
	h.engine.plans["extra-key"] = original
	strict, strictErr := h.engine.decodeFixtureLedger(f.body)
	got, cachedErr := f.decodeCurrentWAL(f.body)
	if strictErr != cachedErr || !reflect.DeepEqual(strict, got) || strictErr != nil && f.decodeCache.walBody != nil || strictErr == nil && &f.decodeCache.walBody[0] == oldPin {
		t.Fatal("added registry key did not force fresh strict decode")
	}
	delete(h.engine.plans, "extra-key")
	if _, err := f.decodeCurrentWAL(f.body); err != nil {
		t.Fatal("restored registry refused")
	}
	// Engine replacement is a separate miss even with identical plan pointers.
	oldPin = &f.decodeCache.walBody[0]
	replacement := &Engine{plans: h.engine.plans}
	f.engine = replacement
	if got, err := f.decodeCurrentWAL(f.body); err != nil || !reflect.DeepEqual(got, f.document) || &f.decodeCache.walBody[0] == oldPin || f.decodeCache.engine != replacement {
		t.Fatal("equivalent distinct engine reused prior owner decode")
	}
	f.engine = h.engine
	if _, err := f.decodeCurrentWAL(f.body); err != nil {
		t.Fatal("restored original engine refused")
	}
	oldV1, oldV2 := fixtureCatalog, fixtureCatalogV2
	defer func() { fixtureCatalog, fixtureCatalogV2 = oldV1, oldV2 }()
	fixtureCatalog[0].suffix = "foreign"
	if _, err := f.decodeCurrentWAL(f.body); err != ErrFixtures {
		t.Fatal("changed recipe reused decode")
	}
	fixtureCatalog = oldV1
	if _, err := f.decodeCurrentWAL(f.body); err != nil {
		t.Fatal("restored recipe refused")
	}
	oldPin = &f.decodeCache.walBody[0]
	fixtureCatalogV2[10].suffix = "foreign"
	if _, err := f.decodeCurrentWAL(f.body); err != nil || &f.decodeCache.walBody[0] == oldPin {
		t.Fatal("other catalog change was hidden by cache")
	}
}

func TestFixtureDecodeCacheCannotSubstituteInMemoryWALOrGrantCapabilities(t *testing.T) {
	h := newFixture(t, false)
	f, err := h.engine.prepareFixtureLedger(t.Context(), h.snapshot)
	if err != nil {
		t.Fatal(err)
	}
	defer f.close()
	if _, err := f.object(0); err != nil {
		t.Fatal("strict object prime unavailable")
	}
	name := f.document.Entries[0].Key.Name
	f.document.Entries[0].Key.Name = "foreign"
	if _, err := f.object(0); err != ErrFixtures {
		t.Fatal("cached decode trusted substituted in-memory recipe")
	}
	if _, err := f.worldsJournal(); err != ErrFixtures {
		t.Fatal("cached journal trusted substituted in-memory WAL")
	}
	f.document.Entries[0].Key.Name = name
	next, err := f.nextDocument()
	if err != nil {
		t.Fatal("next strict document unavailable")
	}
	next.Entries[0].State = fixtureCreateAttempted
	if f.advance(next) != nil || f.decodeCache.walBody != nil {
		t.Fatal("advance did not discard WAL cache")
	}
	if _, err := f.decodeCurrentWAL(f.body); err != nil {
		t.Fatal("advanced strict cache prime failed")
	}
	ack, effect := f.ackSlot, f.effectSlot
	for i := 0; i < 3; i++ {
		if _, err := f.decodeCurrentWAL(f.body); err != nil {
			t.Fatal("strict hit refused")
		}
	}
	if f.ackSlot != ack || f.effectSlot != effect || f.behaviorCompletion != nil || f.seedAck || f.seedEffect || f.markerAck || f.markerEffect || f.worldPublication {
		t.Fatal("pure decode changed effect/completion capabilities")
	}
}

func TestFixtureJournalCloneDoesNotAliasPending(t *testing.T) {
	d := installstate.Document{Resources: []installstate.Resource{{UID: "original"}}, Pending: &installstate.Pending{BeforeUID: "original"}}
	copy := cloneFixtureJournalDocument(d)
	copy.Resources[0].UID = "foreign"
	copy.Pending.BeforeUID = "foreign"
	if d.Resources[0].UID != "original" || d.Pending.BeforeUID != "original" {
		t.Fatal("journal clone retained aliases")
	}
}
