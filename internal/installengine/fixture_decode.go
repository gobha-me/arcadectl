// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"slices"
	"sync"

	"github.com/gobha-me/arcadectl/internal/installbaseline"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
)

// One WAL and one embedded journal, local to this ledger instance. Only pure
// strict decoding is memoized. Exact bytes, engine identity, the entire sealed
// plan registry and both closed catalogs must still match. This does NOT cache
// protected-file reads/identity/durability, companions, authorization, cluster
// observations, phases or any effect/completion capability.
type fixtureDecodeCache struct {
	mu          sync.Mutex
	engine      *Engine
	plans       map[string]*installrender.Plan
	baseline    *installbaseline.Plan
	v1          [len(fixtureCatalog)]fixtureRecipe
	v2          [len(fixtureCatalogV2)]fixtureRecipe
	v3          [len(fixtureCatalogV3)]fixtureRecipe
	walBody     []byte
	wal         fixtureLedgerDocument
	journalBody []byte
	journal     installstate.Document
}

func (c *fixtureDecodeCache) bind(e *Engine) {
	match := c.engine == e && c.baseline == e.baselinePlan() && len(c.plans) == len(e.plans) && c.v1 == fixtureCatalog && c.v2 == fixtureCatalogV2 && c.v3 == fixtureCatalogV3
	if match {
		for key, plan := range e.plans {
			old, present := c.plans[key]
			if !present || old != plan {
				match = false
				break
			}
		}
	}
	if match {
		return
	}
	c.engine, c.v1, c.v2 = e, fixtureCatalog, fixtureCatalogV2
	c.v3 = fixtureCatalogV3
	c.baseline = e.baselinePlan()
	c.plans = make(map[string]*installrender.Plan, len(e.plans))
	for key, plan := range e.plans {
		c.plans[key] = plan
	}
	c.walBody, c.wal = nil, fixtureLedgerDocument{}
	c.journalBody, c.journal = nil, installstate.Document{}
}

func cloneFixtureLedgerDocument(d fixtureLedgerDocument) fixtureLedgerDocument {
	d.Journal = bytes.Clone(d.Journal)
	d.Entries = slices.Clone(d.Entries)
	if d.DestroySeed != nil {
		copy := *d.DestroySeed
		d.DestroySeed = &copy
	}
	if d.RetainedMarker != nil {
		copy := *d.RetainedMarker
		d.RetainedMarker = &copy
	}
	if d.Behavior != nil {
		copy := *d.Behavior
		d.Behavior = &copy
	}
	return d
}

func cloneFixtureJournalDocument(d installstate.Document) installstate.Document {
	d.Resources = slices.Clone(d.Resources)
	if d.Pending != nil {
		copy := *d.Pending
		d.Pending = &copy
	}
	if d.SecurityBaseline != nil {
		copy := *d.SecurityBaseline
		copy.Resources = slices.Clone(copy.Resources)
		if copy.Pending != nil {
			pending := *copy.Pending
			copy.Pending = &pending
		}
		d.SecurityBaseline = &copy
	}
	return d
}

func (f *fixtureLedger) decodeCurrentWAL(body []byte) (fixtureLedgerDocument, error) {
	if f == nil || f.engine == nil || f.lock == nil || len(body) == 0 || len(body) > fixtureLedgerMaxBytes {
		return fixtureLedgerDocument{}, ErrFixtures
	}
	c := &f.decodeCache
	c.mu.Lock()
	defer c.mu.Unlock()
	c.bind(f.engine)
	if bytes.Equal(body, c.walBody) {
		return cloneFixtureLedgerDocument(c.wal), nil
	}
	d, err := f.engine.decodeFixtureLedger(body) // unchanged strict decoder on EVERY miss
	if err != nil {
		return fixtureLedgerDocument{}, ErrFixtures // never remember a refused decode
	}
	c.walBody, c.wal = bytes.Clone(body), cloneFixtureLedgerDocument(d)
	return d, nil // the retained copy cannot be changed through this result
}

func (f *fixtureLedger) decodeCurrentJournal(body []byte) (installstate.Document, error) {
	if f == nil || f.engine == nil || f.lock == nil || len(body) == 0 || len(body) > installstate.MaxBytes {
		return installstate.Document{}, ErrFixtures
	}
	c := &f.decodeCache
	c.mu.Lock()
	defer c.mu.Unlock()
	c.bind(f.engine)
	if bytes.Equal(body, c.journalBody) {
		return cloneFixtureJournalDocument(c.journal), nil
	}
	plans := make([]*installrender.Plan, 0, len(f.engine.plans))
	for _, plan := range f.engine.plans {
		plans = append(plans, plan)
	}
	d, err := installstate.DecodeWithBaseline(body, f.engine.baselinePlan(), plans...)
	if err != nil {
		return installstate.Document{}, ErrFixtures
	}
	c.journalBody, c.journal = bytes.Clone(body), cloneFixtureJournalDocument(d)
	return d, nil
}

func (c *fixtureDecodeCache) clearWAL() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.walBody, c.wal = nil, fixtureLedgerDocument{}
}

func (c *fixtureDecodeCache) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.engine, c.plans = nil, nil
	c.baseline = nil
	c.v1, c.v2 = [len(fixtureCatalog)]fixtureRecipe{}, [len(fixtureCatalogV2)]fixtureRecipe{}
	c.v3 = [len(fixtureCatalogV3)]fixtureRecipe{}
	c.walBody, c.wal = nil, fixtureLedgerDocument{}
	c.journalBody, c.journal = nil, installstate.Document{}
}
