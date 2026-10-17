// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/privatefs"
)

func testFixtureWorldsStreamPaths(t *testing.T) {
	for _, f := range []*fixtureLedger{nil, {}, {engine: &Engine{}}} {
		if handled, err := f.matchCurrentWorlds("record"); !handled || err != ErrFixtures {
			t.Fatal("invalid comparison prerequisites did not explicitly refuse")
		}
	}
	newPhase := fixtureV3PhaseFactory(t)
	for _, fault := range []string{"cold", "stale", "large-cache", "namespace", "registry", "missing", "replacement", "changed", "truncated", "run-binding", "rv-binding", "accounts-binding", "wal-binding", "closed-store"} {
		t.Run(fault, func(t *testing.T) {
			h := newPhase(t)
			f := h.f.wire.ledger
			name, err := f.originalWorldsName()
			if err != nil || f.originalWorldsCurrent() != nil {
				t.Fatal("original warm companion unavailable")
			}
			body, identity, err := f.engine.files.ReadEvidence(name, privatefs.MaxEvidenceFileBytes)
			if err != nil {
				t.Fatal("protected reader oracle unavailable")
			}
			if handled, err := f.matchCurrentWorlds(name); !handled || err != nil {
				t.Fatal("warm pure shape did not select complete streaming comparison")
			}
			expectMiss := false
			switch fault {
			case "cold":
				f.decodeCache.clearWAL()
				expectMiss = true
			case "stale":
				f.decodeCache.worldsBody = []byte("stale shape")
				expectMiss = true
			case "large-cache":
				f.decodeCache.worldsBody = make([]byte, fixtureWorldsDecodeRetentionBytes+1)
				expectMiss = true
			case "namespace":
				// A namespace miss must strictly re-decode, not accept an old graph.
				f.decodeCache.worldsNS = "foreign"
				f.decodeCache.worlds.RunID = "foreign"
			case "registry":
				f.decodeCache.plans = nil
				expectMiss = true
			case "missing":
				if f.engine.files.RemoveEvidence(name, identity) != nil {
					t.Fatal("companion removal injection failed")
				}
			case "replacement":
				if _, err := f.engine.files.AtomicWrite(name, body, &identity); err != nil {
					t.Fatal("same-byte replacement injection failed")
				}
			case "changed", "truncated":
				altered := bytes.Clone(body)
				if fault == "changed" {
					altered[0] = '!'
				} else {
					altered = altered[:len(altered)-1]
				}
				// The active store still checks its anchored directory descriptor.
				if os.WriteFile(filepath.Join(h.f.actor.v.f.privateDir, name), altered, 0600) != nil {
					t.Fatal("same-inode change injection failed")
				}
			case "run-binding":
				f.decodeCache.worlds.RunID = "foreign"
			case "rv-binding":
				f.decodeCache.worlds.JournalResourceVersion = "999"
			case "accounts-binding":
				f.decodeCache.worlds.Phase.Accounts = nil
			case "wal-binding":
				f.document.Revision++
			case "closed-store":
				if f.engine.files.Close() != nil {
					t.Fatal("store close injection failed")
				}
			}
			handled, err := f.matchCurrentWorlds(name)
			if expectMiss {
				if handled || err != nil || f.originalWorldsCurrent() != nil {
					t.Fatal("ineligible pure shape did not use unchanged protected reader")
				}
			} else if fault == "namespace" {
				if !handled || err != nil || f.originalWorldsCurrent() != nil {
					t.Fatal("current namespace did not reestablish strict shape")
				}
			} else if !handled || err != ErrFixtures || f.originalWorldsCurrent() != ErrFixtures {
				t.Fatal("eligible failure fell back or accepted original-world evidence")
			}
			if *f.worldIdentity != identity || h.f.creates != 0 || h.f.deletes != 0 || h.f.seeds != 0 || h.f.previews != 0 {
				t.Fatal("comparison adopted identity or granted effects")
			}
		})
	}
}

// Compare the complete document-returning read with the check-only guard.
// Both must retain the same protected-file witnesses; neither may contact the
// cluster or grant effects. Allocation reduction is not native latency proof.
func testFixtureWorldsGuardCopyOracle(t *testing.T) {
	for _, recipe := range []string{"v1", "v2", "v3"} {
		t.Run(recipe, func(t *testing.T) {
			factory := fixturePhaseFactory
			if recipe == "v2" {
				factory = unmarkedRecoveryPhaseFactory
			} else if recipe == "v3" {
				factory = fixtureV3PhaseFactory
			}
			h := factory(t)(t)
			f := h.f.wire.ledger
			body, identity := bytes.Clone(f.body), f.identity
			worldIdentity := *f.worldIdentity
			effect, ack, behavior := f.effectSlot, f.ackSlot, f.behaviorCompletion
			lists, gets, publicGets := h.lists, h.gets, h.publicGets
			writes, namespaceWrites := h.f.actor.v.f.access.writes, h.f.actor.v.f.nsUpdates
			materialize := func() {
				if _, err := f.readOriginalWorlds(false); err != nil {
					t.Fatal("document-returning guard oracle refused")
				}
			}
			check := func() {
				if f.originalWorldsCurrent() != nil {
					t.Fatal("check-only guard differs from document oracle")
				}
			}
			name, err := f.originalWorldsName()
			if err != nil {
				t.Fatal("original companion address unavailable")
			}
			f.decodeCache.clearWAL()
			if handled, err := f.matchCurrentWorlds(name); handled || err != nil {
				t.Fatal("cold shape did not select owned-reader fallback")
			}
			check()
			if handled, err := f.matchCurrentWorlds(name); !handled || err != nil {
				t.Fatal("warm shape did not select fresh streaming match")
			}
			fresh, _, err := f.engine.files.ReadEvidence(name, privatefs.MaxEvidenceFileBytes)
			if err != nil {
				t.Fatal("fresh companion unavailable")
			}
			want, err := decodeFixtureWorldsShape(fresh, h.f.actor.request.Snapshot.Anchor().Namespace)
			got, readErr := f.readOriginalWorlds(false)
			if err != nil || readErr != nil || !reflect.DeepEqual(got, want) {
				t.Fatal("warm streaming operand changed independently strict owned document")
			}
			materialize()
			check()
			oldAllocations := testing.AllocsPerRun(10, materialize)
			newAllocations := testing.AllocsPerRun(10, check)
			t.Logf("protected-world guard allocations: document=%.0f check-only=%.0f", oldAllocations, newAllocations)
			if newAllocations >= oldAllocations {
				t.Error("check-only guard still allocates discarded document copies")
			}
			if !bytes.Equal(body, f.body) || identity != f.identity || worldIdentity != *f.worldIdentity || effect != f.effectSlot || ack != f.ackSlot || behavior != f.behaviorCompletion {
				t.Fatal("read-only guard changed protected identity or effect capabilities")
			}
			if lists != h.lists || gets != h.gets || publicGets != h.publicGets || writes != h.f.actor.v.f.access.writes || namespaceWrites != h.f.actor.v.f.nsUpdates {
				t.Fatal("pure guard introduced remote requests or mutations")
			}
		})
	}
}

func testFixtureWorldsGuardFences(t *testing.T) {
	newPhase := fixtureV3PhaseFactory(t)
	for _, fault := range []string{"wal-document", "wal-body", "journal", "recipe", "wal-replacement", "companion-replacement", "companion-missing", "unpublished", "unpinned", "closed", "concurrent"} {
		t.Run(fault, func(t *testing.T) {
			h := newPhase(t)
			f := h.f.wire.ledger
			if f.originalWorldsCurrent() != nil {
				t.Fatal("warm original guard unavailable")
			}
			switch fault {
			case "wal-document":
				f.document.Revision++
			case "wal-body":
				f.body = append([]byte("!"), f.body[1:]...)
			case "journal":
				f.document.Journal = []byte(`{"foreign":true}`)
			case "recipe":
				f.document.Recipe = fixtureRecipeV2
			case "wal-replacement":
				if _, err := f.engine.files.AtomicWrite(f.name, f.body, &f.identity); err != nil {
					t.Fatal("same-byte WAL replacement injection failed")
				}
			case "companion-replacement", "companion-missing":
				name, err := f.originalWorldsName()
				if err != nil {
					t.Fatal("companion address unavailable")
				}
				body, id, err := f.engine.files.ReadEvidence(name, privatefs.MaxEvidenceFileBytes)
				if err != nil {
					t.Fatal("companion injection source unavailable")
				}
				if fault == "companion-missing" {
					err = f.engine.files.RemoveEvidence(name, id)
				} else {
					_, err = f.engine.files.AtomicWrite(name, body, &id)
				}
				if err != nil {
					t.Fatal("companion fault injection failed")
				}
			case "unpublished":
				f.worldPublication = true
			case "unpinned":
				f.worldIdentity = nil
			case "closed":
				if f.close() != nil {
					t.Fatal("close injection failed")
				}
			case "concurrent":
				var workers sync.WaitGroup
				errors := make(chan error, 8)
				workers.Go(func() {
					for range 16 {
						f.decodeCache.clearWAL()
						f.decodeCache.clear()
					}
				})
				for range 8 {
					workers.Go(func() {
						for range 4 {
							d, err := f.readOriginalWorlds(false)
							if err != nil {
								errors <- err
								return
							}
							// The check-only reader must not expose or retain aliases
							// through concurrently returned defensive documents.
							d.Journal[0] = '!'
							d.Phase.Accounts.Version = "foreign"
							if err := f.originalWorldsCurrent(); err != nil {
								errors <- err
								return
							}
						}
					})
				}
				workers.Wait()
				close(errors)
				for range errors {
					t.Fatal("concurrent owned shape was changed through a borrowed alias")
				}
				return
			}
			_, documentErr := f.readOriginalWorlds(false)
			if documentErr != ErrFixtures || f.originalWorldsCurrent() != documentErr {
				t.Fatal("warm check-only guard differs from protected document oracle")
			}
		})
	}
}

// A bounded whole-phase measurement, not a native timing gate. The fixture's
// explicit100/200 SDK settings are distinct from the production shared200/20.
// The same subtest can run against an immutable-source Go overlay for comparison.
func testFixtureWorldsGuardPhaseCost(t *testing.T) {
	h := fixtureV3PhaseFactory(t)(t)
	f := h.f.wire.ledger
	if _, err := h.f.wire.observePhase(t.Context()); err != nil {
		t.Fatal("complete V3 phase warm-up unavailable")
	}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	start := time.Now()
	var expected [3]int
	for iteration := range 3 {
		counts := [3]int{h.lists, h.gets, h.publicGets}
		if result, err := h.f.wire.observePhase(t.Context()); result == nil || err != nil {
			t.Fatal("complete unchanged V3 phase refused")
		}
		delta := [3]int{h.lists - counts[0], h.gets - counts[1], h.publicGets - counts[2]}
		if iteration == 0 {
			expected = delta
		}
		if delta != expected || delta[1] != 2*len(f.document.Entries) {
			t.Fatal("complete phase lost collections or named reads")
		}
	}
	elapsed := time.Since(start)
	runtime.ReadMemStats(&after)
	if h.f.creates != 0 || h.f.deletes != 0 || h.f.seeds != 0 || h.f.previews != 0 || f.behaviorCompletion != nil {
		t.Fatal("read-only phase gained effect capability")
	}
	t.Logf("three complete V3 phases: wall=%s allocations=%d bytes=%d per-phase lists=%d named=%d public=%d; fixture explicit100/200, not native shared100/20", elapsed, after.Mallocs-before.Mallocs, after.TotalAlloc-before.TotalAlloc, expected[0], expected[1], expected[2])
}
