// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"fmt"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/privatefs"
	"golang.org/x/sys/unix"
)

// The two source builds run this same method/corpus. The variant is only an
// output label: it cannot select a transport, guard, syscall or authority path.
func TestFixtureLocalHashScreen(t *testing.T) {
	if os.Getenv("ARCADECTL_FS_HASH_SCREEN") != "1" {
		t.Skip("private filesystem hash screen is opt-in")
	}
	variant := os.Getenv("ARCADECTL_FS_HASH_SCREEN_VARIANT")
	if variant != "base" && variant != "candidate" {
		t.Fatal("fixed source label unavailable")
	}
	factory := phaseBarrierFactory(t, fixtureRecipeV3)
	for _, mode := range []string{"retained", "fallback"} {
		t.Run(mode, func(t *testing.T) {
			h := factory(t)
			w, f := h.f.wire, h.f.wire.ledger
			f.wireMu.Lock()
			defer f.wireMu.Unlock()
			body, identity, worldID := bytes.Clone(f.body), f.identity, *f.worldIdentity
			name, err := f.originalWorldsName()
			if err != nil || w.localCurrent() != nil {
				t.Fatal("real local guard fixture unavailable")
			}
			world, observedID, err := f.engine.files.ReadEvidence(name, privatefs.MaxEvidenceFileBytes)
			if err != nil || observedID != worldID {
				t.Fatal("original companion unavailable")
			}
			if mode == "fallback" {
				localHashClearWorlds(f)
			}
			handled, err := f.matchCurrentWorlds(name)
			if err != nil || handled != (mode == "retained") {
				t.Fatal("fixture did not select its declared memo mode")
			}
			counts := func() [5]int {
				return [5]int{h.lists, h.gets, h.publicGets, h.f.actor.v.f.access.writes, h.f.actor.v.f.nsUpdates}
			}
			beforeCounts := counts()
			var wall, user, system int64
			var allocated, mallocs uint64
			for range 256 {
				// Only the pure worlds memo is reset, never WAL/journal state.
				// All reset/statistics work is outside the localCurrent wall span.
				if mode == "fallback" {
					localHashClearWorlds(f)
				}
				var memoryBefore, memoryAfter runtime.MemStats
				var cpuBefore, cpuAfter unix.Rusage
				runtime.ReadMemStats(&memoryBefore)
				if unix.Getrusage(unix.RUSAGE_SELF, &cpuBefore) != nil {
					t.Fatal("process CPU observation unavailable")
				}
				started := time.Now()
				guardErr := w.localCurrent()
				wall += time.Since(started).Nanoseconds()
				if unix.Getrusage(unix.RUSAGE_SELF, &cpuAfter) != nil {
					t.Fatal("process CPU observation unavailable")
				}
				runtime.ReadMemStats(&memoryAfter)
				if guardErr != nil {
					t.Fatal("complete local guard refused")
				}
				userDelta := localHashCPU(cpuAfter.Utime) - localHashCPU(cpuBefore.Utime)
				systemDelta := localHashCPU(cpuAfter.Stime) - localHashCPU(cpuBefore.Stime)
				if userDelta < 0 || systemDelta < 0 || memoryAfter.TotalAlloc < memoryBefore.TotalAlloc || memoryAfter.Mallocs < memoryBefore.Mallocs {
					t.Fatal("process counters regressed")
				}
				user += userDelta
				system += systemDelta
				allocated += memoryAfter.TotalAlloc - memoryBefore.TotalAlloc
				mallocs += memoryAfter.Mallocs - memoryBefore.Mallocs
			}
			// Calls are synchronous and joined. Neither measurements nor memo
			// state can stand in for the original post-run custody assertions.
			phaseBarrierUnchanged(t, h, body, identity)
			if counts() != beforeCounts || f.worldIdentity == nil || *f.worldIdentity != worldID {
				t.Fatal("local guard introduced HTTP or changed custody")
			}
			fresh, freshID, err := f.engine.files.Read(f.name, fixtureLedgerMaxBytes)
			if err != nil || freshID != identity || !bytes.Equal(fresh, body) || f.engine.files.ConfirmDurable(f.name, freshID) != nil {
				t.Fatal("original WAL custody changed")
			}
			freshWorld, freshWorldID, err := f.engine.files.ReadEvidence(name, privatefs.MaxEvidenceFileBytes)
			if err != nil || freshWorldID != worldID || !bytes.Equal(freshWorld, world) || f.engine.files.ConfirmEvidenceDurable(name, freshWorldID) != nil {
				t.Fatal("original companion custody changed")
			}
			// CPU and allocation counters are process-wide observations, not
			// exclusive method CPU or native lifecycle performance evidence.
			fmt.Printf("FS_HASH_SCREEN variant=%s mode=%s iterations=256 wall-ns=%d user-cpu-ns=%d system-cpu-ns=%d alloc-bytes=%d mallocs=%d wal-bytes=%d companion-bytes=%d custody=true no-http=true no-effects=true\n", variant, mode, wall, user, system, allocated, mallocs, len(body), len(world))
		})
	}
}

func localHashClearWorlds(f *fixtureLedger) {
	c := &f.decodeCache
	c.mu.Lock()
	c.worldsBody, c.worldsNS, c.worlds = nil, "", fixtureWorldsDocument{}
	c.mu.Unlock()
}

func localHashCPU(value unix.Timeval) int64 {
	return int64(value.Sec)*int64(time.Second) + int64(value.Usec)*int64(time.Microsecond)
}
