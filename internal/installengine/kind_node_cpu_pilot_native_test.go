//go:build kindinstall

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installpackage"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
)

type kindCPUPilotArchive struct {
	name          string
	body          []byte
	identity      privatefs.FileIdentity
	worldName     string
	worldSHA      string
	worldIdentity privatefs.FileIdentity
}

func verifyKindCPUPilotHistory(engine *Engine, history []kindCPUPilotArchive) error {
	for _, previous := range history {
		body, identity, err := engine.files.Read(previous.name, fixtureLedgerMaxBytes)
		if err != nil || identity != previous.identity || !bytes.Equal(body, previous.body) || engine.files.ConfirmDurable(previous.name, identity) != nil {
			return ErrFixtures
		}
		world, worldID, err := engine.files.ReadEvidence(previous.worldName, privatefs.MaxEvidenceFileBytes)
		if err != nil || worldID != previous.worldIdentity || fixtureWorldDigest(world) != previous.worldSHA || engine.files.ConfirmEvidenceDurable(previous.worldName, worldID) != nil {
			return ErrFixtures
		}
	}
	return nil
}

// Disposable CI screen only. The normal native selectors do not include this
// root. No subtest filter can select a partial bracket: all four run directly.
func TestKindAdmissionV3OwnedNodeCPUPilot(t *testing.T) {
	if os.Getenv("ARCADECTL_KIND_CPU_PILOT") == "" {
		t.Skip("owned-node CPU pilot is opt-in")
	}
	if !kindNodeCPUPilotOptIn(os.Getenv("ARCADECTL_KIND_CPU_PILOT"), os.Getenv("CI"), os.Getenv("GITHUB_ACTIONS")) {
		t.Fatal("owned-node CPU pilot requires explicit disposable CI selection")
	}
	source := os.Getenv("ARCADECTL_CPU_PILOT_SOURCE")
	if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(source) {
		t.Fatal("exact pilot source pin unavailable")
	}
	ctx, config, images, _, node := targetKindFixtureImagesWithOwnedNode(t, targetKind137, true, true, false, false, false)
	plan := fixturePlanImages(t, "isolated-install", installrender.Profile137, installpackage.Images{Controller: images.Controller, API: images.API})
	access, engine, store, original, _ := targetKindInstallation(t, ctx, config, plan, true)
	security := installKindFixtureBaseline(t, ctx, access, plan.Namespace(), installrender.Profile137)
	prerequisites, err := NewClusterPrerequisites(engine, access)
	if err != nil {
		t.Fatal("pilot original prerequisites unavailable")
	}
	controllers, err := NewClusterControllers(prerequisites)
	ready := LifecycleCheck{Checkpoint: ControllersAvailable, Snapshot: original, Mode: installstate.Install, Target: plan, Options: LifecycleOptions{Now: time.Now().UTC()}}
	if err != nil || wait.PollUntilContextTimeout(ctx, time.Second, 3*time.Minute, true, func(ctx context.Context) (bool, error) { return controllers.Verify(ctx, ready) == nil, nil }) != nil {
		t.Fatal("pilot original warm controllers did not converge")
	}
	apiSHA := strings.Split(images.API, "@sha256:")
	controllerSHA := strings.Split(images.Controller, "@sha256:")
	if len(apiSHA) != 2 || len(controllerSHA) != 2 || !fixtureWorldsDigest.MatchString(apiSHA[1]) || !fixtureWorldsDigest.MatchString(controllerSHA[1]) {
		t.Fatal("pilot immutable image pins unavailable")
	}
	t.Logf("CPU pilot pins source=%s node=%s registry=%s api-sha256=%s controller-sha256=%s", source, targetKind137, targetKindRegistry, apiSHA[1], controllerSHA[1])
	anchor := original.Anchor()
	seenRuns := map[string]bool{}
	seenUIDs := map[types.UID]bool{}
	var history []kindCPUPilotArchive
	elapsed, err := runKindNodeCPUBracket(ctx, func(index, cpus int) (time.Duration, error) {
		if node.setPilotCPUs(ctx, cpus) != nil {
			return 0, ErrFixtures
		}
		started := time.Now()
		// Genuine Namespace reload is INSIDE each identical timing span. A new
		// observation cannot adopt a different original journal or Namespace.
		fresh, err := store.Load(ctx, anchor)
		if err != nil || fresh.Anchor() != anchor || !fresh.SameJournalBytes(original) || fresh.ResourceVersion() != original.ResourceVersion() {
			return 0, ErrFixtures
		}
		request := LifecycleCheck{Checkpoint: AdmissionEffective, Snapshot: fresh, Mode: installstate.Install, Target: plan, Options: LifecycleOptions{Now: time.Now().UTC()}}
		admission, err := NewClusterAdmission(engine, access)
		if err != nil {
			return 0, ErrFixtures
		}
		trace := &admissionTrace{}
		traced := context.WithValue(ctx, admissionTraceKey{}, trace)
		driver := newKindV3AdmissionDriver(t, traced, admission, request)
		if driver.complete(traced) != nil {
			t.Logf("CPU pilot sample=%d cpus=%d refused: %s", index, cpus, kindAdmissionMatrixFailureSummary(trace))
			return 0, ErrFixtures
		}
		if driver.failed || driver.next != fixtureAdmissionCaseCount || driver.completed != fixtureAdmissionAllCases || driver.wire.ledger.lock != nil {
			return 0, ErrFixtures
		}
		retirement, err := engine.readFixtureRetirement(anchor)
		if err != nil || retirement.record.State != fixtureRetired || retirement.record.RunID != driver.wire.ledger.document.RunID || seenRuns[retirement.record.RunID] {
			return 0, ErrFixtures
		}
		archive, err := engine.decodeFixtureLedger(retirement.archive)
		if err != nil || archive.Recipe != fixtureRecipeV3 || !validFixtureBehaviorDocument(archive) || archive.Behavior == nil || archive.Behavior.Version != fixtureBehaviorRecipeVersion(archive) || archive.DestroySeed == nil || archive.DestroySeed.State != fixtureDestroySeedAcknowledged || archive.RetainedMarker == nil || archive.RetainedMarker.State != fixtureRetainedMarkerAcknowledged {
			return 0, ErrFixtures
		}
		for _, entry := range archive.Entries {
			if entry.State != fixtureAbsent || !nativeFixtureUID(string(entry.OriginalUID)) || seenUIDs[entry.OriginalUID] {
				return 0, ErrFixtures
			}
			seenUIDs[entry.OriginalUID] = true
		}
		seenRuns[archive.RunID] = true
		worldName := "admission-worlds-" + anchor.InstallationID + "-" + archive.RunID + ".json"
		history = append(history, kindCPUPilotArchive{name: fixtureArchiveName(anchor, archive.RunID), body: bytes.Clone(retirement.archive), identity: retirement.archiveIdentity, worldName: worldName, worldSHA: retirement.record.OriginalWorldsSHA256, worldIdentity: retirement.worldIdentity})
		if verifyKindCPUPilotHistory(engine, history) != nil || engine.fixtureFence(fresh) != nil || security.current(ctx, access) != nil {
			return 0, ErrFixtures
		}
		if _, _, err := engine.files.Read(fixtureLedgerName(fresh), fixtureLedgerMaxBytes); !errors.Is(err, privatefs.ErrNotFound) {
			return 0, ErrFixtures
		}
		closing, err := store.Load(ctx, anchor)
		if err != nil || closing.Anchor() != anchor || !closing.SameJournalBytes(original) || closing.ResourceVersion() != original.ResourceVersion() || ctx.Err() != nil {
			return 0, ErrFixtures
		}
		duration := time.Since(started)
		t.Logf("CPU pilot sample=%d cpus=%d elapsed-ns=%d cases=55 fresh-run=true fresh-uids=true retired=true journal-unchanged=true wal-absent=true archives-unchanged=true", index, cpus, duration.Nanoseconds())
		return duration, nil
	})
	if err != nil || len(history) != 4 || len(seenRuns) != 4 || ctx.Err() != nil {
		t.Fatal("owned-node CPU pilot inconclusive: four complete proofs unavailable")
	}
	t.Logf("CPU pilot complete samples=4 useful-screen=%t permanent-adoption=false", kindNodeCPUPilotUseful(elapsed))
	fmt.Println("ARCADECTL_CPU_PILOT_COMPLETE samples=4 cases=55")
}
