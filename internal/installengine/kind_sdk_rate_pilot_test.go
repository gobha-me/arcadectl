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
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installpackage"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/flowcontrol"
)

// Intentionally unset until PR93's exact-main all88 delivery and review of a
// finite source-bound experiment. A plausible environment cannot enable this
// draft while its parent pin is missing.
const kindSDKRatePilotParent = ""

type kindSDKRateSample struct {
	qps                          int
	wall                         time.Duration
	waits, returned, inclusiveNS uint64
}

func kindSDKRatePilotOptIn(flag, ci, actions, source, parent string) bool {
	sha := regexp.MustCompile(`^[a-f0-9]{40}$`)
	return flag == "1" && ci == "true" && actions == "true" && sha.MatchString(source) && sha.MatchString(parent) && source != parent
}

// This is not a runtime configuration API. Only a constructor-owned parent
// with untouched static rate settings can receive the test-owned replacement.
func kindSDKRateSelect(a *HTTPAccess, previous *sdkWaitDiagnosticLimiter, qps int) (*sdkWaitDiagnosticLimiter, error) {
	if a == nil || !a.actorCompatible() || a.pool == nil || a.frozen.QPS != 0 || a.frozen.Burst != 0 || a.frozen.RateLimiter != nil || previous == nil || previous.RateLimiter == nil || a.readLimiter != previous || previous.QPS() != 200 && previous.QPS() != 400 || qps != 200 && qps != 400 || installerReadQPS != 200 || installerReadBurst != 20 {
		return nil, ErrInvalid
	}
	bucket := &sdkWaitDiagnosticLimiter{RateLimiter: flowcontrol.NewTokenBucketRateLimiter(float32(qps), 20)}
	a.readLimiter = bucket
	return bucket, nil
}

// Reading this config consumes no tokens. The constructor's config.QPS stays
// 200; an explicit shared RateLimiter is the effective SDK policy at either
// rate. Frozen caller provenance must remain completely unspecified.
func kindSDKRateInherited(a *HTTPAccess, bucket *sdkWaitDiagnosticLimiter, qps int) bool {
	if a == nil || a.frozen == nil || bucket == nil || bucket.RateLimiter == nil || qps != 200 && qps != 400 || a.readLimiter != bucket || bucket.QPS() != float32(qps) || a.frozen.QPS != 0 || a.frozen.Burst != 0 || a.frozen.RateLimiter != nil {
		return false
	}
	c := a.readConfig()
	return c != nil && c.QPS == 200 && c.Burst == 20 && c.RateLimiter == bucket && c.RateLimiter.QPS() == float32(qps)
}

func kindSDKRateSampleValid(value kindSDKRateSample, qps int) bool {
	return value.qps == qps && value.wall > 0 && value.wall <= 40*time.Minute && value.waits > 0 && value.waits == value.returned && value.waits <= 9007199254740991 && value.inclusiveNS <= 9007199254740991
}

func runKindSDKRateBracket(ctx context.Context, run func(int, int) (kindSDKRateSample, error)) ([4]kindSDKRateSample, error) {
	var samples [4]kindSDKRateSample
	for index, qps := range [4]int{200, 400, 400, 200} {
		if ctx == nil || ctx.Err() != nil || run == nil {
			return samples, ErrInvalid
		}
		value, err := run(index, qps)
		if err != nil || ctx.Err() != nil || !kindSDKRateSampleValid(value, qps) {
			return samples, ErrFixtures
		}
		samples[index] = value
	}
	return samples, nil
}

func kindSDKRateUseful(samples [4]kindSDKRateSample) bool {
	for index, rate := range [4]int{200, 400, 400, 200} {
		if !kindSDKRateSampleValid(samples[index], rate) {
			return false
		}
	}
	control := min(samples[0].wall, samples[3].wall)
	// Fixed <=40m durations keep integer multiplication bounded and exact.
	return samples[1].wall*100 <= control*85 && samples[2].wall*100 <= control*85
}

type kindSDKRateArchive struct {
	name                string
	body                []byte
	identity            privatefs.FileIdentity
	worldName, worldSHA string
	worldIdentity       privatefs.FileIdentity
}

func verifyKindSDKRateHistory(engine *Engine, history []kindSDKRateArchive) error {
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

// Four fresh complete V3 proofs in one unchanged ordinary-2CPU owned fixture.
// No subtest selector can choose one arm. No quota or cleanup path is changed.
func TestKindAdmissionV3SharedSDKReadRatePilot(t *testing.T) {
	flag := os.Getenv("ARCADECTL_KIND_SDK_RATE_PILOT")
	if flag == "" {
		t.Skip("shared SDK rate pilot is opt-in")
	}
	source := os.Getenv("ARCADECTL_SDK_RATE_SOURCE")
	if !kindSDKRatePilotOptIn(flag, os.Getenv("CI"), os.Getenv("GITHUB_ACTIONS"), source, kindSDKRatePilotParent) || os.Getenv("GITHUB_SHA") != source {
		t.Fatal("source-bound SDK rate pilot is unavailable")
	}
	ctx, config, api, controller := targetKindFixtureImagesV2(t, targetKind137, true)
	plan := fixturePlanImages(t, "isolated-install", installrender.Profile137, installpackage.Images{Controller: controller, API: api})
	access, engine, store, original, _ := targetKindInstallation(t, ctx, config, plan, true)
	security := installKindFixtureBaseline(t, ctx, access, plan.Namespace(), installrender.Profile137)
	prerequisites, err := NewClusterPrerequisites(engine, access)
	if err != nil {
		t.Fatal("SDK rate original prerequisites unavailable")
	}
	controllers, err := NewClusterControllers(prerequisites)
	ready := LifecycleCheck{Checkpoint: ControllersAvailable, Snapshot: original, Mode: installstate.Install, Target: plan, Options: LifecycleOptions{Now: time.Now().UTC()}}
	if err != nil || wait.PollUntilContextTimeout(ctx, time.Second, 3*time.Minute, true, func(ctx context.Context) (bool, error) { return controllers.Verify(ctx, ready) == nil, nil }) != nil {
		t.Fatal("SDK rate original warm controllers did not converge")
	}
	originalBucket, ok := access.readLimiter.(*sdkWaitDiagnosticLimiter)
	if !ok || !kindSDKRateInherited(access, originalBucket, 200) {
		t.Fatal("SDK rate constructor-owned default unavailable")
	}
	// Bootstrap observers are local and have returned; these prerequisites and
	// controllers hold only engine/access references. Each arm constructs a new
	// admission driver/actors; observer and GC clients are recreated from current
	// readConfig inside the production methods, never retained across arms.
	previous := originalBucket
	seenBuckets := map[*sdkWaitDiagnosticLimiter]bool{originalBucket: true}
	defer func() { access.readLimiter = originalBucket }()
	anchor := original.Anchor()
	seenRuns := map[string]bool{}
	seenUIDs := map[types.UID]bool{}
	var history []kindSDKRateArchive
	defer func() {
		for _, old := range history {
			clear(old.body)
		}
	}()
	t.Logf("SDK rate pilot pins source=%s parent=%s profile=kubernetes-1.37.0 rates=200,400,400,200 burst=20", source, kindSDKRatePilotParent)
	samples, err := runKindSDKRateBracket(ctx, func(index, qps int) (kindSDKRateSample, error) {
		// Prior complete() joined its workers/readers and retired its WAL before
		// runKindSDKRateBracket can enter this next arm. No old SDK client is used.
		bucket, err := kindSDKRateSelect(access, previous, qps)
		if err != nil || seenBuckets[bucket] || !kindSDKRateInherited(access, bucket, qps) {
			return kindSDKRateSample{}, ErrFixtures
		}
		seenBuckets[bucket] = true
		previous = bucket
		traced, costs := WithLifecycleCosts(ctx)
		started := time.Now()
		fresh, err := store.Load(traced, anchor)
		if err != nil || fresh.Anchor() != anchor || !fresh.SameJournalBytes(original) || fresh.ResourceVersion() != original.ResourceVersion() {
			return kindSDKRateSample{}, ErrFixtures
		}
		request := LifecycleCheck{Checkpoint: AdmissionEffective, Snapshot: fresh, Mode: installstate.Install, Target: plan, Options: LifecycleOptions{Now: time.Now().UTC()}}
		admission, err := NewClusterAdmission(engine, access)
		if err != nil {
			return kindSDKRateSample{}, ErrFixtures
		}
		trace := &admissionTrace{}
		traced = context.WithValue(traced, admissionTraceKey{}, trace)
		driver := newKindV3AdmissionDriver(t, traced, admission, request)
		if !kindSDKRateInherited(admission.prerequisites.access, bucket, qps) {
			return kindSDKRateSample{}, ErrFixtures
		}
		for _, clients := range []map[admissionActor]*HTTPAccess{driver.wire.actors.clients, driver.wire.clients} {
			for _, client := range clients {
				if !kindSDKRateInherited(client, bucket, qps) {
					return kindSDKRateSample{}, ErrFixtures
				}
			}
		}
		if driver.complete(traced) != nil {
			t.Logf("SDK rate pilot sample=%d qps=%d refused: %s", index, qps, kindAdmissionMatrixFailureSummary(trace))
			return kindSDKRateSample{}, ErrFixtures
		}
		if driver.failed || driver.next != fixtureAdmissionCaseCount || driver.completed != fixtureAdmissionAllCases || driver.wire.ledger.lock != nil || !kindSDKRateInherited(access, bucket, qps) {
			return kindSDKRateSample{}, ErrFixtures
		}
		retirement, err := engine.readFixtureRetirement(anchor)
		if err != nil || retirement.record.State != fixtureRetired || retirement.record.RunID != driver.wire.ledger.document.RunID || seenRuns[retirement.record.RunID] {
			return kindSDKRateSample{}, ErrFixtures
		}
		archive, err := engine.decodeFixtureLedger(retirement.archive)
		if err != nil || archive.Recipe != fixtureRecipeV3 || !validFixtureBehaviorDocument(archive) || archive.Behavior == nil || archive.Behavior.Version != fixtureBehaviorRecipeVersion(archive) || archive.DestroySeed == nil || archive.DestroySeed.State != fixtureDestroySeedAcknowledged || archive.RetainedMarker == nil || archive.RetainedMarker.State != fixtureRetainedMarkerAcknowledged {
			return kindSDKRateSample{}, ErrFixtures
		}
		for _, entry := range archive.Entries {
			if entry.State != fixtureAbsent || !nativeFixtureUID(string(entry.OriginalUID)) || seenUIDs[entry.OriginalUID] {
				return kindSDKRateSample{}, ErrFixtures
			}
			seenUIDs[entry.OriginalUID] = true
		}
		seenRuns[archive.RunID] = true
		worldName := "admission-worlds-" + anchor.InstallationID + "-" + archive.RunID + ".json"
		history = append(history, kindSDKRateArchive{name: fixtureArchiveName(anchor, archive.RunID), body: bytes.Clone(retirement.archive), identity: retirement.archiveIdentity, worldName: worldName, worldSHA: retirement.record.OriginalWorldsSHA256, worldIdentity: retirement.worldIdentity})
		if verifyKindSDKRateHistory(engine, history) != nil || engine.fixtureFence(fresh) != nil || security.current(traced, access) != nil {
			return kindSDKRateSample{}, ErrFixtures
		}
		if _, _, err := engine.files.Read(fixtureLedgerName(fresh), fixtureLedgerMaxBytes); !errors.Is(err, privatefs.ErrNotFound) {
			return kindSDKRateSample{}, ErrFixtures
		}
		closing, err := store.Load(traced, anchor)
		if err != nil || closing.Anchor() != anchor || !closing.SameJournalBytes(original) || closing.ResourceVersion() != original.ResourceVersion() || traced.Err() != nil {
			return kindSDKRateSample{}, ErrFixtures
		}
		metric := &costs.metrics[costSDKWait]
		value := kindSDKRateSample{qps: qps, wall: time.Since(started), waits: metric.calls.Load(), returned: metric.returned.Load(), inclusiveNS: metric.wallNS.Load()}
		if !kindSDKRateSampleValid(value, qps) {
			return kindSDKRateSample{}, ErrFixtures
		}
		t.Logf("SDK rate pilot sample=%d qps=%d elapsed-ns=%d sdk-wait-calls=%d sdk-wait-returned=%d sdk-wait-inclusive-wall-ns=%d cases=55 fresh-run=true fresh-uids=true retired=true journal-unchanged=true wal-absent=true archives-unchanged=true", index, qps, value.wall.Nanoseconds(), value.waits, value.returned, value.inclusiveNS)
		return value, nil
	})
	if err != nil || len(history) != 4 || len(seenRuns) != 4 || len(seenBuckets) != 5 || ctx.Err() != nil {
		t.Fatal("SDK rate pilot inconclusive: four complete proofs unavailable")
	}
	t.Logf("SDK rate pilot complete samples=4 useful-screen=%t permanent-adoption=false inclusive-waits-overlap=true", kindSDKRateUseful(samples))
	fmt.Println("ARCADECTL_SDK_RATE_PILOT_COMPLETE samples=4 cases=55")
}
