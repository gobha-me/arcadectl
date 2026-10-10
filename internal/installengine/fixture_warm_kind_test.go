//go:build kindinstall

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installobserve"
	"github.com/gobha-me/arcadectl/internal/installpackage"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	platformkube "github.com/gobha-me/arcadectl/internal/platform/kube"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/dynamic"
)

// Certify actual normal signed-controller cancellation/seed bookkeeping, keeping the
// existing controllers-absent certification separate. This is exclusively an
// owned empty-world native test, NOT complete production AdmissionEffective.
// Closed once-only warm status seeding uses its separate strict validator.
// No persistent confirmation or administrative finalizer stripping occurs.
func TestKindAdmissionFixturesWarmControllers(t *testing.T) {
	proveKindWarmFixtureRecipe(t, fixtureRecipeV1)
}

// Separate exact-owned certification; no active v1 WAL is upgraded and no
// default producer or full finite-matrix completion capability is enabled.
func TestKindAdmissionFixturesRecipeV2WarmControllers(t *testing.T) {
	proveKindWarmFixtureRecipe(t, fixtureRecipeV2)
}

func proveKindWarmFixtureRecipe(t *testing.T, recipe string) {
	t.Helper()
	if recipe != fixtureRecipeV1 && recipe != fixtureRecipeV2 {
		t.Fatal("unknown fixed native recipe")
	}
	markerLearning := os.Getenv("ARCADECTL_TEST_RETAINED_MARKER_LEARNING")
	if markerLearning != "" && markerLearning != "1" || markerLearning == "1" && os.Getenv("ARCADECTL_TEST_NATIVE_FIXTURE_SHAPES") == "" {
		t.Fatal("retained-marker native learning requires explicit private diagnostics")
	}
	if recipe == fixtureRecipeV2 && markerLearning != "" {
		t.Fatal("legacy retained-marker learning is not v2 certification")
	}
	receipt, err := beginWarmNativeOutcome()
	if err != nil {
		t.Fatal(err) // only fixed setup stages, never underlying platform errors
	}
	completed := [2]bool{}
	t.Cleanup(func() {
		if receipt == nil {
			return
		}
		if receipt.finish(t.Failed(), completed) != nil {
			t.Error("private native outcome bookkeeping failed")
		}
		if receipt.files.Close() != nil {
			t.Error("private native outcome descriptor cleanup failed")
		}
	})
	for index, profile := range []struct{ id, node string }{{installrender.Profile135, targetKind135}, {installrender.Profile137, targetKind137}} {
		bodyComplete := false
		success := t.Run(profile.id, func(t *testing.T) {
			images := targetKindFixtureImages
			if recipe == fixtureRecipeV2 {
				images = targetKindFixtureImagesV2
			}
			ctx, config, apiImage, controllerImage := images(t, profile.node, true)
			plan := fixturePlanImages(t, "isolated-install", profile.id, installpackage.Images{Controller: controllerImage, API: apiImage})
			access, engine, store, snapshot, _ := targetKindInstallation(t, ctx, config, plan, true)
			p, err := NewClusterPrerequisites(engine, access)
			if err != nil {
				t.Fatal("original warm prerequisites unavailable")
			}
			controllers, err := NewClusterControllers(p)
			if err != nil {
				t.Fatal("original warm controller proof unavailable")
			}
			request := LifecycleCheck{Checkpoint: ControllersAvailable, Snapshot: snapshot, Mode: installstate.Install, Target: plan, Options: LifecycleOptions{Now: time.Now().UTC()}}
			if wait.PollUntilContextTimeout(ctx, time.Second, 3*time.Minute, true, func(ctx context.Context) (bool, error) {
				return controllers.Verify(ctx, request) == nil, nil // readiness observations only
			}) != nil {
				t.Fatal("original signed warm controllers did not converge")
			}
			var serving *Serving
			var quiet time.Time
			if wait.PollUntilContextTimeout(ctx, time.Second, 3*time.Minute, true, func(ctx context.Context) (bool, error) {
				current, err := engine.ObserveServing(ctx, snapshot, access.Serving())
				if err != nil || current == nil {
					serving, quiet = nil, time.Time{}
					return false, nil
				}
				if serving == nil || serving.fingerprint != current.fingerprint {
					serving, quiet = current, time.Now()
				}
				return time.Since(quiet) >= 5*time.Second, nil
			}) != nil {
				t.Fatal("warm original API runtime did not settle before baseline")
			}
			cold, err := NewClusterCold(p)
			coldRequest := request
			coldRequest.Checkpoint = ColdSafety
			if err != nil || cold.Verify(ctx, coldRequest) != nil {
				t.Fatal("genuine pre-fixture ordinary cold-data safety unavailable")
			}
			baselineObservation, err := p.observe(ctx, request)
			baseline, mapErr := warmNativeObjects(baselineObservation)
			if err != nil || mapErr != nil || controllers.Verify(ctx, request) != nil || warmNativeLeaders(baseline, baseline, time.Now().UTC()) != nil {
				t.Fatal("warm complete original runtime/leadership baseline unavailable")
			}
			admission, err := NewClusterAdmission(engine, access)
			if err != nil {
				t.Fatal("warm original admission unavailable")
			}
			request.Checkpoint = AdmissionEffective
			initial, err := admission.captureInitialPhase(ctx, request)
			if err != nil || len(initial.baseline.Leaders) != 2 {
				t.Fatal("complete pre-fixture original phase with both leaders unavailable")
			}
			actors, err := admission.newActors(ctx, request, existingScopedImpersonation)
			if err != nil {
				t.Fatal("warm original actor witnesses unavailable")
			}
			ledger, err := engine.prepareFixtureLedger(ctx, snapshot)
			if err != nil {
				t.Fatal("warm original fixture ledger unavailable")
			}
			defer ledger.close()
			if recipe == fixtureRecipeV2 {
				instrumentFreshFixtureRecipeV2(t, ledger) // untouched owned test WAL ONLY
			}
			if initial.seal(ledger) != nil {
				t.Fatal("complete original phase companion durability refused")
			}
			wire, err := actors.fixtures(ctx, ledger)
			if err != nil {
				t.Fatal("warm original fixture wire unavailable")
			}
			admin, err := dynamic.NewForConfig(config)
			if err != nil {
				t.Fatal("owned warm observation client unavailable")
			}
			check := func(ctx context.Context) error {
				observation, err := p.observe(ctx, request)
				current, mapErr := warmNativeObjects(observation)
				if err != nil || mapErr != nil || warmNativeBaseline(ledger, baseline, current) != nil || warmNativeIsolation(ctx, wire, admin) != nil || wire.current(ctx) != nil {
					return ErrFixtures
				}
				return nil
			}
			// Observation-only retries allow normal original renewals and native
			// fixture bookkeeping to settle, never replay effects or adopt ACKs.
			phaseUnproved := false
			phaseRead := func(previous *fixturePhaseObservation, requireRenewal bool) *fixturePhaseObservation {
				t.Helper()
				var accepted *fixturePhaseObservation
				if wait.PollUntilContextTimeout(ctx, 200*time.Millisecond, 90*time.Second, true, func(ctx context.Context) (bool, error) {
					fresh, err := wire.observePhase(ctx)
					if err != nil {
						return false, nil
					}
					if len(fresh.phase.Leaders) != 2 || !samePhaseBaseline(initial.baseline, fresh.phase) {
						return false, ErrFixtures
					}
					if previous != nil {
						if !samePhaseBaseline(previous.phase, fresh.phase) {
							return false, ErrFixtures
						}
						for index, leader := range fresh.phase.Leaders {
							old := previous.phase.Leaders[index]
							oldRV, oldErr := strconv.ParseUint(old.Row.ResourceVersion, 10, 64)
							freshRV, freshErr := strconv.ParseUint(leader.Row.ResourceVersion, 10, 64)
							oldRenew, oldRenewErr := time.Parse(time.RFC3339Nano, old.RenewTime)
							freshRenew, freshRenewErr := time.Parse(time.RFC3339Nano, leader.RenewTime)
							if oldErr != nil || freshErr != nil || oldRenewErr != nil || freshRenewErr != nil {
								return false, ErrFixtures
							}
							if requireRenewal && (freshRV <= oldRV || !freshRenew.After(oldRenew)) {
								return false, nil
							}
						}
					}
					accepted = fresh
					return true, nil
				}) != nil || accepted == nil {
					phaseUnproved = true
					t.Fatal("complete original phase did not converge with both renewing native leaders")
				}
				return accepted
			}
			t.Log("checking complete Planned phase with both original native leaders")
			plannedPhase := phaseRead(nil, false)
			phaseRead(plannedPhase, true) // real renewals, no fixed sleep or RV waiver
			t.Log("complete Planned phase accepted across both original native leader renewals")
			// On any uncertainty, refuse object cleanup. The enclosing original
			// exact-owned Kind teardown remains the bounded safe fallback.
			var cancelled *unstructured.Unstructured
			warmSeedAttempted, warmSeedAccepted := false, false
			defer func() {
				if phaseUnproved {
					t.Log("unproved complete phase remains fenced; refusing fixture cleanup; exact-owned empty Kind teardown required")
					return
				}
				if ledger.markerUnresolved() {
					t.Log("unproved retained marker remains fenced; refusing fixture cleanup")
					return
				}
				if warmSeedAttempted && (!warmSeedAccepted || ledger.document.DestroySeed == nil || ledger.document.DestroySeed.Mode != fixtureDestroySeedWarmCancelled || ledger.document.DestroySeed.State != fixtureDestroySeedAcknowledged || ledger.seedAck || ledger.seedEffect) {
					// A reliable ACK alone is NOT whole-shape/isolation authority.
					// Unknown or later-refused seed permits only exact-owned teardown.
					t.Log("unknown/unvalidated warm seed remains fenced; refusing fixture-object cleanup; exact-owned empty Kind teardown required")
					return
				}
				if cancelled == nil {
					return
				}
				// Every selected original cleanup brackets full uncached namespace/GC
				// proofs, in addition to send/actual absence. Keep a finite owned-
				// test budget without skipping any gate when reads are expensive.
				cleanupCtx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
				defer cancel()
				cleanupStarted := time.Now()
				t.Log("starting bounded original cleanup with normal controllers live")
				for slot := len(ledger.document.Entries) - 1; slot >= 0; slot-- {
					if ledger.document.Entries[slot].State != fixtureOriginal || check(cleanupCtx) != nil {
						t.Error("warm original cleanup identity/isolation unproved; requiring owned Kind teardown; context-stage", warmCleanupContextStage(cleanupCtx))
						return
					}
					live, absent, err := wire.get(cleanupCtx, slot)
					if err != nil || absent || !warmNativeWhole(ledger, slot, live) || slot == fixtureCancelledDestroy && !reflect.DeepEqual(live.Object, cancelled.Object) {
						t.Error("warm original cleanup whole body changed; requiring owned Kind teardown")
						return
					}
					next, err := ledger.nextDocument()
					if err != nil {
						t.Error("warm cleanup intent unavailable")
						return
					}
					next.Entries[slot].State, next.Entries[slot].DeleteResourceVersion = fixtureDeleteAttempted, live.GetResourceVersion()
					if ledger.advance(next) != nil {
						t.Error("warm original cleanup intent durability refused")
						return
					}
					if err := wire.delete(cleanupCtx, slot); err != nil && err != ErrOutcomeUnknown {
						t.Error("warm original cleanup send refused")
						return
					}
					if wait.PollUntilContextTimeout(cleanupCtx, 100*time.Millisecond, 20*time.Second, true, func(ctx context.Context) (bool, error) {
						_, absent, err := wire.get(ctx, slot)
						return absent && err == nil, err // never replay DELETE or clear finalizers
					}) != nil {
						t.Error("warm original actual absence unavailable")
						return
					}
					next, _ = ledger.nextDocument()
					next.Entries[slot].State = fixtureAbsent
					if ledger.advance(next) != nil || check(cleanupCtx) != nil {
						t.Error("warm original absence durability/isolation refused; context-stage", warmCleanupContextStage(cleanupCtx))
						return
					}
					t.Logf("original slot %d absent after %d cleanup seconds", slot, int(time.Since(cleanupStarted)/time.Second))
				}
				retirementStarted := time.Now()
				if wire.retireDrained(cleanupCtx) != nil || engine.fixtureFence(snapshot) != nil {
					t.Error("complete original terminal retirement refused; requiring owned Kind teardown")
					return
				}
				t.Logf("terminal archive and retirement durable; ordinary fixture fence retired (%d retirement seconds; %d total cleanup seconds)", int(time.Since(retirementStarted)/time.Second), int(time.Since(cleanupStarted)/time.Second))
				if cold.Verify(cleanupCtx, coldRequest) != nil || engine.fixtureFence(snapshot) != nil {
					t.Error("warm cleanup did not preserve ordinary cold safety after durable retirement")
				}
			}()
			for slot := range fixtureCatalogFor(ledger.document) {
				if check(ctx) != nil {
					t.Fatal("warm original controllers/domain changed before fixed CREATE")
				}
				if _, absent, err := wire.get(ctx, slot); err != nil || !absent {
					t.Fatal("warm exact original fixture address is occupied")
				}
				if _, err := wire.dryRun(ctx, slot); err != nil {
					t.Fatalf("warm fixed original preview refused (fixed slot %d; stage %s)", slot, wire.previewDiagnostic())
				}
				if check(ctx) != nil {
					t.Fatal("warm original baseline changed before persistent CREATE intent")
				}
				next, _ := ledger.nextDocument()
				next.Entries[slot].State = fixtureCreateAttempted
				if ledger.advance(next) != nil {
					t.Fatal("warm original CREATE intent durability refused")
				}
				created, err := wire.create(ctx, slot)
				if err != nil || ledger.validateResult(slot, fixtureAcknowledgedResult, created, time.Now().UTC()) != nil {
					t.Fatal("warm original CREATE ACK/shape/isolation refused")
				}
				if slot == fixtureCancelledDestroy || slot == fixtureVerifiedCancelledDestroy {
					// Observation-only finite controller convergence after the
					// durable CREATE ACK. No further effect until the stable warm
					// shape and complete original baseline both validate.
					if wait.PollUntilContextTimeout(ctx, 200*time.Millisecond, time.Minute, true, func(ctx context.Context) (bool, error) {
						live, absent, err := wire.get(ctx, slot)
						return err == nil && !absent && warmNativeWhole(ledger, slot, live), err
					}) != nil {
						t.Fatal("original warm cancellation did not converge")
					}
				}
				if check(ctx) != nil {
					t.Fatal("warm original baseline changed after CREATE/convergence")
				}
			}
			if wait.PollUntilContextTimeout(ctx, 300*time.Millisecond, time.Minute, true, func(ctx context.Context) (bool, error) {
				for slot := range fixtureCatalogFor(ledger.document) {
					live, absent, err := wire.get(ctx, slot)
					if err != nil || absent || !warmNativeWhole(ledger, slot, live) {
						return false, nil // pre-effect native convergence, not ACK adoption
					}
					if slot == fixtureCancelledDestroy {
						cancelled = live
					}
				}
				return true, nil
			}) != nil || cancelled == nil || check(ctx) != nil {
				t.Fatal("warm original fixed fixture/cancellation convergence refused")
			}
			t.Log("checking complete all-original-fixtures phase after native convergence")
			stablePhase := phaseRead(plannedPhase, false)
			if recipe == fixtureRecipeV2 {
				stablePhase, err = proveKindVerifiedCancelledUpdate(t, ctx, wire, access, stablePhase)
				if err != nil {
					phaseUnproved = true
					t.Fatal("verified original no-op UPDATE or complete surrounding phase refused; requiring owned Kind teardown")
				}
				if captureNativeFixtureShape(ledger, fixtureVerifiedCancelledDestroy, "warm-cancelled", stablePhase.objects[fixtureVerifiedCancelledDestroy]) != nil {
					t.Fatal("private verified original cancellation capture refused")
				}
				stablePhase, err = proveKindFixedNoopReplies(t, ctx, wire, access, stablePhase)
				if err != nil {
					phaseUnproved = true
					t.Fatal("fixed original no-op endpoint or complete surrounding phase refused; requiring owned Kind teardown")
				}
				stablePhase, err = proveKindFixedPositiveDeltas(t, ctx, wire, access, stablePhase)
				if err != nil {
					phaseUnproved = true
					t.Fatal("fixed positive endpoint or complete surrounding phase refused; requiring owned Kind teardown")
				}
			}
			if ledger.validateResult(fixtureCancelledDestroy, fixtureStableResult, cancelled, time.Now().UTC()) != ErrFixtures || ledger.validateDestroySeedResult(cancelled, time.Now().UTC()) != ErrFixtures {
				t.Fatal("cold absent-status/seed validators accepted warm bookkeeping")
			}
			if captureNativeFixtureShape(ledger, fixtureCancelledDestroy, "warm-cancelled", cancelled) != nil {
				t.Fatal("private public-only warm bookkeeping capture refused")
			}
			if check(ctx) != nil {
				t.Fatal("original warm runtime changed around cancellation capture")
			}
			fresh, err := store.Load(ctx, snapshot.Anchor())
			if err != nil || !bytes.Equal(fresh.Bytes(), snapshot.Bytes()) || fresh.ResourceVersion() != snapshot.ResourceVersion() || engine.fixtureFence(snapshot) != ErrFixtures {
				t.Fatal("warm observation changed original journal or retired the fixture fence")
			}
			t.Log("normal signed controllers remained running; original cancelled finalizer/status observed; no status seed/confirmation/world exists; cold validators still refuse warm shape; original cleanup waits for controller-assisted finalizer removal and actual absence")
			if check(ctx) != nil || ledger.validateWarmCancelledDestroyResult(cancelled, time.Now().UTC()) != nil {
				t.Fatal("original complete warm baseline unavailable before fixed seed intent")
			}
			next, err := ledger.nextDocument()
			if err != nil {
				t.Fatal("warm fixed seed intent unavailable")
			}
			next.DestroySeed = &fixtureDestroySeedReceipt{Mode: fixtureDestroySeedWarmCancelled, State: fixtureDestroySeedAttempted, BeforeResourceVersion: cancelled.GetResourceVersion()}
			if ledger.advance(next) != nil {
				t.Fatal("warm fixed seed intent durability refused")
			}
			warmSeedAttempted = true
			seeded, err := wire.seedWarmDestroyStatus(ctx)
			if err != nil || ledger.validateWarmDestroySeedResult(seeded, time.Now().UTC()) != nil || captureNativeFixtureShape(ledger, fixtureCancelledDestroy, "warm-seeded", seeded) != nil {
				t.Fatal("original production warm seed/ACK/strict shape refused")
			}
			if _, err := wire.seedWarmDestroyStatus(ctx); err != ErrFixtures || ledger.seedAck || ledger.seedEffect || engine.fixtureFence(snapshot) != ErrFixtures {
				t.Fatal("warm fixed seed restored send authority or retired the fixture fence")
			}
			freshSeed, absent, err := wire.get(ctx, fixtureCancelledDestroy)
			if err != nil || absent || freshSeed == nil || !reflect.DeepEqual(seeded.Object, freshSeed.Object) || check(ctx) != nil {
				t.Fatal("full original warm baseline/isolation changed after fixed seed")
			}
			fresh, err = store.Load(ctx, snapshot.Anchor())
			if err != nil || !bytes.Equal(fresh.Bytes(), snapshot.Bytes()) || fresh.ResourceVersion() != snapshot.ResourceVersion() || ledger.validateDestroySeedResult(seeded, time.Now().UTC()) != ErrFixtures || ledger.validateWarmCancelledDestroyResult(seeded, time.Now().UTC()) != ErrFixtures {
				t.Fatal("warm fixed seed changed journal or relaxed cold/cancellation acceptance")
			}
			cancelled, warmSeedAccepted = seeded, true
			t.Log("checking complete original phase after reliable warm seed ACK")
			seedPhase := phaseRead(stablePhase, false)
			if recipe == fixtureRecipeV2 {
				if _, err := proveKindFixedNoopReplies(t, ctx, wire, access, seedPhase); err != nil {
					phaseUnproved = true
					t.Fatal("fixed seeded-controller no-op or complete surrounding phase refused; requiring owned Kind teardown")
				}
			}
			t.Log("production warm seed reliably ACKed and exact whole shape validated; fresh whole GET and full unfiltered baseline/GC isolation unchanged; no confirmation or world exists; original-only cleanup still requires current whole shape/GC and actual absence")
			// Every probe uses the existing fixed dryRun=All actor seam. No
			// persistent confirmation or permission expansion is possible here.
			// Bracket EACH reply, including refusals/errors, with fresh strict
			// original GET/full baseline/GC and unchanged protected WAL/journal.
			seedBody, seedIdentity, seedRevision := bytes.Clone(ledger.body), ledger.identity, ledger.document.Revision
			unchanged := func() {
				t.Helper()
				live, absent, getErr := wire.get(ctx, fixtureCancelledDestroy)
				fresh, journalErr := store.Load(ctx, snapshot.Anchor())
				if getErr != nil || absent || live == nil || !reflect.DeepEqual(live.Object, seeded.Object) || ledger.validateWarmDestroySeedResult(live, time.Now().UTC()) != nil || check(ctx) != nil || journalErr != nil || !bytes.Equal(fresh.Bytes(), snapshot.Bytes()) || fresh.ResourceVersion() != snapshot.ResourceVersion() || !bytes.Equal(ledger.body, seedBody) || ledger.identity != seedIdentity || ledger.document.Revision != seedRevision || ledger.seedAck || ledger.seedEffect || engine.fixtureFence(snapshot) != ErrFixtures {
					warmSeedAccepted = false // Unknown/drifted proof permits owned cluster teardown only.
					t.Fatal("warm dry-run changed original whole body/baseline/WAL or witnesses")
				}
			}
			unchanged()
			control, probeErr := wire.actors.probe(ctx, destroyControllerActor, probeUpdateOperation, seeded.DeepCopy(), "", "", "")
			unchanged()
			if probeErr != nil || ledger.validateWarmDestroySeedResult(control, time.Now().UTC()) != nil {
				warmSeedAccepted = false
				t.Fatal("warm unchanged-controller dry-run whole control refused")
			}
			changed := seeded.DeepCopy()
			if unstructured.SetNestedField(changed.Object, ledger.document.RunID, "spec", "confirmationChallenge") != nil {
				t.Fatal("fixed warm dry-run confirmation unavailable")
			}
			var seedTime time.Time
			for _, field := range seeded.GetManagedFields() {
				if field.Manager == "arcadectl-installer" && field.Subresource == "status" && field.Time != nil {
					seedTime = field.Time.Time
				}
			}
			if seedTime.IsZero() || wait.PollUntilContextTimeout(ctx, 50*time.Millisecond, 2*time.Second, true, func(context.Context) (bool, error) {
				return time.Now().UTC().Truncate(time.Second).After(seedTime), nil
			}) != nil {
				t.Fatal("warm later-second confirmation control unavailable")
			}
			unchanged()
			accepted, probeErr := wire.actors.probe(ctx, destroyAdministratorActor, probeUpdateOperation, changed.DeepCopy(), "", "", "")
			unchanged()
			if probeErr != nil || ledger.validateWarmDestroyConfirmationResult(accepted, time.Now().UTC()) != nil || captureNativeFixtureShape(ledger, fixtureCancelledDestroy, "warm-confirmation", accepted) != nil {
				warmSeedAccepted = false
				t.Fatal("warm distinct-admin confirmation dry-run whole shape refused")
			}
			var confirmationTime time.Time
			for _, field := range accepted.GetManagedFields() {
				if field.Manager == "arcadectl-installer" && field.Subresource == "" && field.Time != nil {
					confirmationTime = field.Time.Time
				}
			}
			if !confirmationTime.After(seedTime) {
				warmSeedAccepted = false
				t.Fatal("warm later-second confirmation bookkeeping unproved")
			}
			policyName, bindingName := "", ""
			for name := range wire.actors.policies.policies {
				if name == "arcadectl-destroy-unsafe-admin" || strings.HasPrefix(name, "arcadectl-destroy-unsafe-admin-") {
					if policyName != "" {
						t.Fatal("ambiguous original warm unsafe policy")
					}
					policyName = name
				}
			}
			policy := wire.actors.policies.policies[policyName]
			if policy == nil || len(policy.Spec.Validations) < 1 {
				t.Fatal("original warm unsafe policy unavailable")
			}
			for name, binding := range wire.actors.policies.bindings {
				if binding.Spec.PolicyName == policyName {
					if bindingName != "" {
						t.Fatal("ambiguous original warm unsafe binding")
					}
					bindingName = name
				}
			}
			unchanged()
			denied, probeErr := wire.actors.probe(ctx, destroyControllerActor, probeUpdateOperation, changed.DeepCopy(), policyName, bindingName, policy.Spec.Validations[0].Message)
			unchanged()
			if probeErr != nil || denied != nil {
				warmSeedAccepted = false
				t.Fatal("warm confirmation did not yield exact original controller policy denial")
			}
			t.Log("warm unchanged-controller control and distinct-admin confirmation dry-runs whole-validated; exact signed-policy controller denial; original seeded GET/full baseline/GC/WAL unchanged after EVERY probe; confirmation never persisted")
			if markerLearning == "1" {
				proveKindRetainedMarkerLearning(t, ctx, p, request, baseline, wire, admin)
			}
			bodyComplete = true
		})
		completed[index] = bodyComplete && success
	}
}

// TEST-only noninterference observation of the original ACK-bound diagnostic
// reply. Not a whole seeded-shape validator or an ordinary lifecycle checkpoint.
// Every unfiltered row is accounted for; no status/body projection is accepted.
func warmSeedLearningBaseline(f *fixtureLedger, baseline, current map[installstate.Key]*unstructured.Unstructured, seeded *unstructured.Unstructured) error {
	if seeded == nil || warmSeedLearningPublic(f, seeded, time.Now().UTC()) != nil || warmNativeLeaders(baseline, current, time.Now().UTC()) != nil || len(current) != len(baseline)+len(fixtureCatalog) {
		return ErrFixtures
	}
	for key, original := range baseline {
		fresh := current[key]
		if fresh == nil || key.Kind != "Lease" && !reflect.DeepEqual(original.Object, fresh.Object) {
			return ErrFixtures
		}
	}
	for slot, entry := range f.document.Entries {
		fresh := current[entry.Key]
		if entry.State != fixtureOriginal || fresh == nil || fresh.GetUID() != entry.OriginalUID || baseline[entry.Key] != nil {
			return ErrFixtures
		}
		if slot == fixtureCancelledDestroy {
			if !reflect.DeepEqual(fresh.Object, seeded.Object) {
				return ErrFixtures
			}
		} else if f.validateResult(slot, fixtureStableResult, fresh, time.Now().UTC()) != nil {
			return ErrFixtures
		}
	}
	return nil
}

func warmNativeWhole(f *fixtureLedger, slot int, live *unstructured.Unstructured) bool {
	if slot == fixtureVerifiedCancelledDestroy {
		return f.validateWarmCancelledDestroySlotResult(slot, live, time.Now().UTC()) == nil
	}
	if slot != fixtureCancelledDestroy {
		return f.validateResult(slot, fixtureStableResult, live, time.Now().UTC()) == nil
	}
	if f.document.DestroySeed != nil {
		return f.document.DestroySeed.Mode == fixtureDestroySeedWarmCancelled && f.document.DestroySeed.State == fixtureDestroySeedAcknowledged && f.validateWarmDestroySeedResult(live, time.Now().UTC()) == nil
	}
	return f.validateWarmCancelledDestroyResult(live, time.Now().UTC()) == nil
}

// Unfiltered native-test empty-world/derived-address observations plus complete
// arbitrary-GVR owner closure. NOT a production baseline-world witness and not
// permission to filter ordinary ColdSafety/RuntimeStopped snapshots.
func warmNativeIsolation(ctx context.Context, w *fixtureWire, admin dynamic.Interface) error {
	if w == nil || w.ledger == nil || !validFixtureRecipe(w.ledger.document) {
		return ErrFixtures
	}
	ns := w.actors.request.Snapshot.Anchor().Namespace
	for _, plural := range []string{"gameservers", "gamebackups", "gamerestores", "arcadeoperations"} {
		list, err := admin.Resource(schema.GroupVersionResource{Group: "arcade.gobha.me", Version: "v1alpha1", Resource: plural}).Namespace(ns).List(ctx, metav1.ListOptions{})
		if err != nil || len(list.Items) != 0 {
			return ErrFixtures
		}
	}
	claims, err := admin.Resource(schema.GroupVersionResource{Version: "v1", Resource: "persistentvolumeclaims"}).Namespace(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return ErrFixtures
	}
	for _, claim := range claims.Items {
		known := false
		for _, slot := range []int{fixtureRetainedPVC, fixturePlainPVC} {
			entry := w.ledger.document.Entries[slot]
			known = known || entry.State == fixtureOriginal && entry.Key.Name == claim.GetName() && entry.OriginalUID == claim.GetUID()
		}
		if !known {
			return ErrFixtures
		}
	}
	destroys, err := admin.Resource(schema.GroupVersionResource{Group: "arcade.gobha.me", Version: "v1alpha1", Resource: "gamedestroys"}).Namespace(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return ErrFixtures
	}
	for _, destroy := range destroys.Items {
		known := false
		for _, entry := range w.ledger.document.Entries {
			if entry.Key.Kind == "GameDestroy" && entry.State == fixtureOriginal && destroy.GetName() == entry.Key.Name && destroy.GetUID() == entry.OriginalUID {
				known = true
			}
		}
		if !known {
			return ErrFixtures
		}
	}
	for slot, gd := range w.ledger.document.Entries {
		if gd.Key.Kind != "GameDestroy" || gd.OriginalUID == "" {
			continue
		}
		identity := "synthetic-" + w.ledger.document.RunID
		if slot == fixtureVerifiedCancelledDestroy {
			identity = "synthetic-verified-" + w.ledger.document.RunID
		}
		name := platformkube.DestroyResourceName(gd.OriginalUID)
		for _, item := range []struct {
			gv   schema.GroupVersionResource
			name string
		}{
			{schema.GroupVersionResource{Group: "batch", Version: "v1", Resource: "jobs"}, name},
			{schema.GroupVersionResource{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "rolebindings"}, name + "-authority"},
			{schema.GroupVersionResource{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "roles"}, name + "-authority"},
			{schema.GroupVersionResource{Version: "v1", Resource: "serviceaccounts"}, name + "-authority"},
			{schema.GroupVersionResource{Version: "v1", Resource: "configmaps"}, name + "-input"},
			{schema.GroupVersionResource{Group: "coordination.k8s.io", Version: "v1", Resource: "leases"}, platformkube.DestroyWorkerLeaseName(gd.OriginalUID)},
			{schema.GroupVersionResource{Group: "coordination.k8s.io", Version: "v1", Resource: "leases"}, platformkube.DataOperationLeaseName(identity)},
		} {
			if _, err := admin.Resource(item.gv).Namespace(ns).Get(ctx, item.name, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
				return ErrFixtures
			}
		}
		pods, err := admin.Resource(schema.GroupVersionResource{Version: "v1", Resource: "pods"}).Namespace(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			return ErrFixtures
		}
		for _, pod := range pods.Items {
			if pod.GetLabels()[platformkube.LabelDestroyUID] == string(gd.OriginalUID) {
				return ErrFixtures
			}
		}
	}
	gc, err := w.gcMetadata(ctx)
	if err != nil {
		return ErrFixtures
	}
	for slot, entry := range w.ledger.document.Entries {
		if entry.OriginalUID == "" {
			continue
		}
		children, err := gc.Descendants([]types.UID{entry.OriginalUID})
		if err != nil {
			return ErrFixtures
		}
		expected := 0
		for child, recipe := range fixtureCatalogFor(w.ledger.document) {
			if recipe.owner == slot && w.ledger.document.Entries[child].State == fixtureOriginal {
				expected++
				if len(children) != 1 || children[0].Metadata.UID != w.ledger.document.Entries[child].OriginalUID {
					return ErrFixtures
				}
			}
		}
		if len(children) != expected {
			return ErrFixtures
		}
	}
	return nil
}

// TEST-only explicit delta accounting over every complete, unfiltered public
// observer collection. No projected/filtered snapshot enters an ordinary gate.
func warmNativeObjects(o *installobserve.Observation) (map[installstate.Key]*unstructured.Unstructured, error) {
	if o == nil || o.Snapshot() == nil || o.Runtime() == nil {
		return nil, ErrFixtures
	}
	s, r := o.Snapshot(), o.Runtime()
	collections := []struct {
		version, kind string
		list          runtime.Object
	}{
		{"arcade.gobha.me/v1alpha1", "GameServer", s.GameServers}, {"arcade.gobha.me/v1alpha1", "GameBackup", s.Backups},
		{"arcade.gobha.me/v1alpha1", "GameRestore", s.Restores}, {"arcade.gobha.me/v1alpha1", "GameDestroy", s.Destroys},
		{"arcade.gobha.me/v1alpha1", "ArcadeOperation", s.Operations}, {"batch/v1", "Job", s.Jobs}, {"v1", "Pod", s.Pods},
		{"coordination.k8s.io/v1", "Lease", s.Leases}, {"v1", "PersistentVolumeClaim", s.Claims}, {"v1", "Secret", s.Secrets},
		{"admissionregistration.k8s.io/v1", "ValidatingAdmissionPolicy", s.Policies}, {"admissionregistration.k8s.io/v1", "ValidatingAdmissionPolicyBinding", s.Bindings},
		{"apps/v1", "Deployment", r.Deployments}, {"apps/v1", "ReplicaSet", r.ReplicaSets}, {"apps/v1", "StatefulSet", r.StatefulSets},
		{"apps/v1", "DaemonSet", r.DaemonSets}, {"v1", "ReplicationController", r.ReplicationControllers}, {"batch/v1", "CronJob", r.CronJobs},
		{"storage.k8s.io/v1", "VolumeAttachment", r.Attachments}, {"discovery.k8s.io/v1", "EndpointSlice", r.EndpointSlices},
	}
	rows := map[installstate.Key]*unstructured.Unstructured{}
	for _, collection := range collections {
		items, err := meta.ExtractList(collection.list)
		if err != nil {
			return nil, ErrFixtures
		}
		for _, item := range items {
			body, err := runtime.DefaultUnstructuredConverter.ToUnstructured(item)
			if err != nil {
				return nil, ErrFixtures
			}
			body["apiVersion"], body["kind"] = collection.version, collection.kind
			object := &unstructured.Unstructured{Object: body}
			key := installstate.Key{APIVersion: collection.version, Kind: collection.kind, Namespace: object.GetNamespace(), Name: object.GetName()}
			if rows[key] != nil {
				return nil, ErrFixtures
			}
			rows[key] = object
		}
	}
	return rows, nil
}

func TestWarmNativeBaselineSeedReceiptDisallowsBareOriginal(t *testing.T) {
	f := newFixture(t, false)
	ledger, err := f.engine.prepareFixtureLedger(t.Context(), f.snapshot)
	if err != nil {
		t.Fatal("original ledger unavailable")
	}
	defer ledger.close()
	acknowledgeAllRecipeFixtures(t, ledger)
	now := time.Now().UTC().Truncate(time.Second)
	created := now.Add(-time.Minute)
	ns := ledger.document.Entries[0].Key.Namespace
	baseline := map[installstate.Key]*unstructured.Unstructured{}
	current := map[installstate.Key]*unstructured.Unstructured{}
	// Independent minimal public native-derived leaders with matching original
	// runtime Pods. These synthetic observations are not controller readiness.
	for index, role := range []struct{ name, account string }{
		{"controller.arcade.gobha.me", "arcadectl-controller"},
		{"destroy-controller.arcade.gobha.me", "arcadectl-destroy-controller"},
	} {
		podName := role.account + "-test"
		podKey := installstate.Key{APIVersion: "v1", Kind: "Pod", Namespace: ns, Name: podName}
		pod := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": podName, "namespace": ns},
			"spec": map[string]any{"serviceAccountName": role.account},
		}}
		baseline[podKey], current[podKey] = pod, pod.DeepCopy()
		key := installstate.Key{APIVersion: "coordination.k8s.io/v1", Kind: "Lease", Namespace: ns, Name: role.name}
		uid := types.UID("10000000-0000-4000-8000-000000000011")
		if index == 1 {
			uid = "10000000-0000-4000-8000-000000000012"
		}
		lease := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": key.APIVersion, "kind": "Lease", "metadata": map[string]any{"name": role.name, "namespace": ns},
			"spec": map[string]any{
				"holderIdentity":       podName + "_10000000-0000-4000-8000-000000000099",
				"leaseDurationSeconds": int64(15), "leaseTransitions": int64(0),
				"acquireTime": created.UTC().Format("2006-01-02T15:04:05.000000Z"),
				"renewTime":   now.UTC().Format("2006-01-02T15:04:05.000000Z"),
			},
		}}
		lease.SetUID(uid)
		lease.SetResourceVersion("101")
		lease.SetCreationTimestamp(metav1.NewTime(created))
		baseline[key], current[key] = lease, lease.DeepCopy()
	}
	for slot, entry := range ledger.document.Entries {
		current[entry.Key] = fixtureResultExample(t, ledger, slot, fixtureStableResult, created)
	}
	key := ledger.document.Entries[fixtureCancelledDestroy].Key
	bare := fixtureResultExample(t, ledger, fixtureCancelledDestroy, fixtureAcknowledgedResult, created)
	current[key] = bare
	if warmNativeBaseline(ledger, baseline, current) != nil {
		t.Fatal("pre-seed acknowledged CREATE convergence refused")
	}
	intent := fixtureSeedIntent(t, ledger)
	intent.DestroySeed.Mode = fixtureDestroySeedWarmCancelled
	if ledger.advance(intent) != nil {
		t.Fatal("abstract warm intent unavailable")
	}
	if warmNativeBaseline(ledger, baseline, current) != ErrFixtures {
		t.Error("warm attempted receipt accepted bare CREATE shape")
	}
	seeded := fixtureWarmSeededExample(t, ledger, created, [4]time.Duration{time.Second, time.Second, time.Second, 2 * time.Second})
	current[key] = seeded
	if warmNativeBaseline(ledger, baseline, current) != ErrFixtures {
		t.Error("unacknowledged warm seeded GET acquired baseline authority")
	}
	ledger.seedEffect = false // Abstract test receipt, never a native wire ACK.
	if ledger.advance(fixtureSeedAcknowledgement(t, ledger)) != nil {
		t.Fatal("abstract acknowledged receipt unavailable")
	}
	if warmNativeBaseline(ledger, baseline, current) != nil {
		t.Fatal("exact acknowledged warm seeded baseline refused")
	}
	current[key] = bare
	if warmNativeBaseline(ledger, baseline, current) != ErrFixtures {
		t.Error("acknowledged warm seed accepted stripped bare original")
	}
}

// Bare acknowledged CREATE is only pre-seed controller convergence for the
// cancelled destroy fixture. Once intent exists, neither attempted nor ACKed
// seed receipts may fall back to that earlier shape.
func warmNativeAccounted(f *fixtureLedger, slot int, live *unstructured.Unstructured) bool {
	if warmNativeWhole(f, slot, live) {
		return true
	}
	if slot == fixtureCancelledDestroy && f.document.DestroySeed != nil {
		return false
	}
	return f.validateResult(slot, fixtureAcknowledgedResult, live, time.Now().UTC()) == nil
}

func warmNativeBaseline(f *fixtureLedger, baseline, current map[installstate.Key]*unstructured.Unstructured) error {
	if warmNativeLeaders(baseline, current, time.Now().UTC()) != nil {
		return ErrFixtures
	}
	for slot, entry := range f.document.Entries {
		fresh := current[entry.Key]
		switch entry.State {
		case fixtureOriginal:
			if fresh == nil || fresh.GetUID() != entry.OriginalUID || !warmNativeAccounted(f, slot, fresh) {
				return ErrFixtures
			}
		case fixturePlanned, fixtureAbsent:
			if fresh != nil {
				return ErrFixtures
			}
		default:
			return ErrFixtures // no-effect observation cannot resolve an uncertain send
		}
	}
	for key, original := range baseline {
		fresh := current[key]
		if fresh == nil || key.Kind != "Lease" && !reflect.DeepEqual(original.Object, fresh.Object) {
			return ErrFixtures
		}
	}
	for key, fresh := range current {
		if baseline[key] != nil {
			continue
		}
		known := false
		for slot, entry := range f.document.Entries {
			if entry.Key != key || entry.State != fixtureOriginal || fresh.GetUID() != entry.OriginalUID {
				continue
			}
			known = warmNativeAccounted(f, slot, fresh)
			break
		}
		if !known {
			return ErrFixtures
		}
	}
	return nil
}

// Narrow native-test renewal allowance; never omit the Lease collection or
// accept a data-operation lease. Both original leaders stay bound to original
// signed runtime Pods. Every non-renewal public field remains byte-equivalent.
func warmNativeLeaders(baseline, current map[installstate.Key]*unstructured.Unstructured, observed time.Time) error {
	count := 0
	for key, original := range baseline {
		if key.Kind != "Lease" {
			continue
		}
		count++
		account := "arcadectl-controller"
		if key.Name == "destroy-controller.arcade.gobha.me" {
			account = "arcadectl-destroy-controller"
		} else if key.Name != "controller.arcade.gobha.me" {
			return ErrFixtures
		}
		fresh := current[key]
		if fresh == nil || !nativeFixtureUID(string(original.GetUID())) || fresh.GetUID() != original.GetUID() || !fixtureRV(original.GetResourceVersion()) || !fixtureRV(fresh.GetResourceVersion()) || len(original.GetLabels()) != 0 || len(original.GetAnnotations()) != 0 || len(original.GetOwnerReferences()) != 0 || len(original.GetFinalizers()) != 0 || original.GetDeletionTimestamp() != nil {
			return ErrFixtures
		}
		originalRV, _ := strconv.ParseUint(original.GetResourceVersion(), 10, 64)
		freshRV, _ := strconv.ParseUint(fresh.GetResourceVersion(), 10, 64)
		created := original.GetCreationTimestamp().Time
		acquire, acquireFound, acquireErr := unstructured.NestedString(original.Object, "spec", "acquireTime")
		acquired, parseAcquireErr := time.Parse(time.RFC3339Nano, acquire)
		transitions, transitionsFound, transitionsErr := unstructured.NestedInt64(original.Object, "spec", "leaseTransitions")
		if freshRV < originalRV || created.IsZero() || created.Year() < 1 || created.Year() > 9999 || created.After(observed.Add(time.Second)) || !acquireFound || acquireErr != nil || parseAcquireErr != nil || acquired.IsZero() || acquire != acquired.UTC().Format("2006-01-02T15:04:05.000000Z") || acquired.Before(created) || !transitionsFound || transitionsErr != nil || transitions < 0 {
			return ErrFixtures
		}
		for _, field := range []string{"preferredHolder", "strategy"} {
			if _, found, err := unstructured.NestedFieldNoCopy(original.Object, "spec", field); err != nil || found {
				return ErrFixtures
			}
		}
		if _, found := original.Object["status"]; found {
			return ErrFixtures
		}
		holder, _, _ := unstructured.NestedString(original.Object, "spec", "holderIdentity")
		matched := false
		for podKey, pod := range baseline {
			if podKey.Kind != "Pod" || podKey.Namespace != key.Namespace {
				continue
			}
			podAccount, _, _ := unstructured.NestedString(pod.Object, "spec", "serviceAccountName")
			prefix := podKey.Name + "_"
			matched = matched || podAccount == account && strings.HasPrefix(holder, prefix) && nativeFixtureUID(strings.TrimPrefix(holder, prefix))
		}
		duration, _, _ := unstructured.NestedInt64(original.Object, "spec", "leaseDurationSeconds")
		before, _, _ := unstructured.NestedString(original.Object, "spec", "renewTime")
		after, _, _ := unstructured.NestedString(fresh.Object, "spec", "renewTime")
		oldTime, oldErr := time.Parse(time.RFC3339Nano, before)
		newTime, newErr := time.Parse(time.RFC3339Nano, after)
		if !matched || duration != 15 || oldErr != nil || newErr != nil || oldTime.Before(acquired) || before != oldTime.UTC().Format("2006-01-02T15:04:05.000000Z") || after != newTime.UTC().Format("2006-01-02T15:04:05.000000Z") || newTime.Before(oldTime) || newTime.After(observed.Add(time.Second)) || observed.Sub(newTime) > 15*time.Second {
			return ErrFixtures
		}
		copy := original.DeepCopy()
		copy.SetResourceVersion(fresh.GetResourceVersion())
		if unstructured.SetNestedField(copy.Object, after, "spec", "renewTime") != nil {
			return ErrFixtures
		}
		fields, updates := copy.GetManagedFields(), fresh.GetManagedFields()
		if len(fields) != len(updates) {
			return ErrFixtures
		}
		for i := range fields {
			if fields[i].Time == nil || updates[i].Time == nil || updates[i].Time.Before(fields[i].Time) || updates[i].Time.Time.After(observed.Add(time.Second)) {
				return ErrFixtures
			}
			fields[i].Time = updates[i].Time.DeepCopy()
		}
		copy.SetManagedFields(fields)
		if !reflect.DeepEqual(copy.Object, fresh.Object) {
			return ErrFixtures
		}
	}
	if count != 2 {
		return ErrFixtures
	}
	return nil
}
