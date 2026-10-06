//go:build kindinstall

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	batchv1 "k8s.io/api/batch/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
)

// Certification of private transport and fixed recipes against native actors/
// controllers, ONLY within targetKindFixture's original disposable cluster.
// Whole-result validation is private shape evidence, not a complete production
// permission provider, cleanup recovery or WAL retirement. Leaf/descendant
// checks additionally rely on this exclusively owned application-cold cluster.
func proveKindAdmissionFixtureRecipes(t *testing.T, parent context.Context, config *rest.Config, engine *Engine, s *installstate.Snapshot, plan *installrender.Plan) {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 4*time.Minute)
	defer cancel()
	access, ok := engine.access.(*HTTPAccess)
	if !ok {
		t.Fatal("original native direct transport unavailable")
	}
	admission, err := NewClusterAdmission(engine, access)
	if err != nil {
		t.Fatal("original native admission unavailable")
	}
	request := LifecycleCheck{Checkpoint: AdmissionEffective, Snapshot: s, Mode: installstate.Install, Target: plan, Options: LifecycleOptions{Now: time.Now().UTC()}}
	var actors *admissionActors
	if wait.PollUntilContextTimeout(ctx, 200*time.Millisecond, 30*time.Second, true, func(ctx context.Context) (bool, error) {
		var err error
		actors, err = admission.newActors(ctx, request, existingScopedImpersonation)
		return err == nil, nil // only pre-effect observations while native policies converge
	}) != nil {
		t.Fatal("original native actor/policy witnesses unavailable")
	}
	ledger, err := engine.prepareFixtureLedger(ctx, s)
	if err != nil {
		t.Fatal("owned native recipe ledger unavailable")
	}
	defer ledger.close()
	wire, err := actors.fixtures(ctx, ledger)
	if err != nil {
		t.Fatal("original native fixture wire unavailable")
	}
	admin, err := dynamic.NewForConfig(config)
	if err != nil {
		t.Fatal("owned recipe client unavailable")
	}
	cleanup := func() {
		t.Helper()
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cleanupCancel()
		if ledger.document.DestroySeed != nil && ledger.document.DestroySeed.State != fixtureDestroySeedAcknowledged {
			t.Error("unknown native status seed remains fenced; requiring exact owned-cluster teardown")
			return
		}
		// Enumerate original durable ACKs even after post-ACK refusal. Unknown
		// CREATE blocks all transitions; only the enclosing exact-owned Kind
		// teardown may drain that disposable cluster. No SDK/name adoption.
		for _, entry := range ledger.document.Entries {
			if entry.State == fixtureCreateAttempted {
				t.Error("unknown native CREATE remains fenced; requiring exact owned-cluster teardown")
				return
			}
		}
		for slot := len(fixtureCatalog) - 1; slot >= 0; slot-- {
			entry := ledger.document.Entries[slot]
			key := entry.Key
			if key.Kind == "Job" && ledger.document.Entries[slot+1].State != fixtureAbsent {
				t.Error("refusing Job cleanup without its original worker's actual absence")
				continue
			}
			live, absent, err := wire.get(cleanupCtx, slot)
			if err != nil {
				t.Error("original native cleanup observation refused")
				return
			}
			if entry.State == fixturePlanned {
				if !absent {
					t.Error("uncreated fixture address occupied; refusing adoption/cleanup")
					return
				}
				next, _ := ledger.nextDocument()
				next.Entries[slot].State = fixtureAbsent
				if ledger.advance(next) != nil {
					t.Error("planned native address absence durability refused")
					return
				}
				continue
			}
			if entry.State != fixtureOriginal || absent || live == nil || live.GetUID() != entry.OriginalUID || !fixtureRV(live.GetResourceVersion()) {
				t.Error("refusing replaced/unproved native recipe cleanup")
				return // no fresh intent can repair an externally missing original
			}
			shapeErr := ledger.validateResult(slot, fixtureStableResult, live, time.Now().UTC())
			if slot == fixtureCancelledDestroy && ledger.document.DestroySeed != nil {
				shapeErr = ledger.validateDestroySeedResult(live, time.Now().UTC())
				if live.GetResourceVersion() != ledger.document.DestroySeed.AcknowledgedResourceVersion {
					shapeErr = ErrFixtures
				}
			}
			if shapeErr != nil {
				t.Error("refusing unproved whole native fixture shape before cleanup")
				return // reliable ACK identity is not inert-shape permission
			}
			uid := entry.OriginalUID
			if slot == fixtureCancelledDestroy {
				// This already-cancelled synthetic leaf never created workers,
				// leases or data. Its controller is not deployed in this owned
				// test cluster. Prove that invariant rather than introducing a
				// foreground-GC finalizer on a leaf. Background deletion needs the
				// original UID/RV and an independent actual NotFound observation.
				// These application/runtime collections are not universal GC
				// closure; safety also relies on this fresh exclusively owned
				// cluster and its absent application controllers, not this scan
				// as a production cleanup authority for an arbitrary cluster.
				leaf := len(live.GetFinalizers()) == 0 && len(live.GetOwnerReferences()) == 0
				for _, collection := range []schema.GroupVersionResource{
					{Group: "batch", Version: "v1", Resource: "jobs"}, {Version: "v1", Resource: "pods"},
					{Version: "v1", Resource: "persistentvolumeclaims"}, {Group: "coordination.k8s.io", Version: "v1", Resource: "leases"},
					{Group: "arcade.gobha.me", Version: "v1alpha1", Resource: "gameservers"}, {Group: "arcade.gobha.me", Version: "v1alpha1", Resource: "gamebackups"},
					{Group: "arcade.gobha.me", Version: "v1alpha1", Resource: "gamerestores"}, {Group: "arcade.gobha.me", Version: "v1alpha1", Resource: "gamedestroys"},
					{Group: "arcade.gobha.me", Version: "v1alpha1", Resource: "arcadeoperations"},
				} {
					objects, err := admin.Resource(collection).Namespace(key.Namespace).List(cleanupCtx, metav1.ListOptions{})
					if err != nil {
						leaf = false
						break
					}
					for _, object := range objects.Items {
						for _, owner := range object.GetOwnerReferences() {
							if owner.UID == uid {
								leaf = false
							}
						}
					}
				}
				if !leaf {
					t.Error("refusing unproved cancelled synthetic leaf cleanup")
					continue
				}
			}
			next, _ := ledger.nextDocument()
			next.Entries[slot].State, next.Entries[slot].DeleteResourceVersion = fixtureDeleteAttempted, live.GetResourceVersion()
			if ledger.advance(next) != nil {
				t.Error("native cleanup intent durability refused")
				return
			}
			deleteErr := wire.delete(cleanupCtx, slot)
			if deleteErr != nil && deleteErr != ErrOutcomeUnknown {
				t.Errorf("original native recipe%d deletion refused", slot)
				return
			}
			if wait.PollUntilContextTimeout(cleanupCtx, 100*time.Millisecond, 15*time.Second, true, func(ctx context.Context) (bool, error) {
				live, absent, err := wire.get(ctx, slot)
				if err != nil || !absent && live.GetUID() != uid {
					return false, ErrOwnership
				}
				return absent, nil
			}) != nil {
				t.Errorf("original native recipe%d actual absence unproved", slot)
				return // never replay an uncertain/stale-RV DELETE or add another intent
			}
			next, _ = ledger.nextDocument()
			next.Entries[slot].State = fixtureAbsent
			if ledger.advance(next) != nil {
				t.Error("native original absence durability refused")
				return
			}
		}
	}
	// Cleanup consumes original ledger identity/intent on every outcome. The
	// enclosing exact owned Kind teardown is still required. This active WAL is NOT
	// retired by the test or treated as safe for ordinary installer effects.
	defer cleanup()
	var expected []*unstructured.Unstructured
	for slot := range fixtureCatalog {
		if _, absent, err := wire.get(ctx, slot); err != nil || !absent {
			t.Fatal("fresh exact recipe address absence unproved")
		}
		before := bytes.Clone(ledger.body)
		dry, err := wire.dryRun(ctx, slot)
		if err != nil || dry == nil || dry.GetResourceVersion() != "" {
			t.Fatalf("native closed recipe%d dry-run refused", slot)
		}
		if !bytes.Equal(before, ledger.body) || ledger.document.Entries[slot].OriginalUID != "" || ledger.ackSlot != -1 || ledger.effectSlot != -1 {
			t.Fatal("native preview changed durable ownership or effect capability")
		}
		if _, absent, err := wire.get(ctx, slot); err != nil || !absent {
			t.Fatal("native preview persisted a fixture")
		}
		next, err := ledger.nextDocument()
		if err != nil {
			t.Fatal("native recipe intent unavailable")
		}
		next.Entries[slot].State = fixtureCreateAttempted
		if ledger.advance(next) != nil {
			t.Fatal("native recipe intent durability unavailable")
		}
		live, err := wire.create(ctx, slot) // reliable UID pinned BEFORE any post-ACK check
		if err != nil || live == nil || !nativeFixtureUID(string(live.GetUID())) || ledger.document.Entries[slot].OriginalUID != live.GetUID() {
			t.Fatalf("native recipe%d create unacknowledged: %v", slot, err)
		}
		// Original UID is already durable before whole result acceptance. Never
		// promote returned configuration or a dry-run UID into ownership.
		if ledger.validateResult(slot, fixtureAcknowledgedResult, live, time.Now().UTC()) != nil {
			t.Fatalf("native recipe%d whole acknowledgement shape refused", slot)
		}
		expected = append(expected, live.DeepCopy())
		if captureNativeFixtureShape(ledger, slot, "ack", live) != nil {
			t.Fatal("private synthetic ACK shape capture refused")
		}
	}
	check := func(ctx context.Context, requireSuspended bool) error {
		for slot, want := range expected {
			live, absent, err := wire.get(ctx, slot)
			if err != nil || absent || live.GetUID() != want.GetUID() || live.GetDeletionTimestamp() != nil || !reflect.DeepEqual(live.Object["spec"], want.Object["spec"]) || !reflect.DeepEqual(live.GetLabels(), want.GetLabels()) || !reflect.DeepEqual(live.GetAnnotations(), want.GetAnnotations()) || !reflect.DeepEqual(live.GetOwnerReferences(), want.GetOwnerReferences()) {
				return ErrOwnership
			}
			if live.GetKind() == "Job" {
				var job batchv1.Job
				if decodeServing(live, &job) != nil || job.Status.Active != 0 || job.Status.Succeeded != 0 || job.Status.Failed != 0 {
					return ErrOwnership
				}
				if requireSuspended {
					observed := false
					for _, condition := range job.Status.Conditions {
						if condition.Type == batchv1.JobSuspended && condition.Status == "True" {
							observed = true
						}
					}
					if !observed {
						if ledger.validateResult(slot, fixtureAcknowledgedResult, live, time.Now().UTC()) != nil {
							return ErrOwnership
						}
						return ErrRead
					}
				}
			}
			if live.GetKind() == "PersistentVolumeClaim" {
				phase, _, _ := unstructured.NestedString(live.Object, "status", "phase")
				if phase == "Pending" && ledger.validateResult(slot, fixtureAcknowledgedResult, live, time.Now().UTC()) == nil {
					return ErrRead // bounded native Pending→Lost convergence only
				}
			}
			if ledger.validateResult(slot, fixtureStableResult, live, time.Now().UTC()) != nil {
				return ErrOwnership
			}
			if live.GetKind() == "Pod" {
				for _, field := range []string{"nodeName", "volumes", "initContainers", "ephemeralContainers"} {
					if _, found, _ := unstructured.NestedFieldNoCopy(live.Object, "spec", field); found {
						return ErrOwnership
					}
				}
			}
		}
		pods, err := admin.Resource(schema.GroupVersionResource{Version: "v1", Resource: "pods"}).Namespace(plan.Namespace()).List(ctx, metav1.ListOptions{})
		if err != nil {
			return ErrRead
		}
		for _, pod := range pods.Items {
			if strings.HasPrefix(pod.GetName(), "arcadectl-probe-"+ledger.document.RunID) {
				known := false
				for slot, want := range expected {
					if fixtureCatalog[slot].kind == "Pod" && pod.GetName() == want.GetName() && pod.GetUID() == want.GetUID() {
						known = true
					}
				}
				if !known {
					return ErrOwnership // no Job-created extra probe Pods
				}
			}
		}
		return nil
	}
	if wait.PollUntilContextTimeout(ctx, 200*time.Millisecond, 30*time.Second, true, func(ctx context.Context) (bool, error) {
		err := check(ctx, true)
		if err == ErrRead {
			return false, nil
		}
		return err == nil, err
	}) != nil {
		t.Fatal("actual Job controller did not observe all suspended originals")
	}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if check(ctx, true) != nil {
			t.Fatal("actual Job controller altered/deleted/adopted the inert recipe")
		}
		select {
		case <-ctx.Done():
			t.Fatal("native recipe stability window interrupted")
		case <-time.After(500 * time.Millisecond):
		}
	}
	for slot := range fixtureCatalog {
		live, absent, err := wire.get(ctx, slot)
		if err != nil || absent || ledger.validateResult(slot, fixtureStableResult, live, time.Now().UTC()) != nil || captureNativeFixtureShape(ledger, slot, "live", live) != nil {
			t.Fatal("private synthetic live shape capture refused")
		}
	}
	proveKindCancelledDestroySeed(t, ctx, wire, admin, plan)
	fresh, err := engine.journal.Load(ctx, s.Anchor())
	if err != nil || !bytes.Equal(fresh.Bytes(), s.Bytes()) || fresh.ResourceVersion() != s.ResourceVersion() || engine.fixtureFence(s) != ErrFixtures {
		t.Fatal("native recipe proof changed journal or silently retired its fence")
	}
	t.Log("all ten fixed recipes passed whole dry-run/ACK/stable validation; cancelled synthetic status seed reliably ACKed through original admin wire; schema-valid confirmation dry-run accepted for destroy admin and exactly policy-denied for destroy controller; no confirmation persisted; original cleanup requires actual absence; WAL remains fenced")
}
