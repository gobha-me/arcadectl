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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
)

// Certification of the pure fixed recipes against real native controllers,
// ONLY within targetKindFixture's original disposable cluster. SDK effects and
// test WAL instrumentation are not the missing production guarded transport,
// whole-result validator, cleanup recovery or WAL retirement implementation.
func proveKindAdmissionFixtureRecipes(t *testing.T, parent context.Context, config *rest.Config, engine *Engine, s *installstate.Snapshot, plan *installrender.Plan) {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 4*time.Minute)
	defer cancel()
	ledger, err := engine.prepareFixtureLedger(ctx, s)
	if err != nil {
		t.Fatal("owned native recipe ledger unavailable")
	}
	defer ledger.close()
	admin, err := dynamic.NewForConfig(config)
	if err != nil {
		t.Fatal("owned recipe client unavailable")
	}
	actor := func(account string) dynamic.Interface {
		t.Helper()
		c := rest.CopyConfig(config)
		c.Impersonate = rest.ImpersonationConfig{UserName: "system:serviceaccount:" + plan.Namespace() + ":" + account}
		client, err := dynamic.NewForConfig(c)
		if err != nil {
			t.Fatal("original recipe actor unavailable")
		}
		return client
	}
	destroyAdmin, destroyController := actor(destroyAdministratorActor.account()), actor(destroyControllerActor.account())
	resource := func(client dynamic.Interface, slot int) dynamic.ResourceInterface {
		key := ledger.document.Entries[slot].Key
		gv, err := schema.ParseGroupVersion(key.APIVersion)
		if err != nil {
			t.Fatal("fixed recipe group unavailable")
		}
		plural := map[string]string{"Job": "jobs", "Pod": "pods", "PersistentVolumeClaim": "persistentvolumeclaims", "GameDestroy": "gamedestroys"}[key.Kind]
		if plural == "" {
			t.Fatal("fixed recipe route unavailable")
		}
		return client.Resource(gv.WithResource(plural)).Namespace(key.Namespace)
	}
	type original struct {
		slot int
		uid  types.UID
	}
	var originals []original
	cleanup := func() {
		t.Helper()
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cleanupCancel()
		// Reverse recipe order removes every acknowledged Pod before its Job.
		// No name/nonce discovery supplies a missing CREATE acknowledgement.
		absent := make([]bool, len(fixtureCatalog))
		for i := len(originals) - 1; i >= 0; i-- {
			original := originals[i]
			if fixtureCatalog[original.slot].kind == "Job" && !absent[original.slot+1] {
				t.Error("refusing Job cleanup without its original worker's actual absence")
				continue
			}
			var client dynamic.Interface = admin
			if original.slot == fixtureRetainedPVC {
				client = destroyController // fixed original role, not a live label
			}
			address := resource(client, original.slot)
			key := ledger.document.Entries[original.slot].Key
			live, err := address.Get(cleanupCtx, key.Name, metav1.GetOptions{})
			if apierrors.IsNotFound(err) {
				absent[original.slot] = true
				continue
			}
			if err != nil || live.GetUID() != original.uid || !fixtureRV(live.GetResourceVersion()) {
				t.Error("refusing replaced/unproved native recipe cleanup")
				continue
			}
			uid, rv := original.uid, live.GetResourceVersion()
			foreground := metav1.DeletePropagationForeground
			options := metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &rv}, PropagationPolicy: &foreground}
			if original.slot == fixtureCancelledDestroy {
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
				background := metav1.DeletePropagationBackground
				options.PropagationPolicy = &background
			}
			if key.Kind == "Pod" {
				// Exact disposable scheduling-gated, unassigned Pods have no
				// running process to drain. Do not confuse their default thirty-
				// second deletion grace with failed actual-absence evidence.
				zero := int64(0)
				options.GracePeriodSeconds = &zero
			}
			if address.Delete(cleanupCtx, key.Name, options) != nil {
				t.Errorf("original native recipe%d deletion refused", original.slot)
				continue
			}
			if wait.PollUntilContextTimeout(cleanupCtx, 100*time.Millisecond, 15*time.Second, true, func(ctx context.Context) (bool, error) {
				live, err := address.Get(ctx, key.Name, metav1.GetOptions{})
				if apierrors.IsNotFound(err) {
					return true, nil
				}
				if err != nil || live.GetUID() != original.uid {
					return false, ErrOwnership
				}
				return false, nil
			}) != nil {
				t.Errorf("original native recipe%d actual absence unproved", original.slot)
			} else {
				absent[original.slot] = true
			}
		}
	}
	// Cleanup runs on every outcome, independently of the closed ledger. The
	// enclosing owned Kind teardown is still required. This active WAL is NOT
	// retired by the test or treated as safe for ordinary installer effects.
	defer cleanup()
	var expected []*unstructured.Unstructured
	for slot := range fixtureCatalog {
		o, err := ledger.object(slot)
		if err != nil {
			t.Fatalf("native fixed recipe%d unavailable", slot)
		}
		address := resource(admin, slot)
		if slot == fixtureCancelledDestroy {
			address = resource(destroyAdmin, slot)
		}
		if _, err := address.Get(ctx, o.GetName(), metav1.GetOptions{}); !apierrors.IsNotFound(err) {
			t.Fatal("fresh exact recipe address absence unproved")
		}
		dry, err := address.Create(ctx, o.DeepCopy(), metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}, FieldManager: "arcadectl-installer", FieldValidation: "Strict"})
		if err != nil || dry == nil || dry.GetResourceVersion() != "" {
			t.Fatalf("native closed recipe%d dry-run rejected: %v", slot, err)
		}
		if !reflect.DeepEqual(dry.Object["spec"], o.Object["spec"]) || !reflect.DeepEqual(dry.GetLabels(), o.GetLabels()) || !reflect.DeepEqual(dry.GetAnnotations(), o.GetAnnotations()) || !reflect.DeepEqual(dry.GetOwnerReferences(), o.GetOwnerReferences()) {
			t.Fatalf("native recipe%d dry-run changed closed shape; closed=%v native=%v", slot, o.Object["spec"], dry.Object["spec"])
		}
		next, err := ledger.nextDocument()
		if err != nil {
			t.Fatal("native recipe intent unavailable")
		}
		next.Entries[slot].State = fixtureCreateAttempted
		if ledger.advance(next) != nil {
			t.Fatal("native recipe intent durability unavailable")
		}
		live, err := address.Create(ctx, o, metav1.CreateOptions{FieldManager: "arcadectl-installer", FieldValidation: "Strict"})
		if err != nil || live == nil || !receiptUID.MatchString(string(live.GetUID())) {
			t.Fatalf("native recipe%d create unacknowledged: %v", slot, err)
		}
		originals = append(originals, original{slot: slot, uid: live.GetUID()}) // pin BEFORE validating shape
		next, _ = ledger.nextDocument()
		next.Entries[slot].State, next.Entries[slot].OriginalUID = fixtureOriginal, live.GetUID()
		if ledger.advance(next) != nil {
			t.Fatal("native recipe acknowledgement durability unavailable")
		}
		// Compare both native specs to the closed constructor, never promote a
		// returned dry-run/live spec to desired configuration. Persistent whole
		// metadata/status validators remain a separate obligation.
		if !reflect.DeepEqual(dry.Object["spec"], o.Object["spec"]) || !reflect.DeepEqual(live.Object["spec"], o.Object["spec"]) || !reflect.DeepEqual(live.GetLabels(), o.GetLabels()) || !reflect.DeepEqual(live.GetAnnotations(), o.GetAnnotations()) || !reflect.DeepEqual(live.GetOwnerReferences(), o.GetOwnerReferences()) {
			t.Fatalf("native recipe%d acknowledgement desired shape drifted; closed=%v native=%v", slot, o.Object["spec"], live.Object["spec"])
		}
		expected = append(expected, live.DeepCopy())
	}
	check := func(ctx context.Context, requireSuspended bool) error {
		for slot, want := range expected {
			live, err := resource(admin, slot).Get(ctx, want.GetName(), metav1.GetOptions{})
			if err != nil || live.GetUID() != want.GetUID() || live.GetDeletionTimestamp() != nil || !reflect.DeepEqual(live.Object["spec"], want.Object["spec"]) || !reflect.DeepEqual(live.GetLabels(), want.GetLabels()) || !reflect.DeepEqual(live.GetAnnotations(), want.GetAnnotations()) || !reflect.DeepEqual(live.GetOwnerReferences(), want.GetOwnerReferences()) {
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
						return ErrRead
					}
				}
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
	fresh, err := engine.journal.Load(ctx, s.Anchor())
	if err != nil || !bytes.Equal(fresh.Bytes(), s.Bytes()) || fresh.ResourceVersion() != s.ResourceVersion() || engine.fixtureFence(s) != ErrFixtures {
		t.Fatal("native recipe proof changed journal or silently retired its fence")
	}
	t.Log("all ten fixed recipes accepted; actual Job controller suspended, manual gated Pod owners/specs unchanged for30s; WAL remains fenced")
}
