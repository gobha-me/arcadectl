// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	arcade "github.com/gobha-me/arcadectl/api/v1alpha1"
	"github.com/gobha-me/arcadectl/internal/operations"
	platformkube "github.com/gobha-me/arcadectl/internal/platform/kube"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func newOperationTest(t *testing.T, action arcade.ArcadeOperationAction, extras ...client.Object) (*ArcadeOperationReconciler, *arcade.ArcadeOperation, *arcade.GameServer) {
	t.Helper()
	server := controllerTestServer(arcade.DesiredStateRunning)
	claim := plannedBoundClaim(t, server, "world-uid")
	data := &arcade.RetainedDataReference{Identity: claim.Labels[platformkube.LabelDataIdentity], Claims: []arcade.RetainedDataClaimReference{{Path: claim.Labels[platformkube.LabelDataPath], ClaimRef: arcade.ExactLocalReference{Name: claim.Name, UID: string(claim.UID)}}}}
	server.Status = arcade.GameServerStatus{ObservedGeneration: server.Generation, ObservedData: data.DeepCopy(), Phase: arcade.PhaseReady,
		Conditions: []metav1.Condition{{Type: arcade.ConditionReady, Status: metav1.ConditionTrue, ObservedGeneration: server.Generation}}}
	base, _ := newTestReconciler(t)
	receipt := &arcade.ArcadeOperation{ObjectMeta: metav1.ObjectMeta{Name: "receipt", Namespace: server.Namespace, UID: "receipt-uid", Generation: 1}, Spec: arcade.ArcadeOperationSpec{Version: "v1", Action: action,
		Request: arcade.OperationRequest{Precondition: fmt.Sprintf("\"server:%s:%d\"", server.UID, server.Generation), ServerName: server.Name,
			Target: &arcade.ExactGameServerReference{ExactLocalReference: arcade.ExactLocalReference{Name: server.Name, UID: string(server.UID)}, Generation: server.Generation, DesiredState: server.Spec.DesiredState}}}}
	objects := []client.Object{receipt, server, claim}
	objects = append(objects, extras...)
	kube := fake.NewClientBuilder().WithScheme(base.Scheme).
		WithStatusSubresource(&arcade.ArcadeOperation{}, &arcade.GameServer{}, &arcade.GameBackup{}, &arcade.GameRestore{}, &arcade.GameDestroy{}, &corev1.PersistentVolumeClaim{}).
		WithObjects(objects...).WithInterceptorFuncs(interceptor.Funcs{
		Create: func(ctx context.Context, c client.WithWatch, object client.Object, opts ...client.CreateOption) error {
			if object.GetUID() == "" {
				object.SetUID(types.UID("created-" + object.GetName()))
			}
			if _, ok := object.(*coordinationv1.Lease); !ok {
				object.SetGeneration(1)
			}
			return c.Create(ctx, object, opts...)
		},
		Patch: func(ctx context.Context, c client.WithWatch, object client.Object, patch client.Patch, opts ...client.PatchOption) error {
			prior := object.DeepCopyObject().(client.Object)
			if err := c.Get(ctx, client.ObjectKeyFromObject(object), prior); err != nil {
				return err
			}
			if err := c.Patch(ctx, object, patch, opts...); err != nil {
				return err
			}
			changed := false
			switch before := prior.(type) {
			case *arcade.GameServer:
				changed = !operationSpecsEqual(before.Spec, object.(*arcade.GameServer).Spec)
			case *arcade.GameDestroy:
				changed = before.Spec.CancelRequested != object.(*arcade.GameDestroy).Spec.CancelRequested || before.Spec.ConfirmationChallenge != object.(*arcade.GameDestroy).Spec.ConfirmationChallenge
			}
			if changed {
				object.SetGeneration(prior.GetGeneration() + 1)
				return c.Update(ctx, object)
			}
			return nil
		},
	}).Build()
	return &ArcadeOperationReconciler{Client: kube, APIReader: kube, Scheme: base.Scheme, Catalog: base.Catalog, Now: func() metav1.Time { return metav1.NewTime(time.Unix(1_800_000_000, 0)) }}, receipt, server
}
func operationTestStep(t *testing.T, r *ArcadeOperationReconciler, o *arcade.ArcadeOperation) *arcade.ArcadeOperation {
	t.Helper()
	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(o)})
	if err != nil {
		t.Fatal(err)
	}
	stored := &arcade.ArcadeOperation{}
	if err := r.Get(context.Background(), client.ObjectKeyFromObject(o), stored); err != nil {
		t.Fatal(err)
	}
	return stored
}
func operationTestPlanned(t *testing.T, r *ArcadeOperationReconciler, o *arcade.ArcadeOperation) *arcade.ArcadeOperation {
	t.Helper()
	for i := 0; i < 8; i++ {
		o = operationTestStep(t, r, o)
		if o.Status.Plan != nil {
			return o
		}
		if operationTerminal(o.Status.Phase) {
			t.Fatalf("planning failed: %#v", o.Status.Failure)
		}
	}
	t.Fatal("plan absent")
	return nil
}
func operationTestGetServer(t *testing.T, r *ArcadeOperationReconciler, server *arcade.GameServer) *arcade.GameServer {
	t.Helper()
	stored := &arcade.GameServer{}
	if err := r.Get(context.Background(), client.ObjectKeyFromObject(server), stored); err != nil {
		t.Fatal(err)
	}
	return stored
}
func operationTestObserve(t *testing.T, r *ArcadeOperationReconciler, server *arcade.GameServer) {
	t.Helper()
	server.Status.ObservedGeneration = server.Generation
	if server.Spec.DesiredState == arcade.DesiredStateStopped {
		server.Status.Phase = arcade.PhaseStopped
	} else {
		server.Status.Phase = arcade.PhaseReady
	}
	server.Status.Conditions = []metav1.Condition{{Type: arcade.ConditionReady, Status: metav1.ConditionTrue, ObservedGeneration: server.Generation}}
	if err := r.Status().Update(context.Background(), server); err != nil {
		t.Fatal(err)
	}
}

func TestArcadeOperationRestartUsesWriteAheadAttributableStopAndStart(t *testing.T) {
	r, o, server := newOperationTest(t, arcade.OperationServerRestart)
	o = operationTestPlanned(t, r, o)
	o = operationTestStep(t, r, o)
	if operationTransition(o, "Stop") == nil || operationTestGetServer(t, r, server).Spec.DesiredState != arcade.DesiredStateRunning {
		t.Fatal("stop was not journaled before mutation")
	}
	o = operationTestStep(t, r, o)
	stopped := operationTestGetServer(t, r, server)
	if stopped.Spec.DesiredState != arcade.DesiredStateStopped || stopped.Generation != 2 || stopped.Annotations[operationStepAnnotation] != "Stop" {
		t.Fatalf("stop: %#v", stopped)
	}
	o = operationTestStep(t, r, o)
	if operationTransition(o, "Start") != nil {
		t.Fatal("restart started before exact stopped observation")
	}
	operationTestObserve(t, r, stopped)
	o = operationTestStep(t, r, o)
	if operationTransition(o, "Start") == nil || operationTestGetServer(t, r, server).Spec.DesiredState != arcade.DesiredStateStopped {
		t.Fatal("start was not journaled before mutation")
	}
	o = operationTestStep(t, r, o)
	running := operationTestGetServer(t, r, server)
	if running.Generation != 3 || running.Spec.DesiredState != arcade.DesiredStateRunning || running.Annotations[operationStepAnnotation] != "Start" {
		t.Fatal("exact start missing")
	}
	lease := &coordinationv1.Lease{}
	if err := r.Get(context.Background(), types.NamespacedName{Namespace: o.Namespace, Name: platformkube.DataOperationLeaseName(o.Status.Plan.Data.Identity)}, lease); err != nil {
		t.Fatal(err)
	}
	if !receiptRuntimeAllowed(context.Background(), r.reader(), running, lease) {
		t.Fatal("exact receipt settlement denied")
	}
	tampered := running.DeepCopy()
	tampered.Spec.ImageDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if receiptRuntimeAllowed(context.Background(), r.reader(), tampered, lease) {
		t.Fatal("changed full spec was authorized")
	}
	operationTestObserve(t, r, running)
	o = operationTestStep(t, r, o)
	if o.Status.Phase != arcade.OperationPhaseSucceeded {
		t.Fatal("restart not settled")
	}
	if !receiptRuntimeAllowed(context.Background(), r.reader(), running, lease) {
		t.Fatal("completed exact Running receipt lost runtime authority before fence release")
	}
	for _, changed := range []*arcade.GameServer{tampered, func() *arcade.GameServer { copy := running.DeepCopy(); copy.UID = "replacement"; return copy }(), func() *arcade.GameServer { copy := running.DeepCopy(); copy.Generation++; return copy }()} {
		if receiptRuntimeAllowed(context.Background(), r.reader(), changed, lease) {
			t.Fatal("completed receipt authorized a changed spec or identity")
		}
	}
	o = operationTestStep(t, r, o)
	if containsOperationFinalizer(o) {
		t.Fatal("terminal receipt fence finalizer retained")
	}
	if err := r.Get(context.Background(), client.ObjectKeyFromObject(lease), &coordinationv1.Lease{}); !apierrors.IsNotFound(err) {
		t.Fatal("terminal receipt fence retained")
	}
}

func TestArcadeOperationWaitsForExactTerminalReceiptFenceCleanup(t *testing.T) {
	for _, phase := range []arcade.ArcadeOperationPhase{arcade.OperationPhaseSucceeded, arcade.OperationPhaseFailed, arcade.OperationPhaseCancelled} {
		t.Run(string(phase), func(t *testing.T) {
			r, next, server := newOperationTest(t, arcade.OperationServerStop)
			next = operationTestPlanned(t, r, next)
			owner := next.DeepCopy()
			owner.Name, owner.UID, owner.ResourceVersion = "prior-receipt", "prior-uid", ""
			owner.Status.Phase = phase
			if err := r.Create(context.Background(), owner); err != nil {
				t.Fatal(err)
			}
			if err := r.acquireOperationLease(context.Background(), owner, server.Name, next.Status.Plan.Data.Identity); err != nil {
				t.Fatal(err)
			}
			lease := &coordinationv1.Lease{}
			key := types.NamespacedName{Namespace: next.Namespace, Name: platformkube.DataOperationLeaseName(next.Status.Plan.Data.Identity)}
			if err := r.Get(context.Background(), key, lease); err != nil {
				t.Fatal(err)
			}
			result, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(next)})
			if err == nil || result.RequeueAfter == 0 {
				t.Fatal("terminal foreign cleanup did not retry")
			}
			stored := &arcade.ArcadeOperation{}
			if err := r.Get(context.Background(), client.ObjectKeyFromObject(next), stored); err != nil {
				t.Fatal(err)
			}
			if operationTerminal(stored.Status.Phase) || stored.Status.Failure != nil || len(stored.Status.Transitions) != 0 || operationTestGetServer(t, r, server).Generation != server.Generation {
				t.Fatal("next receipt failed or mutated before exact cleanup")
			}
			remaining := &coordinationv1.Lease{}
			if err := r.Get(context.Background(), key, remaining); err != nil || remaining.UID != lease.UID || *remaining.Spec.HolderIdentity != string(owner.UID) {
				t.Fatal("foreign terminal fence was adopted or removed")
			}
			operationTestStep(t, r, owner)
			stored = operationTestStep(t, r, stored)
			if operationTransition(stored, "Apply") == nil {
				t.Fatal("new intent did not proceed after exact owner cleanup")
			}
		})
	}
}

func TestArcadeOperationTerminalNativeFenceCleanupRequiresCurrentExactOwner(t *testing.T) {
	for _, kind := range []string{"backup", "restore", "destroy"} {
		for _, variant := range []string{"terminal", "active", "stale", "replacement", "malformed"} {
			t.Run(kind+"/"+variant, func(t *testing.T) {
				r, next, server := newOperationTest(t, arcade.OperationServerStop)
				next = operationTestPlanned(t, r, next)
				identity := next.Status.Plan.Data.Identity
				ownerMeta := metav1.ObjectMeta{Name: "native-owner", Namespace: next.Namespace, UID: "native-owner-uid", Generation: 1}
				status := arcade.DataOperationStatus{ObservedGeneration: 1, Phase: arcade.DataPhaseSucceeded}
				if variant == "active" {
					status.Phase = arcade.DataPhaseRunning
				}
				if variant == "stale" {
					status.ObservedGeneration = 0
				}
				lease := &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Name: platformkube.DataOperationLeaseName(identity), Namespace: next.Namespace, Labels: map[string]string{platformkube.LabelManagedBy: platformkube.ManagerName, platformkube.LabelInstance: server.Name, platformkube.LabelDataIdentity: identity}, Annotations: map[string]string{}}, Spec: coordinationv1.LeaseSpec{HolderIdentity: ptrString(string(ownerMeta.UID))}}
				var owner client.Object
				switch kind {
				case "backup":
					ownerMeta.Finalizers = []string{platformkube.BackupFinalizer}
					owner = &arcade.GameBackup{ObjectMeta: ownerMeta, Spec: arcade.GameBackupSpec{Source: arcade.ExactGameServerReference{ExactLocalReference: arcade.ExactLocalReference{Name: server.Name, UID: string(server.UID)}}}, Status: arcade.GameBackupStatus{DataOperationStatus: status}}
					lease.Labels[platformkube.LabelBackupUID], lease.Annotations[platformkube.AnnotationBackupName] = string(ownerMeta.UID), ownerMeta.Name
				case "restore":
					ownerMeta.Finalizers = []string{platformkube.RestoreFinalizer}
					owner = &arcade.GameRestore{ObjectMeta: ownerMeta, Spec: arcade.GameRestoreSpec{Target: arcade.ExactGameServerReference{ExactLocalReference: arcade.ExactLocalReference{Name: server.Name, UID: string(server.UID)}}}, Status: arcade.GameRestoreStatus{DataOperationStatus: status, PreviousDataIdentity: identity}}
					lease.Labels[platformkube.LabelRestoreUID], lease.Annotations[platformkube.AnnotationRestoreName] = string(ownerMeta.UID), ownerMeta.Name
				case "destroy":
					ownerMeta.Finalizers = []string{platformkube.DestroyFinalizer}
					phase := arcade.DestroyPhaseSucceeded
					if variant == "active" {
						phase = arcade.DestroyPhaseVerifying
					}
					owner = &arcade.GameDestroy{ObjectMeta: ownerMeta, Spec: arcade.GameDestroySpec{Target: arcade.GameDestroyTarget{GameServer: arcade.ExactLocalReference{Name: server.Name, UID: string(server.UID)}, Data: *next.Status.Plan.Data.DeepCopy()}}, Status: arcade.GameDestroyStatus{ObservedGeneration: status.ObservedGeneration, Phase: phase}}
					lease.Labels[platformkube.LabelDestroyUID], lease.Annotations[platformkube.AnnotationDestroyName] = string(ownerMeta.UID), ownerMeta.Name
				}
				if variant == "replacement" {
					owner.SetUID("replaced-owner")
				}
				if variant == "malformed" {
					lease.OwnerReferences = []metav1.OwnerReference{{UID: "foreign-owner"}}
				}
				if err := r.Create(context.Background(), owner); err != nil {
					t.Fatal(err)
				}
				if err := r.Create(context.Background(), lease); err != nil {
					t.Fatal(err)
				}
				_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(next)})
				stored := &arcade.ArcadeOperation{}
				if getErr := r.Get(context.Background(), client.ObjectKeyFromObject(next), stored); getErr != nil {
					t.Fatal(getErr)
				}
				if variant == "terminal" {
					if err == nil || operationTerminal(stored.Status.Phase) || stored.Status.Failure != nil {
						t.Fatal("exact current terminal native cleanup failed next receipt")
					}
				} else if err != nil || stored.Status.Phase != arcade.OperationPhaseFailed || stored.Status.Failure.Code != "operation_conflict" {
					t.Fatal("active, stale or unproven native owner bypassed fence conflict")
				}
				remaining := &coordinationv1.Lease{}
				if err := r.Get(context.Background(), client.ObjectKeyFromObject(lease), remaining); err != nil || remaining.UID != lease.UID || *remaining.Spec.HolderIdentity != *lease.Spec.HolderIdentity {
					t.Fatal("foreign native fence removed or adopted")
				}
			})
		}
	}
}

func TestArcadeOperationRejectsUnattributedNPlusOne(t *testing.T) {
	r, o, server := newOperationTest(t, arcade.OperationServerStop)
	o = operationTestPlanned(t, r, o)
	o = operationTestStep(t, r, o)
	other := operationTestGetServer(t, r, server)
	other.Generation++
	other.Spec.DesiredState = arcade.DesiredStateStopped
	if err := r.Update(context.Background(), other); err != nil {
		t.Fatal(err)
	}
	o = operationTestStep(t, r, o)
	if o.Status.Phase != arcade.OperationPhaseFailed || o.Status.Failure.Code != "target_changed" {
		t.Fatalf("foreign mutation adopted: %#v", o.Status)
	}
}

func TestArcadeOperationLeaseInterlocksNativeDataOperation(t *testing.T) {
	r, o, server := newOperationTest(t, arcade.OperationServerStop)
	o = operationTestPlanned(t, r, o)
	lease := &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Name: platformkube.DataOperationLeaseName(o.Status.Plan.Data.Identity), Namespace: o.Namespace, UID: "native-lease"}, Spec: coordinationv1.LeaseSpec{HolderIdentity: ptrString("native-backup")}}
	if err := r.Create(context.Background(), lease); err != nil {
		t.Fatal(err)
	}
	o = operationTestStep(t, r, o)
	if o.Status.Phase != arcade.OperationPhaseFailed || o.Status.Failure.Code != "operation_conflict" || operationTestGetServer(t, r, server).Spec.DesiredState != arcade.DesiredStateRunning {
		t.Fatal("native fence not respected")
	}
	operationTestStep(t, r, o)
	if err := r.Get(context.Background(), client.ObjectKeyFromObject(lease), &coordinationv1.Lease{}); err != nil {
		t.Fatal("foreign lease deleted")
	}
}
func ptrString(value string) *string { return &value }

func TestArcadeOperationDecommissionPersistsCompleteWorldBeforeUIDDelete(t *testing.T) {
	r, o, server := newOperationTest(t, arcade.OperationServerDecommission)
	o = operationTestPlanned(t, r, o)
	if o.Status.RetainedWorld == nil || o.Status.RetainedWorld.Target.GameServer.UID != string(server.UID) || len(o.Status.RetainedWorld.Target.Data.Claims) != 1 {
		t.Fatal("retained original identity not persisted")
	}
	digest, err := operations.RetainedSnapshotDigest(o.Status.RetainedWorld.Target)
	if err != nil || digest != o.Status.RetainedWorld.SnapshotDigest {
		t.Fatal("retained snapshot digest invalid")
	}
	o = operationTestStep(t, r, o)
	o = operationTestStep(t, r, o)
	stopped := operationTestGetServer(t, r, server)
	operationTestObserve(t, r, stopped)
	o = operationTestStep(t, r, o)
	if err := r.Get(context.Background(), client.ObjectKeyFromObject(server), &arcade.GameServer{}); !apierrors.IsNotFound(err) {
		t.Fatal("original not deleted")
	}
	replacement := server.DeepCopy()
	replacement.UID = "replacement-uid"
	replacement.ResourceVersion = ""
	if err := r.Create(context.Background(), replacement); err != nil {
		t.Fatal(err)
	}
	o = operationTestStep(t, r, o)
	if o.Status.Phase != arcade.OperationPhaseSucceeded {
		t.Fatal("original absence not settled")
	}
	if operationTestGetServer(t, r, replacement).UID != replacement.UID {
		t.Fatal("same-name replacement mutated")
	}
	pvc := &corev1.PersistentVolumeClaim{}
	ref := o.Status.RetainedWorld.Target.Data.Claims[0].ClaimRef
	if err := r.Get(context.Background(), types.NamespacedName{Namespace: o.Namespace, Name: ref.Name}, pvc); err != nil || string(pvc.UID) != ref.UID {
		t.Fatal("retained claim changed")
	}
}

type operationAmbiguousCreate struct {
	client.Client
	failed bool
}

func (c *operationAmbiguousCreate) Create(ctx context.Context, object client.Object, opts ...client.CreateOption) error {
	err := c.Client.Create(ctx, object, opts...)
	if _, ok := object.(*arcade.GameRestore); ok && err == nil && !c.failed {
		c.failed = true
		return errors.New("ambiguous-response-canary")
	}
	return err
}
func TestArcadeOperationNativeChildReplaysAmbiguousCreateButRejectsForeignName(t *testing.T) {
	for _, foreign := range []bool{false, true} {
		t.Run(fmt.Sprint(foreign), func(t *testing.T) {
			r, o, server := newOperationTest(t, arcade.OperationWorldRestore)
			secret := arcade.ExactSecretReference{ExactLocalReference: arcade.ExactLocalReference{Name: "repository", UID: "secret-uid"}, ResourceVersion: "42"}
			backupRef := arcade.ExactLocalReference{Name: "backup", UID: "backup-uid"}
			now := r.now()
			backup := &arcade.GameBackup{ObjectMeta: metav1.ObjectMeta{Name: backupRef.Name, Namespace: o.Namespace, UID: types.UID(backupRef.UID)}, Spec: arcade.GameBackupSpec{DataOperationRequest: arcade.DataOperationRequest{RepositorySecretRef: secret}},
				Status: arcade.GameBackupStatus{DataOperationStatus: arcade.DataOperationStatus{ObservedGeneration: 1, Phase: arcade.DataPhaseSucceeded, Source: &arcade.DataSourceSnapshot{Game: server.Spec.Game, Paths: []arcade.DataPathIdentity{{Name: "world"}}},
					Artifact: &arcade.BackupArtifact{PathCount: 1, Verification: arcade.ArtifactVerification{Result: arcade.VerificationVerified, VerifiedAt: &now}, Provenance: arcade.ArtifactProvenance{BackupRef: backupRef, RepositorySecretRef: secret}}}}}
			if err := r.Create(context.Background(), backup); err != nil {
				t.Fatal(err)
			}
			o.Spec.Request.Restore = &arcade.OperationRestoreInput{BackupRef: backupRef, RestartPolicy: arcade.RestartLeaveStopped}
			if err := r.Update(context.Background(), o); err != nil {
				t.Fatal(err)
			}
			o = operationTestPlanned(t, r, o)
			if foreign {
				child := &arcade.GameRestore{ObjectMeta: metav1.ObjectMeta{Name: operations.ChildName(o.UID, "GameRestore"), Namespace: o.Namespace, UID: "foreign"}}
				if err := r.Create(context.Background(), child); err != nil {
					t.Fatal(err)
				}
			} else {
				r.Client = &operationAmbiguousCreate{Client: r.Client}
			}
			_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(o)})
			if !foreign && (err == nil || err.Error() == "ambiguous-response-canary") {
				t.Fatalf("unbounded ambiguity response: %v", err)
			}
			o = operationTestStep(t, r, o)
			if foreign {
				if o.Status.Phase != arcade.OperationPhaseFailed || o.Status.Failure.Code != "child_changed" {
					t.Fatal("foreign child adopted")
				}
				return
			}
			if o.Status.Child == nil || o.Status.Child.UID == "" || o.Status.Child.Generation != 1 {
				t.Fatal("exact existing child was not recorded")
			}
			list := &arcade.GameRestoreList{}
			if err := r.List(context.Background(), list); err != nil || len(list.Items) != 1 || len(list.Items[0].OwnerReferences) != 0 {
				t.Fatal("replay created duplicate or GC-owned child")
			}
		})
	}
}

func TestArcadeOperationRetainedSelectorRequiresSucceededOriginalSnapshot(t *testing.T) {
	r, o, _ := newOperationTest(t, arcade.OperationServerDecommission)
	o = operationTestPlanned(t, r, o)
	selector := &arcade.OperationRetainedWorldSelector{DecommissionOperationRef: arcade.ExactLocalReference{Name: o.Name, UID: string(o.UID)}, SnapshotDigest: o.Status.RetainedWorld.SnapshotDigest}
	if _, err := r.retainedOperationWorld(context.Background(), o.Namespace, selector); err == nil {
		t.Fatal("nonterminal decommission admitted retained world")
	}
	if err := r.operationStatus(context.Background(), o, arcade.OperationPhaseSucceeded, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := r.retainedOperationWorld(context.Background(), o.Namespace, selector); err != nil {
		t.Fatal(err)
	}
	bad := *selector
	bad.DecommissionOperationRef.UID = "replacement"
	if _, err := r.retainedOperationWorld(context.Background(), o.Namespace, &bad); err == nil {
		t.Fatal("replacement decommission admitted")
	}
	bad = *selector
	bad.SnapshotDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if _, err := r.retainedOperationWorld(context.Background(), o.Namespace, &bad); err == nil {
		t.Fatal("changed snapshot admitted")
	}
}

func newOperationDestroyCommandTest(t *testing.T, action arcade.ArcadeOperationAction) (*ArcadeOperationReconciler, *arcade.ArcadeOperation, *arcade.GameDestroy) {
	t.Helper()
	r, o, server := newOperationTest(t, arcade.OperationServerStop)
	claim := plannedBoundClaim(t, server, "world-uid")
	target := arcade.GameDestroyTarget{GameServer: arcade.ExactLocalReference{Name: server.Name, UID: string(server.UID)}, Game: server.Spec.Game,
		Data: arcade.RetainedDataReference{Identity: claim.Labels[platformkube.LabelDataIdentity], Claims: []arcade.RetainedDataClaimReference{{Path: "world", ClaimRef: arcade.ExactLocalReference{Name: claim.Name, UID: string(claim.UID)}}}}}
	digest, err := operations.RetainedSnapshotDigest(target)
	if err != nil {
		t.Fatal(err)
	}
	backup := arcade.ExactLocalReference{Name: "backup", UID: "backup-uid"}
	secret := arcade.ExactSecretReference{ExactLocalReference: arcade.ExactLocalReference{Name: "repository", UID: "secret-uid"}, ResourceVersion: "42"}
	parent := &arcade.ArcadeOperation{ObjectMeta: metav1.ObjectMeta{Name: "parent", Namespace: o.Namespace, UID: "parent-uid", Generation: 1}, Spec: arcade.ArcadeOperationSpec{Version: "v1", Action: arcade.OperationWorldDestroyPreview},
		Status: arcade.ArcadeOperationStatus{Phase: arcade.OperationPhaseAwaitingConfirmation, Plan: &arcade.OperationPlan{BackupRef: &backup, RepositorySecretRef: &secret},
			Child:         &arcade.OperationChildReference{Kind: "GameDestroy", ExactLocalReference: arcade.ExactLocalReference{Name: "destroy", UID: "destroy-uid"}, Generation: 1},
			RetainedWorld: &arcade.OperationRetainedWorld{Target: target, SnapshotDigest: digest}}}
	expires := metav1.NewTime(r.now().Time.Add(15 * time.Minute))
	destroy := &arcade.GameDestroy{ObjectMeta: metav1.ObjectMeta{Name: "destroy", Namespace: o.Namespace, UID: "destroy-uid", Generation: 1,
		Labels: map[string]string{operationReceiptUIDLabel: string(parent.UID)}, Annotations: map[string]string{operationReceiptNameAnnotation: parent.Name}},
		Spec:   arcade.GameDestroySpec{Target: target, Mode: arcade.DestroyModeVerifiedBackup, BackupRef: &backup, RepositorySecretRef: &secret},
		Status: arcade.GameDestroyStatus{ObservedGeneration: 1, Phase: arcade.DestroyPhasePreview, Preview: &arcade.GameDestroyPreview{Challenge: "abcdefghijklmnop", ExpiresAt: expires}}}
	if err := r.Create(context.Background(), parent); err != nil {
		t.Fatal(err)
	}
	if err := r.Create(context.Background(), destroy); err != nil {
		t.Fatal(err)
	}
	o.Spec.Action = action
	o.Spec.Request = arcade.OperationRequest{Precondition: "\"operation:parent-uid:1\"", DestroyCommand: &arcade.OperationDestroyCommand{ParentOperationRef: arcade.ExactLocalReference{Name: parent.Name, UID: string(parent.UID)}, DestroyRef: arcade.ExactLocalReference{Name: destroy.Name, UID: string(destroy.UID)}}}
	if action == arcade.OperationWorldDestroyConfirm {
		o.Spec.Request.DestroyCommand.Challenge = destroy.Status.Preview.Challenge
	}
	if err := r.Update(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	return r, o, destroy
}

func TestArcadeOperationDestroyConfirmRequiresExactParentChildAndCommandAttribution(t *testing.T) {
	for _, variant := range []string{"valid", "child-replacement", "parent-replacement", "expired", "foreign-confirm"} {
		t.Run(variant, func(t *testing.T) {
			r, o, destroy := newOperationDestroyCommandTest(t, arcade.OperationWorldDestroyConfirm)
			switch variant {
			case "child-replacement":
				o.Spec.Request.DestroyCommand.DestroyRef.UID = "replacement"
				if err := r.Update(context.Background(), o); err != nil {
					t.Fatal(err)
				}
			case "parent-replacement":
				o.Spec.Request.Precondition = "\"operation:replacement:1\""
				o.Spec.Request.DestroyCommand.ParentOperationRef.UID = "replacement"
				if err := r.Update(context.Background(), o); err != nil {
					t.Fatal(err)
				}
			case "expired":
				destroy.Status.Preview.ExpiresAt = metav1.NewTime(r.now().Time.Add(-time.Second))
				if err := r.Status().Update(context.Background(), destroy); err != nil {
					t.Fatal(err)
				}
			case "foreign-confirm":
				destroy.Spec.ConfirmationChallenge = destroy.Status.Preview.Challenge
				if err := r.Update(context.Background(), destroy); err != nil {
					t.Fatal(err)
				}
			}
			for i := 0; i < 8 && !operationTerminal(o.Status.Phase); i++ {
				o = operationTestStep(t, r, o)
				if variant == "valid" {
					current := &arcade.GameDestroy{}
					if err := r.Get(context.Background(), client.ObjectKeyFromObject(destroy), current); err != nil {
						t.Fatal(err)
					}
					if current.Spec.ConfirmationChallenge != "" && current.Status.ObservedGeneration != current.Generation {
						current.Status.Phase = arcade.DestroyPhaseVerifying
						current.Status.ObservedGeneration = current.Generation
						if err := r.Status().Update(context.Background(), current); err != nil {
							t.Fatal(err)
						}
					}
				}
			}
			if variant == "valid" {
				if o.Status.Phase != arcade.OperationPhaseSucceeded {
					t.Fatalf("confirm did not settle: %#v", o.Status)
				}
				stored := &arcade.GameDestroy{}
				if err := r.Get(context.Background(), client.ObjectKeyFromObject(destroy), stored); err != nil {
					t.Fatal(err)
				}
				if stored.Spec.ConfirmationChallenge != o.Spec.Request.DestroyCommand.Challenge || stored.Annotations[operationConfirmAnnotation] != string(o.UID) {
					t.Fatal("confirm patch omitted exact command marker")
				}
			} else if o.Status.Phase != arcade.OperationPhaseFailed {
				t.Fatalf("unsafe confirmation accepted: %#v", o.Status)
			}
		})
	}
}

func TestArcadeOperationDestroyCancelWaitsNativeSettlementAndRejectsDeletion(t *testing.T) {
	for _, deleting := range []bool{false, true} {
		t.Run(fmt.Sprint(deleting), func(t *testing.T) {
			r, o, destroy := newOperationDestroyCommandTest(t, arcade.OperationWorldDestroyCancel)
			if deleting {
				destroy.Status.Phase = arcade.DestroyPhaseDeleting
				destroy.Status.DeletionJournal = []arcade.GameDestroyClaimDeletion{{Path: "world"}}
				if err := r.Status().Update(context.Background(), destroy); err != nil {
					t.Fatal(err)
				}
			}
			for i := 0; i < 6; i++ {
				o = operationTestStep(t, r, o)
				if operationTerminal(o.Status.Phase) {
					break
				}
			}
			if deleting {
				if o.Status.Phase != arcade.OperationPhaseFailed || o.Status.Failure.Code != "too_late" {
					t.Fatal("deleting child cancellation admitted")
				}
				return
			}
			if operationTerminal(o.Status.Phase) {
				t.Fatal("cancel completed before native settlement")
			}
			stored := &arcade.GameDestroy{}
			if err := r.Get(context.Background(), client.ObjectKeyFromObject(destroy), stored); err != nil {
				t.Fatal(err)
			}
			if !stored.Spec.CancelRequested || stored.Annotations[operationCancelAnnotation] != string(o.UID) {
				t.Fatal("cancel did not atomically record command")
			}
			stored.Status.Phase = arcade.DestroyPhaseCancelled
			stored.Status.ObservedGeneration = stored.Generation
			if err := r.Status().Update(context.Background(), stored); err != nil {
				t.Fatal(err)
			}
			o = operationTestStep(t, r, o)
			if o.Status.Phase != arcade.OperationPhaseSucceeded {
				t.Fatal("native cancellation not observed")
			}
		})
	}
}

func TestArcadeOperationBlockedNativeChildStaysNonterminal(t *testing.T) {
	r, o, _ := newOperationTest(t, arcade.OperationServerStop)
	o.Status.Phase = arcade.OperationPhaseRunning
	if err := r.Status().Update(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if err := r.mirrorDataOperation(context.Background(), o, arcade.DataOperationStatus{ObservedGeneration: 1, Phase: arcade.DataPhaseBlocked, Conditions: []metav1.Condition{{Reason: arcade.ReasonOperationConflict}}}, 1); err != nil {
		t.Fatal(err)
	}
	stored := &arcade.ArcadeOperation{}
	if err := r.Get(context.Background(), client.ObjectKeyFromObject(o), stored); err != nil {
		t.Fatal(err)
	}
	if stored.Status.Phase != arcade.OperationPhaseRunning || stored.Status.Failure == nil || !stored.Status.Failure.Retryable || stored.Status.Failure.Code != "operation_conflict" {
		t.Fatal("blocked native work falsely terminal or unbounded guidance")
	}
}

func TestArcadeOperationCreateUsesFrozenSpecAndNeverOwnsServer(t *testing.T) {
	for _, foreign := range []bool{false, true} {
		t.Run(fmt.Sprint(foreign), func(t *testing.T) {
			r, o, baseline := newOperationTest(t, arcade.OperationServerCreate)
			intent, err := operations.ServerIntent(baseline.Spec)
			if err != nil {
				t.Fatal(err)
			}
			o.Spec.Request = arcade.OperationRequest{Precondition: "absent", ServerName: "newfactory",
				Create: &arcade.OperationCreateInput{Game: intent.Game, DesiredState: arcade.DesiredStateStopped, Compute: intent.Compute, Storage: intent.Storage, SettingsJSON: intent.SettingsJSON},
				Image:  &arcade.OperationImageInput{Digest: baseline.Spec.ImageDigest, Resolution: arcade.OperationImageResolution{Repository: "ghcr.io/gobha-me/arcadectl-factorio", Digest: baseline.Spec.ImageDigest, ResolvedAt: r.now(), ResolverVersion: "digest-v1"}}}
			if err := r.Update(context.Background(), o); err != nil {
				t.Fatal(err)
			}
			o = operationTestPlanned(t, r, o)
			if foreign {
				replacement := baseline.DeepCopy()
				replacement.Name = o.Spec.Request.ServerName
				replacement.UID = "foreign-uid"
				replacement.ResourceVersion = ""
				if err := r.Create(context.Background(), replacement); err != nil {
					t.Fatal(err)
				}
			}
			o = operationTestStep(t, r, o)
			if foreign {
				if o.Status.Phase != arcade.OperationPhaseFailed || o.Status.Failure.Code != "child_changed" {
					t.Fatal("foreign server adopted")
				}
				return
			}
			o = operationTestStep(t, r, o)
			if o.Status.Child == nil || o.Status.Child.Kind != "GameServer" {
				t.Fatal("created exact server reference absent")
			}
			server := &arcade.GameServer{}
			if err := r.Get(context.Background(), types.NamespacedName{Namespace: o.Namespace, Name: o.Status.Child.Name}, server); err != nil {
				t.Fatal(err)
			}
			if len(server.OwnerReferences) != 0 || server.Spec.DesiredState != arcade.DesiredStateStopped || server.Spec.ImageDigest != baseline.Spec.ImageDigest {
				t.Fatal("create intent or no-GC boundary changed")
			}
			claim := plannedBoundClaim(t, server, "new-world-uid")
			if err := r.Create(context.Background(), claim); err != nil {
				t.Fatal(err)
			}
			server.Status.ObservedData = &arcade.RetainedDataReference{Identity: claim.Labels[platformkube.LabelDataIdentity], Claims: []arcade.RetainedDataClaimReference{{Path: "world", ClaimRef: arcade.ExactLocalReference{Name: claim.Name, UID: string(claim.UID)}}}}
			operationTestObserve(t, r, server)
			o = operationTestStep(t, r, o)
			if o.Status.Phase != arcade.OperationPhaseSucceeded {
				t.Fatal("created stopped server not observed")
			}
			operationTestStep(t, r, o)
			if err := r.Get(context.Background(), client.ObjectKeyFromObject(server), &arcade.GameServer{}); err != nil {
				t.Fatal("terminal receipt cleanup deleted server")
			}
		})
	}
}

type operationMetadataOnlyReader struct {
	client.Reader
	secret metav1.ObjectMeta
	reads  int
}

func (r *operationMetadataOnlyReader) Get(ctx context.Context, key client.ObjectKey, object client.Object, opts ...client.GetOption) error {
	if _, ok := object.(*corev1.Secret); ok {
		return errors.New("typed Secret data read is forbidden")
	}
	if metadata, ok := object.(*metav1.PartialObjectMetadata); ok && metadata.GroupVersionKind() == corev1.SchemeGroupVersion.WithKind("Secret") {
		r.reads++
		metadata.ObjectMeta = *r.secret.DeepCopy()
		return nil
	}
	return r.Reader.Get(ctx, key, object, opts...)
}
func TestArcadeOperationBackupFreezesOnlySecretMetadataOnce(t *testing.T) {
	r, o, _ := newOperationTest(t, arcade.OperationWorldBackup)
	o.Spec.Request.Backup = &arcade.OperationBackupInput{RepositorySecretName: "repository", RestartPolicy: arcade.RestartLeaveStopped}
	if err := r.Update(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	reader := &operationMetadataOnlyReader{Reader: r.APIReader, secret: metav1.ObjectMeta{Name: "repository", Namespace: o.Namespace, UID: "secret-uid", ResourceVersion: "42"}}
	r.APIReader = reader
	o = operationTestPlanned(t, r, o)
	if reader.reads != 1 || o.Status.Plan.RepositorySecretRef.UID != "secret-uid" || o.Status.Plan.RepositorySecretRef.ResourceVersion != "42" {
		t.Fatal("Secret metadata resolution not exact")
	}
	reader.secret.UID = "replacement-uid"
	reader.secret.ResourceVersion = "99"
	o = operationTestStep(t, r, o)
	o = operationTestStep(t, r, o)
	child := &arcade.GameBackup{}
	if err := r.Get(context.Background(), types.NamespacedName{Namespace: o.Namespace, Name: operations.ChildName(o.UID, "GameBackup")}, child); err != nil {
		t.Fatal(err)
	}
	if reader.reads != 1 || child.Spec.RepositorySecretRef.UID != "secret-uid" || child.Spec.RepositorySecretRef.ResourceVersion != "42" || !sameDataSelection(child.Spec.SourceData, o.Status.Plan.Data) {
		t.Fatal("native backup followed replacement Secret or data")
	}
}

func TestArcadeOperationExpiredAdmissionDoesNotCancelAdmittedWork(t *testing.T) {
	r, o, _ := newOperationTest(t, arcade.OperationServerStop)
	o.Spec.Admission.CredentialExpiresAt = metav1.NewTime(r.now().Time.Add(-time.Hour))
	if err := r.Update(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	o = operationTestPlanned(t, r, o)
	if o.Status.Plan == nil {
		t.Fatal("already admitted receipt re-authenticated")
	}
}

func TestArcadeOperationImageResolutionMatchesOnlyCatalogProvenance(t *testing.T) {
	for _, variant := range []string{"digest", "version", "foreign-repository", "foreign-tag", "unsupported-version"} {
		t.Run(variant, func(t *testing.T) {
			r, o, server := newOperationTest(t, arcade.OperationServerUpdate)
			image := &arcade.OperationImageInput{Digest: server.Spec.ImageDigest, Resolution: arcade.OperationImageResolution{Repository: "ghcr.io/gobha-me/arcadectl-factorio", Digest: server.Spec.ImageDigest, ResolvedAt: r.now(), ResolverVersion: "digest-v1"}}
			if variant != "digest" && variant != "foreign-repository" {
				image.Digest = ""
				image.Version = "2.0.73"
				image.Resolution.Tag = "2.0.73"
				image.Resolution.ResolverVersion = "registry-v1"
			}
			switch variant {
			case "foreign-repository":
				image.Resolution.Repository = "example.org/untrusted/game"
			case "foreign-tag":
				image.Resolution.Tag = "latest"
			case "unsupported-version":
				image.Version = "latest"
			}
			o.Spec.Request.Image = image
			if err := r.Update(context.Background(), o); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 5 && o.Status.Plan == nil && !operationTerminal(o.Status.Phase); i++ {
				o = operationTestStep(t, r, o)
			}
			if variant == "digest" || variant == "version" {
				if o.Status.Plan == nil || o.Status.Plan.ServerIntent.ImageDigest != image.Resolution.Digest {
					t.Fatal("frozen adapter-approved resolution denied")
				}
			} else if o.Status.Phase != arcade.OperationPhaseFailed || o.Status.Failure.Code != "validation_failed" {
				t.Fatalf("foreign provenance accepted: %#v", o.Status)
			}
		})
	}
}

type operationFailingReader struct {
	client.Reader
	kind, name string
	nth, reads int
}

func (r *operationFailingReader) Get(ctx context.Context, key client.ObjectKey, object client.Object, opts ...client.GetOption) error {
	kind := ""
	switch object.(type) {
	case *arcade.GameServer:
		kind = "server"
	case *arcade.ArcadeOperation:
		kind = "receipt"
	case *arcade.GameBackup:
		kind = "backup"
	case *arcade.GameDestroy:
		kind = "destroy"
	case *corev1.PersistentVolumeClaim:
		kind = "pvc"
	case *metav1.PartialObjectMetadata:
		kind = "secret"
	}
	if kind == r.kind && (r.name == "" || r.name == key.Name) {
		r.reads++
		if r.nth == 0 || r.reads >= r.nth {
			return errors.New("transient-api-credential-canary")
		}
	}
	return r.Reader.Get(ctx, key, object, opts...)
}
func TestArcadeOperationTransientReadsNeverFailReceiptOrStartEffects(t *testing.T) {
	for _, stage := range []string{"server", "pvc", "secret", "backup", "retained", "create-retained", "parent", "destroy", "destroy-pvc"} {
		t.Run(stage, func(t *testing.T) {
			r, o, server := newOperationTest(t, arcade.OperationServerStop)
			reader := &operationFailingReader{Reader: r.APIReader, kind: stage}
			switch stage {
			case "secret":
				o.Spec.Action = arcade.OperationWorldBackup
				o.Spec.Request.Backup = &arcade.OperationBackupInput{RepositorySecretName: "repository", RestartPolicy: arcade.RestartLeaveStopped}
			case "backup":
				o.Spec.Action = arcade.OperationWorldRestore
				o.Spec.Request.Restore = &arcade.OperationRestoreInput{BackupRef: arcade.ExactLocalReference{Name: "backup", UID: "backup-uid"}, RestartPolicy: arcade.RestartLeaveStopped}
			case "retained":
				selector := &arcade.OperationRetainedWorldSelector{DecommissionOperationRef: arcade.ExactLocalReference{Name: "prior", UID: "prior-uid"}, SnapshotDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
				o.Spec.Action = arcade.OperationWorldDestroyPreview
				o.Spec.Request = arcade.OperationRequest{Precondition: "\"retained:prior-uid:" + selector.SnapshotDigest + "\"", Destroy: &arcade.OperationDestroyInput{BackupRef: arcade.ExactLocalReference{Name: "backup", UID: "backup-uid"}, RetainedWorld: selector}}
				reader.kind, reader.name = "receipt", "prior"
			case "create-retained":
				o.Spec.Action = arcade.OperationServerCreate
				o.Spec.Request = arcade.OperationRequest{Precondition: "absent", ServerName: "newfactory", Create: &arcade.OperationCreateInput{Game: server.Spec.Game, DesiredState: arcade.DesiredStateStopped, Compute: server.Spec.Compute, Storage: server.Spec.Storage, SettingsJSON: string(server.Spec.Settings.Raw),
					RetainedWorld: &arcade.OperationRetainedWorldSelector{DecommissionOperationRef: arcade.ExactLocalReference{Name: "prior", UID: "prior-uid"}, SnapshotDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},
					Image: &arcade.OperationImageInput{Digest: server.Spec.ImageDigest, Resolution: arcade.OperationImageResolution{Repository: "ghcr.io/gobha-me/arcadectl-factorio", Digest: server.Spec.ImageDigest, ResolvedAt: r.now(), ResolverVersion: "digest-v1"}}}
				reader.kind, reader.name = "receipt", "prior"
			case "parent", "destroy":
				r, o, _ = newOperationDestroyCommandTest(t, arcade.OperationWorldDestroyConfirm)
				reader.Reader = r.APIReader
				if stage == "parent" {
					reader.kind, reader.name = "receipt", "parent"
				}
			case "destroy-pvc":
				o.Spec.Action = arcade.OperationWorldDestroyPreview
				backupRef := arcade.ExactLocalReference{Name: "backup", UID: "backup-uid"}
				o.Spec.Request.Destroy = &arcade.OperationDestroyInput{BackupRef: backupRef}
				secret := arcade.ExactSecretReference{ExactLocalReference: arcade.ExactLocalReference{Name: "repository", UID: "secret-uid"}, ResourceVersion: "42"}
				now := r.now()
				claim := plannedBoundClaim(t, server, "world-uid")
				backup := &arcade.GameBackup{ObjectMeta: metav1.ObjectMeta{Name: "backup", Namespace: o.Namespace, UID: types.UID(backupRef.UID)}, Spec: arcade.GameBackupSpec{DataOperationRequest: arcade.DataOperationRequest{RepositorySecretRef: secret, RestartPolicy: arcade.RestartLeaveStopped}, Source: *o.Spec.Request.Target},
					Status: arcade.GameBackupStatus{DataOperationStatus: arcade.DataOperationStatus{ObservedGeneration: 1, Phase: arcade.DataPhaseSucceeded, Source: &arcade.DataSourceSnapshot{Game: server.Spec.Game, Paths: []arcade.DataPathIdentity{{Name: "world", ClaimRef: arcade.ExactLocalReference{Name: claim.Name, UID: string(claim.UID)}}}}, Runtime: &arcade.RuntimeDisposition{Phase: arcade.PhaseStopped, GameServer: arcade.ExactGameServerReference{ExactLocalReference: arcade.ExactLocalReference{Name: server.Name, UID: string(server.UID)}, Generation: 2, DesiredState: arcade.DesiredStateStopped}},
						Artifact: &arcade.BackupArtifact{PathCount: 1, Verification: arcade.ArtifactVerification{Result: arcade.VerificationVerified, VerifiedAt: &now}, Provenance: arcade.ArtifactProvenance{BackupRef: backupRef, RepositorySecretRef: secret}}}}}
				if err := r.Create(context.Background(), backup); err != nil {
					t.Fatal(err)
				}
				reader.kind, reader.nth = "pvc", 2
			}
			if err := r.Update(context.Background(), o); err != nil {
				t.Fatal(err)
			}
			r.APIReader = reader
			retried := false
			for i := 0; i < 6; i++ {
				_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(o)})
				if err != nil {
					retried = true
					if strings.Contains(err.Error(), "credential-canary") {
						t.Fatal("raw API error escaped")
					}
				}
			}
			stored := &arcade.ArcadeOperation{}
			if err := r.Client.Get(context.Background(), client.ObjectKeyFromObject(o), stored); err != nil {
				t.Fatal(err)
			}
			if !retried || operationTerminal(stored.Status.Phase) || stored.Status.Plan != nil || stored.Status.Child != nil || len(stored.Status.Transitions) != 0 || stored.Status.Failure != nil {
				t.Fatalf("ambiguous read persisted failure/effect intent: %#v", stored.Status)
			}
			leases := &coordinationv1.LeaseList{}
			if err := r.List(context.Background(), leases); err != nil || len(leases.Items) != 0 {
				t.Fatal("read failure acquired world authority")
			}
			restores := &arcade.GameRestoreList{}
			if err := r.List(context.Background(), restores); err != nil || len(restores.Items) != 0 {
				t.Fatal("read failure created native restore")
			}
			original := operationTestGetServer(t, r, server)
			if original.Generation != server.Generation || original.Spec.DesiredState != server.Spec.DesiredState {
				t.Fatal("read failure mutated source")
			}
		})
	}
}

func TestArcadeOperationCreateStorageFailureRemainsLeasedWithBoundedGuidance(t *testing.T) {
	for _, stage := range []string{"missing", "unbound", "collision", "aged-missing"} {
		t.Run(stage, func(t *testing.T) {
			r, o, baseline := newOperationTest(t, arcade.OperationServerCreate)
			o.Spec.Request = arcade.OperationRequest{Precondition: "absent", ServerName: "newfactory", Create: &arcade.OperationCreateInput{Game: baseline.Spec.Game, DesiredState: arcade.DesiredStateStopped, Compute: baseline.Spec.Compute, Storage: baseline.Spec.Storage, SettingsJSON: string(baseline.Spec.Settings.Raw)},
				Image: &arcade.OperationImageInput{Digest: baseline.Spec.ImageDigest, Resolution: arcade.OperationImageResolution{Repository: "ghcr.io/gobha-me/arcadectl-factorio", Digest: baseline.Spec.ImageDigest, ResolvedAt: r.now(), ResolverVersion: "digest-v1"}}}
			if err := r.Update(context.Background(), o); err != nil {
				t.Fatal(err)
			}
			o = operationTestPlanned(t, r, o)
			o = operationTestStep(t, r, o)
			o = operationTestStep(t, r, o)
			server := &arcade.GameServer{}
			if err := r.Get(context.Background(), types.NamespacedName{Namespace: o.Namespace, Name: o.Status.Child.Name}, server); err != nil {
				t.Fatal(err)
			}
			server.Status.Phase = arcade.PhaseFailed
			server.Status.ObservedGeneration = server.Generation
			if stage == "aged-missing" {
				server.Status.Phase = arcade.PhasePending
				old := metav1.NewTime(r.now().Time.Add(-16 * time.Minute))
				o.Status.StartedAt = &old
				if err := r.Status().Update(context.Background(), o); err != nil {
					t.Fatal(err)
				}
			}
			if err := r.Status().Update(context.Background(), server); err != nil {
				t.Fatal(err)
			}
			if stage == "unbound" || stage == "collision" {
				claim := plannedBoundClaim(t, server, "new-world-uid")
				if stage == "unbound" {
					claim.Status.Phase = corev1.ClaimPending
					claim.Spec.VolumeName = ""
				} else {
					claim.Labels[platformkube.LabelDataIdentity] = "foreign-world"
				}
				if err := r.Create(context.Background(), claim); err != nil {
					t.Fatal(err)
				}
			}
			o = operationTestStep(t, r, o)
			if o.Status.Phase != arcade.OperationPhaseRunning || o.Status.Failure == nil || o.Status.Failure.Code != "api_unavailable" || !o.Status.Failure.Retryable {
				t.Fatalf("missing storage lost progress guidance or falsely terminal: %#v", o.Status)
			}
			identity, err := platformkube.DataIdentity(server.UID)
			if err != nil {
				t.Fatal(err)
			}
			lease := &coordinationv1.Lease{}
			if err := r.Get(context.Background(), types.NamespacedName{Namespace: o.Namespace, Name: platformkube.DataOperationLeaseName(identity)}, lease); err != nil || !operationLeaseMatches(lease, o, server.Name, identity) {
				t.Fatal("unsettled create lost exact fence")
			}
			if operationTestGetServer(t, r, server).Generation != 1 {
				t.Fatal("storage failure changed native intent")
			}
		})
	}
}

func TestArcadeOperationNeverMirrorsStaleNativeCompletionOrPreview(t *testing.T) {
	for _, phase := range []arcade.DataOperationPhase{arcade.DataPhaseSucceeded, arcade.DataPhaseCancelled, arcade.DataPhaseFailed} {
		t.Run("data-"+string(phase), func(t *testing.T) {
			r, o, _ := newOperationTest(t, arcade.OperationServerStop)
			o.Status.Phase = arcade.OperationPhaseRunning
			if err := r.Status().Update(context.Background(), o); err != nil {
				t.Fatal(err)
			}
			if err := r.mirrorDataOperation(context.Background(), o, arcade.DataOperationStatus{ObservedGeneration: 1, Phase: phase}, 2); err != nil {
				t.Fatal(err)
			}
			stored := &arcade.ArcadeOperation{}
			if err := r.Get(context.Background(), client.ObjectKeyFromObject(o), stored); err != nil {
				t.Fatal(err)
			}
			if operationTerminal(stored.Status.Phase) || stored.Status.Failure == nil || !stored.Status.Failure.Retryable {
				t.Fatal("stale native terminal status settled receipt")
			}
		})
	}
	for _, phase := range []arcade.GameDestroyPhase{arcade.DestroyPhasePreview, arcade.DestroyPhaseSucceeded, arcade.DestroyPhaseCancelled, arcade.DestroyPhaseFailed} {
		t.Run("destroy-"+string(phase), func(t *testing.T) {
			r, o, destroy := newOperationDestroyCommandTest(t, arcade.OperationWorldDestroyConfirm)
			o.Status.Phase = arcade.OperationPhaseAwaitingConfirmation
			o.Status.DestroyPreview = destroy.Status.Preview.DeepCopy()
			if err := r.Status().Update(context.Background(), o); err != nil {
				t.Fatal(err)
			}
			destroy.Generation = 2
			destroy.Status.ObservedGeneration = 1
			destroy.Status.Phase = phase
			if err := r.mirrorDestroyOperation(context.Background(), o, destroy); err != nil {
				t.Fatal(err)
			}
			stored := &arcade.ArcadeOperation{}
			if err := r.Get(context.Background(), client.ObjectKeyFromObject(o), stored); err != nil {
				t.Fatal(err)
			}
			if stored.Status.Phase != arcade.OperationPhaseRunning || stored.Status.DestroyPreview != nil || stored.Status.Failure == nil || !stored.Status.Failure.Retryable {
				t.Fatal("stale destroy observation was exposed as current")
			}
		})
	}
}

func TestArcadeOperationCancelWaitsObservedCurrentChildGeneration(t *testing.T) {
	r, o, destroy := newOperationDestroyCommandTest(t, arcade.OperationWorldDestroyCancel)
	o = operationTestPlanned(t, r, o)
	o = operationTestStep(t, r, o)
	o = operationTestStep(t, r, o)
	current := &arcade.GameDestroy{}
	if err := r.Get(context.Background(), client.ObjectKeyFromObject(destroy), current); err != nil {
		t.Fatal(err)
	}
	current.Status.Phase = arcade.DestroyPhaseCancelled
	current.Status.ObservedGeneration = current.Generation - 1
	if err := r.Status().Update(context.Background(), current); err != nil {
		t.Fatal(err)
	}
	o = operationTestStep(t, r, o)
	if operationTerminal(o.Status.Phase) {
		t.Fatal("stale Cancelled phase settled command")
	}
	current.Status.ObservedGeneration = current.Generation
	if err := r.Status().Update(context.Background(), current); err != nil {
		t.Fatal(err)
	}
	o = operationTestStep(t, r, o)
	if o.Status.Phase != arcade.OperationPhaseSucceeded {
		t.Fatal("current native cancellation did not settle")
	}
}

func TestArcadeOperationBackupPlanningRejectsStaleSucceededObservation(t *testing.T) {
	r, o, _ := newOperationTest(t, arcade.OperationWorldRestore)
	ref := arcade.ExactLocalReference{Name: "backup", UID: "backup-uid"}
	now := r.now()
	secret := arcade.ExactSecretReference{ExactLocalReference: arcade.ExactLocalReference{Name: "repository", UID: "secret-uid"}, ResourceVersion: "42"}
	backup := &arcade.GameBackup{ObjectMeta: metav1.ObjectMeta{Name: ref.Name, Namespace: o.Namespace, UID: types.UID(ref.UID), Generation: 1}, Spec: arcade.GameBackupSpec{DataOperationRequest: arcade.DataOperationRequest{RepositorySecretRef: secret}},
		Status: arcade.GameBackupStatus{DataOperationStatus: arcade.DataOperationStatus{ObservedGeneration: 0, Phase: arcade.DataPhaseSucceeded, Source: &arcade.DataSourceSnapshot{Paths: []arcade.DataPathIdentity{{Name: "world"}}}, Artifact: &arcade.BackupArtifact{PathCount: 1, Verification: arcade.ArtifactVerification{Result: arcade.VerificationVerified, VerifiedAt: &now}, Provenance: arcade.ArtifactProvenance{BackupRef: ref, RepositorySecretRef: secret}}}}}
	if err := r.Create(context.Background(), backup); err != nil {
		t.Fatal(err)
	}
	plan := &arcade.OperationPlan{}
	if err := r.planOperationBackup(context.Background(), o, plan, ref); err == nil || plan.BackupRef != nil || plan.RepositorySecretRef != nil {
		t.Fatal("stale succeeded backup bound to new native child")
	}
}

func TestArcadeOperationDestroyFreshObservationClearsStaleGuidance(t *testing.T) {
	r, o, destroy := newOperationDestroyCommandTest(t, arcade.OperationWorldDestroyConfirm)
	o.Status.Phase = arcade.OperationPhaseRunning
	o.Status.Failure = operationFailure("api_unavailable")
	o.Status.Failure.Retryable = true
	o.Status.DestroyPreview = destroy.Status.Preview.DeepCopy()
	if err := r.Status().Update(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if err := r.mirrorDestroyOperation(context.Background(), o, destroy); err != nil {
		t.Fatal(err)
	}
	stored := &arcade.ArcadeOperation{}
	if err := r.Get(context.Background(), client.ObjectKeyFromObject(o), stored); err != nil {
		t.Fatal(err)
	}
	if stored.Status.Phase != arcade.OperationPhaseAwaitingConfirmation || stored.Status.Failure != nil || stored.Status.DestroyPreview == nil {
		t.Fatal("fresh preview retained stale guidance")
	}
}

func TestArcadeOperationFreshNativeChildStartsNeutralUntilObservationSlow(t *testing.T) {
	for _, kind := range []string{"data", "destroy"} {
		t.Run(kind, func(t *testing.T) {
			r, o, _ := newOperationTest(t, arcade.OperationServerStop)
			o.Status.Phase = arcade.OperationPhaseRunning
			now := r.now()
			o.Status.StartedAt = &now
			if err := r.Status().Update(context.Background(), o); err != nil {
				t.Fatal(err)
			}
			mirror := func(receipt *arcade.ArcadeOperation) error {
				if kind == "data" {
					return r.mirrorDataOperation(context.Background(), receipt, arcade.DataOperationStatus{}, 1)
				}
				return r.mirrorDestroyOperation(context.Background(), receipt, &arcade.GameDestroy{ObjectMeta: metav1.ObjectMeta{Generation: 1}})
			}
			if err := mirror(o); err != nil {
				t.Fatal(err)
			}
			stored := &arcade.ArcadeOperation{}
			if err := r.Get(context.Background(), client.ObjectKeyFromObject(o), stored); err != nil {
				t.Fatal(err)
			}
			if stored.Status.Phase != arcade.OperationPhaseRunning || stored.Status.Failure != nil {
				t.Fatal("normal child admission lag reported as failure")
			}
			old := metav1.NewTime(r.now().Time.Add(-16 * time.Minute))
			stored.Status.StartedAt = &old
			if err := r.Status().Update(context.Background(), stored); err != nil {
				t.Fatal(err)
			}
			if err := mirror(stored); err != nil {
				t.Fatal(err)
			}
			if err := r.Get(context.Background(), client.ObjectKeyFromObject(o), stored); err != nil {
				t.Fatal(err)
			}
			if operationTerminal(stored.Status.Phase) || stored.Status.Failure == nil || !stored.Status.Failure.Retryable {
				t.Fatal("slow child observation omitted safe bounded guidance")
			}
		})
	}
}

func TestArcadeOperationConfirmCannotUseStalePreviewChallenge(t *testing.T) {
	r, o, destroy := newOperationDestroyCommandTest(t, arcade.OperationWorldDestroyConfirm)
	destroy.Spec.CancelRequested = true
	destroy.Generation = 2
	destroy.Status.ObservedGeneration = 1
	if err := r.Update(context.Background(), destroy); err != nil {
		t.Fatal(err)
	}
	o = operationTestPlanned(t, r, o)
	o = operationTestStep(t, r, o)
	o = operationTestStep(t, r, o)
	stored := &arcade.GameDestroy{}
	if err := r.Get(context.Background(), client.ObjectKeyFromObject(destroy), stored); err != nil {
		t.Fatal(err)
	}
	if operationTerminal(o.Status.Phase) || stored.Spec.ConfirmationChallenge != "" || stored.Annotations[operationConfirmAnnotation] != "" {
		t.Fatal("stale preview challenge mutated native child or falsely settled")
	}
}
