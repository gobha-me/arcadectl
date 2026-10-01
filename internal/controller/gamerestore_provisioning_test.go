// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"fmt"
	"testing"
	"time"

	arcadev1alpha1 "github.com/gobha-me/arcadectl/api/v1alpha1"
	"github.com/gobha-me/arcadectl/internal/catalog"
	platformdata "github.com/gobha-me/arcadectl/internal/platform/data"
	platformkube "github.com/gobha-me/arcadectl/internal/platform/kube"
	batchv1 "k8s.io/api/batch/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

type restoreProvisioningFixture struct {
	r           *GameRestoreReconciler
	client      client.Client
	restore     *arcadev1alpha1.GameRestore
	previous    *corev1.PersistentVolumeClaim
	candidate   *corev1.PersistentVolumeClaim
	now         time.Time
	claimWrites int
}

func newRestoreProvisioningFixture(t *testing.T, restart bool, age time.Duration, candidatePresent, bound bool) *restoreProvisioningFixture {
	t.Helper()
	scheme := restoreTestScheme(t)
	for _, add := range []func(*runtime.Scheme) error{batchv1.AddToScheme, coordinationv1.AddToScheme, storagev1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	f := &restoreProvisioningFixture{now: time.Unix(1_700_000_100, 0).UTC()}
	server := controllerTestServer(arcadev1alpha1.DesiredStateStopped)
	server.Generation = 2
	previous := plannedBoundClaim(t, server, "previous-uid")
	selected := exactReattach(previous)
	server.Status.ObservedGeneration = server.Generation
	server.Status.Phase = arcadev1alpha1.PhaseStopped
	server.Status.ObservedData = selected.DeepCopy()
	gameCatalog, err := catalog.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	definition, err := gameCatalog.Get(server.Spec.Game)
	if err != nil {
		t.Fatal(err)
	}
	settingsDigest, err := definition.SettingsDigest(server.Spec.Settings.Raw)
	if err != nil {
		t.Fatal(err)
	}
	path := definition.PersistentPaths[0]
	fence := metav1.NewTime(f.now.Add(-age))
	target := arcadev1alpha1.ExactGameServerReference{
		ExactLocalReference: arcadev1alpha1.ExactLocalReference{Name: server.Name, UID: string(server.UID)},
		Generation:          1, DesiredState: arcadev1alpha1.DesiredStateRunning,
	}
	f.restore = &arcadev1alpha1.GameRestore{
		ObjectMeta: metav1.ObjectMeta{Name: "restore", Namespace: server.Namespace, UID: "restore-uid", Generation: 1, Finalizers: []string{platformkube.RestoreFinalizer}},
		Spec:       arcadev1alpha1.GameRestoreSpec{Target: target, DataOperationRequest: arcadev1alpha1.DataOperationRequest{RestartPolicy: arcadev1alpha1.RestartLeaveStopped}},
	}
	if restart {
		f.restore.Spec.RestartPolicy = arcadev1alpha1.RestartRestorePreviousState
	}
	f.restore.Spec.BackupRef = arcadev1alpha1.ExactLocalReference{Name: "backup", UID: "backup-uid"}
	f.restore.Spec.RepositorySecretRef = arcadev1alpha1.ExactSecretReference{ExactLocalReference: arcadev1alpha1.ExactLocalReference{Name: "repository", UID: "repository-uid"}, ResourceVersion: "42"}
	f.restore.Status.Phase = arcadev1alpha1.DataPhasePreparing
	f.restore.Status.ObservedGeneration = f.restore.Generation
	f.restore.Status.PreflightVerifiedAt = &fence
	f.restore.Status.Fence = &arcadev1alpha1.ColdDataFence{
		GameServer:    arcadev1alpha1.ExactGameServerReference{ExactLocalReference: target.ExactLocalReference, Generation: server.Generation, DesiredState: arcadev1alpha1.DesiredStateStopped},
		EstablishedAt: fence,
	}
	f.restore.Status.PreviousDataIdentity = selected.Identity
	f.restore.Status.PreviousData = []arcadev1alpha1.DataPathIdentity{{Name: path.Name, MountPath: path.MountPath, ClaimRef: selected.Claims[0].ClaimRef}}
	f.restore.Status.Source = &arcadev1alpha1.DataSourceSnapshot{
		GameServer: target, Game: server.Spec.Game, ImageDigest: server.Spec.ImageDigest, SettingsDigest: settingsDigest,
		Paths: f.restore.Status.PreviousData,
	}
	artifactID, err := platformdata.ArtifactID(types.UID(f.restore.Spec.BackupRef.UID))
	if err != nil {
		t.Fatal(err)
	}
	f.restore.Status.Artifact = backupTestArtifact(&arcadev1alpha1.GameBackup{
		ObjectMeta: metav1.ObjectMeta{Name: f.restore.Spec.BackupRef.Name, UID: types.UID(f.restore.Spec.BackupRef.UID)},
		Spec:       arcadev1alpha1.GameBackupSpec{DataOperationRequest: f.restore.Spec.DataOperationRequest},
	}, artifactID)
	f.previous = previous
	candidateIdentity, err := platformdata.RestoreDataIdentity(f.restore.UID)
	if err != nil {
		t.Fatal(err)
	}
	candidateName, err := platformdata.RestoreCandidateID(f.restore.UID, path.Name)
	if err != nil {
		t.Fatal(err)
	}
	candidate := previous.DeepCopy()
	candidate.Name = candidateName
	candidate.UID = "candidate-uid"
	candidate.Spec.VolumeName = ""
	candidate.Status = corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimPending}
	candidate.Labels[platformkube.LabelDataIdentity] = candidateIdentity
	candidate.Labels[platformkube.LabelRestoreUID] = string(f.restore.UID)
	if bound {
		candidate.Spec.VolumeName = "candidate-pv"
		candidate.Status.Phase = corev1.ClaimBound
	}
	f.candidate = candidate
	objects := []client.Object{server, previous, f.restore}
	if candidatePresent {
		objects = append(objects, candidate)
	}
	f.client = fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&arcadev1alpha1.GameRestore{}, &arcadev1alpha1.GameServer{}, &corev1.PersistentVolumeClaim{}).
		WithObjects(objects...).WithInterceptorFuncs(interceptor.Funcs{
		Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			if _, claim := obj.(*corev1.PersistentVolumeClaim); claim {
				f.claimWrites++
				return fmt.Errorf("test forbids any retained claim deletion")
			}
			return c.Delete(ctx, obj, opts...)
		},
		Update: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
			if _, claim := obj.(*corev1.PersistentVolumeClaim); claim {
				f.claimWrites++
			}
			if server, ok := obj.(*arcadev1alpha1.GameServer); ok {
				old := &arcadev1alpha1.GameServer{}
				if err := c.Get(ctx, client.ObjectKeyFromObject(server), old); err != nil {
					return err
				}
				if old.Spec.DesiredState != server.Spec.DesiredState {
					server.Generation = old.Generation + 1 // fake client lacks API-server generation increments.
				}
			}
			return c.Update(ctx, obj, opts...)
		},
		Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
			if _, claim := obj.(*corev1.PersistentVolumeClaim); claim {
				f.claimWrites++
			}
			return c.Patch(ctx, obj, patch, opts...)
		},
	}).Build()
	f.r = &GameRestoreReconciler{Client: f.client, APIReader: f.client, Scheme: scheme, Catalog: gameCatalog, WorkerImage: testWorkerImage,
		Now: func() metav1.Time { return metav1.NewTime(f.now) }}
	return f
}

func (f *restoreProvisioningFixture) reconcile(t *testing.T) *arcadev1alpha1.GameRestore {
	t.Helper()
	if _, err := f.r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(f.restore)}); err != nil {
		t.Fatal(err)
	}
	got := &arcadev1alpha1.GameRestore{}
	if err := f.client.Get(context.Background(), client.ObjectKeyFromObject(f.restore), got); err != nil {
		t.Fatal(err)
	}
	return got
}

func (f *restoreProvisioningFixture) assertRetained(t *testing.T, candidatePresent bool) {
	t.Helper()
	for _, want := range []*corev1.PersistentVolumeClaim{f.previous, f.candidate} {
		got := &corev1.PersistentVolumeClaim{}
		err := f.client.Get(context.Background(), client.ObjectKeyFromObject(want), got)
		if want == f.candidate && !candidatePresent {
			if !apierrors.IsNotFound(err) {
				t.Fatalf("expired provisioning created new storage: %v", err)
			}
			continue
		}
		if err != nil || got.UID != want.UID || len(got.OwnerReferences) != 0 || got.Spec.VolumeName != want.Spec.VolumeName || got.Status.Phase != want.Status.Phase {
			t.Fatalf("retained exact claim %s changed: %#v, %v", want.Name, got, err)
		}
	}
	if f.claimWrites != 0 {
		t.Fatalf("restore attempted %d writes or deletes against retained claims", f.claimWrites)
	}
}

func TestRestoreProvisioningDeadline(t *testing.T) {
	for _, test := range []struct {
		name    string
		age     time.Duration
		present bool
		bound   bool
		failed  bool
	}{
		{name: "just before boundary still waits", age: restoreProvisioningTimeout - time.Second, present: true},
		{name: "exact boundary fails unbound", age: restoreProvisioningTimeout, present: true, failed: true},
		{name: "controller downtime consumes bound", age: 2 * time.Hour, present: true, failed: true},
		{name: "expired absent storage not created", age: 2 * time.Hour, failed: true},
		{name: "bound at deadline proceeds", age: restoreProvisioningTimeout, present: true, bound: true},
		{name: "bound first observed after downtime proceeds", age: 2 * time.Hour, present: true, bound: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newRestoreProvisioningFixture(t, false, test.age, test.present, test.bound)
			got := f.reconcile(t)
			if restoreFailureRecorded(got) != test.failed || got.Status.ActivationStartedAt != nil || got.Status.CandidateVerification != nil {
				t.Fatalf("unexpected provisioning outcome: %#v", got.Status)
			}
			if test.bound && got.Status.Phase != arcadev1alpha1.DataPhaseRunning || !test.bound && got.Status.Phase != arcadev1alpha1.DataPhasePreparing {
				t.Fatalf("unexpected provisioning phase %s", got.Status.Phase)
			}
			if test.failed {
				reason, _ := restoreFailureReason(got)
				if reason != arcadev1alpha1.ReasonStorageUnavailable {
					t.Fatalf("missing actionable storage reason: %s", reason)
				}
				leases := &coordinationv1.LeaseList{}
				if err := f.client.List(context.Background(), leases); err != nil || len(leases.Items) != 2 {
					t.Fatalf("failure released leases before runtime settlement: count=%d err=%v", len(leases.Items), err)
				}
				got = f.reconcile(t)
				if got.Status.Phase != arcadev1alpha1.DataPhaseFailed || got.Status.Runtime == nil || got.Status.Runtime.Phase != arcadev1alpha1.PhaseStopped {
					t.Fatalf("storage failure did not settle previous stopped world: %#v", got.Status)
				}
				f.reconcile(t) // Terminal cleanup releases only owned operation leases.
				if err := f.client.List(context.Background(), leases); err != nil || len(leases.Items) != 0 {
					t.Fatalf("settled failure retained operation leases: %#v, %v", leases.Items, err)
				}
			}
			jobs := &batchv1.JobList{}
			if err := f.client.List(context.Background(), jobs); err != nil || len(jobs.Items) != 0 {
				t.Fatalf("unready storage started external worker: %#v, %v", jobs.Items, err)
			}
			f.assertRetained(t, test.present)
		})
	}
}

func TestRestoreProvisioningFailureRestartsPreviousBeforeRelease(t *testing.T) {
	f := newRestoreProvisioningFixture(t, true, restoreProvisioningTimeout, true, false)
	got := f.reconcile(t)
	if !restoreFailureRecorded(got) {
		t.Fatal("storage timeout was not durably recorded")
	}
	f.reconcile(t) // Journals previous-world recovery intent before changing runtime.
	f.reconcile(t) // Requests exact original-world restart.
	server := &arcadev1alpha1.GameServer{}
	if err := f.client.Get(context.Background(), types.NamespacedName{Namespace: f.restore.Namespace, Name: f.restore.Spec.Target.Name}, server); err != nil {
		t.Fatal(err)
	}
	if server.Spec.DesiredState != arcadev1alpha1.DesiredStateRunning || server.Generation != 3 || !sameDataSelection(server.Status.ObservedData, exactReattach(f.previous)) {
		t.Fatalf("timeout did not restart only the previous world: %#v", server)
	}
	got = f.reconcile(t)
	leases := &coordinationv1.LeaseList{}
	if err := f.client.List(context.Background(), leases); err != nil || len(leases.Items) != 2 || restoreTerminal(got.Status.Phase) {
		t.Fatalf("leases released before exact restart observed: phase=%s leases=%d err=%v", got.Status.Phase, len(leases.Items), err)
	}
	server.Status.ObservedGeneration = server.Generation
	server.Status.Phase = arcadev1alpha1.PhaseReady
	if err := f.client.Status().Update(context.Background(), server); err != nil {
		t.Fatal(err)
	}
	got = f.reconcile(t)
	if got.Status.Phase != arcadev1alpha1.DataPhaseFailed || got.Status.Runtime == nil || got.Status.Runtime.Phase != arcadev1alpha1.PhaseReady || got.Status.ActivationStartedAt != nil {
		t.Fatalf("timeout failed to settle exact previous runtime: %#v", got.Status)
	}
	f.reconcile(t)
	if err := f.client.List(context.Background(), leases); err != nil || len(leases.Items) != 0 {
		t.Fatalf("settled failure did not release operation leases: %v", err)
	}
	f.assertRetained(t, true)
}

func TestRestoreProvisioningRecordedTimeoutCannotRevive(t *testing.T) {
	f := newRestoreProvisioningFixture(t, false, restoreProvisioningTimeout, true, false)
	if !restoreFailureRecorded(f.reconcile(t)) {
		t.Fatal("storage timeout was not recorded")
	}
	candidate := &corev1.PersistentVolumeClaim{}
	if err := f.client.Get(context.Background(), client.ObjectKeyFromObject(f.candidate), candidate); err != nil {
		t.Fatal(err)
	}
	candidate.Spec.VolumeName = "late-candidate-pv"
	if err := f.client.Update(context.Background(), candidate); err != nil {
		t.Fatal(err)
	}
	candidate.Status.Phase = corev1.ClaimBound
	if err := f.client.Status().Update(context.Background(), candidate); err != nil {
		t.Fatal(err)
	}
	got := f.reconcile(t)
	if got.Status.Phase != arcadev1alpha1.DataPhaseFailed || got.Status.CandidateData != nil || got.Status.ActivationStartedAt != nil {
		t.Fatalf("late storage binding revived a recorded timeout: %#v", got.Status)
	}
}
