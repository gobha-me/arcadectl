// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"strings"
	"testing"
	"time"

	arcade "github.com/gobha-me/arcadectl/api/v1alpha1"
	"github.com/gobha-me/arcadectl/internal/catalog"
	platformdata "github.com/gobha-me/arcadectl/internal/platform/data"
	platformkube "github.com/gobha-me/arcadectl/internal/platform/kube"
	batchv1 "k8s.io/api/batch/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type destroyFixture struct {
	r      *GameDestroyReconciler
	client client.Client
	key    types.NamespacedName
	claim  *corev1.PersistentVolumeClaim
	backup *arcade.GameBackup
}

func newDestroyFixture(t *testing.T, retained bool) destroyFixture {
	t.Helper()
	ctx := context.Background()
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{arcade.AddToScheme, corev1.AddToScheme, coordinationv1.AddToScheme, batchv1.AddToScheme, rbacv1.AddToScheme, storagev1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	server := controllerTestServer(arcade.DesiredStateStopped)
	server.Status.Phase = arcade.PhaseStopped
	server.Status.ObservedGeneration = server.Generation
	claim := plannedBoundClaim(t, server, "claim-uid")
	claim.Annotations = map[string]string{platformkube.AnnotationColdBackupUID: "backup-uid"}
	pv := &corev1.PersistentVolume{ObjectMeta: metav1.ObjectMeta{Name: claim.Spec.VolumeName, UID: "pv-uid"}, Spec: corev1.PersistentVolumeSpec{ClaimRef: &corev1.ObjectReference{Namespace: claim.Namespace, Name: claim.Name, UID: claim.UID}}}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "repository", Namespace: server.Namespace, UID: "secret-uid", ResourceVersion: "42"}}
	secretRef := arcade.ExactSecretReference{ExactLocalReference: arcade.ExactLocalReference{Name: secret.Name, UID: string(secret.UID)}, ResourceVersion: secret.ResourceVersion}
	backup := &arcade.GameBackup{ObjectMeta: metav1.ObjectMeta{Name: "backup", Namespace: server.Namespace, UID: "backup-uid", Generation: 1},
		Spec: arcade.GameBackupSpec{DataOperationRequest: arcade.DataOperationRequest{RepositorySecretRef: secretRef, RestartPolicy: arcade.RestartLeaveStopped},
			Source: arcade.ExactGameServerReference{ExactLocalReference: arcade.ExactLocalReference{Name: server.Name, UID: string(server.UID)}, Generation: server.Generation, DesiredState: arcade.DesiredStateStopped}}}
	gameCatalog, err := catalog.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	def, err := gameCatalog.Get(server.Spec.Game)
	if err != nil {
		t.Fatal(err)
	}
	settingsDigest, err := def.SettingsDigest(server.Spec.Settings.Raw)
	if err != nil {
		t.Fatal(err)
	}
	path := def.PersistentPaths[0]
	source := &arcade.DataSourceSnapshot{GameServer: backup.Spec.Source, Game: server.Spec.Game, ImageDigest: server.Spec.ImageDigest, SettingsDigest: settingsDigest,
		Paths: []arcade.DataPathIdentity{{Name: path.Name, MountPath: path.MountPath, ClaimRef: arcade.ExactLocalReference{Name: claim.Name, UID: string(claim.UID)}}}}
	artifactID, err := platformdata.ArtifactID(backup.UID)
	if err != nil {
		t.Fatal(err)
	}
	backup.Status.Phase = arcade.DataPhaseSucceeded
	backup.Status.ObservedGeneration = backup.Generation
	backup.Status.Source = source
	backup.Status.Artifact = backupTestArtifact(backup, artifactID)
	now := metav1.NewTime(time.Unix(1_700_000_100, 0).UTC())
	backup.Status.Fence = &arcade.ColdDataFence{GameServer: backup.Spec.Source, EstablishedAt: now}
	backup.Status.Runtime = &arcade.RuntimeDisposition{GameServer: backup.Spec.Source, Phase: arcade.PhaseStopped, CompletedAt: now}
	selection := exactReattach(claim)
	if !retained {
		server.Status.ObservedData = selection.DeepCopy()
	}
	d := &arcade.GameDestroy{ObjectMeta: metav1.ObjectMeta{Name: "destroy", Namespace: server.Namespace, UID: "destroy-uid", Generation: 1},
		Spec: arcade.GameDestroySpec{Target: arcade.GameDestroyTarget{GameServer: backup.Spec.Source.ExactLocalReference, Game: server.Spec.Game, Data: *selection}, Mode: arcade.DestroyModeVerifiedBackup,
			BackupRef: &arcade.ExactLocalReference{Name: backup.Name, UID: string(backup.UID)}, RepositorySecretRef: &secretRef}}
	objects := []client.Object{claim, pv, secret, backup, d}
	if !retained {
		objects = append(objects, server)
	}
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&arcade.GameDestroy{}, &arcade.GameBackup{}, &arcade.GameServer{}, &corev1.PersistentVolumeClaim{}).WithObjects(objects...).Build()
	r := &GameDestroyReconciler{Client: kubeClient, APIReader: kubeClient, Scheme: scheme, Catalog: gameCatalog, WorkerImage: testWorkerImage, Now: func() metav1.Time { return now }}
	key := client.ObjectKeyFromObject(d)
	if err := kubeClient.Get(ctx, key, d); err != nil {
		t.Fatal(err)
	}
	return destroyFixture{r: r, client: kubeClient, key: key, claim: claim, backup: backup}
}

func (f destroyFixture) destroy(t *testing.T) *arcade.GameDestroy {
	t.Helper()
	d := &arcade.GameDestroy{}
	if err := f.client.Get(context.Background(), f.key, d); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestGameDestroyRetainedWorldGetsExactPreview(t *testing.T) {
	f := newDestroyFixture(t, true)
	req := ctrl.Request{NamespacedName: f.key}
	for i := 0; i < 3; i++ {
		if _, err := f.r.Reconcile(context.Background(), req); err != nil {
			t.Fatal(err)
		}
	}
	d := f.destroy(t)
	if d.Status.Phase != arcade.DestroyPhasePreview || d.Status.Preview == nil || len(d.Status.Preview.Challenge) < 16 || !strings.Contains(d.Status.Preview.RestoreGuidance, "Restore") {
		t.Fatalf("retained preview = %#v", d.Status)
	}
	claim := &corev1.PersistentVolumeClaim{}
	if err := f.client.Get(context.Background(), client.ObjectKeyFromObject(f.claim), claim); err != nil {
		t.Fatalf("preview deleted claim: %v", err)
	}
	lease := &coordinationv1.Lease{}
	if err := f.client.Get(context.Background(), types.NamespacedName{Namespace: d.Namespace, Name: platformkube.DataOperationLeaseName(d.Spec.Target.Data.Identity)}, lease); err == nil {
		t.Fatal("preview acquired destructive lease before confirmation")
	}
}

func TestGameDestroyRejectsLostColdMarkerWithoutDeleting(t *testing.T) {
	f := newDestroyFixture(t, true)
	claim := &corev1.PersistentVolumeClaim{}
	if err := f.client.Get(context.Background(), client.ObjectKeyFromObject(f.claim), claim); err != nil {
		t.Fatal(err)
	}
	delete(claim.Annotations, platformkube.AnnotationColdBackupUID)
	if err := f.client.Update(context.Background(), claim); err != nil {
		t.Fatal(err)
	}
	req := ctrl.Request{NamespacedName: f.key}
	for i := 0; i < 3; i++ {
		if _, err := f.r.Reconcile(context.Background(), req); err != nil {
			t.Fatal(err)
		}
	}
	d := f.destroy(t)
	if d.Status.Phase != arcade.DestroyPhaseFailed || len(d.Status.DeletionJournal) != 0 {
		t.Fatalf("lost cold marker status = %#v", d.Status)
	}
	if err := f.client.Get(context.Background(), client.ObjectKeyFromObject(f.claim), claim); err != nil {
		t.Fatalf("lost marker deleted claim: %v", err)
	}
}

func TestGameDestroyExpiredChallengeDoesNotAcquireLease(t *testing.T) {
	f := newDestroyFixture(t, true)
	ctx := context.Background()
	req := ctrl.Request{NamespacedName: f.key}
	for i := 0; i < 3; i++ {
		if _, err := f.r.Reconcile(ctx, req); err != nil {
			t.Fatal(err)
		}
	}
	d := f.destroy(t)
	if d.Status.Preview == nil {
		t.Fatal("preview missing")
	}
	d.Spec.ConfirmationChallenge = d.Status.Preview.Challenge
	if err := f.client.Update(ctx, d); err != nil {
		t.Fatal(err)
	}
	f.r.Now = func() metav1.Time { return metav1.NewTime(d.Status.Preview.ExpiresAt.Add(time.Second)) }
	if _, err := f.r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	d = f.destroy(t)
	if d.Status.Phase != arcade.DestroyPhaseFailed || len(d.Status.DeletionJournal) != 0 {
		t.Fatalf("expired challenge status = %#v", d.Status)
	}
	lease := &coordinationv1.Lease{}
	if err := f.client.Get(ctx, types.NamespacedName{Namespace: d.Namespace, Name: platformkube.DataOperationLeaseName(d.Spec.Target.Data.Identity)}, lease); err == nil {
		t.Fatal("expired challenge acquired data lease")
	}
	claim := &corev1.PersistentVolumeClaim{}
	if err := f.client.Get(ctx, client.ObjectKeyFromObject(f.claim), claim); err != nil {
		t.Fatalf("expired challenge deleted PVC: %v", err)
	}
}

func TestGameDestroyMountedPodBlocksPreview(t *testing.T) {
	f := newDestroyFixture(t, true)
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "foreign-writer", Namespace: f.claim.Namespace}, Spec: corev1.PodSpec{Volumes: []corev1.Volume{{Name: "world", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: f.claim.Name}}}}}}
	if err := f.client.Create(context.Background(), pod); err != nil {
		t.Fatal(err)
	}
	req := ctrl.Request{NamespacedName: f.key}
	for i := 0; i < 3; i++ {
		if _, err := f.r.Reconcile(context.Background(), req); err != nil {
			t.Fatal(err)
		}
	}
	d := f.destroy(t)
	if d.Status.Phase != arcade.DestroyPhaseFailed || d.Status.Preview != nil {
		t.Fatalf("mounted Pod was allowed: %#v", d.Status)
	}
}

func TestGameDestroyMissingBackupBlocksRetainedWorld(t *testing.T) {
	f := newDestroyFixture(t, true)
	backup := &arcade.GameBackup{}
	if err := f.client.Get(context.Background(), client.ObjectKeyFromObject(f.backup), backup); err != nil {
		t.Fatal(err)
	}
	if err := f.client.Delete(context.Background(), backup); err != nil {
		t.Fatal(err)
	}
	req := ctrl.Request{NamespacedName: f.key}
	for i := 0; i < 3; i++ {
		if _, err := f.r.Reconcile(context.Background(), req); err != nil {
			t.Fatal(err)
		}
	}
	d := f.destroy(t)
	if d.Status.Phase != arcade.DestroyPhaseFailed || d.Status.Preview != nil || len(d.Status.DeletionJournal) != 0 {
		t.Fatalf("missing backup was accepted: %#v", d.Status)
	}
	claim := &corev1.PersistentVolumeClaim{}
	if err := f.client.Get(context.Background(), client.ObjectKeyFromObject(f.claim), claim); err != nil {
		t.Fatalf("missing backup deleted PVC: %v", err)
	}
}

func TestGameDestroyRecreatedServerNameBlocksOriginalWorld(t *testing.T) {
	f := newDestroyFixture(t, true)
	server := controllerTestServer(arcade.DesiredStateStopped)
	server.UID = "recreated-server-uid"
	server.Status.Phase = arcade.PhaseStopped
	server.Status.ObservedGeneration = server.Generation
	if err := f.client.Create(context.Background(), server); err != nil {
		t.Fatal(err)
	}
	req := ctrl.Request{NamespacedName: f.key}
	for i := 0; i < 3; i++ {
		if _, err := f.r.Reconcile(context.Background(), req); err != nil {
			t.Fatal(err)
		}
	}
	d := f.destroy(t)
	if d.Status.Phase != arcade.DestroyPhaseFailed || d.Status.Preview != nil {
		t.Fatalf("reused GameServer name was accepted: %#v", d.Status)
	}
}

func TestGameDestroyJournalPrecedesExactPVCDeleteAndObservesAbsence(t *testing.T) {
	f := newDestroyFixture(t, true)
	ctx := context.Background()
	d := f.destroy(t)
	d.Finalizers = []string{platformkube.DestroyFinalizer}
	if err := f.client.Update(ctx, d); err != nil {
		t.Fatal(err)
	}
	d = f.destroy(t)
	d.Spec.ConfirmationChallenge = "exact-challenge-123456789"
	if err := f.client.Update(ctx, d); err != nil {
		t.Fatal(err)
	}
	d = f.destroy(t)
	d.Status.Phase = arcade.DestroyPhaseDeleting
	d.Status.Preview = &arcade.GameDestroyPreview{Challenge: d.Spec.ConfirmationChallenge, ExpiresAt: metav1.NewTime(f.r.now().Add(time.Minute)), RestoreGuidance: "restore first"}
	d.Status.Verification = &arcade.GameDestroyVerification{BackupRef: *d.Spec.BackupRef, RepositorySecretRef: *d.Spec.RepositorySecretRef,
		ArtifactID: f.backup.Status.Artifact.ID, ManifestDigest: f.backup.Status.Artifact.ManifestDigest, PathCount: 1, VerifiedAt: f.r.now(), ColdAt: f.r.now()}
	if err := f.client.Status().Update(ctx, d); err != nil {
		t.Fatal(err)
	}
	d = f.destroy(t)
	if err := f.r.acquireDataLease(ctx, d); err != nil {
		t.Fatal(err)
	}
	req := ctrl.Request{NamespacedName: f.key}
	if _, err := f.r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	d = f.destroy(t)
	if len(d.Status.DeletionJournal) != 1 || d.Status.DeletionJournal[0].RequestedAt.IsZero() {
		t.Fatalf("no durable journal: %#v", d.Status)
	}
	claim := &corev1.PersistentVolumeClaim{}
	if err := f.client.Get(ctx, client.ObjectKeyFromObject(f.claim), claim); err != nil {
		t.Fatalf("PVC deleted before journal: %v", err)
	}
	if _, err := f.r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	if err := f.client.Get(ctx, client.ObjectKeyFromObject(f.claim), claim); err == nil {
		t.Fatal("exact PVC was not deleted")
	}
	if _, err := f.r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	if _, err := f.r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	d = f.destroy(t)
	if d.Status.Phase != arcade.DestroyPhaseSucceeded || d.Status.DeletionJournal[0].ObservedDeletedAt == nil {
		t.Fatalf("destroy not observed complete: %#v", d.Status)
	}
	lease := &coordinationv1.Lease{}
	if err := f.client.Get(ctx, types.NamespacedName{Namespace: d.Namespace, Name: platformkube.DataOperationLeaseName(d.Spec.Target.Data.Identity)}, lease); err != nil {
		t.Fatalf("lease released before terminal cleanup reconcile: %v", err)
	}
	if _, err := f.r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	if err := f.client.Get(ctx, client.ObjectKeyFromObject(lease), lease); err == nil {
		t.Fatal("terminal destroy retained data lease")
	}
}

func TestGameDestroyRefusesReusedPVCNameAfterJournal(t *testing.T) {
	f := newDestroyFixture(t, true)
	ctx := context.Background()
	d := f.destroy(t)
	d.Finalizers = []string{platformkube.DestroyFinalizer}
	d.Spec.ConfirmationChallenge = "exact-challenge-123456789"
	if err := f.client.Update(ctx, d); err != nil {
		t.Fatal(err)
	}
	d = f.destroy(t)
	d.Status.Phase = arcade.DestroyPhaseDeleting
	d.Status.Preview = &arcade.GameDestroyPreview{Challenge: d.Spec.ConfirmationChallenge, ExpiresAt: metav1.NewTime(f.r.now().Add(time.Minute)), RestoreGuidance: "restore first"}
	d.Status.Verification = &arcade.GameDestroyVerification{BackupRef: *d.Spec.BackupRef, RepositorySecretRef: *d.Spec.RepositorySecretRef, ArtifactID: f.backup.Status.Artifact.ID, ManifestDigest: f.backup.Status.Artifact.ManifestDigest, PathCount: 1, VerifiedAt: f.r.now(), ColdAt: f.r.now()}
	d.Status.DeletionJournal = []arcade.GameDestroyClaimDeletion{{Path: f.claim.Labels[platformkube.LabelDataPath], ClaimRef: arcade.ExactLocalReference{Name: f.claim.Name, UID: string(f.claim.UID)}, RequestedAt: f.r.now()}}
	if err := f.client.Status().Update(ctx, d); err != nil {
		t.Fatal(err)
	}
	d = f.destroy(t)
	if err := f.r.acquireDataLease(ctx, d); err != nil {
		t.Fatal(err)
	}
	if err := f.client.Delete(ctx, f.claim); err != nil {
		t.Fatal(err)
	}
	reused := f.claim.DeepCopy()
	reused.UID = types.UID("replacement-uid")
	reused.ResourceVersion = ""
	if err := f.client.Create(ctx, reused); err != nil {
		t.Fatal(err)
	}
	if _, err := f.r.Reconcile(ctx, ctrl.Request{NamespacedName: f.key}); err != nil {
		t.Fatal(err)
	}
	got := f.destroy(t)
	if got.Status.Phase != arcade.DestroyPhaseDeleting {
		t.Fatalf("reused name advanced phase: %s", got.Status.Phase)
	}
	claim := &corev1.PersistentVolumeClaim{}
	if err := f.client.Get(ctx, client.ObjectKeyFromObject(reused), claim); err != nil || claim.UID != reused.UID {
		t.Fatalf("replacement claim deleted: %#v, %v", claim, err)
	}
}

func TestGameDestroyWorkerLeaseOwnerIsExact(t *testing.T) {
	f := newDestroyFixture(t, true)
	d := f.destroy(t)
	if err := f.r.workerLease(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	lease := &coordinationv1.Lease{}
	key := types.NamespacedName{Namespace: d.Namespace, Name: platformkube.DestroyWorkerLeaseName(d.UID)}
	if err := f.client.Get(context.Background(), key, lease); err != nil {
		t.Fatal(err)
	}
	if len(lease.OwnerReferences) != 1 || lease.OwnerReferences[0].UID != d.UID || lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity != string(d.UID) {
		t.Fatalf("worker lease not pinned: %#v", lease)
	}
	lease.Spec.HolderIdentity = ptr.To("other-destroy")
	if err := f.client.Update(context.Background(), lease); err != nil {
		t.Fatal(err)
	}
	if err := f.r.workerLease(context.Background(), d); err == nil {
		t.Fatal("foreign worker execution was accepted")
	}
}

func TestGameDestroyUncommittedCleanupPreservesUnrelatedDataLease(t *testing.T) {
	for _, action := range []string{"cancel", "delete", "failed"} {
		t.Run(action, func(t *testing.T) {
			f := newDestroyFixture(t, true)
			ctx := context.Background()
			d := f.destroy(t)
			d.Finalizers = []string{platformkube.DestroyFinalizer}
			d.Spec.CancelRequested = action == "cancel"
			if err := f.client.Update(ctx, d); err != nil {
				t.Fatal(err)
			}
			d = f.destroy(t)
			d.Status.Phase = arcade.DestroyPhasePending
			if action == "failed" {
				d.Status.Phase = arcade.DestroyPhaseFailed
			}
			if err := f.client.Status().Update(ctx, d); err != nil {
				t.Fatal(err)
			}
			foreign := &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{
				Name: platformkube.DataOperationLeaseName(d.Spec.Target.Data.Identity), Namespace: d.Namespace, UID: "other-lease",
				Labels: map[string]string{platformkube.LabelManagedBy: platformkube.ManagerName, platformkube.LabelBackupUID: "other-backup"},
			}, Spec: coordinationv1.LeaseSpec{HolderIdentity: ptr.To("other-backup")}}
			if err := f.client.Create(ctx, foreign); err != nil {
				t.Fatal(err)
			}
			if action == "delete" {
				if err := f.client.Delete(ctx, d); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := f.r.Reconcile(ctx, ctrl.Request{NamespacedName: f.key}); err != nil {
				t.Fatalf("unrelated lease blocked %s: %v", action, err)
			}
			if action == "cancel" && f.destroy(t).Status.Phase != arcade.DestroyPhaseCancelled {
				t.Fatal("cancellation did not become terminal")
			}
			if action == "delete" {
				remaining := &arcade.GameDestroy{}
				if err := f.client.Get(ctx, f.key, remaining); err == nil {
					t.Fatal("uncommitted request finalizer remained")
				}
			}
			got := &coordinationv1.Lease{}
			if err := f.client.Get(ctx, client.ObjectKeyFromObject(foreign), got); err != nil || got.UID != foreign.UID || *got.Spec.HolderIdentity != "other-backup" {
				t.Fatalf("unrelated authority changed: %#v, %v", got, err)
			}
		})
	}
}

func TestGameDestroyJobArmPinsExactJobUID(t *testing.T) {
	f := newDestroyFixture(t, true)
	ctx := context.Background()
	d := f.destroy(t)
	if err := f.r.workerLease(ctx, d); err != nil {
		t.Fatal(err)
	}
	job := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: platformkube.DestroyResourceName(d.UID), Namespace: d.Namespace, UID: "job-one"}}
	armed, err := f.r.destroyJobArmed(ctx, d, job)
	if err != nil || armed {
		t.Fatalf("unarmed lease accepted: armed=%v, err=%v", armed, err)
	}
	if err := f.r.armDestroyJob(ctx, d, job); err != nil {
		t.Fatal(err)
	}
	armed, err = f.r.destroyJobArmed(ctx, d, job)
	if err != nil || !armed {
		t.Fatalf("exact Job not armed: armed=%v, err=%v", armed, err)
	}
	other := job.DeepCopy()
	other.UID = "job-two"
	if armed, err = f.r.destroyJobArmed(ctx, d, other); err == nil || armed {
		t.Fatalf("other Job UID accepted: armed=%v, err=%v", armed, err)
	}
}
