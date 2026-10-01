// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	arcade "github.com/gobha-me/arcadectl/api/v1alpha1"
	"github.com/gobha-me/arcadectl/internal/platform/game"
	platformkube "github.com/gobha-me/arcadectl/internal/platform/kube"
	"github.com/gobha-me/arcadectl/internal/restoreworker"
	batchv1 "k8s.io/api/batch/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// The fake API does not allocate Job UIDs, run Job controllers, enforce PVC
// delete preconditions, or garbage-collect dependent Pods. These tests model
// those external actions explicitly rather than treating fake-client deletion
// as evidence of real Kubernetes behavior.
type destroyDeleteProbe struct {
	client.Client
	beforeDelete func(context.Context, *corev1.PersistentVolumeClaim, *client.DeleteOptions) error
	claims       []string
}

func (c *destroyDeleteProbe) Delete(ctx context.Context, object client.Object, options ...client.DeleteOption) error {
	claim, ok := object.(*corev1.PersistentVolumeClaim)
	if !ok {
		return c.Client.Delete(ctx, object, options...)
	}
	deleteOptions := &client.DeleteOptions{}
	deleteOptions.ApplyOptions(options)
	c.claims = append(c.claims, claim.Name)
	if c.beforeDelete != nil {
		if err := c.beforeDelete(ctx, claim, deleteOptions); err != nil {
			return err
		}
	}
	return c.Client.Delete(ctx, object, options...)
}

func prepareDestroyDeleting(t *testing.T, f destroyFixture) *arcade.GameDestroy {
	t.Helper()
	ctx := context.Background()
	d := f.destroy(t)
	d.Finalizers = []string{platformkube.DestroyFinalizer}
	d.Spec.ConfirmationChallenge = "exact-challenge-123456789"
	if err := f.client.Update(ctx, d); err != nil {
		t.Fatal(err)
	}
	d = f.destroy(t)
	d.Status.Phase = arcade.DestroyPhaseDeleting
	d.Status.Preview = &arcade.GameDestroyPreview{Challenge: d.Spec.ConfirmationChallenge, ExpiresAt: metav1.NewTime(f.r.now().Add(time.Minute)), RestoreGuidance: "Restore into fresh claims before destruction"}
	d.Status.Verification = &arcade.GameDestroyVerification{BackupRef: *d.Spec.BackupRef, RepositorySecretRef: *d.Spec.RepositorySecretRef,
		ArtifactID: f.backup.Status.Artifact.ID, ManifestDigest: f.backup.Status.Artifact.ManifestDigest, PathCount: int32(len(d.Spec.Target.Data.Claims)), VerifiedAt: f.r.now(), ColdAt: f.r.now()}
	if err := f.client.Status().Update(ctx, d); err != nil {
		t.Fatal(err)
	}
	d = f.destroy(t)
	if err := f.r.acquireDataLease(ctx, d); err != nil {
		t.Fatal(err)
	}
	return d
}

func reconcileDestroy(t *testing.T, f destroyFixture) {
	t.Helper()
	if _, err := f.r.Reconcile(context.Background(), ctrl.Request{NamespacedName: f.key}); err != nil {
		t.Fatal(err)
	}
}

func requireDestroyClaim(t *testing.T, f destroyFixture, claim *corev1.PersistentVolumeClaim) {
	t.Helper()
	got := &corev1.PersistentVolumeClaim{}
	if err := f.client.Get(context.Background(), client.ObjectKeyFromObject(claim), got); err != nil || got.UID != claim.UID {
		t.Fatalf("exact claim %s changed or disappeared: UID %s, err %v", claim.Name, got.UID, err)
	}
}

func TestGameDestroyLiveWorldPreviewUsesObservedDataWithoutActiveOverride(t *testing.T) {
	f := newDestroyFixture(t, false)
	server := &arcade.GameServer{}
	if err := f.client.Get(context.Background(), types.NamespacedName{Namespace: f.claim.Namespace, Name: f.backup.Spec.Source.Name}, server); err != nil {
		t.Fatal(err)
	}
	if server.Status.ActiveData != nil || server.Status.ObservedData == nil {
		t.Fatal("fixture must model the natural initial data selection without a restore override")
	}
	for i := 0; i < 3; i++ {
		reconcileDestroy(t, f)
	}
	if d := f.destroy(t); d.Status.Phase != arcade.DestroyPhasePreview || d.Status.Preview == nil {
		t.Fatalf("normal stopped live world failed preview: %#v", d.Status)
	}
	requireDestroyClaim(t, f, f.claim)
}

func TestGameDestroyTransientDeleteRetriesDurableJournal(t *testing.T) {
	f := newDestroyFixture(t, true)
	prepareDestroyDeleting(t, f)
	probe := &destroyDeleteProbe{Client: f.client}
	probe.beforeDelete = func(ctx context.Context, claim *corev1.PersistentVolumeClaim, options *client.DeleteOptions) error {
		d := f.destroy(t)
		if len(d.Status.DeletionJournal) != 1 || d.Status.DeletionJournal[0].ClaimRef.UID != string(claim.UID) || d.Status.DeletionJournal[0].RequestedAt.IsZero() {
			t.Fatal("DELETE preceded persisted exact journal")
		}
		if options.Preconditions == nil || options.Preconditions.UID == nil || *options.Preconditions.UID != claim.UID {
			t.Fatal("DELETE omitted exact UID precondition")
		}
		return apierrors.NewServiceUnavailable("temporary API failure")
	}
	f.r.Client = probe
	reconcileDestroy(t, f) // Persist journal before touching the PVC.
	if len(probe.claims) != 0 {
		t.Fatal("journal reconcile called DELETE")
	}
	if _, err := f.r.Reconcile(context.Background(), ctrl.Request{NamespacedName: f.key}); !apierrors.IsServiceUnavailable(err) {
		t.Fatalf("temporary failure not returned: %v", err)
	}
	d := f.destroy(t)
	if d.Status.Phase != arcade.DestroyPhaseDeleting || d.Status.CompletedAt != nil || len(d.Status.DeletionJournal) != 1 || d.Status.DeletionJournal[0].ObservedDeletedAt != nil {
		t.Fatalf("temporary failure abandoned or falsely completed destroy: %#v", d.Status)
	}
	requireDestroyClaim(t, f, f.claim)
	requestedAt := d.Status.DeletionJournal[0].RequestedAt
	probe.beforeDelete = nil
	for i := 0; i < 4; i++ {
		reconcileDestroy(t, f)
	}
	d = f.destroy(t)
	if d.Status.Phase != arcade.DestroyPhaseSucceeded || len(d.Status.DeletionJournal) != 1 || d.Status.DeletionJournal[0].RequestedAt != requestedAt || d.Status.DeletionJournal[0].ObservedDeletedAt == nil || len(probe.claims) != 2 {
		t.Fatalf("retry did not preserve journal and complete once: %#v; deletes %v", d.Status, probe.claims)
	}
}

func TestGameDestroyUIDPreconditionPreservesReplacementDuringDeleteRace(t *testing.T) {
	f := newDestroyFixture(t, true)
	prepareDestroyDeleting(t, f)
	probe := &destroyDeleteProbe{Client: f.client}
	replacement := f.claim.DeepCopy()
	replacement.UID = "racing-replacement"
	replacement.ResourceVersion = ""
	probe.beforeDelete = func(ctx context.Context, claim *corev1.PersistentVolumeClaim, options *client.DeleteOptions) error {
		if options.Preconditions == nil || options.Preconditions.UID == nil || *options.Preconditions.UID != f.claim.UID {
			t.Fatal("API race lacks original UID precondition")
		}
		if err := f.client.Delete(ctx, claim); err != nil {
			t.Fatal(err)
		}
		if err := f.client.Create(ctx, replacement); err != nil {
			t.Fatal(err)
		}
		return apierrors.NewConflict(schema.GroupResource{Resource: "persistentvolumeclaims"}, claim.Name, errors.New("UID precondition failed"))
	}
	f.r.Client = probe
	reconcileDestroy(t, f)
	if _, err := f.r.Reconcile(context.Background(), ctrl.Request{NamespacedName: f.key}); !apierrors.IsConflict(err) {
		t.Fatalf("UID race should return API conflict: %v", err)
	}
	probe.beforeDelete = nil
	for i := 0; i < 3; i++ {
		reconcileDestroy(t, f)
	}
	requireDestroyClaim(t, f, replacement)
	d := f.destroy(t)
	if d.Status.Phase != arcade.DestroyPhaseDeleting || d.Status.DeletionJournal[0].ObservedDeletedAt != nil || len(probe.claims) != 1 {
		t.Fatalf("replacement was deleted or counted absent: %#v; deletes %v", d.Status, probe.claims)
	}
}

func TestGameDestroyMultiplePathsPartialFailureResumesOnlyRemainingClaim(t *testing.T) {
	f := newDestroyFixture(t, true)
	ctx := context.Background()
	definition, err := f.r.Catalog.Get(f.backup.Status.Source.Game)
	if err != nil {
		t.Fatal(err)
	}
	definition.PersistentPaths = append(definition.PersistentPaths, game.PersistentPath{Name: "logs", MountPath: "/srv/logs"})
	f.r.Catalog = fixedCatalog{definition: definition}
	second := f.claim.DeepCopy()
	second.Name += "-logs"
	second.UID = "logs-claim-uid"
	second.ResourceVersion = ""
	second.Labels[platformkube.LabelDataPath] = "logs"
	second.Spec.VolumeName += "-logs"
	if err := f.client.Create(ctx, second); err != nil {
		t.Fatal(err)
	}
	pv := &corev1.PersistentVolume{ObjectMeta: metav1.ObjectMeta{Name: second.Spec.VolumeName, UID: "logs-pv-uid"}, Spec: corev1.PersistentVolumeSpec{ClaimRef: &corev1.ObjectReference{Namespace: second.Namespace, Name: second.Name, UID: second.UID}}}
	if err := f.client.Create(ctx, pv); err != nil {
		t.Fatal(err)
	}
	backup := &arcade.GameBackup{}
	if err := f.client.Get(ctx, client.ObjectKeyFromObject(f.backup), backup); err != nil {
		t.Fatal(err)
	}
	backup.Status.Source.Paths = append(backup.Status.Source.Paths, arcade.DataPathIdentity{Name: "logs", MountPath: "/srv/logs", ClaimRef: arcade.ExactLocalReference{Name: second.Name, UID: string(second.UID)}})
	backup.Status.Artifact.PathCount = 2
	if err := f.client.Status().Update(ctx, backup); err != nil {
		t.Fatal(err)
	}
	f.backup = backup
	d := f.destroy(t)
	d.Spec.Target.Data.Claims = append(d.Spec.Target.Data.Claims, arcade.RetainedDataClaimReference{Path: "logs", ClaimRef: arcade.ExactLocalReference{Name: second.Name, UID: string(second.UID)}})
	if err := f.client.Update(ctx, d); err != nil {
		t.Fatal(err)
	}
	prepareDestroyDeleting(t, f)
	probe := &destroyDeleteProbe{Client: f.client}
	probe.beforeDelete = func(ctx context.Context, claim *corev1.PersistentVolumeClaim, options *client.DeleteOptions) error {
		if claim.Name == second.Name {
			return apierrors.NewServiceUnavailable("second claim deletion temporarily unavailable")
		}
		return nil
	}
	f.r.Client = probe
	for i := 0; i < 4; i++ {
		reconcileDestroy(t, f) // Journal first, delete first, observe first, journal second.
	}
	d = f.destroy(t)
	if len(d.Status.DeletionJournal) != 2 || d.Status.DeletionJournal[0].ObservedDeletedAt == nil || d.Status.DeletionJournal[1].ObservedDeletedAt != nil {
		t.Fatalf("partial progress is not durable: %#v", d.Status)
	}
	requireDestroyClaim(t, f, second)
	if _, err := f.r.Reconcile(ctx, ctrl.Request{NamespacedName: f.key}); !apierrors.IsServiceUnavailable(err) {
		t.Fatalf("expected second-path transient error: %v", err)
	}
	if d = f.destroy(t); d.Status.Phase != arcade.DestroyPhaseDeleting || d.Status.CompletedAt != nil {
		t.Fatalf("partial failure became terminal: %#v", d.Status)
	}
	probe.beforeDelete = nil
	// Reconciliation may resume after the preview expiry once the durable
	// journal records destructive progress; the world must remain cold.
	f.r.Now = func() metav1.Time { return metav1.NewTime(time.Unix(1_700_010_100, 0)) }
	for i := 0; i < 4; i++ {
		reconcileDestroy(t, f)
	}
	d = f.destroy(t)
	if d.Status.Phase != arcade.DestroyPhaseSucceeded || d.Status.DeletionJournal[1].ObservedDeletedAt == nil || len(probe.claims) != 3 || probe.claims[0] != f.claim.Name || probe.claims[1] != second.Name || probe.claims[2] != second.Name {
		t.Fatalf("retry re-deleted completed path or lost progress: %#v; deletes %v", d.Status, probe.claims)
	}
}

func TestGameDestroyTerminatingUnjournaledClaimIsRejected(t *testing.T) {
	f := newDestroyFixture(t, true)
	ctx := context.Background()
	claim := &corev1.PersistentVolumeClaim{}
	if err := f.client.Get(ctx, client.ObjectKeyFromObject(f.claim), claim); err != nil {
		t.Fatal(err)
	}
	claim.Finalizers = []string{"test.example/retain-terminating"}
	if err := f.client.Update(ctx, claim); err != nil {
		t.Fatal(err)
	}
	if err := f.client.Delete(ctx, claim); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		reconcileDestroy(t, f)
	}
	d := f.destroy(t)
	if d.Status.Phase != arcade.DestroyPhaseFailed || d.Status.Preview != nil || len(d.Status.DeletionJournal) != 0 {
		t.Fatalf("independent PVC deletion accepted as this destroy: %#v", d.Status)
	}
	requireDestroyClaim(t, f, f.claim)
}

func TestGameDestroyReusedNameAfterObservedAbsencePreventsSuccess(t *testing.T) {
	f := newDestroyFixture(t, true)
	prepareDestroyDeleting(t, f)
	for i := 0; i < 3; i++ {
		reconcileDestroy(t, f)
	}
	d := f.destroy(t)
	if d.Status.DeletionJournal[0].ObservedDeletedAt == nil || d.Status.Phase != arcade.DestroyPhaseDeleting {
		t.Fatalf("fixture has not observed exact name absence: %#v", d.Status)
	}
	replacement := f.claim.DeepCopy()
	replacement.UID = "replacement-after-absence"
	replacement.ResourceVersion = ""
	if err := f.client.Create(context.Background(), replacement); err != nil {
		t.Fatal(err)
	}
	reconcileDestroy(t, f)
	d = f.destroy(t)
	if d.Status.Phase != arcade.DestroyPhaseDeleting || d.Status.CompletedAt != nil {
		t.Fatalf("name reuse falsely satisfied final absence scan: %#v", d.Status)
	}
	requireDestroyClaim(t, f, replacement)
}

func TestGameDestroyTerminalFinalizerReleasesOnlyOwnedAuthority(t *testing.T) {
	for _, phase := range []arcade.GameDestroyPhase{arcade.DestroyPhaseFailed, arcade.DestroyPhaseCancelled, arcade.DestroyPhaseSucceeded} {
		t.Run(string(phase), func(t *testing.T) {
			f := newDestroyFixture(t, true)
			ctx := context.Background()
			d := prepareDestroyDeleting(t, f)
			foreign := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "unrelated-authority", Namespace: d.Namespace, UID: "foreign-config-uid"}, Data: map[string]string{"keep": "unrelated"}}
			if err := f.client.Create(ctx, foreign); err != nil {
				t.Fatal(err)
			}
			if err := f.r.workerLease(ctx, d); err != nil {
				t.Fatal(err)
			}
			d = f.destroy(t)
			d.Status.Phase = phase
			if phase == arcade.DestroyPhaseSucceeded {
				if err := f.client.Delete(ctx, f.claim); err != nil {
					t.Fatal(err)
				}
				now := f.r.now()
				d.Status.DeletionJournal = []arcade.GameDestroyClaimDeletion{{Path: d.Spec.Target.Data.Claims[0].Path, ClaimRef: d.Spec.Target.Data.Claims[0].ClaimRef, RequestedAt: now, ObservedDeletedAt: &now}}
			}
			if err := f.client.Status().Update(ctx, d); err != nil {
				t.Fatal(err)
			}
			if err := f.client.Delete(ctx, f.destroy(t)); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 4; i++ {
				reconcileDestroy(t, f)
			}
			if err := f.client.Get(ctx, f.key, &arcade.GameDestroy{}); !apierrors.IsNotFound(err) {
				t.Fatalf("terminal finalizer did not finish cleanup: %v", err)
			}
			for _, name := range []string{platformkube.DestroyWorkerLeaseName(d.UID), platformkube.DataOperationLeaseName(d.Spec.Target.Data.Identity)} {
				if err := f.client.Get(ctx, types.NamespacedName{Namespace: d.Namespace, Name: name}, &coordinationv1.Lease{}); !apierrors.IsNotFound(err) {
					t.Fatalf("terminal lease %s was retained: %v", name, err)
				}
			}
			if err := f.client.Get(ctx, client.ObjectKeyFromObject(foreign), &corev1.ConfigMap{}); err != nil {
				t.Fatalf("terminal cleanup deleted unrelated authority: %v", err)
			}
			if phase != arcade.DestroyPhaseSucceeded {
				requireDestroyClaim(t, f, f.claim)
			}
		})
	}
}

func TestGameDestroyRepositoryWorkerProofWaitsForAuthorityAndPodCleanup(t *testing.T) {
	f := newDestroyFixture(t, true)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		reconcileDestroy(t, f)
	}
	d := f.destroy(t)
	d.Spec.ConfirmationChallenge = d.Status.Preview.Challenge
	if err := f.client.Update(ctx, d); err != nil {
		t.Fatal(err)
	}
	reconcileDestroy(t, f)
	jobKey := types.NamespacedName{Namespace: d.Namespace, Name: platformkube.DestroyResourceName(d.UID)}
	job := &batchv1.Job{}
	for i := 0; i < 8; i++ {
		reconcileDestroy(t, f)
		if err := f.client.Get(ctx, jobKey, job); err == nil {
			break
		}
	}
	if job.Name == "" || job.Spec.Suspend == nil || !*job.Spec.Suspend || len(job.Spec.Template.Spec.SchedulingGates) != 1 {
		t.Fatalf("repository Job was not initially inert: %#v", job)
	}
	for _, volume := range job.Spec.Template.Spec.Volumes {
		if volume.PersistentVolumeClaim != nil {
			t.Fatal("repository verification worker mounts a world PVC")
		}
	}
	job.UID = "destroy-job-uid"
	if err := f.client.Update(ctx, job); err != nil {
		t.Fatal(err)
	}
	reconcileDestroy(t, f) // Pin exact Job UID in worker lease.
	reconcileDestroy(t, f) // Unsuspend only after its UID has been pinned.
	if err := f.client.Get(ctx, jobKey, job); err != nil || job.Spec.Suspend == nil || *job.Spec.Suspend {
		t.Fatalf("exact Job did not activate: %v", err)
	}
	lease := &coordinationv1.Lease{}
	if err := f.client.Get(ctx, types.NamespacedName{Namespace: d.Namespace, Name: platformkube.DestroyWorkerLeaseName(d.UID)}, lease); err != nil || lease.Annotations[destroyJobAuthorizedAnnotation] != string(job.UID) {
		t.Fatalf("worker lease did not pin activated Job: %#v, %v", lease, err)
	}
	pod := &corev1.Pod{ObjectMeta: *job.Spec.Template.ObjectMeta.DeepCopy(), Spec: *job.Spec.Template.Spec.DeepCopy()}
	pod.Name, pod.Namespace, pod.UID = "destroy-worker-pod", d.Namespace, "destroy-pod-uid"
	pod.OwnerReferences = []metav1.OwnerReference{{APIVersion: batchv1.SchemeGroupVersion.String(), Kind: "Job", Name: job.Name, UID: job.UID, Controller: ptr.To(true)}}
	if err := f.client.Create(ctx, pod); err != nil {
		t.Fatal(err)
	}
	reconcileDestroy(t, f) // Exact gated Pod is checked, annotated and ungated.
	if err := f.client.Get(ctx, client.ObjectKeyFromObject(pod), pod); err != nil || pod.Annotations[platformkube.AnnotationDestroyPodAuthorized] != string(pod.UID) || len(pod.Spec.SchedulingGates) != 0 {
		t.Fatalf("exact Pod did not become authorized: %#v, %v", pod, err)
	}
	result := restoreworker.Result{Version: restoreworker.ResultVersion, Stage: restoreworker.StagePreflight, ArtifactID: f.backup.Status.Artifact.ID, ManifestDigest: f.backup.Status.Artifact.ManifestDigest, PathCount: 1, VerifiedAt: f.r.now().Time}
	message, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	pod.Status.Phase = corev1.PodSucceeded
	pod.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: "destroy-worker", State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 0, Message: string(message)}}}}
	if err := f.client.Status().Update(ctx, pod); err != nil {
		t.Fatal(err)
	}
	job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: corev1.ConditionTrue}}
	if err := f.client.Status().Update(ctx, job); err != nil {
		t.Fatal(err)
	}
	reconcileDestroy(t, f)
	d = f.destroy(t)
	if d.Status.Phase != arcade.DestroyPhaseVerifying || d.Status.Verification == nil || d.Status.Verification.ManifestDigest != result.ManifestDigest || len(d.Status.DeletionJournal) != 0 {
		t.Fatalf("worker proof was lost or allowed deletion before cleanup: %#v", d.Status)
	}
	reconcileDestroy(t, f) // Foreground Job deletion.
	reconcileDestroy(t, f) // Fake Pod remains until explicit simulated GC.
	if d = f.destroy(t); d.Status.Phase != arcade.DestroyPhaseVerifying || len(d.Status.DeletionJournal) != 0 {
		t.Fatalf("outstanding Pod allowed destructive phase: %#v", d.Status)
	}
	requireDestroyClaim(t, f, f.claim)
	if err := f.client.Delete(ctx, pod); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 7; i++ {
		reconcileDestroy(t, f)
		if f.destroy(t).Status.Phase == arcade.DestroyPhaseDeleting {
			break
		}
	}
	d = f.destroy(t)
	if d.Status.Phase != arcade.DestroyPhaseDeleting || len(d.Status.DeletionJournal) != 0 {
		t.Fatalf("repository proof never reached ready-to-delete state: %#v", d.Status)
	}
	if err := f.client.Get(ctx, types.NamespacedName{Namespace: d.Namespace, Name: platformkube.DestroyWorkerLeaseName(d.UID)}, &coordinationv1.Lease{}); !apierrors.IsNotFound(err) {
		t.Fatalf("worker authority survived into deleting phase: %v", err)
	}
	if err := f.r.requireDataLease(ctx, d); err != nil {
		t.Fatalf("cold-world lease was released across verification cleanup: %v", err)
	}
	requireDestroyClaim(t, f, f.claim)
}
