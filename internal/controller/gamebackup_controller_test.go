// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	arcadev1alpha1 "github.com/gobha-me/arcadectl/api/v1alpha1"
	"github.com/gobha-me/arcadectl/internal/catalog"
	"github.com/gobha-me/arcadectl/internal/games/factorio"
	platformdata "github.com/gobha-me/arcadectl/internal/platform/data"
	platformkube "github.com/gobha-me/arcadectl/internal/platform/kube"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
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

func TestGameBackupReconcileStoppedSourceToVerifiedArtifact(t *testing.T) {
	t.Parallel()
	reconciler, kubeClient, request := newBackupTestReconciler(t, arcadev1alpha1.DesiredStateStopped, arcadev1alpha1.RestartLeaveStopped)
	reconcileUntilPhase(t, reconciler, kubeClient, request, arcadev1alpha1.DataPhaseRunning)

	backup := getBackup(t, kubeClient, request.NamespacedName)
	jobKey := types.NamespacedName{Namespace: request.Namespace, Name: platformkube.BackupResourceName(backup.UID)}
	job := &batchv1.Job{}
	if err := kubeClient.Get(context.Background(), jobKey, job); err != nil {
		t.Fatalf("get backup Job: %v", err)
	}
	job.UID = "job-uid"
	if err := kubeClient.Update(context.Background(), job); err != nil {
		t.Fatalf("set Job UID: %v", err)
	}
	if err := kubeClient.Get(context.Background(), jobKey, job); err != nil {
		t.Fatalf("refresh backup Job: %v", err)
	}
	job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: corev1.ConditionTrue}}
	if err := kubeClient.Status().Update(context.Background(), job); err != nil {
		t.Fatalf("complete backup Job: %v", err)
	}
	artifactID, _ := platformdata.ArtifactID(backup.UID)
	result := platformdata.BackupWorkerResult{
		Version: platformdata.BackupFormatVersion, ArtifactID: artifactID,
		ManifestDigest: "sha256:" + strings.Repeat("a", 64), SizeBytes: 128, PathCount: 1,
		CreatedAt: time.Unix(1_700_000_010, 0).UTC(), VerifiedAt: time.Unix(1_700_000_020, 0).UTC(),
	}
	message, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal worker result: %v", err)
	}
	pod := admittedBackupPod(job, "backup-worker", "worker-pod-uid")
	pod.Status = corev1.PodStatus{Phase: corev1.PodSucceeded, ContainerStatuses: []corev1.ContainerStatus{{
		Name: "backup-worker", State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 0, Message: string(message)}},
	}}}
	if err := kubeClient.Create(context.Background(), pod); err != nil {
		t.Fatalf("create completed worker Pod: %v", err)
	}

	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("observe worker success: %v", err)
	}
	assertBackupPhase(t, kubeClient, request.NamespacedName, arcadev1alpha1.DataPhaseVerifying)
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("remove verified backup Job: %v", err)
	}
	if err := kubeClient.Delete(context.Background(), pod); err != nil {
		t.Fatalf("simulate foreground worker Pod collection: %v", err)
	}
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("settle verified backup: %v", err)
	}
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("release terminal backup lease: %v", err)
	}
	completed := getBackup(t, kubeClient, request.NamespacedName)
	if completed.Status.Phase != arcadev1alpha1.DataPhaseSucceeded || completed.Status.Artifact == nil || completed.Status.Artifact.Verification.Result != arcadev1alpha1.VerificationVerified {
		t.Fatalf("completed backup status = %#v", completed.Status)
	}
	if completed.Status.Runtime == nil || completed.Status.Runtime.Phase != arcadev1alpha1.PhaseStopped {
		t.Fatalf("runtime disposition = %#v, want stopped", completed.Status.Runtime)
	}
	encoded, _ := json.Marshal(completed.Status)
	for _, secret := range []string{"repository-password-canary", "access-key-canary", "secret-key-canary"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("status contains credential canary %q", secret)
		}
	}
	leases := &coordinationv1.LeaseList{}
	if err := kubeClient.List(context.Background(), leases, client.InNamespace(request.Namespace)); err != nil || len(leases.Items) != 0 {
		t.Fatalf("operation leases after success = %#v, error=%v", leases.Items, err)
	}
}

func TestGameBackupPreviouslyRunningStopsBeforeWorkerAndRestartsExactly(t *testing.T) {
	t.Parallel()
	reconciler, kubeClient, request := newBackupTestReconciler(t, arcadev1alpha1.DesiredStateRunning, arcadev1alpha1.RestartRestorePreviousState)
	for attempt := 0; attempt < 5; attempt++ {
		if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
			t.Fatalf("prepare running backup attempt %d: %v", attempt, err)
		}
	}
	server := &arcadev1alpha1.GameServer{}
	if err := kubeClient.Get(context.Background(), types.NamespacedName{Namespace: request.Namespace, Name: "factory"}, server); err != nil {
		t.Fatalf("get operation-stopped GameServer: %v", err)
	}
	if server.Spec.DesiredState != arcadev1alpha1.DesiredStateStopped {
		t.Fatalf("desired state = %s, want operation-owned stop", server.Spec.DesiredState)
	}
	server.Generation = 2
	if err := kubeClient.Update(context.Background(), server); err != nil {
		t.Fatalf("advance stopped generation: %v", err)
	}
	if err := kubeClient.Get(context.Background(), client.ObjectKeyFromObject(server), server); err != nil {
		t.Fatalf("refresh stopped server: %v", err)
	}
	server.Status.ObservedGeneration = 2
	server.Status.Phase = arcadev1alpha1.PhaseStopped
	if err := kubeClient.Status().Update(context.Background(), server); err != nil {
		t.Fatalf("observe stopped server: %v", err)
	}
	reconcileUntilPhase(t, reconciler, kubeClient, request, arcadev1alpha1.DataPhaseRunning)
	backup := getBackup(t, kubeClient, request.NamespacedName)
	if backup.Status.Fence == nil || backup.Status.Fence.GameServer.Generation != 2 {
		t.Fatalf("cold fence = %#v, want exact stopped generation 2", backup.Status.Fence)
	}

	// A verified result can enter the finalization phase without publishing a
	// second artifact. The stopped source is then returned to exactly generation 3.
	artifactID, _ := platformdata.ArtifactID(backup.UID)
	job := &batchv1.Job{}
	jobKey := types.NamespacedName{Namespace: request.Namespace, Name: platformkube.BackupResourceName(backup.UID)}
	if err := kubeClient.Get(context.Background(), jobKey, job); err != nil {
		t.Fatalf("get completed running-source Job: %v", err)
	}
	job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: corev1.ConditionTrue}}
	if err := kubeClient.Status().Update(context.Background(), job); err != nil {
		t.Fatalf("complete running-source Job: %v", err)
	}
	backup.Status.Phase = arcadev1alpha1.DataPhaseVerifying
	backup.Status.Artifact = backupTestArtifact(backup, artifactID)
	if err := kubeClient.Status().Update(context.Background(), backup); err != nil {
		t.Fatalf("seed verified worker result: %v", err)
	}
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("remove running-source backup Job: %v", err)
	}
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("request exact restart: %v", err)
	}
	if err := kubeClient.Get(context.Background(), types.NamespacedName{Namespace: request.Namespace, Name: "factory"}, server); err != nil {
		t.Fatalf("get restarted server: %v", err)
	}
	if server.Spec.DesiredState != arcadev1alpha1.DesiredStateRunning {
		t.Fatalf("desired state = %s, want restored Running", server.Spec.DesiredState)
	}
	server.Generation = 3
	if err := kubeClient.Update(context.Background(), server); err != nil {
		t.Fatalf("advance restart generation: %v", err)
	}
	if err := kubeClient.Get(context.Background(), client.ObjectKeyFromObject(server), server); err != nil {
		t.Fatalf("refresh restarted server: %v", err)
	}
	server.Status.ObservedGeneration = 3
	server.Status.Phase = arcadev1alpha1.PhaseReady
	if err := kubeClient.Status().Update(context.Background(), server); err != nil {
		t.Fatalf("observe restarted server: %v", err)
	}
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("complete exact restart: %v", err)
	}
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("release exact restart lease: %v", err)
	}
	completed := getBackup(t, kubeClient, request.NamespacedName)
	if completed.Status.Phase != arcadev1alpha1.DataPhaseSucceeded || completed.Status.Runtime == nil || completed.Status.Runtime.GameServer.Generation != 3 || completed.Status.Runtime.Phase != arcadev1alpha1.PhaseReady {
		t.Fatalf("completed running backup = %#v", completed.Status)
	}
	leases := &coordinationv1.LeaseList{}
	if err := kubeClient.List(context.Background(), leases, client.InNamespace(request.Namespace)); err != nil || len(leases.Items) != 0 {
		t.Fatalf("operation leases after terminal reconcile = %#v, error=%v", leases.Items, err)
	}

	// Deleting a historical terminal record must not reassert its old runtime
	// disposition after an administrator has deliberately changed the server.
	serverKey := types.NamespacedName{Namespace: request.Namespace, Name: "factory"}
	if err := kubeClient.Get(context.Background(), serverKey, server); err != nil {
		t.Fatalf("get server before later change: %v", err)
	}
	server.Spec.DesiredState = arcadev1alpha1.DesiredStateStopped
	server.Generation = 4
	if err := kubeClient.Update(context.Background(), server); err != nil {
		t.Fatalf("apply later server intent: %v", err)
	}
	if err := kubeClient.Get(context.Background(), serverKey, server); err != nil {
		t.Fatalf("refresh later server intent: %v", err)
	}
	server.Status.ObservedGeneration = 4
	server.Status.Phase = arcadev1alpha1.PhaseStopped
	if err := kubeClient.Status().Update(context.Background(), server); err != nil {
		t.Fatalf("observe later server intent: %v", err)
	}
	if err := kubeClient.Delete(context.Background(), completed, client.PropagationPolicy(metav1.DeletePropagationForeground)); err != nil {
		t.Fatalf("delete terminal backup: %v", err)
	}
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("finalize terminal backup: %v", err)
	}
	if err := kubeClient.Get(context.Background(), request.NamespacedName, &arcadev1alpha1.GameBackup{}); !apierrors.IsNotFound(err) {
		t.Fatalf("terminal backup after finalization error = %v, want NotFound", err)
	}
	if err := kubeClient.Get(context.Background(), serverKey, server); err != nil {
		t.Fatalf("get server after terminal backup deletion: %v", err)
	}
	if server.Generation != 4 || server.Spec.DesiredState != arcadev1alpha1.DesiredStateStopped || server.Status.Phase != arcadev1alpha1.PhaseStopped {
		t.Fatalf("terminal deletion changed later server state = %#v", server)
	}
}

func TestGameBackupActiveForegroundDeletionSettlesRuntimeBeforeReleasingAuthority(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	reconciler, kubeClient, request := newBackupTestReconciler(t, arcadev1alpha1.DesiredStateRunning, arcadev1alpha1.RestartRestorePreviousState)
	serverKey := types.NamespacedName{Namespace: request.Namespace, Name: "factory"}
	for attempt := 0; attempt < 5; attempt++ {
		if _, err := reconciler.Reconcile(ctx, request); err != nil {
			t.Fatalf("prepare running backup attempt %d: %v", attempt, err)
		}
	}
	server := &arcadev1alpha1.GameServer{}
	if err := kubeClient.Get(ctx, serverKey, server); err != nil {
		t.Fatalf("get operation-stopped server: %v", err)
	}
	server.Generation = 2
	if err := kubeClient.Update(ctx, server); err != nil {
		t.Fatalf("advance stopped generation: %v", err)
	}
	if err := kubeClient.Get(ctx, serverKey, server); err != nil {
		t.Fatalf("refresh stopped server: %v", err)
	}
	server.Status.ObservedGeneration = 2
	server.Status.Phase = arcadev1alpha1.PhaseStopped
	if err := kubeClient.Status().Update(ctx, server); err != nil {
		t.Fatalf("observe stopped server: %v", err)
	}
	reconcileUntilPhase(t, reconciler, kubeClient, request, arcadev1alpha1.DataPhaseRunning)
	backup := getBackup(t, kubeClient, request.NamespacedName)
	lease := backupLease(t, kubeClient, request.Namespace, backup.UID)
	operation := arcadev1alpha1.ExactLocalReference{Name: backup.Name, UID: string(backup.UID)}
	if !platformkube.BackupOperationLeaseMatches(lease, operation, server.Name) || len(lease.OwnerReferences) != 0 {
		t.Fatalf("active operation Lease is not exact and ownerless: %#v", lease)
	}
	claimKey := types.NamespacedName{Namespace: request.Namespace, Name: "factory-factorio-world"}
	claim := &corev1.PersistentVolumeClaim{}
	if err := kubeClient.Get(ctx, claimKey, claim); err != nil {
		t.Fatalf("get retained source claim: %v", err)
	}
	claimUID := claim.UID

	if err := kubeClient.Delete(ctx, backup, client.PropagationPolicy(metav1.DeletePropagationForeground)); err != nil {
		t.Fatalf("request active backup deletion: %v", err)
	}
	if _, err := reconciler.Reconcile(ctx, request); err != nil {
		t.Fatalf("stop deleting backup worker: %v", err)
	}
	if _, err := reconciler.Reconcile(ctx, request); err != nil {
		t.Fatalf("authorize deleted-backup runtime settlement: %v", err)
	}
	if err := kubeClient.Get(ctx, serverKey, server); err != nil {
		t.Fatalf("get settlement-requested server: %v", err)
	}
	if server.Spec.DesiredState != arcadev1alpha1.DesiredStateRunning {
		t.Fatalf("deleted backup settlement state = %s, want Running", server.Spec.DesiredState)
	}
	lease = backupLease(t, kubeClient, request.Namespace, backup.UID)
	if lease.Annotations[platformkube.AnnotationRuntimeSettlementState] != string(arcadev1alpha1.DesiredStateRunning) ||
		lease.Annotations[platformkube.AnnotationRuntimeSettlementGeneration] != "3" {
		t.Fatalf("runtime settlement authority = %#v", lease.Annotations)
	}
	server.Generation = 3
	if err := kubeClient.Update(ctx, server); err != nil {
		t.Fatalf("advance restored generation: %v", err)
	}
	if err := kubeClient.Get(ctx, serverKey, server); err != nil {
		t.Fatalf("refresh restored server: %v", err)
	}
	server.Status.ObservedGeneration = 3
	server.Status.Phase = arcadev1alpha1.PhaseReady
	if err := kubeClient.Status().Update(ctx, server); err != nil {
		t.Fatalf("observe restored server: %v", err)
	}
	if _, err := reconciler.Reconcile(ctx, request); err != nil {
		t.Fatalf("finish deleted-backup settlement: %v", err)
	}
	if err := kubeClient.Get(ctx, request.NamespacedName, &arcadev1alpha1.GameBackup{}); !apierrors.IsNotFound(err) {
		t.Fatalf("active backup after finalization error = %v, want NotFound", err)
	}
	if err := kubeClient.Get(ctx, client.ObjectKeyFromObject(lease), &coordinationv1.Lease{}); !apierrors.IsNotFound(err) {
		t.Fatalf("operation Lease after finalization error = %v, want NotFound", err)
	}
	if err := kubeClient.Get(ctx, claimKey, claim); err != nil || claim.UID != claimUID {
		t.Fatalf("retained source claim after finalization = %#v, error=%v", claim, err)
	}
}

func TestGameBackupCancellationBeforeFenceSettlesOperationOwnedStop(t *testing.T) {
	t.Parallel()
	for _, policy := range []arcadev1alpha1.RestartPolicy{arcadev1alpha1.RestartRestorePreviousState, arcadev1alpha1.RestartLeaveStopped} {
		t.Run(string(policy), func(t *testing.T) {
			ctx := context.Background()
			reconciler, kubeClient, request := newBackupTestReconciler(t, arcadev1alpha1.DesiredStateRunning, policy)
			for attempt := 0; attempt < 5; attempt++ {
				if _, err := reconciler.Reconcile(ctx, request); err != nil {
					t.Fatalf("prepare running backup: %v", err)
				}
			}
			backup := getBackup(t, kubeClient, request.NamespacedName)
			if backup.Status.Source == nil || backup.Status.Fence != nil {
				t.Fatalf("expected detachment window, got %#v", backup.Status)
			}
			serverKey := types.NamespacedName{Namespace: request.Namespace, Name: "factory"}
			server := &arcadev1alpha1.GameServer{}
			if err := kubeClient.Get(ctx, serverKey, server); err != nil {
				t.Fatalf("get stopped-intent server: %v", err)
			}
			if server.Spec.DesiredState != arcadev1alpha1.DesiredStateStopped {
				t.Fatal("operation had not requested its cold stop")
			}
			server.Generation = 2
			if err := kubeClient.Update(ctx, server); err != nil {
				t.Fatalf("advance stopped generation: %v", err)
			}
			backup.Spec.CancelRequested = true
			backup.Generation = 2
			if err := kubeClient.Update(ctx, backup); err != nil {
				t.Fatalf("cancel during detachment: %v", err)
			}
			for attempt := 0; attempt < 2; attempt++ {
				if _, err := reconciler.Reconcile(ctx, request); err != nil {
					t.Fatalf("request cancellation settlement: %v", err)
				}
			}
			assertBackupPhase(t, kubeClient, request.NamespacedName, arcadev1alpha1.DataPhaseCancelling)
			lease := backupLease(t, kubeClient, request.Namespace, backup.UID)
			if err := kubeClient.Get(ctx, serverKey, server); err != nil {
				t.Fatalf("get settlement-requested server: %v", err)
			}
			wantGeneration, wantState, wantPhase := int64(2), arcadev1alpha1.DesiredStateStopped, arcadev1alpha1.PhaseStopped
			if policy == arcadev1alpha1.RestartRestorePreviousState {
				wantGeneration, wantState, wantPhase = 3, arcadev1alpha1.DesiredStateRunning, arcadev1alpha1.PhaseReady
				if lease.Annotations[platformkube.AnnotationRuntimeSettlementGeneration] != "3" {
					t.Fatalf("restart lacks exact generation authority: %#v", lease.Annotations)
				}
			}
			if server.Spec.DesiredState != wantState {
				t.Fatalf("settlement intent = %s, want %s", server.Spec.DesiredState, wantState)
			}
			server.Generation = wantGeneration
			if err := kubeClient.Update(ctx, server); err != nil {
				t.Fatalf("advance final runtime generation: %v", err)
			}
			if _, err := reconciler.Reconcile(ctx, request); err != nil {
				t.Fatalf("wait for runtime observation: %v", err)
			}
			assertBackupPhase(t, kubeClient, request.NamespacedName, arcadev1alpha1.DataPhaseCancelling)
			backupLease(t, kubeClient, request.Namespace, backup.UID)
			if err := kubeClient.Get(ctx, serverKey, server); err != nil {
				t.Fatalf("refresh final server: %v", err)
			}
			server.Status.ObservedGeneration, server.Status.Phase = wantGeneration, wantPhase
			if err := kubeClient.Status().Update(ctx, server); err != nil {
				t.Fatalf("observe requested runtime: %v", err)
			}
			reconcileUntilPhase(t, reconciler, kubeClient, request, arcadev1alpha1.DataPhaseCancelled)
			completed := getBackup(t, kubeClient, request.NamespacedName)
			if completed.Status.Fence != nil || completed.Status.Runtime != nil || completed.Status.Artifact != nil {
				t.Fatalf("pre-fence cancellation claimed cold data work: %#v", completed.Status)
			}
			if _, err := reconciler.Reconcile(ctx, request); err != nil {
				t.Fatalf("release settled cancellation Lease: %v", err)
			}
			if err := kubeClient.Get(ctx, client.ObjectKeyFromObject(lease), &coordinationv1.Lease{}); !apierrors.IsNotFound(err) {
				t.Fatalf("settled cancellation Lease = %v, want absent", err)
			}
		})
	}
}

func TestGameBackupFailedDeadlineWithoutPodExhaustsBoundedRetries(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	reconciler, kubeClient, request := newBackupTestReconciler(t, arcadev1alpha1.DesiredStateStopped, arcadev1alpha1.RestartLeaveStopped)
	reconcileUntilPhase(t, reconciler, kubeClient, request, arcadev1alpha1.DataPhaseRunning)
	backup := getBackup(t, kubeClient, request.NamespacedName)
	jobKey := types.NamespacedName{Namespace: request.Namespace, Name: platformkube.BackupResourceName(backup.UID)}
	claimKey := types.NamespacedName{Namespace: request.Namespace, Name: "factory-factorio-world"}
	claim := &corev1.PersistentVolumeClaim{}
	if err := kubeClient.Get(ctx, claimKey, claim); err != nil {
		t.Fatalf("get source claim: %v", err)
	}
	claimUID := claim.UID
	for attempt := int32(1); attempt <= maxBackupAttempts; attempt++ {
		job := &batchv1.Job{}
		if err := kubeClient.Get(ctx, jobKey, job); err != nil {
			t.Fatalf("get attempt %d Job: %v", attempt, err)
		}
		job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobFailed, Status: corev1.ConditionTrue, Reason: "DeadlineExceeded"}}
		if err := kubeClient.Status().Update(ctx, job); err != nil {
			t.Fatalf("fail attempt %d with zero Pods: %v", attempt, err)
		}
		if _, err := reconciler.Reconcile(ctx, request); err != nil {
			t.Fatalf("observe deadline failure %d: %v", attempt, err)
		}
		if attempt == maxBackupAttempts {
			break
		}
		if reason := backupConditionReason(getBackup(t, kubeClient, request.NamespacedName), arcadev1alpha1.ConditionArtifactReady); reason != arcadev1alpha1.ReasonWorkerRetrying {
			t.Fatalf("deadline failure did not trigger retry: %s", reason)
		}
		ready := false
		for reconcile := 0; reconcile < 8; reconcile++ {
			if _, err := reconciler.Reconcile(ctx, request); err != nil {
				t.Fatalf("serialize replacement attempt: %v", err)
			}
			backup = getBackup(t, kubeClient, request.NamespacedName)
			if err := kubeClient.Get(ctx, jobKey, job); err == nil && backup.Status.Attempts == attempt+1 && job.Spec.Suspend != nil && !*job.Spec.Suspend {
				ready = true
				break
			}
		}
		if !ready {
			t.Fatalf("no bounded replacement after failure %d", attempt)
		}
	}
	reconcileUntilPhase(t, reconciler, kubeClient, request, arcadev1alpha1.DataPhaseFailed)
	if _, err := reconciler.Reconcile(ctx, request); err != nil {
		t.Fatalf("release failed operation Lease: %v", err)
	}
	completed := getBackup(t, kubeClient, request.NamespacedName)
	if completed.Status.Attempts != maxBackupAttempts || completed.Status.Artifact != nil {
		t.Fatalf("deadline failures published an artifact or escaped the bound: %#v", completed.Status)
	}
	leases := &coordinationv1.LeaseList{}
	if err := kubeClient.List(ctx, leases, client.InNamespace(request.Namespace)); err != nil || len(leases.Items) != 0 {
		t.Fatalf("deadline failure retained authority: %#v, %v", leases.Items, err)
	}
	if err := kubeClient.Get(ctx, claimKey, claim); err != nil || claim.UID != claimUID {
		t.Fatalf("deadline failure changed source claim: %#v, %v", claim, err)
	}
}

func TestGameBackupRejectsInjectedWorkerJob(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	reconciler, kubeClient, request := newBackupTestReconciler(t, arcadev1alpha1.DesiredStateStopped, arcadev1alpha1.RestartLeaveStopped)
	reconcileUntilPhase(t, reconciler, kubeClient, request, arcadev1alpha1.DataPhaseRunning)
	backup := getBackup(t, kubeClient, request.NamespacedName)
	jobKey := types.NamespacedName{Namespace: request.Namespace, Name: platformkube.BackupResourceName(backup.UID)}
	job := &batchv1.Job{}
	if err := kubeClient.Get(ctx, jobKey, job); err != nil {
		t.Fatalf("get worker Job: %v", err)
	}
	job.Spec.Template.Spec.Containers = append(job.Spec.Template.Spec.Containers, corev1.Container{
		Name: "credential-reader", Image: testWorkerImage,
		VolumeMounts: []corev1.VolumeMount{{Name: "credentials", MountPath: "/stolen"}, {Name: "source-0", MountPath: "/writable-source"}},
	})
	if err := kubeClient.Update(ctx, job); err != nil {
		t.Fatalf("inject changed worker Job: %v", err)
	}
	if _, err := reconciler.Reconcile(ctx, request); err == nil || !strings.Contains(err.Error(), "changed Job") {
		t.Fatalf("Reconcile() error = %v, want changed-Job collision", err)
	}
	if attempts := getBackup(t, kubeClient, request.NamespacedName).Status.Attempts; attempts != 1 {
		t.Fatalf("backup attempts after injected Job = %d, want 1", attempts)
	}
}

func TestGameBackupCreatesJobSuspendedAndRejectsCreateAdmissionMutation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	mutated := false
	admission := interceptor.Funcs{Create: func(ctx context.Context, delegate client.WithWatch, object client.Object, options ...client.CreateOption) error {
		if job, ok := object.(*batchv1.Job); ok {
			mutated = true
			job.Spec.Template.Spec.Containers = append(job.Spec.Template.Spec.Containers, corev1.Container{
				Name: "admission-sidecar", Image: testWorkerImage,
				VolumeMounts: []corev1.VolumeMount{{Name: "credentials", MountPath: "/stolen"}},
			})
		}
		return delegate.Create(ctx, object, options...)
	}}
	reconciler, kubeClient, request := newBackupTestReconcilerWithInterceptor(t, arcadev1alpha1.DesiredStateStopped, arcadev1alpha1.RestartLeaveStopped, admission)
	var reconcileErr error
	for attempt := 0; attempt < 12 && reconcileErr == nil; attempt++ {
		_, reconcileErr = reconciler.Reconcile(ctx, request)
	}
	if !mutated || reconcileErr == nil || !strings.Contains(reconcileErr.Error(), "changed Job") {
		t.Fatalf("admission mutation result: mutated=%t error=%v, want suspended changed-Job rejection", mutated, reconcileErr)
	}
	backup := getBackup(t, kubeClient, request.NamespacedName)
	job := &batchv1.Job{}
	if err := kubeClient.Get(ctx, types.NamespacedName{Namespace: request.Namespace, Name: platformkube.BackupResourceName(backup.UID)}, job); err != nil {
		t.Fatalf("get admission-mutated Job: %v", err)
	}
	if job.Spec.Suspend == nil || !*job.Spec.Suspend {
		t.Fatalf("admission-mutated Job was executable: suspend=%v", job.Spec.Suspend)
	}
	pods := &corev1.PodList{}
	if err := kubeClient.List(ctx, pods, client.InNamespace(request.Namespace), client.MatchingLabels{platformkube.LabelBackupUID: string(backup.UID)}); err != nil || len(pods.Items) != 0 {
		t.Fatalf("Pods from rejected suspended Job = %#v, error=%v", pods.Items, err)
	}
}

func TestGameBackupAuthorizesOnlyExactGatedAdmittedPod(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	reconciler, kubeClient, request := newBackupTestReconciler(t, arcadev1alpha1.DesiredStateStopped, arcadev1alpha1.RestartLeaveStopped)
	reconcileUntilPhase(t, reconciler, kubeClient, request, arcadev1alpha1.DataPhaseRunning)
	backup := getBackup(t, kubeClient, request.NamespacedName)
	job := assignBackupJobUID(t, kubeClient, request.Namespace, backup.UID, "job-uid")
	pod := gatedBackupPod(job, "exact-worker", "exact-worker-uid")
	if err := kubeClient.Create(ctx, pod); err != nil {
		t.Fatalf("create exact gated worker Pod: %v", err)
	}
	if _, err := reconciler.Reconcile(ctx, request); err != nil {
		t.Fatalf("authorize exact admitted worker Pod: %v", err)
	}
	stored := &corev1.Pod{}
	if err := kubeClient.Get(ctx, client.ObjectKeyFromObject(pod), stored); err != nil {
		t.Fatalf("get authorized worker Pod: %v", err)
	}
	if len(stored.Spec.SchedulingGates) != 0 || stored.Annotations[platformkube.AnnotationBackupPodAuthorized] != string(stored.UID) {
		t.Fatalf("worker authorization = gates %#v annotations %#v", stored.Spec.SchedulingGates, stored.Annotations)
	}
}

func TestGameBackupRejectsInjectedAdmittedPodBeforeScheduling(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	reconciler, kubeClient, request := newBackupTestReconciler(t, arcadev1alpha1.DesiredStateStopped, arcadev1alpha1.RestartLeaveStopped)
	reconcileUntilPhase(t, reconciler, kubeClient, request, arcadev1alpha1.DataPhaseRunning)
	backup := getBackup(t, kubeClient, request.NamespacedName)
	job := assignBackupJobUID(t, kubeClient, request.Namespace, backup.UID, "job-uid")
	pod := gatedBackupPod(job, "injected-worker", "injected-worker-uid")
	pod.Spec.Containers = append(pod.Spec.Containers, corev1.Container{
		Name: "credential-reader", Image: testWorkerImage,
		VolumeMounts: []corev1.VolumeMount{{Name: "credentials", MountPath: "/stolen"}, {Name: "source-0", MountPath: "/writable-source"}},
	})
	if err := kubeClient.Create(ctx, pod); err != nil {
		t.Fatalf("create injected gated worker Pod: %v", err)
	}
	if _, err := reconciler.Reconcile(ctx, request); err != nil {
		t.Fatalf("reject injected admitted worker Pod: %v", err)
	}
	stored := &corev1.Pod{}
	if err := kubeClient.Get(ctx, client.ObjectKeyFromObject(pod), stored); err != nil {
		t.Fatalf("get rejected worker Pod: %v", err)
	}
	if len(stored.Spec.SchedulingGates) != 1 || stored.Spec.SchedulingGates[0].Name != platformkube.BackupSchedulingGate ||
		stored.Annotations[platformkube.AnnotationBackupPodAuthorized] != "" || stored.Spec.NodeName != "" || stored.Status.Phase == corev1.PodRunning {
		t.Fatalf("rejected Pod escaped execution gate: %#v", stored)
	}
	jobKey := types.NamespacedName{Namespace: request.Namespace, Name: job.Name}
	if err := kubeClient.Get(ctx, jobKey, &batchv1.Job{}); !apierrors.IsNotFound(err) {
		t.Fatalf("rejected worker Job error = %v, want NotFound", err)
	}
}

func TestBackupJobSpecMatchingAllowsOnlyKubernetesDefaults(t *testing.T) {
	t.Parallel()
	reconciler, kubeClient, request := newBackupTestReconciler(t, arcadev1alpha1.DesiredStateStopped, arcadev1alpha1.RestartLeaveStopped)
	reconcileUntilPhase(t, reconciler, kubeClient, request, arcadev1alpha1.DataPhaseRunning)
	backup := getBackup(t, kubeClient, request.NamespacedName)
	desired := &batchv1.Job{}
	jobKey := types.NamespacedName{Namespace: request.Namespace, Name: platformkube.BackupResourceName(backup.UID)}
	if err := kubeClient.Get(context.Background(), jobKey, desired); err != nil {
		t.Fatalf("get desired worker Job: %v", err)
	}
	stored := desired.DeepCopy()
	stored.UID = "job-uid"
	completionMode := batchv1.NonIndexedCompletion
	stored.Spec.CompletionMode = &completionMode
	suspended := false
	stored.Spec.Suspend = &suspended
	replacement := batchv1.TerminatingOrFailed
	stored.Spec.PodReplacementPolicy = &replacement
	manualSelector := false
	stored.Spec.ManualSelector = &manualSelector
	stored.Spec.Selector = &metav1.LabelSelector{MatchLabels: map[string]string{batchv1.ControllerUidLabel: string(stored.UID)}}
	for label, value := range map[string]string{
		batchv1.JobNameLabel: stored.Name, batchv1.ControllerUidLabel: string(stored.UID),
		"job-name": stored.Name, "controller-uid": string(stored.UID),
	} {
		stored.Spec.Template.Labels[label] = value
	}
	pod := &stored.Spec.Template.Spec
	pod.DeprecatedServiceAccount = pod.ServiceAccountName
	pod.DNSPolicy = corev1.DNSClusterFirst
	grace := int64(corev1.DefaultTerminationGracePeriodSeconds)
	pod.TerminationGracePeriodSeconds = &grace
	pod.SchedulerName = corev1.DefaultSchedulerName
	for index := range pod.InitContainers {
		pod.InitContainers[index].TerminationMessagePath = corev1.TerminationMessagePathDefault
		pod.InitContainers[index].TerminationMessagePolicy = corev1.TerminationMessageReadFile
		for envIndex := range pod.InitContainers[index].Env {
			if source := pod.InitContainers[index].Env[envIndex].ValueFrom; source != nil && source.FieldRef != nil {
				source.FieldRef.APIVersion = "v1"
			}
		}
	}
	for index := range pod.Containers {
		pod.Containers[index].TerminationMessagePath = corev1.TerminationMessagePathDefault
		if pod.Containers[index].TerminationMessagePolicy == "" {
			pod.Containers[index].TerminationMessagePolicy = corev1.TerminationMessageReadFile
		}
	}
	if !backupJobSpecMatches(desired, stored) {
		t.Fatal("stored Job with only Kubernetes defaults did not match desired worker")
	}
	stored.Spec.Template.Spec.Containers = append(stored.Spec.Template.Spec.Containers, corev1.Container{Name: "injected", Image: testWorkerImage})
	if backupJobSpecMatches(desired, stored) {
		t.Fatal("stored Job with an injected container matched desired worker")
	}
}

func TestGameBackupWaitsForExactVolumeAttachmentToDetach(t *testing.T) {
	t.Parallel()
	reconciler, kubeClient, request := newBackupTestReconciler(t, arcadev1alpha1.DesiredStateStopped, arcadev1alpha1.RestartLeaveStopped)
	volumeName := "pv-world"
	attachment := &storagev1.VolumeAttachment{
		ObjectMeta: metav1.ObjectMeta{Name: "attached-world"},
		Spec: storagev1.VolumeAttachmentSpec{
			Attacher: "csi.example.invalid", NodeName: "node-a",
			Source: storagev1.VolumeAttachmentSource{PersistentVolumeName: &volumeName},
		},
		Status: storagev1.VolumeAttachmentStatus{Attached: true},
	}
	if err := kubeClient.Create(context.Background(), attachment); err != nil {
		t.Fatalf("create attached volume evidence: %v", err)
	}
	for attempt := 0; attempt < 5; attempt++ {
		if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
			t.Fatalf("reconcile attached source attempt %d: %v", attempt, err)
		}
	}
	backup := getBackup(t, kubeClient, request.NamespacedName)
	if backup.Status.Phase != arcadev1alpha1.DataPhasePreparing || backup.Status.Fence != nil {
		t.Fatalf("attached source status = %#v, want unfenced Preparing", backup.Status)
	}
	job := &batchv1.Job{}
	jobKey := types.NamespacedName{Namespace: request.Namespace, Name: platformkube.BackupResourceName(backup.UID)}
	if err := kubeClient.Get(context.Background(), jobKey, job); err == nil {
		t.Fatal("backup Job exists while exact source PV is still attached")
	}
	if err := kubeClient.Delete(context.Background(), attachment); err != nil {
		t.Fatalf("remove attached volume evidence: %v", err)
	}
	reconcileUntilPhase(t, reconciler, kubeClient, request, arcadev1alpha1.DataPhaseRunning)
}

func TestGameBackupSerializesRetryAfterOverlappingWorkerPods(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	reconciler, kubeClient, request := newBackupTestReconciler(t, arcadev1alpha1.DesiredStateStopped, arcadev1alpha1.RestartLeaveStopped)
	reconcileUntilPhase(t, reconciler, kubeClient, request, arcadev1alpha1.DataPhaseRunning)
	backup := getBackup(t, kubeClient, request.NamespacedName)
	if backup.Status.Attempts != 1 {
		t.Fatalf("initial attempts = %d, want 1", backup.Status.Attempts)
	}

	jobKey := types.NamespacedName{Namespace: request.Namespace, Name: platformkube.BackupResourceName(backup.UID)}
	job := &batchv1.Job{}
	if err := kubeClient.Get(ctx, jobKey, job); err != nil {
		t.Fatalf("get initial worker Job: %v", err)
	}
	job.UID = "initial-job-uid"
	if err := kubeClient.Update(ctx, job); err != nil {
		t.Fatalf("assign initial Job UID: %v", err)
	}
	for _, pod := range []*corev1.Pod{
		backupWorkerPod("worker-a", "worker-pod-a", request.Namespace, backup.UID, job.Name, job.UID),
		backupWorkerPod("worker-b", "worker-pod-b", request.Namespace, backup.UID, job.Name, job.UID),
	} {
		if err := kubeClient.Create(ctx, pod); err != nil {
			t.Fatalf("create overlapping worker Pod %s: %v", pod.Name, err)
		}
	}
	lease := backupLease(t, kubeClient, request.Namespace, backup.UID)
	if lease.Annotations == nil {
		lease.Annotations = make(map[string]string)
	}
	lease.Annotations[platformkube.AnnotationWorkerPodUID] = "worker-pod-a"
	if err := kubeClient.Update(ctx, lease); err != nil {
		t.Fatalf("record first worker execution: %v", err)
	}

	if _, err := reconciler.Reconcile(ctx, request); err != nil {
		t.Fatalf("detect worker overlap: %v", err)
	}
	backup = getBackup(t, kubeClient, request.NamespacedName)
	if reason := backupConditionReason(backup, arcadev1alpha1.ConditionArtifactReady); reason != arcadev1alpha1.ReasonWorkerRetrying {
		t.Fatalf("artifact reason = %s, want %s", reason, arcadev1alpha1.ReasonWorkerRetrying)
	}
	if _, err := reconciler.Reconcile(ctx, request); err != nil {
		t.Fatalf("delete overlapping worker Job: %v", err)
	}
	if _, err := reconciler.Reconcile(ctx, request); err != nil {
		t.Fatalf("wait for overlapping worker Pods: %v", err)
	}
	if err := kubeClient.Get(ctx, jobKey, &batchv1.Job{}); err == nil {
		t.Fatal("replacement Job started while prior worker Pods still exist")
	}
	lease = backupLease(t, kubeClient, request.Namespace, backup.UID)
	if got := lease.Annotations[platformkube.AnnotationWorkerPodUID]; got != "worker-pod-a" {
		t.Fatalf("worker execution was cleared before Pod absence: %q", got)
	}

	for _, name := range []string{"worker-a", "worker-b"} {
		pod := &corev1.Pod{}
		if err := kubeClient.Get(ctx, types.NamespacedName{Namespace: request.Namespace, Name: name}, pod); err != nil {
			t.Fatalf("get prior worker Pod %s: %v", name, err)
		}
		if err := kubeClient.Delete(ctx, pod); err != nil {
			t.Fatalf("delete prior worker Pod %s: %v", name, err)
		}
	}
	if _, err := reconciler.Reconcile(ctx, request); err != nil {
		t.Fatalf("authorize serialized retry: %v", err)
	}
	backup = getBackup(t, kubeClient, request.NamespacedName)
	if backup.Status.Attempts != 2 {
		t.Fatalf("retry attempts = %d, want 2", backup.Status.Attempts)
	}
	lease = backupLease(t, kubeClient, request.Namespace, backup.UID)
	if got := lease.Annotations[platformkube.AnnotationWorkerPodUID]; got != "" {
		t.Fatalf("worker execution after exact Pod absence = %q, want empty", got)
	}
	if _, err := reconciler.Reconcile(ctx, request); err != nil {
		t.Fatalf("create serialized replacement Job: %v", err)
	}
	if err := kubeClient.Get(ctx, jobKey, &batchv1.Job{}); err != nil {
		t.Fatalf("replacement Job was not created after exact Pod absence: %v", err)
	}
}

func TestGameServerControllerRemovesRuntimeWhileDataOperationLeaseExists(t *testing.T) {
	t.Parallel()
	server := controllerTestServer(arcadev1alpha1.DesiredStateRunning)
	reconciler, kubeClient := newTestReconciler(t, server)
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(server)}
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("create retained claim: %v", err)
	}
	claimKey := types.NamespacedName{Namespace: server.Namespace, Name: "factory-factorio-world"}
	markClaimBound(t, kubeClient, claimKey, server.Spec.Storage.Size)
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("create runtime: %v", err)
	}
	plan, err := platformkube.Build(server, factorio.Definition())
	if err != nil {
		t.Fatalf("build data identity: %v", err)
	}
	lease := &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{
			Name: platformkube.DataOperationLeaseName(plan.DataIdentity), Namespace: server.Namespace,
			Labels: map[string]string{
				platformkube.LabelManagedBy: platformkube.ManagerName, platformkube.LabelDataIdentity: plan.DataIdentity,
				platformkube.LabelInstance: server.Name,
			},
		},
		Spec: coordinationv1.LeaseSpec{HolderIdentity: stringPointer("backup-uid")},
	}
	if err := kubeClient.Create(context.Background(), lease); err != nil {
		t.Fatalf("create data-operation lease: %v", err)
	}
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("reconcile active data operation: %v", err)
	}
	assertNoRuntime(t, kubeClient, request.NamespacedName)
	assertPhase(t, kubeClient, request.NamespacedName, arcadev1alpha1.PhaseStopping, metav1.ConditionFalse, arcadev1alpha1.ReasonDataOperationActive)
}

const testWorkerImage = "registry.example/arcadectl@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func newBackupTestReconciler(t *testing.T, initial arcadev1alpha1.DesiredState, restart arcadev1alpha1.RestartPolicy) (*GameBackupReconciler, client.Client, ctrl.Request) {
	return newBackupTestReconcilerWithInterceptor(t, initial, restart, interceptor.Funcs{})
}

func newBackupTestReconcilerWithInterceptor(t *testing.T, initial arcadev1alpha1.DesiredState, restart arcadev1alpha1.RestartPolicy, interceptors interceptor.Funcs) (*GameBackupReconciler, client.Client, ctrl.Request) {
	t.Helper()
	scheme := runtime.NewScheme()
	for name, add := range map[string]func(*runtime.Scheme) error{
		"Arcadectl": arcadev1alpha1.AddToScheme, "apps": appsv1.AddToScheme, "batch": batchv1.AddToScheme,
		"coordination": coordinationv1.AddToScheme, "core": corev1.AddToScheme, "rbac": rbacv1.AddToScheme, "storage": storagev1.AddToScheme,
	} {
		if err := add(scheme); err != nil {
			t.Fatalf("add %s scheme: %v", name, err)
		}
	}
	server := controllerTestServer(initial)
	server.Status.ObservedGeneration = 1
	if initial == arcadev1alpha1.DesiredStateStopped {
		server.Status.Phase = arcadev1alpha1.PhaseStopped
	} else {
		server.Status.Phase = arcadev1alpha1.PhaseReady
	}
	claim := plannedBoundClaim(t, server, "claim-uid")
	claim.Spec.VolumeName = "pv-world"
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "repository", Namespace: server.Namespace, UID: "secret-uid", ResourceVersion: "42"},
		Immutable:  boolPointer(true),
		Data: map[string][]byte{
			"repository": []byte("s3:http://minio/arcadectl"), "password": []byte("repository-password-canary"),
			"awsAccessKeyID": []byte("access-key-canary"), "awsSecretAccessKey": []byte("secret-key-canary"),
		},
	}
	backup := &arcadev1alpha1.GameBackup{
		ObjectMeta: metav1.ObjectMeta{Name: "backup", Namespace: server.Namespace, UID: "backup-uid", Generation: 1},
		Spec: arcadev1alpha1.GameBackupSpec{
			DataOperationRequest: arcadev1alpha1.DataOperationRequest{
				RepositorySecretRef: arcadev1alpha1.ExactSecretReference{
					ExactLocalReference: arcadev1alpha1.ExactLocalReference{Name: secret.Name, UID: string(secret.UID)}, ResourceVersion: secret.ResourceVersion,
				},
				RestartPolicy: restart,
			},
			Source: arcadev1alpha1.ExactGameServerReference{
				ExactLocalReference: arcadev1alpha1.ExactLocalReference{Name: server.Name, UID: string(server.UID)}, Generation: server.Generation, DesiredState: initial,
			},
			RetentionPolicy: arcadev1alpha1.ArtifactRetentionRetain,
		},
	}
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&arcadev1alpha1.GameBackup{}, &arcadev1alpha1.GameServer{}, &batchv1.Job{}, &corev1.PersistentVolumeClaim{}, &corev1.Pod{}).
		WithObjects(server, claim, secret, backup).WithInterceptorFuncs(interceptors).Build()
	gameCatalog, err := catalog.Builtins()
	if err != nil {
		t.Fatalf("build catalog: %v", err)
	}
	reconciler := &GameBackupReconciler{
		Client: kubeClient, APIReader: kubeClient, Scheme: scheme, Catalog: gameCatalog, WorkerImage: testWorkerImage,
		Now: func() metav1.Time { return metav1.NewTime(time.Unix(1_700_000_100, 0).UTC()) },
	}
	return reconciler, kubeClient, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: server.Namespace, Name: backup.Name}}
}

func reconcileUntilPhase(t *testing.T, reconciler *GameBackupReconciler, kubeClient client.Client, request ctrl.Request, phase arcadev1alpha1.DataOperationPhase) {
	t.Helper()
	for attempt := 0; attempt < 12; attempt++ {
		backup := getBackup(t, kubeClient, request.NamespacedName)
		if backup.Status.Phase == phase {
			return
		}
		if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
			t.Fatalf("Reconcile() attempt %d error = %v", attempt, err)
		}
	}
	t.Fatalf("GameBackup did not reach phase %s", phase)
}

func getBackup(t *testing.T, kubeClient client.Client, key types.NamespacedName) *arcadev1alpha1.GameBackup {
	t.Helper()
	backup := &arcadev1alpha1.GameBackup{}
	if err := kubeClient.Get(context.Background(), key, backup); err != nil {
		t.Fatalf("get GameBackup: %v", err)
	}
	return backup
}

func assertBackupPhase(t *testing.T, kubeClient client.Client, key types.NamespacedName, phase arcadev1alpha1.DataOperationPhase) {
	t.Helper()
	if got := getBackup(t, kubeClient, key).Status.Phase; got != phase {
		t.Fatalf("GameBackup phase = %s, want %s", got, phase)
	}
}

func backupTestArtifact(backup *arcadev1alpha1.GameBackup, artifactID string) *arcadev1alpha1.BackupArtifact {
	created := metav1.NewTime(time.Unix(1_700_000_010, 0).UTC())
	verified := metav1.NewTime(time.Unix(1_700_000_020, 0).UTC())
	return &arcadev1alpha1.BackupArtifact{
		Provenance: arcadev1alpha1.ArtifactProvenance{
			BackupRef: arcadev1alpha1.ExactLocalReference{Name: backup.Name, UID: string(backup.UID)}, RepositorySecretRef: backup.Spec.RepositorySecretRef,
		},
		ID: artifactID, FormatVersion: platformdata.BackupFormatVersion, ManifestDigest: "sha256:" + strings.Repeat("a", 64),
		SizeBytes: 128, PathCount: 1, CreatedAt: created,
		Verification: arcadev1alpha1.ArtifactVerification{Result: arcadev1alpha1.VerificationVerified, VerifiedAt: &verified},
	}
}

func backupWorkerPod(name string, uid types.UID, namespace string, backupUID types.UID, jobName string, jobUID types.UID) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: namespace, UID: uid,
			Labels: map[string]string{platformkube.LabelBackupUID: string(backupUID)},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "batch/v1", Kind: "Job", Name: jobName, UID: jobUID, Controller: boolPointer(true),
			}},
		},
		Spec: corev1.PodSpec{
			RestartPolicy: corev1.RestartPolicyNever,
			Containers:    []corev1.Container{{Name: "backup-worker", Image: testWorkerImage}},
			Volumes: []corev1.Volume{{
				Name: "world", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
					ClaimName: "factory-factorio-world", ReadOnly: true,
				}},
			}},
		},
	}
}

func assignBackupJobUID(t *testing.T, kubeClient client.Client, namespace string, backupUID, jobUID types.UID) *batchv1.Job {
	t.Helper()
	job := &batchv1.Job{}
	key := types.NamespacedName{Namespace: namespace, Name: platformkube.BackupResourceName(backupUID)}
	if err := kubeClient.Get(context.Background(), key, job); err != nil {
		t.Fatalf("get backup Job: %v", err)
	}
	job.UID = jobUID
	if err := kubeClient.Update(context.Background(), job); err != nil {
		t.Fatalf("assign backup Job UID: %v", err)
	}
	if err := kubeClient.Get(context.Background(), key, job); err != nil {
		t.Fatalf("refresh backup Job: %v", err)
	}
	return job
}

func gatedBackupPod(job *batchv1.Job, name string, uid types.UID) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: job.Namespace, UID: uid,
			Labels: cloneStringMap(job.Spec.Template.Labels), Annotations: cloneStringMap(job.Spec.Template.Annotations),
			OwnerReferences: []metav1.OwnerReference{{APIVersion: "batch/v1", Kind: "Job", Name: job.Name, UID: job.UID, Controller: boolPointer(true), BlockOwnerDeletion: boolPointer(true)}},
		},
		Spec: *job.Spec.Template.Spec.DeepCopy(),
	}
}

func admittedBackupPod(job *batchv1.Job, name string, uid types.UID) *corev1.Pod {
	pod := gatedBackupPod(job, name, uid)
	pod.Spec.SchedulingGates = nil
	pod.Annotations[platformkube.AnnotationBackupPodAuthorized] = string(uid)
	return pod
}

func backupLease(t *testing.T, kubeClient client.Client, namespace string, backupUID types.UID) *coordinationv1.Lease {
	t.Helper()
	leases := &coordinationv1.LeaseList{}
	if err := kubeClient.List(context.Background(), leases, client.InNamespace(namespace), client.MatchingLabels{platformkube.LabelBackupUID: string(backupUID)}); err != nil {
		t.Fatalf("list backup leases: %v", err)
	}
	if len(leases.Items) != 1 {
		t.Fatalf("backup leases = %d, want 1", len(leases.Items))
	}
	return leases.Items[0].DeepCopy()
}

func boolPointer(value bool) *bool { return &value }

func stringPointer(value string) *string { return &value }
