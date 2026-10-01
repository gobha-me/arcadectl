// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"

	arcadev1alpha1 "github.com/gobha-me/arcadectl/api/v1alpha1"
	platformdata "github.com/gobha-me/arcadectl/internal/platform/data"
	"github.com/gobha-me/arcadectl/internal/platform/game"
	platformkube "github.com/gobha-me/arcadectl/internal/platform/kube"
	batchv1 "k8s.io/api/batch/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	storagev1 "k8s.io/api/storage/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	backupRequeue     = time.Second
	maxBackupAttempts = int32(3)
)

var backupConditionOrder = []string{
	arcadev1alpha1.ConditionOperationAccepted,
	arcadev1alpha1.ConditionSourceReady,
	arcadev1alpha1.ConditionArtifactReady,
	arcadev1alpha1.ConditionVerified,
	arcadev1alpha1.ConditionOperationComplete,
}

// GameBackupReconciler turns one immutable operation into one cold,
// repository-verified artifact without ever mutating or deleting source PVCs.
type GameBackupReconciler struct {
	client.Client
	APIReader   client.Reader
	Scheme      *runtime.Scheme
	Catalog     DefinitionCatalog
	WorkerImage string
	Now         func() metav1.Time
}

// +kubebuilder:rbac:groups=arcade.gobha.me,resources=gamebackups,verbs=get;list;watch;update;patch,namespace=arcadectl-system
// +kubebuilder:rbac:groups=arcade.gobha.me,resources=gamebackups/status,verbs=get;update;patch,namespace=arcadectl-system
// +kubebuilder:rbac:groups=arcade.gobha.me,resources=gameservers,verbs=get;list;watch;update;patch,namespace=arcadectl-system
// Secret get is the Kubernetes RBAC delegation ceiling required to create each narrower resourceName-scoped worker Role; controller code never reads Secrets.
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get,namespace=arcadectl-system
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch;update,namespace=arcadectl-system
// +kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=get;list;watch;create;delete,namespace=arcadectl-system
// +kubebuilder:rbac:groups=batch,resources=jobs,verbs=get;list;watch;create;update;delete,namespace=arcadectl-system
// +kubebuilder:rbac:groups=coordination.k8s.io,resources=leases,verbs=get;list;watch;create;update;delete,namespace=arcadectl-system
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=roles;rolebindings,verbs=get;list;watch;create;delete,namespace=arcadectl-system

func (r *GameBackupReconciler) Reconcile(ctx context.Context, request ctrl.Request) (ctrl.Result, error) {
	backup := &arcadev1alpha1.GameBackup{}
	if err := r.Get(ctx, request.NamespacedName, backup); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !backup.DeletionTimestamp.IsZero() {
		return r.finalize(ctx, backup)
	}
	if !slices.Contains(backup.Finalizers, platformkube.BackupFinalizer) {
		updated := backup.DeepCopy()
		updated.Finalizers = append(updated.Finalizers, platformkube.BackupFinalizer)
		if err := r.Update(ctx, updated); err != nil {
			return ctrl.Result{}, errors.New("protect GameBackup before external work failed; inspect Kubernetes API availability")
		}
		return ctrl.Result{Requeue: true}, nil
	}
	if backup.Status.Phase == arcadev1alpha1.DataPhaseSucceeded || backup.Status.Phase == arcadev1alpha1.DataPhaseFailed || backup.Status.Phase == arcadev1alpha1.DataPhaseCancelled {
		if err := r.releaseLeases(ctx, backup); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}
	if backup.Spec.CancelRequested {
		return r.cancel(ctx, backup)
	}
	if backup.Status.Phase == "" {
		return ctrl.Result{}, r.writeStatus(ctx, backup, arcadev1alpha1.DataPhasePending, func(updated *arcadev1alpha1.GameBackup) {
			setBackupCondition(updated, arcadev1alpha1.ConditionOperationAccepted, metav1.ConditionTrue, arcadev1alpha1.ReasonOperationAccepted, "the immutable cold-backup request was accepted", r.now())
		})
	}
	if backup.Status.Phase == arcadev1alpha1.DataPhaseVerifying {
		if pending, err := r.deleteWorkerAndWait(ctx, backup); err != nil || pending {
			return ctrl.Result{RequeueAfter: backupRequeue}, err
		}
		if backup.Status.Artifact != nil {
			return r.finishSuccess(ctx, backup, nil)
		}
		reason, message := pendingBackupFailure(backup)
		return r.finishFailure(ctx, backup, nil, reason, message)
	}

	server, definition, plan, source, issue := r.resolveSource(ctx, backup)
	if issue != nil {
		if backup.Status.Fence != nil {
			return r.abortActive(ctx, backup, issue.reason, issue.message)
		}
		return r.reportBlocked(ctx, backup, issue.reason, issue.message)
	}
	if err := r.acquireLease(ctx, backup, plan.DataIdentity, server.Name); err != nil {
		if errors.Is(err, errBackupOperationConflict) {
			return r.reportBlocked(ctx, backup, arcadev1alpha1.ReasonOperationConflict, "another data operation owns this retained world; wait for it to become terminal")
		}
		return ctrl.Result{}, err
	}
	if backup.Status.Phase == arcadev1alpha1.DataPhasePending || backup.Status.Phase == arcadev1alpha1.DataPhaseBlocked {
		return ctrl.Result{}, r.writeStatus(ctx, backup, arcadev1alpha1.DataPhasePreparing, func(updated *arcadev1alpha1.GameBackup) {
			if updated.Status.StartedAt == nil {
				now := r.now()
				updated.Status.StartedAt = &now
			}
			if updated.Status.Source == nil {
				updated.Status.Source = source.DeepCopy()
			}
			setBackupCondition(updated, arcadev1alpha1.ConditionSourceReady, metav1.ConditionUnknown, arcadev1alpha1.ReasonColdStopPending, "waiting for the exact source workload to stop and release every declared path", r.now())
		})
	}
	if backup.Status.Source == nil || !apiequality.Semantic.DeepEqual(backup.Status.Source, source) {
		return r.abortActive(ctx, backup, arcadev1alpha1.ReasonIdentityMismatch, "the live source no longer matches the immutable backup manifest; the worker was stopped")
	}

	if backup.Status.Fence == nil {
		if backup.Spec.Source.DesiredState == arcadev1alpha1.DesiredStateRunning && server.Spec.DesiredState == arcadev1alpha1.DesiredStateRunning {
			updated := server.DeepCopy()
			updated.Spec.DesiredState = arcadev1alpha1.DesiredStateStopped
			if err := r.Update(ctx, updated); err != nil {
				return ctrl.Result{}, errors.New("request exact cold stop failed; inspect Kubernetes API availability")
			}
			return ctrl.Result{RequeueAfter: backupRequeue}, nil
		}
		expectedGeneration := backup.Spec.Source.Generation
		if backup.Spec.Source.DesiredState == arcadev1alpha1.DesiredStateRunning {
			expectedGeneration++
		}
		if server.Generation != expectedGeneration || server.Spec.DesiredState != arcadev1alpha1.DesiredStateStopped ||
			server.Status.ObservedGeneration != expectedGeneration || server.Status.Phase != arcadev1alpha1.PhaseStopped {
			return r.hold(ctx, backup, arcadev1alpha1.ReasonColdStopPending, "waiting for the exact stopped GameServer generation to be observed")
		}
		clear, err := r.sourceClaimsUnmounted(ctx, backup.Namespace, source.Paths)
		if err != nil {
			return ctrl.Result{}, err
		}
		if !clear {
			return r.hold(ctx, backup, arcadev1alpha1.ReasonColdStopPending, "waiting for every pod using the source claims to terminate before the worker can mount them")
		}
		return ctrl.Result{}, r.writeStatus(ctx, backup, arcadev1alpha1.DataPhasePreparing, func(updated *arcadev1alpha1.GameBackup) {
			now := r.now()
			updated.Status.Fence = &arcadev1alpha1.ColdDataFence{
				GameServer: arcadev1alpha1.ExactGameServerReference{
					ExactLocalReference: backup.Spec.Source.ExactLocalReference,
					Generation:          expectedGeneration, DesiredState: arcadev1alpha1.DesiredStateStopped,
				},
				EstablishedAt: now,
			}
			setBackupCondition(updated, arcadev1alpha1.ConditionSourceReady, metav1.ConditionTrue, arcadev1alpha1.ReasonOperationAccepted, "the exact source is cold and every declared path is available to the read-only worker", now)
		})
	}

	if server.Generation != backup.Status.Fence.GameServer.Generation || server.Spec.DesiredState != arcadev1alpha1.DesiredStateStopped {
		return r.abortActive(ctx, backup, arcadev1alpha1.ReasonIdentityMismatch, "the fenced GameServer generation changed; the worker was stopped and the server must remain offline")
	}
	if backup.Status.Phase == arcadev1alpha1.DataPhaseRunning && backupConditionReason(backup, arcadev1alpha1.ConditionArtifactReady) == arcadev1alpha1.ReasonWorkerRetrying {
		if pending, err := r.deleteWorkerAndWait(ctx, backup); err != nil || pending {
			return ctrl.Result{RequeueAfter: backupRequeue}, err
		}
		if backup.Status.Attempts >= maxBackupAttempts {
			return r.markFailure(ctx, backup, arcadev1alpha1.ReasonWorkerFailed, "the bounded backup worker exhausted its retry limit without publishing an artifact")
		}
		if err := r.clearWorkerExecution(ctx, backup); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, r.writeStatus(ctx, backup, arcadev1alpha1.DataPhaseRunning, func(updated *arcadev1alpha1.GameBackup) {
			updated.Status.Attempts++
			setBackupCondition(updated, arcadev1alpha1.ConditionArtifactReady, metav1.ConditionUnknown, arcadev1alpha1.ReasonColdStopPending, "the prior worker is absent and a serialized retry is ready", r.now())
		})
	}
	artifactID, err := platformdata.ArtifactID(backup.UID)
	if err != nil {
		return ctrl.Result{}, errors.New("derive deterministic backup artifact failed")
	}
	resources, err := platformkube.BuildBackupResources(
		backup, *source, artifactID, r.WorkerImage, platformkube.DataOperationLeaseName(plan.DataIdentity), definition.RuntimeIdentity,
	)
	if err != nil {
		return ctrl.Result{}, errors.New("build bounded backup worker failed; inspect controller configuration")
	}
	if err := r.reconcileBackupInput(ctx, backup, resources.Input); err != nil {
		return ctrl.Result{}, err
	}
	authorityChanged, err := r.reconcileBackupAuthority(ctx, backup, resources)
	if err != nil {
		return ctrl.Result{}, err
	}
	job, jobCreated, err := r.reconcileBackupJob(ctx, backup, resources.Job)
	if err != nil {
		if errors.Is(err, errBackupWorkerOrphaned) {
			return r.hold(ctx, backup, arcadev1alpha1.ReasonOperationConflict, "a prior backup worker pod still exists; no replacement worker will start until it is gone")
		}
		return ctrl.Result{}, err
	}
	// Every executable object is created inert. A later reconciliation must
	// read back and exactly validate admission results before removing either
	// execution gate.
	if authorityChanged || jobCreated {
		return ctrl.Result{Requeue: true}, nil
	}
	if job.Spec.Suspend == nil || *job.Spec.Suspend {
		updated := job.DeepCopy()
		updated.Spec.Suspend = ptr.To(false)
		if err := r.Update(ctx, updated); err != nil {
			return ctrl.Result{}, errors.New("activate validated backup worker Job failed; inspect Kubernetes API availability")
		}
		return ctrl.Result{Requeue: true}, nil
	}
	if backup.Status.Phase == arcadev1alpha1.DataPhasePreparing {
		return ctrl.Result{}, r.writeStatus(ctx, backup, arcadev1alpha1.DataPhaseRunning, func(updated *arcadev1alpha1.GameBackup) {
			updated.Status.Attempts++
			setBackupCondition(updated, arcadev1alpha1.ConditionArtifactReady, metav1.ConditionUnknown, arcadev1alpha1.ReasonColdStopPending, "the admitted worker Pod is awaiting exact validation before execution", r.now())
		})
	}

	if backup.Status.Phase == arcadev1alpha1.DataPhaseRunning {
		// A deadline failure can remove every Job Pod. Inspect the durable Job
		// result before waiting for Pod admission, or it would hold data forever.
		if jobFailed(job) {
			reason := r.workerFailureReason(ctx, backup, job)
			if reason == arcadev1alpha1.ReasonWorkerFailed && backup.Status.Attempts < maxBackupAttempts {
				return ctrl.Result{}, r.writeStatus(ctx, backup, arcadev1alpha1.DataPhaseRunning, func(updated *arcadev1alpha1.GameBackup) {
					setBackupCondition(updated, arcadev1alpha1.ConditionArtifactReady, metav1.ConditionUnknown, arcadev1alpha1.ReasonWorkerRetrying, "the interrupted worker will be removed before a serialized retry starts", r.now())
				})
			}
			message := "the bounded backup worker failed; inspect repository availability and create a new operation after correction"
			if reason == arcadev1alpha1.ReasonVerificationFailed {
				message = "repository-side verification failed; the incomplete artifact is not usable"
			} else if reason == arcadev1alpha1.ReasonSecretUnavailable {
				message = "the immutable repository Secret does not satisfy the documented S3 key contract; create a corrected Secret and new operation"
			}
			return r.markFailure(ctx, backup, reason, message)
		}
		podState, err := r.authorizeBackupWorkerPod(ctx, backup, job)
		if err != nil {
			return ctrl.Result{}, err
		}
		switch podState {
		case backupPodPending:
			return ctrl.Result{RequeueAfter: backupRequeue}, nil
		case backupPodOverlap:
			return ctrl.Result{}, r.writeStatus(ctx, backup, arcadev1alpha1.DataPhaseRunning, func(updated *arcadev1alpha1.GameBackup) {
				setBackupCondition(updated, arcadev1alpha1.ConditionArtifactReady, metav1.ConditionUnknown, arcadev1alpha1.ReasonWorkerRetrying, "overlapping worker Pods remained gated and will all be removed before a serialized retry", r.now())
			})
		case backupPodChanged:
			return r.abortActive(ctx, backup, arcadev1alpha1.ReasonOperationConflict, "the admitted worker Pod did not match the exact gated template; it was never authorized to execute")
		}
		mountState, err := r.sourceClaimMountState(ctx, backup.Namespace, source.Paths, backup.UID, job)
		if err != nil {
			return ctrl.Result{}, err
		}
		if mountState == backupMountForeign {
			return r.abortActive(ctx, backup, arcadev1alpha1.ReasonOperationConflict, "another pod mounted the cold source claims; the backup worker was stopped without publishing an artifact")
		}
		if mountState == backupMountOverlap {
			return ctrl.Result{}, r.writeStatus(ctx, backup, arcadev1alpha1.DataPhaseRunning, func(updated *arcadev1alpha1.GameBackup) {
				setBackupCondition(updated, arcadev1alpha1.ConditionArtifactReady, metav1.ConditionUnknown, arcadev1alpha1.ReasonWorkerRetrying, "overlapping worker pods were denied credentials and will all be removed before a serialized retry", r.now())
			})
		}
		if jobComplete(job) {
			result, err := r.workerResult(ctx, backup, job)
			if err != nil {
				if errors.Is(err, errBackupWorkerResultPending) {
					return ctrl.Result{RequeueAfter: backupRequeue}, nil
				}
				return r.markFailure(ctx, backup, arcadev1alpha1.ReasonVerificationFailed, "the worker result could not prove a complete repository-verified artifact")
			}
			if result.ArtifactID != artifactID || result.PathCount != int32(len(source.Paths)) || !strings.HasPrefix(result.ManifestDigest, "sha256:") {
				return r.markFailure(ctx, backup, arcadev1alpha1.ReasonVerificationFailed, "the worker result did not match the exact requested artifact and path set")
			}
			return ctrl.Result{}, r.writeStatus(ctx, backup, arcadev1alpha1.DataPhaseVerifying, func(updated *arcadev1alpha1.GameBackup) {
				createdAt := metav1.NewTime(result.CreatedAt)
				verifiedAt := metav1.NewTime(result.VerifiedAt)
				updated.Status.Artifact = &arcadev1alpha1.BackupArtifact{
					Provenance: arcadev1alpha1.ArtifactProvenance{
						BackupRef:           arcadev1alpha1.ExactLocalReference{Name: backup.Name, UID: string(backup.UID)},
						RepositorySecretRef: backup.Spec.RepositorySecretRef,
					},
					ID: artifactID, FormatVersion: result.Version, ManifestDigest: result.ManifestDigest,
					SizeBytes: result.SizeBytes, PathCount: result.PathCount, CreatedAt: createdAt,
					Verification: arcadev1alpha1.ArtifactVerification{Result: arcadev1alpha1.VerificationVerified, VerifiedAt: &verifiedAt},
				}
				setBackupCondition(updated, arcadev1alpha1.ConditionArtifactReady, metav1.ConditionTrue, arcadev1alpha1.ReasonOperationCompleted, "the deterministic repository artifact is complete", r.now())
				setBackupCondition(updated, arcadev1alpha1.ConditionVerified, metav1.ConditionTrue, arcadev1alpha1.ReasonOperationCompleted, "repository-side verification covered every declared persistent path", r.now())
			})
		}
		return ctrl.Result{RequeueAfter: backupRequeue}, nil
	}
	return ctrl.Result{RequeueAfter: backupRequeue}, nil
}

func (r *GameBackupReconciler) workerTerminalOrAbsent(ctx context.Context, backup *arcadev1alpha1.GameBackup) (bool, error) {
	job := &batchv1.Job{}
	key := types.NamespacedName{Namespace: backup.Namespace, Name: platformkube.BackupResourceName(backup.UID)}
	if err := r.directReader().Get(ctx, key, job); err != nil {
		if !apierrors.IsNotFound(err) {
			return false, errors.New("inspect bounded backup worker failed; inspect Kubernetes API availability")
		}
		pods := &corev1.PodList{}
		if err := r.directReader().List(ctx, pods, client.InNamespace(backup.Namespace), client.MatchingLabels{platformkube.LabelBackupUID: string(backup.UID)}); err != nil {
			return false, errors.New("verify backup worker absence failed; inspect Kubernetes API availability")
		}
		return len(pods.Items) == 0, nil
	}
	if !controlledBy(job.OwnerReferences, "GameBackup", backup.Name, backup.UID) {
		return false, errors.New("backup worker Job ownership changed; inspect namespace ownership")
	}
	return jobComplete(job) || jobFailed(job), nil
}

func (r *GameBackupReconciler) abortActive(ctx context.Context, backup *arcadev1alpha1.GameBackup, reason, message string) (ctrl.Result, error) {
	pending, err := r.deleteWorkerAndWait(ctx, backup)
	if err != nil {
		return ctrl.Result{}, err
	}
	if pending {
		return ctrl.Result{RequeueAfter: backupRequeue}, nil
	}
	return r.markFailure(ctx, backup, reason, message)
}

func (r *GameBackupReconciler) markFailure(ctx context.Context, backup *arcadev1alpha1.GameBackup, reason, message string) (ctrl.Result, error) {
	err := r.writeStatus(ctx, backup, arcadev1alpha1.DataPhaseVerifying, func(updated *arcadev1alpha1.GameBackup) {
		updated.Status.Artifact = nil
		setBackupCondition(updated, arcadev1alpha1.ConditionOperationComplete, metav1.ConditionFalse, reason, message, r.now())
	})
	if err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{Requeue: true}, nil
}

func pendingBackupFailure(backup *arcadev1alpha1.GameBackup) (string, string) {
	for _, condition := range backup.Status.Conditions {
		if condition.Type == arcadev1alpha1.ConditionOperationComplete && condition.Status == metav1.ConditionFalse {
			return condition.Reason, condition.Message
		}
	}
	return arcadev1alpha1.ReasonWorkerFailed, "backup work ended without a verified artifact; create a new operation after inspection"
}

type backupIssue struct{ reason, message string }

func (r *GameBackupReconciler) resolveSource(ctx context.Context, backup *arcadev1alpha1.GameBackup) (*arcadev1alpha1.GameServer, game.Definition, platformkube.Plan, *arcadev1alpha1.DataSourceSnapshot, *backupIssue) {
	server := &arcadev1alpha1.GameServer{}
	key := types.NamespacedName{Namespace: backup.Namespace, Name: backup.Spec.Source.Name}
	if err := r.directReader().Get(ctx, key, server); err != nil {
		return nil, game.Definition{}, platformkube.Plan{}, nil, &backupIssue{arcadev1alpha1.ReasonInvalidReference, "the exact source GameServer is unavailable; restore it or create a new operation"}
	}
	if string(server.UID) != backup.Spec.Source.UID {
		return nil, game.Definition{}, platformkube.Plan{}, nil, &backupIssue{arcadev1alpha1.ReasonIdentityMismatch, "the source GameServer name now identifies a different object; create a new operation for the intended server"}
	}
	if backup.Status.Fence == nil {
		exactRequest := server.Generation == backup.Spec.Source.Generation && server.Spec.DesiredState == backup.Spec.Source.DesiredState
		operationStop := backup.Status.Source != nil && backup.Spec.Source.DesiredState == arcadev1alpha1.DesiredStateRunning &&
			server.Generation == backup.Spec.Source.Generation+1 && server.Spec.DesiredState == arcadev1alpha1.DesiredStateStopped
		if !exactRequest && !operationStop {
			return nil, game.Definition{}, platformkube.Plan{}, nil, &backupIssue{arcadev1alpha1.ReasonIdentityMismatch, "the source GameServer generation no longer matches the request; create a new operation from current state"}
		}
	}
	definition, err := r.Catalog.Get(server.Spec.Game)
	if err != nil || !definition.Capabilities.ColdBackup {
		return nil, game.Definition{}, platformkube.Plan{}, nil, &backupIssue{arcadev1alpha1.ReasonInvalidReference, "the installed adapter does not certify cold backup for this game"}
	}
	plan, err := platformkube.Build(server, definition)
	if err != nil {
		return nil, game.Definition{}, platformkube.Plan{}, nil, &backupIssue{arcadev1alpha1.ReasonIdentityMismatch, "the current source no longer satisfies its certified adapter contract"}
	}
	settingsDigest, err := definition.SettingsDigest(server.Spec.Settings.Raw)
	if err != nil {
		return nil, game.Definition{}, platformkube.Plan{}, nil, &backupIssue{arcadev1alpha1.ReasonIdentityMismatch, "the current source settings no longer satisfy the certified adapter contract"}
	}
	paths := make([]arcadev1alpha1.DataPathIdentity, 0, len(plan.DataClaims))
	pathMounts := make(map[string]string, len(definition.PersistentPaths))
	for _, path := range definition.PersistentPaths {
		pathMounts[path.Name] = path.MountPath
	}
	for _, claim := range plan.DataClaims {
		actual := &corev1.PersistentVolumeClaim{}
		if err := r.directReader().Get(ctx, client.ObjectKeyFromObject(claim.Desired), actual); err != nil || validateExistingDataClaim(actual, claim) != nil || actual.Status.Phase != corev1.ClaimBound || actual.Spec.VolumeName == "" {
			return nil, game.Definition{}, platformkube.Plan{}, nil, &backupIssue{arcadev1alpha1.ReasonIdentityMismatch, "every declared source claim must remain bound with its exact retained identity"}
		}
		pathName := claim.Desired.Labels[platformkube.LabelDataPath]
		paths = append(paths, arcadev1alpha1.DataPathIdentity{
			Name: pathName, MountPath: pathMounts[pathName],
			ClaimRef: arcadev1alpha1.ExactLocalReference{Name: actual.Name, UID: string(actual.UID)},
		})
	}
	currentData := &arcadev1alpha1.RetainedDataReference{Identity: plan.DataIdentity, Claims: make([]arcadev1alpha1.RetainedDataClaimReference, 0, len(paths))}
	for _, path := range paths {
		currentData.Claims = append(currentData.Claims, arcadev1alpha1.RetainedDataClaimReference{Path: path.Name, ClaimRef: path.ClaimRef})
	}
	if server.Status.ActiveData != nil && (!sameDataSelection(backup.Spec.SourceData, server.Status.ActiveData) ||
		!sameDataSelection(server.Status.ObservedData, server.Status.ActiveData)) {
		return nil, game.Definition{}, platformkube.Plan{}, nil, &backupIssue{arcadev1alpha1.ReasonIdentityMismatch, "the source selected data changed or is not yet observed; create a pinned request from current exact claims"}
	}
	if backup.Spec.SourceData != nil && !sameDataSelection(backup.Spec.SourceData, currentData) {
		return nil, game.Definition{}, platformkube.Plan{}, nil, &backupIssue{arcadev1alpha1.ReasonIdentityMismatch, "the source claims no longer match the immutable request data selection"}
	}
	slices.SortFunc(paths, func(left, right arcadev1alpha1.DataPathIdentity) int { return strings.Compare(left.Name, right.Name) })
	source := &arcadev1alpha1.DataSourceSnapshot{
		GameServer: backup.Spec.Source, Game: server.Spec.Game, ImageDigest: server.Spec.ImageDigest,
		SettingsDigest: settingsDigest, Paths: paths,
	}
	return server, definition, plan, source, nil
}

var errBackupOperationConflict = errors.New("retained data is locked by another operation")
var errBackupWorkerOrphaned = errors.New("prior backup worker pod still exists")
var errBackupWorkerResultPending = errors.New("backup worker result is not visible yet")

func (r *GameBackupReconciler) acquireLease(ctx context.Context, backup *arcadev1alpha1.GameBackup, dataIdentity, serverName string) error {
	name := platformkube.DataOperationLeaseName(dataIdentity)
	key := types.NamespacedName{Namespace: backup.Namespace, Name: name}
	existing := &coordinationv1.Lease{}
	if err := r.directReader().Get(ctx, key, existing); err != nil {
		if !apierrors.IsNotFound(err) {
			return errors.New("inspect retained-data operation lease failed; inspect Kubernetes API availability")
		}
		now := metav1.NewMicroTime(r.now().Time)
		lease := &coordinationv1.Lease{
			ObjectMeta: metav1.ObjectMeta{
				Name: name, Namespace: backup.Namespace,
				Labels: map[string]string{
					platformkube.LabelManagedBy:    platformkube.ManagerName,
					platformkube.LabelDataIdentity: dataIdentity,
					platformkube.LabelBackupUID:    string(backup.UID),
					platformkube.LabelInstance:     serverName,
				},
				Annotations: map[string]string{platformkube.AnnotationBackupName: backup.Name},
			},
			Spec: coordinationv1.LeaseSpec{HolderIdentity: ptr.To(string(backup.UID)), AcquireTime: &now},
		}
		if err := r.Create(ctx, lease); err != nil {
			if apierrors.IsAlreadyExists(err) {
				return errBackupOperationConflict
			}
			return errors.New("create retained-data operation lease failed; inspect Kubernetes API availability")
		}
		return nil
	}
	operation := arcadev1alpha1.ExactLocalReference{Name: backup.Name, UID: string(backup.UID)}
	if existing.Labels[platformkube.LabelDataIdentity] != dataIdentity ||
		!platformkube.BackupOperationLeaseMatches(existing, operation, serverName) {
		return errBackupOperationConflict
	}
	return nil
}

func controlledBy(references []metav1.OwnerReference, kind, name string, uid types.UID) bool {
	for _, reference := range references {
		if reference.Controller != nil && *reference.Controller && reference.Kind == kind && reference.Name == name && reference.UID == uid {
			return true
		}
	}
	return false
}

func (r *GameBackupReconciler) sourceClaimsUnmounted(ctx context.Context, namespace string, paths []arcadev1alpha1.DataPathIdentity) (bool, error) {
	unmounted, err := r.sourceClaimsMountedOnlyBy(ctx, namespace, paths, func(*corev1.Pod) bool { return false })
	if err != nil || !unmounted {
		return unmounted, err
	}
	volumeNames := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		claim := &corev1.PersistentVolumeClaim{}
		key := types.NamespacedName{Namespace: namespace, Name: path.ClaimRef.Name}
		if err := r.directReader().Get(ctx, key, claim); err != nil || string(claim.UID) != path.ClaimRef.UID || claim.Spec.VolumeName == "" {
			return false, errors.New("verify exact source claim attachment failed; inspect retained storage identity")
		}
		volumeNames[claim.Spec.VolumeName] = struct{}{}
	}
	attachments := &storagev1.VolumeAttachmentList{}
	if err := r.directReader().List(ctx, attachments); err != nil {
		return false, errors.New("inspect source volume attachments failed; inspect Kubernetes API availability")
	}
	for i := range attachments.Items {
		attachment := &attachments.Items[i]
		if attachment.Spec.Source.PersistentVolumeName == nil || !attachment.Status.Attached {
			continue
		}
		if _, source := volumeNames[*attachment.Spec.Source.PersistentVolumeName]; source {
			return false, nil
		}
	}
	return true, nil
}

type backupMountState int

const (
	backupMountClear backupMountState = iota
	backupMountExclusive
	backupMountOverlap
	backupMountForeign
)

type backupPodState int

const (
	backupPodPending backupPodState = iota
	backupPodAuthorized
	backupPodOverlap
	backupPodChanged
)

// authorizeBackupWorkerPod is the second half of the execution gate. The Job
// is first admitted while suspended. Its Pod is then admitted with a scheduling
// gate, compared exactly with the stored Job template, and only that exact Pod
// UID is annotated and ungated. PodSpec is immutable after this update except
// for scheduler-owned fields, so admission-injected containers or mounts never
// receive credentials or source volumes on a node.
func (r *GameBackupReconciler) authorizeBackupWorkerPod(ctx context.Context, backup *arcadev1alpha1.GameBackup, job *batchv1.Job) (backupPodState, error) {
	pods := &corev1.PodList{}
	if err := r.directReader().List(ctx, pods, client.InNamespace(backup.Namespace), client.MatchingLabels{platformkube.LabelBackupUID: string(backup.UID)}); err != nil {
		return backupPodPending, errors.New("inspect admitted backup worker Pod failed; inspect Kubernetes API availability")
	}
	if len(pods.Items) == 0 {
		return backupPodPending, nil
	}
	if len(pods.Items) != 1 {
		return backupPodOverlap, nil
	}
	pod := &pods.Items[0]
	if !backupPodIdentityMatches(job, pod) {
		return backupPodChanged, nil
	}
	authorizedUID := pod.Annotations[platformkube.AnnotationBackupPodAuthorized]
	if authorizedUID != "" {
		if authorizedUID != string(pod.UID) || len(pod.Spec.SchedulingGates) != 0 {
			return backupPodChanged, nil
		}
		return backupPodAuthorized, nil
	}
	if pod.Spec.NodeName != "" || (pod.Status.Phase != "" && pod.Status.Phase != corev1.PodPending) ||
		len(pod.Status.InitContainerStatuses) != 0 || len(pod.Status.ContainerStatuses) != 0 || !backupPodSpecMatches(job, pod) {
		return backupPodChanged, nil
	}
	updated := pod.DeepCopy()
	if updated.Annotations == nil {
		updated.Annotations = make(map[string]string)
	}
	updated.Annotations[platformkube.AnnotationBackupPodAuthorized] = string(pod.UID)
	updated.Spec.SchedulingGates = nil
	if err := r.Update(ctx, updated); err != nil {
		return backupPodPending, errors.New("authorize exact backup worker Pod failed; inspect Kubernetes API availability")
	}
	return backupPodPending, nil
}

func backupPodIdentityMatches(job *batchv1.Job, pod *corev1.Pod) bool {
	if job == nil || pod == nil || job.UID == "" || pod.UID == "" || pod.Namespace != job.Namespace || !pod.DeletionTimestamp.IsZero() ||
		len(pod.OwnerReferences) != 1 || !controlledBy(pod.OwnerReferences, "Job", job.Name, job.UID) ||
		!apiequality.Semantic.DeepEqual(pod.Labels, job.Spec.Template.Labels) {
		return false
	}
	return workerPodAnnotationsMatch(pod.Annotations, job.Spec.Template.Annotations, platformkube.AnnotationBackupPodAuthorized)
}

func backupPodSpecMatches(job *batchv1.Job, pod *corev1.Pod) bool {
	if job == nil || pod == nil || len(pod.Spec.SchedulingGates) != 1 || pod.Spec.SchedulingGates[0].Name != platformkube.BackupSchedulingGate {
		return false
	}
	desired := job.Spec.Template.Spec.DeepCopy()
	existing := pod.Spec.DeepCopy()
	normalizeBackupPodDefaults(desired)
	normalizeBackupPodDefaults(existing)
	return apiequality.Semantic.DeepEqual(desired, existing)
}

func normalizeBackupPodDefaults(pod *corev1.PodSpec) {
	if pod.DeprecatedServiceAccount == pod.ServiceAccountName {
		pod.DeprecatedServiceAccount = ""
	}
	if pod.DNSPolicy == corev1.DNSClusterFirst {
		pod.DNSPolicy = ""
	}
	if pod.TerminationGracePeriodSeconds != nil && *pod.TerminationGracePeriodSeconds == corev1.DefaultTerminationGracePeriodSeconds {
		pod.TerminationGracePeriodSeconds = nil
	}
	if pod.SchedulerName == corev1.DefaultSchedulerName {
		pod.SchedulerName = ""
	}
	if pod.EnableServiceLinks != nil && *pod.EnableServiceLinks {
		pod.EnableServiceLinks = nil
	}
	if pod.Priority != nil && *pod.Priority == 0 {
		pod.Priority = nil
	}
	if pod.PreemptionPolicy != nil && *pod.PreemptionPolicy == corev1.PreemptLowerPriority {
		pod.PreemptionPolicy = nil
	}
	pod.Tolerations = slices.DeleteFunc(pod.Tolerations, isDefaultNoExecuteToleration)
	for index := range pod.InitContainers {
		normalizeBackupContainerDefaults(&pod.InitContainers[index])
	}
	for index := range pod.Containers {
		normalizeBackupContainerDefaults(&pod.Containers[index])
	}
}

func isDefaultNoExecuteToleration(toleration corev1.Toleration) bool {
	if toleration.Operator != corev1.TolerationOpExists || toleration.Effect != corev1.TaintEffectNoExecute || toleration.TolerationSeconds == nil || *toleration.TolerationSeconds != 300 || toleration.Value != "" {
		return false
	}
	return toleration.Key == corev1.TaintNodeNotReady || toleration.Key == corev1.TaintNodeUnreachable
}

func cloneStringMap(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

func (r *GameBackupReconciler) sourceClaimMountState(ctx context.Context, namespace string, paths []arcadev1alpha1.DataPathIdentity, backupUID types.UID, job *batchv1.Job) (backupMountState, error) {
	claimNames := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		claimNames[path.ClaimRef.Name] = struct{}{}
	}
	pods := &corev1.PodList{}
	if err := r.directReader().List(ctx, pods, client.InNamespace(namespace)); err != nil {
		return backupMountClear, errors.New("inspect source claim mounts failed; inspect Kubernetes API availability")
	}
	workers := make(map[types.UID]struct{})
	for i := range pods.Items {
		pod := &pods.Items[i]
		mountsSource := false
		for _, volume := range pod.Spec.Volumes {
			if volume.PersistentVolumeClaim != nil {
				_, mountsSource = claimNames[volume.PersistentVolumeClaim.ClaimName]
				if mountsSource {
					break
				}
			}
		}
		if !mountsSource {
			continue
		}
		if pod.Labels[platformkube.LabelBackupUID] != string(backupUID) || !controlledBy(pod.OwnerReferences, "Job", job.Name, job.UID) ||
			pod.UID == "" || pod.Annotations[platformkube.AnnotationBackupPodAuthorized] != string(pod.UID) {
			return backupMountForeign, nil
		}
		workers[pod.UID] = struct{}{}
	}
	switch len(workers) {
	case 0:
		return backupMountClear, nil
	case 1:
		return backupMountExclusive, nil
	default:
		return backupMountOverlap, nil
	}
}

func (r *GameBackupReconciler) sourceClaimsMountedOnlyBy(ctx context.Context, namespace string, paths []arcadev1alpha1.DataPathIdentity, allowed func(*corev1.Pod) bool) (bool, error) {
	claimNames := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		claimNames[path.ClaimRef.Name] = struct{}{}
	}
	pods := &corev1.PodList{}
	if err := r.directReader().List(ctx, pods, client.InNamespace(namespace)); err != nil {
		return false, errors.New("inspect source claim mounts failed; inspect Kubernetes API availability")
	}
	for i := range pods.Items {
		pod := &pods.Items[i]
		for _, volume := range pod.Spec.Volumes {
			if volume.PersistentVolumeClaim == nil {
				continue
			}
			if _, source := claimNames[volume.PersistentVolumeClaim.ClaimName]; source {
				if !allowed(pod) {
					return false, nil
				}
			}
		}
	}
	return true, nil
}

func (r *GameBackupReconciler) reconcileBackupInput(ctx context.Context, backup *arcadev1alpha1.GameBackup, desired *corev1.ConfigMap) error {
	existing := &corev1.ConfigMap{}
	key := client.ObjectKeyFromObject(desired)
	if err := r.directReader().Get(ctx, key, existing); err != nil {
		if apierrors.IsNotFound(err) {
			if err := r.Create(ctx, desired.DeepCopy()); err != nil {
				return errors.New("create backup worker input failed; inspect Kubernetes API availability")
			}
			return nil
		}
		return errors.New("inspect backup worker input failed; inspect Kubernetes API availability")
	}
	if !controlledBy(existing.OwnerReferences, "GameBackup", backup.Name, backup.UID) || !apiequality.Semantic.DeepEqual(existing.Data, desired.Data) ||
		!apiequality.Semantic.DeepEqual(existing.Labels, desired.Labels) || !apiequality.Semantic.DeepEqual(existing.Immutable, desired.Immutable) {
		return errors.New("backup worker input collides with a foreign or changed resource; inspect namespace ownership")
	}
	return nil
}

func (r *GameBackupReconciler) reconcileBackupAuthority(ctx context.Context, backup *arcadev1alpha1.GameBackup, resources platformkube.BackupResources) (bool, error) {
	changed := false
	serviceAccount := &corev1.ServiceAccount{}
	if err := r.directReader().Get(ctx, client.ObjectKeyFromObject(resources.ServiceAccount), serviceAccount); err != nil {
		if !apierrors.IsNotFound(err) {
			return false, errors.New("inspect backup authority ServiceAccount failed; inspect Kubernetes API availability")
		}
		if err := r.Create(ctx, resources.ServiceAccount.DeepCopy()); err != nil {
			return false, errors.New("create backup authority ServiceAccount failed; inspect Kubernetes API availability")
		}
		changed = true
	} else if !controlledBy(serviceAccount.OwnerReferences, "GameBackup", backup.Name, backup.UID) ||
		!apiequality.Semantic.DeepEqual(serviceAccount.Labels, resources.ServiceAccount.Labels) ||
		!apiequality.Semantic.DeepEqual(serviceAccount.AutomountServiceAccountToken, resources.ServiceAccount.AutomountServiceAccountToken) {
		return false, errors.New("backup authority ServiceAccount collides with a foreign or changed resource")
	}

	role := &rbacv1.Role{}
	if err := r.directReader().Get(ctx, client.ObjectKeyFromObject(resources.Role), role); err != nil {
		if !apierrors.IsNotFound(err) {
			return false, errors.New("inspect backup authority Role failed; inspect Kubernetes API availability")
		}
		if err := r.Create(ctx, resources.Role.DeepCopy()); err != nil {
			return false, errors.New("create backup authority Role failed; inspect Kubernetes API availability")
		}
		changed = true
	} else if !controlledBy(role.OwnerReferences, "GameBackup", backup.Name, backup.UID) ||
		!apiequality.Semantic.DeepEqual(role.Labels, resources.Role.Labels) || !apiequality.Semantic.DeepEqual(role.Rules, resources.Role.Rules) {
		return false, errors.New("backup authority Role collides with a foreign or changed resource")
	}

	roleBinding := &rbacv1.RoleBinding{}
	if err := r.directReader().Get(ctx, client.ObjectKeyFromObject(resources.RoleBinding), roleBinding); err != nil {
		if !apierrors.IsNotFound(err) {
			return false, errors.New("inspect backup authority RoleBinding failed; inspect Kubernetes API availability")
		}
		if err := r.Create(ctx, resources.RoleBinding.DeepCopy()); err != nil {
			return false, errors.New("create backup authority RoleBinding failed; inspect Kubernetes API availability")
		}
		changed = true
	} else if !controlledBy(roleBinding.OwnerReferences, "GameBackup", backup.Name, backup.UID) ||
		!apiequality.Semantic.DeepEqual(roleBinding.Labels, resources.RoleBinding.Labels) ||
		!apiequality.Semantic.DeepEqual(roleBinding.Subjects, resources.RoleBinding.Subjects) ||
		!apiequality.Semantic.DeepEqual(roleBinding.RoleRef, resources.RoleBinding.RoleRef) {
		return false, errors.New("backup authority RoleBinding collides with a foreign or changed resource")
	}
	return changed, nil
}

func (r *GameBackupReconciler) reconcileBackupJob(ctx context.Context, backup *arcadev1alpha1.GameBackup, desired *batchv1.Job) (*batchv1.Job, bool, error) {
	existing := &batchv1.Job{}
	key := client.ObjectKeyFromObject(desired)
	if err := r.directReader().Get(ctx, key, existing); err != nil {
		if apierrors.IsNotFound(err) {
			pods := &corev1.PodList{}
			if err := r.directReader().List(ctx, pods, client.InNamespace(backup.Namespace), client.MatchingLabels{platformkube.LabelBackupUID: string(backup.UID)}); err != nil {
				return nil, false, errors.New("inspect prior backup worker pods failed; inspect Kubernetes API availability")
			}
			if len(pods.Items) != 0 {
				return nil, false, errBackupWorkerOrphaned
			}
			if err := r.clearWorkerExecution(ctx, backup); err != nil {
				return nil, false, err
			}
			created := desired.DeepCopy()
			if err := r.Create(ctx, created); err != nil {
				return nil, false, errors.New("create bounded backup worker failed; inspect Kubernetes API availability")
			}
			return created, true, nil
		}
		return nil, false, errors.New("inspect bounded backup worker failed; inspect Kubernetes API availability")
	}
	expected := desired
	if existing.Spec.Suspend == nil || !*existing.Spec.Suspend {
		expected = desired.DeepCopy()
		expected.Spec.Suspend = ptr.To(false)
	}
	if !apiequality.Semantic.DeepEqual(existing.OwnerReferences, desired.OwnerReferences) ||
		!apiequality.Semantic.DeepEqual(existing.Labels, desired.Labels) ||
		!apiequality.Semantic.DeepEqual(existing.Annotations, desired.Annotations) ||
		!backupJobSpecMatches(expected, existing) {
		return nil, false, errors.New("backup worker collides with a foreign or changed Job; inspect namespace ownership")
	}
	return existing, false, nil
}

func backupJobSpecMatches(desired, existing *batchv1.Job) bool {
	if desired == nil || existing == nil {
		return false
	}
	// The fake client used by unit tests does not run Kubernetes defaulting or
	// selector generation. Exact raw equality is therefore both valid and the
	// fastest path.
	if apiequality.Semantic.DeepEqual(desired.Spec, existing.Spec) {
		return true
	}
	desiredSpec, desiredOK := normalizedBackupJobSpec(desired)
	existingSpec, existingOK := normalizedBackupJobSpec(existing)
	return desiredOK && existingOK && apiequality.Semantic.DeepEqual(desiredSpec, existingSpec)
}

func normalizedBackupJobSpec(job *batchv1.Job) (*batchv1.JobSpec, bool) {
	spec := job.Spec.DeepCopy()
	if spec.ManualSelector != nil {
		if *spec.ManualSelector {
			return nil, false
		}
		spec.ManualSelector = nil
	}
	if spec.Selector != nil {
		uid := string(job.UID)
		if uid == "" || len(spec.Selector.MatchExpressions) != 0 || len(spec.Selector.MatchLabels) != 1 ||
			spec.Selector.MatchLabels[batchv1.ControllerUidLabel] != uid {
			return nil, false
		}
		generated := map[string]string{
			batchv1.JobNameLabel:       job.Name,
			batchv1.ControllerUidLabel: uid,
			"job-name":                 job.Name,
			"controller-uid":           uid,
		}
		for label, value := range generated {
			if spec.Template.Labels[label] != value {
				return nil, false
			}
			delete(spec.Template.Labels, label)
		}
		spec.Selector = nil
	}
	if spec.CompletionMode != nil && *spec.CompletionMode == batchv1.NonIndexedCompletion {
		spec.CompletionMode = nil
	}
	if spec.Suspend != nil && !*spec.Suspend {
		spec.Suspend = nil
	}
	if spec.PodReplacementPolicy != nil && *spec.PodReplacementPolicy == batchv1.TerminatingOrFailed {
		spec.PodReplacementPolicy = nil
	}
	pod := &spec.Template.Spec
	if pod.DeprecatedServiceAccount == pod.ServiceAccountName {
		pod.DeprecatedServiceAccount = ""
	}
	if pod.DNSPolicy == corev1.DNSClusterFirst {
		pod.DNSPolicy = ""
	}
	if pod.TerminationGracePeriodSeconds != nil && *pod.TerminationGracePeriodSeconds == corev1.DefaultTerminationGracePeriodSeconds {
		pod.TerminationGracePeriodSeconds = nil
	}
	if pod.SchedulerName == corev1.DefaultSchedulerName {
		pod.SchedulerName = ""
	}
	for index := range pod.InitContainers {
		normalizeBackupContainerDefaults(&pod.InitContainers[index])
	}
	for index := range pod.Containers {
		normalizeBackupContainerDefaults(&pod.Containers[index])
	}
	return spec, true
}

func normalizeBackupContainerDefaults(container *corev1.Container) {
	if container.TerminationMessagePath == corev1.TerminationMessagePathDefault {
		container.TerminationMessagePath = ""
	}
	if container.TerminationMessagePolicy == corev1.TerminationMessageReadFile {
		container.TerminationMessagePolicy = ""
	}
	for index := range container.Env {
		field := container.Env[index].ValueFrom
		if field != nil && field.FieldRef != nil && field.FieldRef.APIVersion == "v1" {
			field.FieldRef.APIVersion = ""
		}
	}
}

func jobComplete(job *batchv1.Job) bool {
	for _, condition := range job.Status.Conditions {
		if condition.Type == batchv1.JobComplete && condition.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

func jobFailed(job *batchv1.Job) bool {
	for _, condition := range job.Status.Conditions {
		if condition.Type == batchv1.JobFailed && condition.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

func (r *GameBackupReconciler) workerResult(ctx context.Context, backup *arcadev1alpha1.GameBackup, job *batchv1.Job) (platformdata.BackupWorkerResult, error) {
	pods := &corev1.PodList{}
	if err := r.directReader().List(ctx, pods, client.InNamespace(backup.Namespace), client.MatchingLabels{platformkube.LabelBackupUID: string(backup.UID)}); err != nil {
		return platformdata.BackupWorkerResult{}, errors.New("list backup worker pods failed")
	}
	for i := range pods.Items {
		pod := &pods.Items[i]
		if !controlledBy(pod.OwnerReferences, "Job", job.Name, job.UID) || pod.UID == "" ||
			pod.Annotations[platformkube.AnnotationBackupPodAuthorized] != string(pod.UID) {
			continue
		}
		for _, status := range pod.Status.ContainerStatuses {
			if status.Name != "backup-worker" || status.State.Terminated == nil || status.State.Terminated.ExitCode != 0 {
				continue
			}
			decoder := json.NewDecoder(bytes.NewBufferString(status.State.Terminated.Message))
			decoder.DisallowUnknownFields()
			var result platformdata.BackupWorkerResult
			if err := decoder.Decode(&result); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
				return platformdata.BackupWorkerResult{}, errors.New("backup worker result is invalid")
			}
			if result.Version != platformdata.BackupFormatVersion || result.SizeBytes < 0 || result.PathCount < 1 || result.CreatedAt.IsZero() || result.VerifiedAt.IsZero() || result.VerifiedAt.Before(result.CreatedAt) {
				return platformdata.BackupWorkerResult{}, errors.New("backup worker result is incomplete")
			}
			return result, nil
		}
	}
	return platformdata.BackupWorkerResult{}, errBackupWorkerResultPending
}

func (r *GameBackupReconciler) workerFailureReason(ctx context.Context, backup *arcadev1alpha1.GameBackup, job *batchv1.Job) string {
	pods := &corev1.PodList{}
	if err := r.directReader().List(ctx, pods, client.InNamespace(backup.Namespace), client.MatchingLabels{platformkube.LabelBackupUID: string(backup.UID)}); err != nil {
		return arcadev1alpha1.ReasonWorkerFailed
	}
	for i := range pods.Items {
		pod := &pods.Items[i]
		if !controlledBy(pod.OwnerReferences, "Job", job.Name, job.UID) || pod.UID == "" ||
			pod.Annotations[platformkube.AnnotationBackupPodAuthorized] != string(pod.UID) {
			continue
		}
		statuses := append(slices.Clone(pod.Status.InitContainerStatuses), pod.Status.ContainerStatuses...)
		for _, status := range statuses {
			if status.Name != "backup-worker" || status.State.Terminated == nil {
				if status.Name == "backup-authorizer" && status.State.Terminated != nil {
					switch status.State.Terminated.ExitCode {
					case 11:
						return arcadev1alpha1.ReasonSecretUnavailable
					case 12:
						return arcadev1alpha1.ReasonWorkerFailed
					}
				}
				continue
			}
			switch status.State.Terminated.ExitCode {
			case 11:
				return arcadev1alpha1.ReasonSecretUnavailable
			case 30:
				return arcadev1alpha1.ReasonVerificationFailed
			}
		}
	}
	return arcadev1alpha1.ReasonWorkerFailed
}

func (r *GameBackupReconciler) finishSuccess(ctx context.Context, backup *arcadev1alpha1.GameBackup, _ *arcadev1alpha1.GameServer) (ctrl.Result, error) {
	runtime, pending, err := r.settleRuntime(ctx, backup)
	if err != nil {
		return r.hold(ctx, backup, arcadev1alpha1.ReasonIdentityMismatch, "the operation cannot settle the exact requested runtime generation; leave the server stopped and inspect generation history")
	}
	if pending {
		return ctrl.Result{RequeueAfter: backupRequeue}, nil
	}
	err = r.writeStatus(ctx, backup, arcadev1alpha1.DataPhaseSucceeded, func(updated *arcadev1alpha1.GameBackup) {
		now := r.now()
		updated.Status.Runtime = runtime
		updated.Status.CompletedAt = &now
		setBackupCondition(updated, arcadev1alpha1.ConditionOperationComplete, metav1.ConditionTrue, arcadev1alpha1.ReasonOperationCompleted, "the verified cold backup and requested runtime disposition are complete", now)
	})
	return ctrl.Result{Requeue: err == nil}, err
}

func (r *GameBackupReconciler) finishFailure(ctx context.Context, backup *arcadev1alpha1.GameBackup, _ *arcadev1alpha1.GameServer, reason, message string) (ctrl.Result, error) {
	runtime, pending, err := r.settleRuntime(ctx, backup)
	if err != nil {
		return r.hold(ctx, backup, arcadev1alpha1.ReasonIdentityMismatch, "backup work ended but the exact requested runtime generation cannot be settled; leave the server stopped and inspect generation history")
	}
	if pending {
		return ctrl.Result{RequeueAfter: backupRequeue}, nil
	}
	err = r.writeStatus(ctx, backup, arcadev1alpha1.DataPhaseFailed, func(updated *arcadev1alpha1.GameBackup) {
		now := r.now()
		updated.Status.Runtime = runtime
		updated.Status.CompletedAt = &now
		setBackupCondition(updated, arcadev1alpha1.ConditionOperationComplete, metav1.ConditionFalse, reason, message, now)
	})
	return ctrl.Result{Requeue: err == nil}, err
}

func (r *GameBackupReconciler) settleRuntime(ctx context.Context, backup *arcadev1alpha1.GameBackup) (*arcadev1alpha1.RuntimeDisposition, bool, error) {
	if backup.Status.Fence == nil {
		return nil, false, nil
	}
	server := &arcadev1alpha1.GameServer{}
	key := types.NamespacedName{Namespace: backup.Namespace, Name: backup.Spec.Source.Name}
	if err := r.directReader().Get(ctx, key, server); err != nil || string(server.UID) != backup.Spec.Source.UID {
		return nil, false, errors.New("exact source GameServer is unavailable")
	}
	wantState := arcadev1alpha1.DesiredStateStopped
	wantPhase := arcadev1alpha1.PhaseStopped
	wantGeneration := backup.Status.Fence.GameServer.Generation
	if backup.Spec.RestartPolicy == arcadev1alpha1.RestartRestorePreviousState && backup.Spec.Source.DesiredState == arcadev1alpha1.DesiredStateRunning {
		wantState = arcadev1alpha1.DesiredStateRunning
		wantPhase = arcadev1alpha1.PhaseReady
		wantGeneration++
	}
	if server.Generation == wantGeneration && server.Spec.DesiredState == wantState {
		if server.Status.ObservedGeneration != wantGeneration || server.Status.Phase != wantPhase {
			return nil, true, nil
		}
		now := r.now()
		return &arcadev1alpha1.RuntimeDisposition{
			GameServer: arcadev1alpha1.ExactGameServerReference{
				ExactLocalReference: backup.Spec.Source.ExactLocalReference,
				Generation:          wantGeneration, DesiredState: wantState,
			},
			Phase: wantPhase, CompletedAt: now,
		}, false, nil
	}
	if wantState == arcadev1alpha1.DesiredStateRunning &&
		server.Generation == backup.Status.Fence.GameServer.Generation &&
		server.Spec.DesiredState == arcadev1alpha1.DesiredStateStopped {
		if err := r.allowRuntimeSettlement(ctx, backup, wantState, wantGeneration); err != nil {
			return nil, false, err
		}
		updated := server.DeepCopy()
		updated.Spec.DesiredState = arcadev1alpha1.DesiredStateRunning
		if err := r.Update(ctx, updated); err != nil {
			return nil, false, errors.New("restore previous runtime intent failed")
		}
		return nil, true, nil
	}
	return nil, false, errors.New("GameServer generation does not match runtime disposition")
}

func (r *GameBackupReconciler) cancel(ctx context.Context, backup *arcadev1alpha1.GameBackup) (ctrl.Result, error) {
	if backup.Status.Phase != arcadev1alpha1.DataPhaseCancelling {
		if err := r.writeStatus(ctx, backup, arcadev1alpha1.DataPhaseCancelling, func(updated *arcadev1alpha1.GameBackup) {
			setBackupCondition(updated, arcadev1alpha1.ConditionOperationComplete, metav1.ConditionFalse, arcadev1alpha1.ReasonOperationCancelled, "cancellation is stopping the owned worker before settling runtime", r.now())
		}); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}
	if pending, err := r.deleteWorkerAndWait(ctx, backup); err != nil || pending {
		return ctrl.Result{RequeueAfter: backupRequeue}, err
	}
	var runtime *arcadev1alpha1.RuntimeDisposition
	var pending bool
	var err error
	if backup.Status.Fence == nil {
		// Cancellation may arrive after the stop update but before detach/fence
		// persistence. Settle that exact stop without claiming data was cold.
		pending, err = r.settlePreFenceRuntime(ctx, backup)
	} else {
		runtime, pending, err = r.settleRuntime(ctx, backup)
	}
	if err != nil {
		return r.hold(ctx, backup, arcadev1alpha1.ReasonIdentityMismatch, "cancellation cannot settle the exact requested runtime generation; leave the server stopped and inspect generation history")
	}
	if pending {
		return ctrl.Result{RequeueAfter: backupRequeue}, nil
	}
	err = r.writeStatus(ctx, backup, arcadev1alpha1.DataPhaseCancelled, func(updated *arcadev1alpha1.GameBackup) {
		now := r.now()
		updated.Status.Runtime = runtime
		updated.Status.CompletedAt = &now
		setBackupCondition(updated, arcadev1alpha1.ConditionOperationComplete, metav1.ConditionFalse, arcadev1alpha1.ReasonOperationCancelled, "the worker is absent and the requested runtime disposition is settled", now)
	})
	return ctrl.Result{Requeue: err == nil}, err
}

func (r *GameBackupReconciler) finalize(ctx context.Context, backup *arcadev1alpha1.GameBackup) (ctrl.Result, error) {
	if !slices.Contains(backup.Finalizers, platformkube.BackupFinalizer) {
		return ctrl.Result{}, nil
	}
	if pending, err := r.deleteWorkerAndWait(ctx, backup); err != nil || pending {
		return ctrl.Result{RequeueAfter: backupRequeue}, err
	}
	if pending, err := r.settleDeletedRuntime(ctx, backup); err != nil || pending {
		return ctrl.Result{RequeueAfter: backupRequeue}, err
	}
	if err := r.releaseLeases(ctx, backup); err != nil {
		return ctrl.Result{}, err
	}
	updated := backup.DeepCopy()
	updated.Finalizers = slices.DeleteFunc(updated.Finalizers, func(value string) bool { return value == platformkube.BackupFinalizer })
	if err := r.Update(ctx, updated); err != nil {
		return ctrl.Result{}, errors.New("remove GameBackup protection failed; inspect Kubernetes API availability")
	}
	return ctrl.Result{}, nil
}

func (r *GameBackupReconciler) settleDeletedRuntime(ctx context.Context, backup *arcadev1alpha1.GameBackup) (bool, error) {
	if backup.Status.Phase == arcadev1alpha1.DataPhaseSucceeded || backup.Status.Phase == arcadev1alpha1.DataPhaseFailed || backup.Status.Phase == arcadev1alpha1.DataPhaseCancelled {
		// Terminal status is written only after the exact runtime disposition is
		// observed. Deleting that historical record must not reassert an older
		// generation after the data-operation Lease has been released.
		return false, nil
	}
	if backup.Status.Fence != nil {
		_, pending, err := r.settleRuntime(ctx, backup)
		return pending, err
	}
	return r.settlePreFenceRuntime(ctx, backup)
}

func (r *GameBackupReconciler) settlePreFenceRuntime(ctx context.Context, backup *arcadev1alpha1.GameBackup) (bool, error) {
	if backup.Status.Source == nil || backup.Spec.Source.DesiredState != arcadev1alpha1.DesiredStateRunning {
		return false, nil
	}
	server := &arcadev1alpha1.GameServer{}
	key := types.NamespacedName{Namespace: backup.Namespace, Name: backup.Spec.Source.Name}
	if err := r.directReader().Get(ctx, key, server); err != nil || string(server.UID) != backup.Spec.Source.UID {
		return false, errors.New("exact source GameServer is unavailable during backup finalization")
	}
	if server.Generation == backup.Spec.Source.Generation && server.Spec.DesiredState == arcadev1alpha1.DesiredStateRunning {
		return false, nil
	}
	stoppedGeneration := backup.Spec.Source.Generation + 1
	if server.Generation != stoppedGeneration && server.Generation != stoppedGeneration+1 {
		return false, errors.New("source GameServer generation changed during backup finalization")
	}
	synthetic := backup.DeepCopy()
	synthetic.Status.Fence = &arcadev1alpha1.ColdDataFence{GameServer: arcadev1alpha1.ExactGameServerReference{
		ExactLocalReference: backup.Spec.Source.ExactLocalReference,
		Generation:          stoppedGeneration, DesiredState: arcadev1alpha1.DesiredStateStopped,
	}}
	_, pending, err := r.settleRuntime(ctx, synthetic)
	return pending, err
}

func (r *GameBackupReconciler) deleteWorkerAndWait(ctx context.Context, backup *arcadev1alpha1.GameBackup) (bool, error) {
	job := &batchv1.Job{}
	key := types.NamespacedName{Namespace: backup.Namespace, Name: platformkube.BackupResourceName(backup.UID)}
	if err := r.directReader().Get(ctx, key, job); err == nil {
		if !controlledBy(job.OwnerReferences, "GameBackup", backup.Name, backup.UID) {
			return false, errors.New("refuse to delete foreign backup worker Job")
		}
		propagation := metav1.DeletePropagationForeground
		if err := r.Delete(ctx, job, &client.DeleteOptions{PropagationPolicy: &propagation}); err != nil && !apierrors.IsNotFound(err) {
			return false, errors.New("stop owned backup worker failed; inspect Kubernetes API availability")
		}
		return true, nil
	} else if !apierrors.IsNotFound(err) {
		return false, errors.New("inspect owned backup worker failed; inspect Kubernetes API availability")
	}
	pods := &corev1.PodList{}
	if err := r.directReader().List(ctx, pods, client.InNamespace(backup.Namespace), client.MatchingLabels{platformkube.LabelBackupUID: string(backup.UID)}); err != nil {
		return false, errors.New("verify backup worker absence failed; inspect Kubernetes API availability")
	}
	return len(pods.Items) > 0, nil
}

func (r *GameBackupReconciler) clearWorkerExecution(ctx context.Context, backup *arcadev1alpha1.GameBackup) error {
	leases := &coordinationv1.LeaseList{}
	if err := r.directReader().List(ctx, leases, client.InNamespace(backup.Namespace), client.MatchingLabels{platformkube.LabelBackupUID: string(backup.UID)}); err != nil {
		return errors.New("inspect backup worker execution lease failed; inspect Kubernetes API availability")
	}
	if len(leases.Items) != 1 {
		return errors.New("exact backup worker execution lease is unavailable")
	}
	lease := &leases.Items[0]
	operation := arcadev1alpha1.ExactLocalReference{Name: backup.Name, UID: string(backup.UID)}
	if !platformkube.BackupOperationLeaseMatches(lease, operation, backup.Spec.Source.Name) {
		return errors.New("refuse to clear a foreign backup worker execution lease")
	}
	if lease.Annotations[platformkube.AnnotationWorkerPodUID] == "" {
		return nil
	}
	updated := lease.DeepCopy()
	delete(updated.Annotations, platformkube.AnnotationWorkerPodUID)
	if err := r.Update(ctx, updated); err != nil {
		return errors.New("clear prior backup worker execution failed; inspect Kubernetes API availability")
	}
	return nil
}

func (r *GameBackupReconciler) releaseLeases(ctx context.Context, backup *arcadev1alpha1.GameBackup) error {
	leases := &coordinationv1.LeaseList{}
	if err := r.directReader().List(ctx, leases, client.InNamespace(backup.Namespace), client.MatchingLabels{platformkube.LabelBackupUID: string(backup.UID)}); err != nil {
		return errors.New("list retained-data operation leases failed; inspect Kubernetes API availability")
	}
	for i := range leases.Items {
		lease := &leases.Items[i]
		operation := arcadev1alpha1.ExactLocalReference{Name: backup.Name, UID: string(backup.UID)}
		if !platformkube.BackupOperationLeaseMatches(lease, operation, backup.Spec.Source.Name) {
			return errors.New("refuse to release a foreign retained-data operation lease")
		}
		if err := r.Delete(ctx, lease); err != nil && !apierrors.IsNotFound(err) {
			return errors.New("release retained-data operation lease failed; inspect Kubernetes API availability")
		}
	}
	return nil
}

func (r *GameBackupReconciler) allowRuntimeSettlement(ctx context.Context, backup *arcadev1alpha1.GameBackup, state arcadev1alpha1.DesiredState, generation int64) error {
	leases := &coordinationv1.LeaseList{}
	if err := r.directReader().List(ctx, leases, client.InNamespace(backup.Namespace), client.MatchingLabels{platformkube.LabelBackupUID: string(backup.UID)}); err != nil {
		return errors.New("list retained-data operation leases failed; inspect Kubernetes API availability")
	}
	if len(leases.Items) != 1 {
		return errors.New("exact retained-data operation lease is unavailable")
	}
	lease := &leases.Items[0]
	operation := arcadev1alpha1.ExactLocalReference{Name: backup.Name, UID: string(backup.UID)}
	if !platformkube.BackupOperationLeaseMatches(lease, operation, backup.Spec.Source.Name) {
		return errors.New("refuse to authorize runtime through a foreign retained-data operation lease")
	}
	wantGeneration := strconv.FormatInt(generation, 10)
	if lease.Annotations[platformkube.AnnotationRuntimeSettlementState] == string(state) &&
		lease.Annotations[platformkube.AnnotationRuntimeSettlementGeneration] == wantGeneration {
		return nil
	}
	updated := lease.DeepCopy()
	if updated.Annotations == nil {
		updated.Annotations = make(map[string]string)
	}
	updated.Annotations[platformkube.AnnotationRuntimeSettlementState] = string(state)
	updated.Annotations[platformkube.AnnotationRuntimeSettlementGeneration] = wantGeneration
	if err := r.Update(ctx, updated); err != nil {
		return errors.New("authorize exact runtime settlement failed; inspect Kubernetes API availability")
	}
	return nil
}

func (r *GameBackupReconciler) reportBlocked(ctx context.Context, backup *arcadev1alpha1.GameBackup, reason, message string) (ctrl.Result, error) {
	if backup.Status.Phase == arcadev1alpha1.DataPhaseRunning || backup.Status.Phase == arcadev1alpha1.DataPhaseVerifying || backup.Status.Phase == arcadev1alpha1.DataPhaseCancelling {
		return r.hold(ctx, backup, reason, message)
	}
	err := r.writeStatus(ctx, backup, arcadev1alpha1.DataPhaseBlocked, func(updated *arcadev1alpha1.GameBackup) {
		setBackupCondition(updated, arcadev1alpha1.ConditionSourceReady, metav1.ConditionFalse, reason, message, r.now())
	})
	if err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: 5 * backupRequeue}, nil
}

func (r *GameBackupReconciler) hold(ctx context.Context, backup *arcadev1alpha1.GameBackup, reason, message string) (ctrl.Result, error) {
	err := r.writeStatus(ctx, backup, backup.Status.Phase, func(updated *arcadev1alpha1.GameBackup) {
		setBackupCondition(updated, arcadev1alpha1.ConditionSourceReady, metav1.ConditionFalse, reason, message, r.now())
	})
	if err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: backupRequeue}, nil
}

func (r *GameBackupReconciler) writeStatus(ctx context.Context, backup *arcadev1alpha1.GameBackup, phase arcadev1alpha1.DataOperationPhase, mutate func(*arcadev1alpha1.GameBackup)) error {
	updated := backup.DeepCopy()
	updated.Status.ObservedGeneration = backup.Generation
	updated.Status.Phase = phase
	mutate(updated)
	verified := updated.Status.Artifact != nil && updated.Status.Artifact.Verification.Result == arcadev1alpha1.VerificationVerified
	if err := platformdata.ValidateTransition(platformdata.BackupOperation, backup.Status.Phase, phase, verified); err != nil {
		return errors.New("backup state transition was rejected by the safety contract")
	}
	canonicalizeBackupConditions(updated)
	if err := platformdata.ValidateBackupStatus(updated); err != nil {
		return errors.New("backup status was rejected by the safety contract")
	}
	if apiequality.Semantic.DeepEqual(backup.Status, updated.Status) {
		return nil
	}
	if err := r.Status().Update(ctx, updated); err != nil {
		return errors.New("update GameBackup status failed; inspect Kubernetes API availability")
	}
	return nil
}

func setBackupCondition(backup *arcadev1alpha1.GameBackup, conditionType string, status metav1.ConditionStatus, reason, message string, now metav1.Time) {
	condition := metav1.Condition{Type: conditionType, Status: status, Reason: reason, Message: message, ObservedGeneration: backup.Generation, LastTransitionTime: now}
	for index := range backup.Status.Conditions {
		previous := backup.Status.Conditions[index]
		if previous.Type != conditionType {
			continue
		}
		if previous.Status == condition.Status && previous.Reason == condition.Reason && previous.Message == condition.Message {
			condition.LastTransitionTime = previous.LastTransitionTime
		}
		backup.Status.Conditions[index] = condition
		return
	}
	backup.Status.Conditions = append(backup.Status.Conditions, condition)
}

func backupConditionReason(backup *arcadev1alpha1.GameBackup, conditionType string) string {
	for _, condition := range backup.Status.Conditions {
		if condition.Type == conditionType {
			return condition.Reason
		}
	}
	return ""
}

func canonicalizeBackupConditions(backup *arcadev1alpha1.GameBackup) {
	conditions := make([]metav1.Condition, 0, len(backup.Status.Conditions))
	for _, conditionType := range backupConditionOrder {
		for _, condition := range backup.Status.Conditions {
			if condition.Type == conditionType {
				conditions = append(conditions, condition)
				break
			}
		}
	}
	backup.Status.Conditions = conditions
}

func (r *GameBackupReconciler) now() metav1.Time {
	if r.Now != nil {
		return r.Now()
	}
	return metav1.Now()
}

func (r *GameBackupReconciler) directReader() client.Reader {
	if r.APIReader != nil {
		return r.APIReader
	}
	return r.Client
}

func (r *GameBackupReconciler) SetupWithManager(manager ctrl.Manager) error {
	if r.Client == nil || r.Scheme == nil || r.Catalog == nil || r.WorkerImage == "" {
		return errors.New("backup reconciler client, scheme, catalog, and pinned worker image are required")
	}
	return ctrl.NewControllerManagedBy(manager).
		For(&arcadev1alpha1.GameBackup{}).
		Owns(&corev1.ConfigMap{}).
		Owns(&corev1.ServiceAccount{}).
		Owns(&rbacv1.Role{}).
		Owns(&rbacv1.RoleBinding{}).
		Owns(&batchv1.Job{}).
		Owns(&coordinationv1.Lease{}).
		Complete(r)
}
