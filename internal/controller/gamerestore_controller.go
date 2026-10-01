// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"

	arcadev1alpha1 "github.com/gobha-me/arcadectl/api/v1alpha1"
	platformdata "github.com/gobha-me/arcadectl/internal/platform/data"
	"github.com/gobha-me/arcadectl/internal/platform/game"
	platformkube "github.com/gobha-me/arcadectl/internal/platform/kube"
	"github.com/gobha-me/arcadectl/internal/restoreworker"
	batchv1 "k8s.io/api/batch/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
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
	restoreRequeue = time.Second
	// A candidate that cannot become Ready is rolled back while both data sets
	// remain retained. Kubernetes Deployment deadlines normally fail sooner.
	restoreActivationTimeout   = 15 * time.Minute
	maxRestorePopulateAttempts = int32(3)
	restoreResultGrace         = time.Minute
)

func canRetryRestorePopulate(attempts int32) bool {
	return attempts >= 1 && attempts < maxRestorePopulateAttempts
}

func restoreRetryPendingForPhase(phase arcadev1alpha1.DataOperationPhase, pending bool) bool {
	return phase == arcadev1alpha1.DataPhaseRunning && pending
}

func restoreWorkerResultGraceExpired(job *batchv1.Job, now time.Time) bool {
	if job == nil || !jobComplete(job) {
		return false
	}
	completed := job.Status.CompletionTime
	if completed == nil {
		for _, condition := range job.Status.Conditions {
			if condition.Type == batchv1.JobComplete && condition.Status == corev1.ConditionTrue {
				completed = &condition.LastTransitionTime
				break
			}
		}
	}
	if completed == nil || completed.IsZero() {
		return !job.CreationTimestamp.IsZero() && now.Sub(job.CreationTimestamp.Time) > restoreResultGrace
	}
	return now.Sub(completed.Time) > restoreResultGrace
}

// GameRestoreReconciler owns only the candidate data and the exact operation
// leases. It never writes, replaces, or deletes the previous world claims.
type GameRestoreReconciler struct {
	client.Client
	APIReader   client.Reader
	Scheme      *runtime.Scheme
	Catalog     DefinitionCatalog
	WorkerImage string
	Now         func() metav1.Time
}

type restoreSubject struct {
	server            *arcadev1alpha1.GameServer
	definition        game.Definition
	plan              platformkube.Plan
	previous          *arcadev1alpha1.RetainedDataReference
	previousPaths     []arcadev1alpha1.DataPathIdentity
	candidateIdentity string
	source            *arcadev1alpha1.DataSourceSnapshot
	artifact          *arcadev1alpha1.BackupArtifact
	settingsDigest    string
	targetPaths       []restoreworker.PathContract
}

type restoreIssue struct{ reason, message string }

func (r *GameRestoreReconciler) Reconcile(ctx context.Context, request ctrl.Request) (ctrl.Result, error) {
	restore := &arcadev1alpha1.GameRestore{}
	if err := r.Get(ctx, request.NamespacedName, restore); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !restore.DeletionTimestamp.IsZero() {
		return r.finalizeRestore(ctx, restore)
	}
	if !slices.Contains(restore.Finalizers, platformkube.RestoreFinalizer) {
		updated := restore.DeepCopy()
		updated.Finalizers = append(updated.Finalizers, platformkube.RestoreFinalizer)
		if err := r.Update(ctx, updated); err != nil {
			return ctrl.Result{}, errors.New("protect GameRestore before external work failed")
		}
		return ctrl.Result{Requeue: true}, nil
	}
	if restoreTerminal(restore.Status.Phase) {
		if pending, err := r.deleteAllRestoreWorkers(ctx, restore); err != nil || pending {
			return ctrl.Result{RequeueAfter: restoreRequeue}, err
		}
		return ctrl.Result{}, r.releaseRestoreLeases(ctx, restore)
	}
	if restore.Status.Phase == "" {
		return ctrl.Result{}, r.writeRestoreStatus(ctx, restore, arcadev1alpha1.DataPhasePending, func(updated *arcadev1alpha1.GameRestore) {
			r.setRestoreCondition(updated, arcadev1alpha1.ConditionOperationAccepted, metav1.ConditionTrue, arcadev1alpha1.ReasonOperationAccepted, "the immutable restore request was accepted")
		})
	}
	if restore.Spec.CancelRequested {
		if restore.Status.ActivationStartedAt != nil {
			if restore.Status.Phase != arcadev1alpha1.DataPhaseRollingBack {
				return ctrl.Result{}, r.writeRestoreStatus(ctx, restore, arcadev1alpha1.DataPhaseRollingBack, func(updated *arcadev1alpha1.GameRestore) {
					r.setRestoreCondition(updated, arcadev1alpha1.ConditionOperationComplete, metav1.ConditionFalse, arcadev1alpha1.ReasonOperationCancelled, "cancellation is restoring the exact previous data selection")
				})
			}
		} else if restore.Status.Phase != arcadev1alpha1.DataPhaseCancelling {
			return ctrl.Result{}, r.writeRestoreStatus(ctx, restore, arcadev1alpha1.DataPhaseCancelling, func(updated *arcadev1alpha1.GameRestore) {
				r.setRestoreCondition(updated, arcadev1alpha1.ConditionOperationComplete, metav1.ConditionFalse, arcadev1alpha1.ReasonOperationCancelled, "cancellation is stopping workers before settling the previous world")
			})
		}
	}
	switch restore.Status.Phase {
	case arcadev1alpha1.DataPhasePending, arcadev1alpha1.DataPhaseBlocked:
		return r.prepareRestore(ctx, restore)
	case arcadev1alpha1.DataPhasePreparing:
		return r.reconcileRestorePreflight(ctx, restore)
	case arcadev1alpha1.DataPhaseRunning:
		return r.reconcileRestorePopulate(ctx, restore)
	case arcadev1alpha1.DataPhaseVerifying:
		return r.reconcileRestoreVerification(ctx, restore)
	case arcadev1alpha1.DataPhaseActivating:
		return r.reconcileRestoreActivation(ctx, restore)
	case arcadev1alpha1.DataPhaseRollingBack:
		return r.reconcileRestoreRollback(ctx, restore)
	case arcadev1alpha1.DataPhaseCancelling:
		return r.reconcileRestoreCancellation(ctx, restore)
	default:
		return ctrl.Result{}, errors.New("GameRestore has an unsupported nonterminal phase")
	}
}

func restoreTerminal(phase arcadev1alpha1.DataOperationPhase) bool {
	return phase == arcadev1alpha1.DataPhaseSucceeded || phase == arcadev1alpha1.DataPhaseFailed || phase == arcadev1alpha1.DataPhaseCancelled
}

func (r *GameRestoreReconciler) prepareRestore(ctx context.Context, restore *arcadev1alpha1.GameRestore) (ctrl.Result, error) {
	subject, issue := r.resolveInitialRestore(ctx, restore)
	if issue != nil {
		return r.blockRestore(ctx, restore, issue.reason, issue.message)
	}
	return ctrl.Result{}, r.writeRestoreStatus(ctx, restore, arcadev1alpha1.DataPhasePreparing, func(updated *arcadev1alpha1.GameRestore) {
		if updated.Status.StartedAt == nil {
			now := r.nowRestore()
			updated.Status.StartedAt = &now
		}
		updated.Status.Source = subject.source.DeepCopy()
		artifact := *subject.artifact
		updated.Status.Artifact = &artifact
		updated.Status.PreviousData = slices.Clone(subject.previousPaths)
		updated.Status.PreviousDataIdentity = subject.previous.Identity
		r.setRestoreCondition(updated, arcadev1alpha1.ConditionSourceReady, metav1.ConditionTrue, arcadev1alpha1.ReasonOperationAccepted, "the exact verified backup and target data identities are compatible")
	})
}

// resolveInitialRestore is read-only. It never reads repository Secret bytes;
// the separate preflight worker proves access through a UID/RV-pinned Secret.
func (r *GameRestoreReconciler) resolveInitialRestore(ctx context.Context, restore *arcadev1alpha1.GameRestore) (*restoreSubject, *restoreIssue) {
	if restore.Spec.Target.Name == "" || restore.Spec.Target.UID == "" || restore.Spec.Target.Generation < 1 ||
		restore.Spec.BackupRef.Name == "" || restore.Spec.BackupRef.UID == "" || restore.Spec.RepositorySecretRef.Name == "" ||
		restore.Spec.RepositorySecretRef.UID == "" || restore.Spec.RepositorySecretRef.ResourceVersion == "" ||
		restore.Spec.Target.Namespace != nil || restore.Spec.BackupRef.Namespace != nil || restore.Spec.RepositorySecretRef.Namespace != nil {
		return nil, &restoreIssue{arcadev1alpha1.ReasonInvalidReference, "restore references must identify exact local objects and one immutable repository Secret revision"}
	}
	backup := &arcadev1alpha1.GameBackup{}
	backupKey := types.NamespacedName{Namespace: restore.Namespace, Name: restore.Spec.BackupRef.Name}
	if err := r.directRestoreReader().Get(ctx, backupKey, backup); err != nil || string(backup.UID) != restore.Spec.BackupRef.UID ||
		backup.Status.Phase != arcadev1alpha1.DataPhaseSucceeded || backup.Status.ObservedGeneration != backup.Generation ||
		backup.Status.Source == nil || backup.Status.Artifact == nil || backup.Status.Artifact.Verification.Result != arcadev1alpha1.VerificationVerified ||
		backup.Status.Artifact.Verification.VerifiedAt == nil || backup.Status.Artifact.PathCount != int32(len(backup.Status.Source.Paths)) {
		return nil, &restoreIssue{arcadev1alpha1.ReasonInvalidReference, "the exact backup is unavailable or has no current, complete verified artifact"}
	}
	artifact := backup.Status.Artifact
	if artifact.Provenance.BackupRef.Name != backup.Name || artifact.Provenance.BackupRef.UID != string(backup.UID) ||
		artifact.Provenance.RepositorySecretRef != restore.Spec.RepositorySecretRef {
		return nil, &restoreIssue{arcadev1alpha1.ReasonInvalidReference, "backup artifact provenance does not match the requested repository Secret revision"}
	}
	artifactID, err := platformdata.ArtifactID(backup.UID)
	if err != nil || artifact.ID != artifactID || artifact.FormatVersion != platformdata.BackupFormatVersion {
		return nil, &restoreIssue{arcadev1alpha1.ReasonInvalidReference, "the backup artifact format or deterministic identity is unsupported"}
	}
	server := &arcadev1alpha1.GameServer{}
	serverKey := types.NamespacedName{Namespace: restore.Namespace, Name: restore.Spec.Target.Name}
	if err := r.directRestoreReader().Get(ctx, serverKey, server); err != nil || string(server.UID) != restore.Spec.Target.UID || !server.DeletionTimestamp.IsZero() ||
		server.Generation != restore.Spec.Target.Generation || server.Spec.DesiredState != restore.Spec.Target.DesiredState {
		return nil, &restoreIssue{arcadev1alpha1.ReasonIdentityMismatch, "the exact target GameServer generation is unavailable or changed"}
	}
	definition, err := r.Catalog.Get(server.Spec.Game)
	if err != nil || !definition.Capabilities.Restore || !definition.Capabilities.ColdBackup {
		return nil, &restoreIssue{arcadev1alpha1.ReasonInvalidReference, "the target game adapter does not certify cold restore"}
	}
	plan, err := platformkube.Build(server, definition)
	if err != nil || len(plan.DataClaims) == 0 {
		return nil, &restoreIssue{arcadev1alpha1.ReasonIdentityMismatch, "the target no longer satisfies its certified adapter data contract"}
	}
	settingsDigest, err := definition.SettingsDigest(server.Spec.Settings.Raw)
	if err != nil || backup.Status.Source.Game != server.Spec.Game || backup.Status.Source.ImageDigest != server.Spec.ImageDigest ||
		backup.Status.Source.SettingsDigest != settingsDigest || len(backup.Status.Source.Paths) != len(definition.PersistentPaths) {
		return nil, &restoreIssue{arcadev1alpha1.ReasonInvalidReference, "backup game, image, settings, or persistent path topology is incompatible with the target"}
	}
	pathMounts := make(map[string]string, len(definition.PersistentPaths))
	for _, path := range definition.PersistentPaths {
		pathMounts[path.Name] = path.MountPath
	}
	targetPaths := make([]restoreworker.PathContract, 0, len(backup.Status.Source.Paths))
	for _, path := range backup.Status.Source.Paths {
		if pathMounts[path.Name] != path.MountPath || path.MountPath == "" {
			return nil, &restoreIssue{arcadev1alpha1.ReasonInvalidReference, "backup persistent paths do not match the certified target adapter"}
		}
		targetPaths = append(targetPaths, restoreworker.PathContract{Name: path.Name, MountPath: path.MountPath})
	}
	previous := &arcadev1alpha1.RetainedDataReference{Identity: plan.DataIdentity, Claims: make([]arcadev1alpha1.RetainedDataClaimReference, 0, len(plan.DataClaims))}
	previousPaths := make([]arcadev1alpha1.DataPathIdentity, 0, len(plan.DataClaims))
	for _, claim := range plan.DataClaims {
		actual := &corev1.PersistentVolumeClaim{}
		if err := r.directRestoreReader().Get(ctx, client.ObjectKeyFromObject(claim.Desired), actual); err != nil ||
			validateExistingDataClaim(actual, claim) != nil || actual.UID == "" || actual.Status.Phase != corev1.ClaimBound || actual.Spec.VolumeName == "" {
			return nil, &restoreIssue{arcadev1alpha1.ReasonIdentityMismatch, "every target data claim must remain bound with its exact retained identity"}
		}
		path := claim.Desired.Labels[platformkube.LabelDataPath]
		ref := arcadev1alpha1.ExactLocalReference{Name: actual.Name, UID: string(actual.UID)}
		previous.Claims = append(previous.Claims, arcadev1alpha1.RetainedDataClaimReference{Path: path, ClaimRef: ref})
		previousPaths = append(previousPaths, arcadev1alpha1.DataPathIdentity{Name: path, MountPath: pathMounts[path], ClaimRef: ref})
	}
	if server.Status.ActiveData != nil && (!sameDataSelection(restore.Spec.TargetData, server.Status.ActiveData) ||
		!sameDataSelection(server.Status.ObservedData, server.Status.ActiveData)) {
		return nil, &restoreIssue{arcadev1alpha1.ReasonIdentityMismatch, "the selected target data changed or is not yet observed; create a new exact pinned restore request"}
	}
	if restore.Spec.TargetData != nil && !sameDataSelection(restore.Spec.TargetData, previous) {
		return nil, &restoreIssue{arcadev1alpha1.ReasonIdentityMismatch, "target data claims do not match the immutable restore request"}
	}
	if server.Status.ObservedData == nil || !sameDataSelection(server.Status.ObservedData, previous) ||
		server.Status.ObservedGeneration != server.Generation ||
		(server.Spec.DesiredState == arcadev1alpha1.DesiredStateRunning && server.Status.Phase != arcadev1alpha1.PhaseReady) ||
		(server.Spec.DesiredState == arcadev1alpha1.DesiredStateStopped && server.Status.Phase != arcadev1alpha1.PhaseStopped) {
		return nil, &restoreIssue{arcadev1alpha1.ReasonIdentityMismatch, "the current target runtime and exact data selection must be observed before restore"}
	}
	candidateIdentity, err := platformdata.RestoreDataIdentity(restore.UID)
	if err != nil || candidateIdentity == previous.Identity {
		return nil, &restoreIssue{arcadev1alpha1.ReasonIdentityMismatch, "the candidate data identity is unavailable or aliases active data"}
	}
	slices.SortFunc(previous.Claims, func(a, b arcadev1alpha1.RetainedDataClaimReference) int { return strings.Compare(a.Path, b.Path) })
	slices.SortFunc(previousPaths, func(a, b arcadev1alpha1.DataPathIdentity) int { return strings.Compare(a.Name, b.Name) })
	slices.SortFunc(targetPaths, func(a, b restoreworker.PathContract) int { return strings.Compare(a.Name, b.Name) })
	return &restoreSubject{
		server: server, definition: definition, plan: plan, previous: previous, previousPaths: previousPaths,
		candidateIdentity: candidateIdentity, source: backup.Status.Source.DeepCopy(), artifact: artifact.DeepCopy(),
		settingsDigest: settingsDigest, targetPaths: targetPaths,
	}, nil
}

func (r *GameRestoreReconciler) nowRestore() metav1.Time {
	if r.Now != nil {
		return r.Now()
	}
	return metav1.Now()
}

func (r *GameRestoreReconciler) directRestoreReader() client.Reader {
	if r.APIReader != nil {
		return r.APIReader
	}
	return r.Client
}

func (r *GameRestoreReconciler) preparedRestore(ctx context.Context, restore *arcadev1alpha1.GameRestore) (*restoreSubject, *restoreIssue) {
	if restore.Status.Source == nil || restore.Status.Artifact == nil || restore.Status.PreviousDataIdentity == "" || len(restore.Status.PreviousData) == 0 {
		return nil, &restoreIssue{arcadev1alpha1.ReasonIdentityMismatch, "restore has no complete durable source and previous-data snapshot"}
	}
	server := &arcadev1alpha1.GameServer{}
	key := types.NamespacedName{Namespace: restore.Namespace, Name: restore.Spec.Target.Name}
	if err := r.directRestoreReader().Get(ctx, key, server); err != nil || string(server.UID) != restore.Spec.Target.UID || !server.DeletionTimestamp.IsZero() {
		return nil, &restoreIssue{arcadev1alpha1.ReasonIdentityMismatch, "the exact target GameServer is unavailable"}
	}
	stopGeneration := restore.Spec.Target.Generation
	if restore.Spec.Target.DesiredState == arcadev1alpha1.DesiredStateRunning {
		stopGeneration++
	}
	if server.Generation != restore.Spec.Target.Generation && server.Generation != stopGeneration {
		return nil, &restoreIssue{arcadev1alpha1.ReasonIdentityMismatch, "the target generation changed outside the restore-owned cold stop"}
	}
	if server.Generation == restore.Spec.Target.Generation && server.Spec.DesiredState != restore.Spec.Target.DesiredState ||
		server.Generation == stopGeneration && server.Spec.DesiredState != arcadev1alpha1.DesiredStateStopped {
		return nil, &restoreIssue{arcadev1alpha1.ReasonIdentityMismatch, "the target runtime intent changed outside restore authority"}
	}
	definition, err := r.Catalog.Get(server.Spec.Game)
	if err != nil || !definition.Capabilities.Restore || !definition.Capabilities.ColdBackup || server.Spec.Game != restore.Status.Source.Game ||
		server.Spec.ImageDigest != restore.Status.Source.ImageDigest {
		return nil, &restoreIssue{arcadev1alpha1.ReasonIdentityMismatch, "the target adapter or immutable image no longer matches the verified source"}
	}
	settingsDigest, err := definition.SettingsDigest(server.Spec.Settings.Raw)
	if err != nil || settingsDigest != restore.Status.Source.SettingsDigest {
		return nil, &restoreIssue{arcadev1alpha1.ReasonIdentityMismatch, "the target settings changed after restore preflight"}
	}
	plan, err := platformkube.Build(server, definition)
	if err != nil || plan.DataIdentity != restore.Status.PreviousDataIdentity || len(plan.DataClaims) != len(restore.Status.PreviousData) {
		return nil, &restoreIssue{arcadev1alpha1.ReasonIdentityMismatch, "the previously selected target data changed after preflight"}
	}
	previous := &arcadev1alpha1.RetainedDataReference{Identity: plan.DataIdentity, Claims: make([]arcadev1alpha1.RetainedDataClaimReference, 0, len(plan.DataClaims))}
	for _, path := range restore.Status.PreviousData {
		previous.Claims = append(previous.Claims, arcadev1alpha1.RetainedDataClaimReference{Path: path.Name, ClaimRef: path.ClaimRef})
	}
	if server.Status.ActiveData != nil && !sameDataSelection(server.Status.ActiveData, previous) ||
		restore.Spec.TargetData != nil && !sameDataSelection(restore.Spec.TargetData, previous) {
		return nil, &restoreIssue{arcadev1alpha1.ReasonIdentityMismatch, "the exact previous-world selection changed after preflight"}
	}
	for _, claim := range plan.DataClaims {
		path := claim.Desired.Labels[platformkube.LabelDataPath]
		previousRef := restorePathByName(restore.Status.PreviousData, path)
		if previousRef == nil || previousRef.ClaimRef.Name != claim.Desired.Name ||
			(claim.RequiredUID != "" && previousRef.ClaimRef.UID != string(claim.RequiredUID)) {
			return nil, &restoreIssue{arcadev1alpha1.ReasonIdentityMismatch, "a previous-world path no longer identifies the exact original claim"}
		}
		actual := &corev1.PersistentVolumeClaim{}
		if err := r.directRestoreReader().Get(ctx, client.ObjectKeyFromObject(claim.Desired), actual); err != nil ||
			string(actual.UID) != previousRef.ClaimRef.UID || validateExistingDataClaim(actual, claim) != nil ||
			actual.Status.Phase != corev1.ClaimBound || actual.Spec.VolumeName == "" {
			return nil, &restoreIssue{arcadev1alpha1.ReasonIdentityMismatch, "an exact previous-world claim changed or became unavailable"}
		}
	}
	candidateIdentity, err := platformdata.RestoreDataIdentity(restore.UID)
	if err != nil || candidateIdentity == previous.Identity {
		return nil, &restoreIssue{arcadev1alpha1.ReasonIdentityMismatch, "candidate data identity aliases the previous world"}
	}
	targetPaths := make([]restoreworker.PathContract, 0, len(definition.PersistentPaths))
	for _, path := range definition.PersistentPaths {
		targetPaths = append(targetPaths, restoreworker.PathContract{Name: path.Name, MountPath: path.MountPath})
	}
	slices.SortFunc(targetPaths, func(a, b restoreworker.PathContract) int { return strings.Compare(a.Name, b.Name) })
	return &restoreSubject{
		server: server, definition: definition, plan: plan, previous: previous,
		previousPaths: slices.Clone(restore.Status.PreviousData), candidateIdentity: candidateIdentity,
		source: restore.Status.Source.DeepCopy(), artifact: restore.Status.Artifact.DeepCopy(),
		settingsDigest: settingsDigest, targetPaths: targetPaths,
	}, nil
}

func restorePathByName(paths []arcadev1alpha1.DataPathIdentity, name string) *arcadev1alpha1.DataPathIdentity {
	for index := range paths {
		if paths[index].Name == name {
			return &paths[index]
		}
	}
	return nil
}

func (r *GameRestoreReconciler) reconcileRestorePreflight(ctx context.Context, restore *arcadev1alpha1.GameRestore) (ctrl.Result, error) {
	if restoreFailureRecorded(restore) {
		return r.finishRestoreWithoutActivation(ctx, restore, arcadev1alpha1.DataPhaseFailed)
	}
	subject, issue := r.preparedRestore(ctx, restore)
	if issue != nil {
		return r.failRestorePreparation(ctx, restore, issue.reason, issue.message)
	}
	if err := r.acquireRestoreLease(ctx, restore, subject.candidateIdentity, subject.server.Name); err != nil {
		if errors.Is(err, errBackupOperationConflict) {
			return r.holdRestore(ctx, restore, arcadev1alpha1.ReasonOperationConflict, "the candidate identity is owned by another data operation")
		}
		return ctrl.Result{}, err
	}
	if restore.Status.PreflightVerifiedAt == nil {
		// The candidate lease does not affect the currently selected GameServer.
		// Repository access and inventory are proven before acquiring its lease,
		// stopping its runtime, or creating any target PVC.
		input := r.restoreWorkerInput(restore, subject, restoreworker.StagePreflight)
		outcome, result, err := r.runRestoreWorker(ctx, restore, input, subject.definition.RuntimeIdentity)
		if err != nil {
			return ctrl.Result{}, err
		}
		switch outcome {
		case restoreWorkerPending:
			return ctrl.Result{RequeueAfter: restoreRequeue}, nil
		case restoreWorkerFailed:
			return r.failRestorePreparation(ctx, restore, arcadev1alpha1.ReasonVerificationFailed, "repository-only preflight could not verify the exact backup; target data was not mutated")
		case restoreWorkerSucceeded:
			return ctrl.Result{}, r.writeRestoreStatus(ctx, restore, arcadev1alpha1.DataPhasePreparing, func(updated *arcadev1alpha1.GameRestore) {
				verifiedAt := metav1.NewTime(result.VerifiedAt)
				updated.Status.PreflightVerifiedAt = &verifiedAt
				r.setRestoreCondition(updated, arcadev1alpha1.ConditionArtifactReady, metav1.ConditionTrue, arcadev1alpha1.ReasonOperationAccepted, "repository-only preflight verified complete artifact inventory")
			})
		}
	}
	if pending, err := r.deleteRestoreWorkerAndWait(ctx, restore, restoreworker.StagePreflight); err != nil || pending {
		return ctrl.Result{RequeueAfter: restoreRequeue}, err
	}
	if err := r.clearRestoreWorkerExecution(ctx, restore, subject.candidateIdentity); err != nil {
		return ctrl.Result{}, err
	}
	if err := r.acquireRestoreLease(ctx, restore, subject.previous.Identity, subject.server.Name); err != nil {
		if errors.Is(err, errBackupOperationConflict) {
			return r.holdRestore(ctx, restore, arcadev1alpha1.ReasonOperationConflict, "another data operation owns the active world; wait for its terminal state")
		}
		return ctrl.Result{}, err
	}
	if restore.Status.Fence == nil {
		return r.ensureRestoreColdFence(ctx, restore, subject)
	}
	if subject.server.Generation != restore.Status.Fence.GameServer.Generation || subject.server.Spec.DesiredState != arcadev1alpha1.DesiredStateStopped {
		return r.failRestorePreparation(ctx, restore, arcadev1alpha1.ReasonIdentityMismatch, "the exact fenced target generation changed; no candidate worker will run")
	}
	candidates, ready, err := r.reconcileRestoreCandidates(ctx, restore, subject)
	if err != nil {
		return r.failRestorePreparation(ctx, restore, arcadev1alpha1.ReasonIdentityMismatch, "candidate storage conflicted with an existing retained claim; no previous-world claim was changed")
	}
	if !ready {
		return r.holdRestore(ctx, restore, arcadev1alpha1.ReasonColdStopPending, "waiting for every new candidate claim to bind before population")
	}
	return ctrl.Result{}, r.writeRestoreStatus(ctx, restore, arcadev1alpha1.DataPhaseRunning, func(updated *arcadev1alpha1.GameRestore) {
		updated.Status.CandidateData = candidates
		r.setRestoreCondition(updated, arcadev1alpha1.ConditionTargetReady, metav1.ConditionTrue, arcadev1alpha1.ReasonOperationAccepted, "fresh, exact candidate claims are bound and isolated from active data")
	})
}

func (r *GameRestoreReconciler) restoreWorkerInput(restore *arcadev1alpha1.GameRestore, subject *restoreSubject, stage restoreworker.Stage) restoreworker.Input {
	input := restoreworker.Input{
		Version: restoreworker.InputVersion, Stage: stage,
		OperationRef: arcadev1alpha1.ExactLocalReference{Name: restore.Name, UID: string(restore.UID)},
		BackupRef:    restore.Spec.BackupRef, Target: restore.Spec.Target,
		WorkerLeaseName:     platformkube.DataOperationLeaseName(subject.candidateIdentity),
		RepositorySecretRef: restore.Spec.RepositorySecretRef,
		Artifact:            *subject.artifact.DeepCopy(), Source: *subject.source.DeepCopy(),
		TargetGame: subject.server.Spec.Game, TargetImageDigest: subject.server.Spec.ImageDigest,
		TargetSettingsDigest: subject.settingsDigest, TargetPaths: slices.Clone(subject.targetPaths),
	}
	if stage == restoreworker.StagePopulate {
		input.CandidatePaths = slices.Clone(restore.Status.CandidateData)
		input.PreviousData = slices.Clone(restore.Status.PreviousData)
		input.PreviousDataIdentity = restore.Status.PreviousDataIdentity
	}
	return input
}

func (r *GameRestoreReconciler) ensureRestoreColdFence(ctx context.Context, restore *arcadev1alpha1.GameRestore, subject *restoreSubject) (ctrl.Result, error) {
	server := subject.server
	if restore.Spec.Target.DesiredState == arcadev1alpha1.DesiredStateRunning && server.Generation == restore.Spec.Target.Generation {
		updated := server.DeepCopy()
		updated.Spec.DesiredState = arcadev1alpha1.DesiredStateStopped
		if err := r.Update(ctx, updated); err != nil {
			return ctrl.Result{}, errors.New("request exact restore cold stop failed")
		}
		return ctrl.Result{RequeueAfter: restoreRequeue}, nil
	}
	expected := restore.Spec.Target.Generation
	if restore.Spec.Target.DesiredState == arcadev1alpha1.DesiredStateRunning {
		expected++
	}
	if server.Generation != expected || server.Spec.DesiredState != arcadev1alpha1.DesiredStateStopped ||
		server.Status.ObservedGeneration != expected || server.Status.Phase != arcadev1alpha1.PhaseStopped ||
		!sameDataSelection(server.Status.ObservedData, subject.previous) {
		return r.holdRestore(ctx, restore, arcadev1alpha1.ReasonColdStopPending, "waiting for the exact stopped target generation and previous data selection")
	}
	backupReader := &GameBackupReconciler{Client: r.Client, APIReader: r.APIReader}
	unmounted, err := backupReader.sourceClaimsUnmounted(ctx, restore.Namespace, restore.Status.PreviousData)
	if err != nil {
		return ctrl.Result{}, err
	}
	if !unmounted {
		return r.holdRestore(ctx, restore, arcadev1alpha1.ReasonColdStopPending, "waiting for every previous-world Pod and VolumeAttachment to detach")
	}
	return ctrl.Result{}, r.writeRestoreStatus(ctx, restore, arcadev1alpha1.DataPhasePreparing, func(updated *arcadev1alpha1.GameRestore) {
		now := r.nowRestore()
		updated.Status.Fence = &arcadev1alpha1.ColdDataFence{GameServer: arcadev1alpha1.ExactGameServerReference{
			ExactLocalReference: restore.Spec.Target.ExactLocalReference, Generation: expected, DesiredState: arcadev1alpha1.DesiredStateStopped,
		}, EstablishedAt: now}
		r.setRestoreCondition(updated, arcadev1alpha1.ConditionTargetReady, metav1.ConditionTrue, arcadev1alpha1.ReasonOperationAccepted, "the previous world is cold and fully detached")
	})
}

func (r *GameRestoreReconciler) acquireRestoreLease(ctx context.Context, restore *arcadev1alpha1.GameRestore, identity, serverName string) error {
	if identity == "" || serverName == "" {
		return errors.New("restore lease requires an exact retained-data identity")
	}
	name := platformkube.DataOperationLeaseName(identity)
	key := types.NamespacedName{Namespace: restore.Namespace, Name: name}
	existing := &coordinationv1.Lease{}
	if err := r.directRestoreReader().Get(ctx, key, existing); err != nil {
		if !apierrors.IsNotFound(err) {
			return errors.New("inspect retained-data restore lease failed")
		}
		now := metav1.NewMicroTime(r.nowRestore().Time)
		lease := &coordinationv1.Lease{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: restore.Namespace,
				Labels: map[string]string{
					platformkube.LabelManagedBy:    platformkube.ManagerName,
					platformkube.LabelDataIdentity: identity,
					platformkube.LabelRestoreUID:   string(restore.UID),
					platformkube.LabelInstance:     serverName,
				},
				Annotations: map[string]string{platformkube.AnnotationRestoreName: restore.Name},
			},
			Spec: coordinationv1.LeaseSpec{HolderIdentity: ptr.To(string(restore.UID)), AcquireTime: &now},
		}
		if err := r.Create(ctx, lease); err != nil {
			if apierrors.IsAlreadyExists(err) {
				return errBackupOperationConflict
			}
			return errors.New("create retained-data restore lease failed")
		}
		return nil
	}
	operation := arcadev1alpha1.ExactLocalReference{Name: restore.Name, UID: string(restore.UID)}
	if !platformkube.RestoreOperationLeaseMatches(existing, operation, serverName, identity) {
		return errBackupOperationConflict
	}
	return nil
}

func (r *GameRestoreReconciler) releaseRestoreLeases(ctx context.Context, restore *arcadev1alpha1.GameRestore) error {
	leases := &coordinationv1.LeaseList{}
	if err := r.directRestoreReader().List(ctx, leases, client.InNamespace(restore.Namespace), client.MatchingLabels{
		platformkube.LabelRestoreUID: string(restore.UID),
	}); err != nil {
		return errors.New("list retained-data restore leases failed")
	}
	candidateIdentity, err := platformdata.RestoreDataIdentity(restore.UID)
	if err != nil {
		return errors.New("derive candidate restore lease identity failed")
	}
	for i := range leases.Items {
		lease := &leases.Items[i]
		identity := lease.Labels[platformkube.LabelDataIdentity]
		if identity != candidateIdentity && identity != restore.Status.PreviousDataIdentity {
			return errors.New("refuse to release an unrecognized retained-data restore lease")
		}
		operation := arcadev1alpha1.ExactLocalReference{Name: restore.Name, UID: string(restore.UID)}
		if !platformkube.RestoreOperationLeaseMatches(lease, operation, restore.Spec.Target.Name, identity) {
			return errors.New("refuse to release a foreign retained-data restore lease")
		}
		if err := r.Delete(ctx, lease); err != nil && !apierrors.IsNotFound(err) {
			return errors.New("release retained-data restore lease failed")
		}
	}
	return nil
}

func (r *GameRestoreReconciler) clearRestoreWorkerExecution(ctx context.Context, restore *arcadev1alpha1.GameRestore, identity string) error {
	lease := &coordinationv1.Lease{}
	key := types.NamespacedName{Namespace: restore.Namespace, Name: platformkube.DataOperationLeaseName(identity)}
	if err := r.directRestoreReader().Get(ctx, key, lease); err != nil {
		return errors.New("inspect restore worker execution lease failed")
	}
	operation := arcadev1alpha1.ExactLocalReference{Name: restore.Name, UID: string(restore.UID)}
	if !platformkube.RestoreOperationLeaseMatches(lease, operation, restore.Spec.Target.Name, identity) {
		return errors.New("restore worker execution lease changed ownership")
	}
	if lease.Annotations[platformkube.AnnotationWorkerPodUID] == "" {
		return nil
	}
	updated := lease.DeepCopy()
	delete(updated.Annotations, platformkube.AnnotationWorkerPodUID)
	if err := r.Update(ctx, updated); err != nil {
		return errors.New("clear absent restore worker execution failed")
	}
	return nil
}

func (r *GameRestoreReconciler) allowRestoreSettlement(ctx context.Context, restore *arcadev1alpha1.GameRestore, identity string, state arcadev1alpha1.DesiredState, generation int64) error {
	lease := &coordinationv1.Lease{}
	key := types.NamespacedName{Namespace: restore.Namespace, Name: platformkube.DataOperationLeaseName(identity)}
	if err := r.directRestoreReader().Get(ctx, key, lease); err != nil {
		return errors.New("inspect exact restore settlement lease failed")
	}
	operation := arcadev1alpha1.ExactLocalReference{Name: restore.Name, UID: string(restore.UID)}
	if !platformkube.RestoreOperationLeaseMatches(lease, operation, restore.Spec.Target.Name, identity) {
		return errors.New("refuse runtime settlement through a foreign restore lease")
	}
	wantGeneration := strconv.FormatInt(generation, 10)
	if lease.Annotations[platformkube.AnnotationRuntimeSettlementState] == string(state) &&
		lease.Annotations[platformkube.AnnotationRuntimeSettlementGeneration] == wantGeneration &&
		lease.Annotations[platformkube.AnnotationRestoreSettlementData] == identity {
		return nil
	}
	updated := lease.DeepCopy()
	if updated.Annotations == nil {
		updated.Annotations = make(map[string]string)
	}
	updated.Annotations[platformkube.AnnotationRuntimeSettlementState] = string(state)
	updated.Annotations[platformkube.AnnotationRuntimeSettlementGeneration] = wantGeneration
	updated.Annotations[platformkube.AnnotationRestoreSettlementData] = identity
	if err := r.Update(ctx, updated); err != nil {
		return errors.New("authorize exact restore runtime settlement failed")
	}
	return nil
}

func (r *GameRestoreReconciler) reconcileRestoreCandidates(ctx context.Context, restore *arcadev1alpha1.GameRestore, subject *restoreSubject) ([]arcadev1alpha1.DataPathIdentity, bool, error) {
	if restore.Status.Fence == nil || restore.Status.PreflightVerifiedAt == nil ||
		subject.server.Spec.DesiredState != arcadev1alpha1.DesiredStateStopped ||
		subject.server.Generation != restore.Status.Fence.GameServer.Generation {
		return nil, false, errors.New("candidate claims require exact cold target fence and verified preflight")
	}
	previousVolumes := make(map[string]struct{}, len(subject.plan.DataClaims))
	previousNames := make(map[string]struct{}, len(subject.plan.DataClaims))
	previousUIDs := make(map[types.UID]struct{}, len(subject.plan.DataClaims))
	for _, path := range restore.Status.PreviousData {
		claim := &corev1.PersistentVolumeClaim{}
		key := types.NamespacedName{Namespace: restore.Namespace, Name: path.ClaimRef.Name}
		if err := r.directRestoreReader().Get(ctx, key, claim); err != nil || string(claim.UID) != path.ClaimRef.UID || claim.Spec.VolumeName == "" {
			return nil, false, errors.New("previous-world claim identity changed during candidate provisioning")
		}
		previousVolumes[claim.Spec.VolumeName] = struct{}{}
		previousNames[claim.Name] = struct{}{}
		previousUIDs[claim.UID] = struct{}{}
	}
	selection := make([]arcadev1alpha1.DataPathIdentity, 0, len(subject.plan.DataClaims))
	ready := true
	for _, sourcePlan := range subject.plan.DataClaims {
		pathName := sourcePlan.Desired.Labels[platformkube.LabelDataPath]
		name, err := platformdata.RestoreCandidateID(restore.UID, pathName)
		if err != nil {
			return nil, false, errors.New("derive deterministic restore candidate name failed")
		}
		if _, aliases := previousNames[name]; aliases {
			return nil, false, errors.New("candidate claim name aliases previous world")
		}
		desired := sourcePlan.Desired.DeepCopy()
		desired.Name = name
		desired.UID = ""
		desired.ResourceVersion = ""
		desired.Spec.VolumeName = ""
		desired.Labels[platformkube.LabelDataIdentity] = subject.candidateIdentity
		desired.Labels[platformkube.LabelRestoreUID] = string(restore.UID)
		desired.OwnerReferences = nil // Candidate worlds remain retained after restore deletion.
		key := client.ObjectKeyFromObject(desired)
		actual := &corev1.PersistentVolumeClaim{}
		if err := r.directRestoreReader().Get(ctx, key, actual); err != nil {
			if !apierrors.IsNotFound(err) {
				return nil, false, errors.New("inspect restore candidate claim failed")
			}
			if restore.Status.CandidateData != nil {
				return nil, false, errors.New("previously recorded candidate claim disappeared")
			}
			if err := r.Create(ctx, desired); err != nil {
				return nil, false, errors.New("create isolated restore candidate claim failed")
			}
			return nil, false, nil
		}
		if actual.Labels[platformkube.LabelRestoreUID] != string(restore.UID) ||
			actual.Labels[platformkube.LabelDataIdentity] != subject.candidateIdentity ||
			validateExistingDataClaim(actual, platformkube.DataClaimPlan{Desired: desired, RequiredUID: actual.UID}) != nil ||
			actual.UID == "" {
			return nil, false, errors.New("candidate claim collides with foreign or changed retained data")
		}
		if actual.Spec.Resources.Requests.Storage().Cmp(*desired.Spec.Resources.Requests.Storage()) < 0 {
			return nil, false, errors.New("candidate claim is smaller than the certified target path")
		}
		if _, aliases := previousUIDs[actual.UID]; aliases || actual.Spec.VolumeName != "" && hasVolume(previousVolumes, actual.Spec.VolumeName) {
			return nil, false, errors.New("candidate storage aliases previous-world PVC or PV")
		}
		if actual.Status.Phase != corev1.ClaimBound || actual.Spec.VolumeName == "" {
			ready = false
		}
		if restore.Status.CandidateData != nil {
			recorded := restorePathByName(restore.Status.CandidateData, pathName)
			if recorded == nil || recorded.ClaimRef.Name != actual.Name || recorded.ClaimRef.UID != string(actual.UID) {
				return nil, false, errors.New("candidate claim changed after its exact identity was recorded")
			}
		}
		selection = append(selection, arcadev1alpha1.DataPathIdentity{
			Name: pathName, MountPath: subjectPathMount(subject.targetPaths, pathName),
			ClaimRef: arcadev1alpha1.ExactLocalReference{Name: actual.Name, UID: string(actual.UID)},
		})
	}
	claims := &corev1.PersistentVolumeClaimList{}
	if err := r.directRestoreReader().List(ctx, claims, client.InNamespace(restore.Namespace), client.MatchingLabels{
		platformkube.LabelDataIdentity: subject.candidateIdentity,
	}); err != nil {
		return nil, false, errors.New("list complete candidate data identity failed")
	}
	if len(claims.Items) != len(subject.plan.DataClaims) {
		return nil, false, errors.New("candidate data identity has missing or extra claims")
	}
	for i := range claims.Items {
		claim := &claims.Items[i]
		path := restorePathByName(selection, claim.Labels[platformkube.LabelDataPath])
		if path == nil || path.ClaimRef.Name != claim.Name || path.ClaimRef.UID != string(claim.UID) {
			return nil, false, errors.New("candidate data identity contains an unexpected claim")
		}
	}
	slices.SortFunc(selection, func(a, b arcadev1alpha1.DataPathIdentity) int { return strings.Compare(a.Name, b.Name) })
	return selection, ready, nil
}

func hasVolume(volumes map[string]struct{}, name string) bool {
	_, exists := volumes[name]
	return exists
}

func subjectPathMount(paths []restoreworker.PathContract, name string) string {
	for _, path := range paths {
		if path.Name == name {
			return path.MountPath
		}
	}
	return ""
}

type restoreWorkerOutcome int

const (
	restoreWorkerPending restoreWorkerOutcome = iota
	restoreWorkerSucceeded
	restoreWorkerFailed
)

func (r *GameRestoreReconciler) runRestoreWorker(ctx context.Context, restore *arcadev1alpha1.GameRestore, input restoreworker.Input, identity game.RuntimeIdentity) (restoreWorkerOutcome, restoreworker.Result, error) {
	if input.Stage == restoreworker.StagePopulate && restore.Status.PopulateJobUID != "" {
		existing := &batchv1.Job{}
		key := types.NamespacedName{Namespace: restore.Namespace, Name: platformkube.RestoreResourceName(restore.UID, input.Stage)}
		if err := r.directRestoreReader().Get(ctx, key, existing); err != nil {
			if apierrors.IsNotFound(err) {
				return restoreWorkerFailed, restoreworker.Result{}, nil
			}
			return restoreWorkerPending, restoreworker.Result{}, errors.New("inspect journaled restore worker Job failed")
		}
		if string(existing.UID) != restore.Status.PopulateJobUID {
			return restoreWorkerFailed, restoreworker.Result{}, nil
		}
	}
	resources, err := platformkube.BuildRestoreResources(restore, input, r.WorkerImage, identity)
	if err != nil {
		return restoreWorkerPending, restoreworker.Result{}, errors.New("build bounded restore worker failed; inspect controller configuration")
	}
	if err := r.reconcileRestoreInput(ctx, restore, resources.Input); err != nil {
		return restoreWorkerPending, restoreworker.Result{}, err
	}
	changed, err := r.reconcileRestoreAuthority(ctx, restore, resources)
	if err != nil {
		return restoreWorkerPending, restoreworker.Result{}, err
	}
	job, created, err := r.reconcileRestoreJob(ctx, restore, input.Stage, resources.Job)
	if err != nil {
		return restoreWorkerPending, restoreworker.Result{}, err
	}
	if changed || created {
		return restoreWorkerPending, restoreworker.Result{}, nil
	}
	if input.Stage == restoreworker.StagePopulate {
		if restore.Status.PopulateJobUID == "" {
			if job.UID == "" || job.Spec.Suspend == nil || !*job.Spec.Suspend {
				return restoreWorkerFailed, restoreworker.Result{}, nil
			}
			if err := r.writeRestoreStatus(ctx, restore, restore.Status.Phase, func(updated *arcadev1alpha1.GameRestore) {
				updated.Status.PopulateJobUID = string(job.UID)
			}); err != nil {
				return restoreWorkerPending, restoreworker.Result{}, err
			}
			return restoreWorkerPending, restoreworker.Result{}, nil
		}
		if string(job.UID) != restore.Status.PopulateJobUID {
			return restoreWorkerFailed, restoreworker.Result{}, nil
		}
	}
	if job.Spec.Suspend == nil || *job.Spec.Suspend {
		updated := job.DeepCopy()
		updated.Spec.Suspend = ptr.To(false)
		if err := r.Update(ctx, updated); err != nil {
			return restoreWorkerPending, restoreworker.Result{}, errors.New("activate validated restore Job failed")
		}
		return restoreWorkerPending, restoreworker.Result{}, nil
	}
	if jobFailed(job) {
		return restoreWorkerFailed, restoreworker.Result{}, nil
	}
	podState, err := r.authorizeRestoreWorkerPod(ctx, restore, input.Stage, job)
	if err != nil {
		return restoreWorkerPending, restoreworker.Result{}, err
	}
	if podState == backupPodOverlap || podState == backupPodChanged {
		return restoreWorkerPending, restoreworker.Result{}, errors.New("restore worker Pod admission or execution identity changed; leave it gated and inspect exact ownership")
	}
	if podState != backupPodAuthorized || !jobComplete(job) {
		if restoreWorkerResultGraceExpired(job, r.nowRestore().Time) {
			return restoreWorkerFailed, restoreworker.Result{}, nil
		}
		return restoreWorkerPending, restoreworker.Result{}, nil
	}
	result, err := r.restoreWorkerResult(ctx, restore, input.Stage, job)
	if err != nil {
		if errors.Is(err, errBackupWorkerResultPending) {
			if restoreWorkerResultGraceExpired(job, r.nowRestore().Time) {
				return restoreWorkerFailed, restoreworker.Result{}, nil
			}
			return restoreWorkerPending, restoreworker.Result{}, nil
		}
		return restoreWorkerFailed, restoreworker.Result{}, nil
	}
	if result.Stage != input.Stage || result.ArtifactID != input.Artifact.ID ||
		result.ManifestDigest != input.Artifact.ManifestDigest || result.PathCount != int32(len(input.Source.Paths)) ||
		result.Version != restoreworker.ResultVersion || result.VerifiedAt.IsZero() {
		return restoreWorkerFailed, restoreworker.Result{}, nil
	}
	return restoreWorkerSucceeded, result, nil
}

func restoreControlledBy(object metav1.Object, restore *arcadev1alpha1.GameRestore) bool {
	return controlledBy(object.GetOwnerReferences(), "GameRestore", restore.Name, restore.UID)
}

func (r *GameRestoreReconciler) reconcileRestoreInput(ctx context.Context, restore *arcadev1alpha1.GameRestore, desired *corev1.ConfigMap) error {
	existing := &corev1.ConfigMap{}
	key := client.ObjectKeyFromObject(desired)
	if err := r.directRestoreReader().Get(ctx, key, existing); err != nil {
		if !apierrors.IsNotFound(err) {
			return errors.New("inspect immutable restore worker input failed")
		}
		if err := r.Create(ctx, desired.DeepCopy()); err != nil {
			return errors.New("create immutable restore worker input failed")
		}
		return nil
	}
	if !restoreControlledBy(existing, restore) || !apiequality.Semantic.DeepEqual(existing.Labels, desired.Labels) ||
		!apiequality.Semantic.DeepEqual(existing.Data, desired.Data) || existing.Immutable == nil || !*existing.Immutable {
		return errors.New("restore worker input collides with a foreign or changed ConfigMap")
	}
	return nil
}

func (r *GameRestoreReconciler) reconcileRestoreAuthority(ctx context.Context, restore *arcadev1alpha1.GameRestore, resources platformkube.RestoreResources) (bool, error) {
	changed := false
	sa := &corev1.ServiceAccount{}
	if err := r.directRestoreReader().Get(ctx, client.ObjectKeyFromObject(resources.ServiceAccount), sa); err != nil {
		if !apierrors.IsNotFound(err) {
			return false, errors.New("inspect restore ServiceAccount failed")
		}
		if err := r.Create(ctx, resources.ServiceAccount.DeepCopy()); err != nil {
			return false, errors.New("create restore ServiceAccount failed")
		}
		changed = true
	} else if !restoreControlledBy(sa, restore) || !apiequality.Semantic.DeepEqual(sa.Labels, resources.ServiceAccount.Labels) ||
		sa.AutomountServiceAccountToken == nil || *sa.AutomountServiceAccountToken {
		return false, errors.New("restore ServiceAccount collides with foreign or changed authority")
	}
	role := &rbacv1.Role{}
	if err := r.directRestoreReader().Get(ctx, client.ObjectKeyFromObject(resources.Role), role); err != nil {
		if !apierrors.IsNotFound(err) {
			return false, errors.New("inspect restore Role failed")
		}
		if err := r.Create(ctx, resources.Role.DeepCopy()); err != nil {
			return false, errors.New("create scoped restore Role failed")
		}
		changed = true
	} else if !restoreControlledBy(role, restore) || !apiequality.Semantic.DeepEqual(role.Labels, resources.Role.Labels) ||
		!apiequality.Semantic.DeepEqual(role.Rules, resources.Role.Rules) {
		return false, errors.New("restore Role collides with foreign or broadened authority")
	}
	binding := &rbacv1.RoleBinding{}
	if err := r.directRestoreReader().Get(ctx, client.ObjectKeyFromObject(resources.RoleBinding), binding); err != nil {
		if !apierrors.IsNotFound(err) {
			return false, errors.New("inspect restore RoleBinding failed")
		}
		if err := r.Create(ctx, resources.RoleBinding.DeepCopy()); err != nil {
			return false, errors.New("create scoped restore RoleBinding failed")
		}
		changed = true
	} else if !restoreControlledBy(binding, restore) || !apiequality.Semantic.DeepEqual(binding.Labels, resources.RoleBinding.Labels) ||
		!apiequality.Semantic.DeepEqual(binding.Subjects, resources.RoleBinding.Subjects) ||
		!apiequality.Semantic.DeepEqual(binding.RoleRef, resources.RoleBinding.RoleRef) {
		return false, errors.New("restore RoleBinding collides with foreign or changed authority")
	}
	return changed, nil
}

func (r *GameRestoreReconciler) reconcileRestoreJob(ctx context.Context, restore *arcadev1alpha1.GameRestore, stage restoreworker.Stage, desired *batchv1.Job) (*batchv1.Job, bool, error) {
	job := &batchv1.Job{}
	key := client.ObjectKeyFromObject(desired)
	if err := r.directRestoreReader().Get(ctx, key, job); err != nil {
		if !apierrors.IsNotFound(err) {
			return nil, false, errors.New("inspect bounded restore Job failed")
		}
		pods := &corev1.PodList{}
		if err := r.listRestoreStagePods(ctx, restore, stage, pods); err != nil {
			return nil, false, errors.New("inspect orphaned restore Pods failed")
		}
		if len(pods.Items) != 0 {
			return nil, false, errors.New("prior restore worker Pod remains; no replacement Job may start")
		}
		if err := r.Create(ctx, desired.DeepCopy()); err != nil {
			return nil, false, errors.New("create bounded restore worker Job failed")
		}
		return desired, true, nil
	}
	expected := desired
	if job.Spec.Suspend == nil || !*job.Spec.Suspend {
		expected = desired.DeepCopy()
		expected.Spec.Suspend = ptr.To(false)
	}
	if !restoreControlledBy(job, restore) || !apiequality.Semantic.DeepEqual(job.Labels, desired.Labels) ||
		!apiequality.Semantic.DeepEqual(job.Annotations, desired.Annotations) || !backupJobSpecMatches(expected, job) {
		return nil, false, errors.New("restore worker Job collides with foreign or changed execution spec")
	}
	return job, false, nil
}

func (r *GameRestoreReconciler) authorizeRestoreWorkerPod(ctx context.Context, restore *arcadev1alpha1.GameRestore, stage restoreworker.Stage, job *batchv1.Job) (backupPodState, error) {
	pods := &corev1.PodList{}
	if err := r.listRestoreStagePods(ctx, restore, stage, pods); err != nil {
		return backupPodPending, errors.New("inspect exact restore Pod failed")
	}
	if len(pods.Items) == 0 {
		return backupPodPending, nil
	}
	if len(pods.Items) != 1 {
		return backupPodOverlap, nil
	}
	pod := &pods.Items[0]
	if !restorePodIdentityMatches(job, pod) {
		return backupPodChanged, nil
	}
	if authorized := pod.Annotations[platformkube.AnnotationRestorePodAuthorized]; authorized != "" {
		if authorized != string(pod.UID) || len(pod.Spec.SchedulingGates) != 0 {
			return backupPodChanged, nil
		}
		return backupPodAuthorized, nil
	}
	if pod.Spec.NodeName != "" || pod.Status.Phase != "" && pod.Status.Phase != corev1.PodPending ||
		len(pod.Status.InitContainerStatuses) != 0 || len(pod.Status.ContainerStatuses) != 0 ||
		!restorePodSpecMatches(job, pod) {
		return backupPodChanged, nil
	}
	updated := pod.DeepCopy()
	if updated.Annotations == nil {
		updated.Annotations = make(map[string]string)
	}
	updated.Annotations[platformkube.AnnotationRestorePodAuthorized] = string(pod.UID)
	updated.Spec.SchedulingGates = nil
	if err := r.Update(ctx, updated); err != nil {
		return backupPodPending, errors.New("authorize exact gated restore Pod failed")
	}
	return backupPodPending, nil
}

func restorePodIdentityMatches(job *batchv1.Job, pod *corev1.Pod) bool {
	if job == nil || pod == nil || job.UID == "" || pod.UID == "" || pod.Namespace != job.Namespace || !pod.DeletionTimestamp.IsZero() ||
		len(pod.OwnerReferences) != 1 || !controlledBy(pod.OwnerReferences, "Job", job.Name, job.UID) ||
		!apiequality.Semantic.DeepEqual(pod.Labels, job.Spec.Template.Labels) {
		return false
	}
	return workerPodAnnotationsMatch(pod.Annotations, job.Spec.Template.Annotations, platformkube.AnnotationRestorePodAuthorized)
}

func restorePodSpecMatches(job *batchv1.Job, pod *corev1.Pod) bool {
	if job == nil || pod == nil || len(pod.Spec.SchedulingGates) != 1 ||
		pod.Spec.SchedulingGates[0].Name != platformkube.RestoreSchedulingGate {
		return false
	}
	desired := job.Spec.Template.Spec.DeepCopy()
	actual := pod.Spec.DeepCopy()
	normalizeBackupPodDefaults(desired)
	normalizeBackupPodDefaults(actual)
	return apiequality.Semantic.DeepEqual(desired, actual)
}

func (r *GameRestoreReconciler) restoreWorkerResult(ctx context.Context, restore *arcadev1alpha1.GameRestore, stage restoreworker.Stage, job *batchv1.Job) (restoreworker.Result, error) {
	pods := &corev1.PodList{}
	if err := r.listRestoreStagePods(ctx, restore, stage, pods); err != nil {
		return restoreworker.Result{}, errors.New("inspect restore result Pod failed")
	}
	if len(pods.Items) != 1 {
		return restoreworker.Result{}, errBackupWorkerResultPending
	}
	pod := &pods.Items[0]
	if !restorePodIdentityMatches(job, pod) || pod.Annotations[platformkube.AnnotationRestorePodAuthorized] != string(pod.UID) {
		return restoreworker.Result{}, errors.New("restore result Pod was not exactly authorized")
	}
	for _, status := range pod.Status.ContainerStatuses {
		if status.Name != "restore-worker" || status.State.Terminated == nil || status.State.Terminated.ExitCode != 0 {
			continue
		}
		decoder := json.NewDecoder(bytes.NewBufferString(status.State.Terminated.Message))
		decoder.DisallowUnknownFields()
		var result restoreworker.Result
		if decoder.Decode(&result) != nil || decoder.Decode(&struct{}{}) != io.EOF {
			return restoreworker.Result{}, errors.New("restore worker result is invalid")
		}
		return result, nil
	}
	return restoreworker.Result{}, errBackupWorkerResultPending
}

func (r *GameRestoreReconciler) deleteRestoreWorkerAndWait(ctx context.Context, restore *arcadev1alpha1.GameRestore, stage restoreworker.Stage) (bool, error) {
	job := &batchv1.Job{}
	key := types.NamespacedName{Namespace: restore.Namespace, Name: platformkube.RestoreResourceName(restore.UID, stage)}
	if err := r.directRestoreReader().Get(ctx, key, job); err == nil {
		if !restoreControlledBy(job, restore) {
			return false, errors.New("refuse to delete foreign restore Job")
		}
		foreground := metav1.DeletePropagationForeground
		if err := r.Delete(ctx, job, &client.DeleteOptions{PropagationPolicy: &foreground}); err != nil && !apierrors.IsNotFound(err) {
			return false, errors.New("stop owned restore Job failed")
		}
		return true, nil
	} else if !apierrors.IsNotFound(err) {
		return false, errors.New("inspect owned restore Job failed")
	}
	pods := &corev1.PodList{}
	if err := r.listRestoreStagePods(ctx, restore, stage, pods); err != nil {
		return false, errors.New("verify restore Pod absence failed")
	}
	if len(pods.Items) > 0 {
		return true, nil
	}
	return r.deleteRestoreStageAuthorityAndWait(ctx, restore, stage)
}

func (r *GameRestoreReconciler) listRestoreStagePods(ctx context.Context, restore *arcadev1alpha1.GameRestore, stage restoreworker.Stage, result *corev1.PodList) error {
	all := &corev1.PodList{}
	if err := r.directRestoreReader().List(ctx, all, client.InNamespace(restore.Namespace)); err != nil {
		return err
	}
	jobName := platformkube.RestoreResourceName(restore.UID, stage)
	if jobName == "" {
		return errors.New("restore stage identity is invalid")
	}
	for i := range all.Items {
		pod := &all.Items[i]
		matchesLabels := pod.Labels[platformkube.LabelRestoreUID] == string(restore.UID) && pod.Labels[platformkube.LabelRestoreStage] == string(stage)
		matchesOwner := false
		for _, owner := range pod.OwnerReferences {
			if owner.APIVersion == batchv1.SchemeGroupVersion.String() && owner.Kind == "Job" && owner.Name == jobName {
				matchesOwner = true
				break
			}
		}
		if matchesLabels || matchesOwner {
			result.Items = append(result.Items, *pod.DeepCopy())
		}
	}
	return nil
}

func (r *GameRestoreReconciler) deleteRestoreStageAuthorityAndWait(ctx context.Context, restore *arcadev1alpha1.GameRestore, stage restoreworker.Stage) (bool, error) {
	name := platformkube.RestoreResourceName(restore.UID, stage)
	if name == "" {
		return false, errors.New("restore stage resource identity is invalid")
	}
	key := types.NamespacedName{Namespace: restore.Namespace, Name: name + "-authority"}
	resources := []client.Object{&rbacv1.RoleBinding{}, &rbacv1.Role{}, &corev1.ServiceAccount{}}
	for _, object := range resources {
		if err := r.directRestoreReader().Get(ctx, key, object); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return false, errors.New("inspect owned restore worker authority failed")
		}
		if !restoreControlledBy(object, restore) || object.GetLabels()[platformkube.LabelRestoreStage] != string(stage) {
			return false, errors.New("refuse to delete foreign restore worker authority")
		}
		if err := r.Delete(ctx, object); err != nil && !apierrors.IsNotFound(err) {
			return false, errors.New("remove scoped restore worker authority failed")
		}
		return true, nil
	}
	input := &corev1.ConfigMap{}
	key.Name = name + "-input"
	if err := r.directRestoreReader().Get(ctx, key, input); err != nil {
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		return false, errors.New("inspect owned restore worker input failed")
	}
	if !restoreControlledBy(input, restore) || input.Labels[platformkube.LabelRestoreStage] != string(stage) {
		return false, errors.New("refuse to delete foreign restore worker input")
	}
	if err := r.Delete(ctx, input); err != nil && !apierrors.IsNotFound(err) {
		return false, errors.New("remove scoped restore worker input failed")
	}
	return true, nil
}

func (r *GameRestoreReconciler) deleteAllRestoreWorkers(ctx context.Context, restore *arcadev1alpha1.GameRestore) (bool, error) {
	for _, stage := range []restoreworker.Stage{restoreworker.StagePreflight, restoreworker.StagePopulate} {
		pending, err := r.deleteRestoreWorkerAndWait(ctx, restore, stage)
		if err != nil || pending {
			return pending, err
		}
	}
	return false, nil
}

func (r *GameRestoreReconciler) reconcileRestorePopulate(ctx context.Context, restore *arcadev1alpha1.GameRestore) (ctrl.Result, error) {
	if restoreFailureRecorded(restore) {
		return r.finishRestoreWithoutActivation(ctx, restore, arcadev1alpha1.DataPhaseFailed)
	}
	subject, issue := r.preparedRestore(ctx, restore)
	if issue != nil || restore.Status.Fence == nil || restore.Status.PreflightVerifiedAt == nil ||
		subject.server.Generation != restore.Status.Fence.GameServer.Generation || subject.server.Spec.DesiredState != arcadev1alpha1.DesiredStateStopped ||
		!sameDataSelection(subject.server.Status.ObservedData, subject.previous) {
		return r.failRestorePreparation(ctx, restore, arcadev1alpha1.ReasonIdentityMismatch, "the exact cold target or previous world changed before candidate population")
	}
	candidates, ready, err := r.reconcileRestoreCandidates(ctx, restore, subject)
	if err != nil || !ready || !sameDataPaths(candidates, restore.Status.CandidateData) {
		return r.failRestorePreparation(ctx, restore, arcadev1alpha1.ReasonIdentityMismatch, "fresh candidate claims are no longer complete, bound, and distinct from active data")
	}
	if restore.Status.PopulateRetryPending {
		if !canRetryRestorePopulate(restore.Status.PopulateAttempts) {
			return r.failRestorePreparation(ctx, restore, arcadev1alpha1.ReasonWorkerFailed, "populate retry journal is outside its bounded attempt range")
		}
		if pending, err := r.deleteRestoreWorkerAndWait(ctx, restore, restoreworker.StagePopulate); err != nil || pending {
			return ctrl.Result{RequeueAfter: restoreRequeue}, err
		}
		if err := r.clearRestoreWorkerExecution(ctx, restore, subject.candidateIdentity); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, r.writeRestoreStatus(ctx, restore, arcadev1alpha1.DataPhaseRunning, func(updated *arcadev1alpha1.GameRestore) {
			updated.Status.PopulateAttempts++
			updated.Status.PopulateRetryPending = false
			updated.Status.PopulateJobUID = ""
			r.setRestoreCondition(updated, arcadev1alpha1.ConditionArtifactReady, metav1.ConditionUnknown, arcadev1alpha1.ReasonWorkerRetrying, "the failed worker is absent; retrying the same exact candidate claims with a new bounded Pod")
		})
	}
	if restore.Status.PopulateAttempts == 0 {
		return ctrl.Result{}, r.writeRestoreStatus(ctx, restore, arcadev1alpha1.DataPhaseRunning, func(updated *arcadev1alpha1.GameRestore) {
			updated.Status.PopulateAttempts = 1
		})
	}
	if restore.Status.PopulateAttempts > maxRestorePopulateAttempts {
		return r.failRestorePreparation(ctx, restore, arcadev1alpha1.ReasonWorkerFailed, "populate attempt journal exceeded its certified bound")
	}
	input := r.restoreWorkerInput(restore, subject, restoreworker.StagePopulate)
	if err := r.verifyRestoreVolumeIsolation(ctx, restore.Namespace, restore.CreationTimestamp, restore.Status.PreviousData, restore.Status.CandidateData, restore.Status.Source.Paths); err != nil {
		return r.failRestorePreparation(ctx, restore, arcadev1alpha1.ReasonIdentityMismatch, "candidate storage cannot be proven physically distinct from the previous world")
	}
	outcome, result, err := r.runRestoreWorker(ctx, restore, input, subject.definition.RuntimeIdentity)
	if err != nil {
		return ctrl.Result{}, err
	}
	switch outcome {
	case restoreWorkerPending:
		return ctrl.Result{RequeueAfter: restoreRequeue}, nil
	case restoreWorkerFailed:
		if canRetryRestorePopulate(restore.Status.PopulateAttempts) {
			return ctrl.Result{}, r.writeRestoreStatus(ctx, restore, arcadev1alpha1.DataPhaseRunning, func(updated *arcadev1alpha1.GameRestore) {
				updated.Status.PopulateRetryPending = true
				r.setRestoreCondition(updated, arcadev1alpha1.ConditionArtifactReady, metav1.ConditionUnknown, arcadev1alpha1.ReasonWorkerRetrying, "candidate worker failed; remove exact Pod before retrying the same retained candidate claims")
			})
		}
		return r.failRestorePreparation(ctx, restore, arcadev1alpha1.ReasonVerificationFailed, "candidate population or verification failed after three serialized attempts; previous world remains selected")
	case restoreWorkerSucceeded:
		return ctrl.Result{}, r.writeRestoreStatus(ctx, restore, arcadev1alpha1.DataPhaseVerifying, func(updated *arcadev1alpha1.GameRestore) {
			updated.Status.CandidateVerification = &arcadev1alpha1.CandidateDataVerification{
				Result: arcadev1alpha1.VerificationVerified, ManifestDigest: result.ManifestDigest,
				PathCount: result.PathCount, VerifiedAt: metav1.NewTime(result.VerifiedAt),
			}
			r.setRestoreCondition(updated, arcadev1alpha1.ConditionVerified, metav1.ConditionTrue, arcadev1alpha1.ReasonOperationAccepted, "fresh candidate claims match the complete verified artifact inventory")
		})
	}
	return ctrl.Result{}, errors.New("restore worker returned an unsupported result")
}

func sameDataPaths(left, right []arcadev1alpha1.DataPathIdentity) bool {
	if len(left) == 0 || len(left) != len(right) {
		return false
	}
	lookup := make(map[string]arcadev1alpha1.DataPathIdentity, len(left))
	for _, path := range left {
		if _, exists := lookup[path.Name]; exists {
			return false
		}
		lookup[path.Name] = path
	}
	for _, path := range right {
		want, exists := lookup[path.Name]
		if !exists || path.MountPath != want.MountPath || path.ClaimRef.Namespace != nil ||
			path.ClaimRef.Name != want.ClaimRef.Name || path.ClaimRef.UID != want.ClaimRef.UID {
			return false
		}
		delete(lookup, path.Name)
	}
	return len(lookup) == 0
}

func (r *GameRestoreReconciler) reconcileRestoreVerification(ctx context.Context, restore *arcadev1alpha1.GameRestore) (ctrl.Result, error) {
	if pending, err := r.deleteRestoreWorkerAndWait(ctx, restore, restoreworker.StagePopulate); err != nil || pending {
		return ctrl.Result{RequeueAfter: restoreRequeue}, err
	}
	candidateIdentity, identityErr := platformdata.RestoreDataIdentity(restore.UID)
	if identityErr != nil {
		return ctrl.Result{}, identityErr
	}
	if err := r.clearRestoreWorkerExecution(ctx, restore, candidateIdentity); err != nil {
		return ctrl.Result{}, err
	}
	if restore.Status.CandidateVerification == nil || restoreFailureRecorded(restore) {
		return r.finishRestoreWithoutActivation(ctx, restore, arcadev1alpha1.DataPhaseFailed)
	}
	subject, issue := r.preparedRestore(ctx, restore)
	if issue != nil || restore.Status.Fence == nil || subject.server.Generation != restore.Status.Fence.GameServer.Generation ||
		subject.server.Spec.DesiredState != arcadev1alpha1.DesiredStateStopped || !sameDataSelection(subject.server.Status.ObservedData, subject.previous) {
		return r.failRestorePreparation(ctx, restore, arcadev1alpha1.ReasonIdentityMismatch, "the previous world or stopped target changed before atomic activation")
	}
	candidates, ready, err := r.reconcileRestoreCandidates(ctx, restore, subject)
	if err != nil || !ready || !sameDataPaths(candidates, restore.Status.CandidateData) {
		return r.failRestorePreparation(ctx, restore, arcadev1alpha1.ReasonIdentityMismatch, "verified candidate claims changed before atomic activation")
	}
	if err := r.ensureRestoreLeases(ctx, restore, subject.previous.Identity, subject.candidateIdentity); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, r.writeRestoreStatus(ctx, restore, arcadev1alpha1.DataPhaseActivating, func(updated *arcadev1alpha1.GameRestore) {
		now := r.nowRestore()
		updated.Status.ActivationStartedAt = &now
		r.setRestoreCondition(updated, arcadev1alpha1.ConditionOperationComplete, metav1.ConditionUnknown, arcadev1alpha1.ReasonColdStopPending, "verified candidate data is ready for one complete controller-owned selection change")
	})
}

func (r *GameRestoreReconciler) ensureRestoreLeases(ctx context.Context, restore *arcadev1alpha1.GameRestore, previousIdentity, candidateIdentity string) error {
	for _, identity := range []string{previousIdentity, candidateIdentity} {
		lease := &coordinationv1.Lease{}
		key := types.NamespacedName{Namespace: restore.Namespace, Name: platformkube.DataOperationLeaseName(identity)}
		if err := r.directRestoreReader().Get(ctx, key, lease); err != nil ||
			!platformkube.RestoreOperationLeaseMatches(lease, arcadev1alpha1.ExactLocalReference{Name: restore.Name, UID: string(restore.UID)}, restore.Spec.Target.Name, identity) {
			return errors.New("exact dual retained-data restore leases are unavailable")
		}
	}
	return nil
}

func restoreFailureRecorded(restore *arcadev1alpha1.GameRestore) bool {
	for _, condition := range restore.Status.Conditions {
		if condition.Type == arcadev1alpha1.ConditionOperationComplete && condition.Status == metav1.ConditionFalse &&
			condition.Reason != arcadev1alpha1.ReasonOperationCancelled {
			return true
		}
	}
	return false
}

func restoreFailureReason(restore *arcadev1alpha1.GameRestore) (string, string) {
	for _, condition := range restore.Status.Conditions {
		if condition.Type == arcadev1alpha1.ConditionOperationComplete && condition.Status == metav1.ConditionFalse {
			return condition.Reason, condition.Message
		}
	}
	return arcadev1alpha1.ReasonVerificationFailed, "restore work ended without a verified isolated candidate"
}

func (r *GameRestoreReconciler) failRestorePreparation(ctx context.Context, restore *arcadev1alpha1.GameRestore, reason, message string) (ctrl.Result, error) {
	if restore.Status.ActivationStartedAt != nil {
		return ctrl.Result{}, r.writeRestoreStatus(ctx, restore, arcadev1alpha1.DataPhaseRollingBack, func(updated *arcadev1alpha1.GameRestore) {
			r.setRestoreCondition(updated, arcadev1alpha1.ConditionOperationComplete, metav1.ConditionFalse, reason, message)
		})
	}
	if restore.Status.Phase == arcadev1alpha1.DataPhaseRunning {
		return ctrl.Result{}, r.writeRestoreStatus(ctx, restore, arcadev1alpha1.DataPhaseVerifying, func(updated *arcadev1alpha1.GameRestore) {
			r.setRestoreCondition(updated, arcadev1alpha1.ConditionOperationComplete, metav1.ConditionFalse, reason, message)
		})
	}
	if !restoreFailureRecorded(restore) {
		return ctrl.Result{}, r.writeRestoreStatus(ctx, restore, restore.Status.Phase, func(updated *arcadev1alpha1.GameRestore) {
			r.setRestoreCondition(updated, arcadev1alpha1.ConditionOperationComplete, metav1.ConditionFalse, reason, message)
		})
	}
	return r.finishRestoreWithoutActivation(ctx, restore, arcadev1alpha1.DataPhaseFailed)
}

func (r *GameRestoreReconciler) finishRestoreWithoutActivation(ctx context.Context, restore *arcadev1alpha1.GameRestore, terminal arcadev1alpha1.DataOperationPhase) (ctrl.Result, error) {
	if pending, err := r.deleteAllRestoreWorkers(ctx, restore); err != nil || pending {
		return ctrl.Result{RequeueAfter: restoreRequeue}, err
	}
	runtime, pending, err := r.settlePreviousBeforeActivation(ctx, restore)
	if err != nil {
		return r.holdRestore(ctx, restore, arcadev1alpha1.ReasonIdentityMismatch, "the exact previous-world runtime cannot be settled; keep data operation leases and inspect generation history")
	}
	if pending {
		return ctrl.Result{RequeueAfter: restoreRequeue}, nil
	}
	reason, message := restoreFailureReason(restore)
	if terminal == arcadev1alpha1.DataPhaseCancelled {
		reason, message = arcadev1alpha1.ReasonOperationCancelled, "cancellation ended before activation; previous data remains selected and runtime is settled"
	}
	err = r.writeRestoreStatus(ctx, restore, terminal, func(updated *arcadev1alpha1.GameRestore) {
		now := r.nowRestore()
		updated.Status.Runtime = runtime
		updated.Status.CompletedAt = &now
		r.setRestoreCondition(updated, arcadev1alpha1.ConditionOperationComplete, metav1.ConditionFalse, reason, message)
	})
	return ctrl.Result{Requeue: err == nil}, err
}

func (r *GameRestoreReconciler) reconcileRestoreCancellation(ctx context.Context, restore *arcadev1alpha1.GameRestore) (ctrl.Result, error) {
	return r.finishRestoreWithoutActivation(ctx, restore, arcadev1alpha1.DataPhaseCancelled)
}

func (r *GameRestoreReconciler) blockRestore(ctx context.Context, restore *arcadev1alpha1.GameRestore, reason, message string) (ctrl.Result, error) {
	err := r.writeRestoreStatus(ctx, restore, arcadev1alpha1.DataPhaseBlocked, func(updated *arcadev1alpha1.GameRestore) {
		r.setRestoreCondition(updated, arcadev1alpha1.ConditionTargetReady, metav1.ConditionFalse, reason, message)
	})
	return ctrl.Result{RequeueAfter: 5 * restoreRequeue}, err
}

func (r *GameRestoreReconciler) holdRestore(ctx context.Context, restore *arcadev1alpha1.GameRestore, reason, message string) (ctrl.Result, error) {
	err := r.writeRestoreStatus(ctx, restore, restore.Status.Phase, func(updated *arcadev1alpha1.GameRestore) {
		r.setRestoreCondition(updated, arcadev1alpha1.ConditionTargetReady, metav1.ConditionFalse, reason, message)
	})
	return ctrl.Result{RequeueAfter: restoreRequeue}, err
}

func restoreSelection(identity string, paths []arcadev1alpha1.DataPathIdentity) *arcadev1alpha1.RetainedDataReference {
	if identity == "" || len(paths) == 0 {
		return nil
	}
	selection := &arcadev1alpha1.RetainedDataReference{Identity: identity}
	for _, path := range paths {
		selection.Claims = append(selection.Claims, arcadev1alpha1.RetainedDataClaimReference{Path: path.Name, ClaimRef: path.ClaimRef})
	}
	return selection
}

func (r *GameRestoreReconciler) exactRestoreServer(ctx context.Context, restore *arcadev1alpha1.GameRestore) (*arcadev1alpha1.GameServer, error) {
	server := &arcadev1alpha1.GameServer{}
	key := types.NamespacedName{Namespace: restore.Namespace, Name: restore.Spec.Target.Name}
	if err := r.directRestoreReader().Get(ctx, key, server); err != nil || string(server.UID) != restore.Spec.Target.UID || !server.DeletionTimestamp.IsZero() {
		return nil, errors.New("the exact restore target is unavailable")
	}
	return server, nil
}

func (r *GameRestoreReconciler) verifyRestoreDataClaims(ctx context.Context, restore *arcadev1alpha1.GameRestore, paths []arcadev1alpha1.DataPathIdentity, identity string) error {
	if len(paths) == 0 || identity == "" {
		return errors.New("exact restore data paths are missing")
	}
	for _, path := range paths {
		claim := &corev1.PersistentVolumeClaim{}
		key := types.NamespacedName{Namespace: restore.Namespace, Name: path.ClaimRef.Name}
		if err := r.directRestoreReader().Get(ctx, key, claim); err != nil || string(claim.UID) != path.ClaimRef.UID ||
			claim.Labels[platformkube.LabelDataIdentity] != identity || claim.Labels[platformkube.LabelDataPath] != path.Name ||
			claim.Status.Phase != corev1.ClaimBound || claim.Spec.VolumeName == "" || !claim.DeletionTimestamp.IsZero() || len(claim.OwnerReferences) != 0 {
			return errors.New("an exact restore data claim changed or became unavailable")
		}
	}
	return nil
}

func (r *GameRestoreReconciler) updateRestoreActiveData(ctx context.Context, server *arcadev1alpha1.GameServer, selected *arcadev1alpha1.RetainedDataReference) error {
	if selected == nil || selected.Identity == "" || len(selected.Claims) == 0 {
		return errors.New("refuse incomplete GameServer data selection")
	}
	updated := server.DeepCopy()
	updated.Status.ActiveData = selected.DeepCopy()
	if err := r.Status().Update(ctx, updated); err != nil {
		return errors.New("atomic GameServer selected-data status update failed")
	}
	return nil
}

func (r *GameRestoreReconciler) observeRestoreRuntime(ctx context.Context, restore *arcadev1alpha1.GameRestore, server *arcadev1alpha1.GameServer, selection *arcadev1alpha1.RetainedDataReference, state arcadev1alpha1.DesiredState, generation int64) (*arcadev1alpha1.RuntimeDisposition, bool, error) {
	if server.Generation != generation || server.Spec.DesiredState != state || !sameDataSelection(server.Status.ActiveData, selection) && server.Status.ActiveData != nil {
		return nil, false, errors.New("restore-owned runtime intent or data selection changed")
	}
	phase := arcadev1alpha1.PhaseStopped
	if state == arcadev1alpha1.DesiredStateRunning {
		phase = arcadev1alpha1.PhaseReady
	}
	if server.Status.ObservedGeneration != generation || server.Status.Phase != phase || !sameDataSelection(server.Status.ObservedData, selection) {
		return nil, true, nil
	}
	if state == arcadev1alpha1.DesiredStateStopped {
		paths := restore.Status.PreviousData
		if selection.Identity != restore.Status.PreviousDataIdentity {
			paths = restore.Status.CandidateData
		}
		backupReader := &GameBackupReconciler{Client: r.Client, APIReader: r.APIReader}
		unmounted, err := backupReader.sourceClaimsUnmounted(ctx, restore.Namespace, paths)
		if err != nil || !unmounted {
			return nil, true, err
		}
	}
	now := r.nowRestore()
	return &arcadev1alpha1.RuntimeDisposition{GameServer: arcadev1alpha1.ExactGameServerReference{
		ExactLocalReference: restore.Spec.Target.ExactLocalReference, Generation: generation, DesiredState: state,
	}, Phase: phase, CompletedAt: now}, false, nil
}

func (r *GameRestoreReconciler) settlePreviousBeforeActivation(ctx context.Context, restore *arcadev1alpha1.GameRestore) (*arcadev1alpha1.RuntimeDisposition, bool, error) {
	if restore.Status.Fence == nil {
		// Before a cold-stop request the operation has no runtime authority. A
		// cancelled preflight must not reassert an old generation of the target.
		if restore.Status.Source == nil {
			return nil, false, nil
		}
		server, err := r.exactRestoreServer(ctx, restore)
		if err != nil {
			return nil, false, err
		}
		if server.Generation == restore.Spec.Target.Generation && server.Spec.DesiredState == restore.Spec.Target.DesiredState {
			return nil, false, nil
		}
		stoppedGeneration := restore.Spec.Target.Generation + 1
		previous := restoreSelection(restore.Status.PreviousDataIdentity, restore.Status.PreviousData)
		if restore.Spec.Target.DesiredState != arcadev1alpha1.DesiredStateRunning || previous == nil ||
			server.Generation != stoppedGeneration || server.Spec.DesiredState != arcadev1alpha1.DesiredStateStopped ||
			server.Status.ActiveData != nil && !sameDataSelection(server.Status.ActiveData, previous) {
			return nil, false, errors.New("restore cold-stop intent exists without a safe previous-world fence")
		}
		candidateIdentity, identityErr := platformdata.RestoreDataIdentity(restore.UID)
		if identityErr != nil {
			return nil, false, identityErr
		}
		if err := r.ensureRestoreLeases(ctx, restore, previous.Identity, candidateIdentity); err != nil {
			return nil, false, err
		}
		if _, pending, err := r.observeRestoreRuntime(ctx, restore, server, previous, arcadev1alpha1.DesiredStateStopped, stoppedGeneration); err != nil || pending {
			return nil, pending, err
		}
		return nil, true, r.writeRestoreStatus(ctx, restore, restore.Status.Phase, func(updated *arcadev1alpha1.GameRestore) {
			now := r.nowRestore()
			updated.Status.Fence = &arcadev1alpha1.ColdDataFence{GameServer: arcadev1alpha1.ExactGameServerReference{
				ExactLocalReference: restore.Spec.Target.ExactLocalReference, Generation: stoppedGeneration, DesiredState: arcadev1alpha1.DesiredStateStopped,
			}, EstablishedAt: now}
		})
	}
	previous := restoreSelection(restore.Status.PreviousDataIdentity, restore.Status.PreviousData)
	if previous == nil {
		return nil, false, errors.New("previous-world selection is missing")
	}
	if err := r.verifyRestoreDataClaims(ctx, restore, restore.Status.PreviousData, previous.Identity); err != nil {
		return nil, false, err
	}
	server, err := r.exactRestoreServer(ctx, restore)
	if err != nil {
		return nil, false, err
	}
	fenceGeneration := restore.Status.Fence.GameServer.Generation
	if server.Status.ActiveData != nil && !sameDataSelection(server.Status.ActiveData, previous) {
		return nil, false, errors.New("previous world is no longer the selected data")
	}
	if restore.Spec.RestartPolicy != arcadev1alpha1.RestartRestorePreviousState || restore.Spec.Target.DesiredState != arcadev1alpha1.DesiredStateRunning {
		return r.observeRestoreRuntime(ctx, restore, server, previous, arcadev1alpha1.DesiredStateStopped, fenceGeneration)
	}
	if server.Generation == fenceGeneration && server.Spec.DesiredState == arcadev1alpha1.DesiredStateStopped {
		if _, pending, err := r.observeRestoreRuntime(ctx, restore, server, previous, arcadev1alpha1.DesiredStateStopped, fenceGeneration); err != nil || pending {
			return nil, pending, err
		}
		if restore.Status.RuntimeJournal == nil || restore.Status.RuntimeJournal.PreviousRecoveryGeneration == 0 {
			return nil, true, r.writeRestoreStatus(ctx, restore, restore.Status.Phase, func(updated *arcadev1alpha1.GameRestore) {
				if updated.Status.RuntimeJournal == nil {
					updated.Status.RuntimeJournal = &arcadev1alpha1.RestoreRuntimeJournal{}
				}
				updated.Status.RuntimeJournal.PreviousRecoveryGeneration = fenceGeneration + 1
			})
		}
		if err := r.allowRestoreSettlement(ctx, restore, previous.Identity, arcadev1alpha1.DesiredStateRunning, fenceGeneration+1); err != nil {
			return nil, false, err
		}
		updated := server.DeepCopy()
		updated.Spec.DesiredState = arcadev1alpha1.DesiredStateRunning
		if err := r.Update(ctx, updated); err != nil {
			return nil, false, errors.New("restore previous-world restart failed")
		}
		return nil, true, nil
	}
	if restore.Status.RuntimeJournal == nil || restore.Status.RuntimeJournal.PreviousRecoveryGeneration != fenceGeneration+1 {
		return nil, false, errors.New("previous-world restart lacks durable generation intent")
	}
	return r.observeRestoreRuntime(ctx, restore, server, previous, arcadev1alpha1.DesiredStateRunning, fenceGeneration+1)
}

func (r *GameRestoreReconciler) reconcileRestoreActivation(ctx context.Context, restore *arcadev1alpha1.GameRestore) (ctrl.Result, error) {
	if pending, err := r.deleteAllRestoreWorkers(ctx, restore); err != nil || pending {
		return ctrl.Result{RequeueAfter: restoreRequeue}, err
	}
	if restore.Status.Fence == nil || restore.Status.Source == nil || restore.Status.CandidateVerification == nil || restore.Status.ActivationStartedAt == nil {
		return r.holdRestore(ctx, restore, arcadev1alpha1.ReasonIdentityMismatch, "activation history or verified candidate evidence is missing")
	}
	candidateIdentity, err := platformdata.RestoreDataIdentity(restore.UID)
	if err != nil || candidateIdentity == restore.Status.PreviousDataIdentity {
		return r.holdRestore(ctx, restore, arcadev1alpha1.ReasonIdentityMismatch, "candidate identity cannot be derived distinctly")
	}
	if err := r.ensureRestoreLeases(ctx, restore, restore.Status.PreviousDataIdentity, candidateIdentity); err != nil {
		return ctrl.Result{}, err
	}
	if err := r.verifyRestoreDataClaims(ctx, restore, restore.Status.PreviousData, restore.Status.PreviousDataIdentity); err != nil {
		return r.failRestorePreparation(ctx, restore, arcadev1alpha1.ReasonIdentityMismatch, "previous-world claim identity changed during activation")
	}
	if err := r.verifyRestoreDataClaims(ctx, restore, restore.Status.CandidateData, candidateIdentity); err != nil {
		return r.failRestorePreparation(ctx, restore, arcadev1alpha1.ReasonIdentityMismatch, "candidate claim identity changed during activation")
	}
	if err := r.verifyRestoreVolumeIsolation(ctx, restore.Namespace, restore.CreationTimestamp, restore.Status.PreviousData, restore.Status.CandidateData, restore.Status.Source.Paths); err != nil {
		return r.failRestorePreparation(ctx, restore, arcadev1alpha1.ReasonIdentityMismatch, "candidate storage cannot be proven physically distinct at activation")
	}
	server, err := r.exactRestoreServer(ctx, restore)
	if err != nil {
		return r.holdRestore(ctx, restore, arcadev1alpha1.ReasonIdentityMismatch, "the exact target is unavailable during activation")
	}
	previous := restoreSelection(restore.Status.PreviousDataIdentity, restore.Status.PreviousData)
	candidate := restoreSelection(candidateIdentity, restore.Status.CandidateData)
	fenceGeneration := restore.Status.Fence.GameServer.Generation
	journal := restore.Status.RuntimeJournal
	if journal == nil || journal.CandidateStartGeneration == 0 {
		if server.Generation != fenceGeneration || server.Spec.DesiredState != arcadev1alpha1.DesiredStateStopped {
			return r.holdRestore(ctx, restore, arcadev1alpha1.ReasonIdentityMismatch, "target generation changed before candidate start")
		}
		if server.Status.ActiveData == nil || sameDataSelection(server.Status.ActiveData, previous) {
			if !sameDataSelection(server.Status.ObservedData, previous) || server.Status.ObservedGeneration != fenceGeneration || server.Status.Phase != arcadev1alpha1.PhaseStopped {
				return ctrl.Result{RequeueAfter: restoreRequeue}, nil
			}
			if err := r.allowRestoreSettlement(ctx, restore, candidateIdentity, arcadev1alpha1.DesiredStateStopped, fenceGeneration); err != nil {
				return ctrl.Result{}, err
			}
			if err := r.updateRestoreActiveData(ctx, server, candidate); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{RequeueAfter: restoreRequeue}, nil
		}
	}
	if !sameDataSelection(server.Status.ActiveData, candidate) {
		return r.holdRestore(ctx, restore, arcadev1alpha1.ReasonIdentityMismatch, "target selected data is neither the exact previous nor verified candidate set")
	}
	if journal == nil || journal.CandidateStartGeneration == 0 {
		if _, pending, err := r.observeRestoreRuntime(ctx, restore, server, candidate, arcadev1alpha1.DesiredStateStopped, fenceGeneration); err != nil || pending {
			if server.Status.ObservedGeneration == fenceGeneration && server.Status.Phase == arcadev1alpha1.PhaseFailed ||
				r.nowRestore().Sub(restore.Status.ActivationStartedAt.Time) > restoreActivationTimeout {
				return r.failRestorePreparation(ctx, restore, arcadev1alpha1.ReasonWorkerFailed, "candidate could not settle while stopped; rolling back previous data selection")
			}
			return ctrl.Result{RequeueAfter: restoreRequeue}, err
		}
		if restore.Spec.RestartPolicy != arcadev1alpha1.RestartRestorePreviousState || restore.Spec.Target.DesiredState != arcadev1alpha1.DesiredStateRunning {
			return r.completeRestoreSuccess(ctx, restore, server, candidate, fenceGeneration, arcadev1alpha1.DesiredStateStopped)
		}
		return ctrl.Result{}, r.writeRestoreStatus(ctx, restore, arcadev1alpha1.DataPhaseActivating, func(updated *arcadev1alpha1.GameRestore) {
			if updated.Status.RuntimeJournal == nil {
				updated.Status.RuntimeJournal = &arcadev1alpha1.RestoreRuntimeJournal{}
			}
			updated.Status.RuntimeJournal.CandidateStartGeneration = fenceGeneration + 1
		})
	}
	if journal.CandidateStartGeneration != fenceGeneration+1 || server.Generation != fenceGeneration && server.Generation != fenceGeneration+1 {
		return r.holdRestore(ctx, restore, arcadev1alpha1.ReasonIdentityMismatch, "candidate start generation changed from durable intent")
	}
	if server.Generation == fenceGeneration {
		if server.Spec.DesiredState != arcadev1alpha1.DesiredStateStopped {
			return r.holdRestore(ctx, restore, arcadev1alpha1.ReasonIdentityMismatch, "candidate start found unexpected runtime intent")
		}
		if err := r.allowRestoreSettlement(ctx, restore, candidateIdentity, arcadev1alpha1.DesiredStateRunning, fenceGeneration+1); err != nil {
			return ctrl.Result{}, err
		}
		updated := server.DeepCopy()
		updated.Spec.DesiredState = arcadev1alpha1.DesiredStateRunning
		if err := r.Update(ctx, updated); err != nil {
			return ctrl.Result{}, errors.New("start exact restored candidate failed")
		}
		return ctrl.Result{RequeueAfter: restoreRequeue}, nil
	}
	if server.Spec.DesiredState != arcadev1alpha1.DesiredStateRunning {
		return r.holdRestore(ctx, restore, arcadev1alpha1.ReasonIdentityMismatch, "candidate start generation has unexpected desired state")
	}
	if _, pending, err := r.observeRestoreRuntime(ctx, restore, server, candidate, arcadev1alpha1.DesiredStateRunning, fenceGeneration+1); err == nil && !pending {
		return r.completeRestoreSuccess(ctx, restore, server, candidate, fenceGeneration+1, arcadev1alpha1.DesiredStateRunning)
	} else if err != nil {
		return r.holdRestore(ctx, restore, arcadev1alpha1.ReasonIdentityMismatch, "candidate runtime selection changed during readiness")
	}
	if server.Status.ObservedGeneration == fenceGeneration+1 && server.Status.Phase == arcadev1alpha1.PhaseFailed ||
		r.nowRestore().Sub(restore.Status.ActivationStartedAt.Time) > restoreActivationTimeout {
		return r.failRestorePreparation(ctx, restore, arcadev1alpha1.ReasonWorkerFailed, "restored candidate did not reach exact Ready state; rolling back to previous world")
	}
	return ctrl.Result{RequeueAfter: restoreRequeue}, nil
}

func (r *GameRestoreReconciler) completeRestoreSuccess(ctx context.Context, restore *arcadev1alpha1.GameRestore, server *arcadev1alpha1.GameServer, candidate *arcadev1alpha1.RetainedDataReference, generation int64, state arcadev1alpha1.DesiredState) (ctrl.Result, error) {
	runtime, pending, err := r.observeRestoreRuntime(ctx, restore, server, candidate, state, generation)
	if err != nil || pending {
		return ctrl.Result{RequeueAfter: restoreRequeue}, err
	}
	err = r.writeRestoreStatus(ctx, restore, arcadev1alpha1.DataPhaseSucceeded, func(updated *arcadev1alpha1.GameRestore) {
		now := r.nowRestore()
		updated.Status.ActiveData = slices.Clone(restore.Status.CandidateData)
		updated.Status.Runtime = runtime
		updated.Status.CompletedAt = &now
		r.setRestoreCondition(updated, arcadev1alpha1.ConditionOperationComplete, metav1.ConditionTrue, arcadev1alpha1.ReasonOperationCompleted, "verified isolated candidate is selected and the exact requested runtime is observed")
	})
	return ctrl.Result{Requeue: err == nil}, err
}

func (r *GameRestoreReconciler) reconcileRestoreRollback(ctx context.Context, restore *arcadev1alpha1.GameRestore) (ctrl.Result, error) {
	if pending, err := r.deleteAllRestoreWorkers(ctx, restore); err != nil || pending {
		return ctrl.Result{RequeueAfter: restoreRequeue}, err
	}
	if restore.Status.Fence == nil || restore.Status.ActivationStartedAt == nil {
		return r.holdRestore(ctx, restore, arcadev1alpha1.ReasonIdentityMismatch, "rollback requires durable fence and activation history")
	}
	candidateIdentity, err := platformdata.RestoreDataIdentity(restore.UID)
	if err != nil {
		return ctrl.Result{}, err
	}
	if err := r.ensureRestoreLeases(ctx, restore, restore.Status.PreviousDataIdentity, candidateIdentity); err != nil {
		return ctrl.Result{}, err
	}
	if err := r.verifyRestoreDataClaims(ctx, restore, restore.Status.PreviousData, restore.Status.PreviousDataIdentity); err != nil {
		return r.holdRestore(ctx, restore, arcadev1alpha1.ReasonIdentityMismatch, "previous-world rollback claims are unavailable; keep both leases")
	}
	server, err := r.exactRestoreServer(ctx, restore)
	if err != nil {
		return r.holdRestore(ctx, restore, arcadev1alpha1.ReasonIdentityMismatch, "exact target is unavailable for rollback")
	}
	previous := restoreSelection(restore.Status.PreviousDataIdentity, restore.Status.PreviousData)
	candidate := restoreSelection(candidateIdentity, restore.Status.CandidateData)
	fenceGeneration := restore.Status.Fence.GameServer.Generation
	journal := restore.Status.RuntimeJournal
	startRequested := journal != nil && journal.CandidateStartGeneration != 0
	if journal != nil && journal.RollbackRestartGeneration != 0 &&
		server.Generation == journal.RollbackRestartGeneration && server.Spec.DesiredState == arcadev1alpha1.DesiredStateRunning &&
		sameDataSelection(server.Status.ActiveData, previous) {
		return r.finishRestoreRollback(ctx, restore, server, previous, journal.RollbackRestartGeneration, arcadev1alpha1.DesiredStateRunning)
	}
	stopGeneration := fenceGeneration
	if startRequested {
		stopGeneration = fenceGeneration + 2
		if server.Generation == fenceGeneration+1 && server.Spec.DesiredState == arcadev1alpha1.DesiredStateRunning {
			if !sameDataSelection(server.Status.ActiveData, candidate) {
				return r.holdRestore(ctx, restore, arcadev1alpha1.ReasonIdentityMismatch, "running candidate no longer has the exact verified selection")
			}
			if journal.RollbackStopGeneration == 0 {
				return ctrl.Result{}, r.writeRestoreStatus(ctx, restore, arcadev1alpha1.DataPhaseRollingBack, func(updated *arcadev1alpha1.GameRestore) {
					updated.Status.RuntimeJournal.RollbackStopGeneration = stopGeneration
				})
			}
			if journal.RollbackStopGeneration != stopGeneration {
				return r.holdRestore(ctx, restore, arcadev1alpha1.ReasonIdentityMismatch, "rollback stop generation differs from durable intent")
			}
			if err := r.allowRestoreSettlement(ctx, restore, candidateIdentity, arcadev1alpha1.DesiredStateStopped, stopGeneration); err != nil {
				return ctrl.Result{}, err
			}
			updated := server.DeepCopy()
			updated.Spec.DesiredState = arcadev1alpha1.DesiredStateStopped
			if err := r.Update(ctx, updated); err != nil {
				return ctrl.Result{}, errors.New("stop failed candidate before rollback failed")
			}
			return ctrl.Result{RequeueAfter: restoreRequeue}, nil
		}
		if server.Generation == fenceGeneration && server.Spec.DesiredState == arcadev1alpha1.DesiredStateStopped {
			// Journal intent was committed but a spec update never occurred.
			stopGeneration = fenceGeneration
		} else if server.Generation != stopGeneration || server.Spec.DesiredState != arcadev1alpha1.DesiredStateStopped || journal.RollbackStopGeneration != stopGeneration {
			return r.holdRestore(ctx, restore, arcadev1alpha1.ReasonIdentityMismatch, "candidate runtime generation escaped the rollback journal")
		}
	}
	if server.Generation != stopGeneration || server.Spec.DesiredState != arcadev1alpha1.DesiredStateStopped {
		return r.holdRestore(ctx, restore, arcadev1alpha1.ReasonIdentityMismatch, "rollback target is not at an exact cold generation")
	}
	if server.Status.ActiveData != nil && !sameDataSelection(server.Status.ActiveData, previous) {
		if !sameDataSelection(server.Status.ActiveData, candidate) {
			return r.holdRestore(ctx, restore, arcadev1alpha1.ReasonIdentityMismatch, "rollback target selected an unknown data set")
		}
		backupReader := &GameBackupReconciler{Client: r.Client, APIReader: r.APIReader}
		unmounted, err := backupReader.sourceClaimsUnmounted(ctx, restore.Namespace, restore.Status.CandidateData)
		if err != nil || !unmounted {
			return ctrl.Result{RequeueAfter: restoreRequeue}, err
		}
		if err := r.allowRestoreSettlement(ctx, restore, previous.Identity, arcadev1alpha1.DesiredStateStopped, stopGeneration); err != nil {
			return ctrl.Result{}, err
		}
		if err := r.updateRestoreActiveData(ctx, server, previous); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: restoreRequeue}, nil
	}
	if _, pending, err := r.observeRestoreRuntime(ctx, restore, server, previous, arcadev1alpha1.DesiredStateStopped, stopGeneration); err != nil || pending {
		return ctrl.Result{RequeueAfter: restoreRequeue}, err
	}
	finalGeneration := stopGeneration
	finalState := arcadev1alpha1.DesiredStateStopped
	if restore.Spec.RestartPolicy == arcadev1alpha1.RestartRestorePreviousState && restore.Spec.Target.DesiredState == arcadev1alpha1.DesiredStateRunning {
		finalGeneration = fenceGeneration + 1
		if journal != nil && journal.RollbackStopGeneration != 0 {
			finalGeneration = fenceGeneration + 3
		}
		finalState = arcadev1alpha1.DesiredStateRunning
		if journal == nil || journal.RollbackRestartGeneration == 0 {
			return ctrl.Result{}, r.writeRestoreStatus(ctx, restore, arcadev1alpha1.DataPhaseRollingBack, func(updated *arcadev1alpha1.GameRestore) {
				if updated.Status.RuntimeJournal == nil {
					updated.Status.RuntimeJournal = &arcadev1alpha1.RestoreRuntimeJournal{}
				}
				updated.Status.RuntimeJournal.RollbackRestartGeneration = finalGeneration
			})
		}
		if journal.RollbackRestartGeneration != finalGeneration {
			return r.holdRestore(ctx, restore, arcadev1alpha1.ReasonIdentityMismatch, "previous restart differs from durable rollback intent")
		}
		if err := r.allowRestoreSettlement(ctx, restore, previous.Identity, arcadev1alpha1.DesiredStateRunning, finalGeneration); err != nil {
			return ctrl.Result{}, err
		}
		updated := server.DeepCopy()
		updated.Spec.DesiredState = arcadev1alpha1.DesiredStateRunning
		if err := r.Update(ctx, updated); err != nil {
			return ctrl.Result{}, errors.New("restart exact previous world after rollback failed")
		}
		return ctrl.Result{RequeueAfter: restoreRequeue}, nil
	}
	return r.finishRestoreRollback(ctx, restore, server, previous, finalGeneration, finalState)
}

func (r *GameRestoreReconciler) finishRestoreRollback(ctx context.Context, restore *arcadev1alpha1.GameRestore, server *arcadev1alpha1.GameServer, previous *arcadev1alpha1.RetainedDataReference, generation int64, state arcadev1alpha1.DesiredState) (ctrl.Result, error) {
	runtime, pending, err := r.observeRestoreRuntime(ctx, restore, server, previous, state, generation)
	if err != nil || pending {
		return ctrl.Result{RequeueAfter: restoreRequeue}, err
	}
	terminal := arcadev1alpha1.DataPhaseFailed
	reason, message := restoreFailureReason(restore)
	if restore.Spec.CancelRequested || reason == arcadev1alpha1.ReasonOperationCancelled {
		terminal = arcadev1alpha1.DataPhaseCancelled
		reason, message = arcadev1alpha1.ReasonOperationCancelled, "cancellation restored the exact previous world and settled its runtime"
	}
	err = r.writeRestoreStatus(ctx, restore, terminal, func(updated *arcadev1alpha1.GameRestore) {
		now := r.nowRestore()
		updated.Status.ActiveData = slices.Clone(restore.Status.PreviousData)
		updated.Status.Runtime = runtime
		updated.Status.CompletedAt = &now
		r.setRestoreCondition(updated, arcadev1alpha1.ConditionOperationComplete, metav1.ConditionFalse, reason, message)
	})
	return ctrl.Result{Requeue: err == nil}, err
}

func (r *GameRestoreReconciler) writeRestoreStatus(ctx context.Context, restore *arcadev1alpha1.GameRestore, phase arcadev1alpha1.DataOperationPhase, mutate func(*arcadev1alpha1.GameRestore)) error {
	updated := restore.DeepCopy()
	updated.Status.ObservedGeneration = updated.Generation
	updated.Status.Phase = phase
	if mutate != nil {
		mutate(updated)
	}
	// Cancellation, failure, and finalizer-driven exits from Running may occur
	// while a failed worker is awaiting deletion. The retry flag is meaningful
	// only in Running and must be cleared before admission validates the phase.
	updated.Status.PopulateRetryPending = restoreRetryPendingForPhase(phase, updated.Status.PopulateRetryPending)
	verified := updated.Status.CandidateVerification != nil && updated.Status.CandidateVerification.Result == arcadev1alpha1.VerificationVerified &&
		updated.Status.Artifact != nil && updated.Status.Artifact.Verification.Result == arcadev1alpha1.VerificationVerified
	if err := platformdata.ValidateTransition(platformdata.RestoreOperation, restore.Status.Phase, phase, verified); err != nil {
		return fmt.Errorf("restore state transition rejected by the safety contract: %w", err)
	}
	canonicalizeRestoreConditions(updated)
	if err := platformdata.ValidateRestoreStatus(updated); err != nil {
		return fmt.Errorf("restore status rejected by the safety contract: %w", err)
	}
	if apiequality.Semantic.DeepEqual(restore.Status, updated.Status) {
		return nil
	}
	if err := r.Status().Update(ctx, updated); err != nil {
		return errors.New("update GameRestore status failed")
	}
	return nil
}

func (r *GameRestoreReconciler) setRestoreCondition(restore *arcadev1alpha1.GameRestore, conditionType string, status metav1.ConditionStatus, reason, message string) {
	now := r.nowRestore()
	condition := metav1.Condition{Type: conditionType, Status: status, Reason: reason, Message: message,
		ObservedGeneration: restore.Generation, LastTransitionTime: now}
	for index := range restore.Status.Conditions {
		previous := restore.Status.Conditions[index]
		if previous.Type != conditionType {
			continue
		}
		if previous.Status == status && previous.Reason == reason && previous.Message == message {
			condition.LastTransitionTime = previous.LastTransitionTime
		}
		restore.Status.Conditions[index] = condition
		return
	}
	restore.Status.Conditions = append(restore.Status.Conditions, condition)
}

func canonicalizeRestoreConditions(restore *arcadev1alpha1.GameRestore) {
	conditions := make([]metav1.Condition, 0, len(restore.Status.Conditions))
	for _, conditionType := range backupConditionOrder {
		for _, condition := range restore.Status.Conditions {
			if condition.Type == conditionType {
				conditions = append(conditions, condition)
				break
			}
		}
	}
	restore.Status.Conditions = conditions
}

func (r *GameRestoreReconciler) finalizeRestore(ctx context.Context, restore *arcadev1alpha1.GameRestore) (ctrl.Result, error) {
	if !slices.Contains(restore.Finalizers, platformkube.RestoreFinalizer) {
		return ctrl.Result{}, nil
	}
	if !restoreTerminal(restore.Status.Phase) {
		if restore.Status.ActivationStartedAt != nil {
			if restore.Status.Phase != arcadev1alpha1.DataPhaseRollingBack {
				return ctrl.Result{}, r.writeRestoreStatus(ctx, restore, arcadev1alpha1.DataPhaseRollingBack, func(updated *arcadev1alpha1.GameRestore) {
					r.setRestoreCondition(updated, arcadev1alpha1.ConditionOperationComplete, metav1.ConditionFalse, arcadev1alpha1.ReasonOperationCancelled, "deletion is rolling back the exact previous world before removing protection")
				})
			}
			return r.reconcileRestoreRollback(ctx, restore)
		}
		if restore.Status.Phase != arcadev1alpha1.DataPhaseCancelling {
			return ctrl.Result{}, r.writeRestoreStatus(ctx, restore, arcadev1alpha1.DataPhaseCancelling, func(updated *arcadev1alpha1.GameRestore) {
				r.setRestoreCondition(updated, arcadev1alpha1.ConditionOperationComplete, metav1.ConditionFalse, arcadev1alpha1.ReasonOperationCancelled, "deletion is stopping restore work and settling the previous world")
			})
		}
		return r.reconcileRestoreCancellation(ctx, restore)
	}
	if pending, err := r.deleteAllRestoreWorkers(ctx, restore); err != nil || pending {
		return ctrl.Result{RequeueAfter: restoreRequeue}, err
	}
	if err := r.releaseRestoreLeases(ctx, restore); err != nil {
		return ctrl.Result{}, err
	}
	updated := restore.DeepCopy()
	updated.Finalizers = slices.DeleteFunc(updated.Finalizers, func(value string) bool { return value == platformkube.RestoreFinalizer })
	if err := r.Update(ctx, updated); err != nil {
		return ctrl.Result{}, errors.New("remove GameRestore protection failed")
	}
	return ctrl.Result{}, nil
}

func (r *GameRestoreReconciler) SetupWithManager(manager ctrl.Manager) error {
	if r.Client == nil || r.Scheme == nil || r.Catalog == nil || r.WorkerImage == "" {
		return errors.New("restore reconciler client, scheme, catalog, and pinned worker image are required")
	}
	return ctrl.NewControllerManagedBy(manager).
		For(&arcadev1alpha1.GameRestore{}).
		Owns(&corev1.ConfigMap{}).
		Owns(&corev1.ServiceAccount{}).
		Owns(&rbacv1.Role{}).
		Owns(&rbacv1.RoleBinding{}).
		Owns(&batchv1.Job{}).
		Complete(r)
}
