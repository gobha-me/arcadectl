// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"errors"
	"fmt"

	arcadev1alpha1 "github.com/gobha-me/arcadectl/api/v1alpha1"
	platformkube "github.com/gobha-me/arcadectl/internal/platform/kube"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// markLeaveStoppedBackup records durable evidence on each exact claim before
// the backup is allowed to become Succeeded. A later GameServer activation
// clears this marker before creating any runtime that mounts the claim.
func (r *GameBackupReconciler) markLeaveStoppedBackup(ctx context.Context, backup *arcadev1alpha1.GameBackup, runtime *arcadev1alpha1.RuntimeDisposition) error {
	if backup.Spec.RestartPolicy != arcadev1alpha1.RestartLeaveStopped ||
		backup.Status.Source == nil || backup.Status.Artifact == nil || backup.Status.Fence == nil ||
		backup.Status.Artifact.Verification.Result != arcadev1alpha1.VerificationVerified ||
		runtime == nil || runtime.Phase != arcadev1alpha1.PhaseStopped ||
		runtime.GameServer.DesiredState != arcadev1alpha1.DesiredStateStopped ||
		runtime.GameServer.ExactLocalReference != backup.Spec.Source.ExactLocalReference ||
		runtime.GameServer != backup.Status.Fence.GameServer ||
		backup.UID == "" {
		return errors.New("exact leave-stopped backup is not cold")
	}
	if len(backup.Status.Source.Paths) == 0 {
		return errors.New("backup source paths are unavailable")
	}
	for _, path := range backup.Status.Source.Paths {
		claim := &corev1.PersistentVolumeClaim{}
		key := types.NamespacedName{Namespace: backup.Namespace, Name: path.ClaimRef.Name}
		if err := r.directReader().Get(ctx, key, claim); err != nil {
			return fmt.Errorf("exact backup source claim %s is unavailable: %w", key, err)
		}
		if claim.UID == "" || string(claim.UID) != path.ClaimRef.UID || !claim.DeletionTimestamp.IsZero() ||
			claim.Labels[platformkube.LabelManagedBy] != platformkube.ManagerName ||
			claim.Labels[platformkube.LabelInstance] != backup.Spec.Source.Name ||
			claim.Labels[platformkube.LabelGame] != backup.Status.Source.Game ||
			claim.Labels[platformkube.LabelDataPath] != path.Name ||
			claim.Labels[platformkube.LabelDataPolicy] != "retain" ||
			claim.Labels[platformkube.LabelDataIdentity] == "" ||
			len(claim.OwnerReferences) != 0 || claim.Status.Phase != corev1.ClaimBound || claim.Spec.VolumeName == "" {
			return errors.New("exact backup source claim changed before cold marker")
		}
		if claim.Annotations[platformkube.AnnotationColdBackupUID] == string(backup.UID) {
			continue
		}
		original := claim.DeepCopy()
		updated := claim.DeepCopy()
		if updated.Annotations == nil {
			updated.Annotations = make(map[string]string)
		}
		updated.Annotations[platformkube.AnnotationColdBackupUID] = string(backup.UID)
		if err := r.Patch(ctx, updated, client.MergeFromWithOptions(original, client.MergeFromWithOptimisticLock{})); err != nil {
			return errors.New("record cold backup claim marker failed; inspect PVC and admission state")
		}
	}
	return nil
}

// clearColdBackupMarkers invalidates old cold-continuity evidence before an
// Arcadectl GameServer can create runtime for this selected claim set.
func (r *GameServerReconciler) clearColdBackupMarkers(ctx context.Context, server *arcadev1alpha1.GameServer, claims []platformkube.DataClaimPlan) error {
	if len(claims) == 0 {
		return errors.New("selected world identity is unavailable")
	}
	for _, planned := range claims {
		if planned.Desired == nil {
			return errors.New("selected world claim plan is unavailable")
		}
		claim := &corev1.PersistentVolumeClaim{}
		key := types.NamespacedName{Namespace: server.Namespace, Name: planned.Desired.Name}
		reader := r.APIReader
		if reader == nil {
			reader = r.Client
		}
		if err := reader.Get(ctx, key, claim); err != nil {
			if apierrors.IsNotFound(err) && planned.RequiredUID == "" {
				continue
			}
			return errors.New("selected world claim is unavailable")
		}
		if claim.Annotations[platformkube.AnnotationColdBackupUID] == "" {
			continue
		}
		if claim.UID == "" || !claim.DeletionTimestamp.IsZero() ||
			validateExistingDataClaim(claim, planned) != nil {
			return errors.New("selected world claim changed before runtime activation")
		}
		original := claim.DeepCopy()
		updated := claim.DeepCopy()
		delete(updated.Annotations, platformkube.AnnotationColdBackupUID)
		if err := r.Patch(ctx, updated, client.MergeFromWithOptions(original, client.MergeFromWithOptimisticLock{})); err != nil {
			return errors.New("invalidate prior cold backup marker failed; runtime remains blocked")
		}
	}
	return nil
}
