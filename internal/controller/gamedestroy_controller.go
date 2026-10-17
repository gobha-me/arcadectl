// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"

	arcade "github.com/gobha-me/arcadectl/api/v1alpha1"
	"github.com/gobha-me/arcadectl/internal/platform/game"
	platformkube "github.com/gobha-me/arcadectl/internal/platform/kube"
	"github.com/gobha-me/arcadectl/internal/restoreworker"
	batchv1 "k8s.io/api/batch/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	storagev1 "k8s.io/api/storage/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	destroyRequeue                 = time.Second
	destroyJobAuthorizedAnnotation = "arcade.gobha.me/destroy-job-authorized"
)

// GameDestroyReconciler must run under a distinct identity. Unlike ordinary
// lifecycle controllers, that identity is allowed to delete managed PVCs.
type GameDestroyReconciler struct {
	client.Client
	APIReader   client.Reader
	Scheme      *runtime.Scheme
	Catalog     DefinitionCatalog
	WorkerImage string
	Now         func() metav1.Time
}

type destroySubject struct {
	backup     *arcade.GameBackup
	definition game.Definition
	input      restoreworker.Input
}

func (r *GameDestroyReconciler) reader() client.Reader {
	if r.APIReader != nil {
		return r.APIReader
	}
	return r.Client
}

func (r *GameDestroyReconciler) now() metav1.Time {
	if r.Now != nil {
		return r.Now()
	}
	return metav1.Now()
}

func (r *GameDestroyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	d := &arcade.GameDestroy{}
	if err := r.Get(ctx, req.NamespacedName, d); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !slices.Contains(d.Finalizers, platformkube.DestroyFinalizer) && d.DeletionTimestamp.IsZero() {
		copy := d.DeepCopy()
		copy.Finalizers = append(copy.Finalizers, platformkube.DestroyFinalizer)
		return ctrl.Result{Requeue: true}, r.Update(ctx, copy)
	}
	if !d.DeletionTimestamp.IsZero() && len(d.Status.DeletionJournal) == 0 {
		return r.finalize(ctx, d)
	}
	if destroyTerminal(d.Status.Phase) {
		pending, err := r.cleanupWorker(ctx, d)
		if err != nil || pending {
			return ctrl.Result{RequeueAfter: destroyRequeue}, err
		}
		if err := r.releaseDataLease(ctx, d); err != nil {
			return ctrl.Result{}, err
		}
		if !d.DeletionTimestamp.IsZero() {
			return r.removeFinalizer(ctx, d)
		}
		return ctrl.Result{}, nil
	}
	if d.Spec.CancelRequested && len(d.Status.DeletionJournal) == 0 {
		pending, err := r.cleanupWorker(ctx, d)
		if err != nil || pending {
			return ctrl.Result{RequeueAfter: destroyRequeue}, err
		}
		if err := r.releaseDataLease(ctx, d); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, r.status(ctx, d, arcade.DestroyPhaseCancelled, "Cancelled", "destroy cancelled before any PVC deletion")
	}
	if d.Status.Phase == "" {
		return ctrl.Result{}, r.status(ctx, d, arcade.DestroyPhasePending, "Accepted", "exact destroy request accepted; no data has been deleted")
	}
	switch d.Status.Phase {
	case arcade.DestroyPhasePending:
		return r.preview(ctx, d)
	case arcade.DestroyPhasePreview:
		return r.confirm(ctx, d)
	case arcade.DestroyPhaseVerifying:
		return r.verify(ctx, d)
	case arcade.DestroyPhaseDeleting:
		return r.deleteClaims(ctx, d)
	default:
		return ctrl.Result{}, errors.New("unsupported GameDestroy phase")
	}
}

func destroyTerminal(phase arcade.GameDestroyPhase) bool {
	return phase == arcade.DestroyPhaseSucceeded || phase == arcade.DestroyPhaseFailed || phase == arcade.DestroyPhaseCancelled
}

func (r *GameDestroyReconciler) status(ctx context.Context, d *arcade.GameDestroy, phase arcade.GameDestroyPhase, reason, message string) error {
	copy := d.DeepCopy()
	copy.Status.Phase = phase
	copy.Status.ObservedGeneration = d.Generation
	if copy.Status.StartedAt == nil {
		now := r.now()
		copy.Status.StartedAt = &now
	}
	if destroyTerminal(phase) {
		now := r.now()
		copy.Status.CompletedAt = &now
	}
	meta.SetStatusCondition(&copy.Status.Conditions, metav1.Condition{Type: arcade.ConditionOperationComplete, Status: metav1.ConditionUnknown, Reason: reason, Message: message, ObservedGeneration: d.Generation, LastTransitionTime: r.now()})
	if destroyTerminal(phase) {
		state := metav1.ConditionFalse
		if phase == arcade.DestroyPhaseSucceeded {
			state = metav1.ConditionTrue
		}
		meta.SetStatusCondition(&copy.Status.Conditions, metav1.Condition{Type: arcade.ConditionOperationComplete, Status: state, Reason: reason, Message: message, ObservedGeneration: d.Generation, LastTransitionTime: r.now()})
	}
	return r.Status().Update(ctx, copy)
}

func (r *GameDestroyReconciler) hold(ctx context.Context, d *arcade.GameDestroy, reason, message string) (ctrl.Result, error) {
	copy := d.DeepCopy()
	meta.SetStatusCondition(&copy.Status.Conditions, metav1.Condition{Type: arcade.ConditionOperationComplete, Status: metav1.ConditionUnknown, Reason: reason, Message: message, ObservedGeneration: d.Generation, LastTransitionTime: r.now()})
	if err := r.Status().Update(ctx, copy); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: destroyRequeue}, nil
}

func (r *GameDestroyReconciler) fail(ctx context.Context, d *arcade.GameDestroy, reason, message string) (ctrl.Result, error) {
	if len(d.Status.DeletionJournal) != 0 {
		return r.hold(ctx, d, reason, message)
	}
	return ctrl.Result{}, r.status(ctx, d, arcade.DestroyPhaseFailed, reason, message)
}

func (r *GameDestroyReconciler) preview(ctx context.Context, d *arcade.GameDestroy) (ctrl.Result, error) {
	_, err := r.resolve(ctx, d, false)
	if err != nil {
		return r.fail(ctx, d, "PreflightRejected", err.Error())
	}
	challenge := make([]byte, 24)
	if _, err := rand.Read(challenge); err != nil {
		return ctrl.Result{}, errors.New("generate destroy confirmation failed")
	}
	copy := d.DeepCopy()
	copy.Status.Phase = arcade.DestroyPhasePreview
	copy.Status.ObservedGeneration = d.Generation
	guidance := "This deletes the exact retained world claims. Restore from the pinned GameBackup and repository Secret into fresh claims before destroying; PV reclaim policy may retain bytes after PVC deletion."
	if d.Spec.Mode == arcade.DestroyModeUnsafeNoBackup {
		guidance = "UNSAFE: this request has no verified backup. Restore requires an independently verified backup into fresh claims; destruction can permanently lose this world. Review the administrator identity and unsafe reason before confirming; PV reclaim policy may retain bytes."
	}
	copy.Status.Preview = &arcade.GameDestroyPreview{
		Challenge:       base64.RawURLEncoding.EncodeToString(challenge),
		ExpiresAt:       metav1.NewTime(r.now().Add(20 * time.Minute)),
		RestoreGuidance: guidance,
	}
	return ctrl.Result{}, r.Status().Update(ctx, copy)
}

func (r *GameDestroyReconciler) confirmed(d *arcade.GameDestroy) bool {
	return d.Status.Preview != nil && d.Spec.ConfirmationChallenge != "" && d.Spec.ConfirmationChallenge == d.Status.Preview.Challenge && r.now().Time.Before(d.Status.Preview.ExpiresAt.Time)
}

func (r *GameDestroyReconciler) confirm(ctx context.Context, d *arcade.GameDestroy) (ctrl.Result, error) {
	if d.Spec.ConfirmationChallenge == "" {
		return ctrl.Result{RequeueAfter: 15 * time.Second}, nil
	}
	if !r.confirmed(d) {
		return r.fail(ctx, d, "ConfirmationExpired", "confirmation is stale or does not match the exact preview; create a new request")
	}
	if _, err := r.resolve(ctx, d, false); err != nil {
		return r.fail(ctx, d, "PreflightRejected", err.Error())
	}
	if err := r.acquireDataLease(ctx, d); err != nil {
		return r.fail(ctx, d, "OperationConflict", "another data operation owns this world; no claims were deleted")
	}
	phase := arcade.DestroyPhaseVerifying
	if d.Spec.Mode == arcade.DestroyModeUnsafeNoBackup {
		phase = arcade.DestroyPhaseDeleting
	}
	return ctrl.Result{}, r.status(ctx, d, phase, "Confirmed", "exact target confirmed; retained world is fenced cold")
}

// resolve is intentionally read-only and uses uncached reads for the final
// destructive gate. The sole acceptable absent target server is one whose
// original UID is independently pinned by a successful stopped backup.
func (r *GameDestroyReconciler) resolve(ctx context.Context, d *arcade.GameDestroy, permitJournalAbsence bool) (*destroySubject, error) {
	t := d.Spec.Target
	if t.GameServer.Namespace != nil || t.GameServer.Name == "" || t.GameServer.UID == "" || t.Data.Identity == "" || len(t.Data.Claims) == 0 || len(t.Data.Claims) > 16 {
		return nil, errors.New("exact local world identity is incomplete")
	}
	definition, err := r.Catalog.Get(t.Game)
	if err != nil || !definition.Capabilities.ColdBackup || !definition.Capabilities.Restore || len(definition.PersistentPaths) != len(t.Data.Claims) {
		return nil, errors.New("target does not match a certified persistent game adapter")
	}
	paths := make(map[string]string, len(definition.PersistentPaths))
	for _, path := range definition.PersistentPaths {
		paths[path.Name] = path.MountPath
	}
	seenName := map[string]struct{}{}
	seenUID := map[string]struct{}{}
	for _, path := range t.Data.Claims {
		if paths[path.Path] == "" || path.ClaimRef.Namespace != nil || path.ClaimRef.Name == "" || path.ClaimRef.UID == "" {
			return nil, errors.New("target claim path or exact UID is invalid")
		}
		if _, ok := seenName[path.ClaimRef.Name]; ok {
			return nil, errors.New("target claim names overlap")
		}
		if _, ok := seenUID[path.ClaimRef.UID]; ok {
			return nil, errors.New("target claim UIDs overlap")
		}
		seenName[path.ClaimRef.Name] = struct{}{}
		seenUID[path.ClaimRef.UID] = struct{}{}
	}
	var backup *arcade.GameBackup
	if d.Spec.Mode == arcade.DestroyModeVerifiedBackup {
		if d.Spec.BackupRef == nil || d.Spec.RepositorySecretRef == nil || d.Spec.BackupRef.Namespace != nil || d.Spec.RepositorySecretRef.Namespace != nil {
			return nil, errors.New("exact backup and repository references are required")
		}
		backup = &arcade.GameBackup{}
		if err := r.reader().Get(ctx, types.NamespacedName{Namespace: d.Namespace, Name: d.Spec.BackupRef.Name}, backup); err != nil || string(backup.UID) != d.Spec.BackupRef.UID || !backup.DeletionTimestamp.IsZero() || backup.Status.Phase != arcade.DataPhaseSucceeded || backup.Status.ObservedGeneration != backup.Generation || backup.Status.Source == nil || backup.Status.Artifact == nil || backup.Status.Runtime == nil || backup.Status.Fence == nil {
			return nil, errors.New("exact succeeded backup and stopped runtime evidence are unavailable")
		}
		if backup.Spec.RestartPolicy != arcade.RestartLeaveStopped || backup.Status.Runtime.Phase != arcade.PhaseStopped || backup.Status.Runtime.GameServer.DesiredState != arcade.DesiredStateStopped || backup.Status.Source.GameServer.ExactLocalReference != t.GameServer || backup.Status.Source.Game != t.Game || backup.Status.Artifact.Verification.Result != arcade.VerificationVerified || backup.Status.Artifact.Verification.VerifiedAt == nil || backup.Status.Artifact.Provenance.BackupRef != *d.Spec.BackupRef || backup.Status.Artifact.Provenance.RepositorySecretRef != *d.Spec.RepositorySecretRef || len(backup.Status.Source.Paths) != len(t.Data.Claims) || backup.Status.Artifact.PathCount != int32(len(t.Data.Claims)) {
			return nil, errors.New("backup does not prove the exact original world stayed cold")
		}
		for _, sourcePath := range backup.Status.Source.Paths {
			if paths[sourcePath.Name] != sourcePath.MountPath {
				return nil, errors.New("backup adapter topology changed")
			}
			found := false
			for _, claim := range t.Data.Claims {
				if claim.Path == sourcePath.Name && claim.ClaimRef == sourcePath.ClaimRef {
					found = true
				}
			}
			if !found {
				return nil, errors.New("backup data identities do not match exact destroy target")
			}
		}
		secret := &metav1.PartialObjectMetadata{}
		secret.SetGroupVersionKind(corev1.SchemeGroupVersion.WithKind("Secret"))
		if err := r.reader().Get(ctx, types.NamespacedName{Namespace: d.Namespace, Name: d.Spec.RepositorySecretRef.Name}, secret); err != nil || string(secret.UID) != d.Spec.RepositorySecretRef.UID || secret.ResourceVersion != d.Spec.RepositorySecretRef.ResourceVersion || !secret.DeletionTimestamp.IsZero() {
			return nil, errors.New("exact repository Secret revision is unavailable")
		}
	} else if d.Spec.Mode != arcade.DestroyModeUnsafeNoBackup || len(d.Spec.UnsafeReason) < 8 {
		return nil, errors.New("destroy mode is invalid")
	}
	server := &arcade.GameServer{}
	err = r.reader().Get(ctx, types.NamespacedName{Namespace: d.Namespace, Name: t.GameServer.Name}, server)
	if apierrors.IsNotFound(err) {
		if backup == nil {
			return nil, errors.New("unsafe destroy of a removed GameServer lacks durable original UID evidence")
		}
	} else if err != nil {
		return nil, errors.New("inspect exact GameServer failed")
	} else {
		selected := server.Status.ActiveData
		if selected == nil {
			selected = server.Status.ObservedData
		}
		if string(server.UID) != t.GameServer.UID || !server.DeletionTimestamp.IsZero() || server.Spec.Game != t.Game || server.Spec.DesiredState != arcade.DesiredStateStopped || server.Status.Phase != arcade.PhaseStopped || server.Status.ObservedGeneration != server.Generation || !sameDataSelection(server.Status.ObservedData, &t.Data) || !sameDataSelection(selected, &t.Data) {
			return nil, errors.New("exact GameServer generation is not stopped on the requested data")
		}
		if backup != nil && (server.Generation != backup.Status.Runtime.GameServer.Generation || server.Spec.ImageDigest != backup.Status.Source.ImageDigest) {
			return nil, errors.New("GameServer changed since its leave-stopped backup")
		}
	}
	servers := &arcade.GameServerList{}
	if err := r.reader().List(ctx, servers, client.InNamespace(d.Namespace)); err != nil {
		return nil, errors.New("inspect GameServer data selectors failed")
	}
	for i := range servers.Items {
		other := &servers.Items[i]
		if other.Name == t.GameServer.Name && string(other.UID) == t.GameServer.UID {
			continue
		}
		if sameDataSelection(other.Status.ActiveData, &t.Data) || sameDataSelection(other.Status.ObservedData, &t.Data) || sameDataSelection(other.Spec.Storage.Reattach, &t.Data) {
			return nil, errors.New("another GameServer selects the target world")
		}
	}
	journal := map[string]arcade.GameDestroyClaimDeletion{}
	for _, entry := range d.Status.DeletionJournal {
		journal[entry.Path] = entry
	}
	volumeNames := map[string]struct{}{}
	for _, path := range t.Data.Claims {
		claim := &corev1.PersistentVolumeClaim{}
		err := r.reader().Get(ctx, types.NamespacedName{Namespace: d.Namespace, Name: path.ClaimRef.Name}, claim)
		if apierrors.IsNotFound(err) && permitJournalAbsence {
			if entry, ok := journal[path.Path]; ok && entry.ClaimRef == path.ClaimRef {
				continue
			}
		}
		if err != nil {
			return nil, errors.New("exact target PVC is unavailable")
		}
		if string(claim.UID) != path.ClaimRef.UID || len(claim.OwnerReferences) != 0 || claim.Labels[platformkube.LabelManagedBy] != platformkube.ManagerName || claim.Labels[platformkube.LabelName] != "game-data" || claim.Labels[platformkube.LabelDataPolicy] != "retain" || claim.Labels[platformkube.LabelInstance] != t.GameServer.Name || claim.Labels[platformkube.LabelGame] != t.Game || claim.Labels[platformkube.LabelDataIdentity] != t.Data.Identity || claim.Labels[platformkube.LabelDataPath] != path.Path || claim.Spec.VolumeName == "" {
			return nil, errors.New("exact target PVC identity or binding changed")
		}
		if backup != nil && claim.Annotations[platformkube.AnnotationColdBackupUID] != string(backup.UID) {
			return nil, errors.New("exact PVC cold-backup continuity marker is absent or changed")
		}
		if !claim.DeletionTimestamp.IsZero() {
			entry, journaled := journal[path.Path]
			if !permitJournalAbsence || !journaled || entry.ClaimRef != path.ClaimRef {
				return nil, errors.New("target PVC is already terminating without this destroy journal")
			}
		}
		volumeNames[claim.Spec.VolumeName] = struct{}{}
		if entry, journaled := journal[path.Path]; permitJournalAbsence && journaled && entry.ClaimRef == path.ClaimRef && !claim.DeletionTimestamp.IsZero() {
			// After a UID-preconditioned DELETE, Kubernetes may change the
			// terminating claim's phase or remove its PV before name absence.
			// No next claim is deleted until this exact name becomes absent.
			continue
		}
		if claim.Status.Phase != corev1.ClaimBound {
			return nil, errors.New("target PVC is no longer bound")
		}
		pv := &corev1.PersistentVolume{}
		if err := r.reader().Get(ctx, types.NamespacedName{Name: claim.Spec.VolumeName}, pv); err != nil || pv.Spec.ClaimRef == nil || pv.Spec.ClaimRef.Namespace != claim.Namespace || pv.Spec.ClaimRef.Name != claim.Name || pv.Spec.ClaimRef.UID != claim.UID {
			return nil, errors.New("target PVC/PV binding is not exact")
		}
	}
	pods := &corev1.PodList{}
	if err := r.reader().List(ctx, pods, client.InNamespace(d.Namespace)); err != nil {
		return nil, errors.New("inspect PVC mount users failed")
	}
	for i := range pods.Items {
		for _, volume := range pods.Items[i].Spec.Volumes {
			if volume.PersistentVolumeClaim != nil {
				if _, used := seenName[volume.PersistentVolumeClaim.ClaimName]; used {
					return nil, errors.New("target PVC remains mounted by a Pod")
				}
			}
		}
	}
	attachments := &storagev1.VolumeAttachmentList{}
	if err := r.reader().List(ctx, attachments); err != nil {
		return nil, errors.New("inspect target volume attachments failed")
	}
	for i := range attachments.Items {
		a := &attachments.Items[i]
		if a.Spec.Source.PersistentVolumeName != nil {
			if _, target := volumeNames[*a.Spec.Source.PersistentVolumeName]; target && a.Status.Attached {
				return nil, errors.New("target volume remains attached")
			}
		}
	}
	if backup == nil {
		return &destroySubject{definition: definition}, nil
	}
	source := backup.Status.Source
	targetPaths := make([]restoreworker.PathContract, 0, len(source.Paths))
	for _, path := range source.Paths {
		targetPaths = append(targetPaths, restoreworker.PathContract{Name: path.Name, MountPath: path.MountPath})
	}
	input := restoreworker.Input{Version: restoreworker.InputVersion, Stage: restoreworker.StagePreflight,
		OperationRef: arcade.ExactLocalReference{Name: d.Name, UID: string(d.UID)}, BackupRef: *d.Spec.BackupRef,
		Target: source.GameServer, WorkerLeaseName: platformkube.DestroyWorkerLeaseName(d.UID),
		RepositorySecretRef: *d.Spec.RepositorySecretRef, Artifact: *backup.Status.Artifact.DeepCopy(), Source: *source.DeepCopy(),
		TargetGame: source.Game, TargetImageDigest: source.ImageDigest, TargetSettingsDigest: source.SettingsDigest, TargetPaths: targetPaths,
	}
	if err := restoreworker.ValidateInput(input); err != nil {
		return nil, errors.New("repository preflight input is invalid")
	}
	return &destroySubject{backup: backup, definition: definition, input: input}, nil
}

func (r *GameDestroyReconciler) acquireDataLease(ctx context.Context, d *arcade.GameDestroy) error {
	name := platformkube.DataOperationLeaseName(d.Spec.Target.Data.Identity)
	key := types.NamespacedName{Namespace: d.Namespace, Name: name}
	existing := &coordinationv1.Lease{}
	err := r.reader().Get(ctx, key, existing)
	if apierrors.IsNotFound(err) {
		now := metav1.NewMicroTime(r.now().Time)
		lease := &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: d.Namespace,
			Labels:      map[string]string{platformkube.LabelManagedBy: platformkube.ManagerName, platformkube.LabelInstance: d.Spec.Target.GameServer.Name, platformkube.LabelDataIdentity: d.Spec.Target.Data.Identity, platformkube.LabelDestroyUID: string(d.UID)},
			Annotations: map[string]string{platformkube.AnnotationDestroyName: d.Name}},
			Spec: coordinationv1.LeaseSpec{HolderIdentity: ptr.To(string(d.UID)), AcquireTime: &now}}
		return r.Create(ctx, lease)
	}
	if err != nil {
		return err
	}
	if !platformkube.DestroyOperationLeaseMatches(existing, arcade.ExactLocalReference{Name: d.Name, UID: string(d.UID)}, d.Spec.Target.GameServer.Name, d.Spec.Target.Data.Identity) {
		return errors.New("retained world operation lease belongs to another operation")
	}
	return nil
}

func (r *GameDestroyReconciler) requireDataLease(ctx context.Context, d *arcade.GameDestroy) error {
	lease := &coordinationv1.Lease{}
	if err := r.reader().Get(ctx, types.NamespacedName{Namespace: d.Namespace, Name: platformkube.DataOperationLeaseName(d.Spec.Target.Data.Identity)}, lease); err != nil || !platformkube.DestroyOperationLeaseMatches(lease, arcade.ExactLocalReference{Name: d.Name, UID: string(d.UID)}, d.Spec.Target.GameServer.Name, d.Spec.Target.Data.Identity) {
		return errors.New("exact destroy data lease is not held")
	}
	return nil
}

func (r *GameDestroyReconciler) releaseDataLease(ctx context.Context, d *arcade.GameDestroy) error {
	lease := &coordinationv1.Lease{}
	err := r.reader().Get(ctx, types.NamespacedName{Namespace: d.Namespace, Name: platformkube.DataOperationLeaseName(d.Spec.Target.Data.Identity)}, lease)
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !platformkube.DestroyOperationLeaseMatches(lease, arcade.ExactLocalReference{Name: d.Name, UID: string(d.UID)}, d.Spec.Target.GameServer.Name, d.Spec.Target.Data.Identity) {
		if (lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity != string(d.UID)) &&
			lease.Labels[platformkube.LabelDestroyUID] != string(d.UID) &&
			lease.Annotations[platformkube.AnnotationDestroyName] != d.Name {
			return nil
		}
		return errors.New("refuse to release foreign data lease")
	}
	return r.Delete(ctx, lease, client.Preconditions{UID: &lease.UID})
}

func (r *GameDestroyReconciler) workerLease(ctx context.Context, d *arcade.GameDestroy) error {
	key := types.NamespacedName{Namespace: d.Namespace, Name: platformkube.DestroyWorkerLeaseName(d.UID)}
	lease := &coordinationv1.Lease{}
	err := r.reader().Get(ctx, key, lease)
	if apierrors.IsNotFound(err) {
		owner := metav1.OwnerReference{APIVersion: arcade.GroupVersion.String(), Kind: "GameDestroy", Name: d.Name, UID: d.UID, Controller: ptr.To(true), BlockOwnerDeletion: ptr.To(true)}
		lease = &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Name: key.Name, Namespace: key.Namespace,
			Labels:      map[string]string{platformkube.LabelManagedBy: platformkube.ManagerName, platformkube.LabelInstance: d.Spec.Target.GameServer.Name, platformkube.LabelDataIdentity: d.Spec.Target.Data.Identity, platformkube.LabelDestroyUID: string(d.UID)},
			Annotations: map[string]string{platformkube.AnnotationDestroyName: d.Name}, OwnerReferences: []metav1.OwnerReference{owner}},
			Spec: coordinationv1.LeaseSpec{HolderIdentity: ptr.To(string(d.UID))}}
		return r.Create(ctx, lease)
	}
	if err != nil {
		return err
	}
	if len(lease.OwnerReferences) != 1 || !controlledBy(lease.OwnerReferences, "GameDestroy", d.Name, d.UID) || lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity != string(d.UID) || lease.Labels[platformkube.LabelDestroyUID] != string(d.UID) || lease.Labels[platformkube.LabelDataIdentity] != d.Spec.Target.Data.Identity || lease.Annotations[platformkube.AnnotationDestroyName] != d.Name {
		return errors.New("destroy worker lease changed owner")
	}
	return nil
}

func (r *GameDestroyReconciler) verify(ctx context.Context, d *arcade.GameDestroy) (ctrl.Result, error) {
	if d.Status.Verification != nil {
		if err := r.requireDataLease(ctx, d); err != nil {
			return r.fail(ctx, d, "OperationConflict", err.Error())
		}
		if _, err := r.resolve(ctx, d, false); err != nil {
			return r.fail(ctx, d, "ColdContinuityLost", err.Error())
		}
		pending, err := r.cleanupWorker(ctx, d)
		if err != nil || pending {
			return ctrl.Result{RequeueAfter: destroyRequeue}, err
		}
		return ctrl.Result{}, r.status(ctx, d, arcade.DestroyPhaseDeleting, "RepositoryVerified", "exact repository artifact reverified while the world remained cold")
	}
	if !r.confirmed(d) {
		return r.fail(ctx, d, "ConfirmationExpired", "confirmation expired before repository verification completed")
	}
	if err := r.requireDataLease(ctx, d); err != nil {
		return r.fail(ctx, d, "OperationConflict", err.Error())
	}
	s, err := r.resolve(ctx, d, false)
	if err != nil {
		return r.fail(ctx, d, "PreflightRejected", err.Error())
	}
	if err := r.workerLease(ctx, d); err != nil {
		return ctrl.Result{}, err
	}
	resources, err := platformkube.BuildDestroyResources(d, s.input, r.WorkerImage, s.definition.RuntimeIdentity)
	if err != nil {
		return r.fail(ctx, d, "WorkerInvalid", "bounded repository worker configuration is invalid")
	}
	changed, err := r.ensureWorkerResources(ctx, d, resources)
	if err != nil {
		return ctrl.Result{}, err
	}
	if changed {
		return ctrl.Result{Requeue: true}, nil
	}
	job := &batchv1.Job{}
	if err := r.reader().Get(ctx, client.ObjectKeyFromObject(resources.Job), job); err != nil {
		return ctrl.Result{}, err
	}
	if job.UID == "" {
		return ctrl.Result{RequeueAfter: destroyRequeue}, nil
	}
	armed, err := r.destroyJobArmed(ctx, d, job)
	if err != nil {
		return ctrl.Result{}, err
	}
	if !armed {
		if job.Spec.Suspend == nil || !*job.Spec.Suspend {
			return r.fail(ctx, d, "WorkerActivatedEarly", "preflight Job became active before exact authorization")
		}
		if err := r.armDestroyJob(ctx, d, job); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}
	if jobFailed(job) {
		return r.fail(ctx, d, "RepositoryVerificationFailed", "repository preflight worker failed; no claim was deleted")
	}
	if job.Spec.Suspend == nil || *job.Spec.Suspend {
		updated := job.DeepCopy()
		updated.Spec.Suspend = ptr.To(false)
		return ctrl.Result{Requeue: true}, r.Update(ctx, updated)
	}
	state, pod, err := r.authorizeWorkerPod(ctx, d, job)
	if err != nil {
		return ctrl.Result{}, err
	}
	if state == backupPodChanged || state == backupPodOverlap {
		return r.fail(ctx, d, "WorkerIdentityChanged", "preflight Pod did not match exact gated worker")
	}
	if state != backupPodAuthorized || !jobComplete(job) {
		return ctrl.Result{RequeueAfter: destroyRequeue}, nil
	}
	result, err := destroyWorkerResult(pod)
	if err != nil {
		return r.fail(ctx, d, "WorkerResultInvalid", "repository verification result is unavailable or invalid")
	}
	if result.Version != restoreworker.ResultVersion || result.Stage != restoreworker.StagePreflight || result.ArtifactID != s.input.Artifact.ID || result.ManifestDigest != s.input.Artifact.ManifestDigest || result.PathCount != int32(len(d.Spec.Target.Data.Claims)) || result.VerifiedAt.IsZero() || result.VerifiedAt.After(r.now().Add(time.Minute)) {
		return r.fail(ctx, d, "WorkerResultInvalid", "repository verification did not match exact backup")
	}
	copy := d.DeepCopy()
	copy.Status.Verification = &arcade.GameDestroyVerification{BackupRef: *d.Spec.BackupRef, RepositorySecretRef: *d.Spec.RepositorySecretRef, ArtifactID: result.ArtifactID, ManifestDigest: result.ManifestDigest, PathCount: result.PathCount, VerifiedAt: metav1.NewTime(result.VerifiedAt), ColdAt: r.now()}
	return ctrl.Result{}, r.Status().Update(ctx, copy)
}

func (r *GameDestroyReconciler) destroyJobArmed(ctx context.Context, d *arcade.GameDestroy, job *batchv1.Job) (bool, error) {
	lease := &coordinationv1.Lease{}
	if err := r.reader().Get(ctx, types.NamespacedName{Namespace: d.Namespace, Name: platformkube.DestroyWorkerLeaseName(d.UID)}, lease); err != nil {
		return false, err
	}
	if !controlledBy(lease.OwnerReferences, "GameDestroy", d.Name, d.UID) || lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity != string(d.UID) {
		return false, errors.New("destroy worker lease changed owner")
	}
	authorized := lease.Annotations[destroyJobAuthorizedAnnotation]
	if authorized != "" && authorized != string(job.UID) {
		return false, errors.New("destroy worker lease pins a different Job UID")
	}
	return authorized == string(job.UID), nil
}

func (r *GameDestroyReconciler) armDestroyJob(ctx context.Context, d *arcade.GameDestroy, job *batchv1.Job) error {
	lease := &coordinationv1.Lease{}
	if err := r.reader().Get(ctx, types.NamespacedName{Namespace: d.Namespace, Name: platformkube.DestroyWorkerLeaseName(d.UID)}, lease); err != nil {
		return err
	}
	if !controlledBy(lease.OwnerReferences, "GameDestroy", d.Name, d.UID) || lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity != string(d.UID) || lease.Annotations[destroyJobAuthorizedAnnotation] != "" {
		return errors.New("destroy worker lease cannot arm this Job")
	}
	updated := lease.DeepCopy()
	updated.Annotations[destroyJobAuthorizedAnnotation] = string(job.UID)
	return r.Update(ctx, updated)
}

func (r *GameDestroyReconciler) ensureWorkerResources(ctx context.Context, d *arcade.GameDestroy, resources platformkube.DestroyResources) (bool, error) {
	for _, desired := range []client.Object{resources.Input, resources.ServiceAccount, resources.Role, resources.RoleBinding} {
		existing := desired.DeepCopyObject().(client.Object)
		err := r.reader().Get(ctx, client.ObjectKeyFromObject(desired), existing)
		if apierrors.IsNotFound(err) {
			return true, r.Create(ctx, desired)
		}
		if err != nil {
			return false, err
		}
		if !apiequality.Semantic.DeepEqual(existing.GetOwnerReferences(), desired.GetOwnerReferences()) ||
			!apiequality.Semantic.DeepEqual(existing.GetLabels(), desired.GetLabels()) ||
			!apiequality.Semantic.DeepEqual(existing.GetAnnotations(), desired.GetAnnotations()) {
			return false, errors.New("destroy worker authority collides with a changed object")
		}
		switch a := existing.(type) {
		case *corev1.ConfigMap:
			if !apiequality.Semantic.DeepEqual(a.Data, desired.(*corev1.ConfigMap).Data) || a.Immutable == nil || !*a.Immutable {
				return false, errors.New("destroy input ConfigMap changed")
			}
		case *rbacv1.Role:
			if !apiequality.Semantic.DeepEqual(a.Rules, desired.(*rbacv1.Role).Rules) {
				return false, errors.New("destroy worker Role changed")
			}
		case *rbacv1.RoleBinding:
			if !apiequality.Semantic.DeepEqual(a.Subjects, desired.(*rbacv1.RoleBinding).Subjects) || a.RoleRef != desired.(*rbacv1.RoleBinding).RoleRef {
				return false, errors.New("destroy worker RoleBinding changed")
			}
		case *corev1.ServiceAccount:
			if a.AutomountServiceAccountToken == nil || *a.AutomountServiceAccountToken {
				return false, errors.New("destroy worker ServiceAccount changed")
			}
		}
	}
	job := &batchv1.Job{}
	err := r.reader().Get(ctx, client.ObjectKeyFromObject(resources.Job), job)
	if apierrors.IsNotFound(err) {
		return true, r.Create(ctx, resources.Job)
	}
	if err != nil {
		return false, err
	}
	expectedJob := resources.Job.DeepCopy()
	if job.Spec.Suspend != nil && !*job.Spec.Suspend {
		expectedJob.Spec.Suspend = ptr.To(false)
	}
	if !apiequality.Semantic.DeepEqual(job.OwnerReferences, resources.Job.OwnerReferences) || !apiequality.Semantic.DeepEqual(job.Labels, resources.Job.Labels) || !apiequality.Semantic.DeepEqual(job.Annotations, resources.Job.Annotations) || !backupJobSpecMatches(expectedJob, job) {
		return false, errors.New("destroy preflight Job changed")
	}
	return false, nil
}

func (r *GameDestroyReconciler) authorizeWorkerPod(ctx context.Context, d *arcade.GameDestroy, job *batchv1.Job) (backupPodState, *corev1.Pod, error) {
	pods := &corev1.PodList{}
	if err := r.reader().List(ctx, pods, client.InNamespace(d.Namespace), client.MatchingLabels{platformkube.LabelDestroyUID: string(d.UID)}); err != nil {
		return backupPodPending, nil, err
	}
	if len(pods.Items) == 0 {
		return backupPodPending, nil, nil
	}
	if len(pods.Items) != 1 {
		return backupPodOverlap, nil, nil
	}
	pod := &pods.Items[0]
	if pod.UID == "" || job.UID == "" || !controlledBy(pod.OwnerReferences, "Job", job.Name, job.UID) || !apiequality.Semantic.DeepEqual(pod.Labels, job.Spec.Template.Labels) || !workerPodAnnotationsMatch(pod.Annotations, job.Spec.Template.Annotations, platformkube.AnnotationDestroyPodAuthorized) {
		return backupPodChanged, nil, nil
	}
	if pod.Annotations[platformkube.AnnotationDestroyPodAuthorized] == string(pod.UID) && len(pod.Spec.SchedulingGates) == 0 {
		return backupPodAuthorized, pod, nil
	}
	if pod.Annotations[platformkube.AnnotationDestroyPodAuthorized] != "" || pod.Spec.NodeName != "" || pod.Status.Phase != "" && pod.Status.Phase != corev1.PodPending || len(pod.Status.InitContainerStatuses) != 0 || len(pod.Status.ContainerStatuses) != 0 || len(pod.Spec.SchedulingGates) != 1 || pod.Spec.SchedulingGates[0].Name != platformkube.DestroySchedulingGate {
		return backupPodChanged, nil, nil
	}
	desired := job.Spec.Template.Spec.DeepCopy()
	actual := pod.Spec.DeepCopy()
	normalizeBackupPodDefaults(desired)
	normalizeBackupPodDefaults(actual)
	if !apiequality.Semantic.DeepEqual(desired, actual) {
		return backupPodChanged, nil, nil
	}
	copy := pod.DeepCopy()
	copy.Annotations[platformkube.AnnotationDestroyPodAuthorized] = string(pod.UID)
	copy.Spec.SchedulingGates = nil
	if err := r.Update(ctx, copy); err != nil {
		return backupPodPending, nil, err
	}
	return backupPodPending, nil, nil
}

func destroyWorkerResult(pod *corev1.Pod) (restoreworker.Result, error) {
	if pod == nil {
		return restoreworker.Result{}, errors.New("no result Pod")
	}
	for _, container := range pod.Status.ContainerStatuses {
		if container.Name != "destroy-worker" || container.State.Terminated == nil || container.State.Terminated.ExitCode != 0 {
			continue
		}
		decoder := json.NewDecoder(bytes.NewBufferString(container.State.Terminated.Message))
		decoder.DisallowUnknownFields()
		var result restoreworker.Result
		if decoder.Decode(&result) == nil && decoder.Decode(&struct{}{}) == io.EOF {
			return result, nil
		}
	}
	return restoreworker.Result{}, errors.New("no valid destroy result")
}

func (r *GameDestroyReconciler) cleanupWorker(ctx context.Context, d *arcade.GameDestroy) (bool, error) {
	job := &batchv1.Job{}
	jobKey := types.NamespacedName{Namespace: d.Namespace, Name: platformkube.DestroyResourceName(d.UID)}
	err := r.reader().Get(ctx, jobKey, job)
	if err == nil {
		if !controlledBy(job.OwnerReferences, "GameDestroy", d.Name, d.UID) {
			return false, errors.New("refuse to delete foreign destroy Job")
		}
		foreground := metav1.DeletePropagationForeground
		// A same-name replacement or changed ownership after this read must
		// not become cleanup authority. Preserve the whole original witness.
		return true, r.Delete(ctx, job, &client.DeleteOptions{PropagationPolicy: &foreground,
			Preconditions: &metav1.Preconditions{UID: ptr.To(job.UID), ResourceVersion: ptr.To(job.ResourceVersion)}})
	}
	if !apierrors.IsNotFound(err) {
		return false, err
	}
	pods := &corev1.PodList{}
	if err := r.reader().List(ctx, pods, client.InNamespace(d.Namespace), client.MatchingLabels{platformkube.LabelDestroyUID: string(d.UID)}); err != nil {
		return false, err
	}
	if len(pods.Items) != 0 {
		return true, nil
	}
	for _, object := range []client.Object{&rbacv1.RoleBinding{}, &rbacv1.Role{}, &corev1.ServiceAccount{}, &corev1.ConfigMap{}, &coordinationv1.Lease{}} {
		name := platformkube.DestroyResourceName(d.UID) + "-authority"
		if _, ok := object.(*corev1.ConfigMap); ok {
			name = platformkube.DestroyResourceName(d.UID) + "-input"
		}
		if _, ok := object.(*coordinationv1.Lease); ok {
			name = platformkube.DestroyWorkerLeaseName(d.UID)
		}
		err := r.reader().Get(ctx, types.NamespacedName{Namespace: d.Namespace, Name: name}, object)
		if apierrors.IsNotFound(err) {
			continue
		}
		if err != nil {
			return false, err
		}
		if !controlledBy(object.GetOwnerReferences(), "GameDestroy", d.Name, d.UID) {
			return false, errors.New("refuse to delete foreign destroy authority")
		}
		if err := r.Delete(ctx, object, client.Preconditions{UID: ptr.To(object.GetUID())}); err != nil && !apierrors.IsNotFound(err) {
			return false, err
		}
		return true, nil
	}
	return false, nil
}

func (r *GameDestroyReconciler) deleteClaims(ctx context.Context, d *arcade.GameDestroy) (ctrl.Result, error) {
	if len(d.Status.DeletionJournal) == 0 && !r.confirmed(d) {
		return r.fail(ctx, d, "ConfirmationExpired", "confirmation expired before PVC deletion began; no claim was deleted")
	}
	if d.Spec.Mode == arcade.DestroyModeVerifiedBackup && d.Status.Verification == nil {
		return r.fail(ctx, d, "VerificationMissing", "repository verification is missing")
	}
	if d.Spec.Mode == arcade.DestroyModeVerifiedBackup && d.Status.Verification != nil {
		pending, err := r.cleanupWorker(ctx, d)
		if err != nil || pending {
			return ctrl.Result{RequeueAfter: destroyRequeue}, err
		}
	}
	if err := r.requireDataLease(ctx, d); err != nil {
		return r.hold(ctx, d, "OperationConflict", err.Error())
	}
	if _, err := r.resolve(ctx, d, true); err != nil {
		return r.hold(ctx, d, "IdentityMismatch", err.Error())
	}
	for _, target := range d.Spec.Target.Data.Claims {
		var entry *arcade.GameDestroyClaimDeletion
		for i := range d.Status.DeletionJournal {
			if d.Status.DeletionJournal[i].Path == target.Path {
				entry = &d.Status.DeletionJournal[i]
				break
			}
		}
		if entry == nil {
			copy := d.DeepCopy()
			copy.Status.DeletionJournal = append(copy.Status.DeletionJournal, arcade.GameDestroyClaimDeletion{Path: target.Path, ClaimRef: target.ClaimRef, RequestedAt: r.now()})
			return ctrl.Result{Requeue: true}, r.Status().Update(ctx, copy)
		}
		if entry.ClaimRef != target.ClaimRef {
			return r.hold(ctx, d, "JournalMismatch", "deletion journal does not match exact target")
		}
		claim := &corev1.PersistentVolumeClaim{}
		err := r.reader().Get(ctx, types.NamespacedName{Namespace: d.Namespace, Name: target.ClaimRef.Name}, claim)
		if apierrors.IsNotFound(err) {
			if entry.ObservedDeletedAt == nil {
				copy := d.DeepCopy()
				now := r.now()
				for i := range copy.Status.DeletionJournal {
					if copy.Status.DeletionJournal[i].Path == target.Path {
						copy.Status.DeletionJournal[i].ObservedDeletedAt = &now
					}
				}
				return ctrl.Result{Requeue: true}, r.Status().Update(ctx, copy)
			}
			continue
		}
		if err != nil {
			return ctrl.Result{}, err
		}
		if string(claim.UID) != target.ClaimRef.UID || entry.ObservedDeletedAt != nil {
			return r.hold(ctx, d, "NameReused", "target PVC name was reused or deletion evidence contradicted")
		}
		if !claim.DeletionTimestamp.IsZero() {
			return ctrl.Result{RequeueAfter: destroyRequeue}, nil
		}
		if err := r.requireDataLease(ctx, d); err != nil {
			return r.hold(ctx, d, "OperationConflict", err.Error())
		}
		if _, err := r.resolve(ctx, d, true); err != nil {
			return r.hold(ctx, d, "IdentityMismatch", err.Error())
		}
		if err := r.Delete(ctx, claim, client.Preconditions{UID: ptr.To(claim.UID)}); err != nil && !apierrors.IsNotFound(err) {
			return ctrl.Result{}, fmt.Errorf("delete exact journaled PVC failed: %w", err)
		}
		return ctrl.Result{RequeueAfter: destroyRequeue}, nil
	}
	if _, err := r.resolve(ctx, d, true); err != nil {
		return r.hold(ctx, d, "FinalAbsenceFailed", err.Error())
	}
	return ctrl.Result{}, r.status(ctx, d, arcade.DestroyPhaseSucceeded, "Destroyed", "all exact target PVC names were observed absent; backing PV reclaim policy may retain bytes")
}

func (r *GameDestroyReconciler) finalize(ctx context.Context, d *arcade.GameDestroy) (ctrl.Result, error) {
	pending, err := r.cleanupWorker(ctx, d)
	if err != nil || pending {
		return ctrl.Result{RequeueAfter: destroyRequeue}, err
	}
	if err := r.releaseDataLease(ctx, d); err != nil {
		return ctrl.Result{}, err
	}
	return r.removeFinalizer(ctx, d)
}

func (r *GameDestroyReconciler) removeFinalizer(ctx context.Context, d *arcade.GameDestroy) (ctrl.Result, error) {
	copy := d.DeepCopy()
	copy.Finalizers = slices.DeleteFunc(copy.Finalizers, func(value string) bool { return value == platformkube.DestroyFinalizer })
	return ctrl.Result{}, r.Update(ctx, copy)
}

func (r *GameDestroyReconciler) SetupWithManager(manager ctrl.Manager) error {
	if r.Client == nil || r.Scheme == nil || r.Catalog == nil || r.WorkerImage == "" {
		return errors.New("destroy reconciler client, scheme, catalog, and pinned worker image are required")
	}
	return ctrl.NewControllerManagedBy(manager).For(&arcade.GameDestroy{}).Owns(&batchv1.Job{}).Owns(&corev1.ConfigMap{}).Owns(&corev1.ServiceAccount{}).Owns(&rbacv1.Role{}).Owns(&rbacv1.RoleBinding{}).Complete(r)
}
