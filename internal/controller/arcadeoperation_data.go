// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"maps"
	"time"

	arcade "github.com/gobha-me/arcadectl/api/v1alpha1"
	"github.com/gobha-me/arcadectl/internal/operations"
	platformkube "github.com/gobha-me/arcadectl/internal/platform/kube"
	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const operationConfirmAnnotation = "arcade.gobha.me/operation-confirm-uid"
const operationCancelAnnotation = "arcade.gobha.me/operation-cancel-uid"

func (r *ArcadeOperationReconciler) planOperationBackup(ctx context.Context, o *arcade.ArcadeOperation, plan *arcade.OperationPlan, ref arcade.ExactLocalReference) error {
	backup := &arcade.GameBackup{}
	if ref.Namespace != nil {
		return operationError("invalid_reference")
	}
	if err := r.operationReference(ctx, types.NamespacedName{Namespace: o.Namespace, Name: ref.Name}, backup, "invalid_reference"); err != nil {
		return err
	}
	if string(backup.UID) != ref.UID || !backup.DeletionTimestamp.IsZero() || backup.Status.ObservedGeneration != backup.Generation ||
		backup.Status.Phase != arcade.DataPhaseSucceeded || backup.Status.Artifact == nil || backup.Status.Source == nil || backup.Status.Artifact.Verification.Result != arcade.VerificationVerified ||
		backup.Status.Artifact.Verification.VerifiedAt == nil || backup.Status.Artifact.Verification.VerifiedAt.IsZero() || backup.Status.Artifact.PathCount != int32(len(backup.Status.Source.Paths)) ||
		!apiequality.Semantic.DeepEqual(backup.Status.Artifact.Provenance.BackupRef, ref) || !apiequality.Semantic.DeepEqual(backup.Status.Artifact.Provenance.RepositorySecretRef, backup.Spec.RepositorySecretRef) {
		return operationError("invalid_reference")
	}
	if o.Spec.Action == arcade.OperationWorldDestroyPreview {
		if backup.Spec.RestartPolicy != arcade.RestartLeaveStopped || backup.Status.Runtime == nil || backup.Status.Runtime.Phase != arcade.PhaseStopped ||
			backup.Status.Runtime.GameServer.DesiredState != arcade.DesiredStateStopped || plan.Server == nil || plan.Data == nil || backup.Spec.Source.UID != plan.Server.UID || backup.Spec.Source.Name != plan.Server.Name {
			return operationError("invalid_reference")
		}
		data := &arcade.RetainedDataReference{Identity: plan.Data.Identity}
		for _, path := range backup.Status.Source.Paths {
			data.Claims = append(data.Claims, arcade.RetainedDataClaimReference{Path: path.Name, ClaimRef: path.ClaimRef})
		}
		if !sameDataSelection(data, plan.Data) {
			return operationError("invalid_reference")
		}
		for _, claim := range plan.Data.Claims {
			pvc := &corev1.PersistentVolumeClaim{}
			if err := r.operationReference(ctx, types.NamespacedName{Namespace: o.Namespace, Name: claim.ClaimRef.Name}, pvc, "invalid_reference"); err != nil {
				return err
			}
			if string(pvc.UID) != claim.ClaimRef.UID || !pvc.DeletionTimestamp.IsZero() ||
				pvc.Labels[platformkube.LabelDataIdentity] != plan.Data.Identity || pvc.Labels[platformkube.LabelDataPath] != claim.Path || pvc.Annotations[platformkube.AnnotationColdBackupUID] != ref.UID {
				return operationError("invalid_reference")
			}
		}
	}
	copy := ref
	secret := backup.Status.Artifact.Provenance.RepositorySecretRef
	plan.BackupRef = &copy
	plan.RepositorySecretRef = &secret
	return nil
}

func (r *ArcadeOperationReconciler) reconcileOperationData(ctx context.Context, o *arcade.ArcadeOperation) error {
	if o.Spec.Request.DestroyCommand != nil {
		return r.reconcileDestroyCommand(ctx, o)
	}
	plan := o.Status.Plan
	if plan == nil || plan.Server == nil || plan.Data == nil || plan.RepositorySecretRef == nil {
		return operationError("receipt_invalid")
	}
	meta := metav1.ObjectMeta{Namespace: o.Namespace, Labels: map[string]string{operationReceiptUIDLabel: string(o.UID)}, Annotations: map[string]string{operationReceiptNameAnnotation: o.Name}}
	var child client.Object
	switch o.Spec.Action {
	case arcade.OperationWorldBackup:
		meta.Name = operations.ChildName(o.UID, "GameBackup")
		child = &arcade.GameBackup{ObjectMeta: meta, Spec: arcade.GameBackupSpec{DataOperationRequest: arcade.DataOperationRequest{RepositorySecretRef: *plan.RepositorySecretRef, RestartPolicy: o.Spec.Request.Backup.RestartPolicy},
			Source: *plan.Server.DeepCopy(), SourceData: plan.Data.DeepCopy(), RetentionPolicy: arcade.ArtifactRetentionRetain}}
	case arcade.OperationWorldRestore:
		if plan.BackupRef == nil {
			return operationError("receipt_invalid")
		}
		meta.Name = operations.ChildName(o.UID, "GameRestore")
		child = &arcade.GameRestore{ObjectMeta: meta, Spec: arcade.GameRestoreSpec{DataOperationRequest: arcade.DataOperationRequest{RepositorySecretRef: *plan.RepositorySecretRef, RestartPolicy: o.Spec.Request.Restore.RestartPolicy},
			BackupRef: *plan.BackupRef, Target: *plan.Server.DeepCopy(), TargetData: plan.Data.DeepCopy()}}
	case arcade.OperationWorldDestroyPreview:
		if plan.BackupRef == nil || o.Status.RetainedWorld == nil {
			return operationError("receipt_invalid")
		}
		meta.Name = operations.ChildName(o.UID, "GameDestroy")
		child = &arcade.GameDestroy{ObjectMeta: meta, Spec: arcade.GameDestroySpec{Target: o.Status.RetainedWorld.Target, Mode: arcade.DestroyModeVerifiedBackup, BackupRef: plan.BackupRef.DeepCopy(), RepositorySecretRef: plan.RepositorySecretRef.DeepCopy()}}
	default:
		return operationError("invalid_request")
	}
	actual := child.DeepCopyObject().(client.Object)
	err := r.reader().Get(ctx, client.ObjectKeyFromObject(child), actual)
	if apierrors.IsNotFound(err) {
		if o.Status.Child != nil {
			return operationError("child_changed")
		}
		// Native children, like servers, are deliberately not owned by receipts.
		return r.Create(ctx, child)
	}
	if err != nil {
		return err
	}
	kind := operationChildKind(child)
	if actual.GetUID() == "" || len(actual.GetOwnerReferences()) != 0 || !actual.GetDeletionTimestamp().IsZero() || actual.GetLabels()[operationReceiptUIDLabel] != string(o.UID) || actual.GetAnnotations()[operationReceiptNameAnnotation] != o.Name ||
		!operationChildSpecMatches(child, actual) {
		return operationError("child_changed")
	}
	if o.Status.Child == nil {
		if actual.GetGeneration() != 1 {
			return operationError("child_changed")
		}
		return r.operationStatus(ctx, o, arcade.OperationPhaseRunning, func(copy *arcade.ArcadeOperation) {
			copy.Status.Child = &arcade.OperationChildReference{Kind: kind, ExactLocalReference: arcade.ExactLocalReference{Name: actual.GetName(), UID: string(actual.GetUID())}, Generation: actual.GetGeneration()}
		})
	}
	if o.Status.Child.Kind != kind || o.Status.Child.Name != actual.GetName() || o.Status.Child.UID != string(actual.GetUID()) ||
		(kind != "GameDestroy" && o.Status.Child.Generation != actual.GetGeneration()) || actual.GetGeneration() < o.Status.Child.Generation {
		return operationError("child_changed")
	}
	switch actual := actual.(type) {
	case *arcade.GameBackup:
		return r.mirrorDataOperation(ctx, o, actual.Status.DataOperationStatus, actual.Generation)
	case *arcade.GameRestore:
		return r.mirrorDataOperation(ctx, o, actual.Status.DataOperationStatus, actual.Generation)
	case *arcade.GameDestroy:
		return r.mirrorDestroyOperation(ctx, o, actual)
	}
	return operationError("receipt_invalid")
}

func operationChildKind(object client.Object) string {
	switch object.(type) {
	case *arcade.GameBackup:
		return "GameBackup"
	case *arcade.GameRestore:
		return "GameRestore"
	case *arcade.GameDestroy:
		return "GameDestroy"
	}
	return "GameServer"
}
func operationChildSpecMatches(want, got client.Object) bool {
	switch expected := want.(type) {
	case *arcade.GameBackup:
		actual, ok := got.(*arcade.GameBackup)
		return ok && apiequality.Semantic.DeepEqual(expected.Spec, actual.Spec)
	case *arcade.GameRestore:
		actual, ok := got.(*arcade.GameRestore)
		return ok && apiequality.Semantic.DeepEqual(expected.Spec, actual.Spec)
	case *arcade.GameDestroy:
		actual, ok := got.(*arcade.GameDestroy)
		if !ok {
			return false
		}
		copy := *actual.Spec.DeepCopy()
		copy.ConfirmationChallenge = ""
		copy.CancelRequested = false
		return apiequality.Semantic.DeepEqual(expected.Spec, copy)
	}
	return false
}
func (r *ArcadeOperationReconciler) mirrorDataOperation(ctx context.Context, o *arcade.ArcadeOperation, status arcade.DataOperationStatus, generation int64) error {
	if status.ObservedGeneration != generation {
		if status.ObservedGeneration == 0 && status.Phase == "" && !r.operationObservationSlow(o) {
			return nil
		}
		return r.operationProgressGuidance(ctx, o, "api_unavailable")
	}
	phase := arcade.OperationPhaseRunning
	switch status.Phase {
	case arcade.DataPhaseBlocked:
		code := "invalid_reference"
		for _, condition := range status.Conditions {
			if condition.Reason == arcade.ReasonOperationConflict {
				code = "operation_conflict"
			}
			if condition.Reason == arcade.ReasonSecretUnavailable {
				code = "secret_unavailable"
			}
		}
		return r.operationProgressGuidance(ctx, o, code)
	case arcade.DataPhaseSucceeded:
		phase = arcade.OperationPhaseSucceeded
	case arcade.DataPhaseCancelled:
		phase = arcade.OperationPhaseCancelled
	case arcade.DataPhaseFailed:
		code := "worker_failed"
		complete := meta.FindStatusCondition(status.Conditions, arcade.ConditionOperationComplete)
		if complete != nil && complete.Reason == arcade.ReasonVerificationFailed {
			code = "verification_failed"
		}
		return operationError(code)
	case arcade.DataPhaseVerifying:
		phase = arcade.OperationPhaseVerifying
	}
	if o.Status.Phase == phase && o.Status.Failure == nil {
		return nil
	}
	return r.operationStatus(ctx, o, phase, func(copy *arcade.ArcadeOperation) { copy.Status.Failure = nil })
}
func (r *ArcadeOperationReconciler) mirrorDestroyOperation(ctx context.Context, o *arcade.ArcadeOperation, destroy *arcade.GameDestroy) error {
	if destroy.Status.ObservedGeneration != destroy.Generation {
		if destroy.Status.ObservedGeneration == 0 && destroy.Status.Phase == "" && !r.operationObservationSlow(o) {
			if o.Status.Phase == arcade.OperationPhaseRunning && o.Status.DestroyPreview == nil && o.Status.Failure == nil {
				return nil
			}
			return r.operationStatus(ctx, o, arcade.OperationPhaseRunning, func(copy *arcade.ArcadeOperation) { copy.Status.DestroyPreview = nil; copy.Status.Failure = nil })
		}
		if o.Status.Phase == arcade.OperationPhaseRunning && o.Status.DestroyPreview == nil && o.Status.Failure != nil && o.Status.Failure.Code == "api_unavailable" && o.Status.Failure.Retryable {
			return nil
		}
		return r.operationStatus(ctx, o, arcade.OperationPhaseRunning, func(copy *arcade.ArcadeOperation) {
			copy.Status.DestroyPreview = nil
			copy.Status.Failure = operationFailure("api_unavailable")
			copy.Status.Failure.Retryable = true
		})
	}
	phase := arcade.OperationPhaseRunning
	switch destroy.Status.Phase {
	case arcade.DestroyPhasePreview:
		phase = arcade.OperationPhaseAwaitingConfirmation
	case arcade.DestroyPhaseVerifying:
		phase = arcade.OperationPhaseVerifying
	case arcade.DestroyPhaseDeleting:
		phase = arcade.OperationPhaseDeleting
	case arcade.DestroyPhaseSucceeded:
		phase = arcade.OperationPhaseSucceeded
	case arcade.DestroyPhaseCancelled:
		phase = arcade.OperationPhaseCancelled
	case arcade.DestroyPhaseFailed:
		complete := meta.FindStatusCondition(destroy.Status.Conditions, arcade.ConditionOperationComplete)
		if complete != nil && complete.Reason == arcade.ReasonVerificationFailed {
			return operationError("verification_failed")
		}
		return operationError("invalid_reference")
	}
	if o.Status.Phase == phase && o.Status.Failure == nil && apiequality.Semantic.DeepEqual(o.Status.DestroyPreview, destroy.Status.Preview) {
		return nil
	}
	return r.operationStatus(ctx, o, phase, func(copy *arcade.ArcadeOperation) {
		copy.Status.DestroyPreview = destroy.Status.Preview.DeepCopy()
		copy.Status.Failure = nil
	})
}

func (r *ArcadeOperationReconciler) operationObservationSlow(o *arcade.ArcadeOperation) bool {
	return o.Status.StartedAt != nil && r.now().Time.Sub(o.Status.StartedAt.Time) > 15*time.Minute
}

func (r *ArcadeOperationReconciler) planDestroyCommand(ctx context.Context, o *arcade.ArcadeOperation) (*arcade.OperationPlan, *arcade.OperationRetainedWorld, error) {
	command := o.Spec.Request.DestroyCommand
	parent, destroy, err := r.operationDestroyCommandObjects(ctx, o)
	if err != nil {
		return nil, nil, err
	}
	plan := parent.Status.Plan.DeepCopy()
	ref := command.DestroyRef
	plan.DestroyRef = &ref
	if destroy.Spec.Mode != arcade.DestroyModeVerifiedBackup {
		return nil, nil, operationError("invalid_reference")
	}
	return plan, nil, nil
}
func (r *ArcadeOperationReconciler) operationDestroyCommandObjects(ctx context.Context, o *arcade.ArcadeOperation) (*arcade.ArcadeOperation, *arcade.GameDestroy, error) {
	command := o.Spec.Request.DestroyCommand
	precondition, err := operations.ParsePrecondition(o.Spec.Request.Precondition)
	if err != nil || precondition.Kind != "operation" {
		return nil, nil, operationError("invalid_request")
	}
	parent := &arcade.ArcadeOperation{}
	if command == nil || command.ParentOperationRef.Namespace != nil || command.DestroyRef.Namespace != nil {
		return nil, nil, operationError("invalid_reference")
	}
	if err := r.operationReference(ctx, types.NamespacedName{Namespace: o.Namespace, Name: command.ParentOperationRef.Name}, parent, "invalid_reference"); err != nil {
		return nil, nil, err
	}
	if string(parent.UID) != command.ParentOperationRef.UID ||
		parent.Generation != precondition.Generation || parent.Spec.Action != arcade.OperationWorldDestroyPreview || parent.Status.Plan == nil || parent.Status.Child == nil || parent.Status.Child.Kind != "GameDestroy" ||
		parent.Status.Child.Name != command.DestroyRef.Name || parent.Status.Child.UID != command.DestroyRef.UID {
		return nil, nil, operationError("invalid_reference")
	}
	destroy := &arcade.GameDestroy{}
	if err := r.operationReference(ctx, types.NamespacedName{Namespace: o.Namespace, Name: command.DestroyRef.Name}, destroy, "invalid_reference"); err != nil {
		return nil, nil, err
	}
	if string(destroy.UID) != command.DestroyRef.UID ||
		!destroy.DeletionTimestamp.IsZero() || destroy.Labels[operationReceiptUIDLabel] != string(parent.UID) || destroy.Annotations[operationReceiptNameAnnotation] != parent.Name ||
		destroy.Spec.Mode != arcade.DestroyModeVerifiedBackup || parent.Status.RetainedWorld == nil || !apiequality.Semantic.DeepEqual(destroy.Spec.Target, parent.Status.RetainedWorld.Target) ||
		!apiequality.Semantic.DeepEqual(destroy.Spec.BackupRef, parent.Status.Plan.BackupRef) || !apiequality.Semantic.DeepEqual(destroy.Spec.RepositorySecretRef, parent.Status.Plan.RepositorySecretRef) {
		return nil, nil, operationError("child_changed")
	}
	return parent, destroy, nil
}
func (r *ArcadeOperationReconciler) reconcileDestroyCommand(ctx context.Context, o *arcade.ArcadeOperation) error {
	_, destroy, err := r.operationDestroyCommandObjects(ctx, o)
	if err != nil {
		return err
	}
	command := o.Spec.Request.DestroyCommand
	if o.Status.Plan.DestroyRef == nil || !apiequality.Semantic.DeepEqual(*o.Status.Plan.DestroyRef, command.DestroyRef) {
		return operationError("receipt_invalid")
	}
	if o.Status.Child == nil {
		return r.operationStatus(ctx, o, arcade.OperationPhaseRunning, func(copy *arcade.ArcadeOperation) {
			copy.Status.Child = &arcade.OperationChildReference{Kind: "GameDestroy", ExactLocalReference: command.DestroyRef, Generation: destroy.Generation}
		})
	}
	if o.Status.Child.Kind != "GameDestroy" || o.Status.Child.UID != string(destroy.UID) || o.Status.Child.Name != destroy.Name {
		return operationError("child_changed")
	}
	if destroy.Status.ObservedGeneration != destroy.Generation {
		return r.operationProgressGuidance(ctx, o, "api_unavailable")
	}
	annotations := maps.Clone(destroy.Annotations)
	if annotations == nil {
		annotations = map[string]string{}
	}
	if o.Spec.Action == arcade.OperationWorldDestroyCancel {
		if destroy.Spec.CancelRequested && destroy.Annotations[operationCancelAnnotation] == string(o.UID) {
			if destroy.Status.Phase == arcade.DestroyPhaseCancelled {
				return r.operationStatus(ctx, o, arcade.OperationPhaseSucceeded, nil)
			}
			if len(destroy.Status.DeletionJournal) > 0 || destroyTerminal(destroy.Status.Phase) {
				return operationError("too_late")
			}
			return nil
		}
		if destroyTerminal(destroy.Status.Phase) || destroy.Status.Phase == arcade.DestroyPhaseDeleting || len(destroy.Status.DeletionJournal) > 0 || destroy.Spec.CancelRequested {
			return operationError("too_late")
		}
		annotations[operationCancelAnnotation] = string(o.UID)
		return r.patchOperationObject(ctx, destroy, []operationJSONPatch{{Op: "add", Path: "/metadata/annotations", Value: annotations}, {Op: "add", Path: "/spec/cancelRequested", Value: true}})
	}
	if o.Spec.Action != arcade.OperationWorldDestroyConfirm {
		return operationError("invalid_request")
	}
	if destroy.Spec.ConfirmationChallenge == command.Challenge && destroy.Annotations[operationConfirmAnnotation] == string(o.UID) {
		if destroy.Status.Phase == arcade.DestroyPhaseFailed || destroy.Status.Phase == arcade.DestroyPhaseCancelled {
			return operationError("too_late")
		}
		return r.operationStatus(ctx, o, arcade.OperationPhaseSucceeded, nil)
	}
	if destroy.Spec.CancelRequested || destroyTerminal(destroy.Status.Phase) || destroy.Status.Phase != arcade.DestroyPhasePreview || len(destroy.Status.DeletionJournal) > 0 || destroy.Spec.ConfirmationChallenge != "" {
		return operationError("too_late")
	}
	if destroy.Status.Preview == nil || command.Challenge != destroy.Status.Preview.Challenge {
		return operationError("invalid_request")
	}
	now := r.now()
	if !now.Before(&destroy.Status.Preview.ExpiresAt) {
		return operationError("confirmation_expired")
	}
	annotations[operationConfirmAnnotation] = string(o.UID)
	return r.patchOperationObject(ctx, destroy, []operationJSONPatch{{Op: "add", Path: "/metadata/annotations", Value: annotations}, {Op: "add", Path: "/spec/confirmationChallenge", Value: command.Challenge}})
}
