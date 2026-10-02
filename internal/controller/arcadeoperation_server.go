// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"time"

	arcade "github.com/gobha-me/arcadectl/api/v1alpha1"
	"github.com/gobha-me/arcadectl/internal/operations"
	platformdata "github.com/gobha-me/arcadectl/internal/platform/data"
	platformkube "github.com/gobha-me/arcadectl/internal/platform/kube"
	coordinationv1 "k8s.io/api/coordination/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func (r *ArcadeOperationReconciler) reconcileOperationServer(ctx context.Context, o *arcade.ArcadeOperation) error {
	if o.Status.Plan.ServerIntent == nil {
		return operationError("receipt_invalid")
	}
	if o.Spec.Action == arcade.OperationServerCreate {
		return r.reconcileOperationCreate(ctx, o)
	}
	plan := o.Status.Plan
	if plan.Server == nil || plan.Data == nil {
		return operationError("receipt_invalid")
	}
	server := &arcade.GameServer{}
	err := r.reader().Get(ctx, types.NamespacedName{Namespace: o.Namespace, Name: plan.Server.Name}, server)
	if o.Spec.Action == arcade.OperationServerDecommission && o.Status.RetainedWorld != nil && len(o.Status.Transitions) > 0 &&
		(apierrors.IsNotFound(err) || err == nil && string(server.UID) != plan.Server.UID) {
		// Deletion of the original is complete; a later same-name object is not ours.
		return r.operationStatus(ctx, o, arcade.OperationPhaseSucceeded, nil)
	}
	if err != nil {
		if apierrors.IsNotFound(err) {
			return operationError("target_changed")
		}
		return err
	}
	if string(server.UID) != plan.Server.UID {
		return operationError("target_changed")
	}
	if !server.DeletionTimestamp.IsZero() {
		if o.Spec.Action == arcade.OperationServerDecommission && o.Status.RetainedWorld != nil && len(o.Status.Transitions) > 0 {
			return nil
		}
		return operationError("target_changed")
	}
	data, err := r.operationServerData(ctx, server)
	if err != nil {
		return err
	}
	if !sameDataSelection(data, plan.Data) {
		return operationError("target_changed")
	}
	if err := r.acquireOperationLease(ctx, o, server.Name, data.Identity); err != nil {
		return err
	}
	intent, err := operations.ServerSpec(*plan.ServerIntent)
	if err != nil {
		return operationError("receipt_invalid")
	}
	step := "Apply"
	if o.Spec.Action == arcade.OperationServerRestart || o.Spec.Action == arcade.OperationServerDecommission {
		step = "Stop"
		intent.DesiredState = arcade.DesiredStateStopped
	}
	if o.Spec.Action == arcade.OperationServerRestart && operationTransition(o, "Start") != nil {
		step = "Start"
		intent.DesiredState = arcade.DesiredStateRunning
	}
	transition := operationTransition(o, step)
	if transition == nil {
		if !operationExactServer(server, plan.Server) {
			return operationError("target_changed")
		}
		return r.journalOperationTransition(ctx, o, server, step, intent)
	}
	if err := r.applyOperationTransition(ctx, o, server, transition, intent); err != nil {
		return err
	}
	if !operationTransitionApplied(o, server, transition, intent) {
		return nil
	}
	if !operationRuntimeObserved(server, intent.DesiredState, plan.Data) {
		if server.Status.Phase == arcade.PhaseFailed || o.Status.StartedAt != nil && r.now().Time.Sub(o.Status.StartedAt.Time) > 15*time.Minute {
			return r.operationProgressGuidance(ctx, o, "api_unavailable")
		}
		return nil
	}
	if o.Spec.Action == arcade.OperationServerRestart && step == "Stop" {
		intent.DesiredState = arcade.DesiredStateRunning
		return r.journalOperationTransition(ctx, o, server, "Start", intent)
	}
	if o.Spec.Action == arcade.OperationServerDecommission {
		if o.Status.RetainedWorld == nil {
			return operationError("receipt_invalid")
		}
		uid, rv := server.UID, server.ResourceVersion
		return r.Delete(ctx, server, client.Preconditions{UID: &uid, ResourceVersion: &rv})
	}
	return r.operationStatus(ctx, o, arcade.OperationPhaseSucceeded, nil)
}

func operationTransition(o *arcade.ArcadeOperation, step string) *arcade.OperationServerTransition {
	for i := range o.Status.Transitions {
		if o.Status.Transitions[i].Step == step {
			return &o.Status.Transitions[i]
		}
	}
	return nil
}
func (r *ArcadeOperationReconciler) journalOperationTransition(ctx context.Context, o *arcade.ArcadeOperation, server *arcade.GameServer, step string, intent arcade.GameServerSpec) error {
	digest, err := operations.SpecDigest(intent)
	if err != nil {
		return operationError("receipt_invalid")
	}
	to := server.Generation
	if !operationSpecsEqual(server.Spec, intent) {
		to++
	}
	transition := arcade.OperationServerTransition{Step: step, FromGeneration: server.Generation, ToGeneration: to,
		DesiredState: intent.DesiredState, SpecDigest: digest, RequestedAt: r.now()}
	return r.operationStatus(ctx, o, arcade.OperationPhaseRunning, func(copy *arcade.ArcadeOperation) {
		copy.Status.Transitions = append(copy.Status.Transitions, transition)
	})
}
func operationTransitionApplied(o *arcade.ArcadeOperation, server *arcade.GameServer, transition *arcade.OperationServerTransition, intent arcade.GameServerSpec) bool {
	digest, err := operations.SpecDigest(server.Spec)
	return err == nil && server.Generation == transition.ToGeneration && server.Spec.DesiredState == transition.DesiredState && digest == transition.SpecDigest &&
		operationSpecsEqual(server.Spec, intent) && server.Labels[operationReceiptUIDLabel] == string(o.UID) &&
		server.Annotations[operationReceiptNameAnnotation] == o.Name && server.Annotations[operationStepAnnotation] == transition.Step &&
		server.Annotations[operationSpecDigestAnnotation] == transition.SpecDigest
}
func (r *ArcadeOperationReconciler) applyOperationTransition(ctx context.Context, o *arcade.ArcadeOperation, server *arcade.GameServer, transition *arcade.OperationServerTransition, intent arcade.GameServerSpec) error {
	want, err := operations.SpecDigest(intent)
	if err != nil || want != transition.SpecDigest || transition.DesiredState != intent.DesiredState {
		return operationError("receipt_invalid")
	}
	if operationTransitionApplied(o, server, transition, intent) {
		return nil
	}
	if server.Generation != transition.FromGeneration {
		return operationError("target_changed")
	}
	// After a completed Stop, Start can only follow that exact attributable step.
	if transition.Step == "Start" {
		stop := operationTransition(o, "Stop")
		stopped := *intent.DeepCopy()
		stopped.DesiredState = arcade.DesiredStateStopped
		if stop == nil || !operationTransitionApplied(o, server, stop, stopped) || !operationRuntimeObserved(server, arcade.DesiredStateStopped, o.Status.Plan.Data) {
			return operationError("target_changed")
		}
	} else if server.Generation != o.Status.Plan.Server.Generation || server.Spec.DesiredState != o.Status.Plan.Server.DesiredState {
		return operationError("target_changed")
	}
	labels := maps.Clone(server.Labels)
	if labels == nil {
		labels = map[string]string{}
	}
	labels[operationReceiptUIDLabel] = string(o.UID)
	annotations := maps.Clone(server.Annotations)
	if annotations == nil {
		annotations = map[string]string{}
	}
	annotations[operationReceiptNameAnnotation] = o.Name
	annotations[operationStepAnnotation] = transition.Step
	annotations[operationSpecDigestAnnotation] = transition.SpecDigest
	return r.patchOperationObject(ctx, server, []operationJSONPatch{
		{Op: "add", Path: "/metadata/labels", Value: labels}, {Op: "add", Path: "/metadata/annotations", Value: annotations}, {Op: "replace", Path: "/spec", Value: intent},
	})
}

type operationJSONPatch struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value any    `json:"value"`
}

// Explicit UID and resourceVersion tests protect both name replacement and
// concurrent intent. Markers and spec change in the same apiserver transaction.
func (r *ArcadeOperationReconciler) patchOperationObject(ctx context.Context, object client.Object, patches []operationJSONPatch) error {
	patches = append([]operationJSONPatch{{Op: "test", Path: "/metadata/uid", Value: string(object.GetUID())},
		{Op: "test", Path: "/metadata/resourceVersion", Value: object.GetResourceVersion()}}, patches...)
	encoded, err := json.Marshal(patches)
	if err != nil {
		return errors.New("encode exact operation patch failed")
	}
	return r.Patch(ctx, object, client.RawPatch(types.JSONPatchType, encoded))
}

func (r *ArcadeOperationReconciler) reconcileOperationCreate(ctx context.Context, o *arcade.ArcadeOperation) error {
	intent, err := operations.ServerSpec(*o.Status.Plan.ServerIntent)
	if err != nil {
		return operationError("receipt_invalid")
	}
	digest, err := operations.SpecDigest(intent)
	if err != nil {
		return operationError("receipt_invalid")
	}
	server := &arcade.GameServer{}
	key := types.NamespacedName{Namespace: o.Namespace, Name: o.Spec.Request.ServerName}
	err = r.reader().Get(ctx, key, server)
	if apierrors.IsNotFound(err) {
		if o.Status.Child != nil {
			return operationError("child_changed")
		}
		if o.Status.Plan.Data != nil {
			if err := r.acquireOperationLease(ctx, o, o.Spec.Request.ServerName, o.Status.Plan.Data.Identity); err != nil {
				return err
			}
		}
		server = &arcade.GameServer{ObjectMeta: metav1.ObjectMeta{Name: key.Name, Namespace: key.Namespace,
			Labels:      map[string]string{operationReceiptUIDLabel: string(o.UID)},
			Annotations: map[string]string{operationReceiptNameAnnotation: o.Name, operationStepAnnotation: "Create", operationSpecDigestAnnotation: digest}}, Spec: intent}
		// No ownerReference: removing a receipt must never remove a server/world.
		return r.Create(ctx, server)
	}
	if err != nil {
		return err
	}
	if server.UID == "" || len(server.OwnerReferences) != 0 || !server.DeletionTimestamp.IsZero() || server.Generation != 1 || server.Labels[operationReceiptUIDLabel] != string(o.UID) ||
		server.Annotations[operationReceiptNameAnnotation] != o.Name || server.Annotations[operationStepAnnotation] != "Create" || server.Annotations[operationSpecDigestAnnotation] != digest || !operationSpecsEqual(server.Spec, intent) {
		return operationError("child_changed")
	}
	if o.Status.Child == nil {
		return r.operationStatus(ctx, o, arcade.OperationPhaseRunning, func(copy *arcade.ArcadeOperation) {
			copy.Status.Child = &arcade.OperationChildReference{Kind: "GameServer", ExactLocalReference: arcade.ExactLocalReference{Name: server.Name, UID: string(server.UID)}, Generation: server.Generation}
		})
	}
	if o.Status.Child.Kind != "GameServer" || o.Status.Child.Name != server.Name || o.Status.Child.UID != string(server.UID) || o.Status.Child.Generation != server.Generation {
		return operationError("child_changed")
	}
	identity, err := platformkube.DataIdentity(server.UID)
	if err != nil {
		return operationError("receipt_invalid")
	}
	if o.Status.Plan.Data != nil {
		identity = o.Status.Plan.Data.Identity
	}
	if err := r.acquireOperationLease(ctx, o, server.Name, identity); err != nil {
		return err
	}
	data, err := r.operationServerData(ctx, server)
	if err != nil {
		var issue *operationIssue
		if errors.As(err, &issue) && issue.code == "invalid_reference" {
			if server.Status.Phase == arcade.PhaseFailed || o.Status.StartedAt != nil && r.now().Time.Sub(o.Status.StartedAt.Time) > 15*time.Minute {
				return r.operationProgressGuidance(ctx, o, "api_unavailable")
			}
			return nil
		}
		return err
	}
	if data.Identity != identity || o.Status.Plan.Data != nil && !sameDataSelection(data, o.Status.Plan.Data) {
		return operationError("target_changed")
	}
	if !operationRuntimeObserved(server, intent.DesiredState, data) {
		if server.Status.Phase == arcade.PhaseFailed || o.Status.StartedAt != nil && r.now().Time.Sub(o.Status.StartedAt.Time) > 15*time.Minute {
			return r.operationProgressGuidance(ctx, o, "api_unavailable")
		}
		return nil
	}
	return r.operationStatus(ctx, o, arcade.OperationPhaseSucceeded, nil)
}

func (r *ArcadeOperationReconciler) acquireOperationLease(ctx context.Context, o *arcade.ArcadeOperation, name, identity string) error {
	key := types.NamespacedName{Namespace: o.Namespace, Name: platformkube.DataOperationLeaseName(identity)}
	lease := &coordinationv1.Lease{}
	if err := r.reader().Get(ctx, key, lease); err != nil {
		if !apierrors.IsNotFound(err) {
			return err
		}
		now := metav1.NewMicroTime(r.now().Time)
		lease = &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Name: key.Name, Namespace: key.Namespace,
			Labels:      map[string]string{platformkube.LabelManagedBy: platformkube.ManagerName, platformkube.LabelInstance: name, platformkube.LabelDataIdentity: identity, operationReceiptUIDLabel: string(o.UID)},
			Annotations: map[string]string{operationReceiptNameAnnotation: o.Name}}, Spec: coordinationv1.LeaseSpec{HolderIdentity: ptr.To(string(o.UID)), AcquireTime: &now}}
		if err := r.Create(ctx, lease); err != nil {
			return err
		}
		return nil
	}
	if !operationLeaseMatches(lease, o, name, identity) {
		pending, err := r.operationFenceCleanupPending(ctx, lease, name, identity)
		if err != nil {
			return err
		}
		if pending {
			// Only the exact owner may release this fence. Retry without failing
			// the new receipt, and revalidate its frozen target on the next pass.
			return errors.New("exact terminal operation fence cleanup is pending")
		}
		return operationError("operation_conflict")
	}
	return nil
}

// operationFenceCleanupPending recognizes only an exact terminal owner whose
// native cleanup contract still holds this fence. It never releases or adopts
// a foreign lease; malformed and active fences remain operation conflicts.
func (r *ArcadeOperationReconciler) operationFenceCleanupPending(ctx context.Context, lease *coordinationv1.Lease, name, identity string) (bool, error) {
	if lease.UID == "" || lease.Namespace == "" || lease.Name != platformkube.DataOperationLeaseName(identity) || lease.Labels[platformkube.LabelDataIdentity] != identity {
		return false, nil
	}
	get := func(object client.Object, ownerName string) (bool, error) {
		if ownerName == "" {
			return false, nil
		}
		err := r.reader().Get(ctx, types.NamespacedName{Namespace: lease.Namespace, Name: ownerName}, object)
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		return err == nil, err
	}
	if lease.Labels[operationReceiptUIDLabel] != "" {
		owner := &arcade.ArcadeOperation{}
		found, err := get(owner, lease.Annotations[operationReceiptNameAnnotation])
		if !found || err != nil {
			return false, err
		}
		ownerName, ownerIdentity, err := operationLeaseCoordinates(owner)
		return err == nil && operationTerminal(owner.Status.Phase) && containsOperationFinalizer(owner) && ownerName == name && ownerIdentity == identity && operationLeaseMatches(lease, owner, name, identity), err
	}
	if lease.Labels[platformkube.LabelBackupUID] != "" {
		owner := &arcade.GameBackup{}
		found, err := get(owner, lease.Annotations[platformkube.AnnotationBackupName])
		if !found || err != nil {
			return false, err
		}
		return owner.Status.ObservedGeneration == owner.Generation && restoreTerminal(owner.Status.Phase) && slices.Contains(owner.Finalizers, platformkube.BackupFinalizer) &&
			platformkube.BackupOperationLeaseMatches(lease, arcade.ExactLocalReference{Name: owner.Name, UID: string(owner.UID)}, owner.Spec.Source.Name) && owner.Spec.Source.Name == name, nil
	}
	if lease.Labels[platformkube.LabelRestoreUID] != "" {
		owner := &arcade.GameRestore{}
		found, err := get(owner, lease.Annotations[platformkube.AnnotationRestoreName])
		if !found || err != nil {
			return false, err
		}
		candidate, err := platformdata.RestoreDataIdentity(owner.UID)
		return err == nil && (identity == candidate || identity == owner.Status.PreviousDataIdentity) && owner.Status.ObservedGeneration == owner.Generation && restoreTerminal(owner.Status.Phase) && slices.Contains(owner.Finalizers, platformkube.RestoreFinalizer) &&
			owner.Spec.Target.Name == name && platformkube.RestoreOperationLeaseMatches(lease, arcade.ExactLocalReference{Name: owner.Name, UID: string(owner.UID)}, name, identity), err
	}
	if lease.Labels[platformkube.LabelDestroyUID] != "" {
		owner := &arcade.GameDestroy{}
		found, err := get(owner, lease.Annotations[platformkube.AnnotationDestroyName])
		if !found || err != nil {
			return false, err
		}
		return owner.Status.ObservedGeneration == owner.Generation && destroyTerminal(owner.Status.Phase) && slices.Contains(owner.Finalizers, platformkube.DestroyFinalizer) && owner.Spec.Target.Data.Identity == identity && owner.Spec.Target.GameServer.Name == name &&
			platformkube.DestroyOperationLeaseMatches(lease, arcade.ExactLocalReference{Name: owner.Name, UID: string(owner.UID)}, name, identity), nil
	}
	return false, nil
}

func operationLeaseCoordinates(o *arcade.ArcadeOperation) (name, identity string, err error) {
	if o.Status.Plan == nil || !operationServerAction(o.Spec.Action) {
		return "", "", nil
	}
	if o.Status.Plan.Server != nil {
		name = o.Status.Plan.Server.Name
	}
	if o.Status.Plan.Data != nil {
		identity = o.Status.Plan.Data.Identity
	}
	if o.Spec.Action == arcade.OperationServerCreate {
		name = o.Spec.Request.ServerName
		if identity == "" && o.Status.Child != nil && o.Status.Child.Kind == "GameServer" {
			identity, err = platformkube.DataIdentity(types.UID(o.Status.Child.UID))
		}
	}
	return name, identity, err
}

func (r *ArcadeOperationReconciler) releaseOperationLease(ctx context.Context, o *arcade.ArcadeOperation) error {
	name, identity, err := operationLeaseCoordinates(o)
	if err != nil {
		return err
	}
	if name == "" || identity == "" {
		return nil
	}
	lease := &coordinationv1.Lease{}
	err = r.reader().Get(ctx, types.NamespacedName{Namespace: o.Namespace, Name: platformkube.DataOperationLeaseName(identity)}, lease)
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !operationLeaseMatches(lease, o, name, identity) {
		if lease.Labels[operationReceiptUIDLabel] == string(o.UID) || lease.Spec.HolderIdentity != nil && *lease.Spec.HolderIdentity == string(o.UID) {
			return errors.New("operation fence ownership changed")
		}
		return nil // A foreign fence must never be released, even after failure.
	}
	uid, rv := lease.UID, lease.ResourceVersion
	return client.IgnoreNotFound(r.Delete(ctx, lease, client.Preconditions{UID: &uid, ResourceVersion: &rv}))
}

// receiptRuntimeAllowed permits only the journaled, fully attributed server
// generation under a receipt-owned world fence. A name/state match alone is not
// authorization, and a native data-operation lease never enters this branch.
func receiptRuntimeAllowed(ctx context.Context, reader client.Reader, server *arcade.GameServer, lease *coordinationv1.Lease) bool {
	o := &arcade.ArcadeOperation{}
	if reader.Get(ctx, types.NamespacedName{Namespace: server.Namespace, Name: lease.Annotations[operationReceiptNameAnnotation]}, o) != nil ||
		string(o.UID) != lease.Labels[operationReceiptUIDLabel] || (!o.DeletionTimestamp.IsZero() && o.Status.Phase != arcade.OperationPhaseSucceeded) || (operationTerminal(o.Status.Phase) && o.Status.Phase != arcade.OperationPhaseSucceeded) || !operationServerAction(o.Spec.Action) || o.Status.Plan == nil || o.Status.Plan.ServerIntent == nil || !containsOperationFinalizer(o) {
		return false
	}
	intent, err := operations.ServerSpec(*o.Status.Plan.ServerIntent)
	if err != nil {
		return false
	}
	identity := lease.Labels[platformkube.LabelDataIdentity]
	if !operationLeaseMatches(lease, o, server.Name, identity) {
		return false
	}
	if o.Spec.Action == arcade.OperationServerCreate {
		if o.Status.Child == nil || o.Status.Child.Kind != "GameServer" || o.Status.Child.UID != string(server.UID) || o.Status.Child.Name != server.Name || o.Status.Child.Generation != server.Generation {
			return false
		}
		expected, err := platformkube.DataIdentity(server.UID)
		if err != nil {
			return false
		}
		if o.Status.Plan.Data != nil {
			expected = o.Status.Plan.Data.Identity
		}
		digest, err := operations.SpecDigest(intent)
		return err == nil && identity == expected && server.Generation == 1 && server.Labels[operationReceiptUIDLabel] == string(o.UID) &&
			server.Annotations[operationReceiptNameAnnotation] == o.Name && server.Annotations[operationStepAnnotation] == "Create" && server.Annotations[operationSpecDigestAnnotation] == digest && operationSpecsEqual(server.Spec, intent)
	}
	if o.Status.Plan.Server == nil || o.Status.Plan.Server.UID != string(server.UID) || o.Status.Plan.Server.Name != server.Name || o.Status.Plan.Data == nil || o.Status.Plan.Data.Identity != identity {
		return false
	}
	step := server.Annotations[operationStepAnnotation]
	transition := operationTransition(o, step)
	if transition == nil {
		return false
	}
	intent.DesiredState = transition.DesiredState
	return operationTransitionApplied(o, server, transition, intent)
}

func operationSpecsEqual(left, right arcade.GameServerSpec) bool {
	a, err := operations.SpecDigest(left)
	if err != nil {
		return false
	}
	b, err := operations.SpecDigest(right)
	return err == nil && a == b
}
