// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"errors"
	"time"

	arcade "github.com/gobha-me/arcadectl/api/v1alpha1"
	"github.com/gobha-me/arcadectl/internal/operations"
	"github.com/gobha-me/arcadectl/internal/platform/game"
	platformkube "github.com/gobha-me/arcadectl/internal/platform/kube"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	operationReceiptUIDLabel       = "arcade.gobha.me/operation-uid"
	operationReceiptNameAnnotation = "arcade.gobha.me/operation-name"
	operationStepAnnotation        = "arcade.gobha.me/operation-step"
	operationSpecDigestAnnotation  = "arcade.gobha.me/operation-spec-digest"
	operationFinalizer             = "arcade.gobha.me/operation-fence"
	operationRequeue               = time.Second
)

// ArcadeOperationReconciler translates admitted, immutable receipts into native
// lifecycle intent. It does not read Secret data or mutate workloads or PVCs.
// Admission credentials are historical audit evidence, never re-authenticated.
type ArcadeOperationReconciler struct {
	client.Client
	APIReader client.Reader
	Scheme    *runtime.Scheme
	Catalog   DefinitionCatalog
	Now       func() metav1.Time
}

// +kubebuilder:rbac:groups=arcade.gobha.me,resources=arcadeoperations,verbs=get;list;watch;update;patch,namespace=arcadectl-system
// +kubebuilder:rbac:groups=arcade.gobha.me,resources=arcadeoperations/status,verbs=get;update;patch,namespace=arcadectl-system
// +kubebuilder:rbac:groups=arcade.gobha.me,resources=gameservers,verbs=get;list;watch;create;update;patch;delete,namespace=arcadectl-system
// +kubebuilder:rbac:groups=arcade.gobha.me,resources=gamebackups;gamerestores;gamedestroys,verbs=get;list;watch;create;patch,namespace=arcadectl-system

type operationIssue struct{ code string }

func (e *operationIssue) Error() string { return "operation could not proceed: " + e.code }
func operationError(code string) error  { return &operationIssue{code: code} }

func (r *ArcadeOperationReconciler) reader() client.Reader {
	if r.APIReader != nil {
		return r.APIReader
	}
	return r.Client
}

// A transient or ambiguous GET is not definitive identity evidence. Keep the
// receipt nonterminal and retry, exposing only operationResultError's fixed
// message. Only authoritative NotFound becomes bounded missing-reference state.
func (r *ArcadeOperationReconciler) operationReference(ctx context.Context, key client.ObjectKey, object client.Object, missingCode string) error {
	if err := r.reader().Get(ctx, key, object); err != nil {
		if apierrors.IsNotFound(err) {
			return operationError(missingCode)
		}
		return err
	}
	return nil
}
func (r *ArcadeOperationReconciler) now() metav1.Time {
	if r.Now != nil {
		return r.Now()
	}
	return metav1.Now()
}
func operationTerminal(phase arcade.ArcadeOperationPhase) bool {
	return phase == arcade.OperationPhaseSucceeded || phase == arcade.OperationPhaseFailed || phase == arcade.OperationPhaseCancelled
}
func operationServerAction(action arcade.ArcadeOperationAction) bool {
	switch action {
	case arcade.OperationServerCreate, arcade.OperationServerConfigure, arcade.OperationServerStart, arcade.OperationServerStop,
		arcade.OperationServerRestart, arcade.OperationServerUpdate, arcade.OperationServerDecommission:
		return true
	}
	return false
}

func (r *ArcadeOperationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	o := &arcade.ArcadeOperation{}
	if err := r.reader().Get(ctx, req.NamespacedName, o); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !o.DeletionTimestamp.IsZero() || operationTerminal(o.Status.Phase) {
		if err := r.releaseOperationLease(ctx, o); err != nil {
			return operationRetry(), errors.New("release exact operation fence failed")
		}
		return ctrl.Result{}, r.removeOperationFinalizer(ctx, o)
	}
	if o.UID == "" || o.Spec.Version != "v1" || operations.ValidateRequest(o.Spec.Action, o.Spec.Request) != nil {
		return r.failOperation(ctx, o, "invalid_request")
	}
	if o.Status.Phase == "" {
		return operationRetry(), r.operationStatus(ctx, o, arcade.OperationPhaseAccepted, nil)
	}
	if operationServerAction(o.Spec.Action) && !containsOperationFinalizer(o) {
		copy := o.DeepCopy()
		copy.Finalizers = append(copy.Finalizers, operationFinalizer)
		if err := r.Update(ctx, copy); err != nil {
			return operationRetry(), errors.New("protect operation fence failed")
		}
		return operationRetry(), nil
	}
	if o.Status.Plan == nil {
		plan, retained, err := r.planOperation(ctx, o)
		if err != nil {
			return r.operationResultError(ctx, o, err)
		}
		return operationRetry(), r.operationStatus(ctx, o, arcade.OperationPhasePlanning, func(copy *arcade.ArcadeOperation) {
			copy.Status.Plan = plan
			copy.Status.RetainedWorld = retained
		})
	}
	var err error
	if operationServerAction(o.Spec.Action) {
		err = r.reconcileOperationServer(ctx, o)
	} else {
		err = r.reconcileOperationData(ctx, o)
	}
	if err != nil {
		return r.operationResultError(ctx, o, err)
	}
	return operationRetry(), nil
}

func operationRetry() ctrl.Result { return ctrl.Result{RequeueAfter: operationRequeue} }
func containsOperationFinalizer(o *arcade.ArcadeOperation) bool {
	for _, f := range o.Finalizers {
		if f == operationFinalizer {
			return true
		}
	}
	return false
}
func (r *ArcadeOperationReconciler) removeOperationFinalizer(ctx context.Context, o *arcade.ArcadeOperation) error {
	if !containsOperationFinalizer(o) {
		return nil
	}
	copy := o.DeepCopy()
	copy.Finalizers = nil
	for _, f := range o.Finalizers {
		if f != operationFinalizer {
			copy.Finalizers = append(copy.Finalizers, f)
		}
	}
	if err := r.Update(ctx, copy); err != nil {
		return errors.New("release operation finalizer failed")
	}
	return nil
}
func (r *ArcadeOperationReconciler) operationStatus(ctx context.Context, o *arcade.ArcadeOperation, phase arcade.ArcadeOperationPhase, modify func(*arcade.ArcadeOperation)) error {
	copy := o.DeepCopy()
	copy.Status.ObservedGeneration = o.Generation
	copy.Status.Phase = phase
	if copy.Status.StartedAt == nil {
		now := r.now()
		copy.Status.StartedAt = &now
	}
	if modify != nil {
		modify(copy)
	}
	if operationTerminal(phase) {
		now := r.now()
		copy.Status.CompletedAt = &now
		if phase != arcade.OperationPhaseFailed {
			copy.Status.Failure = nil
		}
	}
	if err := r.Status().Update(ctx, copy); err != nil {
		return errors.New("persist operation journal failed")
	}
	return nil
}

func (r *ArcadeOperationReconciler) operationProgressGuidance(ctx context.Context, o *arcade.ArcadeOperation, code string) error {
	failure := operationFailure(code)
	failure.Retryable = true
	failure.SuggestedAction = "Continue observing this receipt and inspect its exact server or native operation; admitted work remains active and waiting does not cancel it."
	if o.Status.Failure != nil && o.Status.Failure.Code == failure.Code && o.Status.Failure.Retryable {
		return nil
	}
	return r.operationStatus(ctx, o, o.Status.Phase, func(copy *arcade.ArcadeOperation) { copy.Status.Failure = failure })
}
func (r *ArcadeOperationReconciler) operationResultError(ctx context.Context, o *arcade.ArcadeOperation, err error) (ctrl.Result, error) {
	var issue *operationIssue
	if errors.As(err, &issue) {
		return r.failOperation(ctx, o, issue.code)
	}
	// API ambiguity is not a failed operation: reread exact identity and journal.
	return operationRetry(), errors.New("operation reconciliation is awaiting Kubernetes API availability")
}
func operationFailure(code string) *arcade.OperationFailure {
	message := "The operation could not safely finish."
	action := "Inspect the receipt and current exact target, then submit a new idempotency key after correction."
	switch code {
	case "invalid_request", "receipt_invalid":
		message = "The receipt does not satisfy the supported lifecycle request contract."
	case "target_changed", "child_changed":
		message = "The exact target or operation child changed; no replacement was adopted."
	case "operation_conflict":
		message = "Another exact operation owns the retained-world fence."
		action = "Wait for the existing data operation to settle, then submit a new receipt."
	case "invalid_reference":
		message = "Exact retained-world or verified-backup evidence is unavailable."
		action = "Reattach the exact retained world and create a fresh leave-stopped verified backup before destruction."
	case "secret_unavailable":
		message = "The named immutable repository Secret metadata is unavailable."
		action = "Create a valid immutable repository Secret and submit a new receipt."
	case "validation_failed", "unsupported":
		message = "The server intent does not satisfy its installed adapter contract."
	case "api_unavailable":
		message = "The recorded server intent has not reached its requested observed runtime state."
		action = "Inspect server readiness and Kubernetes availability; the applied intent may still converge and waiting does not cancel it."
	case "verification_failed":
		message = "The native operation refused repository or data verification."
	case "worker_failed":
		message = "The native operation failed; the translator did not alter world data."
	case "too_late":
		message = "Cancellation or confirmation is no longer applicable to this destroy."
	case "confirmation_expired":
		message = "The exact destroy preview challenge has expired."
		action = "Cancel the old preview and request a new preview before confirming."
	}
	return &arcade.OperationFailure{Code: code, Message: message, SuggestedAction: action}
}
func (r *ArcadeOperationReconciler) failOperation(ctx context.Context, o *arcade.ArcadeOperation, code string) (ctrl.Result, error) {
	err := r.operationStatus(ctx, o, arcade.OperationPhaseFailed, func(copy *arcade.ArcadeOperation) { copy.Status.Failure = operationFailure(code) })
	return operationRetry(), err
}

func (r *ArcadeOperationReconciler) planOperation(ctx context.Context, o *arcade.ArcadeOperation) (*arcade.OperationPlan, *arcade.OperationRetainedWorld, error) {
	request := o.Spec.Request
	plan := &arcade.OperationPlan{}
	if request.DestroyCommand != nil {
		return r.planDestroyCommand(ctx, o)
	}
	if o.Spec.Action == arcade.OperationServerCreate {
		if request.Create.Storage.Reattach != nil {
			return nil, nil, operationError("invalid_request")
		}
		intent := arcade.GameServerSpec{Game: request.Create.Game, ImageDigest: request.Image.Resolution.Digest, DesiredState: request.Create.DesiredState,
			Compute: request.Create.Compute, Storage: request.Create.Storage, Settings: runtime.RawExtension{Raw: []byte(request.Create.SettingsJSON)}}
		if err := r.validateOperationImage(intent.Game, request.Image); err != nil {
			return nil, nil, err
		}
		if request.Create.RetainedWorld != nil {
			world, err := r.retainedOperationWorld(ctx, o.Namespace, request.Create.RetainedWorld)
			if err != nil {
				return nil, nil, err
			}
			if world.Target.Game != intent.Game {
				return nil, nil, operationError("invalid_reference")
			}
			plan.Data = world.Target.Data.DeepCopy()
			intent.Storage.Reattach = plan.Data.DeepCopy()
		}
		server := &arcade.GameServer{ObjectMeta: metav1.ObjectMeta{Name: request.ServerName, Namespace: o.Namespace, UID: o.UID}, Spec: intent}
		if r.validateOperationIntent(server) != nil {
			return nil, nil, operationError("validation_failed")
		}
		frozen, err := operations.ServerIntent(intent)
		if err != nil {
			return nil, nil, operationError("validation_failed")
		}
		plan.ServerIntent = &frozen
		return plan, nil, nil
	}
	if o.Spec.Action == arcade.OperationWorldDestroyPreview && request.Destroy.RetainedWorld != nil {
		world, err := r.retainedOperationWorld(ctx, o.Namespace, request.Destroy.RetainedWorld)
		if err != nil {
			return nil, nil, err
		}
		plan.Data = world.Target.Data.DeepCopy()
		plan.Server = &arcade.ExactGameServerReference{ExactLocalReference: world.Target.GameServer, Generation: 1, DesiredState: arcade.DesiredStateStopped}
		if err := r.planOperationBackup(ctx, o, plan, request.Destroy.BackupRef); err != nil {
			return nil, nil, err
		}
		return plan, world, nil
	}
	server := &arcade.GameServer{}
	if request.Target == nil {
		return nil, nil, operationError("invalid_reference")
	}
	if err := r.operationReference(ctx, types.NamespacedName{Namespace: o.Namespace, Name: request.Target.Name}, server, "invalid_reference"); err != nil {
		return nil, nil, err
	}
	if !operationExactServer(server, request.Target) {
		return nil, nil, operationError("target_changed")
	}
	plan.Server = request.Target.DeepCopy()
	data, err := r.operationServerData(ctx, server)
	if err != nil {
		return nil, nil, err
	}
	plan.Data = data
	intent := *server.Spec.DeepCopy()
	switch o.Spec.Action {
	case arcade.OperationServerStart:
		intent.DesiredState = arcade.DesiredStateRunning
	case arcade.OperationServerStop, arcade.OperationServerDecommission:
		intent.DesiredState = arcade.DesiredStateStopped
	case arcade.OperationServerRestart:
		if server.Spec.DesiredState != arcade.DesiredStateRunning || !operationRuntimeObserved(server, arcade.DesiredStateRunning, plan.Data) {
			return nil, nil, operationError("target_changed")
		}
	case arcade.OperationServerConfigure:
		input := request.Configure
		if input.Compute != nil {
			intent.Compute = *input.Compute.DeepCopy()
		}
		if input.Storage != nil {
			if input.Storage.Reattach != nil {
				return nil, nil, operationError("invalid_request")
			}
			reattach := intent.Storage.Reattach
			intent.Storage = *input.Storage.DeepCopy()
			intent.Storage.Reattach = reattach
		}
		if input.SettingsJSON != nil {
			intent.Settings.Raw = []byte(*input.SettingsJSON)
		}
	case arcade.OperationServerUpdate:
		if err := r.validateOperationImage(server.Spec.Game, request.Image); err != nil {
			return nil, nil, err
		}
		intent.ImageDigest = request.Image.Resolution.Digest
	}
	if operationServerAction(o.Spec.Action) {
		copy := server.DeepCopy()
		copy.Spec = intent
		if r.validateOperationIntent(copy) != nil {
			return nil, nil, operationError("validation_failed")
		}
		frozen, err := operations.ServerIntent(intent)
		if err != nil {
			return nil, nil, operationError("validation_failed")
		}
		plan.ServerIntent = &frozen
	}
	var world *arcade.OperationRetainedWorld
	if o.Spec.Action == arcade.OperationServerDecommission || o.Spec.Action == arcade.OperationWorldDestroyPreview {
		target := arcade.GameDestroyTarget{GameServer: arcade.ExactLocalReference{Name: server.Name, UID: string(server.UID)}, Game: server.Spec.Game, Data: *data.DeepCopy()}
		digest, err := operations.RetainedSnapshotDigest(target)
		if err != nil {
			return nil, nil, operationError("invalid_reference")
		}
		world = &arcade.OperationRetainedWorld{Target: target, SnapshotDigest: digest}
	}
	switch o.Spec.Action {
	case arcade.OperationWorldBackup:
		secret := &metav1.PartialObjectMetadata{}
		secret.SetGroupVersionKind(corev1.SchemeGroupVersion.WithKind("Secret"))
		if err := r.operationReference(ctx, types.NamespacedName{Namespace: o.Namespace, Name: request.Backup.RepositorySecretName}, secret, "secret_unavailable"); err != nil {
			return nil, nil, err
		}
		if secret.UID == "" || secret.ResourceVersion == "" || !secret.DeletionTimestamp.IsZero() {
			return nil, nil, operationError("secret_unavailable")
		}
		plan.RepositorySecretRef = &arcade.ExactSecretReference{ExactLocalReference: arcade.ExactLocalReference{Name: secret.Name, UID: string(secret.UID)}, ResourceVersion: secret.ResourceVersion}
	case arcade.OperationWorldRestore:
		if err := r.planOperationBackup(ctx, o, plan, request.Restore.BackupRef); err != nil {
			return nil, nil, err
		}
	case arcade.OperationWorldDestroyPreview:
		if err := r.planOperationBackup(ctx, o, plan, request.Destroy.BackupRef); err != nil {
			return nil, nil, err
		}
	}
	return plan, world, nil
}

// The digest is frozen admission output, not a reason to resolve a mutable tag
// again. Its repository/tag provenance must still match the installed adapter.
func (r *ArcadeOperationReconciler) validateOperationImage(gameID string, image *arcade.OperationImageInput) error {
	if r.Catalog == nil || image == nil {
		return operationError("unsupported")
	}
	definition, err := r.Catalog.Get(gameID)
	if err != nil {
		return operationError("unsupported")
	}
	if image.Resolution.Repository != definition.ImageRepository {
		return operationError("validation_failed")
	}
	if image.Version != "" {
		tag, err := game.ResolveVersionTag(definition, image.Version)
		if err != nil || tag != image.Resolution.Tag || image.Resolution.ResolverVersion != "registry-v1" {
			return operationError("validation_failed")
		}
	} else if image.Resolution.Tag != "" || image.Resolution.ResolverVersion != "digest-v1" || image.Digest != image.Resolution.Digest {
		return operationError("validation_failed")
	}
	return nil
}

func (r *ArcadeOperationReconciler) validateOperationIntent(server *arcade.GameServer) error {
	if r.Catalog == nil {
		return operationError("unsupported")
	}
	definition, err := r.Catalog.Get(server.Spec.Game)
	if err != nil {
		return err
	}
	_, err = platformkube.Build(server, definition)
	return err
}
func operationExactServer(server *arcade.GameServer, reference *arcade.ExactGameServerReference) bool {
	return reference != nil && reference.Namespace == nil && server.DeletionTimestamp.IsZero() && string(server.UID) == reference.UID && server.Name == reference.Name && server.Generation == reference.Generation && server.Spec.DesiredState == reference.DesiredState
}
func (r *ArcadeOperationReconciler) operationServerData(ctx context.Context, server *arcade.GameServer) (*arcade.RetainedDataReference, error) {
	if r.Catalog == nil {
		return nil, operationError("unsupported")
	}
	definition, err := r.Catalog.Get(server.Spec.Game)
	if err != nil {
		return nil, operationError("unsupported")
	}
	plan, err := platformkube.Build(server, definition)
	if err != nil {
		return nil, operationError("validation_failed")
	}
	data := &arcade.RetainedDataReference{Identity: plan.DataIdentity}
	for _, claim := range plan.DataClaims {
		pvc := &corev1.PersistentVolumeClaim{}
		if err := r.operationReference(ctx, client.ObjectKeyFromObject(claim.Desired), pvc, "invalid_reference"); err != nil {
			return nil, err
		}
		if pvc.UID == "" || validateExistingDataClaim(pvc, claim) != nil || pvc.Status.Phase != corev1.ClaimBound || pvc.Spec.VolumeName == "" {
			return nil, operationError("invalid_reference")
		}
		data.Claims = append(data.Claims, arcade.RetainedDataClaimReference{Path: claim.Desired.Labels[platformkube.LabelDataPath], ClaimRef: arcade.ExactLocalReference{Name: pvc.Name, UID: string(pvc.UID)}})
	}
	if server.Status.ActiveData != nil && (!sameDataSelection(data, server.Status.ActiveData) || !sameDataSelection(data, server.Status.ObservedData)) {
		return nil, operationError("target_changed")
	}
	return data, nil
}
func operationRuntimeObserved(server *arcade.GameServer, desired arcade.DesiredState, data *arcade.RetainedDataReference) bool {
	if server.Status.ObservedGeneration != server.Generation || server.Spec.DesiredState != desired || !sameDataSelection(data, server.Status.ObservedData) {
		return false
	}
	if desired == arcade.DesiredStateStopped {
		return server.Status.Phase == arcade.PhaseStopped
	}
	ready := meta.FindStatusCondition(server.Status.Conditions, arcade.ConditionReady)
	return server.Status.Phase == arcade.PhaseReady && ready != nil && ready.Status == metav1.ConditionTrue && ready.ObservedGeneration == server.Generation
}
func (r *ArcadeOperationReconciler) retainedOperationWorld(ctx context.Context, namespace string, selector *arcade.OperationRetainedWorldSelector) (*arcade.OperationRetainedWorld, error) {
	prior := &arcade.ArcadeOperation{}
	if selector == nil || selector.DecommissionOperationRef.Namespace != nil {
		return nil, operationError("invalid_reference")
	}
	if err := r.operationReference(ctx, types.NamespacedName{Namespace: namespace, Name: selector.DecommissionOperationRef.Name}, prior, "invalid_reference"); err != nil {
		return nil, err
	}
	if string(prior.UID) != selector.DecommissionOperationRef.UID || prior.Spec.Action != arcade.OperationServerDecommission || prior.Status.Phase != arcade.OperationPhaseSucceeded || prior.Status.RetainedWorld == nil {
		return nil, operationError("invalid_reference")
	}
	digest, err := operations.RetainedSnapshotDigest(prior.Status.RetainedWorld.Target)
	if err != nil || digest != selector.SnapshotDigest || digest != prior.Status.RetainedWorld.SnapshotDigest {
		return nil, operationError("invalid_reference")
	}
	return prior.Status.RetainedWorld.DeepCopy(), nil
}

func (r *ArcadeOperationReconciler) SetupWithManager(manager ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(manager).For(&arcade.ArcadeOperation{}).Complete(r)
}

// Keep this identity check common to server fencing and terminal cleanup.
func operationLeaseMatches(lease *coordinationv1.Lease, o *arcade.ArcadeOperation, serverName, identity string) bool {
	return lease != nil && identity != "" && lease.Name == platformkube.DataOperationLeaseName(identity) && lease.Namespace == o.Namespace &&
		len(lease.OwnerReferences) == 0 && lease.Spec.HolderIdentity != nil && *lease.Spec.HolderIdentity == string(o.UID) &&
		lease.Labels[platformkube.LabelManagedBy] == platformkube.ManagerName && lease.Labels[platformkube.LabelInstance] == serverName &&
		lease.Labels[platformkube.LabelDataIdentity] == identity && lease.Labels[operationReceiptUIDLabel] == string(o.UID) && lease.Annotations[operationReceiptNameAnnotation] == o.Name
}
