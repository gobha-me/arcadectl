// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

// Package controller reconciles Arcadectl desired state into Kubernetes
// resources without granting ordinary lifecycle operations authority to
// delete persistent data.
package controller

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"time"

	arcadev1alpha1 "github.com/gobha-me/arcadectl/api/v1alpha1"
	"github.com/gobha-me/arcadectl/internal/platform/game"
	platformkube "github.com/gobha-me/arcadectl/internal/platform/kube"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// DefinitionCatalog resolves only installed, validated game adapters.
type DefinitionCatalog interface {
	Get(id string) (game.Definition, error)
}

// GameServerReconciler reconciles a GameServer into retained storage and
// disposable runtime resources.
type GameServerReconciler struct {
	client.Client
	Scheme  *runtime.Scheme
	Catalog DefinitionCatalog
	Now     func() metav1.Time
}

// +kubebuilder:rbac:groups=arcade.gobha.me,resources=gameservers,verbs=get;list;watch,namespace=arcadectl-system
// +kubebuilder:rbac:groups=arcade.gobha.me,resources=gameservers/status,verbs=get;update;patch,namespace=arcadectl-system
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete,namespace=arcadectl-system
// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch;create;update;patch;delete,namespace=arcadectl-system
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;create;update;patch;delete,namespace=arcadectl-system
// +kubebuilder:rbac:groups="",resources=persistentvolumeclaims,verbs=get;list;watch;create;update;patch,namespace=arcadectl-system
// +kubebuilder:rbac:groups=coordination.k8s.io,resources=leases,verbs=get;list;watch;create;update;patch,namespace=arcadectl-system

// Reconcile validates all desired state before mutation, then converges
// storage before compute and networking.
func (r *GameServerReconciler) Reconcile(ctx context.Context, request ctrl.Request) (ctrl.Result, error) {
	server := &arcadev1alpha1.GameServer{}
	if err := r.Get(ctx, request.NamespacedName, server); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !server.DeletionTimestamp.IsZero() {
		progress := newConditionProgress()
		progress.set(arcadev1alpha1.ConditionSpecValid, metav1.ConditionUnknown, arcadev1alpha1.ReasonBlocked,
			"spec validation is not evaluated while the GameServer is terminating")
		progress.set(arcadev1alpha1.ConditionStorageReady, metav1.ConditionUnknown, arcadev1alpha1.ReasonBlocked,
			"retained storage is not changed while the GameServer is terminating")
		progress.set(arcadev1alpha1.ConditionConfigurationReady, metav1.ConditionFalse, arcadev1alpha1.ReasonRuntimeStopping,
			"the GameServer is terminating and disposable configuration is no longer reported ready")
		progress.set(arcadev1alpha1.ConditionWorkloadReady, metav1.ConditionFalse, arcadev1alpha1.ReasonRuntimeStopping,
			"the GameServer is terminating and its workload is no longer reported ready")
		progress.set(arcadev1alpha1.ConditionNetworkReady, metav1.ConditionFalse, arcadev1alpha1.ReasonRuntimeStopping,
			"the GameServer is terminating and player networking is no longer reported ready")
		progress.set(arcadev1alpha1.ConditionReady, metav1.ConditionFalse, arcadev1alpha1.ReasonRuntimeStopping,
			"the GameServer is terminating; retained claims are not deleted by Arcadectl")
		return ctrl.Result{}, r.updateStatus(ctx, server, arcadev1alpha1.PhaseStopping, progress, nil)
	}

	progress := newConditionProgress()
	if r.Catalog == nil {
		failure := newReconcileFailure(
			arcadev1alpha1.ConditionSpecValid,
			arcadev1alpha1.ReasonControllerMisconfigured,
			"the controller game catalog is unavailable; inspect the controller Deployment configuration",
			errors.New("game catalog is not configured"),
			true,
		)
		return ctrl.Result{}, r.reportFailure(ctx, server, progress, failure)
	}
	definition, err := r.Catalog.Get(server.Spec.Game)
	if err != nil {
		failure := newReconcileFailure(
			arcadev1alpha1.ConditionSpecValid,
			arcadev1alpha1.ReasonInvalidSpec,
			"the GameServer spec selects an unsupported game; choose an installed game adapter",
			err,
			false,
		)
		return ctrl.Result{}, r.reportFailure(ctx, server, progress, failure)
	}
	plan, err := platformkube.Build(server, definition)
	if err != nil {
		message := validationFailureMessage(err)
		failure := newReconcileFailure(
			arcadev1alpha1.ConditionSpecValid,
			arcadev1alpha1.ReasonInvalidSpec,
			message,
			err,
			false,
		)
		return ctrl.Result{}, r.reportFailure(ctx, server, progress, failure)
	}
	progress.set(arcadev1alpha1.ConditionSpecValid, metav1.ConditionTrue, arcadev1alpha1.ReasonValid,
		"the current GameServer generation passed adapter and platform validation")
	if failure := r.preflight(ctx, server, plan); failure != nil {
		return ctrl.Result{}, r.reportFailure(ctx, server, progress, failure)
	}

	for _, claim := range plan.DataClaims {
		if err := r.reconcileDataClaim(ctx, claim); err != nil {
			key := client.ObjectKeyFromObject(claim)
			failure := newReconcileFailure(
				arcadev1alpha1.ConditionStorageReady,
				arcadev1alpha1.ReasonStorageOperationFailed,
				fmt.Sprintf("PersistentVolumeClaim %s could not be reconciled; inspect storage events and the storage provisioner", key),
				err,
				true,
			)
			return ctrl.Result{}, r.reportFailure(ctx, server, progress, failure)
		}
	}
	storage, failure := r.observeStorage(ctx, plan.DataClaims)
	if failure != nil {
		return ctrl.Result{}, r.reportFailure(ctx, server, progress, failure)
	}
	progress.set(arcadev1alpha1.ConditionStorageReady, storage.status, storage.reason, storage.message)
	if server.Spec.DesiredState == arcadev1alpha1.DesiredStateStopped {
		stopping, failure := r.deleteControlledRuntime(ctx, server)
		if failure != nil {
			return ctrl.Result{}, r.reportFailure(ctx, server, progress, failure)
		}
		if stopping {
			progress.set(arcadev1alpha1.ConditionConfigurationReady, metav1.ConditionFalse, arcadev1alpha1.ReasonRuntimeStopping,
				"the disposable configuration is being removed; retained data is untouched")
			progress.set(arcadev1alpha1.ConditionWorkloadReady, metav1.ConditionFalse, arcadev1alpha1.ReasonRuntimeStopping,
				"the singleton game workload is being removed; retained data is untouched")
			progress.set(arcadev1alpha1.ConditionNetworkReady, metav1.ConditionFalse, arcadev1alpha1.ReasonRuntimeStopping,
				"player networking is being removed; retained data is untouched")
			progress.set(arcadev1alpha1.ConditionReady, metav1.ConditionFalse, arcadev1alpha1.ReasonRuntimeStopping,
				"waiting for disposable runtime resources to terminate; persistent data is retained")
			if err := r.updateStatus(ctx, server, arcadev1alpha1.PhaseStopping, progress, nil); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{RequeueAfter: time.Second}, nil
		}
		progress.set(arcadev1alpha1.ConditionConfigurationReady, metav1.ConditionFalse, arcadev1alpha1.ReasonRuntimeStopped,
			"disposable configuration is absent because the game server is stopped")
		progress.set(arcadev1alpha1.ConditionWorkloadReady, metav1.ConditionFalse, arcadev1alpha1.ReasonRuntimeStopped,
			"the game workload is absent because the game server is stopped")
		progress.set(arcadev1alpha1.ConditionNetworkReady, metav1.ConditionFalse, arcadev1alpha1.ReasonRuntimeStopped,
			"player networking is absent because the game server is stopped")
		progress.set(arcadev1alpha1.ConditionReady, metav1.ConditionFalse, arcadev1alpha1.ReasonRuntimeStopped,
			"the game server is stopped; persistent data is retained")
		return ctrl.Result{}, r.updateStatus(ctx, server, arcadev1alpha1.PhaseStopped, progress, nil)
	}

	if err := r.reconcileConfigMap(ctx, plan.Configuration); err != nil {
		key := client.ObjectKeyFromObject(plan.Configuration)
		failure := newReconcileFailure(
			arcadev1alpha1.ConditionConfigurationReady,
			arcadev1alpha1.ReasonConfigurationOperationFailed,
			fmt.Sprintf("ConfigMap %s could not be reconciled; inspect its ownership and cluster API events", key),
			err,
			true,
		)
		return ctrl.Result{}, r.reportFailure(ctx, server, progress, failure)
	}
	progress.set(arcadev1alpha1.ConditionConfigurationReady, metav1.ConditionTrue, arcadev1alpha1.ReasonConfigurationReady,
		"the current rendered game configuration is applied")

	deployment, err := r.reconcileDeployment(ctx, plan.Workload)
	if err != nil {
		key := client.ObjectKeyFromObject(plan.Workload)
		failure := newReconcileFailure(
			arcadev1alpha1.ConditionWorkloadReady,
			arcadev1alpha1.ReasonWorkloadOperationFailed,
			fmt.Sprintf("Deployment %s could not be reconciled; inspect workload events and image availability", key),
			err,
			true,
		)
		return ctrl.Result{}, r.reportFailure(ctx, server, progress, failure)
	}
	available := workloadAvailable(deployment)
	if failureMessage := terminalWorkloadFailure(deployment); failureMessage != "" {
		key := client.ObjectKeyFromObject(deployment)
		failure := newReconcileFailure(
			arcadev1alpha1.ConditionWorkloadReady,
			arcadev1alpha1.ReasonWorkloadUnavailable,
			fmt.Sprintf("Deployment %s %s", key, failureMessage),
			errors.New("Deployment reported a terminal availability condition"),
			false,
		)
		return ctrl.Result{}, r.reportFailure(ctx, server, progress, failure)
	} else if available {
		progress.set(arcadev1alpha1.ConditionWorkloadReady, metav1.ConditionTrue, arcadev1alpha1.ReasonWorkloadAvailable,
			"the current singleton game workload is observed available")
	} else {
		progress.set(arcadev1alpha1.ConditionWorkloadReady, metav1.ConditionFalse, arcadev1alpha1.ReasonWorkloadProgressing,
			"waiting for the current singleton game workload to become available")
	}
	service, err := r.reconcileService(ctx, plan.PlayerService)
	if err != nil {
		key := client.ObjectKeyFromObject(plan.PlayerService)
		failure := newReconcileFailure(
			arcadev1alpha1.ConditionNetworkReady,
			arcadev1alpha1.ReasonNetworkOperationFailed,
			fmt.Sprintf("Service %s could not be reconciled; inspect load-balancer events and provider configuration", key),
			err,
			true,
		)
		return ctrl.Result{}, r.reportFailure(ctx, server, progress, failure)
	}
	endpoints := observedEndpoints(service, plan.PlayerService)
	networkReady := len(endpoints) > 0
	if networkReady {
		progress.set(arcadev1alpha1.ConditionNetworkReady, metav1.ConditionTrue, arcadev1alpha1.ReasonPlayerEndpointReady,
			"the player Service published a certified reachable endpoint")
	} else {
		progress.set(arcadev1alpha1.ConditionNetworkReady, metav1.ConditionFalse, arcadev1alpha1.ReasonPlayerEndpointPending,
			"waiting for the player Service to publish a certified reachable endpoint")
	}
	if storage.ready && available && networkReady {
		progress.set(arcadev1alpha1.ConditionReady, metav1.ConditionTrue, arcadev1alpha1.ReasonReady,
			"the current game workload and certified player endpoint are ready")
		return ctrl.Result{}, r.updateStatus(ctx, server, arcadev1alpha1.PhaseReady, progress, endpoints)
	}
	phase := arcadev1alpha1.PhaseStarting
	readyReason := arcadev1alpha1.ReasonWorkloadPending
	readyMessage := "waiting for the current singleton workload and certified player endpoint"
	if !storage.ready {
		phase = arcadev1alpha1.PhasePending
		readyReason = arcadev1alpha1.ReasonStoragePending
		readyMessage = "waiting for retained storage to become available"
	} else if available && !networkReady {
		readyReason = arcadev1alpha1.ReasonPlayerEndpointPending
		readyMessage = "waiting for the player Service to publish a certified reachable endpoint"
	}
	progress.set(arcadev1alpha1.ConditionReady, metav1.ConditionFalse, readyReason, readyMessage)
	return ctrl.Result{}, r.updateStatus(ctx, server, phase, progress, nil)
}

func (r *GameServerReconciler) preflight(ctx context.Context, server *arcadev1alpha1.GameServer, plan platformkube.Plan) *reconcileFailure {
	for _, desired := range plan.DataClaims {
		existing := &corev1.PersistentVolumeClaim{}
		key := client.ObjectKeyFromObject(desired)
		if err := r.Get(ctx, key, existing); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return newReconcileFailure(
				arcadev1alpha1.ConditionStorageReady,
				arcadev1alpha1.ReasonStorageOperationFailed,
				fmt.Sprintf("PersistentVolumeClaim %s could not be inspected; inspect storage events and API availability", key),
				fmt.Errorf("preflight retained data claim %s: %w", key, err),
				true,
			)
		}
		if err := validateExistingDataClaim(existing, desired); err != nil {
			return collisionFailure(arcadev1alpha1.ConditionStorageReady, "PersistentVolumeClaim", key,
				"preserve its data and correct its identity or choose a different GameServer name",
				fmt.Errorf("preflight retained data claim %s: %w", key, err))
		}
	}

	wanted := metav1.OwnerReference{
		APIVersion: arcadev1alpha1.GroupVersion.String(),
		Kind:       "GameServer",
		Name:       server.Name,
		UID:        server.UID,
	}
	for _, resource := range []struct {
		object        client.Object
		kind          string
		conditionType string
		failureReason string
	}{
		{&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: server.Name + "-configuration", Namespace: server.Namespace}}, "ConfigMap", arcadev1alpha1.ConditionConfigurationReady, arcadev1alpha1.ReasonConfigurationOperationFailed},
		{&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: server.Name, Namespace: server.Namespace}}, "Deployment", arcadev1alpha1.ConditionWorkloadReady, arcadev1alpha1.ReasonWorkloadOperationFailed},
		{&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: server.Name, Namespace: server.Namespace}}, "Service", arcadev1alpha1.ConditionNetworkReady, arcadev1alpha1.ReasonNetworkOperationFailed},
	} {
		key := client.ObjectKeyFromObject(resource.object)
		if err := r.Get(ctx, key, resource.object); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return newReconcileFailure(
				resource.conditionType,
				resource.failureReason,
				fmt.Sprintf("%s %s could not be inspected; inspect cluster API availability", resource.kind, key),
				fmt.Errorf("preflight runtime resource %s: %w", key, err),
				true,
			)
		}
		if err := requireControlledBy(resource.object, wanted); err != nil {
			return collisionFailure(resource.conditionType, resource.kind, key,
				"Arcadectl will not adopt or delete it; inspect ownership and rename the GameServer or deliberately resolve the conflict",
				fmt.Errorf("preflight runtime resource %s: %w", key, err))
		}
	}
	return nil
}

func collisionFailure(conditionType, kind string, key client.ObjectKey, action string, cause error) *reconcileFailure {
	return newReconcileFailure(
		conditionType,
		arcadev1alpha1.ReasonResourceCollision,
		fmt.Sprintf("%s %s conflicts with this GameServer; %s", kind, key, action),
		cause,
		true,
	)
}

func (r *GameServerReconciler) reconcileConfigMap(ctx context.Context, desired *corev1.ConfigMap) error {
	existing := &corev1.ConfigMap{}
	key := client.ObjectKeyFromObject(desired)
	if err := r.Get(ctx, key, existing); err != nil {
		if apierrors.IsNotFound(err) {
			if err := r.Create(ctx, desired.DeepCopy()); err != nil {
				return fmt.Errorf("create game configuration %s: %w", key, err)
			}
			return nil
		}
		return fmt.Errorf("get game configuration %s: %w", key, err)
	}
	if err := requireControlledBy(existing, desired.OwnerReferences[0]); err != nil {
		return fmt.Errorf("refuse game configuration %s: %w", key, err)
	}
	if configurationMatches(existing, desired) {
		return nil
	}

	updated := existing.DeepCopy()
	updated.Labels = maps.Clone(desired.Labels)
	updated.Annotations = maps.Clone(desired.Annotations)
	updated.OwnerReferences = append([]metav1.OwnerReference(nil), desired.OwnerReferences...)
	updated.Data = maps.Clone(desired.Data)
	updated.BinaryData = maps.Clone(desired.BinaryData)
	if desired.Immutable != nil {
		updated.Immutable = new(bool)
		*updated.Immutable = *desired.Immutable
	} else {
		updated.Immutable = nil
	}
	if err := r.Update(ctx, updated); err != nil {
		return fmt.Errorf("update game configuration %s: %w", key, err)
	}
	return nil
}

func configurationMatches(existing, desired *corev1.ConfigMap) bool {
	return apiequality.Semantic.DeepEqual(existing.Labels, desired.Labels) &&
		apiequality.Semantic.DeepEqual(existing.Annotations, desired.Annotations) &&
		apiequality.Semantic.DeepEqual(existing.OwnerReferences, desired.OwnerReferences) &&
		apiequality.Semantic.DeepEqual(existing.Data, desired.Data) &&
		apiequality.Semantic.DeepEqual(existing.BinaryData, desired.BinaryData) &&
		apiequality.Semantic.DeepEqual(existing.Immutable, desired.Immutable)
}

func (r *GameServerReconciler) reconcileDataClaim(ctx context.Context, desired *corev1.PersistentVolumeClaim) error {
	existing := &corev1.PersistentVolumeClaim{}
	key := client.ObjectKeyFromObject(desired)
	if err := r.Get(ctx, key, existing); err != nil {
		if apierrors.IsNotFound(err) {
			if err := r.Create(ctx, desired.DeepCopy()); err != nil {
				return fmt.Errorf("create retained data claim %s: %w", key, err)
			}
			return nil
		}
		return fmt.Errorf("get retained data claim %s: %w", key, err)
	}

	if err := validateExistingDataClaim(existing, desired); err != nil {
		return fmt.Errorf("refuse data claim %s: %w", key, err)
	}

	existingSize := existing.Spec.Resources.Requests[corev1.ResourceStorage]
	desiredSize := desired.Spec.Resources.Requests[corev1.ResourceStorage]
	if existingSize.Cmp(desiredSize) >= 0 {
		return nil
	}
	updated := existing.DeepCopy()
	if updated.Spec.Resources.Requests == nil {
		updated.Spec.Resources.Requests = corev1.ResourceList{}
	}
	updated.Spec.Resources.Requests[corev1.ResourceStorage] = desiredSize.DeepCopy()
	if err := r.Update(ctx, updated); err != nil {
		return fmt.Errorf("expand retained data claim %s: %w", key, err)
	}
	return nil
}

type storageObservation struct {
	ready   bool
	status  metav1.ConditionStatus
	reason  string
	message string
}

func (r *GameServerReconciler) observeStorage(ctx context.Context, desiredClaims []*corev1.PersistentVolumeClaim) (storageObservation, *reconcileFailure) {
	for _, desired := range desiredClaims {
		actual := &corev1.PersistentVolumeClaim{}
		key := client.ObjectKeyFromObject(desired)
		if err := r.Get(ctx, key, actual); err != nil {
			return storageObservation{}, newReconcileFailure(
				arcadev1alpha1.ConditionStorageReady,
				arcadev1alpha1.ReasonStorageOperationFailed,
				fmt.Sprintf("PersistentVolumeClaim %s could not be observed; inspect storage events and API availability", key),
				fmt.Errorf("observe retained data claim %s: %w", key, err),
				true,
			)
		}
		if actual.Status.Phase != corev1.ClaimBound {
			if actual.Status.Phase == corev1.ClaimLost {
				return storageObservation{}, newReconcileFailure(
					arcadev1alpha1.ConditionStorageReady,
					arcadev1alpha1.ReasonStorageOperationFailed,
					fmt.Sprintf("PersistentVolumeClaim %s is lost; inspect its PersistentVolume and storage recovery procedure", key),
					errors.New("retained data claim is lost"),
					false,
				)
			}
			return storageObservation{
				status:  metav1.ConditionFalse,
				reason:  arcadev1alpha1.ReasonClaimsProvisioning,
				message: fmt.Sprintf("PersistentVolumeClaim %s is waiting to bind; inspect storage class and provisioner events", key),
			}, nil
		}
		requested := desired.Spec.Resources.Requests[corev1.ResourceStorage]
		observed := actual.Status.Capacity[corev1.ResourceStorage]
		if observed.Cmp(requested) < 0 {
			return storageObservation{
				status:  metav1.ConditionFalse,
				reason:  arcadev1alpha1.ReasonClaimExpansionPending,
				message: fmt.Sprintf("PersistentVolumeClaim %s is waiting for requested capacity; inspect storage expansion events", key),
			}, nil
		}
	}
	return storageObservation{
		ready:   true,
		status:  metav1.ConditionTrue,
		reason:  arcadev1alpha1.ReasonClaimsReady,
		message: "all retained data claims are bound at their requested capacity",
	}, nil
}

func validateExistingDataClaim(existing, desired *corev1.PersistentVolumeClaim) error {
	if len(existing.OwnerReferences) != 0 {
		return errors.New("retained claims must not have owner references")
	}
	for _, label := range []string{
		platformkube.LabelManagedBy,
		platformkube.LabelName,
		platformkube.LabelInstance,
		platformkube.LabelGame,
		platformkube.LabelDataPolicy,
		platformkube.LabelDataPath,
	} {
		if existing.Labels[label] != desired.Labels[label] {
			return fmt.Errorf("identity label %q does not match", label)
		}
	}
	if !storageClassCompatible(existing.Spec.StorageClassName, desired.Spec.StorageClassName) {
		return errors.New("storage class does not match")
	}
	if !slices.Equal(existing.Spec.AccessModes, desired.Spec.AccessModes) {
		return errors.New("access modes do not match")
	}
	return nil
}

func storageClassCompatible(existing, desired *string) bool {
	if desired == nil {
		return true
	}
	return existing != nil && *existing == *desired
}

func (r *GameServerReconciler) reconcileDeployment(ctx context.Context, desired *appsv1.Deployment) (*appsv1.Deployment, error) {
	existing := &appsv1.Deployment{}
	key := client.ObjectKeyFromObject(desired)
	if err := r.Get(ctx, key, existing); err != nil {
		if apierrors.IsNotFound(err) {
			created := desired.DeepCopy()
			if err := r.Create(ctx, created); err != nil {
				return nil, fmt.Errorf("create game workload %s: %w", key, err)
			}
			return created, nil
		}
		return nil, fmt.Errorf("get game workload %s: %w", key, err)
	}
	if err := requireControlledBy(existing, desired.OwnerReferences[0]); err != nil {
		return nil, fmt.Errorf("refuse game workload %s: %w", key, err)
	}

	updated := desired.DeepCopy()
	if err := r.Patch(ctx, updated, client.Apply, client.FieldOwner("arcadectl-controller"), client.ForceOwnership); err != nil {
		return nil, fmt.Errorf("apply game workload %s: %w", key, err)
	}
	actual := &appsv1.Deployment{}
	if err := r.Get(ctx, key, actual); err != nil {
		return nil, fmt.Errorf("read applied game workload %s: %w", key, err)
	}
	return actual, nil
}

func (r *GameServerReconciler) reconcileService(ctx context.Context, desired *corev1.Service) (*corev1.Service, error) {
	existing := &corev1.Service{}
	key := client.ObjectKeyFromObject(desired)
	if err := r.Get(ctx, key, existing); err != nil {
		if apierrors.IsNotFound(err) {
			created := desired.DeepCopy()
			if err := r.Create(ctx, created); err != nil {
				return nil, fmt.Errorf("create player service %s: %w", key, err)
			}
			return created, nil
		}
		return nil, fmt.Errorf("get player service %s: %w", key, err)
	}
	if err := requireControlledBy(existing, desired.OwnerReferences[0]); err != nil {
		return nil, fmt.Errorf("refuse player service %s: %w", key, err)
	}

	updated := desired.DeepCopy()
	if err := r.Patch(ctx, updated, client.Apply, client.FieldOwner("arcadectl-controller"), client.ForceOwnership); err != nil {
		return nil, fmt.Errorf("apply player service %s: %w", key, err)
	}
	actual := &corev1.Service{}
	if err := r.Get(ctx, key, actual); err != nil {
		return nil, fmt.Errorf("read applied player service %s: %w", key, err)
	}
	return actual, nil
}

func requireControlledBy(object metav1.Object, wanted metav1.OwnerReference) error {
	reference := metav1.GetControllerOf(object)
	if reference == nil {
		return errors.New("existing resource has no controller owner")
	}
	if reference.APIVersion != wanted.APIVersion || reference.Kind != wanted.Kind ||
		reference.Name != wanted.Name || reference.UID != wanted.UID {
		return errors.New("existing resource is controlled by a different owner")
	}
	return nil
}

func (r *GameServerReconciler) deleteControlledRuntime(ctx context.Context, server *arcadev1alpha1.GameServer) (bool, *reconcileFailure) {
	wanted := metav1.OwnerReference{
		APIVersion: arcadev1alpha1.GroupVersion.String(),
		Kind:       "GameServer",
		Name:       server.Name,
		UID:        server.UID,
	}
	resources := []struct {
		object        client.Object
		kind          string
		conditionType string
		failureReason string
	}{
		{&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: server.Name + "-configuration", Namespace: server.Namespace}}, "ConfigMap", arcadev1alpha1.ConditionConfigurationReady, arcadev1alpha1.ReasonConfigurationOperationFailed},
		{&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: server.Name, Namespace: server.Namespace}}, "Deployment", arcadev1alpha1.ConditionWorkloadReady, arcadev1alpha1.ReasonWorkloadOperationFailed},
		{&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: server.Name, Namespace: server.Namespace}}, "Service", arcadev1alpha1.ConditionNetworkReady, arcadev1alpha1.ReasonNetworkOperationFailed},
	}
	stopping := false
	for _, resource := range resources {
		key := client.ObjectKeyFromObject(resource.object)
		if err := r.Get(ctx, key, resource.object); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return false, newReconcileFailure(
				resource.conditionType,
				resource.failureReason,
				fmt.Sprintf("%s %s could not be observed while stopping; inspect cluster API availability", resource.kind, key),
				fmt.Errorf("get runtime resource %s: %w", key, err),
				true,
			)
		}
		if err := requireControlledBy(resource.object, wanted); err != nil {
			return false, collisionFailure(resource.conditionType, resource.kind, key,
				"Arcadectl will not adopt or delete it; inspect ownership and deliberately resolve the conflict",
				fmt.Errorf("refuse deleting runtime resource %s: %w", key, err))
		}
		if err := r.Delete(ctx, resource.object); err != nil && !apierrors.IsNotFound(err) {
			return false, newReconcileFailure(
				resource.conditionType,
				resource.failureReason,
				fmt.Sprintf("%s %s could not be removed while stopping; inspect cluster API events", resource.kind, key),
				fmt.Errorf("delete runtime resource %s: %w", key, err),
				true,
			)
		}
		stopping = true
	}
	return stopping, nil
}

func workloadAvailable(deployment *appsv1.Deployment) bool {
	return deployment != nil &&
		deletionNotRequested(deployment) &&
		deployment.Spec.Replicas != nil && *deployment.Spec.Replicas == 1 &&
		deployment.Status.ObservedGeneration >= deployment.Generation &&
		deployment.Status.Replicas == 1 &&
		deployment.Status.UpdatedReplicas == 1 &&
		deployment.Status.ReadyReplicas == 1 &&
		deployment.Status.AvailableReplicas == 1 &&
		deployment.Status.UnavailableReplicas == 0
}

func terminalWorkloadFailure(deployment *appsv1.Deployment) string {
	if deployment == nil || deployment.Status.ObservedGeneration < deployment.Generation {
		return ""
	}
	for _, condition := range deployment.Status.Conditions {
		if condition.Type == appsv1.DeploymentProgressing && condition.Status == corev1.ConditionFalse &&
			condition.Reason == "ProgressDeadlineExceeded" {
			return "exceeded its progress deadline; inspect Pod status, workload events, and image availability"
		}
		if condition.Type == appsv1.DeploymentReplicaFailure && condition.Status == corev1.ConditionTrue {
			return "cannot create or run its replica; inspect Pod status, workload events, quotas, and policy"
		}
	}
	return ""
}

func validationFailureMessage(err error) string {
	validationErr := &platformkube.ValidationError{}
	if !errors.As(err, &validationErr) {
		return "the GameServer plan is invalid; inspect the installed game adapter and controller configuration"
	}
	switch validationErr.Category {
	case platformkube.ValidationIdentity:
		return "the GameServer identity is invalid; correct its name, namespace, or Kubernetes identity"
	case platformkube.ValidationGame:
		return "the selected game adapter is invalid or incompatible; choose a supported installed adapter"
	case platformkube.ValidationImage:
		return "imageDigest is invalid; supply an immutable sha256 image digest"
	case platformkube.ValidationDesiredState:
		return "desiredState is invalid; choose Running or Stopped"
	case platformkube.ValidationCompute:
		return "compute is invalid; use positive requests and limits with each request no greater than its limit"
	case platformkube.ValidationStorage:
		return "storage is invalid; use a positive size and a valid storageClassName"
	case platformkube.ValidationSettings:
		return "settings are invalid; correct them to match the selected game adapter schema and rendering limits"
	default:
		return "the GameServer spec is invalid; inspect its validated fields"
	}
}

func deletionNotRequested(object metav1.Object) bool {
	return object.GetDeletionTimestamp() == nil
}

func observedEndpoints(actual, desired *corev1.Service) []arcadev1alpha1.ObservedEndpoint {
	if actual == nil || desired == nil || !deletionNotRequested(actual) {
		return nil
	}
	actualPorts := make(map[string]corev1.ServicePort, len(actual.Spec.Ports))
	for _, port := range actual.Spec.Ports {
		actualPorts[port.Name] = port
	}
	desiredPorts := append([]corev1.ServicePort(nil), desired.Spec.Ports...)
	slices.SortFunc(desiredPorts, func(left, right corev1.ServicePort) int {
		return strings.Compare(left.Name, right.Name)
	})
	if len(desiredPorts) == 0 {
		return nil
	}
	address := observedLoadBalancerAddress(actual.Status.LoadBalancer.Ingress, desiredPorts)
	if address == "" {
		return nil
	}
	endpoints := make([]arcadev1alpha1.ObservedEndpoint, 0, len(desiredPorts))
	for _, port := range desiredPorts {
		observed, exists := actualPorts[port.Name]
		if !exists || observed.Protocol != port.Protocol || observed.Port != port.Port || observed.TargetPort != port.TargetPort {
			return nil
		}
		endpoints = append(endpoints, arcadev1alpha1.ObservedEndpoint{
			Name:     port.Name,
			Protocol: string(port.Protocol),
			Address:  address,
			Port:     port.Port,
		})
	}
	return endpoints
}

func observedLoadBalancerAddress(ingresses []corev1.LoadBalancerIngress, desiredPorts []corev1.ServicePort) string {
	ips := make(map[string]struct{})
	hostnames := make(map[string]struct{})
	for _, ingress := range ingresses {
		if !ingressSupportsPorts(ingress, desiredPorts) {
			continue
		}
		if parsed, err := netip.ParseAddr(strings.TrimSpace(ingress.IP)); err == nil &&
			strings.TrimSpace(ingress.IP) == ingress.IP && parsed.IsGlobalUnicast() {
			ips[parsed.Unmap().String()] = struct{}{}
		}
		hostname := strings.ToLower(strings.TrimSpace(ingress.Hostname))
		if hostname != "" && hostname == ingress.Hostname && len(validation.IsDNS1123Subdomain(hostname)) == 0 {
			hostnames[hostname] = struct{}{}
		}
	}
	orderedIPs := slices.Sorted(maps.Keys(ips))
	if len(orderedIPs) > 0 {
		return orderedIPs[0]
	}
	orderedHostnames := slices.Sorted(maps.Keys(hostnames))
	if len(orderedHostnames) > 0 {
		return orderedHostnames[0]
	}
	return ""
}

func ingressSupportsPorts(ingress corev1.LoadBalancerIngress, desiredPorts []corev1.ServicePort) bool {
	if len(ingress.Ports) == 0 {
		return true
	}
	for _, desired := range desiredPorts {
		matches := 0
		for _, observed := range ingress.Ports {
			if observed.Port != desired.Port || observed.Protocol != desired.Protocol {
				continue
			}
			matches++
			if observed.Error != nil {
				return false
			}
		}
		if matches != 1 {
			return false
		}
	}
	return true
}

// SetupWithManager registers GameServer and owned-runtime watches. Retained
// claims are watched by identity labels because they intentionally are not
// owned by the GameServer.
func (r *GameServerReconciler) SetupWithManager(manager ctrl.Manager) error {
	if r.Client == nil || r.Scheme == nil || r.Catalog == nil {
		return errors.New("reconciler client, scheme, and catalog are required")
	}
	return ctrl.NewControllerManagedBy(manager).
		For(&arcadev1alpha1.GameServer{}).
		Owns(&corev1.ConfigMap{}).
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.Service{}).
		Watches(&corev1.PersistentVolumeClaim{}, handler.EnqueueRequestsFromMapFunc(func(_ context.Context, object client.Object) []reconcile.Request {
			if object.GetLabels()[platformkube.LabelManagedBy] != platformkube.ManagerName ||
				object.GetLabels()[platformkube.LabelDataPolicy] != "retain" {
				return nil
			}
			name := object.GetLabels()[platformkube.LabelInstance]
			if name == "" {
				return nil
			}
			return []reconcile.Request{{NamespacedName: types.NamespacedName{Namespace: object.GetNamespace(), Name: name}}}
		})).
		Complete(r)
}
