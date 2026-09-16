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
	"slices"
	"time"

	arcadev1alpha1 "github.com/gobha-me/arcadectl/api/v1alpha1"
	"github.com/gobha-me/arcadectl/internal/platform/game"
	platformkube "github.com/gobha-me/arcadectl/internal/platform/kube"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const readyCondition = "Ready"

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

// +kubebuilder:rbac:groups=arcade.gobha.me,resources=gameservers,verbs=get;list;watch
// +kubebuilder:rbac:groups=arcade.gobha.me,resources=gameservers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=persistentvolumeclaims,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=coordination.k8s.io,resources=leases,verbs=get;list;watch;create;update;patch

// Reconcile validates all desired state before mutation, then converges
// storage before compute and networking.
func (r *GameServerReconciler) Reconcile(ctx context.Context, request ctrl.Request) (ctrl.Result, error) {
	server := &arcadev1alpha1.GameServer{}
	if err := r.Get(ctx, request.NamespacedName, server); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !server.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}

	if r.Catalog == nil {
		err := errors.New("game catalog is not configured")
		return ctrl.Result{}, r.reportFailure(ctx, server, "ReconcileFailed", err, true)
	}
	definition, err := r.Catalog.Get(server.Spec.Game)
	if err != nil {
		return ctrl.Result{}, r.reportFailure(ctx, server, "InvalidSpec", err, false)
	}
	plan, err := platformkube.Build(server, definition)
	if err != nil {
		return ctrl.Result{}, r.reportFailure(ctx, server, "InvalidSpec", err, false)
	}
	if err := r.preflight(ctx, server, plan); err != nil {
		return ctrl.Result{}, r.reportFailure(ctx, server, "ReconcileFailed", err, true)
	}

	for _, claim := range plan.DataClaims {
		if err := r.reconcileDataClaim(ctx, claim); err != nil {
			return ctrl.Result{}, r.reportFailure(ctx, server, "ReconcileFailed", err, true)
		}
	}

	if server.Spec.DesiredState == arcadev1alpha1.DesiredStateStopped {
		stopping, err := r.deleteControlledRuntime(ctx, server)
		if err != nil {
			return ctrl.Result{}, r.reportFailure(ctx, server, "ReconcileFailed", err, true)
		}
		if stopping {
			if err := r.updateStatus(ctx, server, arcadev1alpha1.PhaseStopping, metav1.Condition{
				Type:    readyCondition,
				Status:  metav1.ConditionFalse,
				Reason:  "RuntimeStopping",
				Message: "waiting for game compute and player networking to terminate; persistent data is retained",
			}, nil); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{RequeueAfter: time.Second}, nil
		}
		return ctrl.Result{}, r.updateStatus(ctx, server, arcadev1alpha1.PhaseStopped, metav1.Condition{
			Type:    readyCondition,
			Status:  metav1.ConditionFalse,
			Reason:  "Stopped",
			Message: "game server is stopped; persistent data is retained",
		}, nil)
	}

	deployment, err := r.reconcileDeployment(ctx, plan.Workload)
	if err != nil {
		return ctrl.Result{}, r.reportFailure(ctx, server, "ReconcileFailed", err, true)
	}
	service, err := r.reconcileService(ctx, plan.PlayerService)
	if err != nil {
		return ctrl.Result{}, r.reportFailure(ctx, server, "ReconcileFailed", err, true)
	}

	if workloadAvailable(deployment) {
		if endpoints := observedEndpoints(service); len(endpoints) > 0 {
			return ctrl.Result{}, r.updateStatus(ctx, server, arcadev1alpha1.PhaseReady, metav1.Condition{
				Type:    readyCondition,
				Status:  metav1.ConditionTrue,
				Reason:  "RuntimeReady",
				Message: "game workload and player networking are ready",
			}, endpoints)
		}
	}

	return ctrl.Result{}, r.updateStatus(ctx, server, arcadev1alpha1.PhaseStarting, metav1.Condition{
		Type:    readyCondition,
		Status:  metav1.ConditionFalse,
		Reason:  "RuntimePending",
		Message: "waiting for the game workload and player networking",
	}, nil)
}

func (r *GameServerReconciler) preflight(ctx context.Context, server *arcadev1alpha1.GameServer, plan platformkube.Plan) error {
	for _, desired := range plan.DataClaims {
		existing := &corev1.PersistentVolumeClaim{}
		key := client.ObjectKeyFromObject(desired)
		if err := r.Get(ctx, key, existing); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return fmt.Errorf("preflight retained data claim %s: %w", key, err)
		}
		if err := validateExistingDataClaim(existing, desired); err != nil {
			return fmt.Errorf("preflight retained data claim %s: %w", key, err)
		}
	}

	wanted := metav1.OwnerReference{
		APIVersion: arcadev1alpha1.GroupVersion.String(),
		Kind:       "GameServer",
		Name:       server.Name,
		UID:        server.UID,
	}
	for _, object := range []client.Object{
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: server.Name, Namespace: server.Namespace}},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: server.Name, Namespace: server.Namespace}},
	} {
		key := client.ObjectKeyFromObject(object)
		if err := r.Get(ctx, key, object); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return fmt.Errorf("preflight runtime resource %s: %w", key, err)
		}
		if err := requireControlledBy(object, wanted); err != nil {
			return fmt.Errorf("preflight runtime resource %s: %w", key, err)
		}
	}
	return nil
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

func (r *GameServerReconciler) deleteControlledRuntime(ctx context.Context, server *arcadev1alpha1.GameServer) (bool, error) {
	wanted := metav1.OwnerReference{
		APIVersion: arcadev1alpha1.GroupVersion.String(),
		Kind:       "GameServer",
		Name:       server.Name,
		UID:        server.UID,
	}
	objects := []client.Object{
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: server.Name, Namespace: server.Namespace}},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: server.Name, Namespace: server.Namespace}},
	}
	stopping := false
	for _, object := range objects {
		key := client.ObjectKeyFromObject(object)
		if err := r.Get(ctx, key, object); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return false, fmt.Errorf("get runtime resource %s: %w", key, err)
		}
		if err := requireControlledBy(object, wanted); err != nil {
			return false, fmt.Errorf("refuse deleting runtime resource %s: %w", key, err)
		}
		if err := r.Delete(ctx, object); err != nil && !apierrors.IsNotFound(err) {
			return false, fmt.Errorf("delete runtime resource %s: %w", key, err)
		}
		stopping = true
	}
	return stopping, nil
}

func workloadAvailable(deployment *appsv1.Deployment) bool {
	desiredReplicas := int32(1)
	if deployment.Spec.Replicas != nil {
		desiredReplicas = *deployment.Spec.Replicas
	}
	return deployment.Status.AvailableReplicas >= desiredReplicas &&
		deployment.Status.UpdatedReplicas >= desiredReplicas &&
		deployment.Status.ObservedGeneration >= deployment.Generation
}

func observedEndpoints(service *corev1.Service) []arcadev1alpha1.ObservedEndpoint {
	address := ""
	for _, ingress := range service.Status.LoadBalancer.Ingress {
		if ingress.IP != "" {
			address = ingress.IP
			break
		}
		if ingress.Hostname != "" {
			address = ingress.Hostname
			break
		}
	}
	if address == "" {
		return nil
	}
	endpoints := make([]arcadev1alpha1.ObservedEndpoint, 0, len(service.Spec.Ports))
	for _, port := range service.Spec.Ports {
		endpoints = append(endpoints, arcadev1alpha1.ObservedEndpoint{
			Name:     port.Name,
			Protocol: string(port.Protocol),
			Address:  address,
			Port:     port.Port,
		})
	}
	return endpoints
}

func (r *GameServerReconciler) reportFailure(ctx context.Context, server *arcadev1alpha1.GameServer, reason string, reconcileErr error, retry bool) error {
	statusErr := r.updateStatus(ctx, server, arcadev1alpha1.PhaseFailed, metav1.Condition{
		Type:    readyCondition,
		Status:  metav1.ConditionFalse,
		Reason:  reason,
		Message: reconcileErr.Error(),
	}, nil)
	if !retry {
		return statusErr
	}
	return errors.Join(reconcileErr, statusErr)
}

func (r *GameServerReconciler) updateStatus(ctx context.Context, server *arcadev1alpha1.GameServer, phase arcadev1alpha1.GameServerPhase, condition metav1.Condition, endpoints []arcadev1alpha1.ObservedEndpoint) error {
	updated := server.DeepCopy()
	updated.Status.ObservedGeneration = server.Generation
	updated.Status.Phase = phase
	updated.Status.Endpoints = append([]arcadev1alpha1.ObservedEndpoint(nil), endpoints...)
	condition.ObservedGeneration = server.Generation
	if r.Now != nil {
		condition.LastTransitionTime = r.Now()
	} else {
		condition.LastTransitionTime = metav1.Now()
	}
	meta.SetStatusCondition(&updated.Status.Conditions, condition)
	if apiequality.Semantic.DeepEqual(server.Status, updated.Status) {
		return nil
	}
	if err := r.Status().Update(ctx, updated); err != nil {
		return fmt.Errorf("update GameServer status: %w", err)
	}
	return nil
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
