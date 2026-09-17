// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"

	arcadev1alpha1 "github.com/gobha-me/arcadectl/api/v1alpha1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var conditionOrder = []string{
	arcadev1alpha1.ConditionSpecValid,
	arcadev1alpha1.ConditionStorageReady,
	arcadev1alpha1.ConditionConfigurationReady,
	arcadev1alpha1.ConditionWorkloadReady,
	arcadev1alpha1.ConditionNetworkReady,
	arcadev1alpha1.ConditionReady,
}

type conditionProgress map[string]metav1.Condition

func newConditionProgress() conditionProgress {
	return make(conditionProgress, len(conditionOrder))
}

func (progress conditionProgress) set(conditionType string, status metav1.ConditionStatus, reason, message string) {
	progress[conditionType] = metav1.Condition{
		Type:    conditionType,
		Status:  status,
		Reason:  reason,
		Message: message,
	}
}

func (progress conditionProgress) fillBlocked(reason string) {
	for _, conditionType := range conditionOrder {
		if _, exists := progress[conditionType]; exists || conditionType == arcadev1alpha1.ConditionReady {
			continue
		}
		progress.set(conditionType, metav1.ConditionUnknown, arcadev1alpha1.ReasonBlocked,
			fmt.Sprintf("%s was not evaluated because an earlier lifecycle stage is blocked by %s", conditionType, reason))
	}
}

type reconcileFailure struct {
	conditionType string
	reason        string
	message       string
	retry         bool
}

func (failure *reconcileFailure) Error() string {
	return failure.message
}

func newReconcileFailure(conditionType, reason, message string, _ error, retry bool) *reconcileFailure {
	return &reconcileFailure{
		conditionType: conditionType,
		reason:        reason,
		message:       message,
		retry:         retry,
	}
}

func (r *GameServerReconciler) reportFailure(ctx context.Context, server *arcadev1alpha1.GameServer, progress conditionProgress, failure *reconcileFailure) error {
	progress.set(failure.conditionType, metav1.ConditionFalse, failure.reason, failure.message)
	progress.fillBlocked(failure.reason)
	readyReason := arcadev1alpha1.ReasonReconcileFailed
	if failure.reason == arcadev1alpha1.ReasonInvalidSpec || failure.reason == arcadev1alpha1.ReasonControllerMisconfigured {
		readyReason = failure.reason
	}
	if failure.reason == arcadev1alpha1.ReasonResourceCollision {
		readyReason = arcadev1alpha1.ReasonResourceCollision
	}
	progress.set(arcadev1alpha1.ConditionReady, metav1.ConditionFalse, readyReason,
		"the game server is not ready; follow the failed condition's safe operator action")
	statusErr := r.updateStatus(ctx, server, arcadev1alpha1.PhaseFailed, progress, nil)
	if !failure.retry {
		return statusErr
	}
	if statusErr != nil {
		return errors.Join(failure, statusErr)
	}
	// Return only the curated operator-safe message. The original cause is
	// discarded and must not be reflected into status, Events, or
	// controller-runtime's reconcile-error log.
	return failure
}

func (r *GameServerReconciler) updateStatus(ctx context.Context, server *arcadev1alpha1.GameServer, phase arcadev1alpha1.GameServerPhase, progress conditionProgress, endpoints []arcadev1alpha1.ObservedEndpoint) error {
	updated := server.DeepCopy()
	updated.Status.ObservedGeneration = server.Generation
	updated.Status.Phase = phase
	updated.Status.Endpoints = canonicalEndpoints(endpoints)
	updated.Status.Conditions = r.canonicalConditions(server, progress)
	if apiequality.Semantic.DeepEqual(server.Status, updated.Status) {
		return nil
	}
	if err := r.Status().Update(ctx, updated); err != nil {
		return errors.New("update GameServer status failed; inspect Kubernetes API availability")
	}
	return nil
}

func (r *GameServerReconciler) canonicalConditions(server *arcadev1alpha1.GameServer, progress conditionProgress) []metav1.Condition {
	now := metav1.Now()
	if r.Now != nil {
		now = r.Now()
	}
	conditions := make([]metav1.Condition, 0, len(conditionOrder))
	for _, conditionType := range conditionOrder {
		condition, exists := progress[conditionType]
		if !exists {
			condition = metav1.Condition{
				Type:    conditionType,
				Status:  metav1.ConditionUnknown,
				Reason:  arcadev1alpha1.ReasonBlocked,
				Message: conditionType + " was not evaluated",
			}
		}
		condition.Type = conditionType
		condition.ObservedGeneration = server.Generation
		condition.LastTransitionTime = now
		if previous := meta.FindStatusCondition(server.Status.Conditions, conditionType); previous != nil && previous.Status == condition.Status {
			condition.LastTransitionTime = previous.LastTransitionTime
		}
		conditions = append(conditions, condition)
	}
	return conditions
}

func canonicalEndpoints(source []arcadev1alpha1.ObservedEndpoint) []arcadev1alpha1.ObservedEndpoint {
	if len(source) == 0 {
		return nil
	}
	endpoints := append([]arcadev1alpha1.ObservedEndpoint(nil), source...)
	slices.SortFunc(endpoints, func(left, right arcadev1alpha1.ObservedEndpoint) int {
		if order := cmp.Compare(left.Name, right.Name); order != 0 {
			return order
		}
		if order := cmp.Compare(left.Protocol, right.Protocol); order != 0 {
			return order
		}
		if order := cmp.Compare(left.Address, right.Address); order != 0 {
			return order
		}
		return cmp.Compare(left.Port, right.Port)
	})
	return endpoints
}
