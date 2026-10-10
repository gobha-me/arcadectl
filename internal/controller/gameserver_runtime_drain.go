// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"errors"
	"fmt"

	arcade "github.com/gobha-me/arcadectl/api/v1alpha1"
	platformkube "github.com/gobha-me/arcadectl/internal/platform/kube"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var errRuntimeDraining = errors.New("original game runtime is still draining")

func (r *GameServerReconciler) runtimeReader() client.Reader {
	if r.APIReader != nil {
		return r.APIReader
	}
	return r.Client
}

func runtimeDrainFailure(err error) *reconcileFailure {
	return newReconcileFailure(arcade.ConditionWorkloadReady, arcade.ReasonWorkloadOperationFailed,
		"runtime drain cannot be verified; inspect namespace API availability before starting or reporting stopped", err, true)
}

// Recreate protects revisions within a Deployment, not Pods surviving deletion
// of that Deployment. Never create its replacement until the original writers
// are absent. Reads bypass the cache so cached absence is not drain evidence.
func (r *GameServerReconciler) runtimeReplacementDraining(ctx context.Context, server *arcade.GameServer, desired *appsv1.Deployment) (bool, error) {
	existing := &appsv1.Deployment{}
	if err := r.runtimeReader().Get(ctx, client.ObjectKeyFromObject(desired), existing); err != nil {
		if !apierrors.IsNotFound(err) {
			return false, fmt.Errorf("observe original game Deployment: %w", err)
		}
		return r.runtimePodsRemain(ctx, server, desired.Spec.Template.Spec.Volumes)
	}
	if err := requireControlledBy(existing, desired.OwnerReferences[0]); err != nil {
		return false, err
	}
	return !existing.DeletionTimestamp.IsZero(), nil
}

// Labels and claim names here are conservative blocking evidence, never
// authority to delete/adopt a Pod. Terminal or terminating Pods are not skipped:
// API phase alone cannot prove their mounts have been released. Readonly backup
// workers may remain as audit evidence without preventing normal lifecycle.
func (r *GameServerReconciler) runtimePodsRemain(ctx context.Context, server *arcade.GameServer, volumes []corev1.Volume) (bool, error) {
	claims := make(map[string]bool)
	identities := make(map[string]bool)
	if identity, err := platformkube.DataIdentity(server.UID); err == nil {
		identities[identity] = true
	}
	for _, selection := range []*arcade.RetainedDataReference{server.Status.ActiveData, server.Status.ObservedData, server.Spec.Storage.Reattach} {
		if selection != nil {
			identities[selection.Identity] = true
			for _, claim := range selection.Claims {
				claims[claim.ClaimRef.Name] = true
			}
		}
	}
	for _, volume := range volumes {
		if volume.PersistentVolumeClaim != nil {
			claims[volume.PersistentVolumeClaim.ClaimName] = true
		}
	}
	// Stop must work even with an invalid spec or unavailable adapter. Durable
	// claim labels recover the original claim names without rebuilding that spec.
	retained := &corev1.PersistentVolumeClaimList{}
	if err := r.runtimeReader().List(ctx, retained, client.InNamespace(server.Namespace), client.MatchingLabels{
		platformkube.LabelManagedBy: platformkube.ManagerName,
		platformkube.LabelInstance:  server.Name, platformkube.LabelDataPolicy: "retain",
	}); err != nil {
		return false, fmt.Errorf("observe original retained claims while draining: %w", err)
	}
	for _, claim := range retained.Items {
		if claim.Labels[platformkube.LabelDataIdentity] != "" && identities[claim.Labels[platformkube.LabelDataIdentity]] {
			claims[claim.Name] = true
		}
	}
	if retained.Continue != "" || (retained.RemainingItemCount != nil && *retained.RemainingItemCount != 0) {
		return false, errors.New("retained claim drain observation was incomplete")
	}
	// A surviving old ReplicaSet can recreate a writer even in a moment with
	// zero Pods. Foreground deletion normally drains these producers too, but
	// older background deletions must not bypass the same safety boundary.
	replicaSets := &appsv1.ReplicaSetList{}
	if err := r.runtimeReader().List(ctx, replicaSets, client.InNamespace(server.Namespace)); err != nil {
		return false, fmt.Errorf("observe namespace ReplicaSets while draining: %w", err)
	}
	if replicaSets.Continue != "" || (replicaSets.RemainingItemCount != nil && *replicaSets.RemainingItemCount != 0) {
		return false, errors.New("ReplicaSet drain observation was incomplete")
	}
	for _, replicaSet := range replicaSets.Items {
		if runtimePodBlocksDrain(replicaSet.Spec.Template.Labels, replicaSet.Spec.Template.Spec, server.Name, claims) {
			return true, nil
		}
	}
	pods := &corev1.PodList{}
	if err := r.runtimeReader().List(ctx, pods, client.InNamespace(server.Namespace)); err != nil {
		return false, fmt.Errorf("observe namespace Pods while draining: %w", err)
	}
	if pods.Continue != "" || (pods.RemainingItemCount != nil && *pods.RemainingItemCount != 0) {
		return false, errors.New("Pod drain observation was incomplete")
	}
	for _, pod := range pods.Items {
		if runtimePodBlocksDrain(pod.Labels, pod.Spec, server.Name, claims) {
			return true, nil
		}
	}
	return false, nil
}

func runtimePodBlocksDrain(labels map[string]string, spec corev1.PodSpec, name string, claims map[string]bool) bool {
	if labels[platformkube.LabelManagedBy] == platformkube.ManagerName &&
		labels[platformkube.LabelName] == "game-server" && labels[platformkube.LabelInstance] == name {
		return true
	}
	for _, volume := range spec.Volumes {
		if volume.PersistentVolumeClaim != nil && claims[volume.PersistentVolumeClaim.ClaimName] && !runtimeVolumeReadOnly(spec, volume) {
			return true
		}
	}
	return false
}

func runtimeVolumeReadOnly(spec corev1.PodSpec, volume corev1.Volume) bool {
	if !volume.PersistentVolumeClaim.ReadOnly {
		return false
	}
	readonly := func(mounts []corev1.VolumeMount, devices []corev1.VolumeDevice) bool {
		for _, device := range devices {
			if device.Name == volume.Name {
				return false
			}
		}
		for _, mount := range mounts {
			if mount.Name == volume.Name && !mount.ReadOnly {
				return false
			}
		}
		return true
	}
	for _, container := range spec.Containers {
		if !readonly(container.VolumeMounts, container.VolumeDevices) {
			return false
		}
	}
	for _, container := range spec.InitContainers {
		if !readonly(container.VolumeMounts, container.VolumeDevices) {
			return false
		}
	}
	for _, container := range spec.EphemeralContainers {
		if !readonly(container.VolumeMounts, container.VolumeDevices) {
			return false
		}
	}
	return true
}
