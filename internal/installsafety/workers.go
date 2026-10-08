// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installsafety

import (
	"strings"

	platformkube "github.com/gobha-me/arcadectl/internal/platform/kube"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func workerName(name string) bool {
	return strings.HasPrefix(name, "backup-") || strings.HasPrefix(name, "restore-") || strings.HasPrefix(name, "destroy-")
}

func workerSignals(metadata metav1.Object) bool {
	return workerName(metadata.GetName()) || workerName(metadata.GetGenerateName()) || workerMetadataSignals(metadata)
}

func workerMetadataSignals(metadata metav1.Object) bool {
	if operationOwner(metadata) {
		return true
	}
	labels := metadata.GetLabels()
	if labels[platformkube.LabelDataOperation] != "" || labels[platformkube.LabelBackupUID] != "" || labels[platformkube.LabelRestoreUID] != "" || labels[platformkube.LabelDestroyUID] != "" {
		return true
	}
	switch labels[platformkube.LabelName] {
	case "backup-worker", "restore-worker", "destroy-worker":
		return true
	}
	for key, value := range metadata.GetAnnotations() {
		if value != "" && (strings.HasPrefix(key, "arcade.gobha.me/backup-") || strings.HasPrefix(key, "arcade.gobha.me/restore-") || strings.HasPrefix(key, "arcade.gobha.me/destroy-") || key == platformkube.AnnotationWorkerPodUID) {
			return true
		}
	}
	return false
}

func mountsRetained(spec corev1.PodSpec, retained map[string]bool) bool {
	for _, volume := range spec.Volumes {
		if volume.PersistentVolumeClaim != nil && retained[volume.PersistentVolumeClaim.ClaimName] {
			return true
		}
	}
	return false
}

func validateWorkers(namespace string, s *Snapshot, removable map[types.UID]bool) error {
	retained := recordedClaims(s)
	seen := map[string]bool{}
	for i := range s.Claims.Items {
		o := &s.Claims.Items[i]
		if !namespaced(o, namespace, seen) {
			return ErrInvalid
		}
		// Neither labels nor history authorize deletion; both are conservative
		// signals for mount refusal. All claims are preserved by uninstall.
		if o.Labels[platformkube.LabelDataPolicy] == "retain" || o.Labels[platformkube.LabelName] == "game-data" || o.Labels[platformkube.LabelDataIdentity] != "" {
			retained[o.Name] = true
		}
		if gcHazard(o, removable) || retained[o.Name] && o.DeletionTimestamp != nil {
			return ErrRetention
		}
	}
	seen = map[string]bool{}
	for i := range s.Jobs.Items {
		o := &s.Jobs.Items[i]
		if !namespaced(o, namespace, seen) {
			return ErrInvalid
		}
		if workerSignals(o) || workerSignals(&o.Spec.Template) || workerName(o.Spec.Template.Spec.ServiceAccountName) || workerName(o.Spec.Template.Spec.DeprecatedServiceAccount) || mountsRetained(o.Spec.Template.Spec, retained) {
			return ErrWorker
		}
	}
	seen = map[string]bool{}
	for i := range s.Pods.Items {
		o := &s.Pods.Items[i]
		if !namespaced(o, namespace, seen) {
			return ErrInvalid
		}
		if workerSignals(o) || workerName(o.Spec.ServiceAccountName) || workerName(o.Spec.DeprecatedServiceAccount) {
			return ErrWorker
		}
		for _, owner := range o.OwnerReferences {
			if owner.APIVersion == "batch/v1" && owner.Kind == "Job" && workerName(owner.Name) {
				return ErrWorker
			}
		}
		if mountsRetained(o.Spec, retained) {
			return ErrRetention
		}
	}
	operationUIDs := map[types.UID]bool{}
	for _, o := range s.Backups.Items {
		operationUIDs[o.UID] = true
	}
	for _, o := range s.Restores.Items {
		operationUIDs[o.UID] = true
	}
	for _, o := range s.Destroys.Items {
		operationUIDs[o.UID] = true
	}
	for _, o := range s.Operations.Items {
		operationUIDs[o.UID] = true
	}
	seen = map[string]bool{}
	for i := range s.Leases.Items {
		o := &s.Leases.Items[i]
		if !namespaced(o, namespace, seen) {
			return ErrInvalid
		}
		// Operation evidence always wins, including at a reserved election
		// address. Only Lease bookkeeping can distinguish the name collision;
		// workerSignals remains unchanged for every Job and Pod.
		if strings.HasPrefix(o.Name, "data-operation-") || workerMetadataSignals(o) || workerName(o.GenerateName) || o.Labels[platformkube.LabelDataIdentity] != "" || o.Labels["arcade.gobha.me/operation-uid"] != "" || o.Spec.HolderIdentity != nil && operationUIDs[types.UID(*o.Spec.HolderIdentity)] {
			return ErrWorker
		}
		if controllerElectionAddress(o.Name) {
			if !controllerElectionBookkeeping(namespace, o) {
				return ErrWorker
			}
		} else if workerName(o.Name) {
			return ErrWorker
		}
	}
	return nil
}
