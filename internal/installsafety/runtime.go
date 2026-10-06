// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installsafety

import (
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
)

// RuntimeSnapshot supplements the domain/GC observation with complete builtin
// workload templates and cluster attachment intent. Nil/partial lists cannot
// prove absence. Counts, identity and pagination are validated by cold checks;
// collection provenance must come from the sealed authoritative observer.
type RuntimeSnapshot struct {
	Deployments            *appsv1.DeploymentList
	ReplicaSets            *appsv1.ReplicaSetList
	StatefulSets           *appsv1.StatefulSetList
	DaemonSets             *appsv1.DaemonSetList
	ReplicationControllers *corev1.ReplicationControllerList
	CronJobs               *batchv1.CronJobList
	Attachments            *storagev1.VolumeAttachmentList
}

func (r *RuntimeSnapshot) DeepCopy() *RuntimeSnapshot {
	if r == nil {
		return nil
	}
	return &RuntimeSnapshot{
		Deployments: r.Deployments.DeepCopy(), ReplicaSets: r.ReplicaSets.DeepCopy(), StatefulSets: r.StatefulSets.DeepCopy(),
		DaemonSets: r.DaemonSets.DeepCopy(), ReplicationControllers: r.ReplicationControllers.DeepCopy(),
		CronJobs: r.CronJobs.DeepCopy(), Attachments: r.Attachments.DeepCopy(),
	}
}
