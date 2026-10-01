// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"testing"

	arcadev1alpha1 "github.com/gobha-me/arcadectl/api/v1alpha1"
	platformkube "github.com/gobha-me/arcadectl/internal/platform/kube"
	"github.com/gobha-me/arcadectl/internal/restoreworker"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestWorkerPodIdentityIgnoresOnlyPostAuthorizationNetworkAnnotations(t *testing.T) {
	job := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "worker", Namespace: "test", UID: "job-uid"}}
	job.Spec.Template.Labels = map[string]string{"arcade.gobha.me/data-operation": "backup"}
	job.Spec.Template.Annotations = map[string]string{"arcade.gobha.me/artifact-id": "artifact"}
	for _, test := range []struct {
		name  string
		key   string
		match func(*batchv1.Job, *corev1.Pod) bool
	}{
		{"backup", platformkube.AnnotationBackupPodAuthorized, backupPodIdentityMatches},
		{"restore", platformkube.AnnotationRestorePodAuthorized, restorePodIdentityMatches},
	} {
		t.Run(test.name, func(t *testing.T) {
			pod := gatedBackupPod(job, "worker-pod", "pod-uid")
			if !test.match(job, pod) {
				t.Fatal("unmodified gated Pod did not match")
			}
			pod.Annotations["cni.projectcalico.org/containerID"] = "container-id"
			if test.match(job, pod) {
				t.Fatal("network annotation before authorization was accepted")
			}
			pod.Annotations[test.key] = string(pod.UID)
			pod.Annotations["cni.projectcalico.org/podIP"] = "10.0.0.1"
			pod.Annotations["cni.projectcalico.org/podIPs"] = "10.0.0.1"
			pod.Annotations["k8s.v1.cni.cncf.io/network-status"] = "[]"
			if !test.match(job, pod) {
				t.Fatal("authorized Pod with network annotations did not match")
			}
			pod.Annotations["arcade.gobha.me/foreign"] = "injected"
			if test.match(job, pod) {
				t.Fatal("foreign controller annotation was accepted")
			}
			delete(pod.Annotations, "arcade.gobha.me/foreign")
			pod.Annotations["arcade.gobha.me/artifact-id"] = "changed"
			if test.match(job, pod) {
				t.Fatal("changed artifact identity was accepted")
			}
		})
	}
}

func TestWorkerAuthorizationRejectsWrongPodUIDWithNetworkAnnotations(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		key  string
	}{
		{"backup", platformkube.AnnotationBackupPodAuthorized},
		{"restore", platformkube.AnnotationRestorePodAuthorized},
	} {
		t.Run(test.name, func(t *testing.T) {
			job := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "worker", Namespace: "test", UID: "job-uid"}}
			if test.name == "restore" {
				job.Name = platformkube.RestoreResourceName("restore-uid", restoreworker.StagePreflight)
			}
			job.Spec.Template.Labels = map[string]string{
				platformkube.LabelBackupUID:    "backup-uid",
				platformkube.LabelRestoreUID:   "restore-uid",
				platformkube.LabelRestoreStage: string(restoreworker.StagePreflight),
			}
			job.Spec.Template.Annotations = map[string]string{"arcade.gobha.me/artifact-id": "artifact"}
			pod := gatedBackupPod(job, "worker-pod", "pod-uid")
			pod.Annotations[test.key] = "wrong-pod-uid"
			pod.Annotations["cni.projectcalico.org/containerID"] = "container-id"
			pod.Annotations["cni.projectcalico.org/podIP"] = "10.0.0.1"
			pod.Annotations["cni.projectcalico.org/podIPs"] = "10.0.0.1"
			pod.Annotations["k8s.v1.cni.cncf.io/network-status"] = "[]"
			pod.Spec.SchedulingGates = nil
			kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pod).Build()
			var state backupPodState
			var err error
			if test.name == "backup" {
				reconciler := &GameBackupReconciler{Client: kubeClient, APIReader: kubeClient}
				state, err = reconciler.authorizeBackupWorkerPod(context.Background(), &arcadev1alpha1.GameBackup{
					ObjectMeta: metav1.ObjectMeta{Namespace: "test", UID: "backup-uid"},
				}, job)
			} else {
				reconciler := &GameRestoreReconciler{Client: kubeClient, APIReader: kubeClient}
				state, err = reconciler.authorizeRestoreWorkerPod(context.Background(), &arcadev1alpha1.GameRestore{
					ObjectMeta: metav1.ObjectMeta{Namespace: "test", UID: "restore-uid"},
				}, restoreworker.StagePreflight, job)
			}
			if err != nil || state != backupPodChanged {
				t.Fatalf("wrong authorization UID: state=%v err=%v, want changed", state, err)
			}
		})
	}
}
