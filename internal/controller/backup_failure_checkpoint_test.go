// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	arcadev1alpha1 "github.com/gobha-me/arcadectl/api/v1alpha1"
	platformdata "github.com/gobha-me/arcadectl/internal/platform/data"
	platformkube "github.com/gobha-me/arcadectl/internal/platform/kube"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

func TestBackupVerificationFailureMessageUsesOnlyFixedCheckpoints(t *testing.T) {
	t.Parallel()
	for checkpoint, detail := range map[string]string{
		"snapshot-selection": "snapshot selection", "repository-check": "full repository check",
		"manifest": "manifest readback", "inventory": "snapshot inventory", "file": "file checksum readback",
		"source-recheck": "cold source recheck", "stats": "snapshot statistics",
	} {
		raw, err := json.Marshal(map[string]string{"version": platformdata.WorkerInputVersion, "failure": "VerificationFailed", "checkpoint": checkpoint})
		if err != nil {
			t.Fatal(err)
		}
		want := "repository-side verification failed at " + detail + "; the incomplete artifact is not usable"
		if got := backupVerificationFailureMessage(string(raw)); got != want {
			t.Fatalf("checkpoint %q = %q, want %q", checkpoint, got, want)
		}
	}
}

func TestBackupFailureCheckpointRequiresExactAuthorizedWorker(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"exact", "wrong-job", "unauthorized", "replaced-pod"} {
		t.Run(mode, func(t *testing.T) {
			reconciler, kubeClient, request := newBackupTestReconciler(t, arcadev1alpha1.DesiredStateStopped, arcadev1alpha1.RestartLeaveStopped)
			backup := getBackup(t, kubeClient, request.NamespacedName)
			job := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "worker-job", UID: "job-uid"}}
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name: "worker-pod", Namespace: backup.Namespace, UID: "pod-uid",
					Labels:          map[string]string{platformkube.LabelBackupUID: string(backup.UID)},
					Annotations:     map[string]string{platformkube.AnnotationBackupPodAuthorized: "pod-uid"},
					OwnerReferences: []metav1.OwnerReference{{APIVersion: "batch/v1", Kind: "Job", Name: job.Name, UID: job.UID, Controller: ptr.To(true)}},
				},
				Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{Name: "backup-worker", State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{
					ExitCode: 30, Message: `{"version":"arcadectl.backup-worker/v1","failure":"VerificationFailed","checkpoint":"repository-check"}`,
				}}}}},
			}
			switch mode {
			case "wrong-job":
				pod.OwnerReferences[0].UID = "other-job-uid"
			case "unauthorized":
				delete(pod.Annotations, platformkube.AnnotationBackupPodAuthorized)
			case "replaced-pod":
				pod.UID = "replacement-pod-uid"
			}
			if err := kubeClient.Create(context.Background(), pod); err != nil {
				t.Fatal(err)
			}
			reason, message := reconciler.workerFailureReason(context.Background(), backup, job)
			if mode == "exact" {
				if reason != arcadev1alpha1.ReasonVerificationFailed || !strings.Contains(message, "full repository check") {
					t.Fatalf("exact worker result = %q, %q", reason, message)
				}
			} else if reason != arcadev1alpha1.ReasonWorkerFailed || message != "" {
				t.Fatalf("untrusted worker selected a verification diagnostic: %q, %q", reason, message)
			}
		})
	}
}

func TestBackupVerificationFailureMessageRejectsUntrustedOutput(t *testing.T) {
	t.Parallel()
	const fallback = "repository-side verification failed; the incomplete artifact is not usable"
	const valid = `{"version":"arcadectl.backup-worker/v1","failure":"VerificationFailed","checkpoint":"repository-check"}`
	for _, raw := range []string{
		"", "credential-canary", strings.Repeat("credential-canary", 4096), valid + `{}`,
		strings.Replace(valid, "repository-check", "credential-canary", 1),
		strings.Replace(valid, "VerificationFailed", "credential-canary", 1),
		strings.Replace(valid, "arcadectl.backup-worker/v1", "credential-canary", 1),
		strings.TrimSuffix(valid, "}") + `,"error":"credential-canary"}`,
		`{"version":"arcadectl.backup-worker/v1","failure":"VerificationFailed"}`,
	} {
		if got := backupVerificationFailureMessage(raw); got != fallback || strings.Contains(got, "canary") {
			t.Fatalf("untrusted worker message selected non-fallback diagnostic: %q", got)
		}
	}
}
