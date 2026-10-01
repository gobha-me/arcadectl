// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"testing"

	arcadev1alpha1 "github.com/gobha-me/arcadectl/api/v1alpha1"
	platformkube "github.com/gobha-me/arcadectl/internal/platform/kube"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestColdBackupMarkerRecordsAndInvalidatesExactWorld(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	claim := coldMarkerClaim()
	cluster := coldMarkerClient(t, claim)
	backup, disposition := coldMarkerBackup()
	backupController := &GameBackupReconciler{Client: cluster, APIReader: cluster}
	if err := backupController.markLeaveStoppedBackup(ctx, backup, disposition); err != nil {
		t.Fatalf("mark leave-stopped backup: %v", err)
	}
	got := &corev1.PersistentVolumeClaim{}
	key := client.ObjectKeyFromObject(claim)
	if err := cluster.Get(ctx, key, got); err != nil {
		t.Fatal(err)
	}
	if got.Annotations[platformkube.AnnotationColdBackupUID] != string(backup.UID) {
		t.Fatalf("cold marker = %q, want %q", got.Annotations[platformkube.AnnotationColdBackupUID], backup.UID)
	}
	server := &arcadev1alpha1.GameServer{ObjectMeta: metav1.ObjectMeta{Name: "replacement", Namespace: "games", UID: "new-server"}}
	selection := []platformkube.DataClaimPlan{{Desired: claim.DeepCopy(), RequiredUID: claim.UID}}
	serverController := &GameServerReconciler{Client: cluster, APIReader: cluster}
	if err := serverController.clearColdBackupMarkers(ctx, server, selection); err != nil {
		t.Fatalf("clear before runtime activation: %v", err)
	}
	if err := cluster.Get(ctx, key, got); err != nil {
		t.Fatal(err)
	}
	if got.Annotations[platformkube.AnnotationColdBackupUID] != "" {
		t.Fatal("prior backup remained authoritative after reactivation")
	}
}

func TestColdBackupMarkerRejectsChangedClaimAndNonColdBackup(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	backup, disposition := coldMarkerBackup()
	changed := coldMarkerClaim()
	changed.UID = "replacement-pvc"
	cluster := coldMarkerClient(t, changed)
	r := &GameBackupReconciler{Client: cluster, APIReader: cluster}
	if err := r.markLeaveStoppedBackup(ctx, backup, disposition); err == nil {
		t.Fatal("changed PVC UID accepted")
	}
	disposition.Phase = arcadev1alpha1.PhaseReady
	if err := r.markLeaveStoppedBackup(ctx, backup, disposition); err == nil {
		t.Fatal("running backup accepted as a cold marker")
	}
}

func coldMarkerClaim() *corev1.PersistentVolumeClaim {
	return &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Name: "factory-factorio-world", Namespace: "games", UID: types.UID("exact-pvc"),
			Labels: map[string]string{platformkube.LabelManagedBy: platformkube.ManagerName, platformkube.LabelInstance: "factory", platformkube.LabelGame: "factorio", platformkube.LabelDataPath: "world", platformkube.LabelDataPolicy: "retain", platformkube.LabelDataIdentity: "data-one"}},
		Spec:   corev1.PersistentVolumeClaimSpec{VolumeName: "pv-one"},
		Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound},
	}
}

func coldMarkerBackup() (*arcadev1alpha1.GameBackup, *arcadev1alpha1.RuntimeDisposition) {
	source := arcadev1alpha1.ExactGameServerReference{ExactLocalReference: arcadev1alpha1.ExactLocalReference{Name: "factory", UID: "original-server"}, Generation: 3, DesiredState: arcadev1alpha1.DesiredStateStopped}
	backup := &arcadev1alpha1.GameBackup{
		ObjectMeta: metav1.ObjectMeta{Name: "backup", Namespace: "games", UID: "exact-backup"},
		Spec:       arcadev1alpha1.GameBackupSpec{DataOperationRequest: arcadev1alpha1.DataOperationRequest{RestartPolicy: arcadev1alpha1.RestartLeaveStopped}, Source: source},
		Status: arcadev1alpha1.GameBackupStatus{DataOperationStatus: arcadev1alpha1.DataOperationStatus{
			Source: &arcadev1alpha1.DataSourceSnapshot{GameServer: source, Game: "factorio", Paths: []arcadev1alpha1.DataPathIdentity{{Name: "world", ClaimRef: arcadev1alpha1.ExactLocalReference{Name: "factory-factorio-world", UID: "exact-pvc"}}}},
			Fence:  &arcadev1alpha1.ColdDataFence{GameServer: source}, Artifact: &arcadev1alpha1.BackupArtifact{Verification: arcadev1alpha1.ArtifactVerification{Result: arcadev1alpha1.VerificationVerified}},
		}},
	}
	return backup, &arcadev1alpha1.RuntimeDisposition{GameServer: source, Phase: arcadev1alpha1.PhaseStopped}
}

func coldMarkerClient(t *testing.T, claim *corev1.PersistentVolumeClaim) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(claim).Build()
}
