// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"testing"
	"time"

	arcadev1alpha1 "github.com/gobha-me/arcadectl/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestRestoreVolumeIsolationRejectsAliasedBackingSource(t *testing.T) {
	t.Parallel()
	previous := arcadev1alpha1.DataPathIdentity{Name: "world", MountPath: "/factorio", ClaimRef: arcadev1alpha1.ExactLocalReference{Name: "previous-world", UID: "previous-uid"}}
	candidate := arcadev1alpha1.DataPathIdentity{Name: "world", MountPath: "/factorio", ClaimRef: arcadev1alpha1.ExactLocalReference{Name: "candidate-world", UID: "candidate-uid"}}
	source := arcadev1alpha1.DataPathIdentity{Name: "world", MountPath: "/factorio", ClaimRef: arcadev1alpha1.ExactLocalReference{Name: "backup-world", UID: "backup-uid"}}
	restoreCreated := metav1.NewTime(time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC))
	claim := func(name, uid, pvName string) *corev1.PersistentVolumeClaim {
		created := metav1.NewTime(restoreCreated.Add(-time.Hour))
		if name == "candidate-world" {
			created = metav1.NewTime(restoreCreated.Add(time.Second))
		}
		return &corev1.PersistentVolumeClaim{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "games", UID: types.UID(uid), CreationTimestamp: created},
			Spec:       corev1.PersistentVolumeClaimSpec{VolumeName: pvName},
			Status:     corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound},
		}
	}
	pv := func(name, claimName, claimUID, handle string) *corev1.PersistentVolume {
		created := metav1.NewTime(restoreCreated.Add(-time.Hour))
		if name == "pv-candidate" {
			created = metav1.NewTime(restoreCreated.Add(2 * time.Second))
		}
		return &corev1.PersistentVolume{
			ObjectMeta: metav1.ObjectMeta{Name: name, CreationTimestamp: created},
			Spec: corev1.PersistentVolumeSpec{
				ClaimRef:               &corev1.ObjectReference{Namespace: "games", Name: claimName, UID: types.UID(claimUID)},
				PersistentVolumeSource: corev1.PersistentVolumeSource{CSI: &corev1.CSIPersistentVolumeSource{Driver: "rbd.csi.ceph.com", VolumeHandle: handle}},
			},
			Status: corev1.PersistentVolumeStatus{Phase: corev1.VolumeBound},
		}
	}
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, candidateHandle   string
		wantError, candidateOld bool
	}{
		{name: "distinct CSI handles", candidateHandle: "candidate-volume"},
		{name: "alias under different PV names", candidateHandle: "previous-volume", wantError: true},
		{name: "alias backup source under different PV name", candidateHandle: "backup-volume", wantError: true},
		{name: "old retained PV cannot be adopted", candidateHandle: "old-unrelated-volume", candidateOld: true, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidatePV := pv("pv-candidate", "candidate-world", "candidate-uid", test.candidateHandle)
			if test.candidateOld {
				candidatePV.CreationTimestamp = metav1.NewTime(restoreCreated.Add(-time.Hour))
			}
			kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
				claim("previous-world", "previous-uid", "pv-previous"), claim("candidate-world", "candidate-uid", "pv-candidate"),
				claim("backup-world", "backup-uid", "pv-backup"),
				pv("pv-previous", "previous-world", "previous-uid", "previous-volume"),
				candidatePV,
				pv("pv-backup", "backup-world", "backup-uid", "backup-volume"),
			).Build()
			reconciler := &GameRestoreReconciler{Client: kubeClient, APIReader: kubeClient}
			err := reconciler.verifyRestoreVolumeIsolation(context.Background(), "games", restoreCreated, []arcadev1alpha1.DataPathIdentity{previous}, []arcadev1alpha1.DataPathIdentity{candidate}, []arcadev1alpha1.DataPathIdentity{source})
			if (err != nil) != test.wantError {
				t.Fatalf("volume isolation error = %v, wantError=%t", err, test.wantError)
			}
		})
	}
}

func TestRestoreVolumeSourceRejectsUnsupportedBackend(t *testing.T) {
	t.Parallel()
	if _, err := restoreVolumeSourceFingerprint(&corev1.PersistentVolume{}); err == nil {
		t.Fatal("unknown storage source accepted")
	}
	for _, source := range []corev1.PersistentVolumeSource{
		{HostPath: &corev1.HostPathVolumeSource{Path: "/data/one"}},
		{Local: &corev1.LocalVolumeSource{Path: "/data/two"}},
		{NFS: &corev1.NFSVolumeSource{Server: "files.example", Path: "/exports/three"}},
	} {
		if _, err := restoreVolumeSourceFingerprint(&corev1.PersistentVolume{Spec: corev1.PersistentVolumeSpec{PersistentVolumeSource: source}}); err == nil {
			t.Fatal("path-based storage source accepted without physical isolation proof")
		}
	}
}
