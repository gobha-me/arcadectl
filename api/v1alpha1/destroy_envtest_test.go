//go:build envtest

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

func TestGameDestroyAdmission(t *testing.T) {
	environment := &envtest.Environment{
		CRDDirectoryPaths:            []string{filepath.Join("..", "..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing:        true,
		DownloadBinaryAssets:         true,
		DownloadBinaryAssetsVersion:  "1.37.0",
		DownloadBinaryAssetsIndexURL: "https://raw.githubusercontent.com/kubernetes-sigs/controller-tools/1031496fc98a4f51010c3bdfdeb57b5d67bea7bd/envtest-releases.yaml",
		BinaryAssetsDirectory:        t.TempDir(),
		ControlPlaneStartTimeout:     90 * time.Second,
		ControlPlaneStopTimeout:      30 * time.Second,
	}
	configuration, err := environment.Start()
	if err != nil {
		t.Fatalf("start envtest: %v", err)
	}
	t.Cleanup(func() {
		if err := environment.Stop(); err != nil {
			t.Errorf("stop envtest: %v", err)
		}
	})
	scheme := runtime.NewScheme()
	if err := AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	kubeClient, err := client.New(configuration, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := kubeClient.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "games"}}); err != nil {
		t.Fatal(err)
	}

	valid := destroyAdmissionFixture("destroy-valid")
	if err := kubeClient.Create(ctx, valid); err != nil {
		t.Fatalf("create valid verified destroy: %v", err)
	}
	missingBackup := destroyAdmissionFixture("destroy-missing-backup")
	missingBackup.Spec.BackupRef = nil
	if err := kubeClient.Create(ctx, missingBackup); err == nil || !strings.Contains(err.Error(), "verified destroy requires") {
		t.Fatalf("missing backup error = %v", err)
	}
	unsafeWithBackup := destroyAdmissionFixture("destroy-unsafe-backup")
	unsafeWithBackup.Spec.Mode = DestroyModeUnsafeNoBackup
	unsafeWithBackup.Spec.UnsafeReason = "operator emergency override"
	if err := kubeClient.Create(ctx, unsafeWithBackup); err == nil || !strings.Contains(err.Error(), "verified destroy requires") {
		t.Fatalf("unsafe with backup error = %v", err)
	}
	unsafeMissingReason := destroyAdmissionFixture("destroy-unsafe-no-reason")
	unsafeMissingReason.Spec.Mode = DestroyModeUnsafeNoBackup
	unsafeMissingReason.Spec.BackupRef = nil
	unsafeMissingReason.Spec.RepositorySecretRef = nil
	if err := kubeClient.Create(ctx, unsafeMissingReason); err == nil || !strings.Contains(err.Error(), "verified destroy requires") {
		t.Fatalf("unsafe without reason error = %v", err)
	}
	unsafeValid := destroyAdmissionFixture("destroy-unsafe-valid")
	unsafeValid.Spec.Mode = DestroyModeUnsafeNoBackup
	unsafeValid.Spec.BackupRef = nil
	unsafeValid.Spec.RepositorySecretRef = nil
	unsafeValid.Spec.UnsafeReason = "operator emergency override"
	if err := kubeClient.Create(ctx, unsafeValid); err != nil {
		t.Fatalf("create explicit unsafe request: %v", err)
	}
	duplicateClaims := destroyAdmissionFixture("destroy-duplicate-claims")
	duplicateClaims.Spec.Target.Data.Claims = append(duplicateClaims.Spec.Target.Data.Claims, RetainedDataClaimReference{
		Path: "config", ClaimRef: duplicateClaims.Spec.Target.Data.Claims[0].ClaimRef,
	})
	if err := kubeClient.Create(ctx, duplicateClaims); err == nil || !strings.Contains(err.Error(), "unique names and UIDs") {
		t.Fatalf("duplicate claim error = %v", err)
	}

	stored := &GameDestroy{}
	key := client.ObjectKeyFromObject(valid)
	if err := kubeClient.Get(ctx, key, stored); err != nil {
		t.Fatal(err)
	}
	stored.Spec.Target.GameServer.UID = "replacement"
	if err := kubeClient.Update(ctx, stored); err == nil || !strings.Contains(err.Error(), "destroy target is immutable") {
		t.Fatalf("target mutation error = %v", err)
	}
	if err := kubeClient.Get(ctx, key, stored); err != nil {
		t.Fatal(err)
	}
	stored.Status.Phase = DestroyPhasePreview
	stored.Status.Preview = &GameDestroyPreview{
		Challenge: "challenge-1234567890", ExpiresAt: metav1.NewTime(time.Now().Add(5 * time.Minute)),
		RestoreGuidance: "Restore from the named backup before a new destroy request.",
	}
	if err := kubeClient.Status().Update(ctx, stored); err != nil {
		t.Fatalf("publish preview: %v", err)
	}
	if err := kubeClient.Get(ctx, key, stored); err != nil {
		t.Fatal(err)
	}
	stored.Status.Preview.Challenge = "forged-1234567890123"
	if err := kubeClient.Status().Update(ctx, stored); err == nil || !strings.Contains(err.Error(), "preview challenge and guidance are immutable") {
		t.Fatalf("preview mutation error = %v", err)
	}
	if err := kubeClient.Get(ctx, key, stored); err != nil {
		t.Fatal(err)
	}
	stored.Spec.ConfirmationChallenge = "incorrect-1234567890"
	if err := kubeClient.Update(ctx, stored); err == nil || !strings.Contains(err.Error(), "must echo the controller-issued") {
		t.Fatalf("incorrect confirmation echo error = %v", err)
	}
	if err := kubeClient.Get(ctx, key, stored); err != nil {
		t.Fatal(err)
	}
	stored.Spec.ConfirmationChallenge = "challenge-1234567890"
	if err := kubeClient.Update(ctx, stored); err != nil {
		t.Fatalf("echo preview challenge: %v", err)
	}
	if err := kubeClient.Get(ctx, key, stored); err != nil {
		t.Fatal(err)
	}
	stored.Spec.ConfirmationChallenge = "different-1234567890"
	if err := kubeClient.Update(ctx, stored); err == nil || !strings.Contains(err.Error(), "confirmation challenge cannot be changed") {
		t.Fatalf("confirmation replay mutation error = %v", err)
	}
	if err := kubeClient.Get(ctx, key, stored); err != nil {
		t.Fatal(err)
	}
	stored.Status.Phase = DestroyPhaseDeleting
	if err := kubeClient.Status().Update(ctx, stored); err == nil || !strings.Contains(err.Error(), "matching complete repository proof") {
		t.Fatalf("delete without verification error = %v", err)
	}
	if err := kubeClient.Get(ctx, key, stored); err != nil {
		t.Fatal(err)
	}
	stored.Status.Verification = &GameDestroyVerification{
		BackupRef: *stored.Spec.BackupRef, RepositorySecretRef: *stored.Spec.RepositorySecretRef,
		ArtifactID: "artifact-1", ManifestDigest: "sha256:" + strings.Repeat("a", 64), PathCount: 1,
		VerifiedAt: metav1.Now(), ColdAt: metav1.Now(),
	}
	stored.Status.Phase = DestroyPhaseDeleting
	if err := kubeClient.Status().Update(ctx, stored); err != nil {
		t.Fatalf("delete after exact proof: %v", err)
	}
	if err := kubeClient.Get(ctx, key, stored); err != nil {
		t.Fatal(err)
	}
	stored.Status.Phase = DestroyPhaseSucceeded
	if err := kubeClient.Status().Update(ctx, stored); err == nil || !strings.Contains(err.Error(), "every target PVC") {
		t.Fatalf("success without claim journal error = %v", err)
	}
	if err := kubeClient.Get(ctx, key, stored); err != nil {
		t.Fatal(err)
	}
	stored.Status.DeletionJournal = []GameDestroyClaimDeletion{{
		Path: "world", ClaimRef: ExactLocalReference{Name: "wrong-world", UID: "world-uid"}, RequestedAt: metav1.Now(),
	}}
	if err := kubeClient.Status().Update(ctx, stored); err == nil || !strings.Contains(err.Error(), "only exact target claims") {
		t.Fatalf("wrong claim journal error = %v", err)
	}
	if err := kubeClient.Get(ctx, key, stored); err != nil {
		t.Fatal(err)
	}
	stored.Status.DeletionJournal = []GameDestroyClaimDeletion{{
		Path: "world", ClaimRef: stored.Spec.Target.Data.Claims[0].ClaimRef, RequestedAt: metav1.Now(),
	}}
	if err := kubeClient.Status().Update(ctx, stored); err != nil {
		t.Fatalf("record write-ahead deletion: %v", err)
	}
	if err := kubeClient.Get(ctx, key, stored); err != nil {
		t.Fatal(err)
	}
	stored.Spec.CancelRequested = true
	if err := kubeClient.Update(ctx, stored); err == nil || !strings.Contains(err.Error(), "cancellation cannot be newly requested after deletion begins") {
		t.Fatalf("late cancellation error = %v", err)
	}
	if err := kubeClient.Get(ctx, key, stored); err != nil {
		t.Fatal(err)
	}
	stored.Status.Phase = DestroyPhaseFailed
	if err := kubeClient.Status().Update(ctx, stored); err == nil || !strings.Contains(err.Error(), "cannot fail terminally") {
		t.Fatalf("terminal failure after deletion begins error = %v", err)
	}
}

func destroyAdmissionFixture(name string) *GameDestroy {
	return &GameDestroy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "games"},
		Spec: GameDestroySpec{
			Target: GameDestroyTarget{
				GameServer: ExactLocalReference{Name: "original", UID: "server-uid"}, Game: "factorio",
				Data: RetainedDataReference{Identity: "world-identity", Claims: []RetainedDataClaimReference{{
					Path: "world", ClaimRef: ExactLocalReference{Name: "original-world", UID: "world-uid"},
				}}},
			},
			Mode:                DestroyModeVerifiedBackup,
			BackupRef:           &ExactLocalReference{Name: "backup", UID: "backup-uid"},
			RepositorySecretRef: &ExactSecretReference{ExactLocalReference: ExactLocalReference{Name: "repository", UID: "secret-uid"}, ResourceVersion: "1"},
		},
	}
}
