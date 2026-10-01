// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package backupauth

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	arcadev1alpha1 "github.com/gobha-me/arcadectl/api/v1alpha1"
	platformdata "github.com/gobha-me/arcadectl/internal/platform/data"
	platformkube "github.com/gobha-me/arcadectl/internal/platform/kube"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"
)

func TestRunMaterializesOnlyExactAuthorizedCredentials(t *testing.T) {
	t.Parallel()
	inputPath, outputPath, input := authorizerFixture(t)
	secret := authorizedSecret(input)
	claim := authorizedClaim(input)
	client := fake.NewSimpleClientset(secret, claim, authorizedLease(input))
	if err := Run(context.Background(), Config{InputPath: inputPath, OutputPath: outputPath, Namespace: "games", PodUID: "worker-pod-1", Client: client}); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	for key, want := range secret.Data {
		got, err := os.ReadFile(filepath.Join(outputPath, key))
		if err != nil {
			t.Fatalf("read authorized %s: %v", key, err)
		}
		if string(got) != string(want) {
			t.Fatalf("authorized %s changed", key)
		}
	}
}

func TestRunRejectsReplacementIdentityWithoutWritingCredentials(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*corev1.Secret, *corev1.PersistentVolumeClaim)
	}{
		{name: "secret UID", mutate: func(secret *corev1.Secret, _ *corev1.PersistentVolumeClaim) { secret.UID = "replacement-secret" }},
		{name: "secret revision", mutate: func(secret *corev1.Secret, _ *corev1.PersistentVolumeClaim) { secret.ResourceVersion = "43" }},
		{name: "claim UID", mutate: func(_ *corev1.Secret, claim *corev1.PersistentVolumeClaim) { claim.UID = "replacement-claim" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			inputPath, outputPath, input := authorizerFixture(t)
			secret, claim := authorizedSecret(input), authorizedClaim(input)
			test.mutate(secret, claim)
			client := fake.NewSimpleClientset(secret, claim, authorizedLease(input))
			err := Run(context.Background(), Config{InputPath: inputPath, OutputPath: outputPath, Namespace: "games", PodUID: "worker-pod-1", Client: client})
			if err == nil {
				t.Fatal("Run() accepted a replacement authority object")
			}
			entries, readErr := os.ReadDir(outputPath)
			if readErr != nil {
				t.Fatalf("read output directory: %v", readErr)
			}
			if len(entries) != 0 {
				t.Fatalf("replacement authority wrote credentials: %#v", entries)
			}
			if strings.Contains(err.Error(), "secret-key-canary") {
				t.Fatalf("error reflected credential material: %q", err)
			}
		})
	}
}

func TestRunRefusesASecondLiveWorkerPod(t *testing.T) {
	t.Parallel()
	inputPath, firstOutput, input := authorizerFixture(t)
	secondOutput := filepath.Join(t.TempDir(), "credentials")
	if err := os.Mkdir(secondOutput, 0o700); err != nil {
		t.Fatalf("mkdir second output: %v", err)
	}
	client := fake.NewSimpleClientset(authorizedSecret(input), authorizedClaim(input), authorizedLease(input))
	if err := Run(context.Background(), Config{
		InputPath: inputPath, OutputPath: firstOutput, Namespace: "games", PodUID: "worker-pod-1", Client: client,
	}); err != nil {
		t.Fatalf("first Run() error = %v", err)
	}
	err := Run(context.Background(), Config{
		InputPath: inputPath, OutputPath: secondOutput, Namespace: "games", PodUID: "worker-pod-2", Client: client,
	})
	if !errors.Is(err, ErrExecutionOwned) {
		t.Fatalf("second Run() error = %v, want ErrExecutionOwned", err)
	}
	if code := ExitCode(err); code != 12 {
		t.Fatalf("ExitCode() = %d, want 12", code)
	}
	entries, err := os.ReadDir(secondOutput)
	if err != nil {
		t.Fatalf("read second output: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("rejected worker received credentials: %#v", entries)
	}
}

func TestRunRejectsChangedExecutionLeaseWithoutWritingCredentials(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*coordinationv1.Lease)
	}{
		{name: "owner reference", mutate: func(lease *coordinationv1.Lease) {
			lease.OwnerReferences = []metav1.OwnerReference{{APIVersion: "v1", Kind: "Secret", Name: "foreign", UID: "foreign"}}
		}},
		{name: "holder", mutate: func(lease *coordinationv1.Lease) { lease.Spec.HolderIdentity = ptr.To("other-backup") }},
		{name: "backup uid", mutate: func(lease *coordinationv1.Lease) { lease.Labels[platformkube.LabelBackupUID] = "other-backup" }},
		{name: "manager", mutate: func(lease *coordinationv1.Lease) { lease.Labels[platformkube.LabelManagedBy] = "other-controller" }},
		{name: "data identity", mutate: func(lease *coordinationv1.Lease) { lease.Labels[platformkube.LabelDataIdentity] = "other-world" }},
		{name: "server", mutate: func(lease *coordinationv1.Lease) { lease.Labels[platformkube.LabelInstance] = "other-server" }},
		{name: "backup name", mutate: func(lease *coordinationv1.Lease) {
			lease.Annotations[platformkube.AnnotationBackupName] = "other-backup"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			inputPath, outputPath, input := authorizerFixture(t)
			lease := authorizedLease(input)
			test.mutate(lease)
			client := fake.NewSimpleClientset(authorizedSecret(input), authorizedClaim(input), lease)
			if err := Run(context.Background(), Config{InputPath: inputPath, OutputPath: outputPath, Namespace: "games", PodUID: "worker-pod-1", Client: client}); err == nil {
				t.Fatal("Run() accepted a changed execution Lease")
			}
			entries, err := os.ReadDir(outputPath)
			if err != nil {
				t.Fatalf("read output directory: %v", err)
			}
			if len(entries) != 0 {
				t.Fatalf("changed execution Lease wrote credentials: %#v", entries)
			}
		})
	}
}

func TestExitCodeDefaultsToAuthorityFailure(t *testing.T) {
	t.Parallel()
	if code := ExitCode(errors.New("unavailable")); code != 11 {
		t.Fatalf("ExitCode() = %d, want 11", code)
	}
}

func authorizerFixture(t *testing.T) (string, string, platformdata.BackupWorkerInput) {
	t.Helper()
	root := t.TempDir()
	inputPath := filepath.Join(root, "input.json")
	outputPath := filepath.Join(root, "credentials")
	if err := os.Mkdir(outputPath, 0o700); err != nil {
		t.Fatalf("mkdir output: %v", err)
	}
	input := platformdata.BackupWorkerInput{
		Version: platformdata.WorkerInputVersion, ArtifactID: "backup-artifact",
		OperationRef:    arcadev1alpha1.ExactLocalReference{Name: "backup", UID: "backup-uid"},
		WorkerLeaseName: platformkube.DataOperationLeaseName("factorio/factory/world"),
		RepositorySecretRef: arcadev1alpha1.ExactSecretReference{
			ExactLocalReference: arcadev1alpha1.ExactLocalReference{Name: "repository", UID: "secret-uid"}, ResourceVersion: "42",
		},
		Source: arcadev1alpha1.DataSourceSnapshot{
			GameServer: arcadev1alpha1.ExactGameServerReference{
				ExactLocalReference: arcadev1alpha1.ExactLocalReference{Name: "factory", UID: "server-uid"},
				Generation:          1, DesiredState: arcadev1alpha1.DesiredStateStopped,
			},
			Game: "factorio", ImageDigest: "sha256:" + strings.Repeat("1", 64), SettingsDigest: "sha256:" + strings.Repeat("2", 64),
			Paths: []arcadev1alpha1.DataPathIdentity{{
				Name: "world", MountPath: "/factorio", ClaimRef: arcadev1alpha1.ExactLocalReference{Name: "world", UID: "claim-uid"},
			}},
		},
	}
	contents, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("marshal input: %v", err)
	}
	if err := os.WriteFile(inputPath, contents, 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}
	return inputPath, outputPath, input
}

func authorizedSecret(input platformdata.BackupWorkerInput) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: input.RepositorySecretRef.Name, Namespace: "games", UID: types.UID(input.RepositorySecretRef.UID), ResourceVersion: input.RepositorySecretRef.ResourceVersion},
		Immutable:  ptr.To(true),
		Data: map[string][]byte{
			platformdata.RepositoryKeyRepository:      []byte("s3:http://minio/arcadectl"),
			platformdata.RepositoryKeyPassword:        []byte("repository-password-canary"),
			platformdata.RepositoryKeyAccessKeyID:     []byte("access-key"),
			platformdata.RepositoryKeySecretAccessKey: []byte("secret-key-canary"),
		},
	}
}

func authorizedClaim(input platformdata.BackupWorkerInput) *corev1.PersistentVolumeClaim {
	return &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Name: input.Source.Paths[0].ClaimRef.Name, Namespace: "games", UID: types.UID(input.Source.Paths[0].ClaimRef.UID)},
		Spec:       corev1.PersistentVolumeClaimSpec{VolumeName: "pv-world"},
		Status:     corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound},
	}
}

func authorizedLease(input platformdata.BackupWorkerInput) *coordinationv1.Lease {
	holder := input.OperationRef.UID
	return &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{
			Name: input.WorkerLeaseName, Namespace: "games",
			Labels: map[string]string{
				platformkube.LabelManagedBy:    platformkube.ManagerName,
				platformkube.LabelBackupUID:    input.OperationRef.UID,
				platformkube.LabelDataIdentity: "factorio/factory/world",
				platformkube.LabelInstance:     input.Source.GameServer.Name,
			},
			Annotations: map[string]string{platformkube.AnnotationBackupName: input.OperationRef.Name},
		},
		Spec: coordinationv1.LeaseSpec{HolderIdentity: &holder},
	}
}
