// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package kube

import (
	"strings"
	"testing"

	arcadev1alpha1 "github.com/gobha-me/arcadectl/api/v1alpha1"
	"github.com/gobha-me/arcadectl/internal/platform/game"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestBuildBackupResourcesIsPinnedReadOnlyAndLeastPrivilege(t *testing.T) {
	t.Parallel()
	backup := &arcadev1alpha1.GameBackup{
		ObjectMeta: metav1.ObjectMeta{Name: "nightly", Namespace: "games", UID: types.UID("backup-uid")},
		Spec: arcadev1alpha1.GameBackupSpec{DataOperationRequest: arcadev1alpha1.DataOperationRequest{
			RepositorySecretRef: arcadev1alpha1.ExactSecretReference{
				ExactLocalReference: arcadev1alpha1.ExactLocalReference{Name: "repository", UID: "secret-uid"}, ResourceVersion: "42",
			},
		}},
	}
	source := arcadev1alpha1.DataSourceSnapshot{
		GameServer: arcadev1alpha1.ExactGameServerReference{
			ExactLocalReference: arcadev1alpha1.ExactLocalReference{Name: "factory", UID: "server-uid"},
			Generation:          1, DesiredState: arcadev1alpha1.DesiredStateStopped,
		},
		Game: "factorio", ImageDigest: "sha256:" + strings.Repeat("1", 64), SettingsDigest: "sha256:" + strings.Repeat("2", 64),
		Paths: []arcadev1alpha1.DataPathIdentity{
			{Name: "world", MountPath: "/factorio", ClaimRef: arcadev1alpha1.ExactLocalReference{Name: "world-pvc", UID: "world-uid"}},
			{Name: "mods", MountPath: "/mods", ClaimRef: arcadev1alpha1.ExactLocalReference{Name: "mods-pvc", UID: "mods-uid"}},
		},
	}
	resources, err := BuildBackupResources(backup, source, "backup-artifact", "registry.example/arcadectl@sha256:"+strings.Repeat("a", 64), "data-operation-lease", game.RuntimeIdentity{UserID: 845, GroupID: 845, FSGroup: 845})
	if err != nil {
		t.Fatalf("BuildBackupResources() error = %v", err)
	}
	if resources.Input.Immutable == nil || !*resources.Input.Immutable {
		t.Fatal("worker input ConfigMap must be immutable")
	}
	job := resources.Job
	if job.Spec.BackoffLimit == nil || *job.Spec.BackoffLimit != 0 || job.Spec.ActiveDeadlineSeconds == nil || *job.Spec.ActiveDeadlineSeconds != 3600 {
		t.Fatalf("job retry/deadline = %#v", job.Spec)
	}
	if job.Spec.Suspend == nil || !*job.Spec.Suspend {
		t.Fatal("worker Job must be admitted suspended")
	}
	pod := job.Spec.Template.Spec
	if len(pod.SchedulingGates) != 1 || pod.SchedulingGates[0].Name != BackupSchedulingGate {
		t.Fatalf("worker Pod scheduling gates = %#v, want controller authorization gate", pod.SchedulingGates)
	}
	if pod.Hostname != BackupResourceName(backup.UID) {
		t.Fatalf("worker hostname = %q, want stable operation identity %q", pod.Hostname, BackupResourceName(backup.UID))
	}
	if pod.AutomountServiceAccountToken == nil || *pod.AutomountServiceAccountToken || pod.SecurityContext == nil || pod.SecurityContext.RunAsUser == nil || *pod.SecurityContext.RunAsUser == 0 {
		t.Fatalf("pod security boundary = %#v", pod.SecurityContext)
	}
	if len(pod.InitContainers) != 1 || len(pod.Containers) != 1 || pod.Containers[0].Image != "registry.example/arcadectl@sha256:"+strings.Repeat("a", 64) {
		t.Fatalf("worker containers = %#v", pod.Containers)
	}
	container := pod.Containers[0]
	if len(container.Env) != 0 || len(container.EnvFrom) != 0 || container.SecurityContext == nil || container.SecurityContext.ReadOnlyRootFilesystem == nil || !*container.SecurityContext.ReadOnlyRootFilesystem {
		t.Fatalf("worker environment/security = env=%#v envFrom=%#v security=%#v", container.Env, container.EnvFrom, container.SecurityContext)
	}
	if pod.ServiceAccountName != resources.ServiceAccount.Name || len(pod.InitContainers[0].VolumeMounts) != 3 {
		t.Fatalf("worker authority boundary = serviceAccount %q init mounts %#v", pod.ServiceAccountName, pod.InitContainers[0].VolumeMounts)
	}
	authorityProjectionFound := false
	authorityTokenFound := false
	for _, volume := range pod.Volumes {
		if volume.Name != "authority" {
			continue
		}
		authorityProjectionFound = true
		if volume.Projected == nil || volume.Projected.DefaultMode == nil || *volume.Projected.DefaultMode != 0o444 {
			t.Fatalf("authorizer token projection = %#v, want adapter-readable mode", volume.Projected)
		}
		for _, projection := range volume.Projected.Sources {
			if projection.ServiceAccountToken == nil {
				continue
			}
			authorityTokenFound = true
			if projection.ServiceAccountToken.ExpirationSeconds == nil || *projection.ServiceAccountToken.ExpirationSeconds != 600 {
				t.Fatalf("authorizer token lifetime = %#v, want 600 seconds", projection.ServiceAccountToken.ExpirationSeconds)
			}
		}
	}
	if !authorityProjectionFound || !authorityTokenFound {
		t.Fatal("authorizer token projection is absent or incomplete")
	}
	for _, mount := range container.VolumeMounts {
		if mount.Name == "authority" {
			t.Fatal("worker container received the authorizer API token")
		}
		if mount.Name == "credentials" && !mount.ReadOnly {
			t.Fatal("worker credential mount is writable")
		}
	}
	for _, mount := range pod.InitContainers[0].VolumeMounts {
		if mount.Name == "work" || strings.HasPrefix(mount.Name, "source-") {
			t.Fatalf("authorizer received data-plane mount %#v", mount)
		}
	}
	wantRules := []rbacv1.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"secrets"}, ResourceNames: []string{"repository"}, Verbs: []string{"get"}},
		{APIGroups: []string{""}, Resources: []string{"persistentvolumeclaims"}, ResourceNames: []string{"mods-pvc", "world-pvc"}, Verbs: []string{"get"}},
		{APIGroups: []string{"coordination.k8s.io"}, Resources: []string{"leases"}, ResourceNames: []string{"data-operation-lease"}, Verbs: []string{"get", "update"}},
	}
	if !apiequality.Semantic.DeepEqual(resources.Role.Rules, wantRules) {
		t.Fatalf("worker resourceName-scoped authority = %#v", resources.Role.Rules)
	}
	readOnlyClaims := 0
	for _, volume := range pod.Volumes {
		if volume.PersistentVolumeClaim == nil {
			continue
		}
		readOnlyClaims++
		if !volume.PersistentVolumeClaim.ReadOnly {
			t.Errorf("claim volume %q is writable", volume.Name)
		}
	}
	if readOnlyClaims != 2 {
		t.Fatalf("read-only claim volumes = %d, want 2", readOnlyClaims)
	}
	for _, mount := range container.VolumeMounts {
		if strings.HasPrefix(mount.MountPath, "/arcadectl/source/") && !mount.ReadOnly {
			t.Errorf("source mount %q is writable", mount.MountPath)
		}
	}
	if !controlledByKind(resources.Job.OwnerReferences, "GameBackup") || !controlledByKind(resources.Input.OwnerReferences, "GameBackup") ||
		!controlledByKind(resources.ServiceAccount.OwnerReferences, "GameBackup") || !controlledByKind(resources.Role.OwnerReferences, "GameBackup") || !controlledByKind(resources.RoleBinding.OwnerReferences, "GameBackup") {
		t.Fatal("worker resources are not controlled by the exact GameBackup")
	}
	if pod.SecurityContext.SeccompProfile == nil || pod.SecurityContext.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
		t.Fatalf("worker Pod seccomp boundary = %#v", pod.SecurityContext.SeccompProfile)
	}
}

func TestBuildBackupResourcesRejectsMutableWorkerImage(t *testing.T) {
	t.Parallel()
	backup := &arcadev1alpha1.GameBackup{ObjectMeta: metav1.ObjectMeta{Name: "backup", Namespace: "games", UID: "uid"}}
	backup.Spec.RepositorySecretRef.Name = "repository"
	source := arcadev1alpha1.DataSourceSnapshot{
		GameServer: arcadev1alpha1.ExactGameServerReference{ExactLocalReference: arcadev1alpha1.ExactLocalReference{Name: "server", UID: "server-uid"}, Generation: 1, DesiredState: arcadev1alpha1.DesiredStateStopped},
		Game:       "factorio", ImageDigest: "sha256:" + strings.Repeat("1", 64), SettingsDigest: "sha256:" + strings.Repeat("2", 64),
		Paths: []arcadev1alpha1.DataPathIdentity{{Name: "world", MountPath: "/world", ClaimRef: arcadev1alpha1.ExactLocalReference{Name: "claim", UID: "claim-uid"}}},
	}
	if _, err := BuildBackupResources(backup, source, "artifact", "registry.example/worker:latest", "data-operation-lease", game.RuntimeIdentity{UserID: 845, GroupID: 845, FSGroup: 845}); err == nil {
		t.Fatal("BuildBackupResources accepted mutable worker image")
	}
}

func controlledByKind(references []metav1.OwnerReference, kind string) bool {
	for _, reference := range references {
		if reference.Kind == kind && reference.Controller != nil && *reference.Controller {
			return true
		}
	}
	return false
}
