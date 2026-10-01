// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package kube

import (
	"encoding/json"
	"strings"
	"testing"

	arcadev1alpha1 "github.com/gobha-me/arcadectl/api/v1alpha1"
	platformdata "github.com/gobha-me/arcadectl/internal/platform/data"
	"github.com/gobha-me/arcadectl/internal/platform/game"
	"github.com/gobha-me/arcadectl/internal/restoreworker"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
)

const testRestoreImage = "registry.example/arcadectl@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func restoreResourceFixture(t *testing.T, stage restoreworker.Stage) (*arcadev1alpha1.GameRestore, restoreworker.Input) {
	t.Helper()
	backup := arcadev1alpha1.ExactLocalReference{Name: "verified-backup", UID: "backup-uid"}
	secret := arcadev1alpha1.ExactSecretReference{
		ExactLocalReference: arcadev1alpha1.ExactLocalReference{Name: "repository", UID: "secret-uid"}, ResourceVersion: "42",
	}
	target := arcadev1alpha1.ExactGameServerReference{
		ExactLocalReference: arcadev1alpha1.ExactLocalReference{Name: "factory", UID: "target-uid"},
		Generation:          3, DesiredState: arcadev1alpha1.DesiredStateStopped,
	}
	restore := &arcadev1alpha1.GameRestore{
		ObjectMeta: metav1.ObjectMeta{Name: "restore-world", Namespace: "games", UID: types.UID("restore-uid")},
		Spec: arcadev1alpha1.GameRestoreSpec{
			DataOperationRequest: arcadev1alpha1.DataOperationRequest{RepositorySecretRef: secret},
			BackupRef:            backup, Target: target,
		},
	}
	artifactID, err := platformdata.ArtifactID(types.UID(backup.UID))
	if err != nil {
		t.Fatal(err)
	}
	candidateIdentity, err := platformdata.RestoreDataIdentity(restore.UID)
	if err != nil {
		t.Fatal(err)
	}
	source := arcadev1alpha1.DataSourceSnapshot{
		GameServer: arcadev1alpha1.ExactGameServerReference{
			ExactLocalReference: arcadev1alpha1.ExactLocalReference{Name: "original", UID: "source-uid"},
			Generation:          1, DesiredState: arcadev1alpha1.DesiredStateStopped,
		},
		Game: "factorio", ImageDigest: "sha256:" + strings.Repeat("1", 64), SettingsDigest: "sha256:" + strings.Repeat("2", 64),
		Paths: []arcadev1alpha1.DataPathIdentity{
			{Name: "world", MountPath: "/factorio", ClaimRef: arcadev1alpha1.ExactLocalReference{Name: "active-world", UID: "old-world-uid"}},
			{Name: "mods", MountPath: "/mods", ClaimRef: arcadev1alpha1.ExactLocalReference{Name: "active-mods", UID: "old-mods-uid"}},
		},
	}
	input := restoreworker.Input{
		Version: restoreworker.InputVersion, Stage: stage,
		OperationRef: arcadev1alpha1.ExactLocalReference{Name: restore.Name, UID: string(restore.UID)},
		BackupRef:    backup, Target: target, WorkerLeaseName: DataOperationLeaseName(candidateIdentity),
		RepositorySecretRef: secret,
		Artifact: arcadev1alpha1.BackupArtifact{
			Provenance: arcadev1alpha1.ArtifactProvenance{BackupRef: backup, RepositorySecretRef: secret},
			ID:         artifactID, FormatVersion: platformdata.BackupFormatVersion, ManifestDigest: "sha256:" + strings.Repeat("3", 64),
			PathCount: 2, Verification: arcadev1alpha1.ArtifactVerification{Result: arcadev1alpha1.VerificationVerified},
		},
		Source: source, TargetGame: source.Game, TargetImageDigest: source.ImageDigest, TargetSettingsDigest: source.SettingsDigest,
		TargetPaths: []restoreworker.PathContract{{Name: "world", MountPath: "/factorio"}, {Name: "mods", MountPath: "/mods"}},
	}
	if stage == restoreworker.StagePopulate {
		input.PreviousDataIdentity = "data-previous"
		for _, path := range source.Paths {
			input.PreviousData = append(input.PreviousData, arcadev1alpha1.DataPathIdentity{
				Name: path.Name, MountPath: path.MountPath,
				ClaimRef: arcadev1alpha1.ExactLocalReference{Name: "previous-" + path.Name, UID: path.Name + "-previous-uid"},
			})
			candidateName, err := platformdata.RestoreCandidateID(restore.UID, path.Name)
			if err != nil {
				t.Fatal(err)
			}
			input.CandidatePaths = append(input.CandidatePaths, arcadev1alpha1.DataPathIdentity{
				Name: path.Name, MountPath: path.MountPath,
				ClaimRef: arcadev1alpha1.ExactLocalReference{Name: candidateName, UID: path.Name + "-candidate-uid"},
			})
		}
	}
	return restore, input
}

func TestBuildRestorePreflightHasNoPVCOrTargetDataAuthority(t *testing.T) {
	t.Parallel()
	restore, input := restoreResourceFixture(t, restoreworker.StagePreflight)
	resources, err := BuildRestoreResources(restore, input, testRestoreImage, game.RuntimeIdentity{UserID: 845, GroupID: 845, FSGroup: 845})
	if err != nil {
		t.Fatalf("BuildRestoreResources(): %v", err)
	}
	if resources.Input.Immutable == nil || !*resources.Input.Immutable {
		t.Fatal("restore input must be immutable")
	}
	job := resources.Job
	if job.Name != RestoreResourceName(restore.UID, restoreworker.StagePreflight) || job.Spec.Suspend == nil || !*job.Spec.Suspend ||
		job.Spec.BackoffLimit == nil || *job.Spec.BackoffLimit != 0 {
		t.Fatalf("preflight Job is not deterministically inert: %#v", job.Spec)
	}
	pod := job.Spec.Template.Spec
	if len(pod.SchedulingGates) != 1 || pod.SchedulingGates[0].Name != RestoreSchedulingGate || pod.Hostname != job.Name {
		t.Fatalf("Pod gate/hostname = %#v / %q", pod.SchedulingGates, pod.Hostname)
	}
	if pod.AutomountServiceAccountToken == nil || *pod.AutomountServiceAccountToken || pod.SecurityContext == nil || pod.SecurityContext.FSGroup != nil {
		t.Fatalf("preflight Pod authority = %#v", pod.SecurityContext)
	}
	if len(pod.InitContainers) != 1 || len(pod.Containers) != 1 || pod.Containers[0].Image != testRestoreImage {
		t.Fatalf("worker containers = %#v", pod.Containers)
	}
	if pod.InitContainers[0].Command[0] != "/arcadectl-restore-authorizer" || pod.Containers[0].Command[0] != "/arcadectl-restore-worker" {
		t.Fatal("restore executables are not exact")
	}
	if pod.Containers[0].TerminationMessagePath != restoreworker.DefaultTerminationPath || pod.Containers[0].TerminationMessagePolicy != corev1.TerminationMessageReadFile {
		t.Fatal("worker termination result is not bounded to the private work volume")
	}
	if len(pod.Containers[0].Env) != 0 || len(pod.Containers[0].EnvFrom) != 0 {
		t.Fatal("worker received Kubernetes/environment credentials")
	}
	for _, volume := range pod.Volumes {
		if volume.PersistentVolumeClaim != nil {
			t.Fatalf("preflight mounted PVC %q", volume.PersistentVolumeClaim.ClaimName)
		}
	}
	for _, mount := range pod.Containers[0].VolumeMounts {
		if mount.Name == "authority" || strings.HasPrefix(mount.MountPath, restoreworker.DefaultCandidateRoot) || strings.HasPrefix(mount.MountPath, restoreworker.DefaultSourceRoot) {
			t.Fatalf("preflight worker mount unsafe: %#v", mount)
		}
		if mount.Name == "credentials" && !mount.ReadOnly {
			t.Fatal("worker credential mount is writable")
		}
	}
	for _, mount := range pod.InitContainers[0].VolumeMounts {
		if mount.Name == "work" || strings.HasPrefix(mount.Name, "candidate-") {
			t.Fatalf("authorizer received data mount: %#v", mount)
		}
	}
	wantRules := []rbacv1.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"secrets"}, ResourceNames: []string{"repository"}, Verbs: []string{"get"}},
		{APIGroups: []string{coordinationv1.GroupName}, Resources: []string{"leases"}, ResourceNames: []string{input.WorkerLeaseName}, Verbs: []string{"get", "update"}},
	}
	if !apiequality.Semantic.DeepEqual(resources.Role.Rules, wantRules) {
		t.Fatalf("preflight Role is over-privileged: %#v", resources.Role.Rules)
	}
	if resources.RoleBinding.Subjects[0].Name != resources.ServiceAccount.Name || resources.RoleBinding.RoleRef.Name != resources.Role.Name {
		t.Fatal("RoleBinding does not bind exact short-lived authority")
	}
	if len(job.OwnerReferences) != 1 || job.OwnerReferences[0].UID != restore.UID || job.OwnerReferences[0].Kind != "GameRestore" {
		t.Fatal("Job owner is not exact restore")
	}
	var decoded restoreworker.Input
	if err := json.Unmarshal([]byte(resources.Input.Data[restoreInputKey]), &decoded); err != nil || decoded.RepositorySecretRef.UID != "secret-uid" || decoded.RepositorySecretRef.ResourceVersion != "42" || len(decoded.CandidatePaths) != 0 {
		t.Fatalf("non-secret exact preflight input invalid: %+v %v", decoded, err)
	}
}

func TestBuildRestorePopulateMountsOnlyExactFreshCandidates(t *testing.T) {
	t.Parallel()
	restore, input := restoreResourceFixture(t, restoreworker.StagePopulate)
	resources, err := BuildRestoreResources(restore, input, testRestoreImage, game.RuntimeIdentity{UserID: 845, GroupID: 845, FSGroup: 845})
	if err != nil {
		t.Fatalf("BuildRestoreResources(): %v", err)
	}
	if resources.Job.Name == RestoreResourceName(restore.UID, restoreworker.StagePreflight) {
		t.Fatal("populate reused preflight Job identity")
	}
	pod := resources.Job.Spec.Template.Spec
	if pod.SecurityContext == nil || pod.SecurityContext.FSGroup == nil || *pod.SecurityContext.FSGroup != 845 ||
		pod.SecurityContext.FSGroupChangePolicy == nil || *pod.SecurityContext.FSGroupChangePolicy != corev1.FSGroupChangeOnRootMismatch {
		t.Fatalf("candidate write identity = %#v", pod.SecurityContext)
	}
	wantClaims := make(map[string]string)
	for _, path := range input.CandidatePaths {
		wantClaims[path.ClaimRef.Name] = restoreworker.DefaultCandidateRoot + "/" + path.Name
	}
	mounted := make(map[string]string)
	for _, volume := range pod.Volumes {
		if volume.PersistentVolumeClaim == nil {
			continue
		}
		if volume.PersistentVolumeClaim.ReadOnly {
			t.Fatalf("candidate PVC %q is read-only", volume.PersistentVolumeClaim.ClaimName)
		}
		if _, exists := wantClaims[volume.PersistentVolumeClaim.ClaimName]; !exists {
			t.Fatalf("non-candidate PVC mounted: %q", volume.PersistentVolumeClaim.ClaimName)
		}
		mounted[volume.Name] = volume.PersistentVolumeClaim.ClaimName
	}
	if len(mounted) != len(wantClaims) {
		t.Fatalf("candidate volume count = %d, want %d", len(mounted), len(wantClaims))
	}
	for _, mount := range pod.Containers[0].VolumeMounts {
		if claim, exists := mounted[mount.Name]; exists && (mount.ReadOnly || mount.MountPath != wantClaims[claim]) {
			t.Fatalf("candidate mount mismatch: %#v", mount)
		}
		if strings.HasPrefix(mount.MountPath, restoreworker.DefaultSourceRoot) {
			t.Fatalf("source mount leaked into restore Pod: %#v", mount)
		}
	}
	for _, mount := range pod.InitContainers[0].VolumeMounts {
		if _, exists := mounted[mount.Name]; exists {
			t.Fatalf("authorizer received candidate data mount: %#v", mount)
		}
	}
	allowedClaims := make(map[string]struct{}, len(input.CandidatePaths)+len(input.PreviousData))
	for _, path := range input.CandidatePaths {
		allowedClaims[path.ClaimRef.Name] = struct{}{}
	}
	for _, path := range input.PreviousData {
		allowedClaims[path.ClaimRef.Name] = struct{}{}
	}
	if len(resources.Role.Rules) != 5 ||
		!apiequality.Semantic.DeepEqual(resources.Role.Rules[2].ResourceNames, []string{DataOperationLeaseName(input.PreviousDataIdentity)}) ||
		!apiequality.Semantic.DeepEqual(resources.Role.Rules[3].ResourceNames, []string{input.Target.Name}) ||
		len(resources.Role.Rules[4].ResourceNames) != len(allowedClaims) || resources.Role.Rules[4].Resources[0] != "persistentvolumeclaims" {
		t.Fatalf("dual-lease and exact target authority = %#v", resources.Role.Rules)
	}
	for _, name := range resources.Role.Rules[4].ResourceNames {
		if _, exists := allowedClaims[name]; !exists {
			t.Fatalf("Role grants unrelated PVC %q", name)
		}
	}
}

func TestBuildRestoreRejectsMutableOrAliasedInput(t *testing.T) {
	t.Parallel()
	restore, input := restoreResourceFixture(t, restoreworker.StagePopulate)
	identity := game.RuntimeIdentity{UserID: 845, GroupID: 845, FSGroup: 845}
	if _, err := BuildRestoreResources(restore, input, "registry.example/arcadectl:latest", identity); err == nil {
		t.Fatal("mutable worker image accepted")
	}
	wrong := input
	wrong.CandidatePaths = append([]arcadev1alpha1.DataPathIdentity(nil), input.CandidatePaths...)
	wrong.CandidatePaths[0].ClaimRef.UID = input.Source.Paths[0].ClaimRef.UID
	if _, err := BuildRestoreResources(restore, wrong, testRestoreImage, identity); err == nil {
		t.Fatal("candidate aliasing source claim accepted")
	}
	wrong = input
	wrong.RepositorySecretRef.ResourceVersion = "43"
	if _, err := BuildRestoreResources(restore, wrong, testRestoreImage, identity); err == nil {
		t.Fatal("substituted repository Secret revision accepted")
	}
}

func TestRestoreOperationLeaseMatchesExactOwnerlessCandidate(t *testing.T) {
	t.Parallel()
	operation := arcadev1alpha1.ExactLocalReference{Name: "restore-world", UID: "restore-uid"}
	identity := "candidate-identity"
	lease := &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{
			Name:        DataOperationLeaseName(identity),
			Labels:      map[string]string{LabelManagedBy: ManagerName, LabelRestoreUID: operation.UID, LabelInstance: "factory", LabelDataIdentity: identity},
			Annotations: map[string]string{AnnotationRestoreName: operation.Name},
		},
		Spec: coordinationv1.LeaseSpec{HolderIdentity: ptr.To(operation.UID)},
	}
	if !RestoreOperationLeaseMatches(lease, operation, "factory", identity) {
		t.Fatal("exact candidate lease refused")
	}
	bad := lease.DeepCopy()
	bad.OwnerReferences = []metav1.OwnerReference{{UID: "owner"}}
	if RestoreOperationLeaseMatches(bad, operation, "factory", identity) {
		t.Fatal("owner-controlled candidate lease accepted")
	}
	bad = lease.DeepCopy()
	bad.Labels[LabelDataIdentity] = "previous-identity"
	if RestoreOperationLeaseMatches(bad, operation, "factory", identity) {
		t.Fatal("previous-data lease accepted as worker authority")
	}
	bad = lease.DeepCopy()
	bad.Annotations[AnnotationRestoreName] = "other"
	if RestoreOperationLeaseMatches(bad, operation, "factory", identity) {
		t.Fatal("foreign restore name accepted")
	}
}
