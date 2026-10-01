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

func destroyResourceFixture(t *testing.T) (*arcadev1alpha1.GameDestroy, restoreworker.Input) {
	t.Helper()
	backup := arcadev1alpha1.ExactLocalReference{Name: "verified-backup", UID: "backup-uid"}
	secret := arcadev1alpha1.ExactSecretReference{ExactLocalReference: arcadev1alpha1.ExactLocalReference{Name: "repository", UID: "secret-uid"}, ResourceVersion: "42"}
	server := arcadev1alpha1.ExactGameServerReference{
		ExactLocalReference: arcadev1alpha1.ExactLocalReference{Name: "factory", UID: "server-uid"}, Generation: 3, DesiredState: arcadev1alpha1.DesiredStateStopped,
	}
	source := arcadev1alpha1.DataSourceSnapshot{
		GameServer: server, Game: "factorio", ImageDigest: "sha256:" + strings.Repeat("1", 64), SettingsDigest: "sha256:" + strings.Repeat("2", 64),
		Paths: []arcadev1alpha1.DataPathIdentity{{Name: "world", MountPath: "/factorio", ClaimRef: arcadev1alpha1.ExactLocalReference{Name: "old-world", UID: "old-world-uid"}}},
	}
	destroy := &arcadev1alpha1.GameDestroy{
		ObjectMeta: metav1.ObjectMeta{Name: "destroy-world", Namespace: "games", UID: types.UID("destroy-uid")},
		Spec: arcadev1alpha1.GameDestroySpec{
			Mode: arcadev1alpha1.DestroyModeVerifiedBackup, BackupRef: &backup, RepositorySecretRef: &secret,
			Target: arcadev1alpha1.GameDestroyTarget{
				GameServer: server.ExactLocalReference, Game: "factorio",
				Data: arcadev1alpha1.RetainedDataReference{
					Identity: "data-world", Claims: []arcadev1alpha1.RetainedDataClaimReference{{Path: "world", ClaimRef: arcadev1alpha1.ExactLocalReference{Name: "retained-world", UID: "retained-world-uid"}}},
				},
			},
		},
	}
	artifactID, err := platformdata.ArtifactID(types.UID(backup.UID))
	if err != nil {
		t.Fatal(err)
	}
	input := restoreworker.Input{
		Version: restoreworker.InputVersion, Stage: restoreworker.StagePreflight,
		OperationRef: arcadev1alpha1.ExactLocalReference{Name: destroy.Name, UID: string(destroy.UID)},
		BackupRef:    backup, Target: server, WorkerLeaseName: DestroyWorkerLeaseName(destroy.UID), RepositorySecretRef: secret,
		Artifact: arcadev1alpha1.BackupArtifact{
			Provenance: arcadev1alpha1.ArtifactProvenance{BackupRef: backup, RepositorySecretRef: secret},
			ID:         artifactID, FormatVersion: platformdata.BackupFormatVersion, ManifestDigest: "sha256:" + strings.Repeat("3", 64),
			PathCount: 1, Verification: arcadev1alpha1.ArtifactVerification{Result: arcadev1alpha1.VerificationVerified},
		},
		Source: source, TargetGame: source.Game, TargetImageDigest: source.ImageDigest, TargetSettingsDigest: source.SettingsDigest,
		TargetPaths: []restoreworker.PathContract{{Name: "world", MountPath: "/factorio"}},
	}
	return destroy, input
}

func TestBuildDestroyResourcesRepositoryOnlyAndInert(t *testing.T) {
	t.Parallel()
	destroy, input := destroyResourceFixture(t)
	resources, err := BuildDestroyResources(destroy, input, testRestoreImage, game.RuntimeIdentity{UserID: 845, GroupID: 845, FSGroup: 845})
	if err != nil {
		t.Fatalf("BuildDestroyResources(): %v", err)
	}
	if resources.Input.Immutable == nil || !*resources.Input.Immutable || resources.Input.Name != DestroyResourceName(destroy.UID)+"-input" {
		t.Fatal("input ConfigMap is not deterministic and immutable")
	}
	var decoded restoreworker.Input
	if err := json.Unmarshal([]byte(resources.Input.Data[destroyInputKey]), &decoded); err != nil ||
		decoded.OperationRef.UID != string(destroy.UID) || decoded.BackupRef.UID != input.BackupRef.UID ||
		decoded.RepositorySecretRef.UID != input.RepositorySecretRef.UID || decoded.RepositorySecretRef.ResourceVersion != "42" ||
		decoded.WorkerLeaseName != DestroyWorkerLeaseName(destroy.UID) || decoded.Stage != restoreworker.StagePreflight {
		t.Fatalf("input lost exact operation authority: %+v %v", decoded, err)
	}
	job := resources.Job
	if job.Name != DestroyResourceName(destroy.UID) || job.Spec.Suspend == nil || !*job.Spec.Suspend ||
		job.Spec.BackoffLimit == nil || *job.Spec.BackoffLimit != 0 {
		t.Fatalf("preflight Job is not initially inert: %#v", job.Spec)
	}
	for _, object := range []metav1.Object{resources.Input, resources.ServiceAccount, resources.Role, resources.RoleBinding, job} {
		if refs := object.GetOwnerReferences(); len(refs) != 1 || refs[0].UID != destroy.UID || refs[0].Kind != "GameDestroy" {
			t.Fatalf("resource lacks exact destroy owner: %#v", refs)
		}
		if object.GetLabels()[LabelDestroyUID] != string(destroy.UID) || object.GetLabels()[LabelDataIdentity] != destroy.Spec.Target.Data.Identity ||
			object.GetLabels()[LabelDestroyStage] != string(restoreworker.StagePreflight) {
			t.Fatalf("resource labels are incomplete: %#v", object.GetLabels())
		}
	}
	pod := job.Spec.Template.Spec
	if len(pod.SchedulingGates) != 1 || pod.SchedulingGates[0].Name != DestroySchedulingGate || pod.Hostname != job.Name ||
		pod.AutomountServiceAccountToken == nil || *pod.AutomountServiceAccountToken || pod.SecurityContext == nil || pod.SecurityContext.FSGroup != nil {
		t.Fatalf("preflight pod gate/authority invalid: %#v", pod)
	}
	if len(pod.InitContainers) != 1 || len(pod.Containers) != 1 ||
		pod.InitContainers[0].Command[0] != "/arcadectl-destroy-authorizer" || pod.Containers[0].Command[0] != "/arcadectl-destroy-worker" ||
		pod.InitContainers[0].Image != testRestoreImage || pod.Containers[0].Image != testRestoreImage ||
		pod.Containers[0].TerminationMessagePath != restoreworker.DefaultTerminationPath || pod.Containers[0].TerminationMessagePolicy != corev1.TerminationMessageReadFile {
		t.Fatalf("preflight executable/image/result invalid: %#v", pod)
	}
	for _, volume := range pod.Volumes {
		if volume.PersistentVolumeClaim != nil {
			t.Fatalf("preflight Pod mounts PVC %q", volume.PersistentVolumeClaim.ClaimName)
		}
	}
	for _, container := range pod.Containers {
		if len(container.Env) != 0 || len(container.EnvFrom) != 0 {
			t.Fatal("worker received ambient credentials")
		}
		for _, mount := range container.VolumeMounts {
			if mount.Name == "authority" || strings.HasPrefix(mount.MountPath, restoreworker.DefaultSourceRoot) || strings.HasPrefix(mount.MountPath, restoreworker.DefaultCandidateRoot) ||
				(mount.Name == "credentials" && !mount.ReadOnly) {
				t.Fatalf("worker mount unsafe: %#v", mount)
			}
		}
	}
	for _, mount := range pod.InitContainers[0].VolumeMounts {
		if mount.Name == "work" {
			t.Fatal("authorizer received work volume")
		}
	}
	wantRules := []rbacv1.PolicyRule{
		{APIGroups: []string{arcadev1alpha1.GroupVersion.Group}, Resources: []string{"gamedestroys"}, ResourceNames: []string{destroy.Name}, Verbs: []string{"get"}},
		{APIGroups: []string{arcadev1alpha1.GroupVersion.Group}, Resources: []string{"gamebackups"}, ResourceNames: []string{input.BackupRef.Name}, Verbs: []string{"get"}},
		{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}},
		{APIGroups: []string{""}, Resources: []string{"secrets"}, ResourceNames: []string{input.RepositorySecretRef.Name}, Verbs: []string{"get"}},
		{APIGroups: []string{coordinationv1.GroupName}, Resources: []string{"leases"}, ResourceNames: []string{input.WorkerLeaseName}, Verbs: []string{"get", "update"}},
		{APIGroups: []string{coordinationv1.GroupName}, Resources: []string{"leases"}, ResourceNames: []string{DataOperationLeaseName(destroy.Spec.Target.Data.Identity)}, Verbs: []string{"get"}},
	}
	if !apiequality.Semantic.DeepEqual(resources.Role.Rules, wantRules) {
		t.Fatalf("worker Role exceeded exact read/worker-claim authority: %#v", resources.Role.Rules)
	}
	if resources.RoleBinding.Subjects[0].Name != resources.ServiceAccount.Name || resources.RoleBinding.RoleRef.Name != resources.Role.Name {
		t.Fatal("RoleBinding does not bind exact short-lived authority")
	}
}

func TestBuildDestroyResourcesRejectsCrossOperationInput(t *testing.T) {
	t.Parallel()
	destroy, input := destroyResourceFixture(t)
	identity := game.RuntimeIdentity{UserID: 845, GroupID: 845, FSGroup: 845}
	tests := []struct {
		name string
		edit func(*arcadev1alpha1.GameDestroy, *restoreworker.Input)
	}{
		{"wrong stage", func(_ *arcadev1alpha1.GameDestroy, in *restoreworker.Input) { in.Stage = restoreworker.StagePopulate }},
		{"wrong operation", func(_ *arcadev1alpha1.GameDestroy, in *restoreworker.Input) { in.OperationRef.UID = "other" }},
		{"wrong backup", func(_ *arcadev1alpha1.GameDestroy, in *restoreworker.Input) { in.BackupRef.UID = "other" }},
		{"wrong secret revision", func(_ *arcadev1alpha1.GameDestroy, in *restoreworker.Input) {
			in.RepositorySecretRef.ResourceVersion = "43"
		}},
		{"wrong worker lease", func(_ *arcadev1alpha1.GameDestroy, in *restoreworker.Input) { in.WorkerLeaseName = "other" }},
		{"wrong server", func(_ *arcadev1alpha1.GameDestroy, in *restoreworker.Input) { in.Target.UID = "other" }},
		{"wrong game", func(d *arcadev1alpha1.GameDestroy, _ *restoreworker.Input) { d.Spec.Target.Game = "other" }},
		{"wrong data path", func(d *arcadev1alpha1.GameDestroy, _ *restoreworker.Input) {
			d.Spec.Target.Data.Claims[0].Path = "other"
		}},
		{"unsafe mode", func(d *arcadev1alpha1.GameDestroy, _ *restoreworker.Input) {
			d.Spec.Mode = arcadev1alpha1.DestroyModeUnsafeNoBackup
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			d := destroy.DeepCopy()
			in := input
			test.edit(d, &in)
			if _, err := BuildDestroyResources(d, in, testRestoreImage, identity); err == nil {
				t.Fatal("accepted mismatched destroy preflight")
			}
		})
	}
	if _, err := BuildDestroyResources(destroy, input, "arcadectl:latest", identity); err == nil {
		t.Fatal("accepted unpinned image")
	}
	if _, err := BuildDestroyResources(destroy, input, testRestoreImage, game.RuntimeIdentity{}); err == nil {
		t.Fatal("accepted root worker identity")
	}
}

func TestDestroyOperationLeaseMatchesExactOwnerlessFence(t *testing.T) {
	t.Parallel()
	operation := arcadev1alpha1.ExactLocalReference{Name: "destroy-world", UID: "destroy-uid"}
	lease := &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{
			Name: DataOperationLeaseName("data-world"),
			Labels: map[string]string{
				LabelManagedBy: ManagerName, LabelDestroyUID: operation.UID,
				LabelInstance: "factory", LabelDataIdentity: "data-world",
			},
			Annotations: map[string]string{AnnotationDestroyName: operation.Name},
		},
		Spec: coordinationv1.LeaseSpec{HolderIdentity: ptr.To(operation.UID)},
	}
	if !DestroyOperationLeaseMatches(lease, operation, "factory", "data-world") {
		t.Fatal("exact ownerless destroy fence rejected")
	}
	for name, modify := range map[string]func(*coordinationv1.Lease){
		"wrong holder": func(l *coordinationv1.Lease) { l.Spec.HolderIdentity = ptr.To("other") },
		"wrong name":   func(l *coordinationv1.Lease) { l.Name = "other" },
		"owned": func(l *coordinationv1.Lease) {
			l.OwnerReferences = []metav1.OwnerReference{{UID: types.UID(operation.UID)}}
		},
		"wrong data":       func(l *coordinationv1.Lease) { l.Labels[LabelDataIdentity] = "other" },
		"wrong destroy":    func(l *coordinationv1.Lease) { l.Labels[LabelDestroyUID] = "other" },
		"wrong server":     func(l *coordinationv1.Lease) { l.Labels[LabelInstance] = "other" },
		"wrong annotation": func(l *coordinationv1.Lease) { l.Annotations[AnnotationDestroyName] = "other" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := lease.DeepCopy()
			modify(changed)
			if DestroyOperationLeaseMatches(changed, operation, "factory", "data-world") {
				t.Fatal("accepted mismatched destroy fence")
			}
		})
	}
}
