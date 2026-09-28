// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package kube

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"

	arcadev1alpha1 "github.com/gobha-me/arcadectl/api/v1alpha1"
	platformdata "github.com/gobha-me/arcadectl/internal/platform/data"
	"github.com/gobha-me/arcadectl/internal/platform/game"
	batchv1 "k8s.io/api/batch/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/utils/ptr"
)

var pinnedWorkerImagePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._:/-]*@sha256:[0-9a-f]{64}$`)

const (
	LabelBackupUID                        = "arcade.gobha.me/backup-uid"
	LabelDataOperation                    = "arcade.gobha.me/data-operation"
	AnnotationArtifactID                  = "arcade.gobha.me/artifact-id"
	AnnotationBackupName                  = "arcade.gobha.me/backup-name"
	AnnotationBackupPodAuthorized         = "arcade.gobha.me/backup-pod-authorized"
	AnnotationWorkerPodUID                = "arcade.gobha.me/worker-pod-uid"
	AnnotationRuntimeSettlementState      = "arcade.gobha.me/runtime-settlement-state"
	AnnotationRuntimeSettlementGeneration = "arcade.gobha.me/runtime-settlement-generation"
	BackupFinalizer                       = "arcade.gobha.me/backup-protection"
	BackupSchedulingGate                  = "arcade.gobha.me/backup-authorized"
	backupInputKey                        = "input.json"
)

// BackupResources is the deterministic, least-privilege worker boundary.
type BackupResources struct {
	Input          *corev1.ConfigMap
	ServiceAccount *corev1.ServiceAccount
	Role           *rbacv1.Role
	RoleBinding    *rbacv1.RoleBinding
	Job            *batchv1.Job
}

// BuildBackupResources constructs one immutable Job and its non-secret input.
func BuildBackupResources(backup *arcadev1alpha1.GameBackup, source arcadev1alpha1.DataSourceSnapshot, artifactID, workerImage, workerLeaseName string, identity game.RuntimeIdentity) (BackupResources, error) {
	if backup == nil || backup.Name == "" || backup.Namespace == "" || backup.UID == "" {
		return BackupResources{}, errors.New("exact GameBackup identity is required")
	}
	if problems := validation.IsDNS1123Label(backup.Namespace); len(problems) > 0 {
		return BackupResources{}, errors.New("GameBackup namespace is invalid")
	}
	if !pinnedWorkerImagePattern.MatchString(workerImage) {
		return BackupResources{}, errors.New("backup worker image must be pinned by sha256 digest")
	}
	if identity.UserID <= 0 || identity.GroupID <= 0 || identity.FSGroup <= 0 {
		return BackupResources{}, errors.New("backup source identity must be non-root")
	}
	input := platformdata.BackupWorkerInput{
		Version: platformdata.WorkerInputVersion, ArtifactID: artifactID,
		OperationRef:        arcadev1alpha1.ExactLocalReference{Name: backup.Name, UID: string(backup.UID)},
		WorkerLeaseName:     workerLeaseName,
		RepositorySecretRef: backup.Spec.RepositorySecretRef, Source: source,
	}
	if err := platformdata.ValidateBackupWorkerInput(input); err != nil {
		return BackupResources{}, err
	}
	contents, err := json.Marshal(input)
	if err != nil {
		return BackupResources{}, errors.New("encode backup worker input")
	}
	contents = append(contents, '\n')
	name := BackupResourceName(backup.UID)
	owner := metav1.OwnerReference{
		APIVersion: arcadev1alpha1.GroupVersion.String(), Kind: "GameBackup", Name: backup.Name, UID: backup.UID,
		Controller: ptr.To(true), BlockOwnerDeletion: ptr.To(true),
	}
	labels := map[string]string{
		LabelManagedBy:     ManagerName,
		LabelName:          "backup-worker",
		LabelBackupUID:     string(backup.UID),
		LabelDataOperation: "backup",
	}
	inputConfig := &corev1.ConfigMap{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"},
		ObjectMeta: metav1.ObjectMeta{Name: name + "-input", Namespace: backup.Namespace, Labels: cloneMap(labels), OwnerReferences: []metav1.OwnerReference{owner}},
		Data:       map[string]string{backupInputKey: string(contents)},
		Immutable:  ptr.To(true),
	}
	authorityName := name + "-authority"
	serviceAccount := &corev1.ServiceAccount{
		ObjectMeta:                   metav1.ObjectMeta{Name: authorityName, Namespace: backup.Namespace, Labels: cloneMap(labels), OwnerReferences: []metav1.OwnerReference{owner}},
		AutomountServiceAccountToken: ptr.To(false),
	}
	claimNames := make([]string, 0, len(source.Paths))
	for _, path := range source.Paths {
		claimNames = append(claimNames, path.ClaimRef.Name)
	}
	slices.Sort(claimNames)
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{Name: authorityName, Namespace: backup.Namespace, Labels: cloneMap(labels), OwnerReferences: []metav1.OwnerReference{owner}},
		Rules: []rbacv1.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"secrets"}, ResourceNames: []string{backup.Spec.RepositorySecretRef.Name}, Verbs: []string{"get"}},
			{APIGroups: []string{""}, Resources: []string{"persistentvolumeclaims"}, ResourceNames: claimNames, Verbs: []string{"get"}},
			{APIGroups: []string{coordinationv1.GroupName}, Resources: []string{"leases"}, ResourceNames: []string{workerLeaseName}, Verbs: []string{"get", "update"}},
		},
	}
	roleBinding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: authorityName, Namespace: backup.Namespace, Labels: cloneMap(labels), OwnerReferences: []metav1.OwnerReference{owner}},
		Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", APIGroup: "", Name: authorityName, Namespace: backup.Namespace}},
		RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: authorityName},
	}
	volumes := []corev1.Volume{
		{Name: "input", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: inputConfig.Name}, DefaultMode: ptr.To[int32](0o444)}}},
		{Name: "credentials", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{SizeLimit: ptr.To(resource.MustParse("2Mi"))}}},
		{Name: "work", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{SizeLimit: ptr.To(resource.MustParse("512Mi"))}}},
		{Name: "authority", VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{
			// This volume exists only in the short-lived authorizer init
			// container. World-readable projection modes are required because
			// projected files remain root-owned and the adapter UID must not use
			// a Pod-wide fsGroup that could rewrite source-volume ownership.
			DefaultMode: ptr.To[int32](0o444), Sources: []corev1.VolumeProjection{
				{ServiceAccountToken: &corev1.ServiceAccountTokenProjection{Path: "token", ExpirationSeconds: ptr.To[int64](600)}},
				{ConfigMap: &corev1.ConfigMapProjection{LocalObjectReference: corev1.LocalObjectReference{Name: "kube-root-ca.crt"}, Items: []corev1.KeyToPath{{Key: "ca.crt", Path: "ca.crt"}}}},
			},
		}}},
	}
	mounts := []corev1.VolumeMount{
		{Name: "input", MountPath: "/arcadectl/input", ReadOnly: true},
		{Name: "credentials", MountPath: "/arcadectl/credentials", ReadOnly: true},
		{Name: "work", MountPath: "/arcadectl/work"},
	}
	for index, path := range source.Paths {
		volumeName := fmt.Sprintf("source-%d", index)
		volumes = append(volumes, corev1.Volume{Name: volumeName, VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: path.ClaimRef.Name, ReadOnly: true}}})
		mounts = append(mounts, corev1.VolumeMount{Name: volumeName, MountPath: "/arcadectl/source/" + path.Name, ReadOnly: true})
	}
	job := &batchv1.Job{
		TypeMeta: metav1.TypeMeta{APIVersion: "batch/v1", Kind: "Job"},
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: backup.Namespace, Labels: cloneMap(labels), OwnerReferences: []metav1.OwnerReference{owner},
			Annotations: map[string]string{AnnotationArtifactID: artifactID},
		},
		Spec: batchv1.JobSpec{
			BackoffLimit: ptr.To[int32](0), ActiveDeadlineSeconds: ptr.To[int64](3600),
			Parallelism: ptr.To[int32](1), Completions: ptr.To[int32](1), Suspend: ptr.To(true),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: cloneMap(labels), Annotations: map[string]string{AnnotationArtifactID: artifactID}},
				Spec: corev1.PodSpec{
					// A stable operation-unique hostname lets Restic prove that a lock
					// abandoned by a prior serialized attempt is local and stale. Jobs
					// can transiently overlap Pods, so the authorizer first atomically
					// claims the operation Lease for this Pod UID. Controller retries
					// clear that claim only after every old worker Pod is absent.
					Hostname: name, ServiceAccountName: authorityName, AutomountServiceAccountToken: ptr.To(false), RestartPolicy: corev1.RestartPolicyNever,
					SchedulingGates: []corev1.PodSchedulingGate{{Name: BackupSchedulingGate}},
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot: ptr.To(true), RunAsUser: ptr.To(identity.UserID), RunAsGroup: ptr.To(identity.GroupID),
						SupplementalGroups: []int64{identity.FSGroup}, SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
					},
					InitContainers: []corev1.Container{{
						Name: "backup-authorizer", Image: workerImage, ImagePullPolicy: corev1.PullIfNotPresent,
						Command: []string{"/arcadectl-backup-authorizer"},
						Env: []corev1.EnvVar{
							{Name: "POD_NAMESPACE", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.namespace"}}},
							{Name: "POD_UID", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.uid"}}},
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("25m"), corev1.ResourceMemory: resource.MustParse("32Mi"), corev1.ResourceEphemeralStorage: resource.MustParse("8Mi")},
							Limits:   corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("100m"), corev1.ResourceMemory: resource.MustParse("64Mi"), corev1.ResourceEphemeralStorage: resource.MustParse("16Mi")},
						},
						SecurityContext: &corev1.SecurityContext{AllowPrivilegeEscalation: ptr.To(false), ReadOnlyRootFilesystem: ptr.To(true), Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}},
						VolumeMounts: []corev1.VolumeMount{
							{Name: "input", MountPath: "/arcadectl/input", ReadOnly: true},
							{Name: "credentials", MountPath: "/arcadectl/authorized-credentials"},
							{Name: "authority", MountPath: "/var/run/secrets/kubernetes.io/serviceaccount", ReadOnly: true},
						},
					}},
					Containers: []corev1.Container{{
						Name: "backup-worker", Image: workerImage, ImagePullPolicy: corev1.PullIfNotPresent,
						Command: []string{"/arcadectl-backup-worker"},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("100m"), corev1.ResourceMemory: resource.MustParse("128Mi"), corev1.ResourceEphemeralStorage: resource.MustParse("64Mi")},
							Limits:   corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("500m"), corev1.ResourceMemory: resource.MustParse("512Mi"), corev1.ResourceEphemeralStorage: resource.MustParse("768Mi")},
						},
						SecurityContext: &corev1.SecurityContext{AllowPrivilegeEscalation: ptr.To(false), ReadOnlyRootFilesystem: ptr.To(true), Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}},
						VolumeMounts:    mounts, TerminationMessagePolicy: corev1.TerminationMessageReadFile,
					}},
					Volumes: volumes,
				},
			},
		},
	}
	return BackupResources{Input: inputConfig, ServiceAccount: serviceAccount, Role: role, RoleBinding: roleBinding, Job: job}, nil
}

// BackupResourceName is stable for every retry of one GameBackup UID.
func BackupResourceName(uid types.UID) string {
	digest := sha256.Sum256([]byte("arcadectl/backup-job/" + string(uid)))
	return "backup-" + hex.EncodeToString(digest[:16])
}

// DataOperationLeaseName serializes any operation touching one retained data
// identity. Leases deliberately have no expiry while a worker may exist.
func DataOperationLeaseName(dataIdentity string) string {
	digest := sha256.Sum256([]byte("arcadectl/data-operation/" + dataIdentity))
	return "data-operation-" + hex.EncodeToString(digest[:16])
}

// BackupOperationLeaseMatches proves the exact, explicitly managed authority
// that serializes one backup against one retained-data identity. The Lease is
// intentionally ownerless so foreground deletion cannot garbage-collect the
// authority needed to settle runtime before the GameBackup finalizer clears.
func BackupOperationLeaseMatches(lease *coordinationv1.Lease, operation arcadev1alpha1.ExactLocalReference, serverName string) bool {
	if lease == nil || operation.Name == "" || operation.UID == "" || serverName == "" || len(lease.OwnerReferences) != 0 ||
		lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity != operation.UID ||
		lease.Labels[LabelManagedBy] != ManagerName ||
		lease.Labels[LabelBackupUID] != operation.UID ||
		lease.Labels[LabelInstance] != serverName ||
		lease.Annotations[AnnotationBackupName] != operation.Name {
		return false
	}
	dataIdentity := lease.Labels[LabelDataIdentity]
	return dataIdentity != "" && lease.Name == DataOperationLeaseName(dataIdentity)
}
