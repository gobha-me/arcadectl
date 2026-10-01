// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package kube

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"

	arcadev1alpha1 "github.com/gobha-me/arcadectl/api/v1alpha1"
	"github.com/gobha-me/arcadectl/internal/platform/game"
	"github.com/gobha-me/arcadectl/internal/restoreworker"
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

const (
	LabelDestroyUID                = "arcade.gobha.me/destroy-uid"
	LabelDestroyStage              = "arcade.gobha.me/destroy-stage"
	AnnotationDestroyName          = "arcade.gobha.me/destroy-name"
	AnnotationDestroyPodAuthorized = "arcade.gobha.me/destroy-pod-authorized"
	DestroyFinalizer               = "arcade.gobha.me/destroy-protection"
	DestroySchedulingGate          = "arcade.gobha.me/destroy-authorized"
	destroyInputKey                = "input.json"
)

// DestroyResources are a repository-only verification boundary. They contain
// no volume or RBAC authority capable of reading or deleting a world claim.
type DestroyResources struct {
	Input          *corev1.ConfigMap
	ServiceAccount *corev1.ServiceAccount
	Role           *rbacv1.Role
	RoleBinding    *rbacv1.RoleBinding
	Job            *batchv1.Job
}

// BuildDestroyResources constructs a deterministic, initially inert preflight
// Job. The controller must prove and hold the exact data-operation Lease from
// cold verification through deletion; the separate worker Lease serializes
// Pods of this Job without granting them write access to the data Lease.
func BuildDestroyResources(destroy *arcadev1alpha1.GameDestroy, input restoreworker.Input, workerImage string, identity game.RuntimeIdentity) (DestroyResources, error) {
	if destroy == nil || destroy.Name == "" || destroy.Namespace == "" || destroy.UID == "" ||
		len(validation.IsDNS1123Label(destroy.Namespace)) != 0 ||
		destroy.Spec.Mode != arcadev1alpha1.DestroyModeVerifiedBackup || destroy.Spec.BackupRef == nil || destroy.Spec.RepositorySecretRef == nil {
		return DestroyResources{}, errors.New("exact verified GameDestroy identity is required")
	}
	if !pinnedWorkerImagePattern.MatchString(workerImage) {
		return DestroyResources{}, errors.New("destroy worker image must be pinned by sha256 digest")
	}
	if identity.UserID <= 0 || identity.GroupID <= 0 || identity.FSGroup <= 0 {
		return DestroyResources{}, errors.New("destroy worker identity must be non-root")
	}
	if err := restoreworker.ValidateInput(input); err != nil || input.Stage != restoreworker.StagePreflight ||
		input.OperationRef != (arcadev1alpha1.ExactLocalReference{Name: destroy.Name, UID: string(destroy.UID)}) ||
		input.BackupRef != *destroy.Spec.BackupRef || input.RepositorySecretRef != *destroy.Spec.RepositorySecretRef ||
		input.WorkerLeaseName != DestroyWorkerLeaseName(destroy.UID) ||
		input.Target != input.Source.GameServer ||
		input.Target.ExactLocalReference != destroy.Spec.Target.GameServer ||
		input.TargetGame != destroy.Spec.Target.Game ||
		len(validation.IsDNS1123Label(destroy.Spec.Target.Data.Identity)) != 0 ||
		len(input.TargetPaths) != len(destroy.Spec.Target.Data.Claims) {
		return DestroyResources{}, errors.New("destroy worker input does not match the exact preflight operation")
	}
	claimPaths := make(map[string]struct{}, len(destroy.Spec.Target.Data.Claims))
	claimNames := make(map[string]struct{}, len(destroy.Spec.Target.Data.Claims))
	claimUIDs := make(map[string]struct{}, len(destroy.Spec.Target.Data.Claims))
	for _, claim := range destroy.Spec.Target.Data.Claims {
		if claim.Path == "" || claim.ClaimRef.Name == "" || claim.ClaimRef.UID == "" || claim.ClaimRef.Namespace != nil {
			return DestroyResources{}, errors.New("destroy target claim is incomplete")
		}
		if _, duplicate := claimPaths[claim.Path]; duplicate {
			return DestroyResources{}, errors.New("destroy target paths overlap")
		}
		if _, duplicate := claimNames[claim.ClaimRef.Name]; duplicate {
			return DestroyResources{}, errors.New("destroy target claim names overlap")
		}
		if _, duplicate := claimUIDs[claim.ClaimRef.UID]; duplicate {
			return DestroyResources{}, errors.New("destroy target claim UIDs overlap")
		}
		claimPaths[claim.Path] = struct{}{}
		claimNames[claim.ClaimRef.Name] = struct{}{}
		claimUIDs[claim.ClaimRef.UID] = struct{}{}
	}
	for _, path := range input.TargetPaths {
		if _, present := claimPaths[path.Name]; !present {
			return DestroyResources{}, errors.New("destroy target paths differ from verified backup")
		}
	}
	input.TargetPaths = slices.Clone(input.TargetPaths)
	slices.SortFunc(input.TargetPaths, func(left, right restoreworker.PathContract) int { return compareName(left.Name, right.Name) })
	contents, err := json.Marshal(input)
	if err != nil {
		return DestroyResources{}, errors.New("encode destroy worker input")
	}
	contents = append(contents, '\n')
	name := DestroyResourceName(destroy.UID)
	authorityName := name + "-authority"
	owner := metav1.OwnerReference{
		APIVersion: arcadev1alpha1.GroupVersion.String(), Kind: "GameDestroy", Name: destroy.Name, UID: destroy.UID,
		Controller: ptr.To(true), BlockOwnerDeletion: ptr.To(true),
	}
	labels := map[string]string{
		LabelManagedBy: ManagerName, LabelName: "destroy-worker", LabelDestroyUID: string(destroy.UID),
		LabelDestroyStage: string(restoreworker.StagePreflight), LabelDataOperation: "destroy",
		LabelDataIdentity: destroy.Spec.Target.Data.Identity, LabelInstance: destroy.Spec.Target.GameServer.Name,
	}
	annotations := map[string]string{AnnotationArtifactID: input.Artifact.ID, AnnotationDestroyName: destroy.Name}
	inputConfig := &corev1.ConfigMap{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"},
		ObjectMeta: metav1.ObjectMeta{Name: name + "-input", Namespace: destroy.Namespace, Labels: cloneMap(labels), OwnerReferences: []metav1.OwnerReference{owner}},
		Data:       map[string]string{destroyInputKey: string(contents)}, Immutable: ptr.To(true),
	}
	serviceAccount := &corev1.ServiceAccount{
		ObjectMeta:                   metav1.ObjectMeta{Name: authorityName, Namespace: destroy.Namespace, Labels: cloneMap(labels), OwnerReferences: []metav1.OwnerReference{owner}},
		AutomountServiceAccountToken: ptr.To(false),
	}
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{Name: authorityName, Namespace: destroy.Namespace, Labels: cloneMap(labels), OwnerReferences: []metav1.OwnerReference{owner}},
		Rules: []rbacv1.PolicyRule{
			{APIGroups: []string{arcadev1alpha1.GroupVersion.Group}, Resources: []string{"gamedestroys"}, ResourceNames: []string{destroy.Name}, Verbs: []string{"get"}},
			{APIGroups: []string{arcadev1alpha1.GroupVersion.Group}, Resources: []string{"gamebackups"}, ResourceNames: []string{input.BackupRef.Name}, Verbs: []string{"get"}},
			{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}},
			{APIGroups: []string{""}, Resources: []string{"secrets"}, ResourceNames: []string{input.RepositorySecretRef.Name}, Verbs: []string{"get"}},
			{APIGroups: []string{coordinationv1.GroupName}, Resources: []string{"leases"}, ResourceNames: []string{input.WorkerLeaseName}, Verbs: []string{"get", "update"}},
			{APIGroups: []string{coordinationv1.GroupName}, Resources: []string{"leases"}, ResourceNames: []string{DataOperationLeaseName(destroy.Spec.Target.Data.Identity)}, Verbs: []string{"get"}},
		},
	}
	roleBinding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: authorityName, Namespace: destroy.Namespace, Labels: cloneMap(labels), OwnerReferences: []metav1.OwnerReference{owner}},
		Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: authorityName, Namespace: destroy.Namespace}},
		RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: authorityName},
	}
	volumes := []corev1.Volume{
		{Name: "input", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: inputConfig.Name}, DefaultMode: ptr.To[int32](0o444)}}},
		{Name: "credentials", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{Medium: corev1.StorageMediumMemory, SizeLimit: ptr.To(resource.MustParse("2Mi"))}}},
		{Name: "work", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{SizeLimit: ptr.To(resource.MustParse("512Mi"))}}},
		{Name: "authority", VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{DefaultMode: ptr.To[int32](0o444), Sources: []corev1.VolumeProjection{
			{ServiceAccountToken: &corev1.ServiceAccountTokenProjection{Path: "token", ExpirationSeconds: ptr.To[int64](600)}},
			{ConfigMap: &corev1.ConfigMapProjection{LocalObjectReference: corev1.LocalObjectReference{Name: "kube-root-ca.crt"}, Items: []corev1.KeyToPath{{Key: "ca.crt", Path: "ca.crt"}}}},
		}}}},
	}
	job := &batchv1.Job{
		TypeMeta:   metav1.TypeMeta{APIVersion: "batch/v1", Kind: "Job"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: destroy.Namespace, Labels: cloneMap(labels), Annotations: cloneMap(annotations), OwnerReferences: []metav1.OwnerReference{owner}},
		Spec: batchv1.JobSpec{
			BackoffLimit: ptr.To[int32](0), ActiveDeadlineSeconds: ptr.To[int64](3600),
			Parallelism: ptr.To[int32](1), Completions: ptr.To[int32](1), Suspend: ptr.To(true),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: cloneMap(labels), Annotations: cloneMap(annotations)},
				Spec: corev1.PodSpec{
					Hostname: name, ServiceAccountName: authorityName, AutomountServiceAccountToken: ptr.To(false), RestartPolicy: corev1.RestartPolicyNever,
					SchedulingGates: []corev1.PodSchedulingGate{{Name: DestroySchedulingGate}},
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot: ptr.To(true), RunAsUser: ptr.To(identity.UserID), RunAsGroup: ptr.To(identity.GroupID),
						SupplementalGroups: []int64{identity.FSGroup}, SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
					},
					InitContainers: []corev1.Container{{
						Name: "destroy-authorizer", Image: workerImage, ImagePullPolicy: corev1.PullIfNotPresent,
						Command: []string{"/arcadectl-destroy-authorizer"},
						Env: []corev1.EnvVar{
							{Name: "POD_NAMESPACE", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.namespace"}}},
							{Name: "POD_NAME", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.name"}}},
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
						Name: "destroy-worker", Image: workerImage, ImagePullPolicy: corev1.PullIfNotPresent,
						Command: []string{"/arcadectl-destroy-worker"},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("100m"), corev1.ResourceMemory: resource.MustParse("128Mi"), corev1.ResourceEphemeralStorage: resource.MustParse("64Mi")},
							Limits:   corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("500m"), corev1.ResourceMemory: resource.MustParse("512Mi"), corev1.ResourceEphemeralStorage: resource.MustParse("768Mi")},
						},
						SecurityContext: &corev1.SecurityContext{AllowPrivilegeEscalation: ptr.To(false), ReadOnlyRootFilesystem: ptr.To(true), Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}},
						VolumeMounts: []corev1.VolumeMount{
							{Name: "input", MountPath: "/arcadectl/input", ReadOnly: true},
							{Name: "credentials", MountPath: "/arcadectl/credentials", ReadOnly: true},
							{Name: "work", MountPath: "/arcadectl/work"},
						},
						TerminationMessagePath: restoreworker.DefaultTerminationPath, TerminationMessagePolicy: corev1.TerminationMessageReadFile,
					}},
					Volumes: volumes,
				},
			},
		},
	}
	return DestroyResources{Input: inputConfig, ServiceAccount: serviceAccount, Role: role, RoleBinding: roleBinding, Job: job}, nil
}

// DestroyResourceName and DestroyWorkerLeaseName are retry-stable, operation-
// unique names. They intentionally do not derive from mutable object names.
func DestroyResourceName(uid types.UID) string {
	if uid == "" {
		return ""
	}
	digest := sha256.Sum256([]byte("arcadectl/destroy-job/" + string(uid)))
	return "destroy-" + hex.EncodeToString(digest[:16]) + "-preflight"
}

func DestroyWorkerLeaseName(uid types.UID) string {
	if uid == "" {
		return ""
	}
	digest := sha256.Sum256([]byte("arcadectl/destroy-worker/" + string(uid)))
	return "destroy-worker-" + hex.EncodeToString(digest[:16])
}

// DestroyOperationLeaseMatches proves the ownerless data-operation fence held
// by this exact destroy request. It must remain held across worker and PVC
// deletion; the Pod authorizer only reads this Lease and cannot update it.
func DestroyOperationLeaseMatches(lease *coordinationv1.Lease, operation arcadev1alpha1.ExactLocalReference, serverName, dataIdentity string) bool {
	if lease == nil || operation.Name == "" || operation.UID == "" || operation.Namespace != nil || serverName == "" || dataIdentity == "" ||
		len(lease.OwnerReferences) != 0 || lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity != operation.UID ||
		lease.Name != DataOperationLeaseName(dataIdentity) ||
		lease.Labels[LabelManagedBy] != ManagerName || lease.Labels[LabelDestroyUID] != operation.UID ||
		lease.Labels[LabelInstance] != serverName || lease.Labels[LabelDataIdentity] != dataIdentity ||
		lease.Annotations[AnnotationDestroyName] != operation.Name {
		return false
	}
	return true
}
