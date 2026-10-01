// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package kube

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	arcadev1alpha1 "github.com/gobha-me/arcadectl/api/v1alpha1"
	platformdata "github.com/gobha-me/arcadectl/internal/platform/data"
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
	LabelRestoreUID                = "arcade.gobha.me/restore-uid"
	LabelRestoreStage              = "arcade.gobha.me/restore-stage"
	AnnotationRestoreName          = "arcade.gobha.me/restore-name"
	AnnotationRestorePodAuthorized = "arcade.gobha.me/restore-pod-authorized"
	AnnotationRestoreSettlementData = "arcade.gobha.me/restore-settlement-data-identity"
	RestoreFinalizer               = "arcade.gobha.me/restore-protection"
	RestoreSchedulingGate          = "arcade.gobha.me/restore-authorized"
	restoreInputKey                = "input.json"
)

// RestoreResources are deliberately stage-specific. Preflight has no PVC
// resources at all; Populate references only exact fresh candidate claims.
type RestoreResources struct {
	Input          *corev1.ConfigMap
	ServiceAccount *corev1.ServiceAccount
	Role           *rbacv1.Role
	RoleBinding    *rbacv1.RoleBinding
	Job            *batchv1.Job
}

// BuildRestoreResources creates a deterministic, inert worker boundary. The
// controller must read back exact Job and admitted Pod specs before unsuspending
// or removing the scheduling gate. The short-lived init container alone can
// GET the exact repository Secret revision and atomically claim the worker
// Lease; the Restic container never receives a Kubernetes API token.
func BuildRestoreResources(restore *arcadev1alpha1.GameRestore, input restoreworker.Input, workerImage string, identity game.RuntimeIdentity) (RestoreResources, error) {
	if restore == nil || restore.Name == "" || restore.Namespace == "" || restore.UID == "" ||
		len(validation.IsDNS1123Label(restore.Namespace)) != 0 {
		return RestoreResources{}, errors.New("exact namespaced GameRestore identity is required")
	}
	if !pinnedWorkerImagePattern.MatchString(workerImage) {
		return RestoreResources{}, errors.New("restore worker image must be pinned by sha256 digest")
	}
	if identity.UserID <= 0 || identity.GroupID <= 0 || identity.FSGroup <= 0 {
		return RestoreResources{}, errors.New("restore worker identity must be non-root")
	}
	if err := restoreworker.ValidateInput(input); err != nil ||
		input.OperationRef != (arcadev1alpha1.ExactLocalReference{Name: restore.Name, UID: string(restore.UID)}) ||
		input.BackupRef != restore.Spec.BackupRef || input.Target != restore.Spec.Target ||
		input.RepositorySecretRef != restore.Spec.RepositorySecretRef {
		return RestoreResources{}, errors.New("restore worker input does not match the exact operation")
	}
	candidateIdentity, err := platformdata.RestoreDataIdentity(restore.UID)
	if err != nil || input.WorkerLeaseName != DataOperationLeaseName(candidateIdentity) ||
		(input.Stage == restoreworker.StagePopulate && input.PreviousDataIdentity == candidateIdentity) {
		return RestoreResources{}, errors.New("restore worker leases do not identify distinct exact data sets")
	}
	input.TargetPaths = slices.Clone(input.TargetPaths)
	slices.SortFunc(input.TargetPaths, func(left, right restoreworker.PathContract) int {
		return compareName(left.Name, right.Name)
	})
	input.CandidatePaths = slices.Clone(input.CandidatePaths)
	slices.SortFunc(input.CandidatePaths, func(left, right arcadev1alpha1.DataPathIdentity) int {
		return compareName(left.Name, right.Name)
	})
	contents, err := json.Marshal(input)
	if err != nil {
		return RestoreResources{}, errors.New("encode restore worker input")
	}
	contents = append(contents, '\n')
	name := RestoreResourceName(restore.UID, input.Stage)
	if name == "" {
		return RestoreResources{}, errors.New("restore worker stage is invalid")
	}
	authorityName := name + "-authority"
	owner := metav1.OwnerReference{
		APIVersion: arcadev1alpha1.GroupVersion.String(), Kind: "GameRestore", Name: restore.Name, UID: restore.UID,
		Controller: ptr.To(true), BlockOwnerDeletion: ptr.To(true),
	}
	labels := map[string]string{
		LabelManagedBy: ManagerName, LabelName: "restore-worker", LabelRestoreUID: string(restore.UID),
		LabelRestoreStage: string(input.Stage), LabelDataOperation: "restore", LabelInstance: restore.Spec.Target.Name,
	}
	annotations := map[string]string{AnnotationArtifactID: input.Artifact.ID, AnnotationRestoreName: restore.Name}
	inputConfig := &corev1.ConfigMap{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"},
		ObjectMeta: metav1.ObjectMeta{Name: name + "-input", Namespace: restore.Namespace, Labels: cloneMap(labels), OwnerReferences: []metav1.OwnerReference{owner}},
		Data:       map[string]string{restoreInputKey: string(contents)}, Immutable: ptr.To(true),
	}
	serviceAccount := &corev1.ServiceAccount{
		ObjectMeta:                   metav1.ObjectMeta{Name: authorityName, Namespace: restore.Namespace, Labels: cloneMap(labels), OwnerReferences: []metav1.OwnerReference{owner}},
		AutomountServiceAccountToken: ptr.To(false),
	}
	rules := []rbacv1.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"secrets"}, ResourceNames: []string{input.RepositorySecretRef.Name}, Verbs: []string{"get"}},
		{APIGroups: []string{coordinationv1.GroupName}, Resources: []string{"leases"}, ResourceNames: []string{input.WorkerLeaseName}, Verbs: []string{"get", "update"}},
	}
	if input.Stage == restoreworker.StagePopulate {
		claims := make([]string, 0, len(input.CandidatePaths)+len(input.PreviousData))
		for _, path := range input.CandidatePaths {
			claims = append(claims, path.ClaimRef.Name)
		}
		for _, path := range input.PreviousData {
			claims = append(claims, path.ClaimRef.Name)
		}
		slices.Sort(claims)
		rules = append(rules,
			rbacv1.PolicyRule{APIGroups: []string{coordinationv1.GroupName}, Resources: []string{"leases"}, ResourceNames: []string{DataOperationLeaseName(input.PreviousDataIdentity)}, Verbs: []string{"get"}},
			rbacv1.PolicyRule{APIGroups: []string{arcadev1alpha1.GroupVersion.Group}, Resources: []string{"gameservers"}, ResourceNames: []string{input.Target.Name}, Verbs: []string{"get"}},
			rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"persistentvolumeclaims"}, ResourceNames: claims, Verbs: []string{"get"}},
		)
	}
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{Name: authorityName, Namespace: restore.Namespace, Labels: cloneMap(labels), OwnerReferences: []metav1.OwnerReference{owner}},
		Rules:      rules,
	}
	roleBinding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: authorityName, Namespace: restore.Namespace, Labels: cloneMap(labels), OwnerReferences: []metav1.OwnerReference{owner}},
		Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", APIGroup: "", Name: authorityName, Namespace: restore.Namespace}},
		RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: authorityName},
	}
	volumes := []corev1.Volume{
		{Name: "input", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: inputConfig.Name}, DefaultMode: ptr.To[int32](0o444)}}},
		{Name: "credentials", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{Medium: corev1.StorageMediumMemory, SizeLimit: ptr.To(resource.MustParse("2Mi"))}}},
		{Name: "work", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{SizeLimit: ptr.To(resource.MustParse("512Mi"))}}},
		{Name: "authority", VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{
			DefaultMode: ptr.To[int32](0o444), Sources: []corev1.VolumeProjection{
				{ServiceAccountToken: &corev1.ServiceAccountTokenProjection{Path: "token", ExpirationSeconds: ptr.To[int64](600)}},
				{ConfigMap: &corev1.ConfigMapProjection{LocalObjectReference: corev1.LocalObjectReference{Name: "kube-root-ca.crt"}, Items: []corev1.KeyToPath{{Key: "ca.crt", Path: "ca.crt"}}}},
			},
		}}},
	}
	workerMounts := []corev1.VolumeMount{
		{Name: "input", MountPath: "/arcadectl/input", ReadOnly: true},
		{Name: "credentials", MountPath: "/arcadectl/credentials", ReadOnly: true},
		{Name: "work", MountPath: "/arcadectl/work"},
	}
	if input.Stage == restoreworker.StagePopulate {
		for index, path := range input.CandidatePaths {
			volumeName := fmt.Sprintf("candidate-%d", index)
			volumes = append(volumes, corev1.Volume{
				Name:         volumeName,
				VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: path.ClaimRef.Name}},
			})
			workerMounts = append(workerMounts, corev1.VolumeMount{Name: volumeName, MountPath: restoreworker.DefaultCandidateRoot + "/" + path.Name})
		}
	}
	podSecurity := &corev1.PodSecurityContext{
		RunAsNonRoot: ptr.To(true), RunAsUser: ptr.To(identity.UserID), RunAsGroup: ptr.To(identity.GroupID),
		SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
	}
	if input.Stage == restoreworker.StagePopulate {
		// Kubelet may make only the fresh candidate volumes writable by the
		// certified game identity. No active/previous claim is in this Pod.
		podSecurity.FSGroup = ptr.To(identity.FSGroup)
		podSecurity.FSGroupChangePolicy = ptr.To(corev1.FSGroupChangeOnRootMismatch)
	} else {
		podSecurity.SupplementalGroups = []int64{identity.FSGroup}
	}
	job := &batchv1.Job{
		TypeMeta:   metav1.TypeMeta{APIVersion: "batch/v1", Kind: "Job"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: restore.Namespace, Labels: cloneMap(labels), Annotations: cloneMap(annotations), OwnerReferences: []metav1.OwnerReference{owner}},
		Spec: batchv1.JobSpec{
			BackoffLimit: ptr.To[int32](0), ActiveDeadlineSeconds: ptr.To[int64](3600),
			Parallelism: ptr.To[int32](1), Completions: ptr.To[int32](1), Suspend: ptr.To(true),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: cloneMap(labels), Annotations: cloneMap(annotations)},
				Spec: corev1.PodSpec{
					Hostname: name, ServiceAccountName: authorityName, AutomountServiceAccountToken: ptr.To(false), RestartPolicy: corev1.RestartPolicyNever,
					SchedulingGates: []corev1.PodSchedulingGate{{Name: RestoreSchedulingGate}}, SecurityContext: podSecurity,
					InitContainers: []corev1.Container{{
						Name: "restore-authorizer", Image: workerImage, ImagePullPolicy: corev1.PullIfNotPresent,
						Command: []string{"/arcadectl-restore-authorizer"},
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
						Name: "restore-worker", Image: workerImage, ImagePullPolicy: corev1.PullIfNotPresent,
						Command: []string{"/arcadectl-restore-worker"},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("100m"), corev1.ResourceMemory: resource.MustParse("128Mi"), corev1.ResourceEphemeralStorage: resource.MustParse("64Mi")},
							Limits:   corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("500m"), corev1.ResourceMemory: resource.MustParse("512Mi"), corev1.ResourceEphemeralStorage: resource.MustParse("768Mi")},
						},
						SecurityContext: &corev1.SecurityContext{AllowPrivilegeEscalation: ptr.To(false), ReadOnlyRootFilesystem: ptr.To(true), Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}},
						VolumeMounts:    workerMounts, TerminationMessagePath: restoreworker.DefaultTerminationPath, TerminationMessagePolicy: corev1.TerminationMessageReadFile,
					}},
					Volumes: volumes,
				},
			},
		},
	}
	return RestoreResources{Input: inputConfig, ServiceAccount: serviceAccount, Role: role, RoleBinding: roleBinding, Job: job}, nil
}

func compareName(left, right string) int {
	if left < right {
		return -1
	}
	if left > right {
		return 1
	}
	return 0
}

// RestoreResourceName derives distinct stable Job names for each stage and
// every retry of a GameRestore UID.
func RestoreResourceName(uid types.UID, stage restoreworker.Stage) string {
	if uid == "" {
		return ""
	}
	var suffix string
	switch stage {
	case restoreworker.StagePreflight:
		suffix = "preflight"
	case restoreworker.StagePopulate:
		suffix = "populate"
	default:
		return ""
	}
	digest := sha256.Sum256([]byte("arcadectl/restore-job/" + string(uid) + "/" + suffix))
	return "restore-" + hex.EncodeToString(digest[:16]) + "-" + suffix
}

// RestoreOperationLeaseMatches proves the ownerless candidate-data Lease
// authorizing one restore worker. It remains after foreground deletion until
// worker and runtime settlement are complete.
func RestoreOperationLeaseMatches(lease *coordinationv1.Lease, operation arcadev1alpha1.ExactLocalReference, serverName, dataIdentity string) bool {
	if lease == nil || operation.Name == "" || operation.UID == "" || operation.Namespace != nil || serverName == "" || dataIdentity == "" ||
		len(lease.OwnerReferences) != 0 || lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity != operation.UID ||
		lease.Labels[LabelManagedBy] != ManagerName || lease.Labels[LabelRestoreUID] != operation.UID ||
		lease.Labels[LabelInstance] != serverName || lease.Labels[LabelDataIdentity] != dataIdentity ||
		lease.Annotations[AnnotationRestoreName] != operation.Name {
		return false
	}
	return lease.Name == DataOperationLeaseName(dataIdentity)
}
