// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

// Package destroyauth releases one exact repository Secret revision to an
// authorized, repository-only destroy preflight Pod. It never reads world data.
package destroyauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	arcadev1alpha1 "github.com/gobha-me/arcadectl/api/v1alpha1"
	platformdata "github.com/gobha-me/arcadectl/internal/platform/data"
	platformkube "github.com/gobha-me/arcadectl/internal/platform/kube"
	"github.com/gobha-me/arcadectl/internal/restoreworker"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/retry"
)

const (
	DefaultInputPath               = restoreworker.DefaultInputPath
	DefaultOutputPath              = "/arcadectl/authorized-credentials"
	maxInputBytes                  = 1 << 20
	defaultExitCode                = 11
	executionExitCode              = 12
	annotationDestroyJobAuthorized = "arcade.gobha.me/destroy-job-authorized"
)

var (
	ErrExecutionOwned = errors.New("destroy worker execution is already owned")
	destroyResource   = schema.GroupVersionResource{Group: arcadev1alpha1.GroupVersion.Group, Version: arcadev1alpha1.GroupVersion.Version, Resource: "gamedestroys"}
	backupResource    = schema.GroupVersionResource{Group: arcadev1alpha1.GroupVersion.Group, Version: arcadev1alpha1.GroupVersion.Version, Resource: "gamebackups"}
)

type Config struct {
	InputPath  string
	OutputPath string
	Namespace  string
	PodName    string
	PodUID     string
	Now        func() time.Time
	Client     kubernetes.Interface
	GameClient dynamic.Interface
}

// Run checks live operation, backup, lease, and Secret authority both before
// and after the Pod-UID lease CAS. No credential bytes are returned in errors.
func Run(ctx context.Context, config Config) error {
	if config.InputPath == "" {
		config.InputPath = DefaultInputPath
	}
	if config.OutputPath == "" {
		config.OutputPath = DefaultOutputPath
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	input, err := readInput(config.InputPath)
	if err != nil {
		return errors.New("destroy authority input is invalid")
	}
	if config.Client == nil || config.GameClient == nil {
		clusterConfig, err := rest.InClusterConfig()
		if err != nil {
			return errors.New("destroy authority is unavailable")
		}
		if config.Client == nil {
			config.Client, err = kubernetes.NewForConfig(clusterConfig)
			if err != nil {
				return errors.New("destroy authority is unavailable")
			}
		}
		if config.GameClient == nil {
			config.GameClient, err = dynamic.NewForConfig(clusterConfig)
			if err != nil {
				return errors.New("destroy authority is unavailable")
			}
		}
	}
	namespace := config.Namespace
	if namespace == "" {
		namespace = os.Getenv("POD_NAMESPACE")
	}
	podUID := config.PodUID
	if podUID == "" {
		podUID = os.Getenv("POD_UID")
	}
	podName := config.PodName
	if podName == "" {
		podName = os.Getenv("POD_NAME")
	}
	if namespace == "" || podName == "" || podUID == "" {
		return errors.New("destroy worker identity is unavailable")
	}
	jobUID, dataIdentity, err := verifyPod(ctx, config.Client, namespace, podName, podUID, input)
	if err != nil {
		return errors.New("destroy Pod authority is unavailable")
	}
	if err := verifyAuthority(ctx, config, namespace, input, jobUID, dataIdentity); err != nil {
		return errors.New("destroy preflight authority is unavailable")
	}
	if err := claimExecution(ctx, config.Client, namespace, input, podUID, jobUID); err != nil {
		if errors.Is(err, ErrExecutionOwned) {
			return err
		}
		return errors.New("destroy worker execution authority is unavailable")
	}
	confirmedJobUID, confirmedDataIdentity, err := verifyPod(ctx, config.Client, namespace, podName, podUID, input)
	if err != nil || confirmedJobUID != jobUID || confirmedDataIdentity != dataIdentity {
		return errors.New("destroy Pod authority changed")
	}
	if err := verifyAuthority(ctx, config, namespace, input, jobUID, dataIdentity); err != nil {
		return errors.New("destroy preflight authority changed")
	}
	lease, err := config.Client.CoordinationV1().Leases(namespace).Get(ctx, input.WorkerLeaseName, metav1.GetOptions{})
	if err != nil || !workerLeaseMatches(lease, input, dataIdentity, jobUID) || lease.Annotations[platformkube.AnnotationWorkerPodUID] != podUID {
		return errors.New("destroy worker execution authority changed")
	}
	secret, err := config.Client.CoreV1().Secrets(namespace).Get(ctx, input.RepositorySecretRef.Name, metav1.GetOptions{})
	if err != nil || string(secret.UID) != input.RepositorySecretRef.UID || secret.ResourceVersion != input.RepositorySecretRef.ResourceVersion ||
		secret.Immutable == nil || !*secret.Immutable {
		return errors.New("exact repository Secret revision is unavailable")
	}
	if platformdata.ValidateRepositorySecretData(secret.Data) != nil {
		return errors.New("repository Secret contract is invalid")
	}
	return writeCredentials(config.OutputPath, secret.Data)
}

func ExitCode(err error) int {
	if errors.Is(err, ErrExecutionOwned) {
		return executionExitCode
	}
	return defaultExitCode
}

func readInput(name string) (restoreworker.Input, error) {
	contents, err := os.ReadFile(name)
	if err != nil || len(contents) == 0 || len(contents) > maxInputBytes {
		return restoreworker.Input{}, errors.New("input unavailable")
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var input restoreworker.Input
	if decoder.Decode(&input) != nil || decoder.Decode(&struct{}{}) != io.EOF ||
		restoreworker.ValidateInput(input) != nil || input.Stage != restoreworker.StagePreflight ||
		input.WorkerLeaseName == "" {
		return restoreworker.Input{}, errors.New("input invalid")
	}
	return input, nil
}

func verifyAuthority(ctx context.Context, config Config, namespace string, input restoreworker.Input, jobUID types.UID, dataIdentity string) error {
	object, err := config.GameClient.Resource(destroyResource).Namespace(namespace).Get(ctx, input.OperationRef.Name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	var destroy arcadev1alpha1.GameDestroy
	if runtime.DefaultUnstructuredConverter.FromUnstructured(object.Object, &destroy) != nil ||
		string(destroy.UID) != input.OperationRef.UID || !destroy.DeletionTimestamp.IsZero() ||
		destroy.Spec.Mode != arcadev1alpha1.DestroyModeVerifiedBackup || destroy.Spec.CancelRequested ||
		destroy.Status.Phase != arcadev1alpha1.DestroyPhaseVerifying || destroy.Status.ObservedGeneration != destroy.Generation ||
		destroy.Status.Preview == nil || destroy.Spec.ConfirmationChallenge == "" ||
		destroy.Spec.ConfirmationChallenge != destroy.Status.Preview.Challenge ||
		!config.Now().Before(destroy.Status.Preview.ExpiresAt.Time) ||
		destroy.Spec.BackupRef == nil || *destroy.Spec.BackupRef != input.BackupRef ||
		destroy.Spec.RepositorySecretRef == nil || *destroy.Spec.RepositorySecretRef != input.RepositorySecretRef ||
		destroy.Spec.Target.GameServer != input.Target.ExactLocalReference ||
		destroy.Spec.Target.Data.Identity == "" || destroy.Spec.Target.Data.Identity != dataIdentity ||
		input.WorkerLeaseName != platformkube.DestroyWorkerLeaseName(destroy.UID) ||
		!targetPathsMatch(destroy.Spec.Target, input) {
		return errors.New("destroy request changed")
	}
	backupObject, err := config.GameClient.Resource(backupResource).Namespace(namespace).Get(ctx, input.BackupRef.Name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	var backup arcadev1alpha1.GameBackup
	if runtime.DefaultUnstructuredConverter.FromUnstructured(backupObject.Object, &backup) != nil ||
		string(backup.UID) != input.BackupRef.UID || !backup.DeletionTimestamp.IsZero() ||
		backup.Status.Phase != arcadev1alpha1.DataPhaseSucceeded || backup.Status.Source == nil || backup.Status.Artifact == nil ||
		backup.Spec.RepositorySecretRef != input.RepositorySecretRef ||
		!reflect.DeepEqual(*backup.Status.Source, input.Source) || !reflect.DeepEqual(*backup.Status.Artifact, input.Artifact) ||
		input.Source.GameServer != input.Target || input.Source.GameServer.ExactLocalReference != destroy.Spec.Target.GameServer ||
		backup.Spec.Source != input.Source.GameServer {
		return errors.New("exact backup is unavailable")
	}
	lease, err := config.Client.CoordinationV1().Leases(namespace).Get(ctx, input.WorkerLeaseName, metav1.GetOptions{})
	if err != nil || !workerLeaseMatches(lease, input, destroy.Spec.Target.Data.Identity, jobUID) {
		return errors.New("destroy worker lease is unavailable")
	}
	worldLease, err := config.Client.CoordinationV1().Leases(namespace).Get(ctx, platformkube.DataOperationLeaseName(destroy.Spec.Target.Data.Identity), metav1.GetOptions{})
	if err != nil || !worldLeaseMatches(worldLease, input, destroy.Spec.Target.Data.Identity) {
		return errors.New("destroy data lease is unavailable")
	}
	return nil
}

func targetPathsMatch(target arcadev1alpha1.GameDestroyTarget, input restoreworker.Input) bool {
	if target.Game != input.Source.Game || len(target.Data.Claims) != len(input.Source.Paths) || len(input.TargetPaths) != len(input.Source.Paths) {
		return false
	}
	paths := make(map[string]arcadev1alpha1.ExactLocalReference, len(target.Data.Claims))
	for _, claim := range target.Data.Claims {
		if _, exists := paths[claim.Path]; exists {
			return false
		}
		paths[claim.Path] = claim.ClaimRef
	}
	for _, path := range input.Source.Paths {
		if paths[path.Name] != path.ClaimRef {
			return false
		}
		delete(paths, path.Name)
	}
	return len(paths) == 0
}

func verifyPod(ctx context.Context, client kubernetes.Interface, namespace, podName, podUID string, input restoreworker.Input) (types.UID, string, error) {
	pod, err := client.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
	if err != nil || pod == nil || string(pod.UID) != podUID || !pod.DeletionTimestamp.IsZero() ||
		len(pod.OwnerReferences) != 1 || len(pod.Spec.SchedulingGates) != 0 ||
		pod.Spec.AutomountServiceAccountToken == nil || *pod.Spec.AutomountServiceAccountToken ||
		pod.Spec.ServiceAccountName != platformkube.DestroyResourceName(types.UID(input.OperationRef.UID))+"-authority" ||
		len(pod.Spec.InitContainers) != 1 || pod.Spec.InitContainers[0].Name != "destroy-authorizer" ||
		len(pod.Spec.Containers) != 1 || pod.Spec.Containers[0].Name != "destroy-worker" ||
		pod.Labels[platformkube.LabelManagedBy] != platformkube.ManagerName ||
		pod.Labels[platformkube.LabelName] != "destroy-worker" ||
		pod.Labels[platformkube.LabelDestroyUID] != input.OperationRef.UID ||
		pod.Labels[platformkube.LabelDestroyStage] != string(restoreworker.StagePreflight) ||
		pod.Labels[platformkube.LabelDataOperation] != "destroy" ||
		pod.Labels[platformkube.LabelDataIdentity] == "" ||
		pod.Labels[platformkube.LabelInstance] != input.Target.Name ||
		pod.Annotations[platformkube.AnnotationDestroyName] != input.OperationRef.Name ||
		pod.Annotations[platformkube.AnnotationArtifactID] != input.Artifact.ID ||
		pod.Annotations[platformkube.AnnotationDestroyPodAuthorized] != podUID {
		return "", "", errors.New("exact approved destroy Pod is unavailable")
	}
	owner := pod.OwnerReferences[0]
	if owner.APIVersion != "batch/v1" || owner.Kind != "Job" || owner.Name != platformkube.DestroyResourceName(types.UID(input.OperationRef.UID)) ||
		owner.UID == "" || owner.Controller == nil || !*owner.Controller {
		return "", "", errors.New("destroy Pod Job ownership is invalid")
	}
	// A worker must not inherit a source PVC even through an unexpected
	// admission mutation. The repository-only Pod has only ephemeral volumes.
	for _, volume := range pod.Spec.Volumes {
		if volume.PersistentVolumeClaim != nil || volume.Ephemeral != nil || volume.CSI != nil || volume.HostPath != nil || volume.NFS != nil || volume.Secret != nil {
			return "", "", errors.New("destroy Pod has an unsafe volume")
		}
	}
	for _, container := range append(append([]corev1.Container{}, pod.Spec.InitContainers...), pod.Spec.Containers...) {
		for _, mount := range container.VolumeMounts {
			if mount.MountPath == restoreworker.DefaultSourceRoot || strings.HasPrefix(mount.MountPath, restoreworker.DefaultSourceRoot+"/") ||
				mount.MountPath == restoreworker.DefaultCandidateRoot || strings.HasPrefix(mount.MountPath, restoreworker.DefaultCandidateRoot+"/") {
				return "", "", errors.New("destroy Pod has a world mount")
			}
		}
	}
	for _, mount := range pod.Spec.Containers[0].VolumeMounts {
		if mount.Name == "authority" || mount.MountPath == "/var/run/secrets/kubernetes.io/serviceaccount" {
			return "", "", errors.New("destroy worker received an API token")
		}
	}
	return owner.UID, pod.Labels[platformkube.LabelDataIdentity], nil
}

func workerLeaseMatches(lease *coordinationv1.Lease, input restoreworker.Input, identity string, jobUID types.UID) bool {
	if lease == nil || len(lease.OwnerReferences) != 1 {
		return false
	}
	owner := lease.OwnerReferences[0]
	return lease.Name == input.WorkerLeaseName && owner.APIVersion == arcadev1alpha1.GroupVersion.String() &&
		owner.Kind == "GameDestroy" && owner.Name == input.OperationRef.Name && string(owner.UID) == input.OperationRef.UID &&
		lease.Spec.HolderIdentity != nil && *lease.Spec.HolderIdentity == input.OperationRef.UID &&
		lease.Labels[platformkube.LabelManagedBy] == platformkube.ManagerName &&
		lease.Labels[platformkube.LabelInstance] == input.Target.Name &&
		lease.Labels[platformkube.LabelDestroyUID] == input.OperationRef.UID &&
		(identity == "" || lease.Labels[platformkube.LabelDataIdentity] == identity) &&
		lease.Annotations[platformkube.AnnotationDestroyName] == input.OperationRef.Name &&
		lease.Annotations[annotationDestroyJobAuthorized] == string(jobUID)
}

func worldLeaseMatches(lease *coordinationv1.Lease, input restoreworker.Input, identity string) bool {
	return lease != nil && lease.Name == platformkube.DataOperationLeaseName(identity) && len(lease.OwnerReferences) == 0 &&
		lease.Spec.HolderIdentity != nil && *lease.Spec.HolderIdentity == input.OperationRef.UID &&
		lease.Labels[platformkube.LabelManagedBy] == platformkube.ManagerName &&
		lease.Labels[platformkube.LabelInstance] == input.Target.Name &&
		lease.Labels[platformkube.LabelDataIdentity] == identity &&
		lease.Labels[platformkube.LabelDestroyUID] == input.OperationRef.UID &&
		lease.Annotations[platformkube.AnnotationDestroyName] == input.OperationRef.Name
}

func claimExecution(ctx context.Context, client kubernetes.Interface, namespace string, input restoreworker.Input, podUID string, jobUID types.UID) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		lease, err := client.CoordinationV1().Leases(namespace).Get(ctx, input.WorkerLeaseName, metav1.GetOptions{})
		if err != nil || !workerLeaseMatches(lease, input, "", jobUID) {
			return errors.New("exact destroy lease is unavailable")
		}
		if holder := lease.Annotations[platformkube.AnnotationWorkerPodUID]; holder != "" {
			if holder == podUID {
				return nil
			}
			return ErrExecutionOwned
		}
		updated := lease.DeepCopy()
		if updated.Annotations == nil {
			updated.Annotations = make(map[string]string)
		}
		updated.Annotations[platformkube.AnnotationWorkerPodUID] = podUID
		_, err = client.CoordinationV1().Leases(namespace).Update(ctx, updated, metav1.UpdateOptions{})
		return err
	})
}

func writeCredentials(directory string, data map[string][]byte) error {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return errors.New("authorized credential directory is unavailable")
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 {
		return errors.New("authorized credential directory is not empty")
	}
	for key, value := range data {
		file, err := os.OpenFile(filepath.Join(directory, key), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o400)
		if err != nil {
			return errors.New("authorized credential materialization failed")
		}
		_, writeErr := file.Write(value)
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			return errors.New("authorized credential materialization failed")
		}
	}
	return nil
}
