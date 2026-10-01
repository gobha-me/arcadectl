// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

// Package restoreauth releases one exact repository Secret revision only to
// an authorized restore Pod. Populate additionally proves the previous world
// is selected, observed, stopped, and fenced before candidate PVCs can be
// written. The worker container receives no Kubernetes API token.
package restoreauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

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
	DefaultInputPath  = "/arcadectl/input/input.json"
	DefaultOutputPath = "/arcadectl/authorized-credentials"
	maxInputBytes     = 1 << 20
	defaultExitCode   = 11
	executionExitCode = 12
)

var (
	// ErrExecutionOwned lets the controller distinguish overlapping Pods from
	// a repository credential failure and serialize their cleanup.
	ErrExecutionOwned  = errors.New("restore worker execution is already owned")
	gameServerResource = schema.GroupVersionResource{
		Group: arcadev1alpha1.GroupVersion.Group, Version: arcadev1alpha1.GroupVersion.Version, Resource: "gameservers",
	}
)

type Config struct {
	InputPath  string
	OutputPath string
	Namespace  string
	PodUID     string
	Client     kubernetes.Interface
	GameClient dynamic.Interface
}

// Run performs the complete live authority check before copying credential
// bytes into the Pod-private EmptyDir. A preflight Pod never reads a target
// GameServer or PVC; it has no target volume mount.
func Run(ctx context.Context, config Config) error {
	if config.InputPath == "" {
		config.InputPath = DefaultInputPath
	}
	if config.OutputPath == "" {
		config.OutputPath = DefaultOutputPath
	}
	input, err := readInput(config.InputPath)
	if err != nil {
		return errors.New("restore authority input is invalid")
	}
	if config.Client == nil || (config.GameClient == nil && input.Stage == restoreworker.StagePopulate) {
		clusterConfig, err := rest.InClusterConfig()
		if err != nil {
			return errors.New("restore authority is unavailable")
		}
		if config.Client == nil {
			config.Client, err = kubernetes.NewForConfig(clusterConfig)
			if err != nil {
				return errors.New("restore authority is unavailable")
			}
		}
		if config.GameClient == nil && input.Stage == restoreworker.StagePopulate {
			config.GameClient, err = dynamic.NewForConfig(clusterConfig)
			if err != nil {
				return errors.New("restore authority is unavailable")
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
	if namespace == "" || podUID == "" {
		return errors.New("restore worker identity is unavailable")
	}
	candidateIdentity, err := platformdata.RestoreDataIdentity(types.UID(input.OperationRef.UID))
	if err != nil || candidateIdentity == input.PreviousDataIdentity ||
		input.WorkerLeaseName != platformkube.DataOperationLeaseName(candidateIdentity) {
		return errors.New("restore worker lease identity is invalid")
	}
	if input.Stage == restoreworker.StagePopulate {
		if err := verifyPopulateBoundary(ctx, config, namespace, input, candidateIdentity, ""); err != nil {
			return errors.New("restore target authority is unavailable")
		}
	}
	if err := acquireWorkerExecution(ctx, config.Client, namespace, input, candidateIdentity, podUID); err != nil {
		if errors.Is(err, ErrExecutionOwned) {
			return ErrExecutionOwned
		}
		return errors.New("restore worker execution authority is unavailable")
	}
	lease, err := config.Client.CoordinationV1().Leases(namespace).Get(ctx, input.WorkerLeaseName, metav1.GetOptions{})
	if err != nil || !authorizedLease(lease, input, candidateIdentity) || lease.Annotations[platformkube.AnnotationWorkerPodUID] != podUID {
		return errors.New("restore worker execution authority changed")
	}
	// Re-read mutable target state after the lease CAS. Credentials remain
	// unreleased if a claim or the stopped selection changed meanwhile.
	if input.Stage == restoreworker.StagePopulate {
		if err := verifyPopulateBoundary(ctx, config, namespace, input, candidateIdentity, podUID); err != nil {
			return errors.New("restore target authority changed")
		}
	}
	secret, err := config.Client.CoreV1().Secrets(namespace).Get(ctx, input.RepositorySecretRef.Name, metav1.GetOptions{})
	if err != nil || string(secret.UID) != input.RepositorySecretRef.UID ||
		secret.ResourceVersion != input.RepositorySecretRef.ResourceVersion || secret.Immutable == nil || !*secret.Immutable {
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
	if decoder.Decode(&input) != nil || decoder.Decode(&struct{}{}) != io.EOF || restoreworker.ValidateInput(input) != nil {
		return restoreworker.Input{}, errors.New("input invalid")
	}
	return input, nil
}

func acquireWorkerExecution(ctx context.Context, client kubernetes.Interface, namespace string, input restoreworker.Input, candidateIdentity, podUID string) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		lease, err := client.CoordinationV1().Leases(namespace).Get(ctx, input.WorkerLeaseName, metav1.GetOptions{})
		if err != nil || !authorizedLease(lease, input, candidateIdentity) {
			return errors.New("exact candidate lease is unavailable")
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

func authorizedLease(lease *coordinationv1.Lease, input restoreworker.Input, dataIdentity string) bool {
	return platformkube.RestoreOperationLeaseMatches(lease, input.OperationRef, input.Target.Name, dataIdentity)
}

func verifyPopulateBoundary(ctx context.Context, config Config, namespace string, input restoreworker.Input, candidateIdentity, authorizedPodUID string) error {
	previousLease, err := config.Client.CoordinationV1().Leases(namespace).Get(ctx, platformkube.DataOperationLeaseName(input.PreviousDataIdentity), metav1.GetOptions{})
	if err != nil || !authorizedLease(previousLease, input, input.PreviousDataIdentity) {
		return errors.New("previous world is not fenced")
	}
	candidateLease, err := config.Client.CoordinationV1().Leases(namespace).Get(ctx, input.WorkerLeaseName, metav1.GetOptions{})
	if err != nil || !authorizedLease(candidateLease, input, candidateIdentity) {
		return errors.New("candidate world is not fenced")
	}
	if authorizedPodUID != "" && candidateLease.Annotations[platformkube.AnnotationWorkerPodUID] != authorizedPodUID {
		return errors.New("candidate worker execution changed ownership")
	}
	object, err := config.GameClient.Resource(gameServerResource).Namespace(namespace).Get(ctx, input.Target.Name, metav1.GetOptions{})
	if err != nil {
		return errors.New("target GameServer is unavailable")
	}
	var server arcadev1alpha1.GameServer
	if runtime.DefaultUnstructuredConverter.FromUnstructured(object.Object, &server) != nil ||
		string(server.UID) != input.Target.UID || !server.DeletionTimestamp.IsZero() ||
		server.Spec.DesiredState != arcadev1alpha1.DesiredStateStopped || server.Status.Phase != arcadev1alpha1.PhaseStopped ||
		server.Status.ObservedGeneration != server.Generation || !stoppedGenerationMatches(input.Target, server.Generation) ||
		!referenceMatches(server.Status.ObservedData, input.PreviousDataIdentity, input.PreviousData) {
		return errors.New("target GameServer no longer selects the stopped previous world")
	}
	selected := server.Status.ActiveData
	if selected == nil {
		selected = server.Spec.Storage.Reattach
	}
	if selected == nil {
		selected = server.Status.ObservedData
	}
	if !referenceMatches(selected, input.PreviousDataIdentity, input.PreviousData) {
		return errors.New("target GameServer selected data changed")
	}
	volumes := make(map[string]struct{}, len(input.PreviousData)+len(input.CandidatePaths))
	for _, path := range input.PreviousData {
		if err := verifyClaim(ctx, config.Client, namespace, path, input.PreviousDataIdentity, "", volumes); err != nil {
			return err
		}
	}
	for _, path := range input.CandidatePaths {
		if err := verifyClaim(ctx, config.Client, namespace, path, candidateIdentity, input.OperationRef.UID, volumes); err != nil {
			return err
		}
	}
	return nil
}

func stoppedGenerationMatches(target arcadev1alpha1.ExactGameServerReference, generation int64) bool {
	want := target.Generation
	if target.DesiredState == arcadev1alpha1.DesiredStateRunning {
		want++
	}
	return generation == want
}

func referenceMatches(reference *arcadev1alpha1.RetainedDataReference, identity string, paths []arcadev1alpha1.DataPathIdentity) bool {
	if reference == nil || reference.Identity != identity || len(reference.Claims) != len(paths) || len(paths) == 0 {
		return false
	}
	want := make(map[string]arcadev1alpha1.ExactLocalReference, len(paths))
	for _, path := range paths {
		if _, duplicate := want[path.Name]; duplicate {
			return false
		}
		want[path.Name] = path.ClaimRef
	}
	for _, claim := range reference.Claims {
		ref, exists := want[claim.Path]
		if !exists || claim.ClaimRef != ref {
			return false
		}
		delete(want, claim.Path)
	}
	return len(want) == 0
}

func verifyClaim(ctx context.Context, client kubernetes.Interface, namespace string, path arcadev1alpha1.DataPathIdentity, identity, restoreUID string, volumes map[string]struct{}) error {
	claim, err := client.CoreV1().PersistentVolumeClaims(namespace).Get(ctx, path.ClaimRef.Name, metav1.GetOptions{})
	if err != nil || string(claim.UID) != path.ClaimRef.UID || !claim.DeletionTimestamp.IsZero() ||
		len(claim.OwnerReferences) != 0 || claim.Status.Phase != corev1.ClaimBound || claim.Spec.VolumeName == "" ||
		claim.Labels[platformkube.LabelManagedBy] != platformkube.ManagerName ||
		claim.Labels[platformkube.LabelName] != "game-data" || claim.Labels[platformkube.LabelDataPolicy] != "retain" ||
		claim.Labels[platformkube.LabelDataIdentity] != identity || claim.Labels[platformkube.LabelDataPath] != path.Name {
		return errors.New("exact retained claim is unavailable")
	}
	if restoreUID != "" && claim.Labels[platformkube.LabelRestoreUID] != restoreUID {
		return errors.New("candidate claim belongs to another restore")
	}
	if _, alias := volumes[claim.Spec.VolumeName]; alias {
		return errors.New("candidate and previous claims alias a PV")
	}
	volumes[claim.Spec.VolumeName] = struct{}{}
	return nil
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
