// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

// Package backupauth materializes one exact repository Secret revision for a
// backup worker and proves that every already-mounted PVC still has the UID
// recorded by the controller. It runs as a short-lived init container with a
// resourceName-scoped API token; the backup container never receives that
// token and the controller never receives credential bytes.
package backupauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	platformdata "github.com/gobha-me/arcadectl/internal/platform/data"
	platformkube "github.com/gobha-me/arcadectl/internal/platform/kube"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

// ErrExecutionOwned identifies a live worker overlap. The authorizer returns a
// distinct process code so the controller can remove every old Pod before a
// serialized retry instead of misreporting a credential failure.
var ErrExecutionOwned = errors.New("backup worker execution is already owned")

// Config permits hermetic tests while production uses in-cluster authority.
type Config struct {
	InputPath  string
	OutputPath string
	Namespace  string
	PodUID     string
	Client     kubernetes.Interface
}

// Run authorizes exact API objects and copies only the exact Secret response
// into the worker Pod's private EmptyDir.
func Run(ctx context.Context, config Config) error {
	if config.InputPath == "" {
		config.InputPath = DefaultInputPath
	}
	if config.OutputPath == "" {
		config.OutputPath = DefaultOutputPath
	}
	input, err := readInput(config.InputPath)
	if err != nil {
		return errors.New("backup authority input is invalid")
	}
	if config.Client == nil {
		clusterConfig, err := rest.InClusterConfig()
		if err != nil {
			return errors.New("backup authority is unavailable")
		}
		config.Client, err = kubernetes.NewForConfig(clusterConfig)
		if err != nil {
			return errors.New("backup authority is unavailable")
		}
	}
	namespace := config.Namespace
	if namespace == "" {
		namespace = os.Getenv("POD_NAMESPACE")
	}
	if namespace == "" {
		return errors.New("backup authority namespace is unavailable")
	}
	podUID := config.PodUID
	if podUID == "" {
		podUID = os.Getenv("POD_UID")
	}
	if podUID == "" {
		return errors.New("backup worker identity is unavailable")
	}
	if err := acquireWorkerExecution(ctx, config.Client, namespace, input, podUID); err != nil {
		if errors.Is(err, ErrExecutionOwned) {
			return ErrExecutionOwned
		}
		return errors.New("backup worker execution authority is unavailable")
	}
	secret, err := config.Client.CoreV1().Secrets(namespace).Get(ctx, input.RepositorySecretRef.Name, metav1.GetOptions{})
	if err != nil || string(secret.UID) != input.RepositorySecretRef.UID || secret.ResourceVersion != input.RepositorySecretRef.ResourceVersion || secret.Immutable == nil || !*secret.Immutable {
		return errors.New("exact repository Secret revision is unavailable")
	}
	if err := platformdata.ValidateRepositorySecretData(secret.Data); err != nil {
		return errors.New("repository Secret contract is invalid")
	}
	for _, path := range input.Source.Paths {
		claim, err := config.Client.CoreV1().PersistentVolumeClaims(namespace).Get(ctx, path.ClaimRef.Name, metav1.GetOptions{})
		if err != nil || string(claim.UID) != path.ClaimRef.UID || claim.Status.Phase != corev1.ClaimBound || claim.Spec.VolumeName == "" {
			return errors.New("exact source claim is unavailable")
		}
	}
	return writeCredentials(config.OutputPath, secret.Data)
}

// ExitCode maps authority failures to the intentionally small public process
// contract consumed by the controller. Errors never include credentials.
func ExitCode(err error) int {
	if errors.Is(err, ErrExecutionOwned) {
		return executionExitCode
	}
	return defaultExitCode
}

func acquireWorkerExecution(ctx context.Context, client kubernetes.Interface, namespace string, input platformdata.BackupWorkerInput, podUID string) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		lease, err := client.CoordinationV1().Leases(namespace).Get(ctx, input.WorkerLeaseName, metav1.GetOptions{})
		if err != nil || !authorizedWorkerLease(lease, input) {
			return errors.New("exact worker lease is unavailable")
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

func authorizedWorkerLease(lease *coordinationv1.Lease, input platformdata.BackupWorkerInput) bool {
	return platformkube.BackupOperationLeaseMatches(lease, input.OperationRef, input.Source.GameServer.Name)
}

func readInput(name string) (platformdata.BackupWorkerInput, error) {
	contents, err := os.ReadFile(name)
	if err != nil || len(contents) == 0 || len(contents) > maxInputBytes {
		return platformdata.BackupWorkerInput{}, errors.New("input is unavailable")
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var input platformdata.BackupWorkerInput
	if err := decoder.Decode(&input); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return platformdata.BackupWorkerInput{}, errors.New("input is invalid")
	}
	if err := platformdata.ValidateBackupWorkerInput(input); err != nil {
		return platformdata.BackupWorkerInput{}, err
	}
	return input, nil
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
		name := filepath.Join(directory, key)
		file, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o400)
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
