// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

// Package admincredential implements the trusted single-install administrator
// credential workflow. It is not an ordinary API client or namespace selector.
package admincredential

import (
	"context"
	"errors"
	"math"
	"reflect"
	"time"

	"github.com/gobha-me/arcadectl/internal/adminauth"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes"
)

const (
	apiDeploymentName = "arcadectl-api"
	apiServiceName    = "arcadectl-api"
)

var (
	ErrInvalidManagedSecret = errors.New("managed credential Secret is invalid")
	ErrCredentialConflict   = errors.New("credential mutation conflict")
	ErrMutationUnconfirmed  = errors.New("credential mutation outcome is unconfirmed; private output retained")
	ErrActivationIncomplete = errors.New("credential committed but activation is incomplete; private output retained")
	ErrTopologyUnavailable  = errors.New("the API does not have exactly one settled serving replica")
)

type ClusterAccess interface {
	GetSecret(context.Context) (*corev1.Secret, error)
	CreateSecret(context.Context, *corev1.Secret) (*corev1.Secret, error)
	UpdateSecret(context.Context, *corev1.Secret) (*corev1.Secret, error)
	GetDeployment(context.Context) (*appsv1.Deployment, error)
	ListEndpointSlices(context.Context) (*discoveryv1.EndpointSliceList, error)
}

type clientGoAccess struct {
	client    kubernetes.Interface
	namespace string
}

func (access clientGoAccess) GetSecret(ctx context.Context) (*corev1.Secret, error) {
	return access.client.CoreV1().Secrets(access.namespace).Get(ctx, adminauth.CredentialSecretName, metav1.GetOptions{})
}

func (access clientGoAccess) CreateSecret(ctx context.Context, secret *corev1.Secret) (*corev1.Secret, error) {
	return access.client.CoreV1().Secrets(access.namespace).Create(ctx, secret, metav1.CreateOptions{})
}

func (access clientGoAccess) UpdateSecret(ctx context.Context, secret *corev1.Secret) (*corev1.Secret, error) {
	return access.client.CoreV1().Secrets(access.namespace).Update(ctx, secret, metav1.UpdateOptions{})
}

func (access clientGoAccess) GetDeployment(ctx context.Context) (*appsv1.Deployment, error) {
	return access.client.AppsV1().Deployments(access.namespace).Get(ctx, apiDeploymentName, metav1.GetOptions{})
}

func (access clientGoAccess) ListEndpointSlices(ctx context.Context) (*discoveryv1.EndpointSliceList, error) {
	return access.client.DiscoveryV1().EndpointSlices(access.namespace).List(ctx, metav1.ListOptions{
		LabelSelector: discoveryv1.LabelServiceName + "=" + apiServiceName,
	})
}

type Probe interface {
	Verify(context.Context, adminauth.ClientCredential, string) error
}

type apiPodIdentity struct {
	uid     types.UID
	address string
}

func (w *Workflow) Initialize(ctx context.Context, options InitializeOptions) error {
	if w == nil || nilValue(w.cluster) || len(validation.IsDNS1123Label(w.namespace)) != 0 {
		return ErrInvalidConfiguration
	}
	cluster, namespace := w.cluster, w.namespace
	outputPath, now, lifetime := options.OutputPath, options.Now, options.Lifetime
	credential, err := adminauth.GenerateCredential(now, lifetime)
	if err != nil {
		return ErrInvalidManagedSecret
	}
	private := adminauth.ClientCredential{
		Version: adminauth.ClientCredentialVersion, CredentialID: credential.Bundle.CredentialID,
		Serial: credential.Bundle.Serial, ExpiresAt: credential.Bundle.ExpiresAt, Token: credential.Token,
	}
	privateJSON, err := adminauth.MarshalClientCredential(private)
	if err != nil || writePrivateFile(outputPath, privateJSON) != nil {
		return ErrPrivateOutput
	}
	secret, err := secretForCredential(credential, namespace)
	if err != nil {
		return ErrInvalidManagedSecret
	}
	created, createErr := cluster.CreateSecret(ctx, secret)
	if createErr != nil {
		if definiteMutationFailure(createErr) {
			return ErrCredentialConflict
		}
		if observed, getErr := cluster.GetSecret(ctx); getErr == nil && secretMatchesCandidate(observed, credential, "", "", namespace) {
			return nil
		}
		return ErrMutationUnconfirmed
	}
	if !secretMatchesCandidate(created, credential, "", "", namespace) || created.UID == "" || created.ResourceVersion == "" {
		return ErrMutationUnconfirmed
	}
	observed, err := cluster.GetSecret(ctx)
	if err != nil || !secretMatchesCandidate(observed, credential, string(created.UID), "", namespace) {
		return ErrMutationUnconfirmed
	}
	return nil
}

func (w *Workflow) Rotate(ctx context.Context, probe Probe, options RotateOptions) error {
	if w == nil || nilValue(w.cluster) || len(validation.IsDNS1123Label(w.namespace)) != 0 {
		return ErrInvalidConfiguration
	}
	cluster, namespace := w.cluster, w.namespace
	outputPath, now, lifetime, pollInterval := options.OutputPath, options.Now, options.Lifetime, options.PollInterval
	if nilValue(probe) || pollInterval <= 0 {
		return ErrInvalidConfiguration
	}
	if scoped, ok := probe.(interface{ Namespace() string }); ok && scoped.Namespace() != namespace {
		return ErrInvalidConfiguration
	}
	current, err := cluster.GetSecret(ctx)
	if err != nil {
		return ErrInvalidManagedSecret
	}
	oldBundle, oldToken, err := validateManagedSecret(current, namespace)
	if err != nil || current.UID == "" || current.ResourceVersion == "" || oldBundle.Serial == math.MaxUint64 {
		return ErrInvalidManagedSecret
	}
	identity, err := requirePreMutationTopology(ctx, cluster, namespace)
	if err != nil {
		return err
	}
	generated, err := adminauth.GenerateCredential(now, lifetime)
	if err != nil {
		return ErrInvalidManagedSecret
	}
	generated.Bundle.Serial = oldBundle.Serial + 1
	private := adminauth.ClientCredential{
		Version: adminauth.ClientCredentialVersion, CredentialID: generated.Bundle.CredentialID,
		Serial: generated.Bundle.Serial, ExpiresAt: generated.Bundle.ExpiresAt, Token: generated.Token,
		PriorSecretUID: string(current.UID), PriorResourceVersion: current.ResourceVersion,
	}
	privateJSON, err := adminauth.MarshalClientCredential(private)
	if err != nil || writePrivateFile(outputPath, privateJSON) != nil {
		return ErrPrivateOutput
	}
	generatedSecret, err := secretForCredential(generated, namespace)
	if err != nil {
		return ErrInvalidManagedSecret
	}
	candidate := current.DeepCopy()
	candidate.Type = generatedSecret.Type
	candidate.Labels = generatedSecret.Labels
	candidate.Data = generatedSecret.Data
	updated, updateErr := cluster.UpdateSecret(ctx, candidate)
	if updateErr != nil {
		if definiteMutationFailure(updateErr) {
			return ErrCredentialConflict
		}
		observed, getErr := cluster.GetSecret(ctx)
		if getErr != nil || !secretMatchesCandidate(observed, generated, string(current.UID), "", namespace) {
			return ErrMutationUnconfirmed
		}
		updated = observed
	}
	if !secretMatchesCandidate(updated, generated, string(current.UID), "", namespace) || updated.ResourceVersion == "" {
		return ErrMutationUnconfirmed
	}
	observed, err := cluster.GetSecret(ctx)
	if err != nil || !secretMatchesCandidate(observed, generated, string(current.UID), "", namespace) {
		return ErrMutationUnconfirmed
	}
	if waitForActivation(ctx, cluster, probe, private, generated, oldToken, identity, pollInterval, namespace) != nil {
		return ErrActivationIncomplete
	}
	return nil
}

func waitForActivation(ctx context.Context, cluster ClusterAccess, probe Probe, credential adminauth.ClientCredential, candidate adminauth.Credential, oldToken string, identity apiPodIdentity, pollInterval time.Duration, namespace string) error {
	if probe == nil || pollInterval <= 0 || credential.PriorSecretUID == "" ||
		credential.CredentialID != candidate.Bundle.CredentialID || credential.Serial != candidate.Bundle.Serial ||
		!credential.ExpiresAt.Equal(candidate.Bundle.ExpiresAt) || credential.Token != candidate.Token {
		return ErrActivationIncomplete
	}
	for {
		if requireActivatedTopology(ctx, cluster, identity, namespace) == nil && probe.Verify(ctx, credential, oldToken) == nil {
			// The HTTPS probe can observe this candidate while a concurrent CAS
			// rotation has already replaced the Secret but has not propagated to the
			// Pod yet. Completion therefore linearizes only after an exact candidate
			// readback and a fresh check of the same serving Pod identity.
			observed, err := cluster.GetSecret(ctx)
			if err == nil && secretMatchesCandidate(observed, candidate, credential.PriorSecretUID, "", namespace) &&
				requireActivatedTopology(ctx, cluster, identity, namespace) == nil {
				return nil
			}
		}
		timer := time.NewTimer(pollInterval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ErrActivationIncomplete
		case <-timer.C:
		}
	}
}

func secretForCredential(credential adminauth.Credential, namespace string) (*corev1.Secret, error) {
	bundle, err := adminauth.MarshalVerifierBundle(credential.Bundle)
	if err != nil {
		return nil, err
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: adminauth.CredentialSecretName, Namespace: namespace,
			Labels: adminauth.ManagedSecretLabels(),
		},
		Type: corev1.SecretType(adminauth.CredentialSecretType),
		Data: map[string][]byte{adminauth.VerifierSecretKey: bundle, adminauth.TokenSecretKey: []byte(credential.Token)},
	}, nil
}

func validateManagedSecret(secret *corev1.Secret, namespace string) (adminauth.VerifierBundle, string, error) {
	if secret == nil || secret.Name != adminauth.CredentialSecretName || secret.Namespace != namespace ||
		secret.Type != corev1.SecretType(adminauth.CredentialSecretType) || secret.DeletionTimestamp != nil ||
		!reflect.DeepEqual(secret.Labels, adminauth.ManagedSecretLabels()) || len(secret.Data) != 2 {
		return adminauth.VerifierBundle{}, "", ErrInvalidManagedSecret
	}
	if secret.Immutable != nil && *secret.Immutable {
		return adminauth.VerifierBundle{}, "", ErrInvalidManagedSecret
	}
	bundleBytes, hasBundle := secret.Data[adminauth.VerifierSecretKey]
	tokenBytes, hasToken := secret.Data[adminauth.TokenSecretKey]
	if !hasBundle || !hasToken {
		return adminauth.VerifierBundle{}, "", ErrInvalidManagedSecret
	}
	bundle, err := adminauth.ParseVerifierBundle(bundleBytes)
	token := string(tokenBytes)
	if err != nil || !adminauth.TokenMatchesBundle(token, bundle) {
		return adminauth.VerifierBundle{}, "", ErrInvalidManagedSecret
	}
	return bundle, token, nil
}

func secretMatchesCandidate(secret *corev1.Secret, credential adminauth.Credential, requiredUID, requiredResourceVersion, namespace string) bool {
	bundle, token, err := validateManagedSecret(secret, namespace)
	if err != nil || secret.UID == "" || secret.ResourceVersion == "" || token != credential.Token || bundle != credential.Bundle {
		return false
	}
	if requiredUID != "" && string(secret.UID) != requiredUID {
		return false
	}
	return requiredResourceVersion == "" || secret.ResourceVersion == requiredResourceVersion
}

func definiteMutationFailure(err error) bool {
	return apierrors.IsAlreadyExists(err) || apierrors.IsConflict(err) || apierrors.IsInvalid(err) ||
		apierrors.IsForbidden(err) || apierrors.IsUnauthorized(err) || apierrors.IsNotFound(err)
}

func requirePreMutationTopology(ctx context.Context, cluster ClusterAccess, namespace string) (apiPodIdentity, error) {
	deployment, err := cluster.GetDeployment(ctx)
	if err != nil || deployment == nil || deployment.DeletionTimestamp != nil || deployment.Namespace != namespace || deployment.Name != apiDeploymentName || deployment.Spec.Replicas == nil || *deployment.Spec.Replicas != 1 ||
		deployment.Spec.Strategy.Type != appsv1.RecreateDeploymentStrategyType ||
		deployment.Status.ObservedGeneration < deployment.Generation || deployment.Status.Replicas != 1 ||
		deployment.Status.UpdatedReplicas != 1 ||
		(deployment.Status.TerminatingReplicas != nil && *deployment.Status.TerminatingReplicas != 0) {
		return apiPodIdentity{}, ErrTopologyUnavailable
	}
	slices, err := cluster.ListEndpointSlices(ctx)
	if err != nil {
		return apiPodIdentity{}, ErrTopologyUnavailable
	}
	identities := make([]apiPodIdentity, 0, 1)
	if slices == nil {
		return apiPodIdentity{}, ErrTopologyUnavailable
	}
	for sliceIndex := range slices.Items {
		if slices.Items[sliceIndex].DeletionTimestamp != nil || slices.Items[sliceIndex].Namespace != namespace || slices.Items[sliceIndex].Labels[discoveryv1.LabelServiceName] != apiServiceName {
			return apiPodIdentity{}, ErrTopologyUnavailable
		}
		for endpointIndex := range slices.Items[sliceIndex].Endpoints {
			endpoint := &slices.Items[sliceIndex].Endpoints[endpointIndex]
			if endpoint.Conditions.Terminating != nil && *endpoint.Conditions.Terminating {
				if (endpoint.Conditions.Ready == nil || *endpoint.Conditions.Ready) &&
					(endpoint.Conditions.Serving == nil || *endpoint.Conditions.Serving) {
					return apiPodIdentity{}, ErrTopologyUnavailable
				}
				continue
			}
			if len(endpoint.Addresses) != 1 || endpoint.TargetRef == nil || endpoint.TargetRef.Kind != "Pod" ||
				endpoint.TargetRef.Namespace != namespace || endpoint.TargetRef.Name == "" || endpoint.TargetRef.UID == "" {
				return apiPodIdentity{}, ErrTopologyUnavailable
			}
			identities = append(identities, apiPodIdentity{uid: endpoint.TargetRef.UID, address: endpoint.Addresses[0]})
		}
	}
	if len(identities) != 1 {
		return apiPodIdentity{}, ErrTopologyUnavailable
	}
	return identities[0], nil
}

func requireActivatedTopology(ctx context.Context, cluster ClusterAccess, expected apiPodIdentity, namespace string) error {
	deployment, err := cluster.GetDeployment(ctx)
	if err != nil || deployment == nil || deployment.DeletionTimestamp != nil || deployment.Namespace != namespace || deployment.Name != apiDeploymentName || deployment.Spec.Replicas == nil || *deployment.Spec.Replicas != 1 ||
		deployment.Spec.Strategy.Type != appsv1.RecreateDeploymentStrategyType ||
		deployment.Status.ObservedGeneration < deployment.Generation || deployment.Status.Replicas != 1 ||
		deployment.Status.UpdatedReplicas != 1 || deployment.Status.ReadyReplicas != 1 ||
		deployment.Status.AvailableReplicas != 1 || deployment.Status.UnavailableReplicas != 0 ||
		(deployment.Status.TerminatingReplicas != nil && *deployment.Status.TerminatingReplicas != 0) {
		return ErrTopologyUnavailable
	}
	slices, err := cluster.ListEndpointSlices(ctx)
	if err != nil {
		return ErrTopologyUnavailable
	}
	identities := make([]apiPodIdentity, 0, 1)
	if slices == nil {
		return ErrTopologyUnavailable
	}
	for sliceIndex := range slices.Items {
		if slices.Items[sliceIndex].DeletionTimestamp != nil || slices.Items[sliceIndex].Namespace != namespace || slices.Items[sliceIndex].Labels[discoveryv1.LabelServiceName] != apiServiceName {
			return ErrTopologyUnavailable
		}
		for endpointIndex := range slices.Items[sliceIndex].Endpoints {
			endpoint := &slices.Items[sliceIndex].Endpoints[endpointIndex]
			if endpoint.Conditions.Terminating != nil && *endpoint.Conditions.Terminating {
				if (endpoint.Conditions.Ready == nil || *endpoint.Conditions.Ready) &&
					(endpoint.Conditions.Serving == nil || *endpoint.Conditions.Serving) {
					return ErrTopologyUnavailable
				}
				continue
			}
			if len(endpoint.Addresses) != 1 || endpoint.TargetRef == nil || endpoint.TargetRef.Kind != "Pod" ||
				endpoint.TargetRef.Namespace != namespace || endpoint.TargetRef.Name == "" || endpoint.TargetRef.UID == "" ||
				(endpoint.Conditions.Ready != nil && !*endpoint.Conditions.Ready) ||
				(endpoint.Conditions.Serving != nil && !*endpoint.Conditions.Serving) {
				return ErrTopologyUnavailable
			}
			identities = append(identities, apiPodIdentity{uid: endpoint.TargetRef.UID, address: endpoint.Addresses[0]})
		}
	}
	if len(identities) != 1 || identities[0] != expected {
		return ErrTopologyUnavailable
	}
	return nil
}
