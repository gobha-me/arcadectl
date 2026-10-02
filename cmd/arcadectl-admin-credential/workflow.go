// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package main

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
	"k8s.io/client-go/kubernetes"
)

const (
	apiDeploymentName = "arcadectl-api"
	apiServiceName    = "arcadectl-api"
)

var (
	errInvalidManagedSecret = errors.New("managed credential Secret is invalid")
	errCredentialConflict   = errors.New("credential mutation conflict")
	errMutationUnconfirmed  = errors.New("credential mutation outcome is unconfirmed; private output retained")
	errActivationIncomplete = errors.New("credential committed but activation is incomplete; private output retained")
	errTopologyUnavailable  = errors.New("the API does not have exactly one settled serving replica")
)

type clusterAccess interface {
	GetSecret(context.Context) (*corev1.Secret, error)
	CreateSecret(context.Context, *corev1.Secret) (*corev1.Secret, error)
	UpdateSecret(context.Context, *corev1.Secret) (*corev1.Secret, error)
	GetDeployment(context.Context) (*appsv1.Deployment, error)
	ListEndpointSlices(context.Context) (*discoveryv1.EndpointSliceList, error)
}

type clientGoAccess struct{ client kubernetes.Interface }

func (access clientGoAccess) GetSecret(ctx context.Context) (*corev1.Secret, error) {
	return access.client.CoreV1().Secrets(adminauth.CredentialNamespace).Get(ctx, adminauth.CredentialSecretName, metav1.GetOptions{})
}

func (access clientGoAccess) CreateSecret(ctx context.Context, secret *corev1.Secret) (*corev1.Secret, error) {
	return access.client.CoreV1().Secrets(adminauth.CredentialNamespace).Create(ctx, secret, metav1.CreateOptions{})
}

func (access clientGoAccess) UpdateSecret(ctx context.Context, secret *corev1.Secret) (*corev1.Secret, error) {
	return access.client.CoreV1().Secrets(adminauth.CredentialNamespace).Update(ctx, secret, metav1.UpdateOptions{})
}

func (access clientGoAccess) GetDeployment(ctx context.Context) (*appsv1.Deployment, error) {
	return access.client.AppsV1().Deployments(adminauth.CredentialNamespace).Get(ctx, apiDeploymentName, metav1.GetOptions{})
}

func (access clientGoAccess) ListEndpointSlices(ctx context.Context) (*discoveryv1.EndpointSliceList, error) {
	return access.client.DiscoveryV1().EndpointSlices(adminauth.CredentialNamespace).List(ctx, metav1.ListOptions{
		LabelSelector: discoveryv1.LabelServiceName + "=" + apiServiceName,
	})
}

type credentialProbe interface {
	Verify(context.Context, adminauth.ClientCredential, string) error
}

type apiPodIdentity struct {
	uid     types.UID
	address string
}

func initializeCredential(ctx context.Context, cluster clusterAccess, outputPath string, now time.Time, lifetime time.Duration) error {
	credential, err := adminauth.GenerateCredential(now, lifetime)
	if err != nil {
		return errInvalidManagedSecret
	}
	private := adminauth.ClientCredential{
		Version: adminauth.ClientCredentialVersion, CredentialID: credential.Bundle.CredentialID,
		Serial: credential.Bundle.Serial, ExpiresAt: credential.Bundle.ExpiresAt, Token: credential.Token,
	}
	privateJSON, err := adminauth.MarshalClientCredential(private)
	if err != nil || writePrivateFile(outputPath, privateJSON) != nil {
		return errPrivateOutput
	}
	secret, err := secretForCredential(credential)
	if err != nil {
		return errInvalidManagedSecret
	}
	created, createErr := cluster.CreateSecret(ctx, secret)
	if createErr != nil {
		if definiteMutationFailure(createErr) {
			return errCredentialConflict
		}
		if observed, getErr := cluster.GetSecret(ctx); getErr == nil && secretMatchesCandidate(observed, credential, "", "") {
			return nil
		}
		return errMutationUnconfirmed
	}
	if !secretMatchesCandidate(created, credential, "", "") || created.UID == "" || created.ResourceVersion == "" {
		return errMutationUnconfirmed
	}
	observed, err := cluster.GetSecret(ctx)
	if err != nil || !secretMatchesCandidate(observed, credential, string(created.UID), "") {
		return errMutationUnconfirmed
	}
	return nil
}

func rotateCredential(ctx context.Context, cluster clusterAccess, probe credentialProbe, outputPath string, now time.Time, lifetime, pollInterval time.Duration) error {
	current, err := cluster.GetSecret(ctx)
	if err != nil {
		return errInvalidManagedSecret
	}
	oldBundle, oldToken, err := validateManagedSecret(current)
	if err != nil || current.UID == "" || current.ResourceVersion == "" || oldBundle.Serial == math.MaxUint64 {
		return errInvalidManagedSecret
	}
	identity, err := requirePreMutationTopology(ctx, cluster)
	if err != nil {
		return err
	}
	generated, err := adminauth.GenerateCredential(now, lifetime)
	if err != nil {
		return errInvalidManagedSecret
	}
	generated.Bundle.Serial = oldBundle.Serial + 1
	private := adminauth.ClientCredential{
		Version: adminauth.ClientCredentialVersion, CredentialID: generated.Bundle.CredentialID,
		Serial: generated.Bundle.Serial, ExpiresAt: generated.Bundle.ExpiresAt, Token: generated.Token,
		PriorSecretUID: string(current.UID), PriorResourceVersion: current.ResourceVersion,
	}
	privateJSON, err := adminauth.MarshalClientCredential(private)
	if err != nil || writePrivateFile(outputPath, privateJSON) != nil {
		return errPrivateOutput
	}
	generatedSecret, err := secretForCredential(generated)
	if err != nil {
		return errInvalidManagedSecret
	}
	candidate := current.DeepCopy()
	candidate.Type = generatedSecret.Type
	candidate.Labels = generatedSecret.Labels
	candidate.Data = generatedSecret.Data
	updated, updateErr := cluster.UpdateSecret(ctx, candidate)
	if updateErr != nil {
		if definiteMutationFailure(updateErr) {
			return errCredentialConflict
		}
		observed, getErr := cluster.GetSecret(ctx)
		if getErr != nil || !secretMatchesCandidate(observed, generated, string(current.UID), "") {
			return errMutationUnconfirmed
		}
		updated = observed
	}
	if !secretMatchesCandidate(updated, generated, string(current.UID), "") || updated.ResourceVersion == "" {
		return errMutationUnconfirmed
	}
	observed, err := cluster.GetSecret(ctx)
	if err != nil || !secretMatchesCandidate(observed, generated, string(current.UID), "") {
		return errMutationUnconfirmed
	}
	if waitForActivation(ctx, cluster, probe, private, generated, oldToken, identity, pollInterval) != nil {
		return errActivationIncomplete
	}
	return nil
}

func waitForActivation(ctx context.Context, cluster clusterAccess, probe credentialProbe, credential adminauth.ClientCredential, candidate adminauth.Credential, oldToken string, identity apiPodIdentity, pollInterval time.Duration) error {
	if probe == nil || pollInterval <= 0 || credential.PriorSecretUID == "" ||
		credential.CredentialID != candidate.Bundle.CredentialID || credential.Serial != candidate.Bundle.Serial ||
		!credential.ExpiresAt.Equal(candidate.Bundle.ExpiresAt) || credential.Token != candidate.Token {
		return errActivationIncomplete
	}
	for {
		if requireActivatedTopology(ctx, cluster, identity) == nil && probe.Verify(ctx, credential, oldToken) == nil {
			// The HTTPS probe can observe this candidate while a concurrent CAS
			// rotation has already replaced the Secret but has not propagated to the
			// Pod yet. Completion therefore linearizes only after an exact candidate
			// readback and a fresh check of the same serving Pod identity.
			observed, err := cluster.GetSecret(ctx)
			if err == nil && secretMatchesCandidate(observed, candidate, credential.PriorSecretUID, "") &&
				requireActivatedTopology(ctx, cluster, identity) == nil {
				return nil
			}
		}
		timer := time.NewTimer(pollInterval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return errActivationIncomplete
		case <-timer.C:
		}
	}
}

func secretForCredential(credential adminauth.Credential) (*corev1.Secret, error) {
	bundle, err := adminauth.MarshalVerifierBundle(credential.Bundle)
	if err != nil {
		return nil, err
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: adminauth.CredentialSecretName, Namespace: adminauth.CredentialNamespace,
			Labels: adminauth.ManagedSecretLabels(),
		},
		Type: corev1.SecretType(adminauth.CredentialSecretType),
		Data: map[string][]byte{adminauth.VerifierSecretKey: bundle, adminauth.TokenSecretKey: []byte(credential.Token)},
	}, nil
}

func validateManagedSecret(secret *corev1.Secret) (adminauth.VerifierBundle, string, error) {
	if secret == nil || secret.Name != adminauth.CredentialSecretName || secret.Namespace != adminauth.CredentialNamespace ||
		secret.Type != corev1.SecretType(adminauth.CredentialSecretType) || secret.DeletionTimestamp != nil ||
		!reflect.DeepEqual(secret.Labels, adminauth.ManagedSecretLabels()) || len(secret.Data) != 2 {
		return adminauth.VerifierBundle{}, "", errInvalidManagedSecret
	}
	if secret.Immutable != nil && *secret.Immutable {
		return adminauth.VerifierBundle{}, "", errInvalidManagedSecret
	}
	bundleBytes, hasBundle := secret.Data[adminauth.VerifierSecretKey]
	tokenBytes, hasToken := secret.Data[adminauth.TokenSecretKey]
	if !hasBundle || !hasToken {
		return adminauth.VerifierBundle{}, "", errInvalidManagedSecret
	}
	bundle, err := adminauth.ParseVerifierBundle(bundleBytes)
	token := string(tokenBytes)
	if err != nil || !adminauth.TokenMatchesBundle(token, bundle) {
		return adminauth.VerifierBundle{}, "", errInvalidManagedSecret
	}
	return bundle, token, nil
}

func secretMatchesCandidate(secret *corev1.Secret, credential adminauth.Credential, requiredUID, requiredResourceVersion string) bool {
	bundle, token, err := validateManagedSecret(secret)
	if err != nil || token != credential.Token || bundle != credential.Bundle {
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

func requirePreMutationTopology(ctx context.Context, cluster clusterAccess) (apiPodIdentity, error) {
	deployment, err := cluster.GetDeployment(ctx)
	if err != nil || deployment.Spec.Replicas == nil || *deployment.Spec.Replicas != 1 ||
		deployment.Spec.Strategy.Type != appsv1.RecreateDeploymentStrategyType ||
		deployment.Status.ObservedGeneration < deployment.Generation || deployment.Status.Replicas != 1 ||
		deployment.Status.UpdatedReplicas != 1 ||
		(deployment.Status.TerminatingReplicas != nil && *deployment.Status.TerminatingReplicas != 0) {
		return apiPodIdentity{}, errTopologyUnavailable
	}
	slices, err := cluster.ListEndpointSlices(ctx)
	if err != nil {
		return apiPodIdentity{}, errTopologyUnavailable
	}
	identities := make([]apiPodIdentity, 0, 1)
	for sliceIndex := range slices.Items {
		for endpointIndex := range slices.Items[sliceIndex].Endpoints {
			endpoint := &slices.Items[sliceIndex].Endpoints[endpointIndex]
			if endpoint.Conditions.Terminating != nil && *endpoint.Conditions.Terminating {
				if (endpoint.Conditions.Ready == nil || *endpoint.Conditions.Ready) &&
					(endpoint.Conditions.Serving == nil || *endpoint.Conditions.Serving) {
					return apiPodIdentity{}, errTopologyUnavailable
				}
				continue
			}
			if len(endpoint.Addresses) != 1 || endpoint.TargetRef == nil || endpoint.TargetRef.Kind != "Pod" ||
				endpoint.TargetRef.Namespace != adminauth.CredentialNamespace || endpoint.TargetRef.Name == "" || endpoint.TargetRef.UID == "" {
				return apiPodIdentity{}, errTopologyUnavailable
			}
			identities = append(identities, apiPodIdentity{uid: endpoint.TargetRef.UID, address: endpoint.Addresses[0]})
		}
	}
	if len(identities) != 1 {
		return apiPodIdentity{}, errTopologyUnavailable
	}
	return identities[0], nil
}

func requireActivatedTopology(ctx context.Context, cluster clusterAccess, expected apiPodIdentity) error {
	deployment, err := cluster.GetDeployment(ctx)
	if err != nil || deployment.Spec.Replicas == nil || *deployment.Spec.Replicas != 1 ||
		deployment.Spec.Strategy.Type != appsv1.RecreateDeploymentStrategyType ||
		deployment.Status.ObservedGeneration < deployment.Generation || deployment.Status.Replicas != 1 ||
		deployment.Status.UpdatedReplicas != 1 || deployment.Status.ReadyReplicas != 1 ||
		deployment.Status.AvailableReplicas != 1 || deployment.Status.UnavailableReplicas != 0 ||
		(deployment.Status.TerminatingReplicas != nil && *deployment.Status.TerminatingReplicas != 0) {
		return errTopologyUnavailable
	}
	slices, err := cluster.ListEndpointSlices(ctx)
	if err != nil {
		return errTopologyUnavailable
	}
	identities := make([]apiPodIdentity, 0, 1)
	for sliceIndex := range slices.Items {
		for endpointIndex := range slices.Items[sliceIndex].Endpoints {
			endpoint := &slices.Items[sliceIndex].Endpoints[endpointIndex]
			if endpoint.Conditions.Terminating != nil && *endpoint.Conditions.Terminating {
				if (endpoint.Conditions.Ready == nil || *endpoint.Conditions.Ready) &&
					(endpoint.Conditions.Serving == nil || *endpoint.Conditions.Serving) {
					return errTopologyUnavailable
				}
				continue
			}
			if len(endpoint.Addresses) != 1 || endpoint.TargetRef == nil || endpoint.TargetRef.Kind != "Pod" ||
				endpoint.TargetRef.Namespace != adminauth.CredentialNamespace || endpoint.TargetRef.Name == "" || endpoint.TargetRef.UID == "" ||
				(endpoint.Conditions.Ready != nil && !*endpoint.Conditions.Ready) ||
				(endpoint.Conditions.Serving != nil && !*endpoint.Conditions.Serving) {
				return errTopologyUnavailable
			}
			identities = append(identities, apiPodIdentity{uid: endpoint.TargetRef.UID, address: endpoint.Addresses[0]})
		}
	}
	if len(identities) != 1 || identities[0] != expected {
		return errTopologyUnavailable
	}
	return nil
}
