// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package admincredential

import (
	"context"
	"time"

	"github.com/gobha-me/arcadectl/internal/adminauth"
	corev1 "k8s.io/api/core/v1"
)

// These test-only adapters keep the original default-installation regression
// cases exercising the one extracted implementation. Production has no default
// namespace fallback or duplicate workflow.
func testInitializeCredential(ctx context.Context, access ClusterAccess, path string, now time.Time, lifetime time.Duration) error {
	w, err := NewWithAccess(access, Config{Namespace: adminauth.CredentialNamespace})
	if err != nil {
		return err
	}
	return w.Initialize(ctx, InitializeOptions{OutputPath: path, Now: now, Lifetime: lifetime})
}
func testRotateCredential(ctx context.Context, access ClusterAccess, probe Probe, path string, now time.Time, lifetime, poll time.Duration) error {
	w, err := NewWithAccess(access, Config{Namespace: adminauth.CredentialNamespace})
	if err != nil {
		return err
	}
	return w.Rotate(ctx, probe, RotateOptions{OutputPath: path, Now: now, Lifetime: lifetime, PollInterval: poll})
}
func testSecretForCredential(value adminauth.Credential) (*corev1.Secret, error) {
	return secretForCredential(value, adminauth.CredentialNamespace)
}
func testValidateManagedSecret(secret *corev1.Secret) (adminauth.VerifierBundle, string, error) {
	return validateManagedSecret(secret, adminauth.CredentialNamespace)
}
func testSecretMatchesCandidate(secret *corev1.Secret, value adminauth.Credential, uid, rv string) bool {
	return secretMatchesCandidate(secret, value, uid, rv, adminauth.CredentialNamespace)
}
func testRequirePreMutationTopology(ctx context.Context, access ClusterAccess) (apiPodIdentity, error) {
	return requirePreMutationTopology(ctx, access, adminauth.CredentialNamespace)
}
func testWaitForActivation(ctx context.Context, access ClusterAccess, probe Probe, value adminauth.ClientCredential, candidate adminauth.Credential, old string, identity apiPodIdentity, poll time.Duration) error {
	return waitForActivation(ctx, access, probe, value, candidate, old, identity, poll, adminauth.CredentialNamespace)
}
func testDefaultProbe(endpoint, ca, name string) (*HTTPSProbe, error) {
	return NewHTTPSProbe(ProbeOptions{Namespace: adminauth.CredentialNamespace, Endpoint: endpoint, CAFile: ca, TLSServerName: name})
}
