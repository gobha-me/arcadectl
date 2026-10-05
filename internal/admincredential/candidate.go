// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package admincredential

import (
	"bytes"
	"fmt"
	"io"
	"time"

	"github.com/gobha-me/arcadectl/internal/adminauth"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

// InitialCandidate is sealed private material, not a mutation or activation
// proof. Installers must durably save PrivateBytes before any cluster effect,
// bind it to original installation identity and resume by parsing those bytes.
// Neither method below accesses Kubernetes or writes a file.
type InitialCandidate struct {
	namespace  string
	credential adminauth.Credential
	private    []byte
}

func (InitialCandidate) String() string   { return "private administrator candidate" }
func (InitialCandidate) GoString() string { return "private administrator candidate" }
func (InitialCandidate) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "private administrator candidate")
}

func PrepareInitialCandidate(namespace string, now time.Time, lifetime time.Duration) (*InitialCandidate, error) {
	if len(validation.IsDNS1123Label(namespace)) != 0 || now.IsZero() {
		return nil, ErrInvalidConfiguration
	}
	generated, err := adminauth.GenerateCredential(now, lifetime)
	if err != nil {
		return nil, ErrInvalidManagedSecret
	}
	body, err := adminauth.MarshalClientCredential(adminauth.ClientCredential{Version: adminauth.ClientCredentialVersion, CredentialID: generated.Bundle.CredentialID, Serial: generated.Bundle.Serial, ExpiresAt: generated.Bundle.ExpiresAt, Token: generated.Token})
	if err != nil {
		return nil, ErrInvalidManagedSecret
	}
	return ResumeInitialCandidate(namespace, body, now)
}

// ResumeInitialCandidate never regenerates an expired/malformed candidate or
// mistakes a rotation client file for an initial installation candidate.
func ResumeInitialCandidate(namespace string, body []byte, now time.Time) (*InitialCandidate, error) {
	if len(validation.IsDNS1123Label(namespace)) != 0 || now.IsZero() {
		return nil, ErrInvalidConfiguration
	}
	private, err := adminauth.ParseClientCredential(body)
	if err != nil || private.Serial != 1 || private.PriorSecretUID != "" || private.PriorResourceVersion != "" || !private.ExpiresAt.After(now) {
		return nil, ErrInvalidManagedSecret
	}
	credential := adminauth.Credential{Token: private.Token, Bundle: adminauth.VerifierBundle{Version: adminauth.VerifierBundleVersion, CredentialID: private.CredentialID, Serial: private.Serial, ExpiresAt: private.ExpiresAt, TokenSHA256: adminauth.TokenDigest(private.Token)}}
	if _, err := secretForCredential(credential, namespace); err != nil {
		return nil, ErrInvalidManagedSecret
	}
	canonical, err := adminauth.MarshalClientCredential(private)
	if err != nil {
		return nil, ErrInvalidManagedSecret
	}
	return &InitialCandidate{namespace: namespace, credential: credential, private: canonical}, nil
}

func (c *InitialCandidate) Namespace() string {
	if c == nil {
		return ""
	}
	return c.namespace
}
func (c *InitialCandidate) PrivateBytes() []byte {
	if c == nil {
		return nil
	}
	return bytes.Clone(c.private)
}
func (c *InitialCandidate) Secret() (*corev1.Secret, error) {
	if c == nil || c.namespace == "" || len(c.private) == 0 {
		return nil, ErrInvalidManagedSecret
	}
	secret, err := secretForCredential(c.credential, c.namespace)
	if err != nil {
		return nil, ErrInvalidManagedSecret
	}
	return secret, nil
}
