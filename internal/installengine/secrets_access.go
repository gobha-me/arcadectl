// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/gobha-me/arcadectl/internal/adminauth"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	strictjson "sigs.k8s.io/json"
)

// PrivateSecretAccess is separate from public resource/metadata observation.
// It is a trusted internal seam; raw Secret bytes never enter SDK body logging,
// public journals, observations or returned diagnostics. No update/delete here.
type PrivateSecretAccess interface {
	Get(context.Context, string, string) (*corev1.Secret, error)
	Create(context.Context, *corev1.Secret, bool) (*corev1.Secret, error)
}

type privateSecrets struct{ access *HTTPAccess }

func (a *HTTPAccess) PrivateSecrets() PrivateSecretAccess { return privateSecrets{a} }
func secretKey(namespace, name string) installstate.Key {
	return installstate.Key{APIVersion: "v1", Kind: "Secret", Namespace: namespace, Name: name}
}
func privateSecretPath(k installstate.Key, collection bool) (string, error) {
	if k.APIVersion != "v1" || k.Kind != "Secret" || !installrender.ValidNamespace(k.Namespace) || k.Name != adminauth.CredentialSecretName && k.Name != "arcadectl-api-tls" {
		return "", ErrInvalid
	}
	path := "/api/v1/namespaces/" + k.Namespace + "/secrets"
	if !collection {
		path += "/" + k.Name
	}
	return path, nil
}
func decodePrivateSecret(o *unstructured.Unstructured, err error) (*corev1.Secret, error) {
	if err != nil {
		return nil, err
	}
	if o == nil {
		return nil, ErrRead
	}
	body, err := json.Marshal(o.Object)
	if err != nil {
		return nil, ErrRead
	}
	s := &corev1.Secret{}
	strictErrors, err := strictjson.UnmarshalStrict(body, s)
	if err != nil || len(strictErrors) != 0 {
		return nil, ErrRead
	}
	return s, nil
}
func (s privateSecrets) Get(ctx context.Context, namespace, name string) (*corev1.Secret, error) {
	return decodePrivateSecret(s.access.privateRequest(ctx, http.MethodGet, secretKey(namespace, name), nil, false))
}
func (s privateSecrets) Create(ctx context.Context, secret *corev1.Secret, dry bool) (*corev1.Secret, error) {
	if secret == nil {
		return nil, ErrInvalid
	}
	o := secret.DeepCopy()
	o.APIVersion, o.Kind = "v1", "Secret"
	return decodePrivateSecret(s.access.privateRequest(ctx, http.MethodPost, secretKey(o.Namespace, o.Name), o, dry))
}
