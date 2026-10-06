// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gobha-me/arcadectl/internal/adminauth"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestPrivateSecretTransportIsScopedSingleAttemptAndSuppressesServerErrors(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodPost || r.ProtoMajor != 1 || r.URL.Path != "/api/v1/namespaces/isolated-install/secrets" || r.URL.Query().Get("fieldValidation") != "Strict" {
			t.Error("unsafe private request")
		}
		w.Header().Set("Retry-After", "0")
		w.Header().Set("Warning", "PRIVATE-ERROR-CANARY")
		w.WriteHeader(503)
		_, _ = io.WriteString(w, "PRIVATE-ERROR-CANARY")
	}))
	defer server.Close()
	access, err := NewHTTPAccess(serverConfig(server))
	if err != nil {
		t.Fatal(err)
	}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: adminauth.CredentialSecretName, Namespace: "isolated-install"}, Type: corev1.SecretType(adminauth.CredentialSecretType), Data: map[string][]byte{"token": []byte("fake-private-token")}}
	if _, err := access.PrivateSecrets().Create(context.Background(), secret, false); !errors.Is(err, ErrRead) || strings.Contains(err.Error(), "CANARY") || requests.Load() != 1 {
		t.Fatal("private request replayed/error body reflected")
	}
	secret.Name = "unreviewed"
	if _, err := access.PrivateSecrets().Create(context.Background(), secret, false); !errors.Is(err, ErrInvalid) || requests.Load() != 1 {
		t.Fatal("unreviewed private Secret request sent")
	}
	if _, err := access.Get(context.Background(), secretKey("isolated-install", adminauth.CredentialSecretName)); !errors.Is(err, ErrInvalid) || requests.Load() != 1 {
		t.Fatal("public access accepted full Secret fallback")
	}
}

func TestPrivateSecretDecoderRejectsUnknownAndDuplicateFields(t *testing.T) {
	for _, scenario := range []string{"valid", "unknown", "duplicate", "wrong-name", "wrong-kind", "metadata-uid-alias", "data-alias", "type-alias", "immutable-alias"} {
		t.Run(scenario, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if scenario == "duplicate" {
					_, _ = io.WriteString(w, `{"kind":"Secret","kind":"Secret","apiVersion":"v1","metadata":{"name":"arcadectl-api-tls","namespace":"isolated-install"}}`)
					return
				}
				body := map[string]any{"kind": "Secret", "apiVersion": "v1", "metadata": map[string]any{"name": "arcadectl-api-tls", "namespace": "isolated-install"}, "type": "kubernetes.io/tls", "data": map[string]any{"tls.crt": "ZmFrZQ==", "tls.key": "ZmFrZQ=="}}
				switch scenario {
				case "unknown":
					body["foreign"] = "PRIVATE-CANARY"
				case "wrong-name":
					body["metadata"].(map[string]any)["name"] = "foreign"
				case "wrong-kind":
					body["kind"] = "ConfigMap"
				case "metadata-uid-alias":
					body["metadata"].(map[string]any)["UID"] = "PRIVATE-CANARY"
				case "data-alias":
					body["Data"] = map[string]any{"tls.crt": "UFJJVkFURS1DQU5BUlk="}
				case "type-alias":
					body["Type"] = "PRIVATE-CANARY"
				case "immutable-alias":
					body["Immutable"] = true
				}
				_ = json.NewEncoder(w).Encode(body)
			}))
			defer server.Close()
			access, err := NewHTTPAccess(serverConfig(server))
			if err != nil {
				t.Fatal(err)
			}
			s, err := access.PrivateSecrets().Get(context.Background(), "isolated-install", "arcadectl-api-tls")
			if scenario == "valid" {
				if err != nil || string(s.Data["tls.key"]) != "fake" {
					t.Fatal("typed private decode failed")
				}
			} else if !errors.Is(err, ErrRead) || strings.Contains(err.Error(), "CANARY") {
				t.Fatal("malformed private evidence accepted/reflected")
			}
		})
	}
}
