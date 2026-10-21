// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installstate"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"
)

// Primitive transport controls only, never ledger/phase authority. Derive the
// same private actor-zero identity wrapper over the original direct TLS pool.
func fixturePoolIdentity(access *HTTPAccess, key installstate.Key) fixtureWireIdentity {
	return fixtureWireIdentity{namespace: key.Namespace, authorization: "Bearer " + access.frozen.BearerToken}
}

func derivedFixturePoolAccess(t *testing.T, parent *HTTPAccess, key installstate.Key) *HTTPAccess {
	t.Helper()
	identity := fixturePoolIdentity(parent, key)
	derived, err := parent.derivedDirectAccess(rest.ImpersonationConfig{}, func(next http.RoundTripper) http.RoundTripper {
		return fixtureIdentityTransport{next: next, identity: identity}
	})
	if err != nil || derived == nil || derived.pool != parent.pool || derived.client.Timeout != parent.client.Timeout {
		t.Fatal("private fixture derivative changed canonical pool or budget")
	}
	return derived
}

func fixturePoolRead(ctx context.Context, access *HTTPAccess, key installstate.Key, strict bool) (*fixtureCapture, *http.Response, error) {
	path, _, err := fixturePath(key, false)
	if err != nil {
		return nil, nil, ErrFixtures
	}
	u := *access.base
	u.Path = strings.TrimRight(u.Path, "/") + path
	u.RawQuery = ""
	capture := &fixtureCapture{identity: fixturePoolIdentity(access, key), method: http.MethodGet, url: u.String(), key: key, strictNotFound: strict}
	ctx = context.WithValue(ctx, attemptKey{}, &requestAttempt{method: http.MethodGet, fixture: capture})
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, capture.url, bytes.NewReader(nil))
	if err != nil {
		return nil, nil, ErrFixtures
	}
	r.Header.Set("Accept", "application/json")
	r.Header.Set("Content-Type", "application/json")
	r.GetBody = nil
	response, err := access.client.Do(r)
	return capture, response, err
}

// Test-only inspection of actual returned values, before fixed classification.
// No raw error or private body is printed, even on a failing control.
func fixturePoolCancellationPublicSafe(response *http.Response, err error) bool {
	private := err != nil && strings.Contains(err.Error(), "CANARY")
	if response == nil {
		return err != nil && !private
	}
	if response.Body == nil {
		return false
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 3))
	_ = response.Body.Close()
	return !private && readErr == nil && string(body) == `{}` && response.StatusCode == http.StatusNotFound && response.Status == "404 Not Found" && len(response.Header) == 1 && response.Header.Get("Content-Type") == "application/json" && response.Trailer == nil && response.ContentLength == 2
}

func testFixturePoolCancellationPrivacyControls(t *testing.T) {
	for _, scenario := range []string{"valid", "error", "header", "trailer", "body", "status", "length", "missing", "cancelled-no-response"} {
		t.Run(scenario, func(t *testing.T) {
			response := &http.Response{StatusCode: http.StatusNotFound, Status: "404 Not Found", Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(`{}`)), ContentLength: 2}
			var err error
			switch scenario {
			case "error":
				err = errors.New("PRIVATE-CANCEL-ERROR-CANARY")
			case "header":
				response.Header.Set("Warning", "PRIVATE-CANCEL-HEADER-CANARY")
			case "trailer":
				response.Trailer = http.Header{"X-Private": {"PRIVATE-CANCEL-TRAILER-CANARY"}}
			case "body":
				response.Body = io.NopCloser(strings.NewReader("PRIVATE-CANCEL-BODY-CANARY"))
			case "status":
				response.Status = "PRIVATE-CANCEL-STATUS-CANARY"
			case "length":
				response.ContentLength = 3
			case "missing":
				response = nil
			case "cancelled-no-response":
				response, err = nil, context.Canceled
			}
			if fixturePoolCancellationPublicSafe(response, err) != (scenario == "valid" || scenario == "cancelled-no-response") {
				t.Fatal("actual cancellation privacy assertion missed its control")
			}
		})
	}
}

func testDirectReadPoolStrictFixtureNotFound(t *testing.T) {
	key := installstate.Key{APIVersion: "v1", Kind: "Pod", Namespace: "isolated-install", Name: "fixed-pod"}
	status := apierrors.NewNotFound(schema.GroupResource{Resource: "pods"}, key.Name).ErrStatus
	status.APIVersion, status.Kind = "v1", "Status"
	body, err := json.Marshal(status)
	if err != nil {
		t.Fatal("native strict Status encoding refused")
	}
	for _, scenario := range []struct {
		name     string
		body     []byte
		accepted bool
	}{
		{"exact", body, true}, {"empty", nil, false},
		{"foreign-name", bytes.ReplaceAll(body, []byte(key.Name), []byte("PRIVATE-FOREIGN-NAME-CANARY")), false},
		{"malformed", []byte(`{"message":"PRIVATE-STRICT-BODY-CANARY"`), false},
		{"extra", append(bytes.TrimSuffix(bytes.Clone(body), []byte("}")), []byte(`,"private":"PRIVATE-STRICT-BODY-CANARY"}`)...), false},
		{"duplicate", append(bytes.TrimSuffix(bytes.Clone(body), []byte("}")), []byte(`,"code":404}`)...), false},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Method != http.MethodGet || r.URL.Path != "/api/v1/namespaces/isolated-install/pods/fixed-pod" || r.URL.RawQuery != "" || r.ProtoMajor != 1 || r.Header.Get("Authorization") != "Bearer TEST-ONLY-STRICT-POOL" || r.Header.Get("Impersonate-User") != "" {
					t.Error("strict fixture read changed private route or identity")
				}
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Warning", "PRIVATE-STRICT-HEADER-CANARY")
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write(scenario.body)
			}))
			t.Cleanup(server.Close)
			config := serverConfig(server)
			config.BearerToken = "TEST-ONLY-STRICT-POOL"
			parent, err := NewDirectHTTPAccess(config)
			if err != nil {
				t.Fatal("strict fixture parent refused")
			}
			t.Cleanup(parent.pool.(*http.Transport).CloseIdleConnections)
			access := derivedFixturePoolAccess(t, parent, key)
			capture, response, err := fixturePoolRead(t.Context(), access, key, true)
			if err != nil || response == nil || response.Body == nil || capture == nil {
				t.Fatal("strict fixture native response unavailable")
			}
			public, readErr := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if readErr != nil || string(public) != `{}` || response.Status != "404 Not Found" || len(response.Header) != 1 || response.Header.Get("Content-Type") != "application/json" || response.Trailer != nil || response.ContentLength != 2 || capture.success != scenario.accepted || capture.notFound != scenario.accepted || capture.result != nil || capture.uid != "" || requests.Load() != 1 {
				t.Fatal("strict native Status acceptance, privacy or one-attempt semantics changed")
			}
		})
	}
}
