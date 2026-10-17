// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package admincredential

import (
	"context"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/adminauth"
)

type deadlineTransport struct{ t *testing.T }

func (transport deadlineTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	deadline, ok := request.Context().Deadline()
	if !ok || time.Until(deadline) > 30*time.Second || time.Until(deadline) <= 0 {
		transport.t.Fatal("probe request lacks its bounded deadline")
	}
	return &http.Response{StatusCode: http.StatusUnauthorized, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")), Request: request}, nil
}

func TestProbeRequestUsesBoundedDeadlineEvenWithoutCallerDeadline(t *testing.T) {
	probe := &HTTPSProbe{namespace: customNamespace, endpoint: "https://api.invalid/v1/auth/self", client: &http.Client{Transport: deadlineTransport{t: t}}}
	status, _, err := probe.request(context.Background(), "fake-token")
	if err != nil || status != http.StatusUnauthorized {
		t.Fatal("bounded request did not complete")
	}
}

func TestTrustedProbeAcceptsNewAndRejectsOldWithoutProxy(t *testing.T) {
	now := time.Date(2026, 10, 2, 5, 0, 0, 0, time.UTC)
	generated, _ := adminauth.GenerateCredential(now, time.Hour)
	private := adminauth.ClientCredential{
		Version: adminauth.ClientCredentialVersion, CredentialID: generated.Bundle.CredentialID,
		Serial: generated.Bundle.Serial, ExpiresAt: generated.Bundle.ExpiresAt, Token: generated.Token,
	}
	old := "old-token-kept-only-in-memory"
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.Header.Get("Authorization") {
		case "Bearer " + generated.Token:
			writer.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(writer, `{"version":"v1","principalId":"admin","credentialId":%q,"expiresAt":%q,"namespace":%q}`,
				generated.Bundle.CredentialID, generated.Bundle.ExpiresAt.Format(time.RFC3339Nano), adminauth.CredentialNamespace)
		case "Bearer " + old:
			writer.WriteHeader(http.StatusUnauthorized)
		default:
			writer.WriteHeader(http.StatusForbidden)
		}
	}))
	defer server.Close()
	caPath := writeServerCA(t, server)
	t.Setenv("HTTPS_PROXY", "http://proxy.invalid:1234")
	probe, err := testDefaultProbe(server.URL+"/v1/auth/self", caPath, "")
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	if err := probe.Verify(context.Background(), private, old); err != nil {
		t.Fatal(err)
	}
}

func TestProbeDoesNotFollowRedirectOrAcceptMalformedSelf(t *testing.T) {
	var redirected atomic.Int32
	destination := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected.Add(1) }))
	defer destination.Close()
	source := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	probe, err := testDefaultProbe(source.URL+"/v1/auth/self", writeServerCA(t, source), "")
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	credential, _ := adminauth.GenerateCredential(time.Now().UTC(), time.Hour)
	private := adminauth.ClientCredential{Version: "v1", CredentialID: credential.Bundle.CredentialID, Serial: 1, ExpiresAt: credential.Bundle.ExpiresAt, Token: credential.Token}
	if err := probe.Verify(context.Background(), private, "old"); err == nil {
		t.Fatal("redirecting probe succeeded")
	}
	if redirected.Load() != 0 {
		t.Fatal("probe followed redirect and exposed authorization")
	}

	for _, body := range []string{
		`{"version":"v1","principalId":"admin","credentialId":"x","expiresAt":"2026-10-02T00:00:00Z"}`,
		`{"version":"v1","version":"v1","principalId":"admin","credentialId":"x","expiresAt":"2026-10-02T00:00:00Z"}`,
		`{"version":"v1","principalId":"admin","credentialId":"x","expiresAt":"2026-10-02T00:00:00Z","roles":[]}`,
		`{"version":"v1","principalId":"admin","credentialId":"x"} {}`,
	} {
		if _, err := parseSelfResponse([]byte(body)); err == nil {
			t.Fatalf("accepted malformed self response %s", body)
		}
	}
}

func TestProbeURLAndCAAreStrict(t *testing.T) {
	for _, endpoint := range []string{
		"http://api.example/v1/auth/self",
		"https://user@api.example/v1/auth/self",
		"https://api.example/v1/auth/self?token=value",
		"https://api.example/other",
	} {
		if _, err := testDefaultProbe(endpoint, "/missing", ""); err == nil {
			t.Fatalf("accepted unsafe endpoint %q", endpoint)
		}
	}
	invalidCA := filepath.Join(privateTestDirectory(t), "ca.pem")
	if err := os.WriteFile(invalidCA, []byte(strings.Repeat("x", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := testDefaultProbe("https://api.example/v1/auth/self", invalidCA, ""); err == nil {
		t.Fatal("accepted invalid CA")
	}
}

func TestProbeRejectsAnotherInstallationNamespace(t *testing.T) {
	generated, _ := adminauth.GenerateCredential(time.Now().UTC(), time.Hour)
	credential := adminauth.ClientCredential{Version: "v1", CredentialID: generated.Bundle.CredentialID,
		Serial: generated.Bundle.Serial, ExpiresAt: generated.Bundle.ExpiresAt, Token: generated.Token}
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(writer, `{"version":"v1","principalId":"admin","credentialId":%q,"expiresAt":%q,"namespace":"another-installation"}`,
			credential.CredentialID, credential.ExpiresAt.Format(time.RFC3339Nano))
	}))
	defer server.Close()
	probe, err := testDefaultProbe(server.URL+"/v1/auth/self", writeServerCA(t, server), "")
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	if probe.Verify(context.Background(), credential, "old-token") == nil {
		t.Fatal("credential activation accepted another installation namespace")
	}
}

func TestProbeExplicitCustomNamespace(t *testing.T) {
	generated, _ := adminauth.GenerateCredential(time.Now().UTC(), time.Hour)
	credential := adminauth.ClientCredential{Version: "v1", CredentialID: generated.Bundle.CredentialID, Serial: generated.Bundle.Serial, ExpiresAt: generated.Bundle.ExpiresAt, Token: generated.Token}
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") == "Bearer old-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+credential.Token {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_, _ = fmt.Fprintf(w, `{"version":"v1","principalId":"admin","credentialId":%q,"expiresAt":%q,"namespace":%q}`, credential.CredentialID, credential.ExpiresAt.Format(time.RFC3339Nano), customNamespace)
	}))
	defer server.Close()
	probe, err := NewHTTPSProbe(ProbeOptions{Namespace: customNamespace, Endpoint: server.URL + "/v1/auth/self", CAFile: writeServerCA(t, server)})
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	if probe.Namespace() != customNamespace || probe.Verify(context.Background(), credential, "old-token") != nil || calls.Load() != 2 {
		t.Fatal("custom namespace activation was not proved")
	}
	probe.namespace = "foreign"
	if probe.Verify(context.Background(), credential, "old-token") == nil || calls.Load() != 3 {
		t.Fatal("namespace mismatch accepted or old credential sent after mismatch")
	}
}

func writeServerCA(t *testing.T, server *httptest.Server) string {
	t.Helper()
	certificate := server.Certificate()
	contents := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	path := filepath.Join(privateTestDirectory(t), "ca.pem")
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readBoundedPublicFile(path, 1024*1024); err != nil {
		t.Fatalf("CA fixture read failed: %v", err)
	}
	return path
}
