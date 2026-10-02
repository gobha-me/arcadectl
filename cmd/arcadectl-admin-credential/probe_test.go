// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/pem"
	"fmt"
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
			_, _ = fmt.Fprintf(writer, `{"version":"v1","principalId":"admin","credentialId":%q,"expiresAt":%q}`,
				generated.Bundle.CredentialID, generated.Bundle.ExpiresAt.Format(time.RFC3339Nano))
		case "Bearer " + old:
			writer.WriteHeader(http.StatusUnauthorized)
		default:
			writer.WriteHeader(http.StatusForbidden)
		}
	}))
	defer server.Close()
	caPath := writeServerCA(t, server)
	t.Setenv("HTTPS_PROXY", "http://proxy.invalid:1234")
	probe, err := newHTTPCredentialProbe(server.URL+"/v1/auth/self", caPath, "")
	if err != nil {
		t.Fatal(err)
	}
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
	probe, err := newHTTPCredentialProbe(source.URL+"/v1/auth/self", writeServerCA(t, source), "")
	if err != nil {
		t.Fatal(err)
	}
	credential, _ := adminauth.GenerateCredential(time.Now().UTC(), time.Hour)
	private := adminauth.ClientCredential{Version: "v1", CredentialID: credential.Bundle.CredentialID, Serial: 1, ExpiresAt: credential.Bundle.ExpiresAt, Token: credential.Token}
	if err := probe.Verify(context.Background(), private, "old"); err == nil {
		t.Fatal("redirecting probe succeeded")
	}
	if redirected.Load() != 0 {
		t.Fatal("probe followed redirect and exposed authorization")
	}

	for _, body := range []string{
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
		if _, err := newHTTPCredentialProbe(endpoint, "/missing", ""); err == nil {
			t.Fatalf("accepted unsafe endpoint %q", endpoint)
		}
	}
	invalidCA := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(invalidCA, []byte(strings.Repeat("x", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newHTTPCredentialProbe("https://api.example/v1/auth/self", invalidCA, ""); err == nil {
		t.Fatal("accepted invalid CA")
	}
}

func writeServerCA(t *testing.T, server *httptest.Server) string {
	t.Helper()
	certificate := server.Certificate()
	contents := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
