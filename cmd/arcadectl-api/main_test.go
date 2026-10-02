// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/adminauth"
	"github.com/gobha-me/arcadectl/internal/apiserver"
)

func apiFixture(t *testing.T) (options, adminauth.Credential, *x509.CertPool) {
	t.Helper()
	directory := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "api.test"},
		DNSNames: []string{"api.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	config := options{
		listen: "127.0.0.1:0", healthListen: "127.0.0.1:0", verifierFile: filepath.Join(directory, "auth.json"),
		certificateFile: filepath.Join(directory, "tls.crt"), keyFile: filepath.Join(directory, "tls.key"),
	}
	for path, contents := range map[string][]byte{
		config.certificateFile: certificatePEM,
		config.keyFile:         pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	} {
		if os.WriteFile(path, contents, 0600) != nil {
			t.Fatal("write TLS fixture")
		}
	}
	credential, err := adminauth.GenerateCredential(time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := adminauth.MarshalVerifierBundle(credential.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	if os.WriteFile(config.verifierFile, verifier, 0600) != nil {
		t.Fatal("write verifier fixture")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certificatePEM) {
		t.Fatal("parse TLS fixture")
	}
	return config, credential, roots
}

func TestHTTPSOnlyAndProjectedCredentialRotation(t *testing.T) {
	config, credential, roots := apiFixture(t)
	var audit bytes.Buffer
	api, health, verifier, err := newServers(config, &audit)
	if err != nil {
		t.Fatal(err)
	}
	if api.TLSConfig.MinVersion != tls.VersionTLS12 || api.ReadHeaderTimeout == 0 || api.MaxHeaderBytes != 8192 || api.WriteTimeout == 0 || api.ReadTimeout == 0 {
		t.Fatal("missing TLS/request bounds")
	}
	server := httptest.NewUnstartedServer(api.Handler)
	server.Config = api
	server.TLS = api.TLSConfig.Clone()
	server.StartTLS()
	defer server.Close()
	client := &http.Client{Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: "api.test"}}, Timeout: 3 * time.Second}
	defer client.CloseIdleConnections()
	requestSelf := func(token string) (int, string) {
		request, err := http.NewRequest(http.MethodGet, server.URL+"/v1/auth/self", nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer "+token)
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		contents, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, string(contents)
	}
	if status, body := requestSelf(credential.Token); status != 200 || !strings.Contains(body, credential.Bundle.CredentialID) || strings.Contains(body, credential.Token) || strings.Contains(body, credential.Bundle.TokenSHA256) {
		t.Fatalf("initial self status=%d", status)
	}
	// A plaintext request never reaches authentication/audit, even if it tries
	// to send the bearer credential. The net/http diagnostic logger is silent.
	connection, err := net.DialTimeout("tcp", server.Listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = connection.SetDeadline(time.Now().Add(time.Second))
	_, _ = io.WriteString(connection, "GET /v1/auth/self HTTP/1.1\r\nHost: api.test\r\nAuthorization: Bearer SECRET-CANARY\r\nConnection: close\r\n\r\n")
	plaintextResponse, _ := io.ReadAll(connection)
	_ = connection.Close()
	if !strings.Contains(string(plaintextResponse), "400 Bad Request") || strings.Contains(audit.String(), "SECRET-CANARY") {
		t.Fatal("plaintext API accepted or logged credential")
	}
	untrusted := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: "api.test"}}, Timeout: time.Second}
	defer untrusted.CloseIdleConnections()
	if response, err := untrusted.Get(server.URL + "/v1/auth/self"); err == nil {
		response.Body.Close()
		t.Fatal("untrusted certificate accepted")
	}
	legacyTLS := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11, RootCAs: roots, ServerName: "api.test"}}, Timeout: time.Second}
	defer legacyTLS.CloseIdleConnections()
	if response, err := legacyTLS.Get(server.URL + "/v1/auth/self"); err == nil {
		response.Body.Close()
		t.Fatal("legacy TLS accepted")
	}
	rotated, err := adminauth.GenerateCredential(time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	rotated.Bundle.Serial = 2
	contents, _ := adminauth.MarshalVerifierBundle(rotated.Bundle)
	if os.WriteFile(config.verifierFile, contents, 0600) != nil || verifier.Reload() != nil {
		t.Fatal("reload rotated verifier")
	}
	if status, _ := requestSelf(rotated.Token); status != 200 {
		t.Fatalf("new credential status=%d", status)
	}
	if status, _ := requestSelf(credential.Token); status != 401 {
		t.Fatalf("rotated credential status=%d", status)
	}
	if os.WriteFile(config.verifierFile, []byte("SECRET-CANARY invalid"), 0600) != nil || verifier.Reload() == nil {
		t.Fatal("malformed verifier accepted")
	}
	if status, _ := requestSelf(rotated.Token); status != 503 {
		t.Fatal("invalid bundle retained last-good authentication")
	}
	readiness, liveness := httptest.NewRecorder(), httptest.NewRecorder()
	health.Handler.ServeHTTP(readiness, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	health.Handler.ServeHTTP(liveness, httptest.NewRequest(http.MethodGet, "/livez", nil))
	if readiness.Code != 503 || liveness.Code != 200 {
		t.Fatal("invalid credential health contract")
	}
	if strings.Contains(audit.String(), credential.Token) || strings.Contains(audit.String(), rotated.Token) || strings.Contains(audit.String(), "SECRET-CANARY") || strings.Contains(audit.String(), rotated.Bundle.TokenSHA256) {
		t.Fatal("API audit leaked credential material")
	}
}

func TestConfigurationHasNoInsecureOrInlineTokenOption(t *testing.T) {
	if _, err := parseOptions(nil); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"--token=SECRET-CANARY"}, {"--insecure"}, {"--namespace=other"}, {"--tls-key-file="},
		{"--listen=:8443", "--health-listen=:8443"}, {"SECRET-CANARY"},
	} {
		if _, err := parseOptions(args); err == nil {
			t.Fatal("unsafe configuration accepted")
		}
	}
	config, _, _ := apiFixture(t)
	config.keyFile = filepath.Join(t.TempDir(), "SECRET-CANARY")
	_, _, _, err := newServers(config, io.Discard)
	if err == nil || strings.Contains(err.Error(), "SECRET-CANARY") {
		t.Fatal("TLS startup error not fail-closed/redacted")
	}
}

func TestTLSValidityContinuouslyControlsOnlyReadiness(t *testing.T) {
	now := time.Now()
	leaf := &x509.Certificate{NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Minute)}
	current := now
	health := tlsHealthHandler(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(200) }), leaf, func() time.Time { return current })
	for _, test := range []struct {
		instant time.Time
		ready   int
	}{
		{now, 200}, {leaf.NotBefore, 200}, {leaf.NotBefore.Add(-time.Second), 503}, {leaf.NotAfter, 503}, {leaf.NotAfter.Add(time.Second), 503},
	} {
		current = test.instant
		ready, live := httptest.NewRecorder(), httptest.NewRecorder()
		health.ServeHTTP(ready, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		health.ServeHTTP(live, httptest.NewRequest(http.MethodGet, "/livez", nil))
		if ready.Code != test.ready || live.Code != 200 {
			t.Fatal("TLS validity health mismatch")
		}
	}
}

func TestBrokenStdoutAuditDoesNotTerminateProcess(t *testing.T) {
	const helperFlag = "ARCADECTL_TEST_BROKEN_AUDIT_PIPE"
	if os.Getenv(helperFlag) == "1" {
		disableAuditPipeTermination()
		if apiserver.NewJSONAudit(os.Stdout).Record(apiserver.AuditEvent{Version: "v1"}) == nil {
			os.Exit(3)
		}
		os.Exit(0)
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_ = reader.Close()
	defer writer.Close()
	command := exec.Command(os.Args[0], "-test.run=^TestBrokenStdoutAuditDoesNotTerminateProcess$")
	command.Env = append(os.Environ(), helperFlag+"=1")
	command.Stdout = writer
	if err := command.Run(); err != nil {
		t.Fatal("broken audit stdout terminated process instead of returning guarded failure")
	}
}
