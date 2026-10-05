// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	adminv1 "github.com/gobha-me/arcadectl/api/admin/v1"
	"github.com/gobha-me/arcadectl/internal/adminauth"
)

const maxProbeResponseBytes = 2048

type httpCredentialProbe struct {
	endpoint string
	client   *http.Client
}

type selfResponse = adminv1.Self

func newHTTPCredentialProbe(endpoint, certificatePath, serverName string) (*httpCredentialProbe, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		parsed.Path != "/v1/auth/self" {
		return nil, errActivationIncomplete
	}
	certificate, err := readBoundedPublicFile(certificatePath, 1024*1024)
	if err != nil {
		return nil, errActivationIncomplete
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certificate) {
		return nil, errActivationIncomplete
	}
	if serverName == "" {
		serverName = parsed.Hostname()
	}
	transport := &http.Transport{
		Proxy:       nil,
		DialContext: (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: serverName,
		},
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
	}
	return &httpCredentialProbe{
		endpoint: parsed.String(),
		client: &http.Client{
			Transport:     transport,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

func (probe *httpCredentialProbe) Verify(ctx context.Context, credential adminauth.ClientCredential, oldToken string) error {
	if probe == nil || probe.client == nil || credential.Token == "" || oldToken == "" || credential.Token == oldToken {
		return errActivationIncomplete
	}
	status, body, err := probe.request(ctx, credential.Token)
	if err != nil || status != http.StatusOK {
		return errActivationIncomplete
	}
	response, err := parseSelfResponse(body)
	if err != nil || response.Version != "v1" || response.PrincipalID != adminauth.AdminPrincipalID ||
		response.CredentialID != credential.CredentialID || response.Namespace != adminauth.CredentialNamespace {
		return errActivationIncomplete
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, response.ExpiresAt)
	if err != nil || expiresAt.Location() != time.UTC || !expiresAt.Equal(credential.ExpiresAt) {
		return errActivationIncomplete
	}
	status, _, err = probe.request(ctx, oldToken)
	if err != nil || status != http.StatusUnauthorized {
		return errActivationIncomplete
	}
	return nil
}

func (probe *httpCredentialProbe) request(ctx context.Context, token string) (int, []byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, probe.endpoint, nil)
	if err != nil {
		return 0, nil, errActivationIncomplete
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "application/json")
	response, err := probe.client.Do(request)
	if err != nil {
		return 0, nil, errActivationIncomplete
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxProbeResponseBytes+1))
	if err != nil || len(body) > maxProbeResponseBytes {
		return 0, nil, errActivationIncomplete
	}
	return response.StatusCode, body, nil
}

func parseSelfResponse(contents []byte) (selfResponse, error) {
	if len(contents) == 0 || len(contents) > maxProbeResponseBytes || duplicateTopLevelKey(contents) {
		return selfResponse{}, errActivationIncomplete
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var response selfResponse
	if err := decoder.Decode(&response); err != nil {
		return selfResponse{}, errActivationIncomplete
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return selfResponse{}, errActivationIncomplete
	}
	if response.Version == "" || response.PrincipalID == "" || response.CredentialID == "" || response.ExpiresAt == "" || response.Namespace == "" {
		return selfResponse{}, errActivationIncomplete
	}
	return response, nil
}

func duplicateTopLevelKey(contents []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(contents))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return true
	}
	seen := map[string]struct{}{}
	for decoder.More() {
		keyToken, err := decoder.Token()
		key, ok := keyToken.(string)
		if err != nil || !ok {
			return true
		}
		if _, exists := seen[key]; exists {
			return true
		}
		seen[key] = struct{}{}
		var value any
		if err := decoder.Decode(&value); err != nil {
			return true
		}
	}
	closing, err := decoder.Token()
	return err != nil || closing != json.Delim('}')
}

func readBoundedPublicFile(path string, maximum int64) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errActivationIncomplete
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errActivationIncomplete
	}
	defer file.Close()
	contents, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(contents)) > maximum {
		return nil, errActivationIncomplete
	}
	return contents, nil
}
