// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package admincredential

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
	"time"

	adminv1 "github.com/gobha-me/arcadectl/api/admin/v1"
	"github.com/gobha-me/arcadectl/internal/adminauth"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	"k8s.io/apimachinery/pkg/util/validation"
)

const maxProbeResponseBytes = 2048

type HTTPSProbe struct {
	endpoint  string
	client    *http.Client
	namespace string
}

type selfResponse = adminv1.Self

func (probe *HTTPSProbe) Namespace() string {
	if probe == nil {
		return ""
	}
	return probe.namespace
}

func NewHTTPSProbe(options ProbeOptions) (*HTTPSProbe, error) {
	if len(validation.IsDNS1123Label(options.Namespace)) != 0 {
		return nil, ErrInvalidConfiguration
	}
	endpoint, certificatePath, serverName := options.Endpoint, options.CAFile, options.TLSServerName
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		parsed.Path != "/v1/auth/self" {
		return nil, ErrActivationIncomplete
	}
	certificate, err := readBoundedPublicFile(certificatePath, 1024*1024)
	if err != nil {
		return nil, ErrActivationIncomplete
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certificate) {
		return nil, ErrActivationIncomplete
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
	return &HTTPSProbe{
		endpoint:  parsed.String(),
		namespace: options.Namespace,
		client: &http.Client{
			Transport:     transport,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

func (probe *HTTPSProbe) Verify(ctx context.Context, credential adminauth.ClientCredential, oldToken string) error {
	if probe == nil || probe.client == nil || len(validation.IsDNS1123Label(probe.namespace)) != 0 || credential.Token == "" || oldToken == "" || credential.Token == oldToken {
		return ErrActivationIncomplete
	}
	status, body, err := probe.request(ctx, credential.Token)
	if err != nil || status != http.StatusOK {
		return ErrActivationIncomplete
	}
	response, err := parseSelfResponse(body)
	if err != nil || response.Version != "v1" || response.PrincipalID != adminauth.AdminPrincipalID ||
		response.CredentialID != credential.CredentialID || response.Namespace != probe.namespace {
		return ErrActivationIncomplete
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, response.ExpiresAt)
	if err != nil || expiresAt.Location() != time.UTC || !expiresAt.Equal(credential.ExpiresAt) {
		return ErrActivationIncomplete
	}
	status, _, err = probe.request(ctx, oldToken)
	if err != nil || status != http.StatusUnauthorized {
		return ErrActivationIncomplete
	}
	return nil
}

func (probe *HTTPSProbe) request(ctx context.Context, token string) (int, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, probe.endpoint, nil)
	if err != nil {
		return 0, nil, ErrActivationIncomplete
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "application/json")
	response, err := probe.client.Do(request)
	if err != nil {
		return 0, nil, ErrActivationIncomplete
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxProbeResponseBytes+1))
	if err != nil || len(body) > maxProbeResponseBytes {
		return 0, nil, ErrActivationIncomplete
	}
	return response.StatusCode, body, nil
}

func parseSelfResponse(contents []byte) (selfResponse, error) {
	if len(contents) == 0 || len(contents) > maxProbeResponseBytes || duplicateTopLevelKey(contents) {
		return selfResponse{}, ErrActivationIncomplete
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var response selfResponse
	if err := decoder.Decode(&response); err != nil {
		return selfResponse{}, ErrActivationIncomplete
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return selfResponse{}, ErrActivationIncomplete
	}
	if response.Version == "" || response.PrincipalID == "" || response.CredentialID == "" || response.ExpiresAt == "" || response.Namespace == "" {
		return selfResponse{}, ErrActivationIncomplete
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
	contents, _, err := privatefs.ReadAbsolute(path, maximum, privatefs.TrustedPublic)
	if err != nil {
		return nil, ErrActivationIncomplete
	}
	return contents, nil
}

func (probe *HTTPSProbe) Close() {
	if probe != nil && probe.client != nil {
		probe.client.CloseIdleConnections()
	}
}
