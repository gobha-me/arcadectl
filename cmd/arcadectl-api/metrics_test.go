// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRequestMetricsServedOnlyOnPrivateListener(t *testing.T) {
	config, credential, roots := apiFixture(t)
	var audit bytes.Buffer
	api, health, _, err := newServers(config, &audit)
	if err != nil {
		t.Fatal(err)
	}
	public := httptest.NewUnstartedServer(api.Handler)
	public.Config, public.TLS = api, api.TLSConfig.Clone()
	public.StartTLS()
	defer public.Close()
	private := httptest.NewServer(health.Handler)
	defer private.Close()
	client := &http.Client{Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: "api.test"}}, Timeout: 3 * time.Second}
	defer client.CloseIdleConnections()
	request, err := http.NewRequest(http.MethodGet, public.URL+"/metrics", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+credential.Token)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal("ordinary TLS listener unavailable")
	}
	body, readErr := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || response.StatusCode != 404 || strings.Contains(string(body), "arcadectl_api_") {
		t.Fatal("ordinary TLS listener exposed metrics")
	}
	for _, path := range []string{"/livez", "/readyz", "/metrics"} {
		response, err := private.Client().Get(private.URL + path)
		if err != nil {
			t.Fatal("private health listener unavailable")
		}
		body, readErr := io.ReadAll(response.Body)
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil || response.StatusCode != 200 {
			t.Fatal("private health/metrics route failed")
		}
		if path == "/metrics" {
			text := string(body)
			if !strings.Contains(text, "arcadectl_api_requests_total{action=\"unmatched\",audit=\"acknowledged\",result=\"rejected\"} 1") || strings.Contains(text, credential.Token) || strings.Contains(text, credential.Bundle.CredentialID) || strings.Contains(text, credential.Bundle.TokenSHA256) {
				t.Fatal("private scrape lacked the request outcome or included credential material")
			}
		}
	}
}
