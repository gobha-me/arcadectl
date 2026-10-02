// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package image

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/platform/game"
)

const testManifestType = "application/vnd.oci.image.manifest.v1+json"

var testManifest = []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":1},"layers":[]}`)

func TestRegistryResolverAnonymousManifest(t *testing.T) {
	t.Parallel()
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != "/v2/example/game/manifests/2.0.72" || request.Header.Get("Accept") != manifestAccept || request.Header.Get("Authorization") != "" {
			t.Errorf("unexpected manifest request: %s %s headers=%v", request.Method, request.URL.Path, request.Header)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		writeManifest(writer, testManifest)
	}))
	defer server.Close()

	resolver := testResolver(server)
	resolution, err := resolver.Resolve(context.Background(), testDefinition(server, "example/game"), "2.0.72")
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if resolution.Repository != strings.TrimPrefix(server.URL, "https://")+"/example/game" || resolution.Tag != "2.0.72" || resolution.Digest != manifestDigest(testManifest) {
		t.Fatalf("Resolve() = %#v", resolution)
	}
}

func TestRegistryResolverAnonymousBearerFlow(t *testing.T) {
	t.Parallel()
	const token = "anonymous-token.canary"
	var manifestRequests atomic.Int32
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v2/example/game/manifests/1.2.3":
			if manifestRequests.Add(1) == 1 {
				writer.Header().Set("WWW-Authenticate", `Bearer realm="`+server.URL+`/token",service="`+request.Host+`",scope="repository:example/game:pull"`)
				writer.WriteHeader(http.StatusUnauthorized)
				return
			}
			if request.Header.Get("Authorization") != "Bearer "+token {
				t.Errorf("second request authorization was not the anonymous bearer token")
				writer.WriteHeader(http.StatusUnauthorized)
				return
			}
			writeManifest(writer, testManifest)
		case "/token":
			if request.Header.Get("Authorization") != "" || request.URL.Query().Get("service") != request.Host || request.URL.Query().Get("scope") != "repository:example/game:pull" {
				t.Errorf("unexpected token request: %s headers=%v", request.URL.String(), request.Header)
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(`{"token":"` + token + `"}`))
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	resolution, err := testResolver(server).Resolve(context.Background(), testDefinition(server, "example/game"), "1.2.3")
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if resolution.Digest != manifestDigest(testManifest) || manifestRequests.Load() != 2 {
		t.Fatalf("resolution = %#v, requests = %d", resolution, manifestRequests.Load())
	}
}

func TestRegistryResolverRejectsUntrustedBearerChallenge(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		challenge func(*httptest.Server, *http.Request) string
	}{
		{name: "realm host", challenge: func(_ *httptest.Server, request *http.Request) string {
			return `Bearer realm="https://other.example/token",service="` + request.Host + `",scope="repository:example/game:pull"`
		}},
		{name: "realm scheme", challenge: func(_ *httptest.Server, request *http.Request) string {
			return `Bearer realm="http://` + request.Host + `/token",service="` + request.Host + `",scope="repository:example/game:pull"`
		}},
		{name: "service", challenge: func(server *httptest.Server, _ *http.Request) string {
			return `Bearer realm="` + server.URL + `/token",service="other.example",scope="repository:example/game:pull"`
		}},
		{name: "scope", challenge: func(server *httptest.Server, request *http.Request) string {
			return `Bearer realm="` + server.URL + `/token",service="` + request.Host + `",scope="repository:other/game:pull"`
		}},
		{name: "extra parameter", challenge: func(server *httptest.Server, request *http.Request) string {
			return `Bearer realm="` + server.URL + `/token",service="` + request.Host + `",scope="repository:example/game:pull",error="denied"`
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var server *httptest.Server
			server = httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				writer.Header().Set("WWW-Authenticate", test.challenge(server, request))
				writer.WriteHeader(http.StatusUnauthorized)
			}))
			defer server.Close()
			_, err := testResolver(server).Resolve(context.Background(), testDefinition(server, "example/game"), "1.2.3")
			if !errors.Is(err, ErrRegistryResponseInvalid) {
				t.Fatalf("Resolve() error = %v", err)
			}
		})
	}
}

func TestRegistryResolverRejectsManifestIntegrityFailures(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		serve func(http.ResponseWriter)
	}{
		{name: "wrong digest", serve: func(writer http.ResponseWriter) {
			writer.Header().Set("Content-Type", testManifestType)
			writer.Header().Set("Docker-Content-Digest", "sha256:"+strings.Repeat("0", 64))
			_, _ = writer.Write(testManifest)
		}},
		{name: "missing digest", serve: func(writer http.ResponseWriter) {
			writer.Header().Set("Content-Type", testManifestType)
			_, _ = writer.Write(testManifest)
		}},
		{name: "wrong content type", serve: func(writer http.ResponseWriter) {
			writer.Header().Set("Content-Type", "application/json")
			writer.Header().Set("Docker-Content-Digest", manifestDigest(testManifest))
			_, _ = writer.Write(testManifest)
		}},
		{name: "media type mismatch", serve: func(writer http.ResponseWriter) {
			body := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}`)
			writer.Header().Set("Content-Type", testManifestType)
			writer.Header().Set("Docker-Content-Digest", manifestDigest(body))
			_, _ = writer.Write(body)
		}},
		{name: "oversized", serve: func(writer http.ResponseWriter) {
			writer.Header().Set("Content-Length", "4194305")
			writer.WriteHeader(http.StatusOK)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { test.serve(writer) }))
			defer server.Close()
			_, err := testResolver(server).Resolve(context.Background(), testDefinition(server, "example/game"), "1.2.3")
			if !errors.Is(err, ErrRegistryResponseInvalid) {
				t.Fatalf("Resolve() error = %v", err)
			}
		})
	}
}

func TestRegistryResolverRejectsRedirectAndTimeout(t *testing.T) {
	t.Parallel()
	var redirected atomic.Bool
	target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected.Store(true) }))
	defer target.Close()
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	_, err := testResolver(redirect).Resolve(context.Background(), testDefinition(redirect, "example/game"), "1.2.3")
	if !errors.Is(err, ErrRegistryUnavailable) || redirected.Load() {
		t.Fatalf("redirect error = %v, followed = %v", err, redirected.Load())
	}

	blocked := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { time.Sleep(100 * time.Millisecond) }))
	defer blocked.Close()
	resolver := testResolver(blocked)
	resolver.client.Timeout = 10 * time.Millisecond
	_, err = resolver.Resolve(context.Background(), testDefinition(blocked, "example/game"), "1.2.3")
	if !errors.Is(err, ErrRegistryUnavailable) {
		t.Fatalf("timeout error = %v", err)
	}
}

func TestRegistryResolverErrorsNeverContainBearerToken(t *testing.T) {
	t.Parallel()
	const canary = "token-secret-canary"
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/token" {
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(`{"token":"` + canary + `"}`))
			return
		}
		if request.Header.Get("Authorization") == "" {
			writer.Header().Set("WWW-Authenticate", `Bearer realm="`+server.URL+`/token",service="`+request.Host+`",scope="repository:example/game:pull"`)
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		writer.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	_, err := testResolver(server).Resolve(context.Background(), testDefinition(server, "example/game"), "1.2.3")
	if err == nil || strings.Contains(err.Error(), canary) {
		t.Fatalf("error leaked token: %v", err)
	}
}

func TestRegistryResolverRejectsOversizedTokenResponse(t *testing.T) {
	t.Parallel()
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/token" {
			writer.Header().Set("Content-Type", "application/json")
			writer.Header().Set("Content-Length", "16385")
			writer.WriteHeader(http.StatusOK)
			return
		}
		writer.Header().Set("WWW-Authenticate", `Bearer realm="`+server.URL+`/token",service="`+request.Host+`",scope="repository:example/game:pull"`)
		writer.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()
	_, err := testResolver(server).Resolve(context.Background(), testDefinition(server, "example/game"), "1.2.3")
	if !errors.Is(err, ErrRegistryResponseInvalid) {
		t.Fatalf("Resolve() error = %v", err)
	}
}

func testResolver(server *httptest.Server) *RegistryResolver {
	client := server.Client()
	client.Timeout = time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &RegistryResolver{client: client}
}

func testDefinition(server *httptest.Server, repository string) game.Definition {
	parsed, _ := url.Parse(server.URL)
	return game.Definition{
		ImageRepository: parsed.Host + "/" + repository,
		VersionPolicy:   &game.VersionPolicy{Pattern: `^[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}$`},
	}
}

func writeManifest(writer http.ResponseWriter, body []byte) {
	writer.Header().Set("Content-Type", testManifestType)
	writer.Header().Set("Docker-Content-Digest", manifestDigest(body))
	_, _ = writer.Write(body)
}

func manifestDigest(body []byte) string {
	digest := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(digest[:])
}
