// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	adminv1 "github.com/gobha-me/arcadectl/api/admin/v1"
	"github.com/gobha-me/arcadectl/internal/adminclient"
	"golang.org/x/net/html"
)

// The read interface is the explicit dependency fixture here. The separate
// command integration tests exercise the real saved context and adminclient.
type uiTLSReadFixture struct {
	server *httptest.Server
	mu     sync.Mutex
	paths  []string
	err    error
}

func (fixture *uiTLSReadFixture) Read(ctx context.Context, path string, out any) (string, error) {
	fixture.mu.Lock()
	fixture.paths = append(fixture.paths, path)
	err := fixture.err
	fixture.mu.Unlock()
	if err != nil {
		return "", err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, fixture.server.URL+path, nil)
	if err != nil {
		return "", err
	}
	response, err := fixture.server.Client().Do(request)
	if err != nil {
		return "", err
	}
	defer func() { _ = response.Body.Close() }()
	return "", json.NewDecoder(response.Body).Decode(out)
}

func (fixture *uiTLSReadFixture) count() int {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	return len(fixture.paths)
}

func TestUIHandlerWithTLSReadDependency(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method != "GET" || request.URL.Path != "/v1/servers" {
			t.Error("unexpected upstream route")
		}
		_ = json.NewEncoder(w).Encode(adminv1.ServerList{Version: "v1", Items: []adminv1.Server{{Name: "survival", Game: "example", Phase: "Stopped", Settings: json.RawMessage(`{"hidden":"SETTINGS-CANARY"}`)}}})
	}))
	defer upstream.Close()
	fixture := &uiTLSReadFixture{server: upstream}
	local := httptest.NewUnstartedServer(nil)
	local.Config.Handler = &uiHandler{client: fixture, host: local.Listener.Addr().String(), timeout: time.Second}
	local.Start()
	defer local.Close()
	for _, test := range []struct {
		method, path, host string
		status             int
		calls              int
	}{
		{"GET", "/", "", 200, 1}, {"HEAD", "/", "", 200, 1},
		{"POST", "/", "", 405, 0}, {"PUT", "/", "", 405, 0}, {"DELETE", "/", "", 405, 0},
		{"PATCH", "/", "", 405, 0}, {"OPTIONS", "/", "", 405, 0},
		{"GET", "/v1/servers", "", 404, 0}, {"GET", "/x", "", 404, 0},
		{"GET", "/?a=1", "", 404, 0}, {"GET", "/?", "", 404, 0}, {"GET", "/%2f", "", 404, 0},
		{"GET", "/", "foreign.example:80", 403, 0}, {"HEAD", "/", "foreign.example:80", 403, 0},
	} {
		t.Run(test.method+test.path+test.host, func(t *testing.T) {
			before := fixture.count()
			request, err := http.NewRequest(test.method, local.URL+test.path, nil)
			if err != nil {
				t.Fatal(err)
			}
			if test.host != "" {
				request.Host = test.host
			}
			response, err := local.Client().Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = response.Body.Close() }()
			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != test.status || fixture.count()-before != test.calls {
				t.Fatalf("status %d or upstream calls drift", response.StatusCode)
			}
			for name, want := range map[string]string{"Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "Cache-Control": "no-store"} {
				if response.Header.Get(name) != want {
					t.Errorf("missing security header %s", name)
				}
			}
			if strings.Contains(string(body), "SETTINGS-CANARY") {
				t.Fatal("settings exposed")
			}
			if test.method == "HEAD" && len(body) != 0 {
				t.Fatal("HEAD has a body")
			}
			if test.method == "GET" && test.status == 200 && !strings.Contains(string(body), "survival") {
				t.Fatal("renderer did not show server")
			}
			if test.status == 405 && response.Header.Get("Allow") != "GET, HEAD" {
				t.Fatal("missing Allow header")
			}
		})
	}
	for _, test := range []struct {
		err  error
		code string
	}{
		{&adminclient.Error{Code: "unavailable"}, "unavailable"},
		{&adminclient.Error{Code: "credential_expired"}, "credential_expired"},
		{errors.New("RAW-PRIVATE-CANARY"), "api_unavailable"},
	} {
		fixture.mu.Lock()
		fixture.err = test.err
		fixture.mu.Unlock()
		response, err := local.Client().Get(local.URL)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != 502 || !strings.Contains(string(body), "Error: "+test.code) || !strings.Contains(string(body), "arcadectl server status") || strings.Contains(string(body), "RAW-PRIVATE-CANARY") {
			t.Fatal("error response lost stable guidance or redaction")
		}
		assertUIErrorStructure(t, string(body))
	}
}

func assertUIErrorStructure(t *testing.T, body string) {
	t.Helper()
	document, err := html.Parse(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	h1, main, title, english, skip, alert := 0, 0, 0, false, false, false
	var visit func(*html.Node)
	visit = func(node *html.Node) {
		if node.Type == html.ElementNode {
			switch node.Data {
			case "h1":
				h1++
			case "title":
				title++
			case "script", "form", "input":
				t.Error("active error page content")
			}
			for _, attr := range node.Attr {
				english = english || node.Data == "html" && attr.Key == "lang" && attr.Val == "en"
				if node.Data == "main" && attr.Key == "id" && attr.Val == "main-content" {
					main++
				}
				skip = skip || node.Data == "a" && attr.Key == "href" && attr.Val == "#main-content"
				alert = alert || attr.Key == "role" && attr.Val == "alert"
				if strings.HasPrefix(attr.Key, "on") {
					t.Error("event handler attribute")
				}
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			visit(child)
		}
	}
	visit(document)
	if h1 != 1 || main != 1 || title != 1 || !english || !skip || !alert {
		t.Fatal("error page lost accessible structure")
	}
}

func TestUIAddressAndStableErrorAllowlist(t *testing.T) {
	for _, address := range []string{"127.0.0.1:0", "127.0.0.2:65535", "[::1]:0"} {
		if !validUIAddress(address) {
			t.Errorf("literal loopback rejected: %s", address)
		}
	}
	for _, address := range []string{"0.0.0.0:0", "[::]:0", "192.0.2.1:0", "localhost:0", ":0", "127.0.0.1", "127.0.0.1:-1", "127.0.0.1:65536", "127.0.0.1:http", "127.0.0.1:", "[::1%lo]:0"} {
		if validUIAddress(address) {
			t.Errorf("unsafe address accepted: %s", address)
		}
	}
	for _, code := range []string{"credential_expired", "credential_unavailable", "context_changed", "tls_unavailable", "request_timeout", "interrupted", "response_too_large", "invalid_response", "unauthenticated", "forbidden", "unavailable", "not_found"} {
		if got := uiReadError(&adminclient.Error{Code: code}); got != code {
			t.Errorf("stable read code %s mapped to %s", code, got)
		}
	}
	if got := uiReadError(fmt.Errorf("private: %s", "CANARY")); got != "api_unavailable" {
		t.Error("raw error exposed")
	}
	if got := uiReadError(&adminclient.Error{Code: "CANARY"}); got != "api_unavailable" {
		t.Error("remote code was not allowlisted")
	}
}

func TestUIAbsoluteRequestTargetRejected(t *testing.T) {
	fixture := &uiTLSReadFixture{}
	handler := &uiHandler{client: fixture, host: "127.0.0.1:1234", timeout: time.Second}
	request := httptest.NewRequest("GET", "http://127.0.0.1:1234/", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != 403 || fixture.count() != 0 {
		t.Fatal("absolute target reached API")
	}
}
