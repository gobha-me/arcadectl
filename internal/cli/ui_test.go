// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/cli"
	"golang.org/x/net/html"
)

type uiOutput struct {
	mu sync.Mutex
	bytes.Buffer
	ready chan string
}

func (out *uiOutput) Write(value []byte) (int, error) {
	out.mu.Lock()
	defer out.mu.Unlock()
	count, err := out.Buffer.Write(value)
	select {
	case out.ready <- string(value):
	default:
	}
	return count, err
}

func (out *uiOutput) text() string {
	out.mu.Lock()
	defer out.mu.Unlock()
	return out.String()
}

type uiFixture struct {
	*integrationFixture
	mu       sync.Mutex
	requests []string
	fail     bool
}

func newUIFixture(t *testing.T) *uiFixture {
	t.Helper()
	fixture := &uiFixture{integrationFixture: newIntegrationFixture(t)}
	// Only the upstream API/store is a fixture. The CLI, saved context,
	// verified TLS client, listener, guards and renderer are production code.
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fixture.mu.Lock()
		fixture.requests = append(fixture.requests, r.Method+" "+r.URL.Path)
		fail := fixture.fail
		fixture.mu.Unlock()
		if fail && r.URL.Path == "/v1/servers" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = fmt.Fprintf(w, `{"version":"v1","code":"unavailable","suggestedAction":%q}`, integrationRawCanary+fixture.credentialFile)
			return
		}
		fixture.server.Config.Handler.ServeHTTP(w, r)
	}))
	t.Cleanup(upstream.Close)
	code, _, stderr := fixture.run(t, "login", "ui-fixture", "--api", upstream.URL, "--ca-file", fixture.caFile, "--credential-file", fixture.credentialFile)
	if code != 0 || stderr != "" {
		t.Fatal("UI API fixture login failed")
	}
	return fixture
}

func (fixture *uiFixture) snapshot() []string {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	return append([]string(nil), fixture.requests...)
}

func (fixture *uiFixture) start(t *testing.T, jsonOutput bool) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	out := &uiOutput{ready: make(chan string, 2)}
	var stderr bytes.Buffer
	done := make(chan int, 1)
	args := []string{"--context", "ui-fixture", "--timeout", "5s", "ui"}
	if jsonOutput {
		args = append([]string{"--output", "json"}, args...)
	}
	go func() {
		done <- cli.Run(ctx, args, cli.Options{In: strings.NewReader(""), Out: out, Err: &stderr, ConfigDir: fixture.config, StateDir: fixture.state})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case code := <-done:
			if code != 130 {
				t.Errorf("UI interruption exit = %d, want 130", code)
			}
		case <-time.After(5 * time.Second):
			t.Error("UI listener did not stop after cancellation")
			return
		}
		fixture.assertSafe(t, out.text()+stderr.String())
	})
	select {
	case output := <-out.ready:
		if jsonOutput {
			var result struct{ Version, URL string }
			if json.Unmarshal([]byte(output), &result) != nil || result.Version != "v1" {
				t.Fatal("UI did not print versioned listener metadata")
			}
			return result.URL
		}
		return strings.TrimSpace(output)
	case <-time.After(5 * time.Second):
		t.Fatal("UI did not announce its bound address")
		return ""
	}
}

func uiRequest(t *testing.T, method, url, host string) (int, http.Header, string) {
	t.Helper()
	request, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if host != "" {
		request.Host = host
	}
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 5 * time.Second}
	defer client.CloseIdleConnections()
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, response.Header, string(body)
}

func assertUIHeaders(t *testing.T, headers http.Header) {
	t.Helper()
	for name, value := range map[string]string{
		"Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
		"X-Content-Type-Options":  "nosniff", "Referrer-Policy": "no-referrer", "Cache-Control": "no-store",
		"Content-Type": "text/html; charset=utf-8",
	} {
		if headers.Get(name) != value {
			t.Errorf("%s = %q, want %q", name, headers.Get(name), value)
		}
	}
	if headers.Get("Set-Cookie") != "" || headers.Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("read-only UI introduced cookies or CORS")
	}
}

func TestUICommandServesStatusThroughVerifiedAPI(t *testing.T) {
	for _, jsonOutput := range []bool{false, true} {
		t.Run(fmt.Sprint(jsonOutput), func(t *testing.T) {
			fixture := newUIFixture(t)
			url := fixture.start(t, jsonOutput)
			if !strings.HasPrefix(url, "http://127.0.0.1:") {
				t.Fatal("default listener is not IPv4 loopback")
			}
			before := len(fixture.snapshot())
			status, headers, body := uiRequest(t, http.MethodGet, url, "")
			if status != 200 || !strings.Contains(body, "factory") || !strings.Contains(body, "Stopped") {
				t.Fatalf("status page = %d without expected server projection", status)
			}
			assertUIHeaders(t, headers)
			fixture.assertSafe(t, body+fmt.Sprint(headers))
			for _, private := range []string{fixture.credentialFile, fixture.caFile, fixture.config, "server-uid", "CLI world"} {
				if strings.Contains(body+fmt.Sprint(headers), private) {
					t.Fatal("UI leaked private context, identity, or settings")
				}
			}
			status, headers, body = uiRequest(t, http.MethodHead, url, "")
			if status != 200 || body != "" {
				t.Fatal("HEAD did not preserve status without a body")
			}
			assertUIHeaders(t, headers)
			requests := fixture.snapshot()[before:]
			if len(requests) != 2 {
				t.Fatalf("upstream read count = %d, want 2", len(requests))
			}
			for _, request := range requests {
				if request != "GET /v1/servers" {
					t.Fatal("UI contacted an unapproved upstream method or route")
				}
			}
			if fixture.mutationCount() != 0 {
				t.Fatal("status page mutated the API")
			}
		})
	}
}

func TestUIListenerGuardsBeforeAnyAPIRead(t *testing.T) {
	fixture := newUIFixture(t)
	url := fixture.start(t, false)
	for _, test := range []struct {
		method, suffix, host string
		status               int
	}{
		{"POST", "", "", 405}, {"PUT", "", "", 405}, {"DELETE", "", "", 405},
		{"PATCH", "", "", 405}, {"OPTIONS", "", "", 405},
		{"GET", "v1/servers", "", 404}, {"GET", "x", "", 404},
		{"GET", "?x=1", "", 404}, {"GET", "?", "", 404}, {"GET", "%2f", "", 404},
		{"GET", "", "foreign.example:1234", 403}, {"HEAD", "", "foreign.example:1234", 403},
	} {
		t.Run(test.method+test.suffix+test.host, func(t *testing.T) {
			before := len(fixture.snapshot())
			status, headers, body := uiRequest(t, test.method, url+test.suffix, test.host)
			if status != test.status || len(fixture.snapshot()) != before {
				t.Fatalf("guard status=%d want=%d, or guard contacted API", status, test.status)
			}
			assertUIHeaders(t, headers)
			if status == 405 && headers.Get("Allow") != "GET, HEAD" {
				t.Fatal("method refusal omitted allowed read methods")
			}
			fixture.assertSafe(t, body+fmt.Sprint(headers))
			if test.method == "HEAD" && body != "" {
				t.Fatal("HEAD error wrote a body")
			}
		})
	}
}

func TestUIAPIErrorIsAccessibleAndRedacted(t *testing.T) {
	fixture := newUIFixture(t)
	url := fixture.start(t, false)
	fixture.mu.Lock()
	fixture.fail = true
	fixture.mu.Unlock()
	status, headers, body := uiRequest(t, "GET", url, "")
	if status != 502 || !strings.Contains(body, "Error: unavailable") || !strings.Contains(body, "arcadectl server status") {
		t.Fatal("API failure lost stable code or recovery guidance")
	}
	assertUIHeaders(t, headers)
	fixture.assertSafe(t, body+fmt.Sprint(headers))
	if strings.Contains(body, fixture.credentialFile) {
		t.Fatal("raw API error path reached HTML")
	}
	document, err := html.Parse(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	h1, main, skip, alert, english := 0, false, false, false, false
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if node.Type == html.ElementNode {
			if node.Data == "h1" {
				h1++
			}
			for _, attr := range node.Attr {
				english = english || node.Data == "html" && attr.Key == "lang" && attr.Val == "en"
				if node.Data == "html" && attr.Key == "lang" && attr.Val != "en" {
					t.Error("wrong language")
				}
				main = main || node.Data == "main" && attr.Key == "id" && attr.Val == "main-content"
				skip = skip || node.Data == "a" && attr.Key == "href" && attr.Val == "#main-content"
				alert = alert || attr.Key == "role" && attr.Val == "alert"
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(document)
	if h1 != 1 || !main || !skip || !alert || !english {
		t.Fatal("error page lost accessible structure")
	}
	status, _, body = uiRequest(t, "HEAD", url, "")
	if status != 502 || body != "" {
		t.Fatal("HEAD failure drift")
	}
}

func TestUIRejectsNonLiteralOrNonLoopbackAddressesBeforeContextAccess(t *testing.T) {
	for _, address := range []string{"0.0.0.0:0", "[::]:0", "192.0.2.1:0", "localhost:0", ":0", "127.0.0.1", "127.0.0.1:-1", "127.0.0.1:65536", "127.0.0.1:http", "127.0.0.1:", "[::1%lo]:0"} {
		t.Run(address, func(t *testing.T) {
			var out, stderr bytes.Buffer
			code := cli.Run(context.Background(), []string{"--output", "json", "ui", "--listen", address}, cli.Options{Out: &out, Err: &stderr, ConfigDir: "/unavailable", StateDir: "/unavailable"})
			if code != 2 || out.Len() != 0 || !strings.Contains(stderr.String(), `"code":"invalid_arguments"`) {
				t.Fatal("unsafe listener did not fail before context access/binding")
			}
		})
	}
}
