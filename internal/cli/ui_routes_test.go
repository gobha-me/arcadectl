// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	adminv1 "github.com/gobha-me/arcadectl/api/admin/v1"
	"github.com/gobha-me/arcadectl/internal/adminclient"
	"golang.org/x/net/html"
)

func TestUIReceiptRoutesKeepEveryAdmissionGuard(t *testing.T) {
	id := "ao-" + strings.Repeat("a", 52)
	other := "ao-" + strings.Repeat("b", 52)
	attack := `<script>alert(1)</script>"onmouseover=`
	private := "PRIVATE-RECEIPT-CANARY"
	operation := adminv1.Operation{OperationID: id, UID: private, Action: attack, Phase: "Running", Generation: 2, ObservedGeneration: 2, StartedAt: "2026-11-23T12:00:00Z", PollURL: "https://foreign.example/" + private,
		Failure: &adminv1.Failure{Code: attack, Retryable: true, Message: private, SuggestedAction: attack}, DestroyPreview: &adminv1.DestroyPreview{Challenge: private}}
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method != "GET" {
			t.Error("UI sent upstream mutation")
		}
		switch request.URL.Path {
		case "/v1/operations":
			_ = json.NewEncoder(w).Encode(adminv1.OperationList{Version: "v1", Items: []adminv1.Operation{{OperationID: other, Action: "server.stop", Phase: "Accepted", StartedAt: "2026-11-23T11:00:00Z"}, operation}})
		case "/v1/operations/" + id:
			_ = json.NewEncoder(w).Encode(operation)
		default:
			t.Error("non-allowlisted upstream path")
		}
	}))
	defer upstream.Close()
	fixture := &uiTLSReadFixture{server: upstream}
	local := httptest.NewUnstartedServer(nil)
	local.Config.Handler = &uiHandler{client: fixture, host: local.Listener.Addr().String(), timeout: time.Second}
	local.Start()
	defer local.Close()
	local.Client().Timeout = 5 * time.Second
	for _, path := range []string{"/operations", "/operations/" + id} {
		for _, method := range []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"} {
			for _, badHost := range []bool{false, true} {
				t.Run(method+path+fmt.Sprint(badHost), func(t *testing.T) {
					before := fixture.count()
					request, err := http.NewRequest(method, local.URL+path, nil)
					if err != nil {
						t.Fatal(err)
					}
					if badHost {
						request.Host = "foreign.example:80"
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
					wantStatus, calls := 200, 1
					if method != "GET" && method != "HEAD" {
						wantStatus, calls = 405, 0
					}
					if badHost {
						wantStatus, calls = 403, 0
					}
					if response.StatusCode != wantStatus || fixture.count()-before != calls {
						t.Fatalf("status %d want %d or upstream call count drift", response.StatusCode, wantStatus)
					}
					for name, want := range map[string]string{"Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "Cache-Control": "no-store"} {
						if response.Header.Get(name) != want {
							t.Errorf("security header %s missing", name)
						}
					}
					if strings.Contains(string(body)+fmt.Sprint(response.Header), private) {
						t.Fatal("private receipt data exposed")
					}
					if method == "HEAD" && len(body) != 0 {
						t.Fatal("HEAD body")
					}
					if method == "GET" && wantStatus == 200 {
						assertUIReceiptStructure(t, string(body), path)
						if !strings.Contains(string(body), id) {
							t.Fatal("receipt identity missing")
						}
						if path == "/operations" {
							if strings.Index(string(body), id) > strings.Index(string(body), other) {
								t.Fatal("operations order lost")
							}
							if !strings.Contains(string(body), `href="/operations/`+id+`"`) {
								t.Fatal("receipt link missing")
							}
						}
					}
				})
			}
		}
	}
	for _, path := range []string{"/operations/", "/operations/bad", "/operations/" + id + "/extra", "/operations/" + id + "/", "/operations/../", "/operations/%2e%2e/", "/operations/%2f", "/operations/%252f", "/operations/%5c", "/operations//", "/operations/.", "/operations/ao-" + strings.Repeat("A", 52), "/operations/ao-" + strings.Repeat("a", 51), "/operations/ao-" + strings.Repeat("a", 53), "/operations/ao-" + strings.Repeat("0", 52), "/operations/%61" + id[1:], "/operations?x=1", "/operations?", "/v1/operations", "/operations/" + id + "/stop"} {
		t.Run(path, func(t *testing.T) {
			before := fixture.count()
			response, err := local.Client().Get(local.URL + path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = response.Body.Close() }()
			if response.StatusCode != 404 || fixture.count() != before {
				t.Fatal("non-exact route reached upstream")
			}
			body, _ := io.ReadAll(response.Body)
			assertUIErrorStructure(t, string(body))
		})
	}
	fixture.mu.Lock()
	fixture.err = &adminclient.Error{Code: "not_found", HTTPStatus: 404}
	fixture.mu.Unlock()
	response, err := local.Client().Get(local.URL + "/operations/" + id)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 404 || !strings.Contains(string(body), "Error: not_found") {
		t.Fatal("missing receipt lost safe not-found projection")
	}
	assertUIErrorStructure(t, string(body))
	for _, code := range []string{"not_found", "invalid_response", "unavailable"} {
		fixture.mu.Lock()
		fixture.err = &adminclient.Error{Code: code}
		fixture.mu.Unlock()
		before := fixture.count()
		request, err := http.NewRequest("HEAD", local.URL+"/operations/"+id, nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := local.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		want := 502
		if code == "not_found" {
			want = 404
		}
		if response.StatusCode != want || len(body) != 0 || fixture.count()-before != 1 {
			t.Fatal("HEAD error status/body/read mismatch")
		}
	}
}

func assertUIReceiptStructure(t *testing.T, body, path string) {
	t.Helper()
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	h1, main, title := 0, 0, 0
	english, skip, nav, refresh := false, false, false, false
	var visit func(*html.Node)
	visit = func(node *html.Node) {
		if node.Type == html.ElementNode {
			switch node.Data {
			case "h1":
				h1++
			case "main":
				main++
			case "title":
				title++
			case "script", "form", "input":
				t.Error("active content in read-only UI")
			}
			for _, attr := range node.Attr {
				english = english || node.Data == "html" && attr.Key == "lang" && attr.Val == "en"
				skip = skip || node.Data == "a" && attr.Key == "href" && attr.Val == "#main-content"
				nav = nav || node.Data == "nav" && attr.Key == "aria-label" && attr.Val != ""
				refresh = refresh || node.Data == "a" && attr.Key == "href" && attr.Val == path
				if strings.HasPrefix(attr.Key, "on") {
					t.Error("event attribute")
				}
				if (attr.Key == "href" || attr.Key == "src") && !strings.HasPrefix(attr.Val, "/") && !strings.HasPrefix(attr.Val, "#") {
					t.Error("non-local link")
				}
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			visit(child)
		}
	}
	visit(doc)
	if h1 != 1 || main != 1 || title != 1 || !english || !skip || !nav || !refresh {
		t.Fatal("receipt view lost semantic structure/navigation/refresh")
	}
}

func TestUIReceiptRouteRejectsMismatchedUpstreamIdentity(t *testing.T) {
	id := "ao-" + strings.Repeat("a", 52)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(adminv1.Operation{OperationID: "ao-" + strings.Repeat("b", 52)})
	}))
	defer upstream.Close()
	fixture := &uiTLSReadFixture{server: upstream}
	handler := &uiHandler{client: fixture, host: "127.0.0.1:1234", timeout: time.Second}
	request := httptest.NewRequest("GET", "/operations/"+id, nil)
	request.Host = "127.0.0.1:1234"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != 502 || !strings.Contains(response.Body.String(), "Error: invalid_response") {
		t.Fatal("mismatched receipt rendered")
	}
}
