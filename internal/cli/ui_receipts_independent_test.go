// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package cli_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	adminv1 "github.com/gobha-me/arcadectl/api/admin/v1"
	"golang.org/x/net/html"
)

func TestUIReceiptErrorsThroughVerifiedAPI(t *testing.T) {
	const privatePath = "/private/receipt-diagnostic-canary"
	const privateHeader = "upstream-receipt-header-canary"
	const privateUID = "private-receipt-uid"
	const receiptETag = `"operation:` + privateUID + `:1"`
	otherID := "ao-" + strings.Repeat("z", 52)
	matchingPath := "/operations/" + otherID
	receiptJSON, err := json.Marshal(adminv1.Operation{
		Version: "v1", OperationID: otherID, UID: privateUID,
		Generation: 1, ObservedGeneration: 1, Action: "server.stop", Phase: "Running",
		PollURL: "/v1/operations/" + otherID,
	})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name       string
		path       string
		wireStatus int
		wireBody   string
		wireETag   string
		wantStatus int
		wantCode   string
	}{
		{
			name: "missing receipt", path: "/operations/ao-" + strings.Repeat("2", 52),
			wireStatus: http.StatusNotFound,
			wireBody:   fmt.Sprintf(`{"version":"v1","code":"not_found","suggestedAction":%q}`, privatePath),
			wantStatus: http.StatusNotFound, wantCode: "not_found",
		},
		{
			name: "malformed successful response", path: "/operations/ao-" + strings.Repeat("7", 52),
			wireStatus: http.StatusOK, wireBody: `{"raw":"` + privatePath + `"`,
			wantStatus: http.StatusBadGateway, wantCode: "invalid_response",
		},
		{
			name: "valid receipt with wrong identity", path: "/operations/ao-" + strings.Repeat("a", 52),
			wireStatus: http.StatusOK, wireBody: string(receiptJSON), wireETag: receiptETag,
			wantStatus: http.StatusBadGateway, wantCode: "invalid_response",
		},
		{
			name: "list service error", path: "/operations",
			wireStatus: http.StatusInternalServerError,
			wireBody:   fmt.Sprintf(`{"version":"v1","code":"internal","suggestedAction":%q}`, privatePath),
			wantStatus: http.StatusBadGateway, wantCode: "api_unavailable",
		},
	}

	fixture := &uiFixture{integrationFixture: newIntegrationFixture(t)}
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fixture.mu.Lock()
		fixture.requests = append(fixture.requests, r.Method+" "+r.RequestURI)
		fixture.mu.Unlock()
		if r.URL.Path == "/v1/auth/self" {
			fixture.server.Config.Handler.ServeHTTP(w, r)
			return
		}
		if r.URL.Path == "/v1"+matchingPath {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("ETag", receiptETag)
			_, _ = w.Write(receiptJSON)
			return
		}
		for _, test := range cases {
			if r.URL.Path == "/v1"+test.path {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("X-Private-Diagnostic", privateHeader)
				if test.wireETag != "" {
					w.Header().Set("ETag", test.wireETag)
				}
				w.WriteHeader(test.wireStatus)
				_, _ = fmt.Fprint(w, test.wireBody)
				return
			}
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(upstream.Close)
	code, _, stderr := fixture.run(t, "login", "ui-fixture", "--api", upstream.URL, "--ca-file", fixture.caFile, "--credential-file", fixture.credentialFile)
	if code != 0 || stderr != "" {
		t.Fatal("receipt error fixture login failed")
	}
	localURL := strings.TrimSuffix(fixture.start(t, false), "/")

	t.Run("same receipt body at its matching path", func(t *testing.T) {
		status, headers, body := uiRequest(t, http.MethodGet, localURL+matchingPath, "")
		if status != http.StatusOK || !strings.Contains(body, otherID) {
			t.Fatalf("valid receipt control returned status %d or omitted its identity", status)
		}
		assertUIHeaders(t, headers)
		if strings.Contains(body+fmt.Sprint(headers), privateUID) {
			t.Fatal("UI exposed the receipt UID or upstream ETag")
		}
	})

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			for _, method := range []string{http.MethodGet, http.MethodHead} {
				before := len(fixture.snapshot())
				status, headers, body := uiRequest(t, method, localURL+test.path, "")
				if status != test.wantStatus {
					t.Errorf("%s status = %d, want %d", method, status, test.wantStatus)
				}
				wantCalls := []string{"GET /v1" + test.path}
				if calls := fixture.snapshot()[before:]; !slices.Equal(calls, wantCalls) {
					t.Errorf("%s made %d upstream requests, want one GET for the exact path", method, len(calls))
				}
				assertUIHeaders(t, headers)
				output := body + fmt.Sprint(headers)
				fixture.assertSafe(t, output)
				for _, canary := range []string{privatePath, privateHeader, otherID, privateUID, fixture.credentialFile, fixture.caFile} {
					if strings.Contains(output, canary) {
						t.Fatal("UI error exposed upstream or private context data")
					}
				}
				if method == http.MethodHead {
					if body != "" {
						t.Error("HEAD error returned a response body")
					}
					continue
				}
				assertReceiptErrorRecovery(t, body, test.wantCode)
			}
		})
	}
}

func assertReceiptErrorRecovery(t *testing.T, body, code string) {
	t.Helper()
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	attribute := func(node *html.Node, name string) string {
		for _, attr := range node.Attr {
			if attr.Key == name {
				return attr.Val
			}
		}
		return ""
	}
	var alert, returnLink bool
	for node := range doc.Descendants() {
		if attribute(node, "role") == "alert" {
			for text := range node.Descendants() {
				alert = alert || text.Type == html.TextNode && strings.Contains(text.Data, code)
			}
		}
		if node.Type != html.ElementNode || node.Data != "nav" || strings.TrimSpace(attribute(node, "aria-label")) == "" {
			continue
		}
		for link := range node.Descendants() {
			if link.Type == html.ElementNode && link.Data == "a" && attribute(link, "href") == "/operations" && attribute(link, "tabindex") != "-1" {
				for label := range link.Descendants() {
					returnLink = returnLink || label.Type == html.TextNode && strings.TrimSpace(label.Data) != ""
				}
			}
		}
	}
	if !alert || !returnLink {
		t.Errorf("error page needs an alert with %q and a keyboard-reachable operations link in labelled navigation", code)
	}
}
