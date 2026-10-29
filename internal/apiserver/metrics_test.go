// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package apiserver

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/adminauth"
)

func scrapeRequestMetrics(t *testing.T, server *Server) string {
	t.Helper()
	response := httptest.NewRecorder()
	server.HealthHandler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("private metrics unavailable or cacheable")
	}
	return response.Body.String()
}

func requireRequestSample(t *testing.T, body, action, result, audit string, count int) {
	t.Helper()
	want := fmt.Sprintf("arcadectl_api_requests_total{action=%q,audit=%q,result=%q} %d\n", action, audit, result, count)
	if !strings.Contains(body, want) {
		t.Fatalf("expected fixed request sample action=%s result=%s audit=%s count=%d", action, result, audit, count)
	}
}

func TestPrivateRequestMetricsDistinguishGuardsWithoutProjectingInputs(t *testing.T) {
	for _, test := range []struct {
		name, action, result string
		status               int
		prepare              func(*fakeAuthentication)
		request              func() *http.Request
	}{
		{"success", "auth.self", "succeeded", 200, nil, func() *http.Request { return authorizedRequest("GET", "/v1/auth/self") }},
		{"missing", "unmatched", "unauthenticated", 401, nil, func() *http.Request {
			return httptest.NewRequest("GET", "/v1/servers/PRIVATE-CANARY?token=PRIVATE-CANARY", nil)
		}},
		{"dependency", "unmatched", "unavailable", 503, func(a *fakeAuthentication) { a.err = adminauth.ErrUnavailable }, func() *http.Request { return authorizedRequest("GET", "/v1/auth/self") }},
		{"forbidden", "auth.self", "forbidden", 403, func(a *fakeAuthentication) { a.principal.Roles = nil }, func() *http.Request { return authorizedRequest("GET", "/v1/auth/self") }},
		{"unmatched", "unmatched", "rejected", 404, nil, func() *http.Request { return authorizedRequest("GET", "/PRIVATE-CANARY") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			server, auth, audit := testBoundary(t)
			if test.prepare != nil {
				test.prepare(auth)
			}
			response := httptest.NewRecorder()
			server.ServeHTTP(response, test.request())
			if response.Code != test.status {
				t.Fatalf("guard response changed: %d", response.Code)
			}
			calls, events := auth.calls, len(audit.events)
			body := scrapeRequestMetrics(t, server)
			requireRequestSample(t, body, test.action, test.result, "acknowledged", 1)
			if auth.calls != calls || len(audit.events) != events || strings.Count(body, "\narcadectl_api_requests_total{") != 1 {
				t.Fatal("scrape entered authentication/audit or added API samples")
			}
			for _, private := range []string{"PRIVATE-CANARY", testToken, auth.principal.ID, auth.principal.CredentialID, server.namespace, "go_goroutines", "process_", "request_id", "route="} {
				if private != "" && strings.Contains(body, private) {
					t.Fatal("private or unrelated data entered metrics")
				}
			}
		})
	}
}

func TestRequestMetricsKeepAppliedMutationAndAuditFailureDistinct(t *testing.T) {
	for _, failAt := range []int{1, 2} {
		t.Run(fmt.Sprint(failAt), func(t *testing.T) {
			server, _, audit := testBoundary(t)
			audit.failAt = failAt
			writes := 0
			if err := server.HandleMutation("POST", "/v1/test", ActionServerCreate, func(w http.ResponseWriter, _ *http.Request, _ AuthorizedMutation) {
				writes++
				w.WriteHeader(http.StatusCreated)
			}); err != nil {
				t.Fatal(err)
			}
			response := httptest.NewRecorder()
			server.ServeHTTP(response, authorizedRequest("POST", "/v1/test"))
			result, status, expectedWrites := "unavailable", 503, 0
			if failAt == 2 {
				result, status, expectedWrites = "succeeded", 201, 1
			}
			if response.Code != status || writes != expectedWrites || server.Ready() {
				t.Fatal("audit guard or truthful applied response changed")
			}
			requireRequestSample(t, scrapeRequestMetrics(t, server), "server.create", result, "unavailable", 1)
			response = httptest.NewRecorder()
			server.ServeHTTP(response, authorizedRequest("POST", "/v1/test"))
			if response.Code != 503 || writes != expectedWrites {
				t.Fatal("metrics bypassed unhealthy audit fence")
			}
			requireRequestSample(t, scrapeRequestMetrics(t, server), "unmatched", "unavailable", "unavailable", 1)
		})
	}
}

func TestRequestMetricsPrivateListenerAndRegistryIsolation(t *testing.T) {
	server, _, _ := testBoundary(t)
	other, _, _ := testBoundary(t)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, authorizedRequest("GET", "/metrics"))
	if response.Code != 404 || strings.Contains(response.Body.String(), "arcadectl_api_") {
		t.Fatal("ordinary API listener exposed metrics")
	}
	if strings.Contains(scrapeRequestMetrics(t, other), "arcadectl_api_requests_total{") {
		t.Fatal("request metrics crossed API boundary registries")
	}
	response = httptest.NewRecorder()
	server.HealthHandler().ServeHTTP(response, httptest.NewRequest("POST", "/metrics", strings.NewReader("PRIVATE-CANARY")))
	if response.Code != 405 {
		t.Fatal("metrics listener accepted a mutation method")
	}
	for i := 0; i < 1000; i++ {
		server.telemetry.observe(Action(fmt.Sprintf("PRIVATE-CANARY-%d", i)), fmt.Sprintf("PRIVATE-CANARY-%d", i), true, -time.Second)
	}
	body := scrapeRequestMetrics(t, server)
	requireRequestSample(t, body, "unmatched", "unknown", "acknowledged", 1000)
	if strings.Contains(body, "PRIVATE-CANARY") || strings.Count(body, "\narcadectl_api_requests_total{") != 2 || strings.Contains(body, "arcadectl_api_request_duration_seconds_count{action=\"unmatched\",audit=\"acknowledged\",result=\"unknown\"}") {
		t.Fatal("unbounded input became a metric series or invalid duration")
	}
}

func TestRequestMetricsRecordRecoveredPanicAsInternal(t *testing.T) {
	server, _, _ := testBoundary(t)
	if err := server.HandleAuthenticatedRead("GET", "/v1/test", ActionServerRead, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("PRIVATE-CANARY")
	})); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	server.ServeHTTP(response, authorizedRequest("GET", "/v1/test"))
	if response.Code != 500 || strings.Contains(response.Body.String(), "PRIVATE-CANARY") {
		t.Fatal("panic response changed or disclosed input")
	}
	requireRequestSample(t, scrapeRequestMetrics(t, server), "server.read", "internal", "acknowledged", 1)
}

func TestConcurrentRequestMetricsCountRealBoundaryOutcomes(t *testing.T) {
	server, err := New(Config{Authenticator: operationTestAuth{expires: time.Now().Add(time.Hour)}, Authorizer: AdministratorAuthorizer{}, Audit: NewJSONAudit(io.Discard), Namespace: "isolated"})
	if err != nil {
		t.Fatal(err)
	}
	const requests = 32
	var group sync.WaitGroup
	for i := 0; i < requests; i++ {
		group.Go(func() {
			response := httptest.NewRecorder()
			server.ServeHTTP(response, authorizedRequest("GET", "/v1/auth/self"))
			if response.Code != 200 {
				t.Error("concurrent guarded request failed")
			}
		})
	}
	group.Wait()
	requireRequestSample(t, scrapeRequestMetrics(t, server), "auth.self", "succeeded", "acknowledged", requests)
}
