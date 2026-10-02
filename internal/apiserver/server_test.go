// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package apiserver

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/adminauth"
)

var testToken = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{17}, 32))
var testNow = time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)

type fakeAuthentication struct {
	principal adminauth.Principal
	err       error
	ready     bool
	calls     int
}

func (auth *fakeAuthentication) Authenticate(_ context.Context, token string) (adminauth.Principal, error) {
	auth.calls++
	if auth.err != nil {
		return adminauth.Principal{}, auth.err
	}
	if token != testToken {
		return adminauth.Principal{}, adminauth.ErrUnauthorized
	}
	return auth.principal, nil
}
func (auth *fakeAuthentication) Ready() bool { return auth.ready }

type fakeAudit struct {
	events []AuditEvent
	failAt int
	calls  int
}

func (audit *fakeAudit) Record(event AuditEvent) error {
	audit.calls++
	if audit.calls == audit.failAt {
		return errors.New("SECRET-CANARY audit sink error")
	}
	audit.events = append(audit.events, event)
	return nil
}

func testBoundary(t *testing.T) (*Server, *fakeAuthentication, *fakeAudit) {
	t.Helper()
	auth := &fakeAuthentication{ready: true, principal: adminauth.Principal{
		ID: "admin", CredentialID: "c27b3d14-436d-4f31-a1f4-416d7029cd8f",
		Roles: []adminauth.Role{adminauth.RoleAdministrator}, ExpiresAt: testNow.Add(time.Hour),
	}}
	audit := &fakeAudit{}
	server, err := New(Config{Authenticator: auth, Authorizer: AdministratorAuthorizer{}, Audit: audit,
		Namespace: "arcadectl-system", Clock: func() time.Time { return testNow }})
	if err != nil {
		t.Fatal(err)
	}
	return server, auth, audit
}

func authorizedRequest(method, path string) *http.Request {
	request := httptest.NewRequest(method, path, nil)
	request.Header.Set("Authorization", "Bearer "+testToken)
	return request
}

type unreadBody struct{ reads int }

func (body *unreadBody) Read([]byte) (int, error) { body.reads++; return 0, io.EOF }
func (*unreadBody) Close() error                  { return nil }

func TestCredentialDenialNeverEntersWriteOrReadsBody(t *testing.T) {
	for _, test := range []struct {
		name   string
		header http.Header
		query  string
	}{
		{"missing", http.Header{}, ""},
		{"basic", http.Header{"Authorization": {"Basic " + testToken}}, ""},
		{"duplicate", http.Header{"Authorization": {"Bearer " + testToken, "Bearer " + testToken}}, ""},
		{"duplicate-case", http.Header{"Authorization": {"Bearer " + testToken}, "authorization": {"Bearer " + testToken}}, ""},
		{"comma", http.Header{"Authorization": {"Bearer " + testToken + ", Bearer " + testToken}}, ""},
		{"padded", http.Header{"Authorization": {"Bearer " + testToken + "="}}, ""},
		{"extra-space", http.Header{"Authorization": {"Bearer  " + testToken}}, ""},
		{"leading-space", http.Header{"Authorization": {" Bearer " + testToken}}, ""},
		{"trailing-space", http.Header{"Authorization": {"Bearer " + testToken + " "}}, ""},
		{"wrong-size", http.Header{"Authorization": {"Bearer abc"}}, ""},
		{"oversize", http.Header{"Authorization": {"Bearer " + strings.Repeat("a", 9000)}}, ""},
		{"noncanonical-base64", http.Header{"Authorization": {"Bearer " + testToken[:42] + "F"}}, ""},
		{"cookie", http.Header{"Cookie": {"token=" + testToken}}, ""},
		{"query", http.Header{}, "?token=" + testToken},
		{"wrong-valid-token", http.Header{"Authorization": {"Bearer " + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{19}, 32))}}, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			server, _, audit := testBoundary(t)
			writes := 0
			if err := server.HandleMutation(http.MethodPost, "/v1/servers", ActionServerCreate, func(http.ResponseWriter, *http.Request, AuthorizedMutation) { writes++ }); err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPost, "/v1/servers"+test.query, nil)
			body := &unreadBody{}
			request.Body, request.Header = body, test.header
			writer := httptest.NewRecorder()
			server.ServeHTTP(writer, request)
			if writer.Code != http.StatusUnauthorized || writes != 0 || body.reads != 0 {
				t.Fatalf("status=%d writes=%d body reads=%d", writer.Code, writes, body.reads)
			}
			if len(audit.events) != 1 || audit.events[0].Outcome != "unauthenticated" || audit.events[0].PrincipalID != "" {
				t.Fatalf("unexpected denial audit: %+v", audit.events)
			}
			contents, _ := json.Marshal(audit.events)
			if strings.Contains(string(contents), testToken) || strings.Contains(writer.Body.String(), testToken) {
				t.Fatal("credential leaked")
			}
		})
	}
}

func TestAuthenticatorFailureAndIdentityValidation(t *testing.T) {
	for _, test := range []struct {
		name      string
		err       error
		principal adminauth.Principal
		want      int
	}{
		{name: "unavailable", err: adminauth.ErrUnavailable, want: 503},
		{name: "unknown-error", err: errors.New("SECRET-CANARY backend"), want: 401},
		{name: "expired", principal: adminauth.Principal{ID: "admin", CredentialID: "valid", ExpiresAt: testNow}, want: 401},
		{name: "missing-expiry", principal: adminauth.Principal{ID: "admin", CredentialID: "valid"}, want: 401},
		{name: "invalid-id", principal: adminauth.Principal{ID: "raw\nSECRET-CANARY", CredentialID: "valid", ExpiresAt: testNow.Add(time.Hour)}, want: 401},
		{name: "invalid-credential-id", principal: adminauth.Principal{ID: "admin", CredentialID: strings.Repeat("X", 65), ExpiresAt: testNow.Add(time.Hour)}, want: 401},
	} {
		t.Run(test.name, func(t *testing.T) {
			server, auth, audit := testBoundary(t)
			auth.err, auth.principal = test.err, test.principal
			writer := httptest.NewRecorder()
			server.ServeHTTP(writer, authorizedRequest(http.MethodGet, "/v1/auth/self"))
			if writer.Code != test.want {
				t.Fatalf("status=%d want=%d", writer.Code, test.want)
			}
			contents, _ := json.Marshal(audit.events)
			if strings.Contains(string(contents)+writer.Body.String(), "SECRET-CANARY") {
				t.Fatal("untrusted error or identity leaked")
			}
		})
	}
}

func TestAuthorizationRequiredForEveryWriteMethod(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			server, auth, audit := testBoundary(t)
			auth.principal.Roles = nil
			writes := 0
			if err := server.HandleMutation(method, "/v1/servers/{name}", ActionServerConfigure, func(http.ResponseWriter, *http.Request, AuthorizedMutation) { writes++ }); err != nil {
				t.Fatal(err)
			}
			body := &unreadBody{}
			request := authorizedRequest(method, "/v1/servers/example")
			request.Body = body
			writer := httptest.NewRecorder()
			server.ServeHTTP(writer, request)
			if writer.Code != 403 || writes != 0 || body.reads != 0 {
				t.Fatalf("status=%d writes=%d reads=%d", writer.Code, writes, body.reads)
			}
			if len(audit.events) != 1 || audit.events[0].Outcome != "forbidden" {
				t.Fatalf("bad authorization audit: %+v", audit.events)
			}
		})
	}
}

func TestMutationCapabilityAndOrderedIntent(t *testing.T) {
	server, auth, audit := testBoundary(t)
	if err := server.HandleMutation(http.MethodPost, "/v1/servers/{name}", ActionServerCreate, func(writer http.ResponseWriter, request *http.Request, capability AuthorizedMutation) {
		if len(audit.events) != 1 || audit.events[0].Phase != "intent" || audit.events[0].Outcome != "authorized" {
			t.Fatal("mutation entered before its successful intent audit")
		}
		if capability.Principal().ID != auth.principal.ID || capability.Action() != ActionServerCreate || capability.RequestID() != writer.Header().Get("X-Request-ID") {
			t.Fatal("wrong authenticated capability")
		}
		copy := capability.Principal()
		copy.Roles[0] = "changed"
		if capability.Principal().Roles[0] != adminauth.RoleAdministrator || request.PathValue("name") != "sample" {
			t.Fatal("capability alias or lost typed route parameter")
		}
		writer.WriteHeader(http.StatusAccepted)
	}); err != nil {
		t.Fatal(err)
	}
	writer := httptest.NewRecorder()
	server.ServeHTTP(writer, authorizedRequest(http.MethodPost, "/v1/servers/sample"))
	if writer.Code != 202 || len(audit.events) != 2 || audit.events[1].Phase != "outcome" || audit.events[1].Status != 202 {
		t.Fatalf("status=%d audit=%+v", writer.Code, audit.events)
	}
}

func TestAuditFailureFencesFutureMutationsWithoutLyingAboutAppliedResult(t *testing.T) {
	for _, test := range []struct {
		name                   string
		failAt, writes, status int
	}{
		{"intent", 1, 0, 503}, {"outcome", 2, 1, 202},
	} {
		t.Run(test.name, func(t *testing.T) {
			server, _, audit := testBoundary(t)
			audit.failAt = test.failAt
			writes := 0
			if err := server.HandleMutation(http.MethodPost, "/v1/servers", ActionServerCreate, func(writer http.ResponseWriter, _ *http.Request, _ AuthorizedMutation) {
				writes++
				writer.WriteHeader(http.StatusAccepted)
			}); err != nil {
				t.Fatal(err)
			}
			first := httptest.NewRecorder()
			server.ServeHTTP(first, authorizedRequest(http.MethodPost, "/v1/servers"))
			if first.Code != test.status || writes != test.writes || server.Ready() {
				t.Fatalf("status=%d writes=%d ready=%t", first.Code, writes, server.Ready())
			}
			second := httptest.NewRecorder()
			server.ServeHTTP(second, authorizedRequest(http.MethodPost, "/v1/servers"))
			if second.Code != 503 || writes != test.writes || strings.Contains(first.Body.String()+second.Body.String(), "SECRET-CANARY") {
				t.Fatal("failed audit did not fence later mutations or leaked error")
			}
			live, ready := httptest.NewRecorder(), httptest.NewRecorder()
			server.HealthHandler().ServeHTTP(live, httptest.NewRequest(http.MethodGet, "/livez", nil))
			server.HealthHandler().ServeHTTP(ready, httptest.NewRequest(http.MethodGet, "/readyz", nil))
			if live.Code != 200 || ready.Code != 503 {
				t.Fatal("wrong health after audit failure")
			}
		})
	}
}

func TestAuditNeverCopiesRequestInputs(t *testing.T) {
	server, _, audit := testBoundary(t)
	if err := server.HandleMutation(http.MethodPost, "/v1/servers/{name}", ActionServerConfigure, func(writer http.ResponseWriter, _ *http.Request, _ AuthorizedMutation) {
		writer.WriteHeader(204)
	}); err != nil {
		t.Fatal(err)
	}
	request := authorizedRequest(http.MethodPost, "/v1/servers/SECRET-CANARY?password=SECRET-CANARY")
	request.Header.Set("X-Request-ID", "SECRET-CANARY")
	request.Header.Set("Cookie", "secret=SECRET-CANARY")
	request.Body = io.NopCloser(strings.NewReader("SECRET-CANARY"))
	writer := httptest.NewRecorder()
	server.ServeHTTP(writer, request)
	contents, _ := json.Marshal(audit.events)
	if strings.Contains(string(contents), "SECRET-CANARY") || strings.Contains(string(contents), testToken) || strings.Contains(string(contents), "tokenSha256") {
		t.Fatal("request input leaked to audit")
	}
	if writer.Header().Get("X-Request-ID") == "SECRET-CANARY" || len(writer.Header().Get("X-Request-ID")) != 32 {
		t.Fatal("caller controlled request identity")
	}
	if audit.events[0].Route != "/v1/servers/{name}" {
		t.Fatal("audit not normalized")
	}
	unknown := authorizedRequest("SECRET-CANARY", "/SECRET-CANARY")
	server.ServeHTTP(httptest.NewRecorder(), unknown)
	last := audit.events[len(audit.events)-1]
	if last.Method != "OTHER" || last.Route != "unmatched" {
		t.Fatal("unmatched request inputs copied")
	}
}

func TestSelfAndReadinessContainNoSecrets(t *testing.T) {
	server, auth, _ := testBoundary(t)
	writer := httptest.NewRecorder()
	server.ServeHTTP(writer, authorizedRequest(http.MethodGet, "/v1/auth/self"))
	var body map[string]any
	if json.Unmarshal(writer.Body.Bytes(), &body) != nil || len(body) != 4 || body["version"] != "v1" || body["principalId"] != "admin" || body["credentialId"] != auth.principal.CredentialID || body["expiresAt"] != auth.principal.ExpiresAt.Format(time.RFC3339Nano) {
		t.Fatalf("invalid self response: %s", writer.Body)
	}
	if writer.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("credential identity response cacheable")
	}
	auth.ready = false
	auth.principal.ExpiresAt = testNow
	writer = httptest.NewRecorder()
	server.ServeHTTP(writer, authorizedRequest(http.MethodGet, "/v1/auth/self"))
	if writer.Code != 401 || server.Ready() {
		t.Fatal("expired credential must remain 401 and unready")
	}
}

func TestRouteRegistrationRejectsIncorrectMethodAndAction(t *testing.T) {
	server, _, _ := testBoundary(t)
	if server.HandleAuthenticatedRead(http.MethodPost, "/v1/test", ActionServerRead, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})) == nil {
		t.Fatal("read registration accepted write")
	}
	if server.HandleMutation(http.MethodGet, "/v1/test", ActionServerCreate, func(http.ResponseWriter, *http.Request, AuthorizedMutation) {}) == nil {
		t.Fatal("mutation registration accepted GET")
	}
	for _, action := range []Action{"unsafe-no-backup", "", "arbitrary", ActionAuthSelf} {
		if server.HandleMutation(http.MethodPost, "/v1/test", action, func(http.ResponseWriter, *http.Request, AuthorizedMutation) {}) == nil {
			t.Fatalf("accepted action %q", action)
		}
	}
	if server.HandleAuthenticatedRead(http.MethodGet, "/v1/auth/self", ActionAuthSelf, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})) == nil {
		t.Fatal("duplicate route accepted")
	}
	for _, path := range []string{"/healthz", "/v1/test?SECRET-CANARY", "/v1/{name...}", "/v1/test/", "/v1/test\n"} {
		if server.HandleAuthenticatedRead(http.MethodGet, path, ActionServerRead, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})) == nil {
			t.Fatalf("accepted invalid pattern %q", path)
		}
	}
	writer := httptest.NewRecorder()
	server.ServeHTTP(writer, httptest.NewRequest(http.MethodPost, "/not-a-route", nil))
	if writer.Code != 401 {
		t.Fatal("unknown route bypassed authentication")
	}
	writer = httptest.NewRecorder()
	server.HealthHandler().ServeHTTP(writer, authorizedRequest(http.MethodPost, "/livez"))
	if writer.Code != 405 {
		t.Fatal("public health accepted mutation")
	}
}

func TestCapturedCapabilityCannotExecuteAfterHandlerReturns(t *testing.T) {
	server, _, _ := testBoundary(t)
	other, _, _ := testBoundary(t)
	writes := 0
	var saved AuthorizedMutation
	execute := func(context.Context) error { writes++; return nil }
	if err := server.HandleMutation(http.MethodPost, "/v1/test", ActionServerCreate, func(writer http.ResponseWriter, _ *http.Request, capability AuthorizedMutation) {
		saved = capability
		if other.ExecuteMutation(capability, execute) == nil || server.ExecuteMutation(nil, execute) == nil {
			t.Fatal("foreign/missing capability executed")
		}
		if server.ExecuteMutation(capability, execute) != nil {
			t.Fatal("live guarded execution refused")
		}
		writer.WriteHeader(202)
	}); err != nil {
		t.Fatal(err)
	}
	server.ServeHTTP(httptest.NewRecorder(), authorizedRequest(http.MethodPost, "/v1/test"))
	if writes != 1 || server.ExecuteMutation(saved, execute) == nil || writes != 1 {
		t.Fatal("retained capability remained active")
	}
	if err := server.HandleAuthenticatedRead(http.MethodGet, "/v1/test", ActionServerRead, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		if server.ExecuteMutation(saved, execute) == nil {
			t.Fatal("read handler reused expired capability")
		}
	})); err != nil {
		t.Fatal(err)
	}
	server.ServeHTTP(httptest.NewRecorder(), authorizedRequest(http.MethodGet, "/v1/test"))
	if writes != 1 {
		t.Fatal("read route reached controlled mutation executor")
	}
}

type blockingAudit struct {
	blockedAt int
	calls     int
	release   chan struct{}
}

func (audit *blockingAudit) Record(AuditEvent) error {
	audit.calls++
	if audit.calls == audit.blockedAt {
		<-audit.release
	}
	return nil
}

func TestStalledAuditIsBoundedBeforeAndAfterMutation(t *testing.T) {
	for _, blockedAt := range []int{1, 2} {
		server, _, _ := testBoundary(t)
		audit := &blockingAudit{blockedAt: blockedAt, release: make(chan struct{})}
		server.audit, server.auditTimeout = audit, 20*time.Millisecond
		writes := 0
		if err := server.HandleMutation(http.MethodPost, "/v1/test", ActionServerCreate, func(writer http.ResponseWriter, _ *http.Request, _ AuthorizedMutation) {
			writes++
			writer.WriteHeader(202)
		}); err != nil {
			t.Fatal(err)
		}
		started := time.Now()
		writer := httptest.NewRecorder()
		server.ServeHTTP(writer, authorizedRequest(http.MethodPost, "/v1/test"))
		wantStatus, wantWrites := 503, 0
		if blockedAt == 2 {
			wantStatus, wantWrites = 202, 1
		}
		if time.Since(started) > time.Second || writer.Code != wantStatus || writes != wantWrites || server.Ready() {
			t.Fatal("stalled audit response not bounded/truthful/fenced")
		}
		server.ServeHTTP(httptest.NewRecorder(), authorizedRequest(http.MethodPost, "/v1/test"))
		if writes != wantWrites {
			t.Fatal("later mutation entered stalled audit")
		}
		close(audit.release)
	}
}

func TestHandlerPanicDoesNotLeakInputsAndIsAudited(t *testing.T) {
	server, _, audit := testBoundary(t)
	if err := server.HandleMutation(http.MethodPost, "/v1/test", ActionWorldBackup, func(http.ResponseWriter, *http.Request, AuthorizedMutation) { panic("SECRET-CANARY") }); err != nil {
		t.Fatal(err)
	}
	writer := httptest.NewRecorder()
	server.ServeHTTP(writer, authorizedRequest(http.MethodPost, "/v1/test"))
	contents, _ := json.Marshal(audit.events)
	if writer.Code != 500 || len(audit.events) != 2 || audit.events[1].Outcome != "internal" || strings.Contains(writer.Body.String()+string(contents), "SECRET-CANARY") {
		t.Fatal("panic response/audit unsafe")
	}
}

type shortWriter struct{}

func (shortWriter) Write(contents []byte) (int, error) { return len(contents) - 1, nil }

func TestJSONAuditPartialAndConcurrentWrites(t *testing.T) {
	if NewJSONAudit(shortWriter{}).Record(AuditEvent{Version: "v1"}) == nil {
		t.Fatal("partial write accepted")
	}
	if NewJSONAudit(nil).Record(AuditEvent{}) == nil {
		t.Fatal("nil writer accepted")
	}
	var output bytes.Buffer
	audit := NewJSONAudit(&output)
	var workers sync.WaitGroup
	for range 50 {
		workers.Go(func() {
			if err := audit.Record(AuditEvent{Version: "v1", RequestID: "server-selected"}); err != nil {
				t.Error(err)
			}
		})
	}
	workers.Wait()
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 50 {
		t.Fatalf("lines=%d", len(lines))
	}
	for _, line := range lines {
		var event AuditEvent
		if json.Unmarshal([]byte(line), &event) != nil || event.RequestID != "server-selected" {
			t.Fatal("interleaved audit output")
		}
	}
}
