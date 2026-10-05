// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0
package adminclient

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	adminv1 "github.com/gobha-me/arcadectl/api/admin/v1"
	"github.com/gobha-me/arcadectl/internal/adminauth"
	"github.com/gobha-me/arcadectl/internal/canonicaljson"
	"github.com/gobha-me/arcadectl/internal/receiptid"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func privateTemp(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if os.Chmod(directory, 0o700) != nil {
		t.Fatal("private fixture directory")
	}
	return directory
}

func clientFixture(t *testing.T, handler func(http.ResponseWriter, *http.Request, adminauth.ClientCredential)) (ContextConfig, adminauth.ClientCredential, *atomic.Int32) {
	t.Helper()
	generated, e := adminauth.GenerateCredential(time.Now().UTC(), time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	credential := adminauth.ClientCredential{Version: "v1", CredentialID: generated.Bundle.CredentialID, Serial: 1, ExpiresAt: generated.Bundle.ExpiresAt, Token: generated.Token}
	requests := &atomic.Int32{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") != "Bearer "+credential.Token {
			w.WriteHeader(401)
			_ = json.NewEncoder(w).Encode(adminv1.Error{Version: "v1", Code: "unauthenticated"})
			return
		}
		if r.URL.Path == "/v1/auth/self" {
			_ = json.NewEncoder(w).Encode(adminv1.Self{Version: "v1", PrincipalID: "admin", CredentialID: credential.CredentialID, ExpiresAt: credential.ExpiresAt.Format(time.RFC3339Nano), Namespace: "isolated-games"})
			return
		}
		handler(w, r, credential)
	}))
	t.Cleanup(server.Close)
	base := privateTemp(t)
	ca := filepath.Join(base, "ca.pem")
	private := filepath.Join(base, "credential.json")
	if e := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600); e != nil {
		t.Fatal(e)
	}
	contents, _ := adminauth.MarshalClientCredential(credential)
	if e := os.WriteFile(private, contents, 0o600); e != nil {
		t.Fatal(e)
	}
	return ContextConfig{Version: "v1", Name: "fixture", APIOrigin: server.URL, TLSServerName: "127.0.0.1", CAFile: ca, CredentialFile: private}, credential, requests
}
func verifiedClient(t *testing.T, config ContextConfig) *Client {
	t.Helper()
	c, e := Load(config)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(c.Close)
	if _, e := c.Verify(context.Background()); e != nil {
		t.Fatal(e)
	}
	return c
}
func operationFor(key string) adminv1.Operation {
	id, _ := receiptid.ReceiptName("isolated-games", "admin", key)
	return adminv1.Operation{Version: "v1", OperationID: id, UID: "receipt-uid", Generation: 1, Action: "server.stop", Phase: "Accepted", PollURL: "/v1/operations/" + id}
}
func writeOperation(w http.ResponseWriter, operation adminv1.Operation) {
	w.Header().Set("ETag", fmt.Sprintf("\"operation:%s:%d\"", operation.UID, operation.Generation))
	w.WriteHeader(202)
	_ = json.NewEncoder(w).Encode(operation)
}
func stopBody() []byte {
	value, _ := canonicaljson.CanonicalJSON([]byte(`{"version":"v1"}`))
	return value
}
func TestVerifiedSubmitExactReceiptAndNoProxy(t *testing.T) {
	config, _, requests := clientFixture(t, func(w http.ResponseWriter, r *http.Request, _ adminauth.ClientCredential) {
		if r.Method != "POST" || r.URL.Path != "/v1/servers/factory/stop" || r.ProtoMajor != 1 || !r.Close || r.Header.Get("If-Match") != "\"server:original-uid:2\"" || len(r.Header.Values("Idempotency-Key")) != 1 {
			t.Error("mutation transport contract differs")
		}
		body, _ := io.ReadAll(r.Body)
		if string(body) != string(stopBody()) {
			t.Error("mutation body changed")
		}
		writeOperation(w, operationFor(r.Header.Get("Idempotency-Key")))
	})
	t.Setenv("HTTPS_PROXY", "http://proxy.invalid:1")
	c := verifiedClient(t, config)
	result, e := c.Submit(context.Background(), "POST", "/v1/servers/factory/stop", stopBody(), "exact-key", Conditional{IfMatch: "\"server:original-uid:2\""})
	if e != nil || result.OperationID != operationFor("exact-key").OperationID || requests.Load() != 2 {
		t.Fatal("exact one-shot receipt failed")
	}
}
func TestLostMutationResponseIsOneShotAndAmbiguous(t *testing.T) {
	config, credential, requests := clientFixture(t, func(w http.ResponseWriter, r *http.Request, _ adminauth.ClientCredential) {
		_, _ = io.ReadAll(r.Body)
		connection, _, e := w.(http.Hijacker).Hijack()
		if e != nil {
			t.Error("hijack")
			return
		}
		_ = connection.Close()
	})
	c := verifiedClient(t, config)
	_, e := c.Submit(context.Background(), "POST", "/v1/servers/factory/stop", stopBody(), "lost-key", Conditional{IfMatch: "\"server:original-uid:2\""})
	var failure *Error
	if !errors.As(e, &failure) || !failure.Ambiguous || failure.OperationID != operationFor("lost-key").OperationID || requests.Load() != 2 || strings.Contains(e.Error(), credential.Token) {
		t.Fatal("lost commit was retried or misreported")
	}
}

func TestUnsupportedMutationStatusCannotProveRejection(t *testing.T) {
	for _, status := range []int{201, 307} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			config, _, requests := clientFixture(t, func(w http.ResponseWriter, r *http.Request, _ adminauth.ClientCredential) {
				if r.Method != "POST" || r.URL.Path != "/v1/servers/factory/stop" {
					t.Error("unsupported status caused a redirect or extra request")
				}
				w.Header().Set("Location", "/redirected")
				w.WriteHeader(status)
				_ = json.NewEncoder(w).Encode(adminv1.Error{Version: "v1", Code: "invalid_request"})
			})
			c := verifiedClient(t, config)
			_, err := c.Submit(context.Background(), "POST", "/v1/servers/factory/stop", stopBody(), "unsupported-key", Conditional{IfMatch: `"server:original-uid:2"`})
			var failure *Error
			if !errors.As(err, &failure) || failure.Code != "invalid_response" || !failure.Ambiguous || failure.HTTPStatus != status || failure.OperationID != operationFor("unsupported-key").OperationID || requests.Load() != 2 {
				t.Fatal("unsupported post-send response released exact attempt or retried")
			}
		})
	}
}

func TestExpiredCredentialHasZeroRequestEffects(t *testing.T) {
	config, credential, requests := clientFixture(t, func(http.ResponseWriter, *http.Request, adminauth.ClientCredential) { t.Error("expired request sent") })
	c := verifiedClient(t, config)
	c.now = func() time.Time { return credential.ExpiresAt }
	_, e := c.Read(context.Background(), "/v1/servers", &adminv1.ServerList{})
	var failure *Error
	if !errors.As(e, &failure) || failure.Code != "credential_expired" || requests.Load() != 1 {
		t.Fatal("expiry boundary permitted network effects")
	}
}

type boundedTimeoutError struct{}

func (boundedTimeoutError) Error() string   { return "private-network-canary" }
func (boundedTimeoutError) Timeout() bool   { return true }
func (boundedTimeoutError) Temporary() bool { return true }

func TestRequestFailureClassifiesBoundedTimeoutWithoutRawErrors(t *testing.T) {
	for _, item := range []struct {
		cause error
		code  string
	}{
		{context.DeadlineExceeded, "request_timeout"},
		{&url.Error{Op: "private-op-canary", URL: "https://private-url-canary", Err: boundedTimeoutError{}}, "request_timeout"},
		{context.Canceled, "interrupted"},
		{errors.New("private-transport-canary"), "tls_unavailable"},
	} {
		failure := requestFailure(item.cause, false)
		if failure.Code != item.code || failure.Ambiguous || strings.Contains(failure.Error(), "canary") {
			t.Fatal("read classification leaked or lost bounded timeout")
		}
		failure = requestFailure(item.cause, true)
		if failure.Code != "ambiguous_submission" || !failure.Ambiguous || strings.Contains(failure.Error(), "canary") {
			t.Fatal("possible mutation commit was reported definitive")
		}
	}
}

func TestRequestTimeoutDuringHeadersOrBodyIsBounded(t *testing.T) {
	for _, bodyStarted := range []bool{false, true} {
		t.Run(strconv.FormatBool(bodyStarted), func(t *testing.T) {
			config, credential, _ := clientFixture(t, func(w http.ResponseWriter, r *http.Request, _ adminauth.ClientCredential) {
				if bodyStarted {
					_, _ = io.WriteString(w, `{"version":"v1","items":[`)
					w.(http.Flusher).Flush()
				}
				<-r.Context().Done()
			})
			c := verifiedClient(t, config)
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			_, err := c.Read(ctx, "/v1/servers", &adminv1.ServerList{})
			var failure *Error
			if !errors.As(err, &failure) || failure.Code != "request_timeout" || failure.Ambiguous || strings.Contains(err.Error(), credential.Token) {
				t.Fatal("bounded read timeout was not separately classified")
			}
		})
	}
}

func TestCanceledRequestBeforeTransportHasNoEffects(t *testing.T) {
	config, _, requests := clientFixture(t, func(http.ResponseWriter, *http.Request, adminauth.ClientCredential) {
		t.Error("cancelled request was sent")
	})
	c := verifiedClient(t, config)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.Submit(ctx, "POST", "/v1/servers/factory/stop", stopBody(), "pre-cancel-key", Conditional{IfMatch: "\"server:original-uid:2\""})
	var failure *Error
	if !errors.As(err, &failure) || failure.Code != "interrupted" || failure.Ambiguous || requests.Load() != 1 {
		t.Fatal("pretransport cancellation had side effects or was ambiguous")
	}
}

func TestCanceledMutationAfterSendRemainsAmbiguousOneShot(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	config, _, requests := clientFixture(t, func(_ http.ResponseWriter, r *http.Request, _ adminauth.ClientCredential) {
		_, _ = io.ReadAll(r.Body)
		cancel()
		<-r.Context().Done()
	})
	c := verifiedClient(t, config)
	_, err := c.Submit(ctx, "POST", "/v1/servers/factory/stop", stopBody(), "cancel-key", Conditional{IfMatch: "\"server:original-uid:2\""})
	var failure *Error
	if !errors.As(err, &failure) || failure.Code != "ambiguous_submission" || !failure.Ambiguous || failure.OperationID != operationFor("cancel-key").OperationID || requests.Load() != 2 {
		t.Fatal("post-send cancellation lost exact ambiguous receipt or retried")
	}
}
func TestMutationWrongReceiptAndMalformedResponsesStayAmbiguous(t *testing.T) {
	for _, mode := range []string{"wrong-id", "wrong-etag", "duplicate", "unknown", "echo", "escaped-echo", "too-large"} {
		t.Run(mode, func(t *testing.T) {
			config, credential, _ := clientFixture(t, func(w http.ResponseWriter, r *http.Request, credential adminauth.ClientCredential) {
				operation := operationFor("response-key")
				switch mode {
				case "wrong-id":
					operation.OperationID = operationFor("other-key").OperationID
					operation.PollURL = "/v1/operations/" + operation.OperationID
				case "wrong-etag":
					w.Header().Set("ETag", "\"operation:other-uid:1\"")
					w.WriteHeader(202)
					_ = json.NewEncoder(w).Encode(operation)
					return
				case "duplicate":
					w.WriteHeader(202)
					_, _ = io.WriteString(w, `{"version":"v1","version":"v1"}`)
					return
				case "unknown":
					w.WriteHeader(202)
					_, _ = io.WriteString(w, `{"version":"v1","token":"x"}`)
					return
				case "echo", "escaped-echo":
					text := credential.Token
					if mode == "escaped-echo" {
						text = ""
						for _, ch := range credential.Token {
							text += fmt.Sprintf("\\u%04x", ch)
						}
					}
					w.WriteHeader(202)
					_, _ = io.WriteString(w, `{"message":"`+text+`"}`)
					return
				case "too-large":
					w.WriteHeader(202)
					_, _ = io.WriteString(w, strings.Repeat(" ", 65537))
					return
				}
				writeOperation(w, operation)
			})
			c := verifiedClient(t, config)
			_, e := c.Submit(context.Background(), "POST", "/v1/servers/factory/stop", stopBody(), "response-key", Conditional{IfMatch: "\"server:original-uid:2\""})
			var failure *Error
			if !errors.As(e, &failure) || !failure.Ambiguous || failure.OperationID != operationFor("response-key").OperationID || strings.Contains(e.Error(), credential.Token) {
				t.Fatal("unsafe success projection")
			}
		})
	}
}
func TestContextTrustChangesAndCredentialFilesystemChecks(t *testing.T) {
	config, _, requests := clientFixture(t, func(http.ResponseWriter, *http.Request, adminauth.ClientCredential) {})
	c := verifiedClient(t, config)
	saved := SavedContext{Config: c.config, Identity: c.Identity()}
	ca, e := os.ReadFile(config.CAFile)
	if e != nil {
		t.Fatal(e)
	}
	if os.WriteFile(config.CAFile, append(ca, '\n'), 0o600) != nil {
		t.Fatal("CA replacement")
	}
	if _, e := LoadSaved(saved); e == nil || requests.Load() != 1 {
		t.Fatal("changed trust sent a credential")
	}
	if os.Chmod(config.CredentialFile, 0o644) != nil {
		t.Fatal("chmod")
	}
	if _, e := Load(config); e == nil {
		t.Fatal("unsafe credential mode accepted")
	}
}
func TestResponseCodecDoesNotExpandNumbersAndRejectsAmbiguity(t *testing.T) {
	for _, body := range []string{`{"version":"v1","items":[],"items":[]}`, `{"Version":"v1","items":[]}`, `{"version":"v1","items":[]}{}`, `{"version":"v1","items":[],"unknown":0}`, strings.Repeat("[", 34) + strings.Repeat("]", 34)} {
		if decodeResponse([]byte(body), &adminv1.ServerList{}) == nil {
			t.Fatal("ambiguous JSON accepted")
		}
	}
	var body struct {
		Settings json.RawMessage `json:"settings"`
	}
	if decodeResponse([]byte(`{"settings":{"number":1e999999999}}`), &body) != nil || !strings.Contains(string(body.Settings), "1e999999999") {
		t.Fatal("response number was expanded")
	}
	if decodeResponse([]byte(`{"settings":{"number":`+strings.Repeat("1", 129)+`}}`), &body) == nil {
		t.Fatal("unbounded numeric token accepted")
	}
	// A legitimate list exceeds a blanket64KiB budget without exponent expansion.
	server := adminv1.Server{Version: "v1", Name: "factory", UID: "server-uid", Generation: 1, Game: "factorio", ImageDigest: "sha256:" + strings.Repeat("1", 64), DesiredState: "Stopped", Phase: "Stopped", Settings: json.RawMessage(`{"description":"` + strings.Repeat("x", 2000) + `"}`)}
	list := adminv1.ServerList{Version: "v1"}
	for i := 0; i < 100; i++ {
		item := server
		item.Name = "factory-" + strconv.Itoa(i)
		list.Items = append(list.Items, item)
	}
	raw, _ := json.Marshal(list)
	if len(raw) <= 65536 || decodeResponse(raw, &list) != nil || validateResponse(&list) != nil {
		t.Fatal("bounded larger list rejected")
	}
}
func TestInvalidRoutesAndPreconditionsHaveZeroEffects(t *testing.T) {
	config, _, requests := clientFixture(t, func(http.ResponseWriter, *http.Request, adminauth.ClientCredential) { t.Error("invalid input sent") })
	c := verifiedClient(t, config)
	for _, path := range []string{"https://other.example/v1/servers", "//other.example/v1/servers", "/v1/servers?token=x", "/v1/servers/name%2fother", "/v1/unsafe"} {
		if _, e := c.Read(context.Background(), path, &adminv1.ServerList{}); e == nil {
			t.Fatal("unsafe path accepted")
		}
	}
	for _, etag := range []string{"W/\"server:uid:1\"", "\"server:uid:01\"", "\"server:uid:1\", \"server:uid:2\""} {
		if _, e := c.Submit(context.Background(), "POST", "/v1/servers/factory/stop", stopBody(), "key", Conditional{IfMatch: etag}); e == nil {
			t.Fatal("unsafe precondition accepted")
		}
	}
	if requests.Load() != 1 {
		t.Fatal("invalid input performed effects")
	}
}
