//go:build kindapi

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package install

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

type kindDiagnosticTransport func(*http.Request) (*http.Response, error)

func (transport kindDiagnosticTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return transport(request)
}

type kindDiagnosticTimeout struct{}

func (kindDiagnosticTimeout) Error() string   { return "PRIVATE-ERROR-CANARY" }
func (kindDiagnosticTimeout) Timeout() bool   { return true }
func (kindDiagnosticTimeout) Temporary() bool { return false }

type kindDiagnosticReadFailure struct{ closed bool }

func (*kindDiagnosticReadFailure) Read([]byte) (int, error) {
	return 0, errors.New("PRIVATE-BODY-ERROR-CANARY")
}
func (body *kindDiagnosticReadFailure) Close() error { body.closed = true; return nil }

func TestKindAPIRequestDiagnosticKeepsObservedPhaseAndStatus(t *testing.T) {
	for _, test := range []struct {
		name, body, phase, code string
		status                  int
		failed, operation       bool
	}{
		{"accepted", `{"operationID":"PRIVATE-OPERATION-CANARY"}`, "response", "unknown", 202, false, true},
		{"missing-id", `{}`, "response", "unknown", 202, false, false},
		{"auth", `{"code":"unauthenticated","message":"PRIVATE-BODY-CANARY"}`, "response", "unauthenticated", 401, false, false},
		{"commit-unknown", `{"code":"commit_unknown","operationID":"PRIVATE-OPERATION-CANARY"}`, "response", "commit_unknown", 503, false, true},
		{"dependency", `{"code":"api_unavailable"}`, "response", "api_unavailable", 503, false, false},
		{"content-type", `{"code":"invalid_content_type"}`, "response", "invalid_content_type", 415, false, false},
		{"body", `{"code":"invalid_body"}`, "response", "invalid_body", 400, false, false},
		{"idempotency-key", `{"code":"invalid_idempotency_key"}`, "response", "invalid_idempotency_key", 400, false, false},
		{"unknown-code", `{"code":"PRIVATE-CODE-CANARY\nstatus=202"}`, "response", "unknown", 503, false, false},
		{"invalid-json", "PRIVATE-BODY-CANARY", "response-json", "unknown", 502, true, false},
		{"too-large", strings.Repeat("X", 65537), "response-oversize", "unknown", 503, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			client := &http.Client{Transport: kindDiagnosticTransport(func(request *http.Request) (*http.Response, error) {
				calls++
				if request.Method != "POST" || request.URL.Path != "/v1/servers" || request.Header.Get("Authorization") != "Bearer PRIVATE-TOKEN-CANARY" || request.Header.Get("Idempotency-Key") != "PRIVATE-KEY-CANARY" || request.Header.Get("If-None-Match") != "*" || request.Header.Get("Content-Type") != "application/json" {
					t.Error("extracted helper changed the original request")
				}
				return &http.Response{StatusCode: test.status, Header: http.Header{"Etag": {"PRIVATE-ETAG-CANARY"}, "X-Request-Id": {"PRIVATE-HEADER-CANARY"}}, Body: io.NopCloser(strings.NewReader(test.body)), Request: request}, nil
			})}
			result := kindAPIRequest(t.Context(), client, "https://PRIVATE-URL-CANARY.invalid", "PRIVATE-TOKEN-CANARY", "POST", "/v1/servers", "PRIVATE-KEY-CANARY", "*", []byte(`{}`))
			if calls != 1 || result.err != test.failed || result.status != test.status || result.etag != "PRIVATE-ETAG-CANARY" || (result.operation.OperationID != "") != test.operation {
				t.Fatal("fixture request changed response handling or replayed a mutation")
			}
			want := "phase=" + test.phase + " status=" + strconv.Itoa(test.status) + " code=" + test.code + " deadline=false canceled=false timeout=false operation-id-present=" + boolText(test.operation)
			if result.diagnostic() != want || strings.Contains(result.diagnostic(), "PRIVATE") {
				t.Fatal("request diagnostic did not preserve bounded phase/status or leaked private data")
			}
		})
	}
	body := &kindDiagnosticReadFailure{}
	client := &http.Client{Transport: kindDiagnosticTransport(func(request *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 503, Body: body, Header: http.Header{}, Request: request}, nil
	})}
	result := kindAPIRequest(t.Context(), client, "https://PRIVATE-URL-CANARY.invalid", "PRIVATE", "POST", "/v1/servers", "PRIVATE", "*", nil)
	if !result.err || !body.closed || result.diagnostic() != "phase=response-read status=503 code=unknown deadline=false canceled=false timeout=false operation-id-present=false" {
		t.Fatal("read error lost observed status, leaked an error or did not close the response")
	}
}

func TestKindAPIRequestDiagnosticClassifiesActualCancellationWithoutReplay(t *testing.T) {
	for _, test := range []struct {
		name, expected string
		ctx            func() (context.Context, context.CancelFunc)
		err            error
	}{
		{"transport-timeout", "deadline=false canceled=false timeout=true", func() (context.Context, context.CancelFunc) { return context.WithCancel(t.Context()) }, kindDiagnosticTimeout{}},
		{"transport-error", "deadline=false canceled=false timeout=false", func() (context.Context, context.CancelFunc) { return context.WithCancel(t.Context()) }, errors.New("PRIVATE-ERROR-CANARY")},
		{"parent-deadline", "deadline=true canceled=false timeout=true", func() (context.Context, context.CancelFunc) {
			return context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
		}, context.DeadlineExceeded},
		{"parent-canceled", "deadline=false canceled=true timeout=false", func() (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			return ctx, cancel
		}, context.Canceled},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := test.ctx()
			defer cancel()
			calls := 0
			client := &http.Client{Transport: kindDiagnosticTransport(func(*http.Request) (*http.Response, error) { calls++; return nil, test.err })}
			result := kindAPIRequest(ctx, client, "https://PRIVATE-URL-CANARY.invalid", "PRIVATE", "POST", "/v1/servers", "PRIVATE", "*", nil)
			if !result.err || calls != 1 || result.diagnostic() != "phase=transport status=0 code=unknown "+test.expected+" operation-id-present=false" {
				t.Fatal("request did not classify actual transport/context state without replay")
			}
		})
	}
	client := &http.Client{Transport: kindDiagnosticTransport(func(*http.Request) (*http.Response, error) {
		t.Error("invalid request reached transport")
		return nil, nil
	})}
	result := kindAPIRequest(t.Context(), client, "https://PRIVATE-URL-CANARY.invalid", "PRIVATE", "PRIVATE\nMETHOD", "/v1/servers", "PRIVATE", "*", nil)
	if !result.err || result.diagnostic() != "phase=request-build status=0 code=unknown deadline=false canceled=false timeout=false operation-id-present=false" {
		t.Fatal("request-build failure was not closed and credential-free")
	}
	result = kindAPIRequest(nil, client, "https://PRIVATE-URL-CANARY.invalid", "PRIVATE", "POST", "/v1/servers", "PRIVATE", "*", nil)
	if !result.err || result.diagnostic() != "phase=request-build status=0 code=unknown deadline=false canceled=false timeout=false operation-id-present=false" {
		t.Fatal("nil-context build refusal did not stay closed")
	}
	for _, status := range []int{-1, 0, 99, 600, 999999} {
		result := kindAPIResult{status: status, code: "PRIVATE", phase: kindAPIRequestPhase(255)}
		if result.diagnostic() != "phase=unknown status=0 code=unknown deadline=false canceled=false timeout=false operation-id-present=false" {
			t.Fatal("diagnostic accepted an arbitrary phase, status or problem code")
		}
	}
}
