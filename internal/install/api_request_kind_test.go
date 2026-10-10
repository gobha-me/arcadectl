//go:build kindapi

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package install

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"

	adminv1 "github.com/gobha-me/arcadectl/api/admin/v1"
)

type kindAPIRequestPhase uint8

const (
	kindAPIRequestUnknown kindAPIRequestPhase = iota
	kindAPIRequestBuild
	kindAPIRequestTransport
	kindAPIRequestRead
	kindAPIRequestOversize
	kindAPIRequestJSON
	kindAPIRequestResponse
)

type kindAPIResult struct {
	status    int
	etag      string
	operation adminv1.Operation
	server    adminv1.Server
	retained  adminv1.RetainedWorld
	code      string
	err       bool

	phase                       kindAPIRequestPhase
	deadline, canceled, timeout bool
}

// Fixture-only diagnostics. Do not format raw errors, URLs, headers, bodies,
// IDs or producer text. In particular a timeout is not a no-commit assertion.
func (result kindAPIResult) diagnostic() string {
	phase := "unknown"
	switch result.phase {
	case kindAPIRequestBuild:
		phase = "request-build"
	case kindAPIRequestTransport:
		phase = "transport"
	case kindAPIRequestRead:
		phase = "response-read"
	case kindAPIRequestOversize:
		phase = "response-oversize"
	case kindAPIRequestJSON:
		phase = "response-json"
	case kindAPIRequestResponse:
		phase = "response"
	}
	status := result.status
	if status < 100 || status > 599 {
		status = 0
	}
	code := "unknown"
	switch result.code {
	case "unauthenticated", "unavailable", "internal", "forbidden", "not_found", "method_not_allowed", "invalid_content_type", "invalid_body", "invalid_request", "invalid_idempotency_key", "unsupported", "invalid_reference", "invalid_precondition", "precondition_required", "precondition_failed", "idempotency_conflict", "image_unavailable", "validation_failed", "api_unavailable", "commit_unknown":
		code = result.code
	}
	return fmt.Sprintf("phase=%s status=%d code=%s deadline=%t canceled=%t timeout=%t operation-id-present=%t", phase, status, code, result.deadline, result.canceled, result.timeout, result.operation.OperationID != "")
}

func kindAPIRequest(ctx context.Context, client *http.Client, baseURL, token, method, path, key, etag string, body []byte) kindAPIResult {
	result := kindAPIResult{phase: kindAPIRequestBuild}
	failed := func(err error) kindAPIResult {
		result.err = true
		if ctx != nil {
			result.deadline = errors.Is(ctx.Err(), context.DeadlineExceeded)
			result.canceled = errors.Is(ctx.Err(), context.Canceled)
		}
		var timeout net.Error
		result.timeout = errors.As(err, &timeout) && timeout.Timeout()
		return result
	}
	r, err := http.NewRequestWithContext(ctx, method, baseURL+path, bytes.NewReader(body))
	if err != nil {
		return failed(err)
	}
	r.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	if key != "" {
		r.Header.Set("Idempotency-Key", key)
	}
	if etag == "*" {
		r.Header.Set("If-None-Match", "*")
	} else if etag != "" {
		r.Header.Set("If-Match", etag)
	}
	result.phase = kindAPIRequestTransport
	response, err := client.Do(r)
	if err != nil {
		return failed(err)
	}
	defer response.Body.Close()
	// Preserve observed status even if reading or validating the body fails.
	result.status, result.etag = response.StatusCode, response.Header.Get("ETag")
	result.phase = kindAPIRequestRead
	contents, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	if err != nil {
		return failed(err)
	}
	if len(contents) > 65536 {
		result.phase = kindAPIRequestOversize
		return failed(nil)
	}
	if !json.Valid(contents) {
		result.phase = kindAPIRequestJSON
		return failed(nil)
	}
	result.phase = kindAPIRequestResponse
	_ = json.Unmarshal(contents, &result.operation)
	_ = json.Unmarshal(contents, &result.server)
	_ = json.Unmarshal(contents, &result.retained)
	var problem adminv1.Error
	_ = json.Unmarshal(contents, &problem)
	result.code = problem.Code
	return result
}
