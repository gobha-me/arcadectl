// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package install

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

// Classify the bounded private capture without printing it. These values are
// observations only; a timeout or absent ID never establishes no admission.
func nativeCLICompletionDiagnostic(ctx context.Context, elapsed time.Duration, exit int, stderr []byte, stdoutTruncated, stderrTruncated bool) string {
	if exit < -1 || exit > 255 {
		exit = -1
	}
	if elapsed < 0 {
		elapsed = 0
	}
	if elapsed > 48*time.Hour {
		elapsed = 48 * time.Hour
	}
	var failure struct {
		Version     string `json:"version"`
		Code        string `json:"code"`
		Reason      string `json:"reason"`
		OperationID string `json:"operationID"`
		AttemptID   string `json:"attemptID"`
	}
	valid := !stderrTruncated && len(stderr) <= 65536 && json.Unmarshal(stderr, &failure) == nil && failure.Version == "v1"
	code, reason := "unknown", "unknown"
	if valid {
		switch failure.Code {
		case "timeout", "interrupted", "api_error", "outcome_unknown", "transport_or_protocol", "authentication_expired", "local_io", "context_changed", "invalid_arguments", "identity_or_preview_changed", "confirmation_required", "operation_failed", "admitted_receipt_missing", "pending_or_changed_intent":
			code = failure.Code
		}
		switch failure.Reason {
		case "unauthenticated", "forbidden", "api_unavailable", "unavailable", "internal", "not_found", "target_changed", "operation_conflict", "invalid_reference", "secret_unavailable", "unsupported", "image_unavailable", "validation_failed", "worker_failed", "verification_failed", "too_late", "confirmation_expired", "child_changed", "receipt_invalid", "commit_unknown", "credential_expired":
			reason = failure.Reason
		}
	}
	deadline, canceled := false, false
	if ctx != nil {
		deadline, canceled = ctx.Err() == context.DeadlineExceeded, ctx.Err() == context.Canceled
	}
	return fmt.Sprintf("exit=%d elapsed-ms=%d deadline=%t canceled=%t error-json=%t code=%s reason=%s operation-id-present=%t attempt-id-present=%t stdout-truncated=%t stderr-truncated=%t",
		exit, elapsed.Milliseconds(), deadline, canceled, valid, code, reason, valid && failure.OperationID != "", valid && failure.AttemptID != "", stdoutTruncated, stderrTruncated)
}

// Closed test-only vocabulary. Never render command arguments, private output,
// error text, endpoint, server/operation identity, or credential-file paths.
func nativeCLIStage(args []string) string {
	if len(args) > 0 && args[0] == "login" {
		return "login"
	}
	if len(args) > 1 {
		switch {
		case args[0] == "server" && args[1] == "status":
			return "server-status"
		case args[0] == "server" && args[1] == "start":
			return "server-start"
		case args[0] == "server" && args[1] == "stop":
			return "server-stop"
		case args[0] == "operation" && args[1] == "wait":
			return "operation-wait"
		}
	}
	return "unavailable"
}

func TestNativeCLIStageIsClosedAndCredentialFree(t *testing.T) {
	for _, fixture := range []struct {
		args []string
		want string
	}{
		{nil, "unavailable"},
		{[]string{"PRIVATE-CANARY"}, "unavailable"},
		{[]string{"server"}, "unavailable"},
		{[]string{"server", "PRIVATE-CANARY"}, "unavailable"},
		{[]string{"PRIVATE-CANARY", "wait"}, "unavailable"},
		{[]string{"login", "PRIVATE-CANARY", "--credential-file", "PRIVATE-CANARY"}, "login"},
		{[]string{"server", "status", "PRIVATE-CANARY"}, "server-status"},
		{[]string{"server", "start", "PRIVATE-CANARY", "--no-wait"}, "server-start"},
		{[]string{"server", "stop", "PRIVATE-CANARY"}, "server-stop"},
		{[]string{"operation", "wait", "PRIVATE-CANARY"}, "operation-wait"},
	} {
		if nativeCLIStage(fixture.args) != fixture.want {
			t.Fatal("fixed native CLI stage escaped its closed vocabulary")
		}
	}
}
