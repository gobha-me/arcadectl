// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	adminv1 "github.com/gobha-me/arcadectl/api/admin/v1"
	"github.com/gobha-me/arcadectl/internal/adminclient"
	"github.com/gobha-me/arcadectl/internal/cliattempt"
	"github.com/gobha-me/arcadectl/internal/clidestroy"
	"github.com/gobha-me/arcadectl/internal/clilifecycle"
)

type cliFailure struct {
	code                           string
	exit                           int
	operationID, attemptID, reason string
}

func (e *cliFailure) Error() string             { return "Arcadectl command did not complete" }
func failure(code string, exit int) *cliFailure { return &cliFailure{code: code, exit: exit} }

func classify(err error) *cliFailure {
	var local *cliFailure
	if errors.As(err, &local) {
		return local
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return failure("timeout", 5)
	}
	if errors.Is(err, context.Canceled) {
		return failure("interrupted", 130)
	}
	var remote *adminclient.Error
	if errors.As(err, &remote) {
		result := failure("api_error", 6)
		result.operationID = remote.OperationID
		result.reason = safeReason(remote.Code)
		switch remote.HTTPStatus {
		case 400, 404, 413, 415, 422:
			result.exit = 2
		case 401, 403:
			result.exit = 3
		case 409, 412, 428:
			result.exit = 4
		}
		if remote.Ambiguous {
			result.exit = 5
			result.code = "outcome_unknown"
		}
		if remote.HTTPStatus == 0 && !remote.Ambiguous {
			result.exit = 7
			result.code = "transport_or_protocol"
			switch remote.Code {
			case "credential_expired":
				result.exit = 3
				result.code = "authentication_expired"
			case "request_timeout":
				result.exit = 5
				result.code = "timeout"
			case "interrupted":
				result.exit = 130
				result.code = "interrupted"
			case "credential_unavailable", "context_unavailable":
				result.exit = 1
				result.code = "local_io"
			case "context_changed":
				result.exit = 4
				result.code = "context_changed"
			case "invalid_request":
				result.exit = 2
				result.code = "invalid_arguments"
			}
		}
		return result
	}
	if errors.Is(err, clilifecycle.ErrInvalidInput) {
		return failure("invalid_arguments", 2)
	}
	if errors.Is(err, clilifecycle.ErrInvalidReference) || errors.Is(err, clidestroy.ErrInvalidPreview) || errors.Is(err, clidestroy.ErrPreviewChanged) || errors.Is(err, clidestroy.ErrExpired) {
		return failure("identity_or_preview_changed", 4)
	}
	if errors.Is(err, clidestroy.ErrPrompt) {
		return failure("confirmation_required", 2)
	}
	if errors.Is(err, cliattempt.ErrReceiptMissing) {
		return failure("admitted_receipt_missing", 5)
	}
	if errors.Is(err, cliattempt.ErrResumeRequired) {
		return failure("outcome_unknown", 5)
	}
	if errors.Is(err, cliattempt.ErrPendingIntent) || errors.Is(err, cliattempt.ErrRejected) || errors.Is(err, cliattempt.ErrContextChanged) {
		return failure("pending_or_changed_intent", 4)
	}
	if errors.Is(err, cliattempt.ErrPrompt) {
		return failure("confirmation_required", 2)
	}
	return failure("local_io", 1)
}

func safeReason(code string) string {
	switch code {
	case "invalid_request", "target_changed", "operation_conflict", "invalid_reference", "secret_unavailable", "unsupported", "image_unavailable", "validation_failed", "worker_failed", "verification_failed", "too_late", "confirmation_expired", "child_changed", "api_unavailable", "receipt_invalid", "unauthenticated", "forbidden", "unavailable", "internal", "not_found", "method_not_allowed", "invalid_content_type", "invalid_body", "invalid_idempotency_key", "precondition_required", "invalid_precondition", "precondition_failed", "idempotency_conflict", "commit_unknown", "credential_expired":
		return code
	}
	return ""
}

func guidance(code string) string {
	switch code {
	case "admitted_receipt_missing":
		return "The previously admitted receipt is missing. Inspect the original endpoint and audit evidence; never resubmit or replace this intent."
	case "outcome_unknown":
		return "Preserve the saved attempt; inspect or explicitly resume that exact attempt. Do not create a replacement intent."
	case "timeout", "interrupted":
		return "Admitted work continues. Inspect or wait on the exact operation; timeout does not cancel it."
	case "context_changed":
		return "Re-establish the trusted context and inspect the original endpoint before deciding on another intent."
	case "identity_or_preview_changed":
		return "Read the exact original world, backup, parent receipt, and native child before taking another action."
	case "confirmation_required":
		return "Destroy confirmation requires a freshly typed exact challenge on a real terminal."
	case "operation_failed":
		return "Inspect this exact operation and native child; preserve retained worlds and backups."
	case "invalid_arguments":
		return "Consult command help; bearer tokens and destructive confirmation flags are not supported."
	default:
		return "Check the trusted context and exact operation status; never include credentials in diagnostics."
	}
}

func writeFailure(out io.Writer, jsonOutput bool, e *cliFailure) error {
	if jsonOutput {
		return json.NewEncoder(out).Encode(struct {
			Version         string `json:"version"`
			Code            string `json:"code"`
			OperationID     string `json:"operationID,omitempty"`
			AttemptID       string `json:"attemptID,omitempty"`
			Reason          string `json:"reason,omitempty"`
			SuggestedAction string `json:"suggestedAction"`
		}{"v1", e.code, e.operationID, e.attemptID, e.reason, guidance(e.code)})
	}
	if _, err := fmt.Fprintf(out, "%s", e.code); err != nil {
		return err
	}
	if e.operationID != "" {
		if _, err := fmt.Fprintf(out, " operation=%s", e.operationID); err != nil {
			return err
		}
	}
	if e.attemptID != "" {
		if _, err := fmt.Fprintf(out, " attempt=%s", e.attemptID); err != nil {
			return err
		}
	}
	if e.reason != "" {
		if _, err := fmt.Fprintf(out, " reason=%s", e.reason); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(out, "\n%s\n", guidance(e.code))
	return err
}

func (app *application) emit(value any) error {
	if app.output == "json" {
		if json.NewEncoder(app.options.Out).Encode(value) != nil {
			return failure("local_io", 1)
		}
		return nil
	}
	var err error
	switch v := value.(type) {
	case adminv1.Server:
		_, err = fmt.Fprintf(app.options.Out, "server %s %s desired=%s uid=%s generation=%d observed=%d\n", v.Name, v.Phase, v.DesiredState, v.UID, v.Generation, v.ObservedGeneration)
		for _, condition := range v.Conditions {
			if err != nil {
				break
			}
			_, err = fmt.Fprintf(app.options.Out, "condition=%s status=%s reason=%s observed=%d\n", condition.Type, condition.Status, condition.Reason, condition.ObservedGeneration)
		}
		for _, endpoint := range v.Endpoints {
			if err != nil {
				break
			}
			_, err = fmt.Fprintf(app.options.Out, "endpoint=%s %s %s:%d\n", endpoint.Name, endpoint.Protocol, endpoint.Address, endpoint.Port)
		}
	case adminv1.ServerList:
		for _, item := range v.Items {
			if err = app.emit(item); err != nil {
				return err
			}
		}
	case adminv1.Operation:
		_, err = fmt.Fprintf(app.options.Out, "operation %s %s %s generation=%d observed=%d\n", v.OperationID, v.Action, v.Phase, v.Generation, v.ObservedGeneration)
		if err == nil && v.Failure != nil {
			_, err = fmt.Fprintf(app.options.Out, "reason=%s retryable=%t\n%s\n", v.Failure.Code, v.Failure.Retryable, guidance("operation_failed"))
		}
	case adminv1.OperationList:
		for _, item := range v.Items {
			if err = app.emit(item); err != nil {
				return err
			}
		}
	case adminv1.RetainedWorld:
		_, err = fmt.Fprintf(app.options.Out, "retained world %s original=%s uid=%s data=%s\n", v.OperationID, v.OriginalServer.Name, v.OriginalServer.UID, v.DataIdentity)
		for _, claim := range v.Claims {
			if err != nil {
				break
			}
			_, err = fmt.Fprintf(app.options.Out, "claim %s %s uid=%s\n", claim.Path, claim.ClaimRef.Name, claim.ClaimRef.UID)
		}
	case adminclient.Identity:
		_, err = fmt.Fprintf(app.options.Out, "verified administrator %s namespace=%s\n", v.PrincipalID, v.Namespace)
	case adminclient.SavedContext:
		_, err = fmt.Fprintf(app.options.Out, "context %s administrator=%s namespace=%s\n", v.Config.Name, v.Identity.PrincipalID, v.Identity.Namespace)
	case []adminclient.SavedContext:
		for _, item := range v {
			if err = app.emit(item); err != nil {
				return err
			}
		}
	default:
		_, err = fmt.Fprintln(app.options.Out, "completed")
	}
	if err != nil {
		return failure("local_io", 1)
	}
	return nil
}
