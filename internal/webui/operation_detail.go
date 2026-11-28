// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package webui

import (
	_ "embed"
	"errors"
	"html/template"
	"io"
	"regexp"
	"time"

	adminv1 "github.com/gobha-me/arcadectl/api/admin/v1"
)

//go:embed templates/operation.html.tmpl
var operationDetailSource string

var operationDetailTemplate = template.Must(template.New("operation").Parse(operationDetailSource))
var operationReceiptID = regexp.MustCompile(`^ao-[a-z2-7]{52}$`)

func operationDetailURL(id string) string {
	if !operationReceiptID.MatchString(id) {
		return ""
	}
	return "/operations/" + id
}

// operationDetail contains only display fields, never the receipt DTO.
type operationDetail struct {
	OperationID, DetailURL, Action, Phase, StartedAt, CompletedAt string
	Currentness, Status, NextStep                                 string
	Failure                                                       *operationFailure
}

// RenderOperationDetail writes an allowlisted, read-only receipt page. Receipt
// completion is distinct from the current runtime state of a game server.
func RenderOperationDetail(w io.Writer, operation adminv1.Operation) error {
	path := operationDetailURL(operation.OperationID)
	if path == "" {
		return errors.New("invalid operation receipt ID")
	}
	currentness, status, next := operationObservation(operation)
	page := operationDetail{
		OperationID: operation.OperationID, DetailURL: path,
		Action: operation.Action, Phase: operation.Phase,
		StartedAt: operation.StartedAt, CompletedAt: operation.CompletedAt,
		Currentness: currentness, Status: status, NextStep: next,
	}
	if operation.Failure != nil {
		page.Failure = &operationFailure{
			Code: operation.Failure.Code, Retryable: operation.Failure.Retryable,
			SuggestedAction: operation.Failure.SuggestedAction,
		}
	}
	return operationDetailTemplate.Execute(w, page)
}

func operationObservation(operation adminv1.Operation) (currentness, status, next string) {
	if operation.Generation < 1 || operation.ObservedGeneration != operation.Generation {
		return "Stale or unavailable", "Completion unconfirmed", "Refresh this receipt for current-generation evidence."
	}
	currentness = "Current generation"
	next = "Refresh this receipt to observe progress; this page cannot submit changes."
	switch operation.Phase {
	case "Accepted", "Pending", "Planning":
		return currentness, "Queued", next
	case "Running":
		return currentness, "Running", next
	case "AwaitingConfirmation":
		return currentness, "Awaiting confirmation", "This read-only page cannot confirm or cancel an operation."
	case "Succeeded", "Failed", "Cancelled":
		if _, err := time.Parse(time.RFC3339Nano, operation.CompletedAt); err != nil {
			return currentness, "Completion unconfirmed", "Completion time is missing or invalid; refresh this receipt."
		}
		switch operation.Phase {
		case "Succeeded":
			return currentness, "Completed successfully", "Check server status for current runtime state; this receipt describes completed work."
		case "Failed":
			return currentness, "Failed", "Review the stable failure code and guidance; failure does not authorize a new request."
		default:
			return currentness, "Cancelled", "Cancellation is not a rollback; check the exact operation and current server status."
		}
	default:
		return currentness, "Completion unconfirmed", next
	}
}
