// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package webui

import (
	"cmp"
	_ "embed"
	"html/template"
	"io"
	"slices"
	"time"

	adminv1 "github.com/gobha-me/arcadectl/api/admin/v1"
)

//go:embed templates/operations.html.tmpl
var operationListSource string

var operationListTemplate = template.Must(template.New("operations").Parse(operationListSource))

// operationRow deliberately contains only the read-only display allowlist.
// In particular, the template never receives the full receipt or its challenge.
type operationRow struct {
	OperationID, Action, Phase, StartedAt, CompletedAt string
	Failure                                            *operationFailure
	started                                            time.Time
	startedValid                                       bool
}

type operationFailure struct {
	Code, SuggestedAction string
	Retryable             bool
}

// RenderOperationList writes an accessible, read-only operations page. It does
// not mutate list, follow polling URLs, or expose receipt identity or challenges.
func RenderOperationList(w io.Writer, list adminv1.OperationList) error {
	rows := make([]operationRow, 0, len(list.Items))
	for _, operation := range list.Items {
		started, err := time.Parse(time.RFC3339Nano, operation.StartedAt)
		row := operationRow{
			OperationID: operation.OperationID, Action: operation.Action,
			Phase: operation.Phase, StartedAt: operation.StartedAt,
			CompletedAt: operation.CompletedAt, started: started, startedValid: err == nil,
		}
		if operation.Failure != nil {
			row.Failure = &operationFailure{
				Code: operation.Failure.Code, SuggestedAction: operation.Failure.SuggestedAction,
				Retryable: operation.Failure.Retryable,
			}
		}
		rows = append(rows, row)
	}
	slices.SortStableFunc(rows, func(a, b operationRow) int {
		// Missing or malformed timestamps have no chronological authority and
		// appear after dated receipts, in operation-ID order.
		if a.startedValid != b.startedValid {
			if a.startedValid {
				return -1
			}
			return 1
		}
		if order := b.started.Compare(a.started); order != 0 {
			return order
		}
		return cmp.Compare(a.OperationID, b.OperationID)
	})
	return operationListTemplate.Execute(w, rows)
}
