// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"time"

	adminv1 "github.com/gobha-me/arcadectl/api/admin/v1"
	"github.com/gobha-me/arcadectl/internal/adminclient"
	"github.com/gobha-me/arcadectl/internal/cliattempt"
)

func terminal(operation adminv1.Operation) bool {
	if operation.UID == "" || operation.Generation < 1 || operation.ObservedGeneration != operation.Generation || operation.CompletedAt == "" {
		return false
	}
	if _, err := time.Parse(time.RFC3339Nano, operation.CompletedAt); err != nil {
		return false
	}
	return operation.Phase == "Succeeded" || operation.Phase == "Failed" || operation.Phase == "Cancelled"
}

func (app *application) emitAdmission(result cliattempt.Result) error {
	if app.output == "json" {
		return app.emit(struct {
			Version     string             `json:"version"`
			AttemptID   string             `json:"attemptID"`
			OperationID string             `json:"operationID"`
			Operation   *adminv1.Operation `json:"operation"`
		}{"v1", result.AttemptID, result.ExpectedOperationID, result.Operation})
	}
	if err := app.emit(*result.Operation); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(app.options.Out, "attempt %s; inspect with operation status or recover with operation resume\n", result.AttemptID); err != nil {
		return failure("local_io", 1)
	}
	return nil
}

// Resolve cannot replay. Only a definitive rejection or exact current terminal
// receipt may release a scope. Missing/stale/replaced receipts remain fenced.
func (app *application) resolve(ctx context.Context, client *adminclient.Client, saved adminclient.SavedContext, id string) error {
	store, err := app.attemptStore(false)
	if err != nil {
		return err
	}
	defer store.Close()
	result, err := store.Resume(ctx, client, saved.Identity, id, func(context.Context, cliattempt.Review) error { return cliattempt.ErrPrompt })
	rejected := errors.Is(err, cliattempt.ErrRejected) && result.State == cliattempt.StateRejected
	if !rejected {
		if err != nil {
			e := classify(err)
			if errors.Is(err, cliattempt.ErrPrompt) {
				e = failure("outcome_unknown", 5)
			}
			e.attemptID = result.AttemptID
			e.operationID = result.ExpectedOperationID
			return e
		}
		if result.Operation == nil || !terminal(*result.Operation) {
			return failure("pending_or_changed_intent", 4)
		}
		if result.ParentOperationID != "" && result.Operation.Phase == "Succeeded" {
			var parent adminv1.Operation
			if _, err := client.Read(ctx, "/v1/operations/"+result.ParentOperationID, &parent); err != nil {
				return err
			}
			if parent.UID != result.ParentOperationUID || !terminal(parent) {
				return failure("pending_or_changed_intent", 4)
			}
			if result.DestroyRef == nil || parent.Child == nil || parent.Child.Kind != "GameDestroy" || parent.Child.Name != result.DestroyRef.Name || parent.Child.UID != result.DestroyRef.UID {
				return failure("identity_or_preview_changed", 4)
			}
		}
	}
	if err := store.Resolve(ctx, saved.Identity, id); err != nil {
		return err
	}
	return app.emit(struct {
		Version   string `json:"version"`
		AttemptID string `json:"attemptID"`
		State     string `json:"state"`
	}{"v1", id, "resolved"})
}
