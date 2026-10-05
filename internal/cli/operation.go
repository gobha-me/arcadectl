// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	adminv1 "github.com/gobha-me/arcadectl/api/admin/v1"
	"github.com/gobha-me/arcadectl/internal/adminclient"
	"github.com/gobha-me/arcadectl/internal/cliattempt"
	"github.com/gobha-me/arcadectl/internal/cliintent"
	"github.com/spf13/cobra"
)

var objectID = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$`)
var receiptID = regexp.MustCompile(`^ao-[a-z2-7]{52}$`)

func (app *application) attemptStore(create bool) (*cliattempt.Store, error) {
	_, state, err := app.paths()
	if err != nil {
		return nil, err
	}
	return cliattempt.OpenStore(state, create)
}

func (app *application) submit(ctx context.Context, client *adminclient.Client, saved adminclient.SavedContext, scope string, fingerprint []byte, prepare func() (cliintent.Intent, error)) error {
	store, err := app.attemptStore(true)
	if err != nil {
		return err
	}
	defer store.Close()
	result, err := store.Submit(ctx, client, saved.Identity, scope, fingerprint, prepare)
	if err != nil {
		safe := classify(err)
		safe.attemptID = result.AttemptID
		safe.operationID = result.ExpectedOperationID
		return safe
	}
	return app.finish(ctx, client, store, saved.Identity, result)
}

func (app *application) finish(ctx context.Context, client *adminclient.Client, store *cliattempt.Store, identity adminclient.Identity, result cliattempt.Result) error {
	if result.Operation == nil {
		e := failure("outcome_unknown", 5)
		e.attemptID = result.AttemptID
		e.operationID = result.ExpectedOperationID
		return e
	}
	if app.noWait {
		return app.emitAdmission(result)
	}
	observation, cancel := context.WithTimeout(ctx, app.timeout)
	defer cancel()
	final, err := app.wait(observation, client, result.ExpectedOperationID, result.Operation.UID, result.Action == "world.destroy.preview", false)
	if err != nil {
		if terminal(final) && classify(err).code == "operation_failed" {
			if resolveErr := settleAttempt(ctx, store, identity, result, final.OperationID); resolveErr != nil {
				return resolveErr
			}
		}
		e := classify(err)
		e.attemptID = result.AttemptID
		e.operationID = result.ExpectedOperationID
		return e
	}
	if result.ParentOperationID != "" {
		final, err = app.waitExact(observation, client, result.ParentOperationID, result.ParentOperationUID, false, result.Action == "world.destroy.cancel", result.DestroyRef)
		if err != nil {
			if terminal(final) && classify(err).code == "operation_failed" {
				if resolveErr := settleAttempt(ctx, store, identity, result, final.OperationID); resolveErr != nil {
					return resolveErr
				}
			}
			e := classify(err)
			e.attemptID = result.AttemptID
			e.operationID = result.ParentOperationID
			return e
		}
	}
	if final.Phase != "AwaitingConfirmation" {
		if resolveErr := settleAttempt(ctx, store, identity, result, final.OperationID); resolveErr != nil {
			return resolveErr
		}
	}
	if final.Phase == "AwaitingConfirmation" {
		result.Operation = &final
		return app.emitAdmission(result)
	}
	return app.emit(final)
}

func settleAttempt(ctx context.Context, store *cliattempt.Store, identity adminclient.Identity, result cliattempt.Result, operationID string) error {
	if err := store.Resolve(ctx, identity, result.AttemptID); err != nil {
		safe := classify(err)
		safe.attemptID, safe.operationID = result.AttemptID, operationID
		return safe
	}
	return nil
}

func (app *application) wait(ctx context.Context, client *adminclient.Client, id, pinnedUID string, preview, cancelExpected bool) (adminv1.Operation, error) {
	return app.waitExact(ctx, client, id, pinnedUID, preview, cancelExpected, nil)
}

func (app *application) waitExact(ctx context.Context, client *adminclient.Client, id, pinnedUID string, preview, cancelExpected bool, child *adminv1.ExactReference) (adminv1.Operation, error) {
	if !receiptID.MatchString(id) {
		return adminv1.Operation{}, failure("invalid_arguments", 2)
	}
	interval := app.options.PollInterval
	if interval <= 0 {
		interval = 2 * time.Second
	}
	if interval > 30*time.Second {
		interval = 30 * time.Second
	}
	last := ""
	for {
		var operation adminv1.Operation
		_, err := client.Read(ctx, "/v1/operations/"+id, &operation)
		if err != nil {
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return operation, failure("timeout", 5)
			}
			if errors.Is(ctx.Err(), context.Canceled) {
				return operation, failure("interrupted", 130)
			}
			return operation, err
		}
		if operation.OperationID != id || operation.UID == "" || pinnedUID != "" && operation.UID != pinnedUID {
			return operation, failure("identity_or_preview_changed", 4)
		}
		if pinnedUID == "" {
			pinnedUID = operation.UID
		}
		if child != nil && (operation.Child == nil || operation.Child.Kind != "GameDestroy" || operation.Child.Name != child.Name || operation.Child.UID != child.UID) {
			return operation, failure("identity_or_preview_changed", 4)
		}
		current := operation.Generation >= 1 && operation.ObservedGeneration == operation.Generation
		if preview && current && operation.Phase == "AwaitingConfirmation" && operation.DestroyPreview != nil {
			return operation, nil
		}
		if current && operation.CompletedAt != "" {
			if _, err := time.Parse(time.RFC3339Nano, operation.CompletedAt); err != nil {
				return operation, failure("transport_or_protocol", 7)
			}
			switch operation.Phase {
			case "Succeeded":
				if cancelExpected {
					e := failure("operation_failed", 6)
					e.reason = "too_late"
					return operation, e
				}
				return operation, nil
			case "Cancelled":
				if cancelExpected {
					return operation, nil
				}
				return operation, failure("operation_failed", 6)
			case "Failed":
				e := failure("operation_failed", 6)
				if operation.Failure != nil {
					e.reason = operation.Failure.Code
				}
				return operation, e
			}
		}
		progress := operation.Phase
		if operation.Failure != nil {
			progress += "/" + operation.Failure.Code
		}
		if progress != last && app.output != "json" {
			if _, err := fmt.Fprintf(app.options.Err, "operation %s %s\n", id, progress); err != nil {
				return operation, failure("local_io", 1)
			}
			last = progress
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			if errors.Is(ctx.Err(), context.Canceled) {
				return operation, failure("interrupted", 130)
			}
			return operation, failure("timeout", 5)
		case <-timer.C:
		}
	}
}

func (app *application) operationCommand() *cobra.Command {
	root := &cobra.Command{Use: "operation", Short: "Inspect, wait on, or explicitly resume durable operations"}
	for _, action := range []string{"list", "status", "wait", "resume", "resolve"} {
		action := action
		argsCheck := exactArgs(1)
		use := action + " OPERATION_ID"
		if action == "list" {
			argsCheck = exactArgs(0)
			use = action
		}
		if action == "resume" || action == "resolve" {
			use = action + " ATTEMPT_ID"
		}
		root.AddCommand(&cobra.Command{Use: use, Short: map[string]string{"list": "List operation receipts", "status": "Inspect one receipt", "wait": "Wait without cancelling admitted work", "resume": "Recover the exact saved request; destructive replay requires fresh terminal confirmation", "resolve": "Release a local attempt only after definitive rejection or exact terminal evidence"}[action], Args: argsCheck, RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), app.timeout)
			defer cancel()
			client, saved, err := app.client(ctx)
			if err != nil {
				return err
			}
			defer client.Close()
			if action == "resolve" {
				return app.resolve(ctx, client, saved, args[0])
			}
			if action == "list" {
				var value adminv1.OperationList
				if _, err := client.Read(ctx, "/v1/operations", &value); err != nil {
					return err
				}
				return app.emit(value)
			}
			if action == "resume" {
				store, err := app.attemptStore(false)
				if err != nil {
					return err
				}
				defer store.Close()
				result, err := store.Resume(ctx, client, saved.Identity, args[0], app.resumePrompt(client))
				if err != nil {
					e := classify(err)
					e.attemptID = result.AttemptID
					e.operationID = result.ExpectedOperationID
					return e
				}
				return app.finish(ctx, client, store, saved.Identity, result)
			}
			if !receiptID.MatchString(args[0]) {
				return failure("invalid_arguments", 2)
			}
			if action == "status" {
				var value adminv1.Operation
				if _, err := client.Read(ctx, "/v1/operations/"+args[0], &value); err != nil {
					return err
				}
				return app.emit(value)
			}
			value, err := app.wait(ctx, client, args[0], "", true, false)
			if err != nil {
				e := classify(err)
				e.operationID = args[0]
				return e
			}
			return app.emit(value)
		}})
	}
	return root
}
