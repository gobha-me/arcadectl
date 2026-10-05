// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"time"

	adminv1 "github.com/gobha-me/arcadectl/api/admin/v1"
	"github.com/gobha-me/arcadectl/internal/adminclient"
	"github.com/gobha-me/arcadectl/internal/canonicaljson"
	"github.com/gobha-me/arcadectl/internal/cliattempt"
	"github.com/gobha-me/arcadectl/internal/clidestroy"
	"github.com/gobha-me/arcadectl/internal/cliintent"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

func (app *application) destroyCommand() *cobra.Command {
	root := &cobra.Command{Use: "destroy", Short: "Exactly confirm or cancel a prepared backup-gated destroy"}
	for _, action := range []string{"confirm", "cancel"} {
		action := action
		root.AddCommand(&cobra.Command{Use: action + " PARENT_OPERATION_ID", Short: map[string]string{"confirm": "Show exact world inventory and type its challenge on a real terminal", "cancel": "Request cancellation; admission is not rollback and deletion may already be too late"}[action], Args: exactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
			if !receiptID.MatchString(args[0]) {
				return failure("invalid_arguments", 2)
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), app.timeout)
			defer cancel()
			client, saved, err := app.client(ctx)
			if err != nil {
				return err
			}
			defer client.Close()
			scope := "world.destroy." + action + "/" + args[0]
			raw := []byte(fmt.Sprintf(`{"action":"world.destroy.%s","parentOperationId":"%s","version":"v1"}`, action, args[0]))
			fingerprint, err := canonicaljson.CanonicalJSON(raw)
			if err != nil {
				return failure("invalid_arguments", 2)
			}
			return app.submit(ctx, client, saved, scope, fingerprint, func() (cliintent.Intent, error) {
				if action == "confirm" {
					return clidestroy.PrepareConfirm(ctx, client, args[0], app.prompt)
				}
				return clidestroy.PrepareCancel(ctx, client, args[0])
			})
		}})
	}
	return root
}

func (app *application) resumePrompt(client *adminclient.Client) cliattempt.ResumePrompt {
	return func(ctx context.Context, review cliattempt.Review) error {
		if review.Action != "world.destroy.confirm" {
			return nil
		}
		if review.DestroyPreview == nil || review.DestroyRef == nil {
			return failure("confirmation_required", 2)
		}
		var parent adminv1.Operation
		if _, err := client.Read(ctx, "/v1/operations/"+review.ParentOperationID, &parent); err != nil {
			return err
		}
		if parent.UID != review.ParentOperationUID {
			return failure("identity_or_preview_changed", 4)
		}
		fresh, err := clidestroy.PrepareConfirm(ctx, client, review.ParentOperationID, func(ctx context.Context, preview adminv1.DestroyPreview) error {
			if !reflect.DeepEqual(preview, *review.DestroyPreview) {
				return failure("identity_or_preview_changed", 4)
			}
			return app.prompt(ctx, preview)
		})
		if err != nil {
			return err
		}
		if fresh.Conditional != review.Conditional || !reflect.DeepEqual(fresh.DestroyRef, review.DestroyRef) || !reflect.DeepEqual(fresh.DestroyPreview, review.DestroyPreview) {
			return failure("identity_or_preview_changed", 4)
		}
		// The caller discards this newly validated intent and posts only saved bytes.
		return nil
	}
}

// No flag, environment value, pipe, old response, or controlling-terminal
// fallback can supply confirmation. Both input and displayed inventory must
// be actual terminal descriptors; polling makes SIGINT/deadline responsive.
func (app *application) prompt(ctx context.Context, preview adminv1.DestroyPreview) error {
	input, ok := app.options.In.(*os.File)
	if !ok || !term.IsTerminal(int(input.Fd())) {
		return failure("confirmation_required", 2)
	}
	output, ok := app.options.Err.(*os.File)
	if !ok || !term.IsTerminal(int(output.Fd())) {
		return failure("confirmation_required", 2)
	}
	expires, err := time.Parse(time.RFC3339Nano, preview.ExpiresAt)
	if err != nil || !expires.After(time.Now()) {
		return failure("confirmation_required", 2)
	}
	ctx, cancel := context.WithDeadline(ctx, expires)
	defer cancel()
	// A line queued for a previous command is not fresh approval of the
	// inventory we are about to display. Refuse if pending input cannot flush.
	if unix.IoctlSetInt(int(input.Fd()), unix.TCFLSH, unix.TCIFLUSH) != nil {
		return failure("confirmation_required", 2)
	}
	if _, err := fmt.Fprintf(output, "Destroy world in namespace %s\nOriginal server: %s uid=%s\nGame: %s data=%s\n", preview.Target.Namespace, preview.Target.OriginalServer.Name, preview.Target.OriginalServer.UID, preview.Target.Game, preview.Target.DataIdentity); err != nil {
		return failure("local_io", 1)
	}
	for _, claim := range preview.Target.Claims {
		if _, err := fmt.Fprintf(output, "Claim %s: %s uid=%s\n", claim.Path, claim.ClaimRef.Name, claim.ClaimRef.UID); err != nil {
			return failure("local_io", 1)
		}
	}
	if _, err := fmt.Fprintf(output, "Backup: %s uid=%s\nExpires: %s\n%s\nType exactly %s: ", preview.BackupRef.Name, preview.BackupRef.UID, preview.ExpiresAt, preview.RestoreGuidance, preview.Challenge); err != nil {
		return failure("local_io", 1)
	}
	line := make([]byte, 0, 129)
	for {
		if err := ctx.Err(); err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				return failure("timeout", 5)
			}
			return failure("interrupted", 130)
		}
		descriptor := []unix.PollFd{{Fd: int32(input.Fd()), Events: unix.POLLIN}}
		count, err := unix.Poll(descriptor, 100)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return failure("confirmation_required", 2)
		}
		if count == 0 {
			continue
		}
		var chunk [130]byte
		n, err := unix.Read(int(input.Fd()), chunk[:])
		if err == unix.EINTR {
			continue
		}
		if err != nil || n == 0 {
			return failure("confirmation_required", 2)
		}
		line = append(line, chunk[:n]...)
		if len(line) > 129 {
			return failure("confirmation_required", 2)
		}
		if end := bytes.IndexByte(line, '\n'); end >= 0 {
			if ctx.Err() != nil {
				if errors.Is(ctx.Err(), context.Canceled) {
					return failure("interrupted", 130)
				}
				return failure("timeout", 5)
			}
			if end != len(line)-1 || !bytes.Equal(line[:end], []byte(preview.Challenge)) {
				return failure("confirmation_required", 2)
			}
			return nil
		}
		// Never spin on a terminal that reports an unrelated event.
		if descriptor[0].Revents&unix.POLLIN == 0 {
			return failure("confirmation_required", 2)
		}
		if deadline, ok := ctx.Deadline(); ok && time.Now().After(deadline) {
			return failure("timeout", 5)
		}
	}
}
