// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"

	"github.com/gobha-me/arcadectl/internal/supportbundle"
	"github.com/spf13/cobra"
)

func (app *application) diagnoseCommand() *cobra.Command {
	return &cobra.Command{Use: "diagnose NAME", Short: "Collect partial redacted server status and build claims without mutation", Args: exactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if !objectID.MatchString(args[0]) {
			return failure("invalid_arguments", 2)
		}
		ctx, cancel := context.WithTimeout(cmd.Context(), app.timeout)
		defer cancel()
		client, saved, err := app.client(ctx)
		if err != nil {
			return err
		}
		defer client.Close()
		bundle, err := supportbundle.Collect(ctx, client, saved.Identity.Namespace, args[0])
		if err != nil {
			return err
		}
		return app.emit(bundle)
	}}
}
