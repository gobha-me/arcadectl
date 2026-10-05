// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"path/filepath"

	adminv1 "github.com/gobha-me/arcadectl/api/admin/v1"
	"github.com/gobha-me/arcadectl/internal/canonicaljson"
	"github.com/gobha-me/arcadectl/internal/cliintent"
	"github.com/gobha-me/arcadectl/internal/clilifecycle"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	"github.com/spf13/cobra"
)

func (app *application) serverCommand() *cobra.Command {
	root := &cobra.Command{Use: "server", Short: "Create, configure, inspect, and operate servers; ordinary removal retains worlds"}
	root.AddCommand(&cobra.Command{Use: "status [NAME]", Short: "Inspect a server or list servers", Args: maximumArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(cmd.Context(), app.timeout)
		defer cancel()
		client, _, err := app.client(ctx)
		if err != nil {
			return err
		}
		defer client.Close()
		if len(args) == 0 {
			var value adminv1.ServerList
			if _, err := client.Read(ctx, "/v1/servers", &value); err != nil {
				return err
			}
			return app.emit(value)
		}
		if !objectID.MatchString(args[0]) {
			return failure("invalid_arguments", 2)
		}
		var value adminv1.Server
		if _, err := client.Read(ctx, "/v1/servers/"+args[0], &value); err != nil {
			return err
		}
		return app.emit(value)
	}})
	for _, action := range []string{"create", "configure", "start", "stop", "restart", "update", "backup", "restore", "decommission", "destroy"} {
		root.AddCommand(app.lifecycleCommand(action, false))
	}
	return root
}

func (app *application) lifecycleCommand(action string, retained bool) *cobra.Command {
	input := clilifecycle.Input{Action: "server." + action}
	if action == "backup" || action == "restore" {
		input.Action = "world." + action
	}
	if action == "destroy" {
		input.Action = "world.destroy.preview"
	}
	compute := adminv1.Compute{}
	storage := adminv1.Storage{}
	settingsFile, class := "", ""
	use := action + " NAME"
	if retained {
		use = action + " DECOMMISSION_OPERATION_ID"
	}
	short := map[string]string{"create": "Create a server stopped by default", "configure": "Replace supplied settings or resource groups", "start": "Start without resetting a world", "stop": "Stop and retain a world", "restart": "Restart without overlapping workloads", "update": "Update an immutable image", "backup": "Make a verified cold backup; leave stopped by default", "restore": "Restore to new claims; leave stopped by default", "decommission": "Remove the server object while retaining its exact world identities", "destroy": "Prepare a backup-gated destroy preview; this command never confirms deletion"}[action]
	command := &cobra.Command{Use: use, Short: short, Args: exactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if retained {
			input.RetainedOperationID = args[0]
		} else {
			input.Name = args[0]
		}
		if input.RetainedOperationID != "" && !receiptID.MatchString(input.RetainedOperationID) {
			return failure("invalid_arguments", 2)
		}
		if action == "create" || action == "configure" {
			changed := false
			for _, name := range []string{"cpu-request", "cpu-limit", "memory-request", "memory-limit"} {
				changed = changed || cmd.Flags().Changed(name)
			}
			if changed || action == "create" {
				input.Compute = &compute
			}
			if cmd.Flags().Changed("storage-size") || cmd.Flags().Changed("storage-class") || action == "create" {
				input.Storage = &storage
				if cmd.Flags().Changed("storage-class") {
					input.Storage.StorageClassName = &class
				}
			}
			if settingsFile != "" {
				path, err := filepath.Abs(settingsFile)
				if err != nil {
					return failure("invalid_arguments", 2)
				}
				contents, _, err := privatefs.ReadAbsolute(path, int64(canonicaljson.MaxBytes), privatefs.TrustedPublic)
				if err != nil {
					return failure("local_io", 1)
				}
				input.Settings = contents
			}
		}
		fingerprint, err := clilifecycle.Fingerprint(input)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(cmd.Context(), app.timeout)
		defer cancel()
		client, saved, err := app.client(ctx)
		if err != nil {
			return err
		}
		defer client.Close()
		target := input.Name
		if retained {
			target = input.RetainedOperationID
		}
		return app.submit(ctx, client, saved, input.Action+"/"+target, fingerprint, func() (cliintent.Intent, error) { return clilifecycle.Prepare(ctx, client, input) })
	}}
	if action == "create" || action == "update" {
		command.Flags().StringVar(&input.Image.Digest, "image-digest", "", "Immutable adapter image digest")
		command.Flags().StringVar(&input.Image.Version, "image-version", "", "Curated adapter image version; mutually exclusive with digest")
	}
	if action == "create" {
		command.Flags().StringVar(&input.Game, "game", "", "Certified game adapter")
		command.Flags().StringVar(&input.DesiredState, "desired-state", "Stopped", "Initial state: Stopped or explicitly Running")
		command.Flags().StringVar(&input.RetainedOperationID, "retained-world", "", "Exact successful decommission receipt for deliberate reattachment")
	}
	if action == "create" || action == "configure" {
		command.Flags().StringVar(&compute.CPURequest, "cpu-request", "", "CPU request; all four compute fields form one replacement group")
		command.Flags().StringVar(&compute.CPULimit, "cpu-limit", "", "CPU limit")
		command.Flags().StringVar(&compute.MemoryRequest, "memory-request", "", "Memory request")
		command.Flags().StringVar(&compute.MemoryLimit, "memory-limit", "", "Memory limit")
		command.Flags().StringVar(&storage.Size, "storage-size", "", "World storage capacity request")
		command.Flags().StringVar(&class, "storage-class", "", "Storage class; explicitly empty selects no class")
		command.Flags().StringVar(&settingsFile, "settings-file", "", "Bounded JSON settings file; supplied object replaces settings")
	}
	if action == "backup" {
		command.Flags().StringVar(&input.RepositorySecretName, "repository-secret", "", "Existing repository credential Secret name only")
	}
	if action == "restore" || action == "destroy" {
		command.Flags().StringVar(&input.BackupName, "backup", "", "Exact successful native backup name (not its operation receipt)")
	}
	if action == "backup" || action == "restore" {
		command.Flags().StringVar(&input.RestartPolicy, "restart-policy", "LeaveStopped", "LeaveStopped or explicit RestorePreviousState")
	}
	command.ValidArgsFunction = func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	return command
}

func (app *application) retainedCommand() *cobra.Command {
	root := &cobra.Command{Use: "retained-world", Short: "Inspect or deliberately destroy worlds after server-object removal"}
	root.AddCommand(app.lifecycleCommand("destroy", true))
	root.AddCommand(&cobra.Command{Use: "status DECOMMISSION_OPERATION_ID", Short: "Read durable original server and claim identity evidence", Args: exactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if !receiptID.MatchString(args[0]) {
			return failure("invalid_arguments", 2)
		}
		ctx, cancel := context.WithTimeout(cmd.Context(), app.timeout)
		defer cancel()
		client, _, err := app.client(ctx)
		if err != nil {
			return err
		}
		defer client.Close()
		var value adminv1.RetainedWorld
		if _, err := client.Read(ctx, "/v1/retained-worlds/"+args[0], &value); err != nil {
			return err
		}
		return app.emit(value)
	}})
	return root
}
