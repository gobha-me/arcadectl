// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"github.com/gobha-me/arcadectl/internal/adminclient"
	"github.com/spf13/cobra"
)

func exactArgs(count int) cobra.PositionalArgs {
	return func(_ *cobra.Command, args []string) error {
		if len(args) != count {
			return failure("invalid_arguments", 2)
		}
		return nil
	}
}
func maximumArgs(count int) cobra.PositionalArgs {
	return func(_ *cobra.Command, args []string) error {
		if len(args) > count {
			return failure("invalid_arguments", 2)
		}
		return nil
	}
}

func (app *application) loginCommand() *cobra.Command {
	config := adminclient.ContextConfig{Version: "v1"}
	command := &cobra.Command{Use: "login CONTEXT", Short: "Verify HTTPS identity and save paths to an owner-only credential and CA file", Args: exactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		config.Name = args[0]
		if config.APIOrigin == "" || config.CAFile == "" || config.CredentialFile == "" {
			return failure("invalid_arguments", 2)
		}
		store, err := app.contextStore(true)
		if err != nil {
			return err
		}
		defer store.Close()
		ctx, cancel := context.WithTimeout(cmd.Context(), app.timeout)
		defer cancel()
		identity, err := store.Login(ctx, config)
		if err != nil {
			return err
		}
		return app.emit(identity)
	}}
	command.Flags().StringVar(&config.APIOrigin, "api", "", "Trusted HTTPS API origin (no path, query, or user information)")
	command.Flags().StringVar(&config.CAFile, "ca-file", "", "Absolute trusted CA bundle path")
	command.Flags().StringVar(&config.CredentialFile, "credential-file", "", "Absolute owner-only 0600 administrator credential path")
	command.Flags().StringVar(&config.TLSServerName, "tls-server-name", "", "Explicit verified TLS server name, if different from origin host")
	return command
}

func (app *application) contextCommand() *cobra.Command {
	command := &cobra.Command{Use: "context", Short: "Manage saved endpoint metadata without storing bearer tokens"}
	command.AddCommand(&cobra.Command{Use: "list", Short: "List saved contexts", Args: exactArgs(0), RunE: func(cmd *cobra.Command, _ []string) error {
		store, err := app.contextStore(false)
		if err != nil {
			return err
		}
		defer store.Close()
		items, _, err := store.List()
		if err != nil {
			return err
		}
		return app.emit(items)
	}})
	command.AddCommand(&cobra.Command{Use: "current", Short: "Show the selected context", Args: exactArgs(0), RunE: func(cmd *cobra.Command, _ []string) error {
		store, err := app.contextStore(false)
		if err != nil {
			return err
		}
		defer store.Close()
		saved, err := store.Load("")
		if err != nil {
			return err
		}
		return app.emit(saved)
	}})
	for _, action := range []string{"use", "remove"} {
		action := action
		command.AddCommand(&cobra.Command{Use: action + " CONTEXT", Short: map[string]string{"use": "Select a saved context", "remove": "Remove metadata only; retain credential and CA files"}[action], Args: exactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
			store, err := app.contextStore(false)
			if err != nil {
				return err
			}
			defer store.Close()
			if action == "use" {
				err = store.Use(args[0])
			} else {
				err = store.Remove(args[0])
			}
			if err != nil {
				return err
			}
			return app.emit(struct {
				Version string `json:"version"`
				Action  string `json:"action"`
			}{"v1", action})
		}})
	}
	return command
}
