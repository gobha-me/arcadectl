// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

// Package cli implements the ordinary administrator client, not a Kubernetes control plane.
package cli

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/gobha-me/arcadectl/internal/adminclient"
	"github.com/spf13/cobra"
)

type Options struct {
	In                  io.Reader
	Out, Err            io.Writer
	ConfigDir, StateDir string
	PollInterval        time.Duration
}

type application struct {
	options             Options
	contextName, output string
	timeout             time.Duration
	noWait              bool
}

// NewCommand is also the offline source for generated help and completions.
// Constructing it never reads credentials, creates state, or makes requests.
func NewCommand(options Options) *cobra.Command {
	if options.In == nil {
		options.In = os.Stdin
	}
	if options.Out == nil {
		options.Out = os.Stdout
	}
	if options.Err == nil {
		options.Err = os.Stderr
	}
	app := &application{options: options}
	root := &cobra.Command{Use: "arcadectl", Short: "Safely operate game servers through the authenticated Arcadectl API", SilenceUsage: true, SilenceErrors: true, Annotations: map[string]string{}}
	root.SetIn(options.In)
	root.SetOut(options.Out)
	root.SetErr(options.Err)
	root.SetFlagErrorFunc(func(*cobra.Command, error) error { return failure("invalid_arguments", 2) })
	root.PersistentFlags().StringVar(&app.contextName, "context", "", "Use a saved administrator context")
	root.PersistentFlags().StringVar(&app.output, "output", "human", "Output format: human or json")
	root.PersistentFlags().DurationVar(&app.timeout, "timeout", 30*time.Minute, "Bounded request, lock, confirmation, and observation timeout; does not cancel admitted work")
	root.PersistentFlags().BoolVar(&app.noWait, "no-wait", false, "Return after receipt admission without waiting for completion")
	root.PersistentPreRunE = func(*cobra.Command, []string) error {
		if app.output != "human" && app.output != "json" || app.timeout <= 0 || app.timeout > 24*time.Hour {
			return failure("invalid_arguments", 2)
		}
		root.Annotations["validated"] = "true"
		return nil
	}
	root.AddCommand(app.loginCommand(), app.contextCommand(), app.serverCommand(), app.retainedCommand(), app.destroyCommand(), app.operationCommand())
	return root
}

// Run returns stable exit codes and never renders raw input-bearing errors.
func Run(ctx context.Context, args []string, options Options) int {
	root := NewCommand(options)
	root.SetArgs(args)
	err := root.ExecuteContext(ctx)
	if err == nil {
		return 0
	}
	code := classify(err)
	if root.Annotations["validated"] != "true" {
		code = failure("invalid_arguments", 2)
	}
	if errors.Is(ctx.Err(), context.Canceled) {
		code.code, code.exit = "interrupted", 130
	}
	out := options.Err
	if out == nil {
		out = os.Stderr
	}
	jsonOutput := false
	if flag := root.PersistentFlags().Lookup("output"); flag != nil {
		jsonOutput = flag.Value.String() == "json"
	}
	if writeFailure(out, jsonOutput, code) != nil {
		return 1
	}
	return code.exit
}

func (app *application) paths() (string, string, error) {
	config, state := app.options.ConfigDir, app.options.StateDir
	if config == "" {
		base := os.Getenv("XDG_CONFIG_HOME")
		if base == "" {
			var err error
			base, err = os.UserConfigDir()
			if err != nil {
				return "", "", failure("local_io", 1)
			}
		}
		config = filepath.Join(base, "arcadectl")
	}
	if state == "" {
		base := os.Getenv("XDG_STATE_HOME")
		if base == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return "", "", failure("local_io", 1)
			}
			base = filepath.Join(home, ".local", "state")
		}
		state = filepath.Join(base, "arcadectl")
	}
	if !filepath.IsAbs(config) || !filepath.IsAbs(state) {
		return "", "", failure("local_io", 1)
	}
	return filepath.Clean(config), filepath.Clean(state), nil
}

func (app *application) contextStore(create bool) (*adminclient.ContextStore, error) {
	config, _, err := app.paths()
	if err != nil {
		return nil, err
	}
	return adminclient.OpenContextStore(config, create)
}

func (app *application) client(ctx context.Context) (*adminclient.Client, adminclient.SavedContext, error) {
	store, err := app.contextStore(false)
	if err != nil {
		return nil, adminclient.SavedContext{}, err
	}
	defer store.Close()
	saved, err := store.Load(app.contextName)
	if err != nil {
		return nil, saved, err
	}
	client, err := adminclient.LoadSaved(saved)
	if err != nil {
		return nil, saved, err
	}
	identity, err := client.Verify(ctx)
	if err != nil {
		client.Close()
		return nil, saved, err
	}
	if identity != saved.Identity {
		client.Close()
		return nil, saved, failure("context_changed", 4)
	}
	return client, saved, nil
}
