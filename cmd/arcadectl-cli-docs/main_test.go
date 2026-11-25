// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const runCLIDocs = "run-cli-docs-test-child"

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == runCLIDocs {
		os.Args = os.Args[1:]
		main()
		return
	}
	os.Exit(m.Run())
}

func TestCheckCLIReference(t *testing.T) {
	committed := os.DirFS("../../docs/generated/cli")
	current, err := os.ReadFile("../../docs/generated/cli/commands.md")
	if err != nil {
		t.Fatal(err)
	}
	stale := append(bytes.Clone(current), []byte("\n## Obsolete example\n")...)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name     string
		wantFile []byte
		wantExit int
	}{
		{name: "current", wantFile: current},
		{name: "stale", wantFile: stale, wantExit: 1},
		{name: "missing", wantExit: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			output := t.TempDir()
			if err := os.CopyFS(output, committed); err != nil {
				t.Fatal(err)
			}
			reference := filepath.Join(output, "commands.md")
			switch test.name {
			case "stale":
				if err := os.WriteFile(reference, test.wantFile, 0o644); err != nil {
					t.Fatal(err)
				}
			case "missing":
				if err := os.Remove(reference); err != nil {
					t.Fatal(err)
				}
			}

			cmd := exec.CommandContext(t.Context(), executable, runCLIDocs, "--check", "--output", output)
			diagnostic, err := cmd.CombinedOutput()
			if test.wantExit == 0 {
				if err != nil || len(diagnostic) != 0 {
					t.Fatalf("check of current reference: %v, output %q", err, diagnostic)
				}
			} else {
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ExitCode() != test.wantExit ||
					!strings.Contains(string(diagnostic), "make generate-cli") {
					t.Fatalf("want stale-artifact exit %d and regeneration guidance, got %v, output %q",
						test.wantExit, err, diagnostic)
				}
			}

			after, err := os.ReadFile(reference)
			if test.wantFile == nil {
				if !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("check must leave the missing reference absent, read error %v", err)
				}
			} else if err != nil || !bytes.Equal(after, test.wantFile) {
				t.Fatalf("check changed the reference or made it unreadable: %v", err)
			}
		})
	}
}
