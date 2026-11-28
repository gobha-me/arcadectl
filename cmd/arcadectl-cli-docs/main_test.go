// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"errors"
	"io/fs"
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
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name     string
		file     string
		stale    bool
		missing  bool
		wantExit int
	}{
		{name: "current", file: "commands.md"},
		{name: "stale", file: "commands.md", stale: true, wantExit: 1},
		{name: "missing", file: "commands.md", missing: true, wantExit: 1},
		{name: "stale-bash", file: "arcadectl.bash", stale: true, wantExit: 1},
		{name: "stale-fish", file: "arcadectl.fish", stale: true, wantExit: 1},
		{name: "stale-powershell", file: "arcadectl.ps1", stale: true, wantExit: 1},
		{name: "stale-zsh", file: "_arcadectl", stale: true, wantExit: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			output := t.TempDir()
			if err := os.CopyFS(output, committed); err != nil {
				t.Fatal(err)
			}
			reference := filepath.Join(output, test.file)
			wantFile, err := fs.ReadFile(committed, test.file)
			if err != nil {
				t.Fatal(err)
			}
			switch {
			case test.stale:
				wantFile = append(wantFile, []byte("\n# Obsolete generated artifact\n")...)
				if err := os.WriteFile(reference, wantFile, 0o644); err != nil {
					t.Fatal(err)
				}
			case test.missing:
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
			if test.missing {
				if !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("check must leave the missing reference absent, read error %v", err)
				}
			} else if err != nil || !bytes.Equal(after, wantFile) {
				t.Fatalf("check changed the reference or made it unreadable: %v", err)
			}
		})
	}
}

func TestGenerateCLIReferenceFiles(t *testing.T) {
	committed := os.DirFS("../../docs/generated/cli")
	wantFiles, err := fs.ReadDir(committed, ".")
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "new", "cli")
	cmd := exec.CommandContext(t.Context(), executable, runCLIDocs, "--output", output)
	if diagnostic, err := cmd.CombinedOutput(); err != nil || len(diagnostic) != 0 {
		t.Fatalf("generate CLI artifacts: %v, output %q", err, diagnostic)
	}

	gotFiles, err := os.ReadDir(output)
	if err != nil {
		t.Fatal(err)
	}
	if len(gotFiles) != len(wantFiles) {
		t.Fatalf("generated %d files, want %d", len(gotFiles), len(wantFiles))
	}
	for _, file := range wantFiles {
		name := file.Name()
		actual, actualErr := os.ReadFile(filepath.Join(output, name))
		want, wantErr := fs.ReadFile(committed, name)
		if actualErr != nil || wantErr != nil || !bytes.Equal(actual, want) {
			t.Errorf("%s differs from the committed artifact, generated read error %v, committed read error %v",
				name, actualErr, wantErr)
		}
	}
}
