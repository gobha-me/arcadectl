// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package lintpolicy

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Execute the real linter against a tiny git history. The new finding is on a
// byte-identical source line in an already baselined file, as in issue #114.
func TestIdenticalNewErrcheckLineCannotHideInBaseline(t *testing.T) {
	linter, err := exec.LookPath("golangci-lint")
	if err != nil {
		if os.Getenv("ARCADECTL_REQUIRE_LINT_TOOL") == "1" {
			t.Fatal("required pinned golangci-lint is unavailable")
		}
		t.Skip("golangci-lint integration tool unavailable")
	}
	root := filepath.Join("..", "..")
	fixture := t.TempDir()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	run := func(wantFailure bool, executable string, args ...string) string {
		t.Helper()
		command := exec.CommandContext(ctx, executable, args...)
		command.Dir = fixture
		output, runErr := command.CombinedOutput()
		if (runErr != nil) != wantFailure {
			t.Fatalf("fixture command %s had unexpected result: %v\n%s", filepath.Base(executable), runErr, output)
		}
		if wantFailure {
			if exit, ok := runErr.(*exec.ExitError); !ok || exit.ExitCode() != 1 {
				t.Fatalf("expected findings exit 1, got %v\n%s", runErr, output)
			}
		}
		return string(output)
	}
	write := func(name, body string) {
		t.Helper()
		path := filepath.Join(fixture, name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{".golangci.yml", ".golangci-new.yml", "hack/lint-new-findings.sh"} {
		body, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		write(name, string(body))
	}
	write("go.mod", "module example.invalid/lintprobe\n\ngo 1.26.0\n")
	const path = "cmd/arcadectl-api/main_test.go"
	const imports = "package main\nimport (\"net/http\"; \"testing\")\n"
	const function = `func TestNAME(t *testing.T) {
 response, err := http.Get("http://fixture.invalid")
 if err != nil { t.Fatal(err) }
 defer response.Body.Close()
}
`
	existing := imports + strings.ReplaceAll(function, "NAME", "Existing")
	write(path, existing)
	run(false, "git", "init", "--quiet", "--initial-branch=main")
	run(false, "git", "config", "user.name", "Projects Lead (agent)")
	run(false, "git", "config", "user.email", "agents@noreply.invalid")
	run(false, "git", "add", ".")
	run(false, "git", "commit", "--quiet", "-m", "lint fixture baseline", "-m", "Agent: Codex (via Projects Lead)\nAgent-Role: tests (Codex, needs non-author re-make)")
	base := strings.TrimSpace(run(false, "git", "rev-parse", "HEAD"))
	run(false, "env", "LINT_BASE_SHA="+base, "bash", "hack/lint-new-findings.sh")
	write(path, existing+strings.ReplaceAll(function, "NAME", "Added"))
	// This confirms the original masking defect, rather than just testing a
	// new source string that the existing anchored exclusions already reject.
	run(false, linter, "run", "--config=.golangci.yml", "./...")
	output := run(true, "env", "LINT_BASE_SHA="+base, "bash", "hack/lint-new-findings.sh")
	if !strings.Contains(output, "cmd/arcadectl-api/main_test.go") || !strings.Contains(output, "errcheck") {
		t.Fatal("new identical-line finding was not reported as errcheck in the baselined file")
	}
}
