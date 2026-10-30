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

const lintEventProbePath = "cmd/arcadectl-api/main_test.go"
const lintEventProbe = `package main
import ("net/http"; "testing")
func TestExisting(t *testing.T) {
 response, err := http.Get("http://fixture.invalid")
 if err != nil { t.Fatal(err) }
 defer response.Body.Close()
}
`

type lintEventFixture struct {
	dir, base, config string
	ctx               context.Context
}

func newLintEventFixture(t *testing.T) *lintEventFixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	t.Cleanup(cancel)
	f := &lintEventFixture{dir: t.TempDir(), ctx: ctx}
	for _, name := range []string{".golangci.yml", ".golangci-new.yml", "hack/lint-new-findings.sh"} {
		body, err := os.ReadFile(filepath.Join("..", "..", name))
		if err != nil {
			t.Fatal(err)
		}
		f.write(t, name, string(body))
	}
	f.write(t, "go.mod", "module example.invalid/lint-event-probe\n\ngo 1.26.0\n")
	f.write(t, lintEventProbePath, lintEventProbe)
	f.run(t, 0, nil, "git", "init", "--quiet", "--initial-branch=main")
	f.run(t, 0, nil, "git", "config", "user.name", "Projects Lead (agent)")
	f.run(t, 0, nil, "git", "config", "user.email", "agents@noreply.invalid")
	f.run(t, 0, nil, "git", "add", ".")
	f.run(t, 0, nil, "git", "commit", "--quiet", "-m", "event lint baseline fixture")
	f.base = strings.TrimSpace(f.run(t, 0, nil, "git", "rev-parse", "HEAD"))
	body, err := os.ReadFile(filepath.Join(f.dir, ".golangci-new.yml"))
	if err != nil {
		t.Fatal(err)
	}
	// The config is fixture data; the script and linter remain the real units.
	lines := strings.Split(string(body), "\n")
	found := false
	for i, line := range lines {
		if strings.HasPrefix(line, "# source-baseline:") {
			lines[i] = "# source-baseline: " + f.base
			found = true
		}
	}
	if !found {
		t.Fatal("source config omitted its explicit baseline declaration")
	}
	f.config = strings.Join(lines, "\n")
	f.write(t, ".golangci-new.yml", f.config)
	return f
}

func (f *lintEventFixture) write(t *testing.T, name, body string) {
	t.Helper()
	path := filepath.Join(f.dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
}

func (f *lintEventFixture) run(t *testing.T, wantExit int, env []string, executable string, args ...string) string {
	t.Helper()
	command := exec.CommandContext(f.ctx, executable, args...)
	command.Dir = f.dir
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "LINT_BASE_SHA=") && !strings.HasPrefix(entry, "GITHUB_EVENT_NAME=") {
			command.Env = append(command.Env, entry)
		}
	}
	command.Env = append(command.Env, env...)
	output, err := command.CombinedOutput()
	gotExit := 0
	if err != nil {
		exit, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("fixture command failed to execute: %v", err)
		}
		gotExit = exit.ExitCode()
	}
	if gotExit != wantExit {
		t.Fatalf("%s %v exited %d, want %d: %s", executable, args, gotExit, wantExit, output)
	}
	return string(output)
}

func requireLintEventTool(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("golangci-lint"); err != nil {
		if os.Getenv("ARCADECTL_REQUIRE_LINT_TOOL") == "1" {
			t.Fatal("required pinned golangci-lint is unavailable")
		}
		t.Skip("golangci-lint integration tool unavailable")
	}
}

func TestLintEventBaseRequiresDeclaredRange(t *testing.T) {
	f := newLintEventFixture(t)
	for _, event := range []string{"", "pull_request", "push", "merge_group", "unknown"} {
		t.Run(event, func(t *testing.T) {
			f.run(t, 2, []string{"GITHUB_EVENT_NAME=" + event}, "bash", "hack/lint-new-findings.sh")
		})
	}
	for _, base := range []string{" ", strings.Repeat("0", 40), f.base + "; touch injected"} {
		f.run(t, 2, []string{"GITHUB_EVENT_NAME=workflow_dispatch", "LINT_BASE_SHA=" + base}, "bash", "hack/lint-new-findings.sh")
	}
	if _, err := os.Stat(filepath.Join(f.dir, "injected")); !os.IsNotExist(err) {
		t.Fatal("base input was executed as shell source")
	}
}

func TestScheduledLintRefusesInvalidAnchors(t *testing.T) {
	f := newLintEventFixture(t)
	anchor := "# source-baseline: " + f.base
	tree := strings.TrimSpace(f.run(t, 0, nil, "git", "rev-parse", "HEAD^{tree}"))
	unrelated := strings.TrimSpace(f.run(t, 0, nil, "git", "commit-tree", tree, "-m", "unrelated lint source fixture"))
	cases := map[string]string{
		"missing":             strings.Replace(f.config, anchor, "", 1),
		"malformed":           strings.Replace(f.config, anchor, "# source-baseline: invalid", 1),
		"duplicate":           f.config + "\n" + anchor + "\n",
		"mixed-duplicate":     f.config + "\n# source-baseline: invalid\n",
		"unavailable":         strings.Replace(f.config, f.base, strings.Repeat("0", 40), 1),
		"tree-not-commit":     strings.Replace(f.config, f.base, tree, 1),
		"available-unrelated": strings.Replace(f.config, f.base, unrelated, 1),
	}
	for name, config := range cases {
		t.Run(name, func(t *testing.T) {
			f.write(t, ".golangci-new.yml", config)
			for _, event := range []string{"schedule", "workflow_dispatch"} {
				f.run(t, 2, []string{"GITHUB_EVENT_NAME=" + event}, "bash", "hack/lint-new-findings.sh")
			}
		})
	}
}

func TestScheduledLintFindsIdenticalNewBaselineLine(t *testing.T) {
	requireLintEventTool(t)
	for _, event := range []string{"schedule", "workflow_dispatch"} {
		t.Run(event, func(t *testing.T) {
			f := newLintEventFixture(t)
			env := []string{"GITHUB_EVENT_NAME=" + event}
			f.run(t, 0, env, "bash", "hack/lint-new-findings.sh")
			added := strings.Replace(lintEventProbe, "package main\nimport (\"net/http\"; \"testing\")\n", "", 1)
			f.write(t, lintEventProbePath, lintEventProbe+strings.Replace(added, "TestExisting", "TestAdded", 1))
			f.run(t, 0, env, "golangci-lint", "run", "--config=.golangci.yml", "./...")
			output := f.run(t, 1, env, "bash", "hack/lint-new-findings.sh")
			if !strings.Contains(output, lintEventProbePath) || !strings.Contains(output, "errcheck") {
				t.Fatal("scheduled/manual diff hid a byte-identical new baseline finding")
			}
		})
	}
}

func TestExplicitLintEventBaseRetainsPriority(t *testing.T) {
	requireLintEventTool(t)
	f := newLintEventFixture(t)
	f.write(t, ".golangci-new.yml", strings.Replace(f.config, f.base, "invalid", 1))
	f.run(t, 0, []string{"GITHUB_EVENT_NAME=workflow_dispatch", "LINT_BASE_SHA=" + f.base}, "bash", "hack/lint-new-findings.sh")
}
