// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	yaml "go.yaml.in/yaml/v3"
)

// Read real workflow documents: this gate deliberately has no runner or cluster
// client. The native proofs themselves remain mandatory on the heavy forge.
func TestForgeCIPolicy(t *testing.T) {
	for _, file := range []string{"../../.gitea/workflows/ci.yml", "../../.gitea/workflows/installer-performance.yml"} {
		t.Run(file, func(t *testing.T) {
			body, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			var workflow struct {
				On       map[string]yaml.Node `yaml:"on"`
				Defaults struct {
					Run struct {
						Shell string `yaml:"shell"`
					} `yaml:"run"`
				} `yaml:"defaults"`
				Env         map[string]string `yaml:"env"`
				Concurrency struct {
					Group  string `yaml:"group"`
					Cancel bool   `yaml:"cancel-in-progress"`
				} `yaml:"concurrency"`
				Jobs map[string]struct {
					Runner  string `yaml:"runs-on"`
					Timeout int    `yaml:"timeout-minutes"`
				} `yaml:"jobs"`
			}
			if err := yaml.Unmarshal(body, &workflow); err != nil {
				t.Fatal(err)
			}
			if workflow.Env["HEAVY_WAIT"] != "30" || workflow.Defaults.Run.Shell != `/config/.local/bin/heavy-run bash --noprofile --norc -e -o pipefail -c 'umask 022; exec bash --noprofile --norc -e -o pipefail "$1"' -- {0}` {
				t.Fatal("heavy shell steps bypass resource admission")
			}
			if len(workflow.On) != 3 {
				t.Fatal("heavy workflows require only named push, nightly, and manual triggers")
			}
			for name := range workflow.On {
				if !slices.Contains([]string{"push", "schedule", "workflow_dispatch"}, name) {
					t.Fatal("unsupported heavy trigger", name)
				}
			}
			var push struct {
				Branches []string `yaml:"branches"`
			}
			node := workflow.On["push"]
			if err := node.Decode(&push); err != nil {
				t.Fatal(err)
			}
			if len(push.Branches) == 0 {
				t.Fatal("heavy pushes must name branches")
			}
			for _, branch := range push.Branches {
				if strings.ContainsAny(branch, "*?![") || branch == "" {
					t.Fatal("heavy push branch is not literal")
				}
			}
			if !workflow.Concurrency.Cancel || !strings.Contains(workflow.Concurrency.Group, "github.sha") || !strings.Contains(workflow.Concurrency.Group, "github.run_id") {
				t.Fatal("heavy main/manual runs can replace each other")
			}
			if len(workflow.Jobs) == 0 {
				t.Fatal("missing heavy proofs")
			}
			for name, job := range workflow.Jobs {
				if !slices.Contains([]string{"ci-kind", "ci-build", "ci-light"}, job.Runner) || job.Timeout <= 0 || job.Timeout >= 180 {
					t.Fatal("invalid runner or task budget", name)
				}
			}
		})
	}
}

func TestGitHubOnlyLightPR(t *testing.T) {
	files, err := filepath.Glob("../../.github/workflows/*")
	if err != nil || len(files) != 1 || filepath.Base(files[0]) != "ci.yml" {
		t.Fatal("GitHub must have exactly one PR workflow", files, err)
	}
	body, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	var workflow struct {
		On          map[string]yaml.Node `yaml:"on"`
		Concurrency struct {
			Group  string `yaml:"group"`
			Cancel bool   `yaml:"cancel-in-progress"`
		} `yaml:"concurrency"`
		Jobs map[string]struct {
			Timeout  int `yaml:"timeout-minutes"`
			Strategy any `yaml:"strategy"`
			Steps    []struct {
				Run  string         `yaml:"run"`
				Uses string         `yaml:"uses"`
				With map[string]any `yaml:"with"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(body, &workflow); err != nil {
		t.Fatal(err)
	}
	if _, ok := workflow.On["pull_request"]; !ok || len(workflow.On) != 1 {
		t.Fatal("GitHub must run only for pull requests")
	}
	if !workflow.Concurrency.Cancel || !strings.Contains(workflow.Concurrency.Group, "github.event.pull_request.number") {
		t.Fatal("superseded PR runs are not cancelled")
	}
	if len(workflow.Jobs) != 1 {
		t.Fatal("GitHub must have one single-configuration light check")
	}
	job, ok := workflow.Jobs["light"]
	if !ok || job.Timeout <= 0 || job.Timeout > 10 || job.Strategy != nil {
		t.Fatal("light check has an invalid budget or matrix")
	}
	var runs []string
	checkouts := 0
	for _, step := range job.Steps {
		if strings.HasPrefix(step.Uses, "actions/checkout@") {
			checkouts++
			if step.With["ref"] != "${{ github.event.pull_request.head.sha }}" {
				t.Fatal("light check is not exact-head evidence")
			}
		}
		if step.Run != "" {
			runs = append(runs, step.Run)
		}
	}
	if checkouts != 1 || !slices.Equal(runs, []string{
		"go build -p 2 ./...",
		"go test -p 2 -timeout=5m -count=1 ./internal/adminauth ./internal/admincredential ./internal/receiptid ./internal/catalog",
		"go vet -p 2 ./internal/adminauth ./internal/admincredential ./internal/receiptid ./internal/catalog",
	}) {
		t.Fatal("light build, fast unit tests, or lint changed")
	}
}

func TestGiteaBinaryLegs(t *testing.T) {
	body, err := os.ReadFile("../../.gitea/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	var workflow struct {
		Jobs map[string]struct {
			Needs    []string `yaml:"needs"`
			If       string   `yaml:"if"`
			Tolerate any      `yaml:"continue-on-error"`
			Timeout  int      `yaml:"timeout-minutes"`
			Strategy any      `yaml:"strategy"`
			Steps    []struct {
				Name string            `yaml:"name"`
				If   string            `yaml:"if"`
				Run  string            `yaml:"run"`
				Env  map[string]string `yaml:"env"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(body, &workflow); err != nil {
		t.Fatal(err)
	}
	legs := []struct {
		Name, Command, Variable string
		Historical              bool
	}{
		{"kind-install-binary-135-fresh", "make test-kind-install-binary INSTALL_BINARY_PROFILE=135 INSTALL_BINARY_MODE=fresh", "INSTALL_BINARY_135_FRESH_RESULT", false},
		{"kind-install-binary-137-fresh", "make test-kind-install-binary INSTALL_BINARY_PROFILE=137 INSTALL_BINARY_MODE=fresh", "INSTALL_BINARY_137_FRESH_RESULT", false},
		{"kind-install-binary-137-transition", "make test-kind-install-binary INSTALL_BINARY_PROFILE=137 INSTALL_BINARY_MODE=transition", "INSTALL_BINARY_RESULT", true},
	}
	gate := workflow.Jobs["go-and-policy"]
	for _, leg := range legs {
		job, ok := workflow.Jobs[leg.Name]
		if !ok || job.Timeout != 170 || job.Strategy != nil || !binaryDiagnosticsPrerequisite(job.Needs, job.If, job.Tolerate) {
			t.Fatal("binary leg missing or not independently bounded", leg.Name)
		}
		runs, historical := 0, 0
		for _, step := range job.Steps {
			if step.Run == leg.Command && step.If == "" {
				runs++
			}
			if step.Name == "Acquire exact historical installer source" {
				historical++
			}
		}
		if runs != 1 || (historical == 1) != leg.Historical || historical > 1 {
			t.Fatal("binary leg command or historical scope changed", leg.Name)
		}
		if !slices.Contains(gate.Needs, leg.Name) {
			t.Fatal("binary leg absent from aggregate", leg.Name)
		}
		bindings := 0
		for _, step := range gate.Steps {
			if step.Env[leg.Variable] == "${{ needs."+leg.Name+".result }}" && strings.Contains(step.Run, "test \"$"+leg.Variable+"\" = success") {
				bindings++
			}
		}
		if bindings != 1 {
			t.Fatal("aggregate does not enforce actual binary leg outcome", leg.Name)
		}
	}
	for name := range workflow.Jobs {
		if strings.HasPrefix(name, "kind-install-binary") && !slices.Contains(gate.Needs, name) {
			t.Fatal("untracked binary leg", name)
		}
	}
}
