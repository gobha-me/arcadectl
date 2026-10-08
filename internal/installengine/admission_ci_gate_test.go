// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"

	yaml "go.yaml.in/yaml/v3"
)

func TestInstallerAdmissionCIProfilesAndFailClosedRequiredGate(t *testing.T) {
	body, err := os.ReadFile("../../.github/workflows/ci.yml")
	if err != nil {
		t.Fatal("CI source unavailable")
	}
	var workflow struct {
		Jobs map[string]struct {
			If       string   `yaml:"if"`
			Needs    []string `yaml:"needs"`
			Strategy struct {
				Matrix struct {
					Shard   []int    `yaml:"shard"`
					Profile []int    `yaml:"profile"`
					Mode    []string `yaml:"mode"`
					Exclude []struct {
						Profile int    `yaml:"profile"`
						Mode    string `yaml:"mode"`
					} `yaml:"exclude"`
				} `yaml:"matrix"`
			} `yaml:"strategy"`
			Steps []struct {
				Name string            `yaml:"name"`
				Uses string            `yaml:"uses"`
				Run  string            `yaml:"run"`
				Env  map[string]string `yaml:"env"`
				With map[string]any    `yaml:"with"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if yaml.Unmarshal(body, &workflow) != nil {
		t.Fatal("CI workflow malformed")
	}
	// Identical PR-merge/head trees do not have identical source SHA/epoch.
	// Signed packages, image revision labels and lifecycle evidence must use
	// the requested head (or exact main push), not a synthetic merge identity.
	for _, name := range []string{"kind-install-binary", "kind-install-admission", "kind-install-auth", "kind-api", "kind-recovery", "install-engine-race", "go-and-policy", "kind-lifecycle"} {
		if _, present := workflow.Jobs[name]; !present {
			t.Errorf("required exact-source CI job %s is absent", name)
		}
	}
	for name, job := range workflow.Jobs {
		checkouts := 0
		for _, step := range job.Steps {
			if strings.HasPrefix(step.Uses, "actions/checkout@") {
				checkouts++
				if step.With["ref"] != "${{ github.event.pull_request.head.sha || github.sha }}" {
					t.Errorf("CI job %s does not pin the exact candidate/main source", name)
				}
			}
		}
		if checkouts != 1 {
			t.Errorf("CI job %s lacks one unambiguous exact-source checkout", name)
		}
	}
	if t.Failed() {
		t.FailNow()
	}
	admission := workflow.Jobs["kind-install-admission"]
	races := workflow.Jobs["install-engine-race"]
	if !slices.Equal(races.Strategy.Matrix.Shard, []int{0, 1, 2, 3, 4, 5, 6, 7}) || len(races.Strategy.Matrix.Exclude) != 0 {
		t.Fatal("compiled race test partitions omitted from CI")
	}
	raceRun := false
	for _, step := range races.Steps {
		raceRun = raceRun || step.Run == "bash ./hack/test-installengine-race-shard.sh '${{ matrix.shard }}'"
	}
	if !raceRun {
		t.Fatal("CI does not execute its assigned compiled race test trees")
	}
	if !slices.Equal(admission.Strategy.Matrix.Profile, []int{135, 137}) || !slices.Equal(admission.Strategy.Matrix.Mode, []string{"cold", "warm"}) {
		t.Fatal("full native admission profile/mode omitted")
	}
	fullRun := false
	for _, step := range admission.Steps {
		fullRun = fullRun || step.Run == "make test-kind-install-admission INSTALL_ADMISSION_PROFILE='${{ matrix.profile }}' INSTALL_ADMISSION_MODE='${{ matrix.mode }}'"
	}
	gate := workflow.Jobs["go-and-policy"]
	binary := workflow.Jobs["kind-install-binary"]
	binaryRun := false
	binaryHistory := false
	for _, step := range binary.Steps {
		binaryRun = binaryRun || step.Run == "make test-kind-install-binary INSTALL_BINARY_PROFILE='${{ matrix.profile }}' INSTALL_BINARY_MODE='${{ matrix.mode }}'"
		if strings.HasPrefix(step.Uses, "actions/checkout@") {
			depth, present := step.With["fetch-depth"]
			binaryHistory = present && depth == 0
		}
	}
	binaryMatrix := binary.Strategy.Matrix
	if !fullRun || !binaryRun || !binaryHistory || !slices.Equal(binaryMatrix.Profile, []int{135, 137}) || !slices.Equal(binaryMatrix.Mode, []string{"fresh", "transition"}) || len(binaryMatrix.Exclude) != 1 || binaryMatrix.Exclude[0].Profile != 135 || binaryMatrix.Exclude[0].Mode != "transition" || gate.If != "${{ always() }}" || !slices.Contains(gate.Needs, "install-engine-race") || !slices.Contains(gate.Needs, "kind-install-admission") || !slices.Contains(gate.Needs, "kind-install-binary") {
		t.Fatal("required gate bypasses full native admission or engine races")
	}
	var command string
	for _, step := range gate.Steps {
		if step.Env["ENGINE_RACE_RESULT"] == "${{ needs.install-engine-race.result }}" && step.Env["INSTALL_ADMISSION_RESULT"] == "${{ needs.kind-install-admission.result }}" && step.Env["INSTALL_BINARY_RESULT"] == "${{ needs.kind-install-binary.result }}" {
			if command != "" {
				t.Fatal("ambiguous required dependency gate")
			}
			command = step.Run
		}
	}
	if command == "" {
		t.Fatal("required dependency gate missing")
	}
	for _, races := range []string{"success", "failure", "cancelled", "skipped", ""} {
		for _, native := range []string{"success", "failure", "cancelled", "skipped", ""} {
			for _, binary := range []string{"success", "failure", "cancelled", "skipped", ""} {
				c := exec.Command("sh", "-e", "-c", command)
				c.Env = append(os.Environ(), "ENGINE_RACE_RESULT="+races, "INSTALL_ADMISSION_RESULT="+native, "INSTALL_BINARY_RESULT="+binary)
				passed := c.Run() == nil
				if passed != (races == "success" && native == "success" && binary == "success") {
					t.Fatal("failed/cancelled/skipped/absent dependency became a green required gate")
				}
			}
		}
	}
}
