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
	admission := workflow.Jobs["kind-install-admission"]
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
