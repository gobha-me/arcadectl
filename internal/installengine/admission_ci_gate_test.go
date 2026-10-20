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

// This is an ordering barrier, not a success prerequisite. A diagnostic failure
// must not hide the independent native or race proof; workflow cancellation may.
func diagnosticOrderingOnly(needs []string, condition string, tolerate any) bool {
	return slices.Equal(needs, []string{"installer-diagnostics"}) && condition == "${{ !cancelled() }}" && tolerate == nil
}

func TestInstallerAdmissionCIProfilesAndFailClosedRequiredGate(t *testing.T) {
	body, err := os.ReadFile("../../.github/workflows/ci.yml")
	if err != nil {
		t.Fatal("CI source unavailable")
	}
	var workflow struct {
		Jobs map[string]struct {
			If              string            `yaml:"if"`
			ContinueOnError any               `yaml:"continue-on-error"`
			Needs           []string          `yaml:"needs"`
			TimeoutMinutes  int               `yaml:"timeout-minutes"`
			Env             map[string]string `yaml:"env"`
			Strategy        struct {
				FailFast *bool `yaml:"fail-fast"`
				Matrix   struct {
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
				If              string            `yaml:"if"`
				ContinueOnError any               `yaml:"continue-on-error"`
				Name            string            `yaml:"name"`
				Uses            string            `yaml:"uses"`
				Run             string            `yaml:"run"`
				Env             map[string]string `yaml:"env"`
				With            map[string]any    `yaml:"with"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if yaml.Unmarshal(body, &workflow) != nil {
		t.Fatal("CI workflow malformed")
	}
	// Identical PR-merge/head trees do not have identical source SHA/epoch.
	// Signed packages, image revision labels and lifecycle evidence must use
	// the requested head (or exact main push), not a synthetic merge identity.
	for _, name := range []string{"installer-diagnostics", "kind-install-binary", "kind-install-baseline", "kind-install-gc", "kind-install-precontroller", "kind-install-admission", "kind-install-admission-v3", "kind-install-auth", "kind-api", "kind-recovery", "install-engine-race", "envtest", "go-and-policy", "kind-lifecycle"} {
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
	for _, name := range []string{"kind-install-baseline", "kind-install-gc", "kind-install-precontroller", "kind-install-admission", "kind-install-admission-v3", "kind-install-auth", "kind-api", "kind-recovery", "install-engine-race", "envtest", "kind-lifecycle"} {
		job := workflow.Jobs[name]
		if !diagnosticOrderingOnly(job.Needs, job.If, job.ContinueOnError) {
			t.Fatalf("CI job %s competes with early diagnostics or skips independent coverage after their failure", name)
		}
	}
	if !diagnosticOrderingOnly([]string{"installer-diagnostics"}, "${{ !cancelled() }}", nil) {
		t.Fatal("ordering-only positive control refused")
	}
	for _, bad := range []struct {
		needs     []string
		condition string
		tolerate  any
	}{
		{nil, "${{ !cancelled() }}", nil},
		{[]string{"installer-diagnostics", "go-and-policy"}, "${{ !cancelled() }}", nil},
		{[]string{"go-and-policy", "installer-diagnostics"}, "${{ !cancelled() }}", nil},
		{[]string{"install-engine-race"}, "${{ !cancelled() }}", nil},
		{[]string{"installer-diagnostics"}, "", nil},
		{[]string{"installer-diagnostics"}, "${{ success() }}", nil},
		{[]string{"installer-diagnostics"}, "${{ always() }}", nil},
		{[]string{"installer-diagnostics"}, "${{ !cancelled() }}", true},
		{[]string{"installer-diagnostics"}, "${{ !cancelled() }}", "${{ true }}"},
	} {
		if diagnosticOrderingOnly(bad.needs, bad.condition, bad.tolerate) {
			t.Fatal("unsafe scheduling control accepted")
		}
	}
	admission := workflow.Jobs["kind-install-admission"]
	races := workflow.Jobs["install-engine-race"]
	wantShards := make([]int, 32)
	for i := range wantShards {
		wantShards[i] = i
	}
	if !slices.Equal(races.Strategy.Matrix.Shard, wantShards) || len(races.Strategy.Matrix.Exclude) != 0 {
		t.Fatal("compiled race test partitions omitted from CI")
	}
	if races.TimeoutMinutes != 30 || races.Strategy.FailFast == nil || *races.Strategy.FailFast || races.Env["GOMAXPROCS"] != "2" || races.Env["GOMEMLIMIT"] != "1GiB" {
		t.Fatal("race workers changed their bounded budgets or cancelled sibling coverage")
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
	if !slices.Equal(gate.Needs, []string{"installer-diagnostics", "install-engine-race", "kind-install-admission", "kind-install-admission-v3", "kind-install-binary", "kind-install-baseline", "kind-install-gc", "kind-install-precontroller", "kind-install-auth", "kind-api", "kind-recovery", "envtest"}) || gate.ContinueOnError != nil {
		t.Fatal("required gate omitted, tolerated or substituted a complete proof")
	}
	diagnostics := workflow.Jobs["installer-diagnostics"]
	var diagnosticRuns []string
	for _, step := range diagnostics.Steps {
		if step.If != "" || step.ContinueOnError != nil || len(step.Env) != 0 {
			t.Fatal("early diagnostic step can skip, tolerate failure or override bounded environment")
		}
		if step.Run != "" {
			diagnosticRuns = append(diagnosticRuns, step.Run)
		}
	}
	wantDiagnosticRuns := []string{
		"go test -race -p 1 -timeout=5m ./cmd/arcadectl-installer -count=1",
		"go test -race -tags=kindinstall -p 1 -timeout=5m ./internal/installengine -run '^(TestInstallerAdmissionCIProfilesAndFailClosedRequiredGate|TestInstallerBinaryProgressCapture|TestInstallerBinaryRequestPipelineCapture|TestInstallerBinaryParentContext|TestLifecycleCostsBoundedCommandAndInvocationIsolation|TestLifecycleCostsConcurrentRefusalsAndCancellation)$' -count=1",
		"go test -race -p 1 -timeout=1m ./hack/profile-installer-wrappers -count=1\ngo run -p 1 ./hack/profile-installer-wrappers '${{ github.event.pull_request.head.sha || github.sha }}'\n",
		"go vet -tags=kindinstall -p 1 ./cmd/arcadectl-installer ./internal/installengine",
	}
	if diagnostics.If != "" || diagnostics.ContinueOnError != nil || len(diagnostics.Needs) != 0 || diagnostics.TimeoutMinutes != 20 || diagnostics.Env["GOMAXPROCS"] != "2" || diagnostics.Env["GOMEMLIMIT"] != "1GiB" || !slices.Equal(diagnosticRuns, wantDiagnosticRuns) || !slices.Contains(gate.Needs, "installer-diagnostics") || len(diagnostics.Steps) != 6 {
		t.Fatal("early CLI/diagnostic controls are missing, unbounded or gated behind native lifecycle")
	}
	if diagnostics.Steps[0].Uses != "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1" || diagnostics.Steps[1].Uses != "actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e" || diagnostics.Steps[1].With["go-version-file"] != "go.mod" || diagnostics.Steps[1].With["cache"] != true {
		t.Fatal("early diagnostics changed pinned source/build setup")
	}
	baseline := workflow.Jobs["kind-install-baseline"]
	baselineRun := false
	for _, step := range baseline.Steps {
		baselineRun = baselineRun || step.Run == "make test-kind-install-baseline INSTALL_BASELINE_PROFILE='${{ matrix.profile }}'"
	}
	if !baselineRun || baseline.TimeoutMinutes != 30 || baseline.Strategy.FailFast == nil || *baseline.Strategy.FailFast || !slices.Equal(baseline.Strategy.Matrix.Profile, []int{135, 137}) || len(baseline.Strategy.Matrix.Exclude) != 0 || len(baseline.Strategy.Matrix.Mode) != 0 || !slices.Contains(gate.Needs, "kind-install-baseline") {
		t.Fatal("native baseline profile or fail-closed dependency omitted")
	}
	envtest := workflow.Jobs["envtest"]
	nativeSuiteRuns := 0
	for _, job := range workflow.Jobs {
		for _, step := range job.Steps {
			if step.Run == "make test-envtest" {
				nativeSuiteRuns++
			}
		}
	}
	if len(envtest.Steps) != 3 || envtest.TimeoutMinutes != 45 || envtest.Env["GOMAXPROCS"] != "2" || envtest.Env["GOMEMLIMIT"] != "1GiB" {
		t.Fatal("complete API-server suite lacks its independent bounded job")
	}
	for _, step := range envtest.Steps {
		if step.If != "" || step.ContinueOnError != nil || len(step.Env) != 0 {
			t.Fatal("complete API-server suite can skip, tolerate failure or override its environment")
		}
	}
	if envtest.Steps[0].Uses != "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1" || envtest.Steps[1].Uses != "actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e" || envtest.Steps[1].With["go-version-file"] != "go.mod" || envtest.Steps[1].With["cache"] != true || envtest.Steps[2].Run != "make test-envtest" || nativeSuiteRuns != 1 {
		t.Fatal("complete API-server suite changed pinned setup or fresh full-suite execution")
	}
	makefile, err := os.ReadFile("../../Makefile")
	if err != nil || strings.Count(string(makefile), "go test -tags=envtest -p 1 -timeout=30m -count=1 ./api/v1alpha1 ./internal/controller ./internal/install ./internal/installcontract ./internal/installengine") != 1 || gate.TimeoutMinutes != 45 {
		t.Fatal("complete fresh API-server suite or its bounded CI envelope changed")
	}
	gc := workflow.Jobs["kind-install-gc"]
	gcRuns := 0
	for _, step := range gc.Steps {
		if step.Run == "make test-kind-install-gc" {
			gcRuns++
		}
	}
	if gcRuns != 1 || gc.TimeoutMinutes != 30 || len(gc.Strategy.Matrix.Profile) != 0 || len(gc.Strategy.Matrix.Mode) != 0 || len(gc.Strategy.Matrix.Exclude) != 0 || !slices.Contains(gate.Needs, "kind-install-gc") || strings.Count(string(makefile), "GOMAXPROCS=2 GOMEMLIMIT=1GiB go test -tags=kindinstall -p 1 -timeout=24m -v ./internal/installengine -run '^TestKindBaselineNativeForegroundGarbageCollection$$' -count=1") != 1 {
		t.Fatal("native foreground GC proof or fail-closed dependency omitted")
	}
	precontroller := workflow.Jobs["kind-install-precontroller"]
	precontrollerRun := false
	for _, step := range precontroller.Steps {
		precontrollerRun = precontrollerRun || step.Run == "make test-kind-install-precontroller INSTALL_PRECONTROLLER_PROFILE='${{ matrix.profile }}'"
	}
	if !precontrollerRun || precontroller.TimeoutMinutes != 40 || precontroller.Strategy.FailFast == nil || *precontroller.Strategy.FailFast || !slices.Equal(precontroller.Strategy.Matrix.Profile, []int{135, 137}) || len(precontroller.Strategy.Matrix.Exclude) != 0 || len(precontroller.Strategy.Matrix.Mode) != 0 || !slices.Contains(gate.Needs, "kind-install-precontroller") || !strings.Contains(string(makefile), "^TestKindBaselinePrecontrollerRuntimeNative$$/") {
		t.Fatal("genuine pre-controller profile or required dependency omitted")
	}
	binary := workflow.Jobs["kind-install-binary"]
	if binary.If != "" || !slices.Equal(binary.Needs, []string{"installer-diagnostics", "kind-install-gc", "kind-install-admission", "kind-install-admission-v3", "kind-install-auth", "kind-install-baseline", "kind-install-precontroller"}) {
		t.Fatal("long signed lifecycle proofs bypass native foundations or override fail-closed scheduling")
	}
	for _, required := range []struct {
		name    string
		command string
		minutes int
	}{
		{"kind-install-auth", "make test-kind-install-auth", 50},
		{"kind-api", "make test-kind-api", 40},
		{"kind-recovery", "make test-kind-recovery", 100},
	} {
		job := workflow.Jobs[required.name]
		runs := 0
		for _, step := range job.Steps {
			if step.Run == required.command {
				runs++
			}
		}
		if job.TimeoutMinutes != required.minutes || runs != 1 || !slices.Contains(gate.Needs, required.name) {
			t.Fatalf("native proof %s or its fail-closed required dependency omitted", required.name)
		}
	}
	// Every prerequisite must exist and the full workflow must remain a DAG.
	// In particular, binary may never depend on its own required aggregate.
	visited := map[string]uint8{}
	var acyclic func(string) bool
	acyclic = func(name string) bool {
		job, exists := workflow.Jobs[name]
		if !exists || visited[name] == 1 {
			return false
		}
		if visited[name] == 2 {
			return true
		}
		visited[name] = 1
		for _, dependency := range job.Needs {
			if !acyclic(dependency) {
				return false
			}
		}
		visited[name] = 2
		return true
	}
	for name := range workflow.Jobs {
		if !acyclic(name) {
			t.Fatal("CI prerequisites are missing or cyclic")
		}
	}
	v3 := workflow.Jobs["kind-install-admission-v3"]
	v3Run := false
	for _, step := range v3.Steps {
		v3Run = v3Run || step.Run == "make test-kind-install-admission-v3 INSTALL_ADMISSION_PROFILE='${{ matrix.profile }}' INSTALL_ADMISSION_MODE='${{ matrix.mode }}'"
	}
	if !v3Run || v3.TimeoutMinutes != 50 || v3.Strategy.FailFast == nil || *v3.Strategy.FailFast || !slices.Equal(v3.Strategy.Matrix.Profile, []int{135, 137}) || !slices.Equal(v3.Strategy.Matrix.Mode, []string{"cold", "warm"}) || len(v3.Strategy.Matrix.Exclude) != 0 || !slices.Contains(gate.Needs, "kind-install-admission-v3") || !strings.Contains(string(makefile), "^TestKindAdmissionEffectiveV3WithBaseline$$/") {
		t.Fatal("complete baseline-active v3 matrix missing from required CI")
	}
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
		if step.Env["INSTALLER_DIAGNOSTICS_RESULT"] == "${{ needs.installer-diagnostics.result }}" && step.Env["ENGINE_RACE_RESULT"] == "${{ needs.install-engine-race.result }}" && step.Env["INSTALL_ADMISSION_RESULT"] == "${{ needs.kind-install-admission.result }}" && step.Env["INSTALL_BINARY_RESULT"] == "${{ needs.kind-install-binary.result }}" && step.Env["INSTALL_BASELINE_RESULT"] == "${{ needs.kind-install-baseline.result }}" && step.Env["INSTALL_ADMISSION_V3_RESULT"] == "${{ needs.kind-install-admission-v3.result }}" && step.Env["INSTALL_PRECONTROLLER_RESULT"] == "${{ needs.kind-install-precontroller.result }}" && step.Env["INSTALL_GC_RESULT"] == "${{ needs.kind-install-gc.result }}" && step.Env["INSTALL_AUTH_RESULT"] == "${{ needs.kind-install-auth.result }}" && step.Env["API_RESULT"] == "${{ needs.kind-api.result }}" && step.Env["RECOVERY_RESULT"] == "${{ needs.kind-recovery.result }}" && step.Env["ENVTEST_RESULT"] == "${{ needs.envtest.result }}" {
			if step.If != "" || step.ContinueOnError != nil {
				t.Fatal("required dependency assertion can be skipped or tolerate failure")
			}
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
				for _, baseline := range []string{"success", "failure", "cancelled", "skipped", ""} {
					for _, v3 := range []string{"success", "failure", "cancelled", "skipped", ""} {
						for _, precontroller := range []string{"success", "failure", "cancelled", "skipped", ""} {
							c := exec.Command("sh", "-e", "-c", command)
							c.Env = append(os.Environ(), "INSTALLER_DIAGNOSTICS_RESULT=success", "ENGINE_RACE_RESULT="+races, "INSTALL_ADMISSION_RESULT="+native, "INSTALL_BINARY_RESULT="+binary, "INSTALL_BASELINE_RESULT="+baseline, "INSTALL_ADMISSION_V3_RESULT="+v3, "INSTALL_PRECONTROLLER_RESULT="+precontroller, "INSTALL_GC_RESULT=success", "INSTALL_AUTH_RESULT=success", "API_RESULT=success", "RECOVERY_RESULT=success", "ENVTEST_RESULT=success")
							passed := c.Run() == nil
							if passed != (races == "success" && native == "success" && binary == "success" && baseline == "success" && v3 == "success" && precontroller == "success") {
								t.Fatal("failed/cancelled/skipped/absent dependency became a green required gate")
							}
						}
					}
				}
			}
		}
	}
	// Preserve all previous combinations without a seventh Cartesian multiplier.
	// Separately exercise every GC outcome while all earlier proofs succeeded.
	for _, result := range []string{"success", "failure", "cancelled", "skipped", ""} {
		c := exec.Command("sh", "-e", "-c", command)
		c.Env = append(os.Environ(), "INSTALLER_DIAGNOSTICS_RESULT=success", "ENGINE_RACE_RESULT=success", "INSTALL_ADMISSION_RESULT=success", "INSTALL_BINARY_RESULT=success", "INSTALL_BASELINE_RESULT=success", "INSTALL_ADMISSION_V3_RESULT=success", "INSTALL_PRECONTROLLER_RESULT=success", "INSTALL_GC_RESULT="+result, "INSTALL_AUTH_RESULT=success", "API_RESULT=success", "RECOVERY_RESULT=success", "ENVTEST_RESULT=success")
		if passed := c.Run() == nil; passed != (result == "success") {
			t.Fatal("failed/cancelled/skipped/absent GC proof became a green required gate")
		}
	}
	// Independently exercise every added prerequisite outcome while the others
	// succeed, preserving all original combinations without multiplying them.
	added := []string{"INSTALL_AUTH_RESULT", "API_RESULT", "RECOVERY_RESULT", "INSTALLER_DIAGNOSTICS_RESULT", "ENVTEST_RESULT"}
	for _, variable := range added {
		for _, result := range []string{"success", "failure", "cancelled", "skipped", ""} {
			c := exec.Command("sh", "-e", "-c", command)
			c.Env = append(os.Environ(), "ENGINE_RACE_RESULT=success", "INSTALL_ADMISSION_RESULT=success", "INSTALL_BINARY_RESULT=success", "INSTALL_BASELINE_RESULT=success", "INSTALL_ADMISSION_V3_RESULT=success", "INSTALL_PRECONTROLLER_RESULT=success", "INSTALL_GC_RESULT=success")
			for _, other := range added {
				value := "success"
				if other == variable {
					value = result
				}
				c.Env = append(c.Env, other+"="+value)
			}
			if passed := c.Run() == nil; passed != (result == "success") {
				t.Fatalf("failed/cancelled/skipped/absent %s proof became a green required gate", variable)
			}
		}
	}
}
