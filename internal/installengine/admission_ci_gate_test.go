// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"testing"

	yaml "go.yaml.in/yaml/v3"
)

// This is an ordering barrier, not a success prerequisite. A diagnostic failure
// must not hide the independent native or race proof; workflow cancellation may.
func diagnosticOrderingOnly(needs []string, condition string, tolerate any) bool {
	return slices.Equal(needs, []string{"installer-diagnostics"}) && condition == "${{ !cancelled() }}" && tolerate == nil
}

// Bulk matrices wait for their closed native foundation set, but failed
// foundations must not skip their independent whole-tree coverage. The long
// signed-binary jobs are independent and become eligible after diagnostics.
func bulkFoundationOrderingOnly(needs []string, condition string, tolerate any) bool {
	return slices.Equal(needs, []string{"installer-diagnostics", "kind-install-gc", "kind-install-admission", "kind-install-admission-v3", "kind-install-auth", "kind-install-baseline", "kind-install-precontroller"}) && condition == "${{ !cancelled() }}" && tolerate == nil
}

// Unlike the ordering-only bulk barrier, diagnostics must actually succeed
// before spending the signed lifecycle budget. No custom condition or failure
// tolerance may bypass the default GitHub needs-success behavior.
func binaryDiagnosticsPrerequisite(needs []string, condition string, tolerate any) bool {
	return slices.Equal(needs, []string{"installer-diagnostics"}) && condition == "" && tolerate == nil
}

func TestInstallerAdmissionCIProfilesAndFailClosedRequiredGate(t *testing.T) {
	body, err := os.ReadFile("../../.github/workflows/ci.yml")
	if err != nil {
		t.Fatal("CI source unavailable")
	}
	var workflow struct {
		Permissions map[string]string `yaml:"permissions"`
		Jobs        map[string]struct {
			Name            string            `yaml:"name"`
			RunsOn          string            `yaml:"runs-on"`
			Permissions     map[string]string `yaml:"permissions"`
			If              string            `yaml:"if"`
			ContinueOnError any               `yaml:"continue-on-error"`
			Needs           []string          `yaml:"needs"`
			TimeoutMinutes  int               `yaml:"timeout-minutes"`
			Env             map[string]string `yaml:"env"`
			Strategy        struct {
				FailFast    *bool `yaml:"fail-fast"`
				MaxParallel int   `yaml:"max-parallel"`
				Matrix      struct {
					Shard   []int    `yaml:"shard"`
					Part    []string `yaml:"part"`
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
	if len(workflow.Permissions) != 1 || workflow.Permissions["contents"] != "read" {
		t.Fatal("CI workflow permissions must be read-only contents")
	}
	// Identical PR-merge/head trees do not have identical source SHA/epoch.
	// Signed packages, image revision labels and lifecycle evidence must use
	// the requested head (or exact main push), not a synthetic merge identity.
	requiredJobs := []string{"installer-diagnostics", "kind-install-binary", "kind-install-baseline", "kind-install-gc", "kind-install-precontroller", "kind-install-admission", "kind-install-admission-v3", "kind-install-auth", "kind-api", "kind-recovery", "install-engine-race", "envtest", "go-policy-checks", "go-and-policy", "kind-lifecycle", "golangci-lint"}
	for _, name := range requiredJobs {
		if _, present := workflow.Jobs[name]; !present {
			t.Errorf("required exact-source CI job %s is absent", name)
		}
	}
	for name, job := range workflow.Jobs {
		if len(job.Permissions) != 0 {
			t.Errorf("CI job %s overrides workflow read-only permissions", name)
		}
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
	for _, name := range []string{"kind-install-baseline", "kind-install-gc", "kind-install-precontroller", "kind-install-admission", "kind-install-admission-v3", "kind-install-auth", "kind-api", "kind-recovery", "kind-lifecycle", "golangci-lint", "go-policy-checks"} {
		job := workflow.Jobs[name]
		if !diagnosticOrderingOnly(job.Needs, job.If, job.ContinueOnError) {
			t.Fatalf("CI job %s competes with early diagnostics or skips independent coverage after their failure", name)
		}
	}
	for _, name := range []string{"install-engine-race", "envtest"} {
		job := workflow.Jobs[name]
		if !bulkFoundationOrderingOnly(job.Needs, job.If, job.ContinueOnError) {
			t.Fatal("bulk matrix bypasses foundations or skips independent coverage on failure", name)
		}
	}
	// Literal independent oracle, not copied from another job's mutable DAG.
	bulkNeeds := []string{"installer-diagnostics", "kind-install-gc", "kind-install-admission", "kind-install-admission-v3", "kind-install-auth", "kind-install-baseline", "kind-install-precontroller"}
	if !bulkFoundationOrderingOnly(bulkNeeds, "${{ !cancelled() }}", nil) {
		t.Fatal("bulk ordering-only positive control refused")
	}
	for index := range bulkNeeds {
		if bulkFoundationOrderingOnly(slices.Delete(slices.Clone(bulkNeeds), index, index+1), "${{ !cancelled() }}", nil) {
			t.Fatal("bulk ordering accepted an omitted foundation", index)
		}
	}
	for _, extra := range []string{"unrelated", "installer-diagnostics", "install-engine-race", "envtest", "kind-install-binary", "go-and-policy"} {
		if bulkFoundationOrderingOnly(append(slices.Clone(bulkNeeds), extra), "${{ !cancelled() }}", nil) {
			t.Fatal("bulk ordering accepted an extra, duplicate, self or sibling dependency", extra)
		}
	}
	reordered := slices.Clone(bulkNeeds)
	reordered[0], reordered[1] = reordered[1], reordered[0]
	if bulkFoundationOrderingOnly(reordered, "${{ !cancelled() }}", nil) || bulkFoundationOrderingOnly(nil, "${{ !cancelled() }}", nil) {
		t.Fatal("bulk ordering accepted a substituted or missing dependency list")
	}
	for _, condition := range []string{"", "${{ success() }}", "${{ always() }}", "${{ failure() }}"} {
		if bulkFoundationOrderingOnly(bulkNeeds, condition, nil) {
			t.Fatal("bulk ordering accepted a skip/bypass condition", condition)
		}
	}
	for _, tolerate := range []any{true, "${{ true }}"} {
		if bulkFoundationOrderingOnly(bulkNeeds, "${{ !cancelled() }}", tolerate) {
			t.Fatal("bulk ordering tolerated failure")
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
	if races.TimeoutMinutes != 30 || races.Strategy.FailFast == nil || *races.Strategy.FailFast || races.Strategy.MaxParallel != 4 || races.Env["GOMAXPROCS"] != "2" || races.Env["GOMEMLIMIT"] != "1GiB" {
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
	if !slices.Equal(gate.Needs, []string{"installer-diagnostics", "install-engine-race", "kind-install-admission", "kind-install-admission-v3", "kind-install-binary", "kind-install-baseline", "kind-install-gc", "kind-install-precontroller", "kind-install-auth", "kind-api", "kind-recovery", "envtest", "kind-lifecycle", "go-policy-checks", "golangci-lint"}) || gate.ContinueOnError != nil || len(gate.Permissions) != 0 {
		t.Fatal("required gate omitted, tolerated or substituted a complete proof")
	}
	if len(gate.Needs) != len(workflow.Jobs)-1 {
		t.Fatal("required aggregate does not cover every other CI job")
	}
	for name := range workflow.Jobs {
		if name != "go-and-policy" && !slices.Contains(gate.Needs, name) {
			t.Fatal("CI job omitted from the fail-closed aggregate", name)
		}
	}
	checks := workflow.Jobs["go-policy-checks"]
	wantPolicyRuns := []string{
		"go mod verify",
		"test -z \"$(gofmt -l .)\"",
		"make verify-generated",
		"make verify-runtime-assets",
		"go vet -p 1 ./...",
		`discovered=$(go list ./...)
mapfile -t packages < <(printf '%s\n' "$discovered" | awk '$0 != "github.com/gobha-me/arcadectl/internal/installengine"')
test "${#packages[@]}" -gt 0
go test -race -p 1 -timeout=15m "${packages[@]}"
`,
		`for tag in first second; do
  docker build --no-cache \
    --build-arg VCS_REF="$(git rev-parse HEAD)" \
    --build-arg SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)" \
    --tag "arcadectl-controller:ci-$tag" \
    .
done
first_id=$(docker image inspect --format '{{.Id}}' arcadectl-controller:ci-first)
second_id=$(docker image inspect --format '{{.Id}}' arcadectl-controller:ci-second)
if [ "$first_id" != "$second_id" ]; then
  docker image inspect arcadectl-controller:ci-first arcadectl-controller:ci-second \
    --format 'id={{.Id}} created={{.Created}} layers={{json .RootFS.Layers}}'
  echo "Independent clean builds produced different controller images" >&2
  exit 1
fi
`,
		`for tag in first second; do
  docker build --no-cache --file Dockerfile.api \
    --build-arg VCS_REF="$(git rev-parse HEAD)" \
    --build-arg SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)" \
    --tag "arcadectl-api:ci-$tag" .
done
first_id=$(docker image inspect --format '{{.Id}}' arcadectl-api:ci-first)
second_id=$(docker image inspect --format '{{.Id}}' arcadectl-api:ci-second)
test "$first_id" = "$second_id"
test "$(docker image inspect --format '{{.Config.User}}' arcadectl-api:ci-first)" = '65532:65532'
test "$(docker image inspect --format '{{json .Config.Entrypoint}}' arcadectl-api:ci-first)" = '["/arcadectl-api"]'
test "$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' arcadectl-api:ci-first)" = "$(git rev-parse HEAD)"
`,
	}
	if checks.Name != "Go and policy checks" || checks.RunsOn != "ubuntu-24.04" || checks.TimeoutMinutes != 45 || len(checks.Env) != 2 || checks.Env["GOMAXPROCS"] != "2" || checks.Env["GOMEMLIMIT"] != "1GiB" || len(checks.Steps) != 10 {
		t.Fatal("independent policy checks changed their runner, budget, environment or complete step set")
	}
	if checks.Steps[0].Uses != "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1" || len(checks.Steps[0].With) != 1 || checks.Steps[1].Uses != "actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e" || checks.Steps[1].With["go-version-file"] != "go.mod" || checks.Steps[1].With["cache"] != true || len(checks.Steps[1].With) != 2 {
		t.Fatal("independent policy checks changed pinned checkout or Go setup")
	}
	for index, step := range checks.Steps {
		if step.If != "" || step.ContinueOnError != nil || len(step.Env) != 0 || index < 2 && step.Run != "" || index >= 2 && (step.Run != wantPolicyRuns[index-2] || step.Uses != "" || len(step.With) != 0) {
			t.Fatal("moved policy commands changed, became conditional or tolerated failures", index)
		}
	}
	// Independently derived golangci-lint baseline ratchet invariants (#106).
	lintJob, lintExists := workflow.Jobs["golangci-lint"]
	if !lintExists || lintJob.Name != "Golangci-lint baseline ratchet" || lintJob.RunsOn != "ubuntu-24.04" || lintJob.TimeoutMinutes != 20 || len(lintJob.Permissions) != 0 || len(lintJob.Env) != 2 || lintJob.Env["GOMAXPROCS"] != "2" || lintJob.Env["GOMEMLIMIT"] != "1GiB" || lintJob.Strategy.FailFast != nil || lintJob.Strategy.MaxParallel != 0 || len(lintJob.Strategy.Matrix.Shard) != 0 || len(lintJob.Strategy.Matrix.Part) != 0 || len(lintJob.Strategy.Matrix.Profile) != 0 || len(lintJob.Strategy.Matrix.Mode) != 0 || len(lintJob.Strategy.Matrix.Exclude) != 0 || len(lintJob.Steps) != 4 {
		t.Fatal("golangci-lint ratchet altered its job identity, read-only permissions, bounded worker or strategy")
	}
	if lintJob.Steps[0].Name != "Check out exact source" || lintJob.Steps[0].Uses != "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1" || len(lintJob.Steps[0].With) != 2 || lintJob.Steps[0].With["fetch-depth"] != 0 || lintJob.Steps[0].With["ref"] != "${{ github.event.pull_request.head.sha || github.sha }}" || lintJob.Steps[1].Name != "Set up Go" || lintJob.Steps[1].Uses != "actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e" || len(lintJob.Steps[1].With) != 2 || lintJob.Steps[1].With["go-version-file"] != "go.mod" || lintJob.Steps[1].With["cache"] != true {
		t.Fatal("golangci-lint ratchet altered exact source checkout or pinned Go setup")
	}
	ratchetAction := lintJob.Steps[2]
	if ratchetAction.Name != "Fail on findings outside the committed baseline" || ratchetAction.Uses != "golangci/golangci-lint-action@ba0d7d2ec06a0ea1cb5fa41b2e4a3ab91d21278a" || strings.Count(string(body), "uses: golangci/golangci-lint-action@ba0d7d2ec06a0ea1cb5fa41b2e4a3ab91d21278a # v9.3.0") != 1 || len(ratchetAction.With) != 4 || ratchetAction.With["version"] != "v2.15.0" || ratchetAction.With["verify"] != true || ratchetAction.With["only-new-issues"] != false || ratchetAction.With["args"] != "--config=.golangci.yml --issues-exit-code=1 ./..." {
		t.Fatal("golangci-lint ratchet must use SHA-pinned v9.3.0 action with v2.15.0, verify=true, only-new-issues=false and fail-closed whole-tree args")
	}
	for stepIdx, step := range lintJob.Steps[:3] {
		if step.If != "" || step.ContinueOnError != nil || len(step.Env) != 0 || step.Run != "" {
			t.Fatalf("golangci-lint step %d can be conditionally skipped, tolerate failure or override env/run", stepIdx)
		}
	}
	newFindings := lintJob.Steps[3]
	if newFindings.If != "" || newFindings.ContinueOnError != nil || newFindings.Uses != "" || len(newFindings.Env) != 1 || newFindings.Env["LINT_BASE_SHA"] != "${{ github.event.pull_request.base.sha || github.event.before }}" || newFindings.Run != "bash hack/lint-new-findings.sh" {
		t.Fatal("new findings must use the exclusion-free ratchet and exact event base without skip or failure tolerance")
	}
	if gate.Name != "Go and policy" || gate.RunsOn != "ubuntu-24.04" || len(gate.Steps) != 2 || gate.Steps[0].Uses != "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1" || gate.Steps[0].Run != "" || gate.Steps[0].If != "" || gate.Steps[0].ContinueOnError != nil || len(gate.Steps[0].Env) != 0 {
		t.Fatal("protected aggregate changed its name, exact checkout or assertion-only scope")
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
		"go test -race -tags=kindinstall -p 1 -timeout=5m ./internal/installengine -run '^(TestInstallerAdmissionCIProfilesAndFailClosedRequiredGate|TestEnvtestPartitionsCompleteCompiledUnion|TestEnvtestPartitionsRefuseInvalidInputs|TestEnvtestPartitionsAllPartsAndFailures|TestInstallerBinaryProgressCapture|TestInstallerBinaryRequestPipelineCapture|TestInstallerBinaryParentContext|TestLifecycleCostsBoundedCommandAndInvocationIsolation|TestLifecycleCostsConcurrentRefusalsAndCancellation)$' -count=1",
		"go test -race -p 1 -timeout=5m -v ./internal/installengine -run '^(TestDiscoveryReplyMemo.*|TestProofDiscovery.*|TestBaselineContainment.*|TestBaselineDenied(EightLanes|Index).*)$' -count=1",
		"go test -race -p 1 -timeout=5m ./internal/installobserve -run '^TestCollectionDiagnostic.*$' -count=1\ngo test -race -p 1 -timeout=5m ./internal/installengine -run '^(TestFixtureTypedCollectionDiagnostic.*|TestFixtureObservationDiagnostic.*|TestFixtureAdmissionSettle.*)$' -count=1\n",
		"go test -p 1 -timeout=2m ./internal/installengine -run '^$' -bench '^(BenchmarkDiscoveryReplyConversion|BenchmarkBaselineDeniedDescriptorMembership)$' -benchmem -benchtime=250ms -count=1",
		"go test -race -p 1 -timeout=1m ./hack/profile-installer-wrappers -count=1\ngo run -p 1 ./hack/profile-installer-wrappers '${{ github.event.pull_request.head.sha || github.sha }}'\n",
		"go vet -tags=kindinstall -p 1 ./cmd/arcadectl-installer ./internal/installengine ./internal/installobserve",
	}
	if diagnostics.If != "" || diagnostics.ContinueOnError != nil || len(diagnostics.Needs) != 0 || diagnostics.TimeoutMinutes != 20 || diagnostics.Env["GOMAXPROCS"] != "2" || diagnostics.Env["GOMEMLIMIT"] != "1GiB" || !slices.Equal(diagnosticRuns, wantDiagnosticRuns) || !slices.Contains(gate.Needs, "installer-diagnostics") || len(diagnostics.Steps) != 9 {
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
	wantEnvtestParts := []string{"base-packages"}
	for i := range 32 {
		wantEnvtestParts = append(wantEnvtestParts, strconv.Itoa(i))
	}
	if !slices.Equal(envtest.Strategy.Matrix.Part, wantEnvtestParts) || len(envtest.Strategy.Matrix.Exclude) != 0 || len(envtest.Strategy.Matrix.Shard) != 0 || len(envtest.Strategy.Matrix.Mode) != 0 || len(envtest.Strategy.Matrix.Profile) != 0 || envtest.Strategy.FailFast == nil || *envtest.Strategy.FailFast || envtest.Strategy.MaxParallel != 4 {
		t.Fatal("complete compiled envtest partition matrix omitted or sibling coverage cancelled")
	}
	wantEnvtestRun := "make test-envtest-part ENVTEST_PART='${{ matrix.part }}'"
	nativeSuiteRuns := 0
	for _, job := range workflow.Jobs {
		for _, step := range job.Steps {
			if step.Run == wantEnvtestRun {
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
	if envtest.Steps[0].Uses != "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1" || envtest.Steps[1].Uses != "actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e" || envtest.Steps[1].With["go-version-file"] != "go.mod" || envtest.Steps[1].With["cache"] != true || envtest.Steps[2].Run != wantEnvtestRun || nativeSuiteRuns != 1 {
		t.Fatal("complete API-server suite changed pinned setup or fresh full-suite execution")
	}
	makefile, err := os.ReadFile("../../Makefile")
	if err != nil || strings.Count(string(makefile), "GOMAXPROCS=2 GOMEMLIMIT=1GiB bash ./hack/test-envtest-part.sh --all") != 1 || strings.Count(string(makefile), "GOMAXPROCS=2 GOMEMLIMIT=1GiB bash ./hack/test-envtest-part.sh \"$(ENVTEST_PART)\"") != 1 || gate.TimeoutMinutes != 45 {
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
	if !binaryDiagnosticsPrerequisite(binary.Needs, binary.If, binary.ContinueOnError) {
		t.Fatal("long signed lifecycle proofs delay independent work or bypass successful diagnostics")
	}
	if !binaryDiagnosticsPrerequisite([]string{"installer-diagnostics"}, "", nil) {
		t.Fatal("binary diagnostics-success positive control refused")
	}
	for _, needs := range [][]string{nil, {}, {"kind-install-gc"}, {"installer-diagnostics", "installer-diagnostics"}, {"installer-diagnostics", "kind-install-binary"}, {"installer-diagnostics", "go-and-policy"}} {
		if binaryDiagnosticsPrerequisite(needs, "", nil) {
			t.Fatal("binary scheduling accepted missing, substituted, duplicate or cyclic prerequisites")
		}
	}
	for _, foundation := range bulkNeeds[1:] {
		if binaryDiagnosticsPrerequisite([]string{"installer-diagnostics", foundation}, "", nil) {
			t.Fatal("binary scheduling delayed independent lifecycle work behind a native foundation", foundation)
		}
	}
	for _, condition := range []string{"${{ !cancelled() }}", "${{ always() }}", "${{ failure() }}", "${{ success() }}"} {
		if binaryDiagnosticsPrerequisite([]string{"installer-diagnostics"}, condition, nil) {
			t.Fatal("binary scheduling accepted a custom diagnostic scheduling condition", condition)
		}
	}
	for _, tolerate := range []any{false, true, "${{ true }}"} {
		if binaryDiagnosticsPrerequisite([]string{"installer-diagnostics"}, "", tolerate) {
			t.Fatal("binary scheduling accepted a failure-tolerance override")
		}
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
		if len(step.Env) == 15 && step.Env["INSTALLER_DIAGNOSTICS_RESULT"] == "${{ needs.installer-diagnostics.result }}" && step.Env["ENGINE_RACE_RESULT"] == "${{ needs.install-engine-race.result }}" && step.Env["INSTALL_ADMISSION_RESULT"] == "${{ needs.kind-install-admission.result }}" && step.Env["INSTALL_BINARY_RESULT"] == "${{ needs.kind-install-binary.result }}" && step.Env["INSTALL_BASELINE_RESULT"] == "${{ needs.kind-install-baseline.result }}" && step.Env["INSTALL_ADMISSION_V3_RESULT"] == "${{ needs.kind-install-admission-v3.result }}" && step.Env["INSTALL_PRECONTROLLER_RESULT"] == "${{ needs.kind-install-precontroller.result }}" && step.Env["INSTALL_GC_RESULT"] == "${{ needs.kind-install-gc.result }}" && step.Env["INSTALL_AUTH_RESULT"] == "${{ needs.kind-install-auth.result }}" && step.Env["API_RESULT"] == "${{ needs.kind-api.result }}" && step.Env["RECOVERY_RESULT"] == "${{ needs.kind-recovery.result }}" && step.Env["ENVTEST_RESULT"] == "${{ needs.envtest.result }}" && step.Env["LIFECYCLE_RESULT"] == "${{ needs.kind-lifecycle.result }}" && step.Env["GO_POLICY_CHECKS_RESULT"] == "${{ needs.go-policy-checks.result }}" && step.Env["GOLANGCI_LINT_RESULT"] == "${{ needs.golangci-lint.result }}" {
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
							c.Env = append(os.Environ(), "INSTALLER_DIAGNOSTICS_RESULT=success", "GOLANGCI_LINT_RESULT=success", "ENGINE_RACE_RESULT="+races, "INSTALL_ADMISSION_RESULT="+native, "INSTALL_BINARY_RESULT="+binary, "INSTALL_BASELINE_RESULT="+baseline, "INSTALL_ADMISSION_V3_RESULT="+v3, "INSTALL_PRECONTROLLER_RESULT="+precontroller, "INSTALL_GC_RESULT=success", "INSTALL_AUTH_RESULT=success", "API_RESULT=success", "RECOVERY_RESULT=success", "ENVTEST_RESULT=success", "LIFECYCLE_RESULT=success", "GO_POLICY_CHECKS_RESULT=success")
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
		c.Env = append(os.Environ(), "INSTALLER_DIAGNOSTICS_RESULT=success", "GOLANGCI_LINT_RESULT=success", "ENGINE_RACE_RESULT=success", "INSTALL_ADMISSION_RESULT=success", "INSTALL_BINARY_RESULT=success", "INSTALL_BASELINE_RESULT=success", "INSTALL_ADMISSION_V3_RESULT=success", "INSTALL_PRECONTROLLER_RESULT=success", "INSTALL_GC_RESULT="+result, "INSTALL_AUTH_RESULT=success", "API_RESULT=success", "RECOVERY_RESULT=success", "ENVTEST_RESULT=success", "LIFECYCLE_RESULT=success", "GO_POLICY_CHECKS_RESULT=success")
		if passed := c.Run() == nil; passed != (result == "success") {
			t.Fatal("failed/cancelled/skipped/absent GC proof became a green required gate")
		}
	}
	// Independently exercise every added prerequisite outcome while the others
	// succeed, preserving all original combinations without multiplying them.
	added := []string{"GOLANGCI_LINT_RESULT", "INSTALL_AUTH_RESULT", "API_RESULT", "RECOVERY_RESULT", "INSTALLER_DIAGNOSTICS_RESULT", "ENVTEST_RESULT", "LIFECYCLE_RESULT", "GO_POLICY_CHECKS_RESULT"}
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
		absentCmd := exec.Command("sh", "-e", "-c", command)
		for _, kv := range os.Environ() {
			if !strings.HasPrefix(kv, variable+"=") {
				absentCmd.Env = append(absentCmd.Env, kv)
			}
		}
		absentCmd.Env = append(absentCmd.Env, "ENGINE_RACE_RESULT=success", "INSTALL_ADMISSION_RESULT=success", "INSTALL_BINARY_RESULT=success", "INSTALL_BASELINE_RESULT=success", "INSTALL_ADMISSION_V3_RESULT=success", "INSTALL_PRECONTROLLER_RESULT=success", "INSTALL_GC_RESULT=success")
		for _, other := range added {
			if other != variable {
				absentCmd.Env = append(absentCmd.Env, other+"=success")
			}
		}
		if absentCmd.Run() == nil {
			t.Fatalf("absent %s environment binding became a green required gate", variable)
		}
	}
}

func TestGolangciLintRatchetGateInvariants(t *testing.T) {
	body, err := os.ReadFile("../../.github/workflows/ci.yml")
	if err != nil {
		t.Fatal("CI workflow source unavailable")
	}
	var ci struct {
		Permissions map[string]string `yaml:"permissions"`
		Jobs        map[string]struct {
			Name            string            `yaml:"name"`
			RunsOn          string            `yaml:"runs-on"`
			Permissions     map[string]string `yaml:"permissions"`
			If              string            `yaml:"if"`
			ContinueOnError any               `yaml:"continue-on-error"`
			Needs           []string          `yaml:"needs"`
			TimeoutMinutes  int               `yaml:"timeout-minutes"`
			Env             map[string]string `yaml:"env"`
			Steps           []struct {
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
	if yaml.Unmarshal(body, &ci) != nil {
		t.Fatal("CI workflow YAML malformed")
	}
	if len(ci.Permissions) != 1 || ci.Permissions["contents"] != "read" {
		t.Fatal("workflow permissions are not read-only")
	}
	lint, ok := ci.Jobs["golangci-lint"]
	if !ok || lint.Name != "Golangci-lint baseline ratchet" || len(lint.Permissions) != 0 || !diagnosticOrderingOnly(lint.Needs, lint.If, lint.ContinueOnError) || lint.RunsOn != "ubuntu-24.04" || lint.TimeoutMinutes != 20 || len(lint.Env) != 2 || lint.Env["GOMAXPROCS"] != "2" || lint.Env["GOMEMLIMIT"] != "1GiB" || len(lint.Steps) != 4 {
		t.Fatal("golangci-lint job missing or altered its identity, permissions, ordering barrier or worker bounds")
	}
	for i, step := range lint.Steps[:3] {
		if step.If != "" || step.ContinueOnError != nil || len(step.Env) != 0 || step.Run != "" {
			t.Fatalf("golangci-lint step %d permits conditional skip, failure tolerance or custom run/env", i)
		}
	}
	if lint.Steps[0].Name != "Check out exact source" || lint.Steps[0].Uses != "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1" || len(lint.Steps[0].With) != 2 || lint.Steps[0].With["fetch-depth"] != 0 || lint.Steps[0].With["ref"] != "${{ github.event.pull_request.head.sha || github.sha }}" || lint.Steps[1].Name != "Set up Go" || lint.Steps[1].Uses != "actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e" || len(lint.Steps[1].With) != 2 || lint.Steps[1].With["go-version-file"] != "go.mod" || lint.Steps[1].With["cache"] != true {
		t.Fatal("golangci-lint setup steps altered exact-source checkout or pinned Go toolchain")
	}
	actionStep := lint.Steps[2]
	if actionStep.Name != "Fail on findings outside the committed baseline" || actionStep.Uses != "golangci/golangci-lint-action@ba0d7d2ec06a0ea1cb5fa41b2e4a3ab91d21278a" || strings.Count(string(body), "uses: golangci/golangci-lint-action@ba0d7d2ec06a0ea1cb5fa41b2e4a3ab91d21278a # v9.3.0") != 1 || len(actionStep.With) != 4 || actionStep.With["version"] != "v2.15.0" || actionStep.With["verify"] != true || actionStep.With["only-new-issues"] != false || actionStep.With["args"] != "--config=.golangci.yml --issues-exit-code=1 ./..." {
		t.Fatal("golangci-lint action step altered SHA/version pinning, only-new-issues=false or fail-closed args")
	}
	diffStep := lint.Steps[3]
	if diffStep.If != "" || diffStep.ContinueOnError != nil || diffStep.Uses != "" || len(diffStep.Env) != 1 || diffStep.Env["LINT_BASE_SHA"] != "${{ github.event.pull_request.base.sha || github.event.before }}" || diffStep.Run != "bash hack/lint-new-findings.sh" {
		t.Fatal("exclusion-free diff ratchet must run with the exact event base and fail closed")
	}
	gate, gateOK := ci.Jobs["go-and-policy"]
	if !gateOK || !slices.Contains(gate.Needs, "golangci-lint") || len(gate.Steps) != 2 || gate.Steps[1].If != "" || gate.Steps[1].ContinueOnError != nil || gate.Steps[1].Env["GOLANGCI_LINT_RESULT"] != "${{ needs.golangci-lint.result }}" {
		t.Fatal("go-and-policy aggregate gate omits golangci-lint prerequisite or GOLANGCI_LINT_RESULT wiring")
	}
	baseEnv := []string{
		"INSTALLER_DIAGNOSTICS_RESULT=success",
		"ENGINE_RACE_RESULT=success",
		"INSTALL_ADMISSION_RESULT=success",
		"INSTALL_BINARY_RESULT=success",
		"INSTALL_BASELINE_RESULT=success",
		"INSTALL_GC_RESULT=success",
		"INSTALL_ADMISSION_V3_RESULT=success",
		"INSTALL_PRECONTROLLER_RESULT=success",
		"INSTALL_AUTH_RESULT=success",
		"API_RESULT=success",
		"RECOVERY_RESULT=success",
		"ENVTEST_RESULT=success",
		"LIFECYCLE_RESULT=success",
		"GO_POLICY_CHECKS_RESULT=success",
	}
	for _, result := range []string{"success", "failure", "cancelled", "skipped", ""} {
		cmd := exec.Command("sh", "-e", "-c", gate.Steps[1].Run)
		cmd.Env = append(append(os.Environ(), baseEnv...), "GOLANGCI_LINT_RESULT="+result)
		if (cmd.Run() == nil) != (result == "success") {
			t.Fatalf("go-and-policy aggregate did not fail closed on GOLANGCI_LINT_RESULT=%q", result)
		}
	}
	absent := exec.Command("sh", "-e", "-c", gate.Steps[1].Run)
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "GOLANGCI_LINT_RESULT=") {
			absent.Env = append(absent.Env, kv)
		}
	}
	absent.Env = append(absent.Env, baseEnv...)
	if absent.Run() == nil {
		t.Fatal("go-and-policy aggregate did not fail closed on absent GOLANGCI_LINT_RESULT")
	}
	cfgBytes, err := os.ReadFile("../../.golangci.yml")
	if err != nil {
		t.Fatal(".golangci.yml unavailable")
	}
	var lintCfg struct {
		Version string `yaml:"version"`
		Run     struct {
			Timeout          string `yaml:"timeout"`
			Concurrency      int    `yaml:"concurrency"`
			RelativePathMode string `yaml:"relative-path-mode"`
		} `yaml:"run"`
		Linters struct {
			Default    string   `yaml:"default"`
			Enable     []string `yaml:"enable"`
			Exclusions struct {
				WarnUnused bool `yaml:"warn-unused"`
			} `yaml:"exclusions"`
		} `yaml:"linters"`
		Issues struct {
			MaxIssuesPerLinter *int  `yaml:"max-issues-per-linter"`
			MaxSameIssues      *int  `yaml:"max-same-issues"`
			UniqByLine         *bool `yaml:"uniq-by-line"`
		} `yaml:"issues"`
	}
	if yaml.Unmarshal(cfgBytes, &lintCfg) != nil {
		t.Fatal(".golangci.yml malformed")
	}
	if lintCfg.Version != "2" || lintCfg.Run.Timeout != "15m" || lintCfg.Run.Concurrency != 2 || lintCfg.Run.RelativePathMode != "cfg" || lintCfg.Linters.Default != "none" || !slices.Equal(lintCfg.Linters.Enable, []string{"errcheck", "govet", "ineffassign", "staticcheck", "unused"}) || !lintCfg.Linters.Exclusions.WarnUnused || lintCfg.Issues.MaxIssuesPerLinter == nil || *lintCfg.Issues.MaxIssuesPerLinter != 0 || lintCfg.Issues.MaxSameIssues == nil || *lintCfg.Issues.MaxSameIssues != 0 || lintCfg.Issues.UniqByLine == nil || *lintCfg.Issues.UniqByLine {
		t.Fatal(".golangci.yml baseline ratchet configuration drifted from uncapped v2 invariants")
	}
}
