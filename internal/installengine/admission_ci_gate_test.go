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
// must not hide the independent native proof; workflow cancellation or an
// intentional non-full scope may.
func diagnosticOrderingOnly(needs []string, condition string, tolerate any) bool {
	return slices.Equal(needs, []string{"classify", "installer-diagnostics"}) && condition == "${{ !cancelled() && needs.classify.outputs.scope != 'docs' && needs.classify.outputs.scope != 'idle' && needs.classify.outputs.scope != 'cheap' }}" && tolerate == nil
}

// Fairness caps may delay an independent proof behind other jobs purely for
// runner capacity. Such a capacity-only prerequisite must keep the exact
// !cancelled() ordering condition (wantCondition), so a failed or skipped
// predecessor never hides the proof; it must name distinct, existing,
// non-aggregate jobs after the classifier/diagnostics barrier.
func capacityOrderingOnly(jobs map[string]bool, self string, needs []string, wantCondition, condition string, tolerate any) bool {
	if !strings.HasPrefix(wantCondition, "${{ !cancelled() && ") || condition != wantCondition || tolerate != nil {
		return false
	}
	if len(needs) < 2 || !slices.Equal(needs[:2], []string{"classify", "installer-diagnostics"}) {
		return false
	}
	seen := map[string]bool{}
	for _, need := range needs[2:] {
		if seen[need] || !jobs[need] || need == self || need == "classify" || need == "installer-diagnostics" || need == "go-and-policy" {
			return false
		}
		seen[need] = true
	}
	return true
}

// Bulk matrices wait for their closed native foundation set and only launch on
// full-scope runs when every foundation succeeded. The long signed-binary jobs
// remain independent of the native foundations and become eligible after diagnostics.
func bulkFoundationOrderingOnly(needs []string, condition string, tolerate any) bool {
	return slices.Equal(needs, []string{"classify", "installer-diagnostics", "kind-install-gc", "kind-install-admission", "kind-install-admission-v3", "kind-install-auth", "kind-install-baseline", "kind-install-precontroller"}) && condition == "${{ success() && needs.classify.outputs.scope != 'docs' && needs.classify.outputs.scope != 'idle' && needs.classify.outputs.scope != 'cheap' }}" && tolerate == nil
}

// envtest waits on all eight foundations plus go-policy-checks as a capacity
// edge, using !cancelled() and explicit foundation result == 'success' checks
// so a Go/policy failure never skips envtest.
func envtestFoundationAndPolicyCapacityOrdering(needs []string, condition string, tolerate any) bool {
	const wantIf = "${{ !cancelled() && needs.classify.result == 'success' && needs.installer-diagnostics.result == 'success' && needs.kind-install-gc.result == 'success' && needs.kind-install-admission.result == 'success' && needs.kind-install-admission-v3.result == 'success' && needs.kind-install-auth.result == 'success' && needs.kind-install-baseline.result == 'success' && needs.kind-install-precontroller.result == 'success' && needs.classify.outputs.scope != 'docs' && needs.classify.outputs.scope != 'idle' && needs.classify.outputs.scope != 'cheap' }}"
	return slices.Equal(needs, []string{"classify", "installer-diagnostics", "kind-install-gc", "kind-install-admission", "kind-install-admission-v3", "kind-install-auth", "kind-install-baseline", "kind-install-precontroller", "go-policy-checks"}) && strings.Join(strings.Fields(condition), " ") == wantIf && tolerate == nil
}

// Go and policy checks must start right after classify and installer-diagnostics
// and never depend on envtest, Kind or race jobs directly or transitively.
func policyIndependentOfEnvtestAndHeavy(needsByJob map[string][]string) bool {
	if !slices.Equal(needsByJob["go-policy-checks"], []string{"classify", "installer-diagnostics"}) {
		return false
	}
	seen := map[string]bool{}
	var queue []string
	for _, n := range needsByJob["go-policy-checks"] {
		seen[n] = true
		queue = append(queue, n)
	}
	for i := 0; i < len(queue); i++ {
		for _, n := range needsByJob[queue[i]] {
			if !seen[n] {
				seen[n] = true
				queue = append(queue, n)
			}
		}
	}
	return !seen["envtest"] && len(seen) == 2 && seen["classify"] && seen["installer-diagnostics"]
}

// Diagnostics and classification must succeed in full scope before spending the
// signed lifecycle budget. No failure tolerance may bypass needs-success behavior.
func binaryDiagnosticsPrerequisite(needs []string, condition string, tolerate any) bool {
	return slices.Equal(needs, []string{"classify", "installer-diagnostics"}) && condition == "${{ success() && needs.classify.outputs.scope != 'docs' && needs.classify.outputs.scope != 'idle' && needs.classify.outputs.scope != 'cheap' }}" && tolerate == nil
}

func TestInstallerAdmissionCIProfilesAndFailClosedRequiredGate(t *testing.T) {
	body, err := os.ReadFile("../../.github/workflows/ci.yml")
	if err != nil {
		t.Fatal("CI source unavailable")
	}
	var workflow struct {
		Jobs map[string]struct {
			Name            string            `yaml:"name"`
			RunsOn          string            `yaml:"runs-on"`
			If              string            `yaml:"if"`
			ContinueOnError any               `yaml:"continue-on-error"`
			Needs           []string          `yaml:"needs"`
			TimeoutMinutes  any               `yaml:"timeout-minutes"`
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
	// Identical PR-merge/head trees do not have identical source SHA/epoch.
	// Signed packages, image revision labels and lifecycle evidence must use
	// the requested head (or exact main push), not a synthetic merge identity.
	for _, name := range []string{"classify", "installer-diagnostics", "kind-install-binary", "kind-install-baseline", "kind-install-gc", "kind-install-precontroller", "kind-install-admission", "kind-install-admission-v3", "kind-install-auth", "kind-api", "kind-recovery", "install-engine-race", "envtest", "go-policy-checks", "go-and-policy", "kind-lifecycle"} {
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
	jobNames := map[string]bool{}
	for name := range workflow.Jobs {
		jobNames[name] = true
	}
	for _, name := range []string{"kind-install-baseline", "kind-install-gc", "kind-install-precontroller", "kind-install-auth"} {
		job := workflow.Jobs[name]
		if !diagnosticOrderingOnly(job.Needs, job.If, job.ContinueOnError) {
			t.Fatalf("CI job %s competes with early diagnostics or skips independent coverage after their failure", name)
		}
	}
	// Fairness caps (<= 10 concurrent hosted jobs per run) may serialize these
	// proofs behind other jobs, but only with !cancelled(): an unrelated earlier
	// failure or skip must never hide them.
	nativeCondition := "${{ !cancelled() && needs.classify.outputs.scope != 'docs' && needs.classify.outputs.scope != 'idle' && needs.classify.outputs.scope != 'cheap' }}"
	for _, name := range []string{"kind-install-admission", "kind-install-admission-v3", "kind-api", "kind-recovery", "kind-lifecycle"} {
		job := workflow.Jobs[name]
		if !capacityOrderingOnly(jobNames, name, job.Needs, nativeCondition, job.If, job.ContinueOnError) {
			t.Fatalf("CI job %s skips independent coverage after an unrelated capacity predecessor fails", name)
		}
	}
	capacityNeeds := []string{"classify", "installer-diagnostics", "envtest"}
	if !capacityOrderingOnly(jobNames, "kind-recovery", capacityNeeds, nativeCondition, nativeCondition, nil) || !capacityOrderingOnly(jobNames, "kind-api", capacityNeeds, nativeCondition, nativeCondition, nil) || !capacityOrderingOnly(jobNames, "kind-install-baseline", []string{"classify", "installer-diagnostics"}, nativeCondition, nativeCondition, nil) {
		t.Fatal("capacity ordering positive control refused")
	}
	for _, bad := range []struct {
		self      string
		needs     []string
		want      string
		condition string
		tolerate  any
	}{
		{"kind-recovery", capacityNeeds, nativeCondition, "${{ success() && needs.classify.outputs.scope != 'docs' && needs.classify.outputs.scope != 'idle' && needs.classify.outputs.scope != 'cheap' }}", nil},
		{"kind-recovery", capacityNeeds, nativeCondition, "", nil},
		{"kind-recovery", capacityNeeds, nativeCondition, "${{ always() }}", nil},
		{"kind-recovery", capacityNeeds, nativeCondition, "${{ !cancelled() }}", nil},
		{"kind-recovery", capacityNeeds, "${{ success() && needs.classify.outputs.scope != 'docs' }}", "${{ success() && needs.classify.outputs.scope != 'docs' }}", nil},
		{"kind-recovery", capacityNeeds, nativeCondition, nativeCondition, true},
		{"kind-recovery", capacityNeeds, nativeCondition, nativeCondition, "${{ true }}"},
		{"kind-recovery", []string{"installer-diagnostics", "classify", "envtest"}, nativeCondition, nativeCondition, nil},
		{"kind-recovery", []string{"classify", "envtest"}, nativeCondition, nativeCondition, nil},
		{"kind-recovery", nil, nativeCondition, nativeCondition, nil},
		{"kind-recovery", []string{"classify", "installer-diagnostics", "envtest", "envtest"}, nativeCondition, nativeCondition, nil},
		{"kind-recovery", []string{"classify", "installer-diagnostics", "kind-recovery"}, nativeCondition, nativeCondition, nil},
		{"kind-recovery", []string{"classify", "installer-diagnostics", "go-and-policy"}, nativeCondition, nativeCondition, nil},
		{"kind-recovery", []string{"classify", "installer-diagnostics", "unrelated"}, nativeCondition, nativeCondition, nil},
		{"kind-recovery", []string{"classify", "installer-diagnostics", "classify"}, nativeCondition, nativeCondition, nil},
	} {
		if capacityOrderingOnly(jobNames, bad.self, bad.needs, bad.want, bad.condition, bad.tolerate) {
			t.Fatal("unsafe capacity-only ordering accepted", bad.needs, bad.condition)
		}
	}
	if raceJob := workflow.Jobs["install-engine-race"]; !bulkFoundationOrderingOnly(raceJob.Needs, raceJob.If, raceJob.ContinueOnError) {
		t.Fatal("bulk matrix bypasses foundations or skips independent coverage on failure", "install-engine-race")
	}
	if envtestJob := workflow.Jobs["envtest"]; !envtestFoundationAndPolicyCapacityOrdering(envtestJob.Needs, envtestJob.If, envtestJob.ContinueOnError) {
		t.Fatal("envtest matrix bypasses foundations, omits go-policy-checks capacity edge or skips on Go/policy failure")
	}
	// Literal independent oracle, not copied from another job's mutable DAG.
	bulkNeeds := []string{"classify", "installer-diagnostics", "kind-install-gc", "kind-install-admission", "kind-install-admission-v3", "kind-install-auth", "kind-install-baseline", "kind-install-precontroller"}
	bulkCondition := "${{ success() && needs.classify.outputs.scope != 'docs' && needs.classify.outputs.scope != 'idle' && needs.classify.outputs.scope != 'cheap' }}"
	envtestNeeds := []string{"classify", "installer-diagnostics", "kind-install-gc", "kind-install-admission", "kind-install-admission-v3", "kind-install-auth", "kind-install-baseline", "kind-install-precontroller", "go-policy-checks"}
	envtestCondition := "${{ !cancelled() && needs.classify.result == 'success' && needs.installer-diagnostics.result == 'success' && needs.kind-install-gc.result == 'success' && needs.kind-install-admission.result == 'success' && needs.kind-install-admission-v3.result == 'success' && needs.kind-install-auth.result == 'success' && needs.kind-install-baseline.result == 'success' && needs.kind-install-precontroller.result == 'success' && needs.classify.outputs.scope != 'docs' && needs.classify.outputs.scope != 'idle' && needs.classify.outputs.scope != 'cheap' }}"
	if !bulkFoundationOrderingOnly(bulkNeeds, bulkCondition, nil) || !envtestFoundationAndPolicyCapacityOrdering(envtestNeeds, envtestCondition, nil) {
		t.Fatal("bulk ordering-only positive control refused")
	}
	for index := range envtestNeeds {
		if envtestFoundationAndPolicyCapacityOrdering(slices.Delete(slices.Clone(envtestNeeds), index, index+1), envtestCondition, nil) {
			t.Fatal("envtest ordering accepted an omitted foundation or missing policy capacity edge", index)
		}
	}
	for _, extra := range []string{"unrelated", "classify", "go-policy-checks", "envtest", "install-engine-race", "kind-install-binary", "go-and-policy"} {
		if envtestFoundationAndPolicyCapacityOrdering(append(slices.Clone(envtestNeeds), extra), envtestCondition, nil) {
			t.Fatal("envtest ordering accepted an extra, duplicate, self or sibling dependency", extra)
		}
	}
	for _, badEnvtestCond := range []string{
		"",
		bulkCondition,
		"${{ !cancelled() && needs.classify.outputs.scope != 'docs' && needs.classify.outputs.scope != 'idle' && needs.classify.outputs.scope != 'cheap' }}",
		strings.Replace(envtestCondition, "needs.kind-install-precontroller.result == 'success' &&", "needs.kind-install-precontroller.result == 'success' && needs.go-policy-checks.result == 'success' &&", 1),
		strings.Replace(envtestCondition, "needs.kind-install-gc.result == 'success' && ", "", 1),
		strings.Replace(envtestCondition, "!cancelled()", "success()", 1),
	} {
		if envtestFoundationAndPolicyCapacityOrdering(envtestNeeds, badEnvtestCond, nil) {
			t.Fatal("envtest ordering accepted a condition that skips on policy failure or omits a foundation check", badEnvtestCond)
		}
	}
	for _, tolerate := range []any{true, "${{ true }}"} {
		if envtestFoundationAndPolicyCapacityOrdering(envtestNeeds, envtestCondition, tolerate) {
			t.Fatal("envtest ordering tolerated failure")
		}
	}
	for index := range bulkNeeds {
		if bulkFoundationOrderingOnly(slices.Delete(slices.Clone(bulkNeeds), index, index+1), bulkCondition, nil) {
			t.Fatal("bulk ordering accepted an omitted foundation", index)
		}
	}
	for _, extra := range []string{"unrelated", "classify", "installer-diagnostics", "install-engine-race", "envtest", "kind-install-binary", "go-and-policy"} {
		if bulkFoundationOrderingOnly(append(slices.Clone(bulkNeeds), extra), bulkCondition, nil) {
			t.Fatal("bulk ordering accepted an extra, duplicate, self or sibling dependency", extra)
		}
	}
	reordered := slices.Clone(bulkNeeds)
	reordered[0], reordered[1] = reordered[1], reordered[0]
	if bulkFoundationOrderingOnly(reordered, bulkCondition, nil) || bulkFoundationOrderingOnly(nil, bulkCondition, nil) {
		t.Fatal("bulk ordering accepted a substituted or missing dependency list")
	}
	for _, condition := range []string{"", "${{ !cancelled() }}", "${{ !cancelled() && needs.classify.outputs.scope != 'docs' && needs.classify.outputs.scope != 'idle' && needs.classify.outputs.scope != 'cheap' }}", "${{ success() }}", "${{ always() }}", "${{ failure() }}"} {
		if bulkFoundationOrderingOnly(bulkNeeds, condition, nil) {
			t.Fatal("bulk ordering accepted a skip/bypass condition", condition)
		}
	}
	for _, tolerate := range []any{true, "${{ true }}"} {
		if bulkFoundationOrderingOnly(bulkNeeds, bulkCondition, tolerate) {
			t.Fatal("bulk ordering tolerated failure")
		}
	}
	diagNeeds := []string{"classify", "installer-diagnostics"}
	diagCondition := "${{ !cancelled() && needs.classify.outputs.scope != 'docs' && needs.classify.outputs.scope != 'idle' && needs.classify.outputs.scope != 'cheap' }}"
	if !diagnosticOrderingOnly(diagNeeds, diagCondition, nil) {
		t.Fatal("ordering-only positive control refused")
	}
	for _, bad := range []struct {
		needs     []string
		condition string
		tolerate  any
	}{
		{nil, diagCondition, nil},
		{[]string{"installer-diagnostics"}, diagCondition, nil},
		{[]string{"installer-diagnostics"}, "${{ !cancelled() }}", nil},
		{[]string{"classify", "installer-diagnostics", "go-and-policy"}, diagCondition, nil},
		{[]string{"go-and-policy", "installer-diagnostics"}, diagCondition, nil},
		{[]string{"installer-diagnostics", "classify"}, diagCondition, nil},
		{[]string{"install-engine-race"}, diagCondition, nil},
		{diagNeeds, "", nil},
		{diagNeeds, "${{ !cancelled() }}", nil},
		{diagNeeds, "${{ !cancelled() && needs.classify.outputs.scope != 'docs' && needs.classify.outputs.scope != 'idle' }}", nil},
		{diagNeeds, "${{ success() }}", nil},
		{diagNeeds, "${{ always() }}", nil},
		{diagNeeds, diagCondition, true},
		{diagNeeds, diagCondition, "${{ true }}"},
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
	// max-parallel bounds concurrency only (every shard still runs); the
	// exact per-run <= 10 hosted-job arithmetic lives in hack/workflowpolicy.
	if races.TimeoutMinutes != 30 || races.Strategy.FailFast == nil || *races.Strategy.FailFast || races.Strategy.MaxParallel < 1 || races.Env["GOMAXPROCS"] != "2" || races.Env["GOMEMLIMIT"] != "1GiB" {
		t.Fatal("race workers changed their bounded budgets or cancelled sibling coverage")
	}
	raceRun := false
	for _, step := range races.Steps {
		raceRun = raceRun || step.Run == "bash ./hack/test-installengine-race-shard.sh '${{ matrix.shard }}'"
	}
	if !raceRun {
		t.Fatal("CI does not execute its assigned compiled race test trees")
	}
	if admission.TimeoutMinutes != "${{ matrix.mode == 'warm' && 30 || 25 }}" || !slices.Equal(admission.Strategy.Matrix.Profile, []int{135, 137}) || !slices.Equal(admission.Strategy.Matrix.Mode, []string{"cold", "warm"}) {
		t.Fatal("full native admission profile/mode omitted")
	}
	fullRun := false
	for _, step := range admission.Steps {
		fullRun = fullRun || step.Run == "make test-kind-install-admission INSTALL_ADMISSION_PROFILE='${{ matrix.profile }}' INSTALL_ADMISSION_MODE='${{ matrix.mode }}'"
	}
	gate := workflow.Jobs["go-and-policy"]
	if !slices.Equal(gate.Needs, []string{"classify", "installer-diagnostics", "install-engine-race", "kind-install-admission", "kind-install-admission-v3", "kind-install-binary", "kind-install-baseline", "kind-install-gc", "kind-install-precontroller", "kind-install-auth", "kind-api", "kind-recovery", "envtest", "kind-lifecycle", "go-policy-checks"}) || gate.ContinueOnError != nil {
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
	needsByJob := map[string][]string{}
	for name, job := range workflow.Jobs {
		needsByJob[name] = slices.Clone(job.Needs)
	}
	if !policyIndependentOfEnvtestAndHeavy(needsByJob) {
		t.Fatal("Go/policy must not depend on envtest, Kind or race jobs directly or transitively")
	}
	for _, badPolicyGraph := range []map[string][]string{
		{"classify": nil, "installer-diagnostics": {"classify"}, "go-policy-checks": {"classify", "installer-diagnostics", "envtest"}},
		{"classify": nil, "installer-diagnostics": {"classify"}, "kind-recovery": {"classify", "installer-diagnostics", "envtest"}, "go-policy-checks": {"classify", "installer-diagnostics", "kind-recovery"}},
		{"classify": nil, "installer-diagnostics": {"classify", "envtest"}, "go-policy-checks": {"classify", "installer-diagnostics"}},
		{"classify": nil, "installer-diagnostics": {"classify"}, "go-policy-checks": {"classify", "installer-diagnostics", "kind-install-gc"}},
		{"classify": nil, "installer-diagnostics": {"classify"}, "go-policy-checks": {"classify", "installer-diagnostics", "install-engine-race"}},
	} {
		if policyIndependentOfEnvtestAndHeavy(badPolicyGraph) {
			t.Fatal("Go/policy must not depend on envtest, Kind or race jobs directly or transitively")
		}
	}
	if checks.Name != "Go and policy checks" || checks.RunsOn != "ubuntu-24.04" || !slices.Equal(checks.Needs, []string{"classify", "installer-diagnostics"}) || checks.If != "${{ !cancelled() && needs.classify.outputs.scope != 'docs' && needs.classify.outputs.scope != 'idle' }}" || checks.ContinueOnError != nil || checks.TimeoutMinutes != 35 || len(checks.Env) != 2 || checks.Env["GOMAXPROCS"] != "2" || checks.Env["GOMEMLIMIT"] != "1GiB" || len(checks.Steps) != 12 {
		t.Fatal("independent policy checks changed their runner, budget, environment or complete step set")
	}
	if checks.Steps[0].Uses != "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1" || len(checks.Steps[0].With) != 1 || checks.Steps[1].Uses != "actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e" || checks.Steps[1].With["go-version-file"] != "go.mod" || checks.Steps[1].With["cache"] != false || len(checks.Steps[1].With) != 2 || checks.Steps[2].Uses != "actions/cache/restore@0057852bfaa89a56745cba8c7296529d2fc39830" || checks.Steps[11].Uses != "actions/cache/save@0057852bfaa89a56745cba8c7296529d2fc39830" || checks.Steps[11].If != "${{ success() && github.ref == 'refs/heads/main' && (github.event_name == 'push' || github.event_name == 'schedule') && steps.go-cache.outputs.cache-hit != 'true' }}" || checks.Steps[11].With["key"] != "${{ steps.go-cache.outputs.cache-primary-key }}" {
		t.Fatal("independent policy checks changed pinned checkout, Go setup or main-only cache ownership")
	}
	for index, step := range checks.Steps {
		if index < 11 && step.If != "" || step.ContinueOnError != nil || len(step.Env) != 0 || (index < 3 || index == 11) && step.Run != "" || index >= 3 && index < 11 && (step.Run != wantPolicyRuns[index-3] || step.Uses != "" || len(step.With) != 0) {
			t.Fatal("moved policy commands changed, became conditional or tolerated failures", index)
		}
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
	if diagnostics.If != "${{ !cancelled() && needs.classify.outputs.scope != 'docs' && needs.classify.outputs.scope != 'idle' }}" || diagnostics.ContinueOnError != nil || !slices.Equal(diagnostics.Needs, []string{"classify"}) || diagnostics.TimeoutMinutes != 20 || diagnostics.Env["GOMAXPROCS"] != "2" || diagnostics.Env["GOMEMLIMIT"] != "1GiB" || !slices.Equal(diagnosticRuns, wantDiagnosticRuns) || !slices.Contains(gate.Needs, "installer-diagnostics") || len(diagnostics.Steps) != 10 {
		t.Fatal("early CLI/diagnostic controls are missing, unbounded or gated behind native lifecycle")
	}
	if diagnostics.Steps[0].Uses != "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1" || diagnostics.Steps[1].Uses != "actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e" || diagnostics.Steps[1].With["go-version-file"] != "go.mod" || diagnostics.Steps[1].With["cache"] != false || diagnostics.Steps[2].Uses != "actions/cache/restore@0057852bfaa89a56745cba8c7296529d2fc39830" {
		t.Fatal("early diagnostics changed pinned source/build setup")
	}
	baseline := workflow.Jobs["kind-install-baseline"]
	baselineRun := false
	for _, step := range baseline.Steps {
		baselineRun = baselineRun || step.Run == "make test-kind-install-baseline INSTALL_BASELINE_PROFILE='${{ matrix.profile }}'"
	}
	if !baselineRun || baseline.TimeoutMinutes != 20 || baseline.Strategy.FailFast == nil || *baseline.Strategy.FailFast || !slices.Equal(baseline.Strategy.Matrix.Profile, []int{135, 137}) || len(baseline.Strategy.Matrix.Exclude) != 0 || len(baseline.Strategy.Matrix.Mode) != 0 || !slices.Contains(gate.Needs, "kind-install-baseline") {
		t.Fatal("native baseline profile or fail-closed dependency omitted")
	}
	envtest := workflow.Jobs["envtest"]
	wantEnvtestParts := []string{"base-packages"}
	for i := range 32 {
		wantEnvtestParts = append(wantEnvtestParts, strconv.Itoa(i))
	}
	if !slices.Equal(envtest.Strategy.Matrix.Part, wantEnvtestParts) || len(envtest.Strategy.Matrix.Exclude) != 0 || len(envtest.Strategy.Matrix.Shard) != 0 || len(envtest.Strategy.Matrix.Mode) != 0 || len(envtest.Strategy.Matrix.Profile) != 0 || envtest.Strategy.FailFast == nil || *envtest.Strategy.FailFast || envtest.Strategy.MaxParallel < 1 {
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
	if len(envtest.Steps) != 4 || envtest.TimeoutMinutes != 20 || envtest.Env["GOMAXPROCS"] != "2" || envtest.Env["GOMEMLIMIT"] != "1GiB" {
		t.Fatal("complete API-server suite lacks its independent bounded job")
	}
	for _, step := range envtest.Steps {
		if step.If != "" || step.ContinueOnError != nil || len(step.Env) != 0 {
			t.Fatal("complete API-server suite can skip, tolerate failure or override its environment")
		}
	}
	if envtest.Steps[0].Uses != "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1" || envtest.Steps[1].Uses != "actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e" || envtest.Steps[1].With["go-version-file"] != "go.mod" || envtest.Steps[1].With["cache"] != false || envtest.Steps[2].Uses != "actions/cache/restore@0057852bfaa89a56745cba8c7296529d2fc39830" || envtest.Steps[3].Run != wantEnvtestRun || nativeSuiteRuns != 1 {
		t.Fatal("complete API-server suite changed pinned setup or fresh full-suite execution")
	}
	makefile, err := os.ReadFile("../../Makefile")
	if err != nil || strings.Count(string(makefile), "GOMAXPROCS=2 GOMEMLIMIT=1GiB bash ./hack/test-envtest-part.sh --all") != 1 || strings.Count(string(makefile), "GOMAXPROCS=2 GOMEMLIMIT=1GiB bash ./hack/test-envtest-part.sh \"$(ENVTEST_PART)\"") != 1 || gate.TimeoutMinutes != 40 {
		t.Fatal("complete fresh API-server suite or its bounded CI envelope changed")
	}
	gc := workflow.Jobs["kind-install-gc"]
	gcRuns := 0
	for _, step := range gc.Steps {
		if step.Run == "make test-kind-install-gc" {
			gcRuns++
		}
	}
	if gcRuns != 1 || gc.TimeoutMinutes != 20 || len(gc.Strategy.Matrix.Profile) != 0 || len(gc.Strategy.Matrix.Mode) != 0 || len(gc.Strategy.Matrix.Exclude) != 0 || !slices.Contains(gate.Needs, "kind-install-gc") || strings.Count(string(makefile), "GOMAXPROCS=2 GOMEMLIMIT=1GiB go test -tags=kindinstall -p 1 -timeout=24m -v ./internal/installengine -run '^TestKindBaselineNativeForegroundGarbageCollection$$' -count=1") != 1 {
		t.Fatal("native foreground GC proof or fail-closed dependency omitted")
	}
	precontroller := workflow.Jobs["kind-install-precontroller"]
	precontrollerRun := false
	for _, step := range precontroller.Steps {
		precontrollerRun = precontrollerRun || step.Run == "make test-kind-install-precontroller INSTALL_PRECONTROLLER_PROFILE='${{ matrix.profile }}'"
	}
	if !precontrollerRun || precontroller.TimeoutMinutes != "${{ matrix.profile == 135 && 30 || 35 }}" || precontroller.Strategy.FailFast == nil || *precontroller.Strategy.FailFast || !slices.Equal(precontroller.Strategy.Matrix.Profile, []int{135, 137}) || len(precontroller.Strategy.Matrix.Exclude) != 0 || len(precontroller.Strategy.Matrix.Mode) != 0 || !slices.Contains(gate.Needs, "kind-install-precontroller") || !strings.Contains(string(makefile), "^TestKindBaselinePrecontrollerRuntimeNative$$/") {
		t.Fatal("genuine pre-controller profile or required dependency omitted")
	}
	binary := workflow.Jobs["kind-install-binary"]
	if !binaryDiagnosticsPrerequisite(binary.Needs, binary.If, binary.ContinueOnError) {
		t.Fatal("long signed lifecycle proofs delay independent work or bypass successful diagnostics")
	}
	if !binaryDiagnosticsPrerequisite(diagNeeds, bulkCondition, nil) {
		t.Fatal("binary diagnostics-success positive control refused")
	}
	for _, needs := range [][]string{nil, {}, {"installer-diagnostics"}, {"kind-install-gc"}, {"classify", "installer-diagnostics", "installer-diagnostics"}, {"classify", "installer-diagnostics", "kind-install-binary"}, {"classify", "installer-diagnostics", "go-and-policy"}} {
		if binaryDiagnosticsPrerequisite(needs, bulkCondition, nil) {
			t.Fatal("binary scheduling accepted missing, substituted, duplicate or cyclic prerequisites")
		}
	}
	for _, foundation := range bulkNeeds[2:] {
		if binaryDiagnosticsPrerequisite([]string{"classify", "installer-diagnostics", foundation}, bulkCondition, nil) {
			t.Fatal("binary scheduling delayed independent lifecycle work behind a native foundation", foundation)
		}
	}
	for _, condition := range []string{"", "${{ !cancelled() }}", diagCondition, "${{ always() }}", "${{ failure() }}", "${{ success() }}"} {
		if binaryDiagnosticsPrerequisite(diagNeeds, condition, nil) {
			t.Fatal("binary scheduling accepted a custom diagnostic scheduling condition", condition)
		}
	}
	for _, tolerate := range []any{false, true, "${{ true }}"} {
		if binaryDiagnosticsPrerequisite(diagNeeds, bulkCondition, tolerate) {
			t.Fatal("binary scheduling accepted a failure-tolerance override")
		}
	}
	for _, required := range []struct {
		name    string
		command string
		minutes int
	}{
		{"kind-install-auth", "make test-kind-install-auth", 35},
		{"kind-api", "make test-kind-api", 25},
		{"kind-recovery", "make test-kind-recovery", 90},
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
	if !slices.Equal(workflow.Jobs["kind-api"].Needs, []string{"classify", "installer-diagnostics", "envtest"}) {
		t.Fatal("kind-api must wait on envtest as a capacity edge after classify and installer-diagnostics")
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
	if !v3Run || v3.TimeoutMinutes != "${{ matrix.mode == 'warm' && 30 || 25 }}" || v3.Strategy.FailFast == nil || *v3.Strategy.FailFast || v3.Strategy.MaxParallel != 3 || !slices.Equal(v3.Strategy.Matrix.Profile, []int{135, 137}) || !slices.Equal(v3.Strategy.Matrix.Mode, []string{"cold", "warm"}) || len(v3.Strategy.Matrix.Exclude) != 0 || !slices.Contains(gate.Needs, "kind-install-admission-v3") || !strings.Contains(string(makefile), "^TestKindAdmissionEffectiveV3WithBaseline$$/") {
		t.Fatal("complete baseline-active v3 matrix missing from required CI")
	}
	const wantBinaryRun = `if [[ "$INSTALL_BINARY_MODE" == transition ]]; then
  bash ./hack/ci-no-progress-watchdog.sh 30 "137 transition" \
    make test-kind-install-binary INSTALL_BINARY_PROFILE="$INSTALL_BINARY_PROFILE" INSTALL_BINARY_MODE="$INSTALL_BINARY_MODE"
else
  make test-kind-install-binary INSTALL_BINARY_PROFILE="$INSTALL_BINARY_PROFILE" INSTALL_BINARY_MODE="$INSTALL_BINARY_MODE"
fi`
	binaryRun := false
	binaryHistory := false
	for _, step := range binary.Steps {
		if strings.TrimSpace(step.Run) == wantBinaryRun && step.If == "" && step.ContinueOnError == nil && len(step.Env) == 2 && step.Env["INSTALL_BINARY_PROFILE"] == "${{ matrix.profile }}" && step.Env["INSTALL_BINARY_MODE"] == "${{ matrix.mode }}" {
			binaryRun = true
		}
		if strings.HasPrefix(step.Uses, "actions/checkout@") {
			depth, present := step.With["fetch-depth"]
			binaryHistory = present && depth == 0
		}
	}
	binaryMatrix := binary.Strategy.Matrix
	if !fullRun || !binaryRun || !binaryHistory || binary.TimeoutMinutes != "${{ matrix.mode == 'transition' && 350 || 290 }}" || !slices.Equal(binaryMatrix.Profile, []int{135, 137}) || !slices.Equal(binaryMatrix.Mode, []string{"fresh", "transition"}) || len(binaryMatrix.Exclude) != 1 || binaryMatrix.Exclude[0].Profile != 135 || binaryMatrix.Exclude[0].Mode != "transition" || gate.If != "${{ always() }}" || !slices.Contains(gate.Needs, "install-engine-race") || !slices.Contains(gate.Needs, "kind-install-admission") || !slices.Contains(gate.Needs, "kind-install-binary") {
		t.Fatal("required gate bypasses full native admission or engine races")
	}
	var command string
	for _, step := range gate.Steps {
		if step.Env["CLASSIFY_RESULT"] == "${{ needs.classify.result }}" && step.Env["CI_SCOPE"] == "${{ needs.classify.outputs.scope }}" && step.Env["CI_EVENT_NAME"] == "${{ github.event_name }}" && step.Env["CI_REF"] == "${{ github.ref }}" && step.Env["INSTALLER_DIAGNOSTICS_RESULT"] == "${{ needs.installer-diagnostics.result }}" && step.Env["ENGINE_RACE_RESULT"] == "${{ needs.install-engine-race.result }}" && step.Env["INSTALL_ADMISSION_RESULT"] == "${{ needs.kind-install-admission.result }}" && step.Env["INSTALL_BINARY_RESULT"] == "${{ needs.kind-install-binary.result }}" && step.Env["INSTALL_BASELINE_RESULT"] == "${{ needs.kind-install-baseline.result }}" && step.Env["INSTALL_ADMISSION_V3_RESULT"] == "${{ needs.kind-install-admission-v3.result }}" && step.Env["INSTALL_PRECONTROLLER_RESULT"] == "${{ needs.kind-install-precontroller.result }}" && step.Env["INSTALL_GC_RESULT"] == "${{ needs.kind-install-gc.result }}" && step.Env["INSTALL_AUTH_RESULT"] == "${{ needs.kind-install-auth.result }}" && step.Env["API_RESULT"] == "${{ needs.kind-api.result }}" && step.Env["RECOVERY_RESULT"] == "${{ needs.kind-recovery.result }}" && step.Env["ENVTEST_RESULT"] == "${{ needs.envtest.result }}" && step.Env["LIFECYCLE_RESULT"] == "${{ needs.kind-lifecycle.result }}" && step.Env["GO_POLICY_CHECKS_RESULT"] == "${{ needs.go-policy-checks.result }}" {
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
							c := exec.Command("bash", "-e", "-c", command)
							c.Env = append(os.Environ(), "CI_EVENT_NAME=pull_request", "CI_REF=refs/pull/1/merge", "CLASSIFY_RESULT=success", "CI_SCOPE=full", "INSTALLER_DIAGNOSTICS_RESULT=success", "ENGINE_RACE_RESULT="+races, "INSTALL_ADMISSION_RESULT="+native, "INSTALL_BINARY_RESULT="+binary, "INSTALL_BASELINE_RESULT="+baseline, "INSTALL_ADMISSION_V3_RESULT="+v3, "INSTALL_PRECONTROLLER_RESULT="+precontroller, "INSTALL_GC_RESULT=success", "INSTALL_AUTH_RESULT=success", "API_RESULT=success", "RECOVERY_RESULT=success", "ENVTEST_RESULT=success", "LIFECYCLE_RESULT=success", "GO_POLICY_CHECKS_RESULT=success")
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
		c := exec.Command("bash", "-e", "-c", command)
		c.Env = append(os.Environ(), "CI_EVENT_NAME=pull_request", "CI_REF=refs/pull/1/merge", "CLASSIFY_RESULT=success", "CI_SCOPE=full", "INSTALLER_DIAGNOSTICS_RESULT=success", "ENGINE_RACE_RESULT=success", "INSTALL_ADMISSION_RESULT=success", "INSTALL_BINARY_RESULT=success", "INSTALL_BASELINE_RESULT=success", "INSTALL_ADMISSION_V3_RESULT=success", "INSTALL_PRECONTROLLER_RESULT=success", "INSTALL_GC_RESULT="+result, "INSTALL_AUTH_RESULT=success", "API_RESULT=success", "RECOVERY_RESULT=success", "ENVTEST_RESULT=success", "LIFECYCLE_RESULT=success", "GO_POLICY_CHECKS_RESULT=success")
		if passed := c.Run() == nil; passed != (result == "success") {
			t.Fatal("failed/cancelled/skipped/absent GC proof became a green required gate")
		}
	}
	// Independently exercise every added prerequisite outcome while the others
	// succeed, preserving all original combinations without multiplying them.
	added := []string{"CLASSIFY_RESULT", "INSTALL_AUTH_RESULT", "API_RESULT", "RECOVERY_RESULT", "INSTALLER_DIAGNOSTICS_RESULT", "ENVTEST_RESULT", "LIFECYCLE_RESULT", "GO_POLICY_CHECKS_RESULT"}
	for _, variable := range added {
		for _, result := range []string{"success", "failure", "cancelled", "skipped", ""} {
			c := exec.Command("bash", "-e", "-c", command)
			c.Env = append(os.Environ(), "CI_EVENT_NAME=pull_request", "CI_REF=refs/pull/1/merge", "CI_SCOPE=full", "ENGINE_RACE_RESULT=success", "INSTALL_ADMISSION_RESULT=success", "INSTALL_BINARY_RESULT=success", "INSTALL_BASELINE_RESULT=success", "INSTALL_ADMISSION_V3_RESULT=success", "INSTALL_PRECONTROLLER_RESULT=success", "INSTALL_GC_RESULT=success")
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
	heavyVars := []string{"ENGINE_RACE_RESULT", "INSTALL_ADMISSION_RESULT", "INSTALL_BINARY_RESULT", "INSTALL_BASELINE_RESULT", "INSTALL_GC_RESULT", "INSTALL_ADMISSION_V3_RESULT", "INSTALL_PRECONTROLLER_RESULT", "INSTALL_AUTH_RESULT", "API_RESULT", "RECOVERY_RESULT", "ENVTEST_RESULT", "LIFECYCLE_RESULT"}
	allProofVars := append([]string{"INSTALLER_DIAGNOSTICS_RESULT", "GO_POLICY_CHECKS_RESULT"}, heavyVars...)
	scopeEvent := map[string]string{"docs": "pull_request", "idle": "schedule"}
	for _, invalidScope := range []string{"", "unknown", "pr"} {
		for _, fill := range []string{"success", "skipped"} {
			c := exec.Command("bash", "-e", "-c", command)
			c.Env = append(os.Environ(), "CI_EVENT_NAME=push", "CI_REF=refs/heads/main", "CLASSIFY_RESULT=success", "CI_SCOPE="+invalidScope)
			for _, v := range allProofVars {
				c.Env = append(c.Env, v+"="+fill)
			}
			if c.Run() == nil {
				t.Fatalf("invalid or missing CI_SCOPE %q became a green required gate", invalidScope)
			}
		}
	}
	for _, variable := range append([]string{"CLASSIFY_RESULT"}, allProofVars...) {
		for _, result := range []string{"success", "failure", "cancelled", "skipped", ""} {
			c := exec.Command("bash", "-e", "-c", command)
			c.Env = append(os.Environ(), "CI_EVENT_NAME=push", "CI_REF=refs/heads/main", "CI_SCOPE=cheap")
			for _, other := range append([]string{"CLASSIFY_RESULT"}, allProofVars...) {
				value := "skipped"
				if other == "CLASSIFY_RESULT" || other == "INSTALLER_DIAGNOSTICS_RESULT" || other == "GO_POLICY_CHECKS_RESULT" {
					value = "success"
				}
				if other == variable {
					value = result
				}
				c.Env = append(c.Env, other+"="+value)
			}
			wantPass := result == "skipped"
			if variable == "CLASSIFY_RESULT" || variable == "INSTALLER_DIAGNOSTICS_RESULT" || variable == "GO_POLICY_CHECKS_RESULT" {
				wantPass = result == "success"
			}
			if passed := c.Run() == nil; passed != wantPass {
				t.Fatalf("unexpected cheap-scope gate outcome for %s=%s", variable, result)
			}
		}
	}
	for _, scope := range []string{"docs", "idle"} {
		for _, variable := range append([]string{"CLASSIFY_RESULT"}, allProofVars...) {
			for _, result := range []string{"success", "failure", "cancelled", "skipped", ""} {
				c := exec.Command("bash", "-e", "-c", command)
				c.Env = append(os.Environ(), "CI_EVENT_NAME="+scopeEvent[scope], "CI_REF=refs/heads/main", "CI_SCOPE="+scope)
				for _, other := range append([]string{"CLASSIFY_RESULT"}, allProofVars...) {
					value := "skipped"
					if other == "CLASSIFY_RESULT" {
						value = "success"
					}
					if other == variable {
						value = result
					}
					c.Env = append(c.Env, other+"="+value)
				}
				wantPass := result == "skipped"
				if variable == "CLASSIFY_RESULT" {
					wantPass = result == "success"
				}
				if passed := c.Run() == nil; passed != wantPass {
					t.Fatalf("unexpected %s-scope gate outcome for %s=%s", scope, variable, result)
				}
			}
		}
	}
	// A reduced scope is only legitimate for the event that can produce it:
	// cheap = push to main, idle = schedule on main, docs = pull_request or
	// push to main. Any other event/ref pair must turn the gate red even when
	// every result matches that scope; full has no event restriction.
	scopeResults := func(scope string) []string {
		env := []string{"CLASSIFY_RESULT=success", "CI_SCOPE=" + scope}
		for _, v := range allProofVars {
			value := "skipped"
			if scope == "full" || scope == "cheap" && (v == "INSTALLER_DIAGNOSTICS_RESULT" || v == "GO_POLICY_CHECKS_RESULT") {
				value = "success"
			}
			env = append(env, v+"="+value)
		}
		return env
	}
	type eventRef struct{ event, ref string }
	pairs := []eventRef{
		{"pull_request", "refs/pull/1/merge"}, {"pull_request", "refs/heads/main"},
		{"push", "refs/heads/main"}, {"push", "refs/heads/topic"}, {"push", "refs/tags/v1.0.0"}, {"push", ""}, {"push", "refs/heads/main "},
		{"schedule", "refs/heads/main"}, {"schedule", "refs/heads/topic"}, {"schedule", ""},
		{"workflow_dispatch", "refs/heads/main"}, {"workflow_dispatch", "refs/heads/topic"},
		{"pull_request_target", "refs/heads/main"}, {"merge_group", "refs/heads/main"}, {"PUSH", "refs/heads/main"}, {"", "refs/heads/main"}, {"", ""},
	}
	valid := map[string][]eventRef{
		"cheap": {{"push", "refs/heads/main"}},
		"idle":  {{"schedule", "refs/heads/main"}},
		"docs":  {{"pull_request", "refs/pull/1/merge"}, {"pull_request", "refs/heads/main"}, {"push", "refs/heads/main"}},
	}
	for _, scope := range []string{"cheap", "idle", "docs"} {
		for _, pair := range pairs {
			c := exec.Command("bash", "-e", "-c", command)
			c.Env = append(append(os.Environ(), "CI_EVENT_NAME="+pair.event, "CI_REF="+pair.ref), scopeResults(scope)...)
			if passed, wantPass := c.Run() == nil, slices.Contains(valid[scope], pair); passed != wantPass {
				t.Fatalf("%s scope with event %q ref %q: gate passed=%v, want %v", scope, pair.event, pair.ref, passed, wantPass)
			}
		}
	}
	for _, pair := range []eventRef{{"pull_request", "refs/pull/1/merge"}, {"push", "refs/heads/main"}, {"schedule", "refs/heads/main"}, {"workflow_dispatch", "refs/heads/topic"}} {
		c := exec.Command("bash", "-e", "-c", command)
		c.Env = append(append(os.Environ(), "CI_EVENT_NAME="+pair.event, "CI_REF="+pair.ref), scopeResults("full")...)
		if c.Run() != nil {
			t.Fatalf("full scope with every proof green must pass on event %q ref %q", pair.event, pair.ref)
		}
	}
}
