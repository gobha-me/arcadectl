// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
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

// Shared images are a real artifact prerequisite. Diagnostic failure still
// permits independent native coverage when the image producer succeeds.
func nativeImagePrerequisites(needs []string, condition string, tolerate any) bool {
	return slices.Equal(needs, []string{"installer-diagnostics", "kind-images"}) && condition == "${{ !cancelled() && needs.kind-images.result == 'success' }}" && tolerate == nil
}

// Unlike the ordering-only bulk barrier, diagnostics must actually succeed
// before spending the signed lifecycle budget. No custom condition or failure
// tolerance may bypass the default GitHub needs-success behavior.
func binaryDiagnosticsPrerequisite(needs []string, condition string, tolerate any) bool {
	return slices.Equal(needs, []string{"installer-diagnostics", "kind-images"}) && condition == "" && tolerate == nil
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
			TimeoutMinutes  int               `yaml:"timeout-minutes"`
			Env             map[string]string `yaml:"env"`
			Strategy        struct {
				FailFast    *bool `yaml:"fail-fast"`
				MaxParallel int   `yaml:"max-parallel"`
				Matrix      struct {
					Shard   []int    `yaml:"shard"`
					Part    []string `yaml:"part"`
					Check   []string `yaml:"check"`
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
	originalJobs := []string{"installer-diagnostics", "kind-install-binary", "kind-install-baseline", "kind-install-gc", "kind-install-precontroller", "kind-install-admission", "kind-install-admission-v3", "kind-install-auth", "kind-api", "kind-recovery", "install-engine-race", "envtest", "go-policy-checks", "go-and-policy", "kind-lifecycle"}
	for _, name := range originalJobs {
		if _, present := workflow.Jobs[name]; !present {
			t.Errorf("original CI job family %s is absent", name)
		}
	}
	if _, present := workflow.Jobs["kind-images"]; !present {
		t.Error("required exact-source CI job kind-images is absent")
	}
	if len(workflow.Jobs) != len(originalJobs)+1 {
		t.Errorf("unexpected CI job count: got %d, want %d", len(workflow.Jobs), len(originalJobs)+1)
	}
	wantTimeouts := map[string]int{
		"installer-diagnostics":      20,
		"kind-images":                20,
		"kind-install-binary":        350,
		"kind-install-baseline":      30,
		"kind-install-gc":            30,
		"kind-install-precontroller": 40,
		"kind-install-admission":     50,
		"kind-install-admission-v3":  50,
		"kind-install-auth":          50,
		"kind-api":                   40,
		"kind-recovery":              100,
		"install-engine-race":        30,
		"envtest":                    45,
		"go-policy-checks":           45,
		"go-and-policy":              45,
		"kind-lifecycle":             45,
	}
	for name, wantTimeout := range wantTimeouts {
		if job, present := workflow.Jobs[name]; present && job.TimeoutMinutes != wantTimeout {
			t.Errorf("CI job %s changed timeout-minutes: got %d, want %d", name, job.TimeoutMinutes, wantTimeout)
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
	nativeKindConsumers := []string{"kind-install-baseline", "kind-install-gc", "kind-install-precontroller", "kind-install-admission", "kind-install-admission-v3", "kind-install-auth", "kind-api", "kind-recovery", "kind-lifecycle"}
	for _, name := range nativeKindConsumers {
		job := workflow.Jobs[name]
		if !nativeImagePrerequisites(job.Needs, job.If, job.ContinueOnError) {
			t.Fatalf("CI job %s competes with early diagnostics or skips independent coverage after their failure", name)
		}
	}
	policy := workflow.Jobs["go-policy-checks"]
	if !diagnosticOrderingOnly(policy.Needs, policy.If, policy.ContinueOnError) {
		t.Fatal("independent policy checks changed their diagnostic-only ordering")
	}
	if !nativeImagePrerequisites([]string{"installer-diagnostics", "kind-images"}, "${{ !cancelled() && needs.kind-images.result == 'success' }}", nil) {
		t.Fatal("native image prerequisite positive control refused")
	}
	for _, needs := range [][]string{nil, {}, {"installer-diagnostics"}, {"kind-images"}, {"kind-images", "installer-diagnostics"}, {"installer-diagnostics", "kind-images", "kind-images"}, {"installer-diagnostics", "kind-images", "kind-install-binary"}} {
		if nativeImagePrerequisites(needs, "${{ !cancelled() && needs.kind-images.result == 'success' }}", nil) {
			t.Fatal("native image prerequisite accepted missing, reordered, duplicate or artificial dependencies")
		}
	}
	for _, condition := range []string{"", "${{ !cancelled() }}", "${{ always() }}", "${{ success() }}", "${{ needs.kind-images.result == 'success' }}"} {
		if nativeImagePrerequisites([]string{"installer-diagnostics", "kind-images"}, condition, nil) {
			t.Fatal("native image prerequisite accepted a coverage skip or artifact bypass")
		}
	}
	for _, tolerate := range []any{false, true, "${{ true }}"} {
		if nativeImagePrerequisites([]string{"installer-diagnostics", "kind-images"}, "${{ !cancelled() && needs.kind-images.result == 'success' }}", tolerate) {
			t.Fatal("native image prerequisite accepted a failure-tolerance override")
		}
	}
	producer := workflow.Jobs["kind-images"]
	if producer.If != "" || producer.ContinueOnError != nil || len(producer.Needs) != 0 || producer.TimeoutMinutes != 20 || producer.RunsOn != "ubuntu-24.04" || len(producer.Steps) != 3 {
		t.Fatal("shared image producer is conditional, unbounded or delayed behind proofs")
	}
	if producer.Steps[1].Run != `bash ./hack/kind-runtime-images.sh export "$GITHUB_WORKSPACE" "$RUNNER_TEMP/kind-images"` || producer.Steps[2].Uses != "actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9" || producer.Steps[2].With["name"] != "kind-images-${{ github.run_id }}-${{ github.run_attempt }}" || producer.Steps[2].With["path"] != "${{ runner.temp }}/kind-images/" || producer.Steps[2].With["if-no-files-found"] != "error" {
		t.Fatal("shared images lack an exact-source, run-attempt-scoped required artifact")
	}
	for _, step := range producer.Steps {
		if step.If != "" || step.ContinueOnError != nil {
			t.Fatal("shared image production can skip or tolerate failure")
		}
	}
	kindConsumerCount := 0
	for name, job := range workflow.Jobs {
		if !strings.HasPrefix(name, "kind-") || name == "kind-images" {
			continue
		}
		kindConsumerCount++
		if name != "kind-install-binary" && !slices.Contains(nativeKindConsumers, name) {
			t.Fatal("unclassified Kind consumer job", name)
		}
		if !slices.Equal(job.Needs, []string{"installer-diagnostics", "kind-images"}) {
			t.Fatal("Kind consumer does not depend on installer-diagnostics and kind-images", name)
		}
		downloads, loads := 0, 0
		for _, step := range job.Steps {
			if strings.HasPrefix(step.Uses, "actions/download-artifact@") {
				downloads++
				if step.Uses != "actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333" || step.If != "" || step.ContinueOnError != nil || step.With["name"] != "kind-images-${{ github.run_id }}-${{ github.run_attempt }}" || step.With["path"] != "${{ runner.temp }}/kind-images/" {
					t.Fatal("Kind consumer bypasses pinned run-local artifact download", name)
				}
			}
			if strings.Contains(step.Run, "kind-runtime-images.sh load") {
				loads++
				if downloads != 1 || step.If != "" || step.ContinueOnError != nil || step.Run != "bash ./hack/kind-runtime-images.sh load \"$GITHUB_WORKSPACE\" \"$RUNNER_TEMP/kind-images\"\necho \"ARCADECTL_KIND_IMAGE_DIR=$RUNNER_TEMP/kind-images\" >> \"$GITHUB_ENV\"\n" {
					t.Fatal("Kind consumer bypasses bundle verification or artifact selection", name)
				}
			}
			if strings.HasPrefix(step.Run, "make test-kind-") && loads != 1 {
				t.Fatal("Kind proof runs before verified image import", name)
			}
		}
		if downloads != 1 || loads != 1 {
			t.Fatal("Kind consumer omitted shared images", name)
		}
	}
	if kindConsumerCount != 10 {
		t.Fatalf("unexpected Kind consumer job count: got %d, want 10", kindConsumerCount)
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
	if admission.TimeoutMinutes != 50 || admission.Strategy.FailFast == nil || *admission.Strategy.FailFast || !slices.Equal(admission.Strategy.Matrix.Profile, []int{135, 137}) || !slices.Equal(admission.Strategy.Matrix.Mode, []string{"cold", "warm"}) || len(admission.Strategy.Matrix.Exclude) != 0 {
		t.Fatal("full native admission profile/mode or timeout omitted")
	}
	fullRun := false
	for _, step := range admission.Steps {
		fullRun = fullRun || step.Run == "make test-kind-install-admission INSTALL_ADMISSION_PROFILE='${{ matrix.profile }}' INSTALL_ADMISSION_MODE='${{ matrix.mode }}'"
	}
	gate := workflow.Jobs["go-and-policy"]
	if !slices.Equal(gate.Needs, []string{"installer-diagnostics", "install-engine-race", "kind-install-admission", "kind-install-admission-v3", "kind-install-binary", "kind-install-baseline", "kind-install-gc", "kind-install-precontroller", "kind-install-auth", "kind-api", "kind-recovery", "envtest", "kind-lifecycle", "go-policy-checks", "kind-images"}) || gate.ContinueOnError != nil {
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
	if gate.Name != "Go and policy" || gate.RunsOn != "ubuntu-24.04" || len(gate.Steps) != 2 || gate.Steps[0].Uses != "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1" || gate.Steps[0].Run != "" || gate.Steps[0].If != "" || gate.Steps[0].ContinueOnError != nil || len(gate.Steps[0].Env) != 0 {
		t.Fatal("protected aggregate changed its name, exact checkout or assertion-only scope")
	}
	diagnostics := workflow.Jobs["installer-diagnostics"]
	wantDiagnosticChecks := []string{"cli", "controls", "discovery", "observation", "benchmarks", "wrappers", "vet"}
	for index, step := range diagnostics.Steps {
		condition := ""
		if index >= 2 && index-2 < len(wantDiagnosticChecks) {
			condition = "matrix.check == '" + wantDiagnosticChecks[index-2] + "'"
		}
		if step.If != condition || step.ContinueOnError != nil || len(step.Env) != 0 || index < 2 && step.Run != "" || index >= 2 && (step.Run == "" || step.Uses != "" || len(step.With) != 0) {
			t.Fatal("early diagnostic step can skip, tolerate failure or override bounded environment")
		}
	}
	var diagnosticRuns []string
	for _, check := range diagnostics.Strategy.Matrix.Check {
		wantIf := "matrix.check == '" + check + "'"
		matches := 0
		for _, step := range diagnostics.Steps[2:] {
			if step.If == wantIf {
				matches++
				diagnosticRuns = append(diagnosticRuns, step.Run)
			}
		}
		if matches != 1 {
			t.Fatalf("diagnostic matrix check %s does not map to a unique diagnostic step", check)
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
	if !slices.Equal(diagnostics.Strategy.Matrix.Check, wantDiagnosticChecks) || diagnostics.Strategy.FailFast == nil || *diagnostics.Strategy.FailFast || diagnostics.Strategy.MaxParallel != 0 || len(diagnostics.Strategy.Matrix.Exclude) != 0 || len(diagnostics.Strategy.Matrix.Profile) != 0 || len(diagnostics.Strategy.Matrix.Mode) != 0 || len(diagnostics.Strategy.Matrix.Shard) != 0 || len(diagnostics.Strategy.Matrix.Part) != 0 {
		t.Fatal("diagnostic matrix omits, serializes or cancels original independent checks")
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
	if !binaryDiagnosticsPrerequisite([]string{"installer-diagnostics", "kind-images"}, "", nil) {
		t.Fatal("binary diagnostics-success positive control refused")
	}
	for _, needs := range [][]string{nil, {}, {"installer-diagnostics"}, {"kind-images"}, {"kind-images", "installer-diagnostics"}, {"kind-install-gc"}, {"installer-diagnostics", "installer-diagnostics"}, {"installer-diagnostics", "kind-images", "kind-images"}, {"installer-diagnostics", "kind-install-binary"}, {"installer-diagnostics", "go-and-policy"}, {"installer-diagnostics", "kind-images", "kind-install-binary"}, {"installer-diagnostics", "kind-images", "go-and-policy"}} {
		if binaryDiagnosticsPrerequisite(needs, "", nil) {
			t.Fatal("binary scheduling accepted missing, substituted, duplicate or cyclic prerequisites")
		}
	}
	for _, foundation := range bulkNeeds[1:] {
		if binaryDiagnosticsPrerequisite([]string{"installer-diagnostics", "kind-images", foundation}, "", nil) {
			t.Fatal("binary scheduling delayed independent lifecycle work behind a native foundation", foundation)
		}
	}
	for _, condition := range []string{"${{ !cancelled() }}", "${{ always() }}", "${{ failure() }}", "${{ success() }}"} {
		if binaryDiagnosticsPrerequisite([]string{"installer-diagnostics", "kind-images"}, condition, nil) {
			t.Fatal("binary scheduling accepted a custom diagnostic scheduling condition", condition)
		}
	}
	for _, tolerate := range []any{false, true, "${{ true }}"} {
		if binaryDiagnosticsPrerequisite([]string{"installer-diagnostics", "kind-images"}, "", tolerate) {
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
	lifecycle := workflow.Jobs["kind-lifecycle"]
	lifecycleRuns, factorioRuns := 0, 0
	for _, step := range lifecycle.Steps {
		if step.Run == "make test-kind-lifecycle" {
			lifecycleRuns++
		}
		if step.Run == "make test-kind-factorio" {
			factorioRuns++
		}
	}
	if lifecycle.TimeoutMinutes != 45 || lifecycleRuns != 1 || factorioRuns != 1 || !slices.Contains(gate.Needs, "kind-lifecycle") {
		t.Fatal("native lifecycle proof, certified Factorio proof or timeout omitted")
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
	if !fullRun || !binaryRun || !binaryHistory || binary.TimeoutMinutes != 350 || binary.Strategy.FailFast == nil || *binary.Strategy.FailFast || !slices.Equal(binaryMatrix.Profile, []int{137, 135}) || !slices.Equal(binaryMatrix.Mode, []string{"transition", "fresh"}) || len(binaryMatrix.Exclude) != 1 || binaryMatrix.Exclude[0].Profile != 135 || binaryMatrix.Exclude[0].Mode != "transition" || gate.If != "${{ always() }}" || !slices.Contains(gate.Needs, "install-engine-race") || !slices.Contains(gate.Needs, "kind-install-admission") || !slices.Contains(gate.Needs, "kind-install-binary") {
		t.Fatal("required gate bypasses full native admission or engine races")
	}
	// Expand matrix legs for every Kind consumer job and every workflow job,
	// pinning both the per-job expanded leg sets and the total leg counts vs 0225dc4.
	expandProfileModeLegs := func(name string) []string {
		m := workflow.Jobs[name].Strategy.Matrix
		var legs []string
		matchedExcludes := 0
		for _, p := range m.Profile {
			for _, mode := range m.Mode {
				excluded := false
				for _, ex := range m.Exclude {
					if ex.Profile == p && ex.Mode == mode {
						excluded = true
						matchedExcludes++
					}
				}
				if !excluded {
					legs = append(legs, strconv.Itoa(p)+":"+mode)
				}
			}
		}
		if matchedExcludes != len(m.Exclude) {
			t.Fatalf("CI job %s has unmatched matrix exclude entry", name)
		}
		return legs
	}
	expandProfileLegs := func(name string) []string {
		m := workflow.Jobs[name].Strategy.Matrix
		if len(m.Exclude) != 0 || len(m.Mode) != 0 {
			t.Fatalf("CI job %s has unexpected mode/exclude on profile matrix", name)
		}
		var legs []string
		for _, p := range m.Profile {
			legs = append(legs, strconv.Itoa(p))
		}
		return legs
	}
	wantKindLegs := map[string][]string{
		"kind-install-binary":        {"137:transition", "137:fresh", "135:fresh"},
		"kind-install-baseline":      {"135", "137"},
		"kind-install-gc":            {"single"},
		"kind-install-precontroller": {"135", "137"},
		"kind-install-admission":     {"135:cold", "135:warm", "137:cold", "137:warm"},
		"kind-install-admission-v3":  {"135:cold", "135:warm", "137:cold", "137:warm"},
		"kind-install-auth":          {"single"},
		"kind-api":                   {"single"},
		"kind-recovery":              {"single"},
		"kind-lifecycle":             {"single"},
	}
	totalKindLegs := 0
	for name, wantLegs := range wantKindLegs {
		m := workflow.Jobs[name].Strategy.Matrix
		var gotLegs []string
		switch {
		case len(m.Profile) != 0 && len(m.Mode) != 0:
			gotLegs = expandProfileModeLegs(name)
		case len(m.Profile) != 0:
			gotLegs = expandProfileLegs(name)
		case len(m.Profile) == 0 && len(m.Mode) == 0 && len(m.Exclude) == 0 && len(m.Shard) == 0 && len(m.Part) == 0 && len(m.Check) == 0:
			gotLegs = []string{"single"}
		default:
			t.Fatalf("CI Kind job %s has malformed matrix dimensions", name)
		}
		if !slices.Equal(gotLegs, wantLegs) {
			t.Fatalf("CI Kind job %s expanded matrix legs changed: got %v, want %v", name, gotLegs, wantLegs)
		}
		totalKindLegs += len(gotLegs)
	}
	if totalKindLegs != 20 {
		t.Fatalf("expanded Kind consumer leg count changed vs 0225dc4: got %d, want 20", totalKindLegs)
	}
	totalExpandedLegs := totalKindLegs + len(diagnostics.Strategy.Matrix.Check) + len(races.Strategy.Matrix.Shard) + len(envtest.Strategy.Matrix.Part) + 3 // kind-images, go-policy-checks, go-and-policy
	if totalExpandedLegs != 95 {
		t.Fatalf("total expanded workflow leg count changed: got %d, want 95", totalExpandedLegs)
	}
	var command string
	for _, step := range gate.Steps {
		if len(step.Env) == 15 && step.Env["KIND_IMAGES_RESULT"] == "${{ needs.kind-images.result }}" && step.Env["INSTALLER_DIAGNOSTICS_RESULT"] == "${{ needs.installer-diagnostics.result }}" && step.Env["ENGINE_RACE_RESULT"] == "${{ needs.install-engine-race.result }}" && step.Env["INSTALL_ADMISSION_RESULT"] == "${{ needs.kind-install-admission.result }}" && step.Env["INSTALL_BINARY_RESULT"] == "${{ needs.kind-install-binary.result }}" && step.Env["INSTALL_BASELINE_RESULT"] == "${{ needs.kind-install-baseline.result }}" && step.Env["INSTALL_ADMISSION_V3_RESULT"] == "${{ needs.kind-install-admission-v3.result }}" && step.Env["INSTALL_PRECONTROLLER_RESULT"] == "${{ needs.kind-install-precontroller.result }}" && step.Env["INSTALL_GC_RESULT"] == "${{ needs.kind-install-gc.result }}" && step.Env["INSTALL_AUTH_RESULT"] == "${{ needs.kind-install-auth.result }}" && step.Env["API_RESULT"] == "${{ needs.kind-api.result }}" && step.Env["RECOVERY_RESULT"] == "${{ needs.kind-recovery.result }}" && step.Env["ENVTEST_RESULT"] == "${{ needs.envtest.result }}" && step.Env["LIFECYCLE_RESULT"] == "${{ needs.kind-lifecycle.result }}" && step.Env["GO_POLICY_CHECKS_RESULT"] == "${{ needs.go-policy-checks.result }}" {
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
							c.Env = append(os.Environ(), "INSTALLER_DIAGNOSTICS_RESULT=success", "ENGINE_RACE_RESULT="+races, "INSTALL_ADMISSION_RESULT="+native, "INSTALL_BINARY_RESULT="+binary, "INSTALL_BASELINE_RESULT="+baseline, "INSTALL_ADMISSION_V3_RESULT="+v3, "INSTALL_PRECONTROLLER_RESULT="+precontroller, "INSTALL_GC_RESULT=success", "INSTALL_AUTH_RESULT=success", "API_RESULT=success", "RECOVERY_RESULT=success", "ENVTEST_RESULT=success", "LIFECYCLE_RESULT=success", "GO_POLICY_CHECKS_RESULT=success", "KIND_IMAGES_RESULT=success")
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
		c.Env = append(os.Environ(), "INSTALLER_DIAGNOSTICS_RESULT=success", "ENGINE_RACE_RESULT=success", "INSTALL_ADMISSION_RESULT=success", "INSTALL_BINARY_RESULT=success", "INSTALL_BASELINE_RESULT=success", "INSTALL_ADMISSION_V3_RESULT=success", "INSTALL_PRECONTROLLER_RESULT=success", "INSTALL_GC_RESULT="+result, "INSTALL_AUTH_RESULT=success", "API_RESULT=success", "RECOVERY_RESULT=success", "ENVTEST_RESULT=success", "LIFECYCLE_RESULT=success", "GO_POLICY_CHECKS_RESULT=success", "KIND_IMAGES_RESULT=success")
		if passed := c.Run() == nil; passed != (result == "success") {
			t.Fatal("failed/cancelled/skipped/absent GC proof became a green required gate")
		}
	}
	// Independently exercise every added prerequisite outcome while the others
	// succeed, preserving all original combinations without multiplying them.
	added := []string{"INSTALL_AUTH_RESULT", "API_RESULT", "RECOVERY_RESULT", "INSTALLER_DIAGNOSTICS_RESULT", "ENVTEST_RESULT", "LIFECYCLE_RESULT", "GO_POLICY_CHECKS_RESULT", "KIND_IMAGES_RESULT"}
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
	// Also prove every required *_RESULT variable fails closed when completely
	// absent (unset) from the process environment while all others are "success".
	allResultVariables := []string{"INSTALLER_DIAGNOSTICS_RESULT", "ENGINE_RACE_RESULT", "INSTALL_ADMISSION_RESULT", "INSTALL_BINARY_RESULT", "INSTALL_BASELINE_RESULT", "INSTALL_GC_RESULT", "INSTALL_ADMISSION_V3_RESULT", "INSTALL_PRECONTROLLER_RESULT", "INSTALL_AUTH_RESULT", "API_RESULT", "RECOVERY_RESULT", "ENVTEST_RESULT", "LIFECYCLE_RESULT", "GO_POLICY_CHECKS_RESULT", "KIND_IMAGES_RESULT"}
	var baseEnv []string
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if !slices.Contains(allResultVariables, name) {
			baseEnv = append(baseEnv, entry)
		}
	}
	for _, omitted := range allResultVariables {
		c := exec.Command("sh", "-e", "-c", command)
		c.Env = slices.Clone(baseEnv)
		for _, other := range allResultVariables {
			if other != omitted {
				c.Env = append(c.Env, other+"=success")
			}
		}
		if c.Run() == nil {
			t.Fatalf("unset/absent %s environment variable became a green required gate", omitted)
		}
	}
	verifyKindRuntimeImagesScriptAndFixtures(t)
}

func verifyKindRuntimeImagesScriptAndFixtures(t *testing.T) {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal("repository root unavailable")
	}
	script := filepath.Join(root, "hack", "kind-runtime-images.sh")
	workspace := t.TempDir()
	random := make([]byte, 6)
	if _, err := rand.Read(random); err != nil {
		t.Fatal("fixture identity unavailable")
	}
	suffix := hex.EncodeToString(random)
	repo := filepath.Join(workspace, "repo")
	if os.Mkdir(repo, 0700) != nil || os.WriteFile(filepath.Join(repo, "README"), []byte("exact\n"), 0600) != nil {
		t.Fatal("write git fixture")
	}
	for _, args := range [][]string{
		{"init", "-q"},
		{"config", "user.email", "test@gobha.me"},
		{"config", "user.name", "Test"},
		{"add", "README"},
		{"commit", "-q", "-m", "init"},
	} {
		if out, err := exec.CommandContext(t.Context(), "git", append([]string{"-C", repo}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git fixture %v: %s", args, out)
		}
	}
	shaOut, err := exec.CommandContext(t.Context(), "git", "-C", repo, "rev-parse", "HEAD").CombinedOutput()
	if err != nil {
		t.Fatalf("git rev-parse: %s", shaOut)
	}
	sha := strings.TrimSpace(string(shaOut))
	epochOut, err := exec.CommandContext(t.Context(), "git", "-C", repo, "show", "-s", "--format=%ct", "HEAD").CombinedOutput()
	if err != nil {
		t.Fatalf("git epoch: %s", epochOut)
	}
	epoch := strings.TrimSpace(string(epochOut))

	// 1. Invalid subcommand and arity checks fail closed.
	for _, args := range [][]string{
		nil,
		{"unknown"},
		{"export", repo},
		{"load", repo},
		{"prepare", "api", repo, sha, epoch, "false"},
		{"prepare", "unsupported", repo, sha, epoch, "false", "127.0.0.1:0/arcadectl-api:bad-" + suffix},
	} {
		if exec.CommandContext(t.Context(), "bash", append([]string{script}, args...)...).Run() == nil {
			t.Fatalf("kind-runtime-images.sh accepted invalid arguments: %v", args)
		}
	}

	// 2. Dirty tree on export fails closed before touching Docker.
	if os.WriteFile(filepath.Join(repo, "dirty"), []byte("dirty\n"), 0600) != nil {
		t.Fatal("write dirty file")
	}
	out, err := exec.CommandContext(t.Context(), "bash", script, "export", repo, filepath.Join(workspace, "dirty-export")).CombinedOutput()
	if err == nil || !strings.Contains(string(out), "export requires a clean exact-source checkout") {
		t.Fatalf("dirty export did not fail closed: err=%v out=%s", err, out)
	}
	if os.Remove(filepath.Join(repo, "dirty")) != nil {
		t.Fatal("clean dirty file")
	}

	// 3. Bundle load checksum verification (SHA256SUMS) and source-sha/epoch checks fail closed.
	bundle := filepath.Join(workspace, "bundle")
	if os.Mkdir(bundle, 0700) != nil {
		t.Fatal("create bundle")
	}
	missingDigest := "sha256:" + strings.Repeat("0", 64)
	writeBundle := func(bundleSHA, bundleEpoch, apiID, controllerID, tarBody string) {
		if os.WriteFile(filepath.Join(bundle, "images.tar"), []byte(tarBody), 0600) != nil ||
			os.WriteFile(filepath.Join(bundle, "source-sha"), []byte(bundleSHA+"\n"), 0600) != nil ||
			os.WriteFile(filepath.Join(bundle, "source-epoch"), []byte(bundleEpoch+"\n"), 0600) != nil ||
			os.WriteFile(filepath.Join(bundle, "api.id"), []byte(apiID+"\n"), 0600) != nil ||
			os.WriteFile(filepath.Join(bundle, "controller.id"), []byte(controllerID+"\n"), 0600) != nil {
			t.Fatal("write bundle files")
		}
		sumCmd := exec.CommandContext(t.Context(), "sha256sum", "images.tar", "source-sha", "source-epoch", "api.id", "controller.id")
		sumCmd.Dir = bundle
		sums, err := sumCmd.Output()
		if err != nil || os.WriteFile(filepath.Join(bundle, "SHA256SUMS"), sums, 0600) != nil {
			t.Fatal("write SHA256SUMS")
		}
	}
	for _, target := range []string{"images.tar", "source-sha", "source-epoch", "api.id", "controller.id", "SHA256SUMS"} {
		writeBundle(sha, epoch, missingDigest, missingDigest, "archive-bytes")
		if os.WriteFile(filepath.Join(bundle, target), []byte("corrupted\n"), 0600) != nil {
			t.Fatal("corrupt bundle file")
		}
		if exec.CommandContext(t.Context(), "bash", script, "load", repo, bundle).Run() == nil {
			t.Fatalf("load accepted corrupted %s checksum", target)
		}
	}
	writeBundle(strings.Repeat("a", 40), epoch, missingDigest, missingDigest, "archive-bytes")
	if out, err := exec.CommandContext(t.Context(), "bash", script, "load", repo, bundle).CombinedOutput(); err == nil || !strings.Contains(string(out), "bundle belongs to another commit") {
		t.Fatalf("load accepted foreign commit SHA: err=%v out=%s", err, out)
	}
	writeBundle(sha, "1700000001", missingDigest, missingDigest, "archive-bytes")
	if out, err := exec.CommandContext(t.Context(), "bash", script, "load", repo, bundle).CombinedOutput(); err == nil || !strings.Contains(string(out), "bundle timestamp mismatch") {
		t.Fatalf("load accepted foreign commit timestamp: err=%v out=%s", err, out)
	}

	// 4. Shared prepare fails closed on dirty tree, SHA/epoch mismatch, invalid digest format, missing image, and metadata drift, and succeeds on exact digest match.
	writeBundle(sha, epoch, missingDigest, missingDigest, "archive-bytes")
	runPrepare := func(role, candSHA, candEpoch, dirty, tag string) ([]byte, error) {
		c := exec.CommandContext(t.Context(), "bash", script, "prepare", role, repo, candSHA, candEpoch, dirty, tag)
		c.Env = append(os.Environ(), "ARCADECTL_KIND_IMAGE_DIR="+bundle)
		return c.CombinedOutput()
	}
	ownedTag := "127.0.0.1:0/arcadectl-api:gate-" + suffix
	if out, err := runPrepare("api", sha, epoch, "true", ownedTag); err == nil || !strings.Contains(string(out), "shared images require a clean consumer checkout") {
		t.Fatalf("prepare accepted dirty consumer checkout: err=%v out=%s", err, out)
	}
	if out, err := runPrepare("api", strings.Repeat("a", 40), epoch, "false", ownedTag); err == nil || !strings.Contains(string(out), "shared source mismatch") {
		t.Fatalf("prepare accepted mismatched source SHA: err=%v out=%s", err, out)
	}
	if out, err := runPrepare("api", sha, "1700000001", "false", ownedTag); err == nil || !strings.Contains(string(out), "shared timestamp mismatch") {
		t.Fatalf("prepare accepted mismatched source epoch: err=%v out=%s", err, out)
	}
	if os.WriteFile(filepath.Join(bundle, "api.id"), []byte("arcadectl-api:mutable-tag\n"), 0600) != nil {
		t.Fatal("write non-digest api.id")
	}
	if out, err := runPrepare("api", sha, epoch, "false", ownedTag); err == nil || !strings.Contains(string(out), "invalid shared image identity") {
		t.Fatalf("prepare accepted non-digest image identity: err=%v out=%s", err, out)
	}
	if os.WriteFile(filepath.Join(bundle, "api.id"), []byte(missingDigest+"\n"), 0600) != nil {
		t.Fatal("restore missingDigest api.id")
	}
	if _, err := runPrepare("api", sha, epoch, "false", ownedTag); err == nil {
		t.Fatal("prepare accepted a missing image digest")
	}

	// Build task-owned scratch control images to verify digest + label/user/entrypoint checks in verify_image.
	var cleanupTags []struct{ tag, id string }
	t.Cleanup(func() {
		for _, item := range cleanupTags {
			out, err := exec.Command("docker", "image", "inspect", "--format", "{{.Id}}", item.tag).CombinedOutput()
			if err == nil && item.id != "" && strings.TrimSpace(string(out)) == item.id {
				_ = exec.Command("docker", "image", "rm", item.tag).Run()
			}
		}
	})
	buildScratch := func(name, rev, dirtyLabel, user, entrypoint string) string {
		dir := filepath.Join(workspace, "img-"+name)
		tag := "127.0.0.1:0/arcadectl-api:" + name + "-" + suffix
		df := "FROM scratch\nLABEL org.opencontainers.image.revision=" + rev + " arcade.gobha.me/source-dirty=" + dirtyLabel + "\nUSER " + user + "\nENTRYPOINT [\"" + entrypoint + "\"]\n"
		if os.Mkdir(dir, 0700) != nil || os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(df), 0600) != nil {
			t.Fatal("write scratch image fixture")
		}
		if out, err := exec.CommandContext(t.Context(), "docker", "build", "--platform", "linux/amd64", "-q", "-t", tag, dir).CombinedOutput(); err != nil {
			t.Fatalf("build scratch image %s: %s", name, out)
		}
		idOut, err := exec.CommandContext(t.Context(), "docker", "image", "inspect", "--format", "{{.Id}}", tag).CombinedOutput()
		if err != nil {
			t.Fatalf("inspect scratch image %s: %s", name, idOut)
		}
		id := strings.TrimSpace(string(idOut))
		cleanupTags = append(cleanupTags, struct{ tag, id string }{tag, id})
		return id
	}
	for _, bad := range []struct {
		name, rev, dirty, user, entrypoint, wantErr string
	}{
		{"bad-rev", strings.Repeat("c", 40), "false", "65532:65532", "/arcadectl-api", "source mismatch"},
		{"bad-dirty", sha, "true", "65532:65532", "/arcadectl-api", "source state mismatch"},
		{"bad-user", sha, "false", "0:0", "/arcadectl-api", "user mismatch"},
		{"bad-entry", sha, "false", "65532:65532", "/arcadectl-controller", "entrypoint mismatch"},
	} {
		id := buildScratch(bad.name, bad.rev, bad.dirty, bad.user, bad.entrypoint)
		if os.WriteFile(filepath.Join(bundle, "api.id"), []byte(id+"\n"), 0600) != nil {
			t.Fatal("write bad api.id")
		}
		if out, err := runPrepare("api", sha, epoch, "false", ownedTag); err == nil || !strings.Contains(string(out), bad.wantErr) {
			t.Fatalf("prepare accepted %s image: err=%v out=%s", bad.name, err, out)
		}
	}
	validID := buildScratch("valid", sha, "false", "65532:65532", "/arcadectl-api")
	cleanupTags = append(cleanupTags, struct{ tag, id string }{ownedTag, validID})
	if os.WriteFile(filepath.Join(bundle, "api.id"), []byte(validID+"\n"), 0600) != nil {
		t.Fatal("write valid api.id")
	}
	if out, err := runPrepare("api", sha, epoch, "false", ownedTag); err != nil {
		t.Fatalf("prepare refused valid exact-source digest image: %v %s", err, out)
	}

	// 5. Verify Kind fixture files wire hack/kind-runtime-images.sh prepare and post-prepare digest/label checks.
	apiKindSource, err := os.ReadFile(filepath.Join(root, "internal", "install", "api_kind_test.go"))
	if err != nil || !strings.Contains(string(apiKindSource), `prepareKindAPIImage(ctx, newCommand, root, filepath.Join(root, "hack", "kind-runtime-images.sh"), sha, epoch, dirty, imageTag)`) {
		t.Fatal("api_kind_test.go does not wire exact-source Kind runtime image preparation")
	}
	targetAuthSource, err := os.ReadFile(filepath.Join(root, "internal", "installengine", "target_auth_kind_test.go"))
	if err != nil || !strings.Contains(string(targetAuthSource), `prepareTargetKindRuntimeImage(ctx, command, root, filepath.Join(root, "hack", "kind-runtime-images.sh"), repository, dockerfile, sourceRoot, sourceSHA, sourceEpoch, sourceDirty, tag)`) {
		t.Fatal("target_auth_kind_test.go does not wire exact-source Kind runtime image preparation")
	}
	lifecycleScript, err := os.ReadFile(filepath.Join(root, "hack", "test-kind-lifecycle.sh"))
	if err != nil || !strings.Contains(string(lifecycleScript), `run_bounded 360 bash "$repository_root/hack/kind-runtime-images.sh" prepare controller`) {
		t.Fatal("test-kind-lifecycle.sh does not wire exact-source controller image preparation")
	}
}
