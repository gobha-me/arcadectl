// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package workflowpolicy

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	yaml "go.yaml.in/yaml/v3"
)

type workflowFile struct {
	Name        string                 `yaml:"name"`
	On          map[string]any         `yaml:"on"`
	Permissions map[string]string      `yaml:"permissions"`
	Concurrency map[string]any         `yaml:"concurrency"`
	Jobs        map[string]workflowJob `yaml:"jobs"`
}

type workflowJob struct {
	Name            string            `yaml:"name"`
	RunsOn          string            `yaml:"runs-on"`
	If              string            `yaml:"if"`
	ContinueOnError any               `yaml:"continue-on-error"`
	Needs           []string          `yaml:"needs"`
	TimeoutMinutes  any               `yaml:"timeout-minutes"`
	Outputs         map[string]string `yaml:"outputs"`
	Env             map[string]string `yaml:"env"`
	Permissions     map[string]string `yaml:"permissions"`
	Strategy        struct {
		FailFast    *bool `yaml:"fail-fast"`
		MaxParallel any   `yaml:"max-parallel"`
		Matrix      struct {
			Shard    []int    `yaml:"shard"`
			Part     []string `yaml:"part"`
			Profile  []int    `yaml:"profile"`
			Mode     []string `yaml:"mode"`
			Revision []string `yaml:"revision"`
			Exclude  []struct {
				Profile int    `yaml:"profile"`
				Mode    string `yaml:"mode"`
			} `yaml:"exclude"`
		} `yaml:"matrix"`
	} `yaml:"strategy"`
	Steps []workflowStep `yaml:"steps"`
}

type workflowStep struct {
	ID              string            `yaml:"id"`
	Name            string            `yaml:"name"`
	If              string            `yaml:"if"`
	ContinueOnError any               `yaml:"continue-on-error"`
	Uses            string            `yaml:"uses"`
	Run             string            `yaml:"run"`
	Env             map[string]string `yaml:"env"`
	With            map[string]any    `yaml:"with"`
}

func validateCIWorkflowBytes(body []byte) (*workflowFile, error) {
	var wf workflowFile
	if err := yaml.Unmarshal(body, &wf); err != nil {
		return nil, fmt.Errorf("unmarshal ci.yml: %w", err)
	}
	if len(wf.On) == 0 {
		return nil, fmt.Errorf("ci.yml missing 'on' triggers")
	}
	for _, requiredTrigger := range []string{"pull_request", "push", "schedule", "workflow_dispatch"} {
		if _, ok := wf.On[requiredTrigger]; !ok {
			return nil, fmt.Errorf("ci.yml missing required trigger %q", requiredTrigger)
		}
	}
	if prConfig := wf.On["pull_request"]; prConfig != nil {
		prMap, ok := prConfig.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("pull_request trigger has unexpected type %T", prConfig)
		}
		for _, forbidden := range []string{"paths", "paths-ignore", "branches", "branches-ignore", "types"} {
			if _, exists := prMap[forbidden]; exists {
				return nil, fmt.Errorf("pull_request trigger contains forbidden filter %q", forbidden)
			}
		}
		if len(prMap) != 0 {
			return nil, fmt.Errorf("pull_request trigger must remain unfiltered, got keys %v", prMap)
		}
	}
	if pushConfig, ok := wf.On["push"].(map[string]any); ok {
		for _, forbidden := range []string{"paths", "paths-ignore"} {
			if _, exists := pushConfig[forbidden]; exists {
				return nil, fmt.Errorf("push trigger contains forbidden path filter %q", forbidden)
			}
		}
	} else {
		return nil, fmt.Errorf("push trigger must specify main branch")
	}

	// Only the latest head of each pull request runs; main, nightly and
	// dispatch runs are never cancelled in progress (exact Atlas expression).
	if err := validateConcurrency(&wf); err != nil {
		return nil, err
	}
	for scope, value := range wf.Permissions {
		if value != "read" && value != "none" {
			return nil, fmt.Errorf("workflow-level permission %s: %s must not grant write access", scope, value)
		}
	}

	requiredJobs := []string{
		"classify",
		"installer-diagnostics",
		"kind-install-binary",
		"kind-recovery",
		"kind-install-baseline",
		"kind-install-precontroller",
		"kind-install-admission",
		"kind-install-admission-v3",
		"kind-install-gc",
		"kind-install-auth",
		"kind-api",
		"kind-lifecycle",
		"envtest",
		"install-engine-race",
		"go-policy-checks",
		"go-and-policy",
	}
	for _, name := range requiredJobs {
		if _, ok := wf.Jobs[name]; !ok {
			return nil, fmt.Errorf("required CI job %q is missing", name)
		}
	}

	// Verify complete unreduced matrices on all rejected jobs.
	binary := wf.Jobs["kind-install-binary"]
	if !slices.Equal(binary.Strategy.Matrix.Profile, []int{135, 137}) ||
		!slices.Equal(binary.Strategy.Matrix.Mode, []string{"fresh", "transition"}) ||
		len(binary.Strategy.Matrix.Exclude) != 1 ||
		binary.Strategy.Matrix.Exclude[0].Profile != 135 ||
		binary.Strategy.Matrix.Exclude[0].Mode != "transition" {
		return nil, fmt.Errorf("kind-install-binary matrix legs must be exactly (135 fresh, 137 fresh, 137 transition)")
	}
	if binary.Strategy.FailFast == nil || *binary.Strategy.FailFast {
		return nil, fmt.Errorf("kind-install-binary must set fail-fast: false")
	}
	hasWatchdog := false
	for _, step := range binary.Steps {
		if strings.Contains(step.Run, "make test-kind-install-binary") &&
			strings.Contains(step.Run, "./hack/ci-no-progress-watchdog.sh") {
			hasWatchdog = true
		}
	}
	if !hasWatchdog {
		return nil, fmt.Errorf("kind-install-binary transition leg lacks no-progress watchdog")
	}

	for _, twoProfileJob := range []string{"kind-install-baseline", "kind-install-precontroller"} {
		job := wf.Jobs[twoProfileJob]
		if !slices.Equal(job.Strategy.Matrix.Profile, []int{135, 137}) ||
			len(job.Strategy.Matrix.Exclude) != 0 ||
			len(job.Strategy.Matrix.Mode) != 0 ||
			job.Strategy.FailFast == nil || *job.Strategy.FailFast {
			return nil, fmt.Errorf("%s must run complete [135, 137] matrix with fail-fast: false", twoProfileJob)
		}
	}

	for _, fourLegJob := range []string{"kind-install-admission", "kind-install-admission-v3"} {
		job := wf.Jobs[fourLegJob]
		if !slices.Equal(job.Strategy.Matrix.Profile, []int{135, 137}) ||
			!slices.Equal(job.Strategy.Matrix.Mode, []string{"cold", "warm"}) ||
			len(job.Strategy.Matrix.Exclude) != 0 ||
			job.Strategy.FailFast == nil || *job.Strategy.FailFast {
			return nil, fmt.Errorf("%s must run complete [135, 137] x [cold, warm] matrix with fail-fast: false", fourLegJob)
		}
	}

	recovery := wf.Jobs["kind-recovery"]
	if len(recovery.Strategy.Matrix.Exclude) != 0 || len(recovery.Strategy.Matrix.Profile) != 0 || len(recovery.Strategy.Matrix.Mode) != 0 {
		return nil, fmt.Errorf("kind-recovery must not have matrix exclusions")
	}

	wantParts := []string{"base-packages"}
	for i := range 32 {
		wantParts = append(wantParts, strconv.Itoa(i))
	}
	// max-parallel only bounds concurrency (validated generically by
	// validateFairness below); every part and shard must still run.
	envtest := wf.Jobs["envtest"]
	if !slices.Equal(envtest.Strategy.Matrix.Part, wantParts) ||
		len(envtest.Strategy.Matrix.Exclude) != 0 ||
		envtest.Strategy.FailFast == nil || *envtest.Strategy.FailFast {
		return nil, fmt.Errorf("envtest must run all 33 parts (base-packages + 0..31) with fail-fast false")
	}

	wantShards := make([]int, 32)
	for i := range wantShards {
		wantShards[i] = i
	}
	races := wf.Jobs["install-engine-race"]
	if !slices.Equal(races.Strategy.Matrix.Shard, wantShards) ||
		len(races.Strategy.Matrix.Exclude) != 0 ||
		races.Strategy.FailFast == nil || *races.Strategy.FailFast {
		return nil, fmt.Errorf("install-engine-race must run all 32 shards (0..31) with fail-fast false")
	}

	// Verify job-level 'if:' conditions on all proof jobs:
	// No github.event_name, labels, paths, or ref exclusions on pull_request.
	// Only upstream foundation status (!cancelled() or success()) and classifier scope checks are allowed.
	allowedIfs := map[string]string{
		"installer-diagnostics":      "${{ !cancelled() && needs.classify.outputs.scope != 'docs' && needs.classify.outputs.scope != 'idle' }}",
		"go-policy-checks":           "${{ !cancelled() && needs.classify.outputs.scope != 'docs' && needs.classify.outputs.scope != 'idle' }}",
		"kind-install-baseline":      "${{ !cancelled() && needs.classify.outputs.scope != 'docs' && needs.classify.outputs.scope != 'idle' && needs.classify.outputs.scope != 'cheap' }}",
		"kind-install-gc":            "${{ !cancelled() && needs.classify.outputs.scope != 'docs' && needs.classify.outputs.scope != 'idle' && needs.classify.outputs.scope != 'cheap' }}",
		"kind-install-precontroller": "${{ !cancelled() && needs.classify.outputs.scope != 'docs' && needs.classify.outputs.scope != 'idle' && needs.classify.outputs.scope != 'cheap' }}",
		"kind-install-admission":     "${{ !cancelled() && needs.classify.outputs.scope != 'docs' && needs.classify.outputs.scope != 'idle' && needs.classify.outputs.scope != 'cheap' }}",
		"kind-install-admission-v3":  "${{ !cancelled() && needs.classify.outputs.scope != 'docs' && needs.classify.outputs.scope != 'idle' && needs.classify.outputs.scope != 'cheap' }}",
		"kind-install-auth":          "${{ !cancelled() && needs.classify.outputs.scope != 'docs' && needs.classify.outputs.scope != 'idle' && needs.classify.outputs.scope != 'cheap' }}",
		"kind-api":                   "${{ !cancelled() && needs.classify.outputs.scope != 'docs' && needs.classify.outputs.scope != 'idle' && needs.classify.outputs.scope != 'cheap' }}",
		"kind-recovery":              "${{ !cancelled() && needs.classify.outputs.scope != 'docs' && needs.classify.outputs.scope != 'idle' && needs.classify.outputs.scope != 'cheap' }}",
		"kind-lifecycle":             "${{ !cancelled() && needs.classify.outputs.scope != 'docs' && needs.classify.outputs.scope != 'idle' && needs.classify.outputs.scope != 'cheap' }}",
		"kind-install-binary":        "${{ success() && needs.classify.outputs.scope != 'docs' && needs.classify.outputs.scope != 'idle' && needs.classify.outputs.scope != 'cheap' }}",
		"install-engine-race":        "${{ success() && needs.classify.outputs.scope != 'docs' && needs.classify.outputs.scope != 'idle' && needs.classify.outputs.scope != 'cheap' }}",
		"envtest":                    "${{ success() && needs.classify.outputs.scope != 'docs' && needs.classify.outputs.scope != 'idle' && needs.classify.outputs.scope != 'cheap' }}",
		"go-and-policy":              "${{ always() }}",
		"classify":                   "",
	}
	// 1) Forbidden event/label/path/ref tokens: no job may stop running on PRs.
	for _, jobName := range slices.Sorted(maps.Keys(allowedIfs)) {
		job := wf.Jobs[jobName]
		for _, forbiddenToken := range []string{"github.event_name", "github.event.", "labels", "paths", "github.ref", "contains("} {
			if strings.Contains(job.If, forbiddenToken) {
				return nil, fmt.Errorf("job %q if condition contains forbidden token %q: %s", jobName, forbiddenToken, job.If)
			}
		}
	}

	// Verify item 2: race and envtest require all foundations in needs.
	wantBulkNeeds := []string{
		"classify",
		"installer-diagnostics",
		"kind-install-gc",
		"kind-install-admission",
		"kind-install-admission-v3",
		"kind-install-auth",
		"kind-install-baseline",
		"kind-install-precontroller",
	}

	// 2) Rejected-list jobs that keep success() semantics may only wait on
	// the classifier, diagnostics and the six native foundations (item 2's
	// only allowed upstream-failure skip). Waiting on any other job would let
	// an unrelated failure or skip suppress a proof that must run on every
	// code pull request. Capacity-only edges with !cancelled() are checked in 3.
	allowedUpstream := []string{
		"classify", "installer-diagnostics", "kind-install-gc", "kind-install-admission",
		"kind-install-admission-v3", "kind-install-auth", "kind-install-baseline", "kind-install-precontroller",
	}
	for _, rejected := range []string{
		"kind-install-binary", "kind-recovery", "kind-install-baseline", "kind-install-precontroller",
		"kind-install-admission", "kind-install-admission-v3", "envtest", "install-engine-race",
	} {
		if keepsRunningAfterFailure(wf.Jobs[rejected].If) {
			continue
		}
		for _, need := range wf.Jobs[rejected].Needs {
			if !slices.Contains(allowedUpstream, need) {
				return nil, fmt.Errorf("rejected-list job %q needs non-foundation job %q", rejected, need)
			}
		}
	}

	// 3) Fairness caps may serialize jobs with capacity-only needs edges. Any
	// prerequisite beyond a job's spec'd barrier (classifier + diagnostics;
	// for race/envtest the item-2 foundation set, which keeps success()) must
	// not use success()-only semantics, or an unrelated earlier failure would
	// skip a must-run proof (signed binary, recovery, 135/137 matrices, envtest).
	if err := validateCapacityEdges(&wf, wantBulkNeeds); err != nil {
		return nil, err
	}

	// 4) Exact job conditions and no failure tolerance.
	for _, jobName := range slices.Sorted(maps.Keys(allowedIfs)) {
		wantIf := allowedIfs[jobName]
		job := wf.Jobs[jobName]
		if job.If != wantIf {
			return nil, fmt.Errorf("job %q if condition = %q, want %q", jobName, job.If, wantIf)
		}
		if job.ContinueOnError != nil {
			return nil, fmt.Errorf("job %q sets continue-on-error: %v", jobName, job.ContinueOnError)
		}
	}

	for _, bulkJob := range []string{"install-engine-race", "envtest"} {
		if !slices.Equal(wf.Jobs[bulkJob].Needs, wantBulkNeeds) {
			return nil, fmt.Errorf("bulk job %q needs = %v, want %v", bulkJob, wf.Jobs[bulkJob].Needs, wantBulkNeeds)
		}
	}

	// Verify gate covers all other jobs.
	gate := wf.Jobs["go-and-policy"]
	if gate.Name != "Go and policy" {
		return nil, fmt.Errorf("go-and-policy job name = %q, want %q", gate.Name, "Go and policy")
	}
	if lifecycle := wf.Jobs["kind-lifecycle"]; lifecycle.Name != "Kind lifecycle" {
		return nil, fmt.Errorf("kind-lifecycle job name = %q, want %q", lifecycle.Name, "Kind lifecycle")
	}
	for jobName := range wf.Jobs {
		if jobName != "go-and-policy" && !slices.Contains(gate.Needs, jobName) {
			return nil, fmt.Errorf("go-and-policy needs omits job %q", jobName)
		}
	}

	// Fairness: every matrix has max-parallel and the worst-case number of
	// concurrently runnable hosted jobs in one run stays <= 10.
	if _, err := validateFairness(body); err != nil {
		return nil, err
	}

	// Verify cache policy (item 10): setup-go cache: false everywhere, cache/save main-only.
	if err := validateWorkflowCachePolicy("ci.yml", &wf); err != nil {
		return nil, err
	}

	// Nightly coverage guard: schedule-only, read-only API, no time window.
	if err := validateNightlyGuardStatic(&wf); err != nil {
		return nil, err
	}

	// Execute the actual gate script: it must never pass when any proof
	// failed, was cancelled, or was skipped on a full-scope run, and never
	// accept a reduced scope for an event/ref that cannot produce it.
	if err := verifyGateBehavior(&wf); err != nil {
		return nil, err
	}

	return &wf, nil
}

// keepsRunningAfterFailure reports whether a job condition keeps the
// "run unless the workflow was cancelled" semantics: it starts with
// !cancelled() and has no other status function or needs result test that
// could turn an unrelated predecessor failure or skip into a skip.
func keepsRunningAfterFailure(condition string) bool {
	if !strings.HasPrefix(condition, "${{ !cancelled() && ") && condition != "${{ !cancelled() }}" {
		return false
	}
	for _, token := range []string{"success()", "failure()", "always()", ".result"} {
		if strings.Contains(condition, token) {
			return false
		}
	}
	return true
}

func validateCapacityEdges(wf *workflowFile, bulkNeeds []string) error {
	barrier := map[string][]string{
		"classify":              nil,
		"installer-diagnostics": {"classify"},
		"install-engine-race":   bulkNeeds,
		"envtest":               bulkNeeds,
	}
	for _, name := range slices.Sorted(maps.Keys(wf.Jobs)) {
		if name == "go-and-policy" {
			continue // always(): the aggregate must observe every result.
		}
		job := wf.Jobs[name]
		allowed, ok := barrier[name]
		if !ok {
			allowed = []string{"classify", "installer-diagnostics"}
		}
		var capacity []string
		for _, need := range job.Needs {
			if !slices.Contains(allowed, need) {
				capacity = append(capacity, need)
			}
		}
		if len(capacity) > 0 && !keepsRunningAfterFailure(job.If) {
			return fmt.Errorf("job %q has capacity-only needs %v but its if %q lacks !cancelled() semantics; an unrelated earlier failure would skip it", name, capacity, job.If)
		}
	}
	return nil
}

func validateConcurrency(wf *workflowFile) error {
	const wantGroup = "ci-${{ github.workflow }}-${{ github.event.pull_request.number || github.ref }}"
	const wantCancel = "${{ github.event_name == 'pull_request' }}"
	if len(wf.Concurrency) != 2 {
		return fmt.Errorf("workflow concurrency must have exactly group and cancel-in-progress, got %v", wf.Concurrency)
	}
	if group, ok := wf.Concurrency["group"].(string); !ok || group != wantGroup {
		return fmt.Errorf("workflow concurrency group = %#v, want %q", wf.Concurrency["group"], wantGroup)
	}
	if cancel, ok := wf.Concurrency["cancel-in-progress"].(string); !ok || cancel != wantCancel {
		return fmt.Errorf("workflow concurrency cancel-in-progress = %#v, want %q", wf.Concurrency["cancel-in-progress"], wantCancel)
	}
	return nil
}

const gateStepName = "Require every foundation, lifecycle and Go/policy proof"

// verifyGateBehavior runs the go-and-policy gate's own Bash, as GitHub runs an
// unspecified-shell step (bash -e), against synthetic needs results. It derives
// the result variables from the step env, after first requiring that every job
// in the gate's needs is wired to exactly one ${{ needs.<job>.result }}.
func verifyGateBehavior(wf *workflowFile) error {
	gate := wf.Jobs["go-and-policy"]
	var step *workflowStep
	for i := range gate.Steps {
		if gate.Steps[i].Name == gateStepName {
			step = &gate.Steps[i]
		}
	}
	if step == nil {
		return fmt.Errorf("gate step %q missing", gateStepName)
	}
	if step.If != "" || step.ContinueOnError != nil {
		return fmt.Errorf("gate step must be unconditional and not continue-on-error (if=%q continue-on-error=%v)", step.If, step.ContinueOnError)
	}
	resultVar := map[string]string{} // job -> env var
	for name, value := range step.Env {
		job, ok := strings.CutPrefix(value, "${{ needs.")
		if !ok {
			continue
		}
		job, ok = strings.CutSuffix(job, ".result }}")
		if !ok {
			continue
		}
		if previous, dup := resultVar[job]; dup {
			return fmt.Errorf("gate wires needs.%s.result twice (%s, %s)", job, previous, name)
		}
		resultVar[job] = name
	}
	for _, job := range gate.Needs {
		if _, ok := resultVar[job]; !ok {
			return fmt.Errorf("gate step env does not read needs.%s.result", job)
		}
	}
	scopeVar := ""
	for name, value := range step.Env {
		if value == "${{ needs.classify.outputs.scope }}" {
			scopeVar = name
		}
	}
	if scopeVar == "" {
		return fmt.Errorf("gate step env does not read needs.classify.outputs.scope")
	}
	// The gate must know which event/ref produced the scope (spec item 2).
	if step.Env["CI_EVENT_NAME"] != "${{ github.event_name }}" {
		return fmt.Errorf("gate step env must bind CI_EVENT_NAME=${{ github.event_name }}, got %q", step.Env["CI_EVENT_NAME"])
	}
	if step.Env["CI_REF"] != "${{ github.ref }}" {
		return fmt.Errorf("gate step env must bind CI_REF=${{ github.ref }}, got %q", step.Env["CI_REF"])
	}
	cheapJobs := []string{"installer-diagnostics", "go-policy-checks"}
	var proofJobs []string // everything except the classifier
	for _, job := range gate.Needs {
		if job != "classify" {
			proofJobs = append(proofJobs, job)
		}
	}
	slices.Sort(proofJobs)

	type eventRef struct{ event, ref string }
	runAt := func(scope string, at eventRef, results map[string]string) error {
		cmd := exec.Command("bash", "--noprofile", "--norc", "-e", "-c", step.Run)
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), scopeVar + "=" + scope, "CI_EVENT_NAME=" + at.event, "CI_REF=" + at.ref}
		for job, name := range resultVar {
			cmd.Env = append(cmd.Env, name+"="+results[job])
		}
		return cmd.Run()
	}
	// Each scope's result table below runs under an event/ref that can
	// legitimately produce it; the event/ref truth table follows at the end.
	typical := map[string]eventRef{
		"full":  {"pull_request", "refs/pull/1/merge"},
		"cheap": {"push", "refs/heads/main"},
		"docs":  {"pull_request", "refs/pull/1/merge"},
		"idle":  {"schedule", "refs/heads/main"},
	}
	run := func(scope string, results map[string]string) error {
		at, ok := typical[scope]
		if !ok {
			at = eventRef{"push", "refs/heads/main"}
		}
		return runAt(scope, at, results)
	}
	uniform := func(classify, proofs string) map[string]string {
		m := map[string]string{"classify": classify}
		for _, job := range proofJobs {
			m[job] = proofs
		}
		return m
	}
	with := func(base map[string]string, job, result string) map[string]string {
		m := maps.Clone(base)
		m[job] = result
		return m
	}
	mustPass := func(label, scope string, results map[string]string) error {
		if err := run(scope, results); err != nil {
			return fmt.Errorf("gate behavior: %s must pass, got %v", label, err)
		}
		return nil
	}
	mustFail := func(label, scope string, results map[string]string) error {
		if err := run(scope, results); err == nil {
			return fmt.Errorf("gate behavior: %s must fail, but the gate passed", label)
		}
		return nil
	}

	allGreen := uniform("success", "success")
	if err := mustPass("full scope, every proof succeeded", "full", allGreen); err != nil {
		return err
	}
	for _, job := range proofJobs {
		for _, bad := range []string{"failure", "cancelled", "skipped", ""} {
			if err := mustFail(fmt.Sprintf("full scope with %s=%q", job, bad), "full", with(allGreen, job, bad)); err != nil {
				return err
			}
		}
	}
	for _, bad := range []string{"failure", "cancelled", "skipped"} {
		if err := mustFail("classifier "+bad+" with full scope", "full", with(allGreen, "classify", bad)); err != nil {
			return err
		}
	}
	for _, scope := range []string{"", "unknown", "FULL", "docs ", "cheap\nfull"} {
		if err := mustFail(fmt.Sprintf("scope %q with every proof green", scope), scope, allGreen); err != nil {
			return err
		}
	}

	cheap := uniform("success", "skipped")
	for _, job := range cheapJobs {
		cheap[job] = "success"
	}
	if err := mustPass("cheap scope, diagnostics and Go/policy checks green", "cheap", cheap); err != nil {
		return err
	}
	for _, job := range proofJobs {
		for _, bad := range []string{"failure", "cancelled"} {
			if err := mustFail(fmt.Sprintf("cheap scope with %s=%s", job, bad), "cheap", with(cheap, job, bad)); err != nil {
				return err
			}
		}
	}
	for _, job := range cheapJobs {
		if err := mustFail("cheap scope with "+job+" skipped", "cheap", with(cheap, job, "skipped")); err != nil {
			return err
		}
	}

	for _, scope := range []string{"docs", "idle"} {
		skipped := uniform("success", "skipped")
		if err := mustPass(scope+" scope, every proof skipped", scope, skipped); err != nil {
			return err
		}
		for _, job := range proofJobs {
			for _, other := range []string{"failure", "cancelled", "success"} {
				if err := mustFail(fmt.Sprintf("%s scope with %s=%s", scope, job, other), scope, with(skipped, job, other)); err != nil {
					return err
				}
			}
		}
		if err := mustFail(scope+" scope with classifier failure", scope, with(skipped, "classify", "failure")); err != nil {
			return err
		}
	}

	// Event/ref truth table (spec item 2): cheap only on push to
	// refs/heads/main; idle only on schedule on refs/heads/main; docs only on
	// pull_request or push to refs/heads/main. Each scope is given results
	// that pass under a valid event, so only the event/ref decides.
	scopeGreen := map[string]map[string]string{
		"cheap": cheap,
		"idle":  uniform("success", "skipped"),
		"docs":  uniform("success", "skipped"),
	}
	pairs := []eventRef{
		{"pull_request", "refs/pull/1/merge"}, {"pull_request", "refs/heads/main"},
		{"push", "refs/heads/main"}, {"push", "refs/heads/topic"}, {"push", "refs/tags/v1.0.0"}, {"push", ""}, {"push", "refs/heads/main "}, {"push", "refs/heads/mainline"},
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
		for _, at := range pairs {
			passed := runAt(scope, at, scopeGreen[scope]) == nil
			if want := slices.Contains(valid[scope], at); passed != want {
				verb := "must fail, but the gate passed"
				if want {
					verb = "must pass, but the gate failed"
				}
				return fmt.Errorf("gate behavior: %s scope with event %q ref %q %s", scope, at.event, at.ref, verb)
			}
		}
	}
	// full is the fail-safe scope: any trigger may produce it.
	for _, at := range []eventRef{{"pull_request", "refs/pull/1/merge"}, {"push", "refs/heads/main"}, {"schedule", "refs/heads/main"}, {"workflow_dispatch", "refs/heads/topic"}} {
		if err := runAt("full", at, allGreen); err != nil {
			return fmt.Errorf("gate behavior: full scope with every proof green on event %q ref %q must pass, got %v", at.event, at.ref, err)
		}
	}
	return nil
}

// maxConcurrentHostedJobs is the per-run fairness cap on GitHub-hosted jobs.
const maxConcurrentHostedJobs = 10

type fairnessJob struct {
	name   string
	legs   int // expanded matrix size; 1 for a non-matrix job
	cap    int // strategy.max-parallel; 0 for a non-matrix job
	weight int // min(cap, legs); 1 for a non-matrix job
}

type fairnessPhase struct {
	jobs []string // a maximal set of jobs not ordered by (transitive) needs
	sum  int
}

type fairnessReport struct {
	jobs   map[string]fairnessJob
	phases []fairnessPhase // every maximal antichain, largest sum first
	max    int
}

// lines renders the per-phase arithmetic for t.Log and validation notes.
func (r *fairnessReport) lines() []string {
	var out []string
	for _, name := range slices.Sorted(maps.Keys(r.jobs)) {
		job := r.jobs[name]
		if job.cap > 0 {
			out = append(out, fmt.Sprintf("weight %-28s = min(max-parallel %d, matrix legs %d) = %d", name, job.cap, job.legs, job.weight))
		}
	}
	for i, phase := range r.phases {
		var terms []string
		for _, name := range phase.jobs {
			terms = append(terms, fmt.Sprintf("%s %d", name, r.jobs[name].weight))
		}
		out = append(out, fmt.Sprintf("phase %2d: %s = %d", i+1, strings.Join(terms, " + "), phase.sum))
	}
	out = append(out, fmt.Sprintf("worst case = max over %d maximal antichains = %d (cap %d)", len(r.phases), r.max, maxConcurrentHostedJobs))
	return out
}

// validateFairness requires strategy.max-parallel (integer >= 1) on every
// matrix job and bounds the worst-case number of concurrently runnable jobs
// in one run: the maximum, over all sets of jobs that the needs graph does
// not order (antichains of the transitive needs relation), of the sum of
// min(max-parallel, matrix size), counting a non-matrix job as 1. This holds
// for any job results and durations, because needs order is unconditional.
func validateFairness(body []byte) (*fairnessReport, error) {
	var raw struct {
		Jobs map[string]struct {
			Needs    any `yaml:"needs"`
			Strategy *struct {
				MaxParallel any `yaml:"max-parallel"`
				Matrix      any `yaml:"matrix"`
			} `yaml:"strategy"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("fairness: unmarshal: %w", err)
	}
	report := &fairnessReport{jobs: map[string]fairnessJob{}}
	needs := map[string][]string{}
	for name, job := range raw.Jobs {
		switch v := job.Needs.(type) {
		case nil:
		case string:
			needs[name] = []string{v}
		case []any:
			for _, need := range v {
				s, ok := need.(string)
				if !ok {
					return nil, fmt.Errorf("fairness: job %q has a non-string needs entry %v", name, need)
				}
				needs[name] = append(needs[name], s)
			}
		default:
			return nil, fmt.Errorf("fairness: job %q has unsupported needs %T", name, job.Needs)
		}
		entry := fairnessJob{name: name, legs: 1, weight: 1}
		if job.Strategy != nil && job.Strategy.Matrix != nil {
			legs, err := matrixLegs(name, job.Strategy.Matrix)
			if err != nil {
				return nil, err
			}
			if job.Strategy.MaxParallel == nil {
				return nil, fmt.Errorf("job %q has a strategy.matrix (%d legs) but no strategy.max-parallel", name, legs)
			}
			limit, ok := job.Strategy.MaxParallel.(int)
			if !ok || limit < 1 {
				return nil, fmt.Errorf("job %q strategy.max-parallel = %#v, want a literal integer >= 1", name, job.Strategy.MaxParallel)
			}
			entry.legs, entry.cap, entry.weight = legs, limit, min(limit, legs)
		}
		report.jobs[name] = entry
	}

	// Transitive needs closure; unknown or cyclic needs are errors.
	ancestors := map[string]map[string]bool{}
	state := map[string]int{}
	var visit func(string) error
	visit = func(name string) error {
		switch state[name] {
		case 1:
			return fmt.Errorf("fairness: needs cycle through job %q", name)
		case 2:
			return nil
		}
		state[name] = 1
		set := map[string]bool{}
		for _, need := range needs[name] {
			if _, ok := report.jobs[need]; !ok {
				return fmt.Errorf("fairness: job %q needs unknown job %q", name, need)
			}
			if err := visit(need); err != nil {
				return err
			}
			set[need] = true
			for a := range ancestors[need] {
				set[a] = true
			}
		}
		ancestors[name] = set
		state[name] = 2
		return nil
	}
	names := slices.Sorted(maps.Keys(report.jobs))
	for _, name := range names {
		if err := visit(name); err != nil {
			return nil, err
		}
	}
	unordered := func(a, b string) bool {
		return a != b && !ancestors[a][b] && !ancestors[b][a]
	}

	// Bron-Kerbosch over the "not ordered by needs" relation enumerates every
	// maximal antichain; with positive weights the maximum is attained there.
	var enumerate func(chosen, candidates, excluded []string)
	enumerate = func(chosen, candidates, excluded []string) {
		if len(candidates) == 0 && len(excluded) == 0 {
			phase := fairnessPhase{jobs: slices.Clone(chosen)}
			for _, name := range chosen {
				phase.sum += report.jobs[name].weight
			}
			report.phases = append(report.phases, phase)
			return
		}
		for len(candidates) > 0 {
			v := candidates[0]
			keep := func(set []string) []string {
				var out []string
				for _, s := range set {
					if unordered(v, s) {
						out = append(out, s)
					}
				}
				return out
			}
			enumerate(append(slices.Clone(chosen), v), keep(candidates), keep(excluded))
			candidates = candidates[1:]
			excluded = append(slices.Clone(excluded), v)
		}
	}
	enumerate(nil, names, nil)
	slices.SortStableFunc(report.phases, func(a, b fairnessPhase) int {
		if a.sum != b.sum {
			return b.sum - a.sum
		}
		return strings.Compare(strings.Join(a.jobs, ","), strings.Join(b.jobs, ","))
	})
	for _, phase := range report.phases {
		report.max = max(report.max, phase.sum)
	}
	if report.max > maxConcurrentHostedJobs {
		worst := report.phases[0]
		var terms []string
		for _, name := range worst.jobs {
			terms = append(terms, fmt.Sprintf("%s %d", name, report.jobs[name].weight))
		}
		return report, fmt.Errorf("worst-case concurrent hosted jobs = %d > %d: %s", report.max, maxConcurrentHostedJobs, strings.Join(terms, " + "))
	}
	return report, nil
}

// matrixLegs expands a literal strategy.matrix the way GitHub does: the
// Cartesian product of its list keys, minus exclude entries that match on
// every key they name, plus each include entry that cannot be merged into an
// existing combination without overwriting an original matrix value.
func matrixLegs(job string, matrix any) (int, error) {
	m, ok := matrix.(map[string]any)
	if !ok {
		return 0, fmt.Errorf("job %q strategy.matrix must be a literal mapping to bound its size, got %T", job, matrix)
	}
	canon := func(v any) string { return fmt.Sprint(v) }
	var keys []string
	for key := range m {
		if key != "include" && key != "exclude" {
			keys = append(keys, key)
		}
	}
	slices.Sort(keys)
	var combos []map[string]string
	if len(keys) > 0 {
		combos = []map[string]string{{}}
	}
	for _, key := range keys {
		values, ok := m[key].([]any)
		if !ok || len(values) == 0 {
			return 0, fmt.Errorf("job %q matrix key %q must be a non-empty literal list", job, key)
		}
		var next []map[string]string
		for _, combo := range combos {
			for _, value := range values {
				c := maps.Clone(combo)
				c[key] = canon(value)
				next = append(next, c)
			}
		}
		combos = next
	}
	entries := func(field string) ([]map[string]any, error) {
		rawList, present := m[field]
		if !present {
			return nil, nil
		}
		list, ok := rawList.([]any)
		if !ok {
			return nil, fmt.Errorf("job %q matrix %s must be a literal list", job, field)
		}
		var out []map[string]any
		for _, item := range list {
			entry, ok := item.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("job %q matrix %s entry must be a mapping, got %T", job, field, item)
			}
			out = append(out, entry)
		}
		return out, nil
	}
	excludes, err := entries("exclude")
	if err != nil {
		return 0, err
	}
	for _, ex := range excludes {
		for key := range ex {
			if !slices.Contains(keys, key) {
				return 0, fmt.Errorf("job %q matrix exclude names unknown key %q", job, key)
			}
		}
		combos = slices.DeleteFunc(combos, func(c map[string]string) bool {
			for key, value := range ex {
				if c[key] != canon(value) {
					return false
				}
			}
			return true
		})
	}
	includes, err := entries("include")
	if err != nil {
		return 0, err
	}
	added := 0
	for _, inc := range includes {
		merged := false
		for _, c := range combos {
			compatible := true
			for key, value := range inc {
				if slices.Contains(keys, key) && c[key] != canon(value) {
					compatible = false
				}
			}
			merged = merged || compatible
		}
		if !merged {
			added++
		}
	}
	legs := len(combos) + added
	if legs == 0 {
		return 0, fmt.Errorf("job %q matrix expands to zero legs", job)
	}
	return legs, nil
}

// nightlyTimeTokens would indicate a time-window freshness heuristic
// instead of proof by the same main SHA.
var nightlyTimeTokens = []string{"datetime", "timedelta", "time.time", "import time", "strptime", "fromisoformat", "utcnow", "created_at", "updated_at", "run_started_at", "created=", "\"created\"", "hours", "date -", "date +"}

func findStep(job workflowJob, id string) (int, *workflowStep) {
	for i := range job.Steps {
		if job.Steps[i].ID == id {
			return i, &job.Steps[i]
		}
	}
	return -1, nil
}

func validateNightlyGuardStatic(wf *workflowFile) error {
	classify := wf.Jobs["classify"]
	wantPerms := map[string]string{"contents": "read", "actions": "read"}
	if !maps.Equal(classify.Permissions, wantPerms) {
		return fmt.Errorf("classify permissions = %v, want exactly %v", classify.Permissions, wantPerms)
	}
	nightlyIndex, nightly := findStep(classify, "nightly")
	if nightly == nil {
		return fmt.Errorf("classify has no step with id nightly")
	}
	if nightly.If != "github.event_name == 'schedule'" && nightly.If != "${{ github.event_name == 'schedule' }}" {
		return fmt.Errorf("nightly guard step must run only on schedule, if = %q", nightly.If)
	}
	if nightly.ContinueOnError != nil {
		return fmt.Errorf("nightly guard step must not set continue-on-error")
	}
	scopeIndex, scope := findStep(classify, "scope")
	if scope == nil || scopeIndex < nightlyIndex || scope.Env["NIGHTLY_SKIP"] != "${{ steps.nightly.outputs.skip }}" {
		return fmt.Errorf("classify scope step must follow the nightly guard and read NIGHTLY_SKIP=${{ steps.nightly.outputs.skip }}")
	}
	ghWord := regexp.MustCompile(`\bgh\b`)
	getCalls := strings.Count(nightly.Run, `"gh", "api", "--method", "GET"`) + strings.Count(nightly.Run, "gh api --method GET")
	if uses := len(ghWord.FindAllString(nightly.Run, -1)); uses == 0 || uses != getCalls {
		return fmt.Errorf("nightly guard must call gh only as `gh api --method GET` (%d gh uses, %d GET calls)", uses, getCalls)
	}
	lower := strings.ToLower(nightly.Run)
	for _, forbidden := range []string{`"post"`, `"patch"`, `"put"`, `"delete"`, "graphql", "--input", `"-x"`, " -x ", "--method post", "--method put", "--method patch", "--method delete"} {
		if strings.Contains(lower, forbidden) {
			return fmt.Errorf("nightly guard contains non-GET API token %q", forbidden)
		}
	}
	for _, token := range nightlyTimeTokens {
		if strings.Contains(lower, token) {
			return fmt.Errorf("nightly guard contains time-window logic token %q; coverage must be proven by SHA", token)
		}
	}
	return nil
}

func validateWorkflowCachePolicy(filename string, wf *workflowFile) error {
	for jobName, job := range wf.Jobs {
		for i, step := range job.Steps {
			if strings.HasPrefix(step.Uses, "actions/setup-go@") {
				cacheVal, exists := step.With["cache"]
				if !exists || cacheVal != false {
					return fmt.Errorf("%s job %q step %d (%s) must set setup-go cache: false, got %v", filename, jobName, i, step.Name, cacheVal)
				}
			}
			if strings.HasPrefix(step.Uses, "actions/cache@") {
				return fmt.Errorf("%s job %q step %d (%s) uses combined actions/cache instead of explicit restore/save", filename, jobName, i, step.Name)
			}
			if strings.HasPrefix(step.Uses, "actions/cache/save@") {
				if !strings.Contains(step.If, "github.ref == 'refs/heads/main'") ||
					!strings.Contains(step.If, "github.event_name == 'push'") ||
					!strings.Contains(step.If, "github.event_name == 'schedule'") ||
					strings.Contains(step.If, "pull_request") {
					return fmt.Errorf("%s job %q step %d (%s) saves cache without strict main push/schedule guard: %q", filename, jobName, i, step.Name, step.If)
				}
			}
		}
	}
	return nil
}

func extractClassifierPython(wf *workflowFile) (string, error) {
	return extractStepPython(wf, "scope")
}

// extractStepPython returns the PYCODE heredoc of the classify job step with
// the given id, so tests execute the workflow's own Python.
func extractStepPython(wf *workflowFile, stepID string) (string, error) {
	classifyJob, ok := wf.Jobs["classify"]
	if !ok {
		return "", fmt.Errorf("classify job missing")
	}
	for _, step := range classifyJob.Steps {
		if step.ID == stepID {
			const startMarker = "python3 - <<'PYCODE'\n"
			const endMarker = "\nPYCODE"
			start := strings.Index(step.Run, startMarker)
			end := strings.LastIndex(step.Run, endMarker)
			if start == -1 || end == -1 || end <= start+len(startMarker) {
				return "", fmt.Errorf("classify %s step does not contain expected PYCODE heredoc", stepID)
			}
			return step.Run[start+len(startMarker) : end], nil
		}
	}
	return "", fmt.Errorf("classify %s step not found", stepID)
}

func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func evaluateClassifierScript(t *testing.T, pyScript, repoDir, eventName string, eventPayload any, extraEnv map[string]string) string {
	t.Helper()
	tmpDir := t.TempDir()
	eventPath := filepath.Join(tmpDir, "event.json")
	if eventPayload != nil {
		raw, err := json.Marshal(eventPayload)
		if err != nil {
			t.Fatalf("marshal event payload: %v", err)
		}
		if err := os.WriteFile(eventPath, raw, 0o600); err != nil {
			t.Fatalf("write event file: %v", err)
		}
	} else {
		if err := os.WriteFile(eventPath, []byte("{invalid-json"), 0o600); err != nil {
			t.Fatalf("write invalid event file: %v", err)
		}
	}
	outputPath := filepath.Join(tmpDir, "github_output.txt")
	cmd := exec.Command("python3", "-c", pyScript)
	cmd.Dir = repoDir
	cmd.Env = append(os.Environ(),
		"EVENT_NAME="+eventName,
		"GITHUB_EVENT_PATH="+eventPath,
		"GITHUB_OUTPUT="+outputPath,
	)
	for k, v := range extraEnv {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("classifier script exited non-zero: %v\n%s", err, out)
	}
	outputBytes, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read GITHUB_OUTPUT: %v", err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(outputBytes)), "\n") {
		if scope, ok := strings.CutPrefix(line, "scope="); ok {
			return scope
		}
	}
	t.Fatalf("GITHUB_OUTPUT missing scope= line: %q", string(outputBytes))
	return ""
}

func verifyClassifierFailSafe(t *testing.T, wf *workflowFile) error {
	t.Helper()
	pyScript, err := extractClassifierPython(wf)
	if err != nil {
		return err
	}
	repoDir := t.TempDir()
	runGit(t, repoDir, "init", "-b", "main")
	runGit(t, repoDir, "config", "user.name", "Test")
	runGit(t, repoDir, "config", "user.email", "test@example.invalid")
	// Developer machines may enforce signing globally; fixture commits are throwaway.
	runGit(t, repoDir, "config", "commit.gpgsign", "false")

	writeFiles := func(files map[string]string) string {
		for rel, content := range files {
			full := filepath.Join(repoDir, rel)
			if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		runGit(t, repoDir, "add", "-A")
		runGit(t, repoDir, "commit", "-m", "commit")
		return runGit(t, repoDir, "rev-parse", "HEAD")
	}

	baseSHA := writeFiles(map[string]string{
		"README.md":             "# Arcadectl\n",
		"cmd/main.go":           "package main\nfunc main() {}\n",
		"Makefile":              "all:\n\t@true\n",
		".github/workflows/x.y": "name: X\n",
	})

	type scenario struct {
		name      string
		files     map[string]string
		eventName string
		wantPR    string
		wantPush  string
	}
	scenarios := []scenario{
		{
			name: "docs and lint config only",
			files: map[string]string{
				"README.md":            "# Updated\n",
				"docs/architecture.md": "# Arch\n",
				"LICENSE":              "Apache-2.0\n",
				"NOTICE.txt":           "Notice\n",
				".golangci.yml":        "run: {}\n",
				".editorconfig":        "root = true\n",
				".markdownlint.json":   "{}\n",
			},
			wantPR:   "docs",
			wantPush: "docs",
		},
		{
			name: "docs plus go source file",
			files: map[string]string{
				"README.md":   "# Updated\n",
				"cmd/main.go": "package main\nfunc main() { println(1) }\n",
			},
			wantPR:   "full",
			wantPush: "cheap",
		},
		{
			name: "workflow markdown file is denied",
			files: map[string]string{
				".github/workflows/x.md": "# Workflow doc\n",
			},
			wantPR:   "full",
			wantPush: "cheap",
		},
		{
			name: "hack markdown file is denied",
			files: map[string]string{
				"hack/foo.md": "# Hack doc\n",
			},
			wantPR:   "full",
			wantPush: "cheap",
		},
		{
			name: "config markdown file is denied",
			files: map[string]string{
				"config/foo.md": "# Config doc\n",
			},
			wantPR:   "full",
			wantPush: "cheap",
		},
		{
			name: "nested markdownlint config is denied",
			files: map[string]string{
				"sub/.markdownlint.json": "{}\n",
			},
			wantPR:   "full",
			wantPush: "cheap",
		},
		// docs/generated/** is generator output verified by CI, never docs-only.
		{
			name: "generated CLI command reference is not docs",
			files: map[string]string{
				"docs/generated/cli/commands.md": "# arcadectl commands\n",
			},
			wantPR:   "full",
			wantPush: "cheap",
		},
		{
			name: "generated bash completion is not docs",
			files: map[string]string{
				"docs/generated/cli/arcadectl.bash": "# bash completion\n",
			},
			wantPR:   "full",
			wantPush: "cheap",
		},
		{
			name: "generated zsh completion is not docs",
			files: map[string]string{
				"docs/generated/cli/_arcadectl": "#compdef arcadectl\n",
			},
			wantPR:   "full",
			wantPush: "cheap",
		},
		{
			name: "plain docs plus generated docs is not docs",
			files: map[string]string{
				"docs/architecture.md":           "# Arch v2\n",
				"README.md":                      "# Updated again\n",
				"docs/generated/cli/commands.md": "# arcadectl commands v2\n",
			},
			wantPR:   "full",
			wantPush: "cheap",
		},
	}

	for _, sc := range scenarios {
		runGit(t, repoDir, "checkout", "-q", "-B", "branch-"+strings.ReplaceAll(sc.name, " ", "-"), baseSHA)
		headSHA := writeFiles(sc.files)
		prEvent := map[string]any{
			"pull_request": map[string]any{
				"base": map[string]any{"sha": baseSHA},
				"head": map[string]any{"sha": headSHA},
			},
		}
		if got := evaluateClassifierScript(t, pyScript, repoDir, "pull_request", prEvent, nil); got != sc.wantPR {
			return fmt.Errorf("classifier PR scenario %q: got scope %q, want %q", sc.name, got, sc.wantPR)
		}
		pushEvent := map[string]any{
			"ref":    "refs/heads/main",
			"before": baseSHA,
			"after":  headSHA,
		}
		if got := evaluateClassifierScript(t, pyScript, repoDir, "push", pushEvent, nil); got != sc.wantPush {
			return fmt.Errorf("classifier push scenario %q: got scope %q, want %q", sc.name, got, sc.wantPush)
		}
	}

	// Fail-safe checks: zero before, forced push, empty diff, unknown event, malformed event JSON, schedule/dispatch.
	runGit(t, repoDir, "checkout", "-q", baseSHA)
	zeroBefore := map[string]any{
		"ref":    "refs/heads/main",
		"before": strings.Repeat("0", 40),
		"after":  baseSHA,
	}
	if got := evaluateClassifierScript(t, pyScript, repoDir, "push", zeroBefore, nil); got != "full" {
		return fmt.Errorf("zero-before push must fail safe to full, got %q", got)
	}
	forcedPush := map[string]any{
		"ref":    "refs/heads/main",
		"before": baseSHA,
		"after":  baseSHA,
		"forced": true,
	}
	if got := evaluateClassifierScript(t, pyScript, repoDir, "push", forcedPush, nil); got != "full" {
		return fmt.Errorf("forced push must fail safe to full, got %q", got)
	}
	emptyDiffPR := map[string]any{
		"pull_request": map[string]any{
			"base": map[string]any{"sha": baseSHA},
			"head": map[string]any{"sha": baseSHA},
		},
	}
	if got := evaluateClassifierScript(t, pyScript, repoDir, "pull_request", emptyDiffPR, nil); got != "full" {
		return fmt.Errorf("empty-diff PR must fail safe to full, got %q", got)
	}
	if got := evaluateClassifierScript(t, pyScript, repoDir, "pull_request_target", emptyDiffPR, nil); got != "full" {
		return fmt.Errorf("unknown event must fail safe to full, got %q", got)
	}
	if got := evaluateClassifierScript(t, pyScript, repoDir, "pull_request", nil, nil); got != "full" {
		return fmt.Errorf("corrupt event payload must fail safe to full, got %q", got)
	}
	if got := evaluateClassifierScript(t, pyScript, repoDir, "workflow_dispatch", map[string]any{}, map[string]string{"NIGHTLY_SKIP": "true"}); got != "full" {
		return fmt.Errorf("workflow_dispatch must always select full, got %q", got)
	}
	if got := evaluateClassifierScript(t, pyScript, repoDir, "schedule", map[string]any{}, map[string]string{"NIGHTLY_SKIP": "false"}); got != "full" {
		return fmt.Errorf("schedule with NIGHTLY_SKIP=false must select full, got %q", got)
	}
	if got := evaluateClassifierScript(t, pyScript, repoDir, "schedule", map[string]any{}, map[string]string{"NIGHTLY_SKIP": "true"}); got != "idle" {
		return fmt.Errorf("schedule with NIGHTLY_SKIP=true must select idle, got %q", got)
	}
	return nil
}

// ghStub emulates the read-only subset of the GitHub REST API that a
// same-SHA nightly coverage guard can use, from a JSON fixture. It logs every
// argv, refuses anything but GET and time-window ("created") filters, and
// exits non-zero (like gh on HTTP errors) for failures and unknown endpoints.
const ghStub = `#!/usr/bin/env python3
import json, os, re, sys, urllib.parse

args = sys.argv[1:]
with open(os.environ["GH_STUB_LOG"], "a") as log:
    log.write(json.dumps(args) + "\n")
with open(os.environ["GH_STUB_FIXTURE"]) as f:
    fx = json.load(f)

def fail(msg):
    sys.stderr.write(msg + "\n")
    sys.exit(1)

def out(obj):
    sys.stdout.write(json.dumps(obj))
    sys.exit(0)

if fx.get("fail_all"):
    fail("HTTP 502: stub outage")
if not args or args[0] != "api":
    fail("stub supports only gh api")
method, endpoint, fields, i = "GET", None, {}, 1
while i < len(args):
    a = args[i]
    if a in ("--method", "-X"):
        method = args[i + 1]; i += 2; continue
    if a in ("-f", "-F", "--field", "--raw-field"):
        k, _, v = args[i + 1].partition("="); fields[k] = v; i += 2; continue
    if a in ("-H", "--header", "--jq", "-q", "--template", "-t", "--hostname", "--cache", "-p", "--preview"):
        i += 2; continue
    if a.startswith("-"):
        i += 1; continue
    if endpoint is None:
        endpoint = a
    i += 1
if method.upper() != "GET" or endpoint is None:
    fail("stub refuses non-GET requests")
path, _, query = endpoint.lstrip("/").partition("?")
params = dict(urllib.parse.parse_qsl(query))
params.update(fields)
if "created" in params:
    fail("time-window filters are not supported")
prefix = "repos/" + fx["repo"] + "/"
if not path.startswith(prefix):
    fail("HTTP 404")
path = path[len(prefix):]
failing = set(fx.get("fail", []))
runs = fx["runs"]
by_id = {str(r["id"]): r for r in runs}

if path in ("commits/main", "commits/heads/main", "commits/refs/heads/main",
            "branches/main", "git/ref/heads/main", "git/refs/heads/main"):
    if "commit" in failing:
        fail("HTTP 502")
    sha = fx["main_sha"]
    if path.startswith("commits/"):
        out({"sha": sha})
    if path.startswith("branches/"):
        out({"name": "main", "commit": {"sha": sha}})
    out({"ref": "refs/heads/main", "object": {"type": "commit", "sha": sha}})

m = re.fullmatch(r"actions/runs/(\d+)", path)
if m:
    if "run" in failing:
        fail("HTTP 502")
    if m.group(1) not in by_id:
        fail("HTTP 404")
    out(by_id[m.group(1)])

m = re.fullmatch(r"actions/runs/(\d+)(?:/attempts/(\d+))?/jobs", path)
if m:
    if "jobs" in failing:
        fail("HTTP 502")
    run = by_id.get(m.group(1))
    if run is None:
        fail("HTTP 404")
    jobs = fx["jobs"].get(m.group(1), [])
    if m.group(2) is not None and int(m.group(2)) != run["run_attempt"]:
        jobs = []
    per_page, page = int(params.get("per_page", "30")), int(params.get("page", "1"))
    out({"total_count": fx.get("jobs_total", len(jobs)),
         "jobs": jobs[(page - 1) * per_page: page * per_page]})

m = re.fullmatch(r"actions/(?:workflows/([^/]+)/)?runs", path)
if m:
    if "runs" in failing:
        fail("HTTP 502")
    workflow, selected = m.group(1), []
    for r in runs:
        if workflow is not None and workflow not in (str(r["workflow_id"]), r["path"].rsplit("/", 1)[-1]):
            continue
        if "branch" in params and r["head_branch"] != params["branch"]:
            continue
        if "head_sha" in params and r["head_sha"] != params["head_sha"]:
            continue
        if "event" in params and r["event"] != params["event"]:
            continue
        if "status" in params:
            want = params["status"]
            if want in ("completed", "in_progress", "queued", "requested", "waiting", "pending"):
                if r["status"] != want:
                    continue
            elif r["conclusion"] != want:
                continue
        selected.append(r)
    selected.sort(key=lambda r: r["id"], reverse=True)
    per_page, page = int(params.get("per_page", "30")), int(params.get("page", "1"))
    out({"total_count": fx.get("runs_total", len(selected)),
         "workflow_runs": selected[(page - 1) * per_page: page * per_page]})

fail("HTTP 404: unsupported stub endpoint " + path)
`

// verifyNightlyGuard runs the nightly step's own Python with a stub gh on
// PATH (never the real gh or network) and requires fail-safe skip=false
// unless a prior successful schedule run of the same SHA proves every job,
// including exactly one "Kind lifecycle" and one "Go and policy", succeeded.
func verifyNightlyGuard(t *testing.T, wf *workflowFile) error {
	t.Helper()
	script, err := extractStepPython(wf, "nightly")
	if err != nil {
		return err
	}
	_, step := findStep(wf.Jobs["classify"], "nightly")
	const (
		repo       = "gobha-me/arcadectl"
		sha        = "0123456789abcdef0123456789abcdef01234567"
		otherSHA   = "89abcdef0123456789abcdef0123456789abcdef"
		workflowID = 77
		currentID  = 5000
	)
	fakeContext := map[string]string{
		"${{ github.token }}":         "stub-token-not-a-secret",
		"${{ secrets.GITHUB_TOKEN }}": "stub-token-not-a-secret",
		"${{ github.repository }}":    repo,
		"${{ github.sha }}":           sha,
		"${{ github.ref }}":           "refs/heads/main",
		"${{ github.ref_name }}":      "main",
		"${{ github.run_id }}":        strconv.Itoa(currentID),
		"${{ github.run_attempt }}":   "1",
		"${{ github.event_name }}":    "schedule",
		"${{ github.workflow }}":      "CI",
	}
	var stepEnv []string
	for _, name := range slices.Sorted(maps.Keys(step.Env)) {
		value, ok := fakeContext[step.Env[name]]
		if !ok {
			return fmt.Errorf("nightly guard env %s=%s has no stub fixture value", name, step.Env[name])
		}
		stepEnv = append(stepEnv, name+"="+value)
	}

	const longAgo = "2020-01-01T01:00:00Z" // a time window would reject this run
	run := func(id int, event, status, conclusion, runSHA, branch string) map[string]any {
		var concl any
		if conclusion != "" {
			concl = conclusion
		}
		return map[string]any{
			"id": id, "workflow_id": workflowID, "name": "CI", "path": ".github/workflows/ci.yml",
			"event": event, "status": status, "conclusion": concl, "head_sha": runSHA, "head_branch": branch,
			"run_attempt": 1, "run_number": id, "created_at": longAgo, "updated_at": longAgo, "run_started_at": longAgo,
		}
	}
	current := run(currentID, "schedule", "in_progress", "", sha, "main")
	fullJobNames := []string{
		"Classify CI scope", "Installer CLI and diagnostic controls", "Kind signed installer binary 137 transition",
		"Kind recovery failure safety", "Installer engine race shard 0", "API-server lifecycle transitions base-packages",
		"Go and policy checks", "Kind lifecycle", "Go and policy",
	}
	jobs := func(runID int, runSHA string, mutate func([]map[string]any) []map[string]any) []map[string]any {
		var out []map[string]any
		for i, name := range fullJobNames {
			out = append(out, map[string]any{
				"id": runID*100 + i, "run_id": runID, "run_attempt": 1, "head_sha": runSHA, "name": name,
				"status": "completed", "conclusion": "success", "started_at": longAgo, "completed_at": longAgo,
			})
		}
		if mutate != nil {
			out = mutate(out)
		}
		return out
	}
	setConclusion := func(name, conclusion string) func([]map[string]any) []map[string]any {
		return func(js []map[string]any) []map[string]any {
			for _, j := range js {
				if j["name"] == name {
					j["conclusion"] = conclusion
				}
			}
			return js
		}
	}
	drop := func(name string) func([]map[string]any) []map[string]any {
		return func(js []map[string]any) []map[string]any {
			return slices.DeleteFunc(js, func(j map[string]any) bool { return j["name"] == name })
		}
	}
	duplicate := func(name string) func([]map[string]any) []map[string]any {
		return func(js []map[string]any) []map[string]any {
			for _, j := range js {
				if j["name"] == name {
					c := maps.Clone(j)
					c["id"] = j["id"].(int) + 50
					return append(js, c)
				}
			}
			return js
		}
	}
	fixture := func(prior []map[string]any, jobsByRun map[int][]map[string]any) map[string]any {
		jobsJSON := map[string]any{}
		for id, js := range jobsByRun {
			jobsJSON[strconv.Itoa(id)] = js
		}
		return map[string]any{
			"repo": repo, "main_sha": sha, "runs": append([]map[string]any{current}, prior...), "jobs": jobsJSON,
		}
	}
	goodPrior := run(4000, "schedule", "completed", "success", sha, "main")
	proven := func() map[string]any {
		return fixture([]map[string]any{goodPrior}, map[int][]map[string]any{4000: jobs(4000, sha, nil)})
	}
	with := func(fx map[string]any, key string, value any) map[string]any {
		fx[key] = value
		return fx
	}
	// A full first page (100 runs) whose total_count says more exist.
	var page []map[string]any
	for i := range 99 {
		page = append(page, run(3000+i, "push", "completed", "success", sha, "main"))
	}

	type scenario struct {
		name     string
		fixture  map[string]any
		wantSkip bool
	}
	scenarios := []scenario{
		{"(i) gh api errors on every call", with(proven(), "fail_all", true), false},
		{"(i-b) gh api errors listing jobs", with(proven(), "fail", []string{"jobs"}), false},
		{"(i-c) gh api errors listing runs", with(proven(), "fail", []string{"runs"}), false},
		{"(ii) truncated run page total_count>=100", with(fixture(append(slices.Clone(page), goodPrior), map[int][]map[string]any{4000: jobs(4000, sha, nil)}), "runs_total", 150), false},
		{"(ii-b) truncated jobs page total_count>=100", with(proven(), "jobs_total", 120), false},
		{"(iii) prior successful schedule run of same SHA, every job success", proven(), true},
		{"(iv) prior run with Kind lifecycle skipped", fixture([]map[string]any{goodPrior}, map[int][]map[string]any{4000: jobs(4000, sha, setConclusion("Kind lifecycle", "skipped"))}), false},
		{"(iv-b) prior run without a Kind lifecycle job", fixture([]map[string]any{goodPrior}, map[int][]map[string]any{4000: jobs(4000, sha, drop("Kind lifecycle"))}), false},
		{"(iv-c) prior run with two Kind lifecycle jobs", fixture([]map[string]any{goodPrior}, map[int][]map[string]any{4000: jobs(4000, sha, duplicate("Kind lifecycle"))}), false},
		{"(iv-d) prior run without the Go and policy job", fixture([]map[string]any{goodPrior}, map[int][]map[string]any{4000: jobs(4000, sha, drop("Go and policy"))}), false},
		{"(iv-e) prior run with one failed job", fixture([]map[string]any{goodPrior}, map[int][]map[string]any{4000: jobs(4000, sha, setConclusion("Installer engine race shard 0", "failure"))}), false},
		{"(v) only push/PR runs of the same SHA", fixture([]map[string]any{
			run(4001, "push", "completed", "success", sha, "main"),
			run(4002, "pull_request", "completed", "success", sha, "topic"),
		}, map[int][]map[string]any{4001: jobs(4001, sha, nil), 4002: jobs(4002, sha, nil)}), false},
		{"(vi) prior successful schedule run of a different SHA", fixture([]map[string]any{
			run(4003, "schedule", "completed", "success", otherSHA, "main"),
		}, map[int][]map[string]any{4003: jobs(4003, otherSHA, nil)}), false},
	}

	stubDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(stubDir, "gh"), []byte(ghStub), 0o755); err != nil {
		return err
	}
	for _, sc := range scenarios {
		dir := t.TempDir()
		raw, err := json.Marshal(sc.fixture)
		if err != nil {
			return err
		}
		fixturePath, logPath, outputPath := filepath.Join(dir, "fixture.json"), filepath.Join(dir, "gh.log"), filepath.Join(dir, "github_output")
		if err := os.WriteFile(fixturePath, raw, 0o600); err != nil {
			return err
		}
		cmd := exec.Command("python3", "-c", script)
		cmd.Dir = dir
		cmd.Env = append([]string{
			"PATH=" + stubDir + string(os.PathListSeparator) + os.Getenv("PATH"),
			"HOME=" + dir,
			"GITHUB_OUTPUT=" + outputPath,
			"GH_STUB_FIXTURE=" + fixturePath,
			"GH_STUB_LOG=" + logPath,
		}, stepEnv...)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("nightly guard %s: must exit 0 and fail safe, got %v\n%s", sc.name, err, out)
		}
		output, err := os.ReadFile(outputPath)
		if err != nil {
			return fmt.Errorf("nightly guard %s: no GITHUB_OUTPUT: %v", sc.name, err)
		}
		var skips []string
		for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
			if value, ok := strings.CutPrefix(line, "skip="); ok {
				skips = append(skips, value)
			}
		}
		if len(skips) != 1 || (skips[0] != "true" && skips[0] != "false") {
			return fmt.Errorf("nightly guard %s: want exactly one skip=true|false output, got %q", sc.name, output)
		}
		if got := skips[0] == "true"; got != sc.wantSkip {
			return fmt.Errorf("nightly guard %s: skip=%v, want %v", sc.name, got, sc.wantSkip)
		}
		calls, _ := os.ReadFile(logPath)
		lines := strings.Split(strings.TrimSpace(string(calls)), "\n")
		if sc.wantSkip && (len(lines) == 0 || lines[0] == "") {
			return fmt.Errorf("nightly guard %s: skipped without any API lookup", sc.name)
		}
		for _, line := range lines {
			if line == "" {
				continue
			}
			var argv []string
			if err := json.Unmarshal([]byte(line), &argv); err != nil {
				return fmt.Errorf("nightly guard %s: unreadable stub log %q", sc.name, line)
			}
			methods := 0
			for _, a := range argv {
				if a == "--method" || a == "-X" || strings.HasPrefix(a, "--method=") || strings.HasPrefix(a, "-X") {
					methods++
				}
			}
			if len(argv) < 4 || !slices.Equal(argv[:3], []string{"api", "--method", "GET"}) || methods != 1 || slices.Contains(argv, "--input") || strings.HasPrefix(strings.TrimPrefix(argv[3], "/"), "graphql") {
				return fmt.Errorf("nightly guard %s: gh call %q is not `gh api --method GET <endpoint>`", sc.name, argv)
			}
		}
	}
	return nil
}

// workflowOverrideEnv names the environment variables that point the test at a
// single ci.yml copy (for example a deliberately broken one in a temp dir), so
// a plain `go test` run against that copy exits non-zero.
var workflowOverrideEnv = []string{"WORKFLOW_POLICY_CI_YML", "ARCADECTL_TEST_WORKFLOW_FILE"}

// validateAll runs every ci.yml policy: static/structural checks and gate
// execution, then the classifier and nightly guard Python with fixtures.
func validateAll(t *testing.T, body []byte) (*workflowFile, error) {
	t.Helper()
	wf, err := validateCIWorkflowBytes(body)
	if err != nil {
		return nil, err
	}
	if err := verifyClassifierFailSafe(t, wf); err != nil {
		return nil, fmt.Errorf("classifier: %w", err)
	}
	if err := verifyNightlyGuard(t, wf); err != nil {
		return nil, fmt.Errorf("nightly guard: %w", err)
	}
	return wf, nil
}

func logFairness(t *testing.T, body []byte) {
	t.Helper()
	report, err := validateFairness(body)
	if report == nil {
		t.Fatalf("fairness arithmetic unavailable: %v", err)
	}
	for _, line := range report.lines() {
		t.Log("fairness: " + line)
	}
}

func TestWorkflowPolicy(t *testing.T) {
	override := ""
	for _, name := range workflowOverrideEnv {
		if value := os.Getenv(name); value != "" {
			override = value
			break
		}
	}
	if override != "" {
		body, err := os.ReadFile(override)
		if err != nil {
			t.Fatalf("read override workflow %q: %v", override, err)
		}
		if _, err := validateAll(t, body); err != nil {
			t.Fatalf("workflow policy violation in %s: %v", override, err)
		}
		logFairness(t, body)
		return
	}

	workflowsDir := filepath.Join("..", "..", ".github", "workflows")
	entries, err := os.ReadDir(workflowsDir)
	if err != nil {
		t.Fatalf("read workflows dir: %v", err)
	}
	var ciBody []byte
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yml") {
			continue
		}
		path := filepath.Join(workflowsDir, entry.Name())
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if entry.Name() == "ci.yml" {
			ciBody = body
			continue
		}
		var wf workflowFile
		if err := yaml.Unmarshal(body, &wf); err != nil {
			t.Fatalf("unmarshal %s: %v", entry.Name(), err)
		}
		if err := validateWorkflowCachePolicy(entry.Name(), &wf); err != nil {
			t.Fatalf("cache policy violation in %s: %v", entry.Name(), err)
		}
	}
	if len(ciBody) == 0 {
		t.Fatal("ci.yml not found in .github/workflows")
	}

	wf, err := validateCIWorkflowBytes(ciBody)
	if err != nil {
		t.Fatalf("real ci.yml failed policy check: %v", err)
	}
	if err := verifyClassifierFailSafe(t, wf); err != nil {
		t.Fatalf("real ci.yml classifier failed fail-safe verification: %v", err)
	}
	if err := verifyNightlyGuard(t, wf); err != nil {
		t.Fatalf("real ci.yml nightly guard failed fail-safe verification: %v", err)
	}
	logFairness(t, ciBody)

	// Permanent negative tests on mutated copies of ci.yml written to a temp dir.
	negativeCases := []struct {
		name    string
		mutate  func(string) string
		wantErr string
	}{
		{
			name: "paths-ignore on pull_request trigger",
			mutate: func(s string) string {
				return strings.Replace(s, "  pull_request:\n", "  pull_request:\n    paths-ignore:\n      - 'docs/**'\n", 1)
			},
			wantErr: "pull_request trigger contains forbidden filter \"paths-ignore\"",
		},
		{
			name: "paths filter on pull_request trigger",
			mutate: func(s string) string {
				return strings.Replace(s, "  pull_request:\n", "  pull_request:\n    paths:\n      - 'internal/**'\n", 1)
			},
			wantErr: "pull_request trigger contains forbidden filter \"paths\"",
		},
		{
			name: "drop 137 transition leg from kind-install-binary",
			mutate: func(s string) string {
				return strings.Replace(s, "mode: [fresh, transition]", "mode: [fresh]", 1)
			},
			wantErr: "kind-install-binary matrix legs must be exactly (135 fresh, 137 fresh, 137 transition)",
		},
		{
			name: "drop 135 profile from kind-install-admission",
			mutate: func(s string) string {
				target := "  kind-install-admission:\n"
				idx := strings.Index(s, target)
				if idx == -1 {
					return s
				}
				return s[:idx] + strings.Replace(s[idx:], "profile: [135, 137]", "profile: [137]", 1)
			},
			wantErr: "kind-install-admission must run complete [135, 137] x [cold, warm] matrix",
		},
		{
			name: "reduce install-engine-race shards",
			mutate: func(s string) string {
				return strings.Replace(s,
					"        shard: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,\n                16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31]",
					"        shard: [0, 1, 2, 3, 4, 5, 6, 7]",
					1)
			},
			wantErr: "install-engine-race must run all 32 shards",
		},
		{
			name: "reduce envtest parts",
			mutate: func(s string) string {
				return strings.Replace(s, `part: [base-packages, "0"`, `part: ["0"`, 1)
			},
			wantErr: "envtest must run all 33 parts",
		},
		{
			name: "exclude pull_request via job if on kind-recovery",
			mutate: func(s string) string {
				oldIf := "    if: ${{ !cancelled() && needs.classify.outputs.scope != 'docs' && needs.classify.outputs.scope != 'idle' && needs.classify.outputs.scope != 'cheap' }}"
				newIf := "    if: ${{ github.event_name != 'pull_request' }}"
				return replaceInJob(s, "kind-recovery", oldIf, newIf)
			},
			wantErr: "job \"kind-recovery\" if condition contains forbidden token \"github.event_name\"",
		},
		{
			name: "keep !cancelled() instead of success() on install-engine-race",
			mutate: func(s string) string {
				target := "            kind-install-auth, kind-install-baseline, kind-install-precontroller]\n"
				oldIf := "    if: ${{ success() && needs.classify.outputs.scope != 'docs' && needs.classify.outputs.scope != 'idle' && needs.classify.outputs.scope != 'cheap' }}"
				newIf := "    if: ${{ !cancelled() && needs.classify.outputs.scope != 'docs' && needs.classify.outputs.scope != 'idle' && needs.classify.outputs.scope != 'cheap' }}"
				return strings.Replace(s, target+oldIf, target+newIf, 1)
			},
			wantErr: "job \"install-engine-race\" if condition",
		},
		{
			name: "enable setup-go cache on PRs",
			mutate: func(s string) string {
				return strings.Replace(s, "cache: false", "cache: true", 1)
			},
			wantErr: "must set setup-go cache: false",
		},
		{
			name: "remove watchdog from binary transition leg",
			mutate: func(s string) string {
				return strings.Replace(s, "bash ./hack/ci-no-progress-watchdog.sh 30 \"137 transition\" \\\n              ", "", 1)
			},
			wantErr: "kind-install-binary transition leg lacks no-progress watchdog",
		},
		{
			name: "gate ignores skipped proofs on full scope",
			mutate: func(s string) string {
				return strings.Replace(s, "            test \"$result\" = \"$expected\"\n", "            test \"$result\" = \"$expected\" || test \"$result\" = skipped\n", 1)
			},
			wantErr: "gate behavior: full scope with",
		},
		{
			name: "gate passes cheap scope without Go and policy checks",
			mutate: func(s string) string {
				return strings.Replace(s, "              test \"$GO_POLICY_CHECKS_RESULT\" = success\n", "", 1)
			},
			wantErr: "gate behavior:",
		},
		{
			name: "gate drops kind-recovery from needs",
			mutate: func(s string) string {
				return strings.Replace(s, "kind-install-precontroller, kind-install-auth, kind-api, kind-recovery, envtest,", "kind-install-precontroller, kind-install-auth, kind-api, envtest,", 1)
			},
			wantErr: "go-and-policy needs omits job \"kind-recovery\"",
		},
		{
			// Round 4: kind-recovery legitimately waits on envtest for capacity
			// with !cancelled(); with success() that wait becomes a skip.
			name: "kind-recovery waits on a non-foundation job",
			mutate: func(s string) string {
				s = regexpInJob(s, "kind-recovery", `needs: \[[^\]]*\]`, "needs: [classify, installer-diagnostics, kind-api]")
				return replaceInJob(s, "kind-recovery", "if: ${{ !cancelled() &&", "if: ${{ success() &&")
			},
			wantErr: "rejected-list job \"kind-recovery\" needs non-foundation job \"kind-api\"",
		},
		{
			name: "label-based skip on kind-install-precontroller",
			mutate: func(s string) string {
				target := "  kind-install-precontroller:\n    name: Kind pre-controller runtime ${{ matrix.profile }}\n    needs: [classify, installer-diagnostics]\n    if: ${{ "
				return strings.Replace(s, target, target+"!contains(github.event.pull_request.labels.*.name, 'skip-kind') && ", 1)
			},
			wantErr: "job \"kind-install-precontroller\" if condition contains forbidden token",
		},
		{
			name: "types filter on pull_request trigger",
			mutate: func(s string) string {
				return strings.Replace(s, "  pull_request:\n", "  pull_request:\n    types: [labeled]\n", 1)
			},
			wantErr: "pull_request trigger contains forbidden filter \"types\"",
		},
		{
			name: "save Go cache on pull requests",
			mutate: func(s string) string {
				return strings.Replace(s, "(github.event_name == 'push' || github.event_name == 'schedule') && steps.go-cache", "(github.event_name == 'push' || github.event_name == 'schedule' || github.event_name == 'pull_request') && steps.go-cache", 1)
			},
			wantErr: "saves cache without strict main push/schedule guard",
		},
		{
			name: "drop 137 from kind-install-baseline",
			mutate: func(s string) string {
				target := "  kind-install-baseline:\n"
				idx := strings.Index(s, target)
				if idx == -1 {
					return s
				}
				return s[:idx] + strings.Replace(s[idx:], "profile: [135, 137]", "profile: [135]", 1)
			},
			wantErr: "kind-install-baseline must run complete [135, 137] matrix",
		},
		// Round 4: fairness caps, concurrency, scope/event binding, nightly
		// guard and generated docs. Each mutation targets one job block.
		{
			name: "(a) remove max-parallel from a Kind matrix",
			mutate: func(s string) string {
				return regexpInJob(s, "kind-install-baseline", `\n\s*max-parallel: \d+`, "")
			},
			wantErr: "job \"kind-install-baseline\" has a strategy.matrix (2 legs) but no strategy.max-parallel",
		},
		{
			name: "max-parallel 0 on a Kind matrix",
			mutate: func(s string) string {
				return regexpInJob(s, "kind-install-precontroller", `max-parallel: \d+`, "max-parallel: 0")
			},
			wantErr: "job \"kind-install-precontroller\" strategy.max-parallel = 0, want a literal integer >= 1",
		},
		{
			name: "max-parallel expression cannot be bounded",
			mutate: func(s string) string {
				return regexpInJob(s, "kind-install-binary", `max-parallel: \d+`, "max-parallel: ${{ fromJSON('3') }}")
			},
			wantErr: "job \"kind-install-binary\" strategy.max-parallel = \"${{ fromJSON('3') }}\", want a literal integer >= 1",
		},
		{
			name: "(b) raise race max-parallel to 8",
			mutate: func(s string) string {
				return regexpInJob(s, "install-engine-race", `max-parallel: \d+`, "max-parallel: 8")
			},
			wantErr: "worst-case concurrent hosted jobs = 14 > 10",
		},
		{
			name: "(c) drop admission capacity serialization edges",
			mutate: func(s string) string {
				return regexpInJob(s, "kind-install-admission", `needs: \[[^\]]*\]`, "needs: [classify, installer-diagnostics]")
			},
			wantErr: "worst-case concurrent hosted jobs = 12 > 10",
		},
		{
			name: "(c2) drop recovery envtest capacity edge",
			mutate: func(s string) string {
				return regexpInJob(s, "kind-recovery", `needs: \[[^\]]*\]`, "needs: [classify, installer-diagnostics]")
			},
			wantErr: "worst-case concurrent hosted jobs = 11 > 10",
		},
		{
			name: "(d) concurrency group back to event_name-ref form",
			mutate: func(s string) string {
				return strings.Replace(s, "group: ci-${{ github.workflow }}-${{ github.event.pull_request.number || github.ref }}", "group: ci-${{ github.workflow }}-${{ github.event_name }}-${{ github.ref }}", 1)
			},
			wantErr: "workflow concurrency group",
		},
		{
			name: "(e) cancel-in-progress true",
			mutate: func(s string) string {
				return strings.Replace(s, "cancel-in-progress: ${{ github.event_name == 'pull_request' }}", "cancel-in-progress: true", 1)
			},
			wantErr: "workflow concurrency cancel-in-progress",
		},
		{
			name: "(f) docs/generated treated as docs",
			mutate: func(s string) string {
				return replaceInJob(s, "classify", `, "docs/generated/"`, "")
			},
			wantErr: "classifier: classifier PR scenario \"generated CLI command reference is not docs\": got scope \"docs\", want \"full\"",
		},
		{
			name: "(g) gate cheap scope without CI_EVENT_NAME check",
			mutate: func(s string) string {
				return replaceInJob(s, "go-and-policy", `cheap) test "$CI_EVENT_NAME" = push && test "$CI_REF"`, `cheap) test "$CI_REF"`)
			},
			wantErr: "gate behavior: cheap scope with event \"pull_request\" ref \"refs/heads/main\" must fail",
		},
		{
			name: "gate env does not bind CI_EVENT_NAME",
			mutate: func(s string) string {
				return replaceInJob(s, "go-and-policy", "          CI_EVENT_NAME: ${{ github.event_name }}\n", "")
			},
			wantErr: "gate step env must bind CI_EVENT_NAME",
		},
		{
			name: "gate env binds CI_REF to the wrong context",
			mutate: func(s string) string {
				return replaceInJob(s, "go-and-policy", "CI_REF: ${{ github.ref }}", "CI_REF: ${{ github.base_ref }}")
			},
			wantErr: "gate step env must bind CI_REF",
		},
		{
			name: "gate idle scope without schedule check",
			mutate: func(s string) string {
				return replaceInJob(s, "go-and-policy", `idle) test "$CI_EVENT_NAME" = schedule && test "$CI_REF"`, `idle) test "$CI_REF"`)
			},
			wantErr: "gate behavior: idle scope with event \"pull_request\" ref \"refs/heads/main\" must fail",
		},
		{
			name: "gate docs scope accepts push to any branch",
			mutate: func(s string) string {
				return replaceInJob(s, "go-and-policy", `test "$CI_EVENT_NAME" = push && test "$CI_REF" = refs/heads/main`+"\n              }", `test "$CI_EVENT_NAME" = push`+"\n              }")
			},
			wantErr: "gate behavior: docs scope with event \"push\" ref \"refs/heads/topic\" must fail",
		},
		{
			name: "(h) envtest part list shortened",
			mutate: func(s string) string {
				return replaceInJob(s, "envtest", `, "31"]`, "]")
			},
			wantErr: "envtest must run all 33 parts",
		},
		{
			name: "signed binary gains a success()-only capacity edge",
			mutate: func(s string) string {
				return regexpInJob(s, "kind-install-binary", `needs: \[[^\]]*\]`, "needs: [classify, installer-diagnostics, kind-install-gc]")
			},
			wantErr: "job \"kind-install-binary\" has capacity-only needs [kind-install-gc]",
		},
		{
			name: "admission capacity edges with success() semantics",
			mutate: func(s string) string {
				return replaceInJob(s, "kind-install-admission", "if: ${{ !cancelled() &&", "if: ${{ success() &&")
			},
			wantErr: "job \"kind-install-admission\" has capacity-only needs",
		},
		{
			name: "Kind lifecycle envtest capacity edge with success() semantics",
			mutate: func(s string) string {
				return replaceInJob(s, "kind-lifecycle", "if: ${{ !cancelled() &&", "if: ${{ success() &&")
			},
			wantErr: "job \"kind-lifecycle\" has capacity-only needs [envtest]",
		},
		{
			name: "nightly guard runs on every event",
			mutate: func(s string) string {
				return replaceInJob(s, "classify", "        if: github.event_name == 'schedule'\n", "")
			},
			wantErr: "nightly guard step must run only on schedule",
		},
		{
			name: "nightly guard writes through the API",
			mutate: func(s string) string {
				return replaceInJob(s, "classify", `"--method", "GET"`, `"--method", "POST"`)
			},
			wantErr: "nightly guard must call gh only as `gh api --method GET`",
		},
		{
			name: "classify gains actions write permission",
			mutate: func(s string) string {
				return replaceInJob(s, "classify", "      actions: read\n", "      actions: write\n")
			},
			wantErr: "classify permissions = ",
		},
		{
			name: "classify gains an extra permission",
			mutate: func(s string) string {
				return replaceInJob(s, "classify", "      actions: read\n", "      actions: read\n      pull-requests: read\n")
			},
			wantErr: "classify permissions = ",
		},
		{
			name: "nightly guard adds time-window logic",
			mutate: func(s string) string {
				return replaceInJob(s, "classify", "          import json\n          import os\n          import re\n          import subprocess\n          import urllib.parse\n", "          import datetime\n          import json\n          import os\n          import re\n          import subprocess\n          import urllib.parse\n")
			},
			wantErr: "time-window logic token \"datetime\"",
		},
		{
			name: "nightly guard trusts a truncated page",
			mutate: func(s string) string {
				return replaceInJob(s, "classify", "\n                      or not 0 <= count < 100 or len(entries) != count\n                      or len({entry[\"id\"] for entry in entries}) != count)", ")")
			},
			wantErr: "nightly guard (ii) truncated run page total_count>=100: skip=true, want false",
		},
		{
			name: "nightly guard skips on API error",
			mutate: func(s string) string {
				return replaceInJob(s, "classify", `print("::notice::Previous full-run lookup uncertain; running full CI")`, "skip = True")
			},
			wantErr: "nightly guard (i) gh api errors on every call: skip=true, want false",
		},
		{
			name: "nightly guard does not require a Kind lifecycle job",
			mutate: func(s string) string {
				return replaceInJob(s, "classify", `names.count("Kind lifecycle") == 1 and `, "")
			},
			wantErr: "nightly guard (iv-b) prior run without a Kind lifecycle job: skip=true, want false",
		},
	}

	tempDir := t.TempDir()
	for i, tc := range negativeCases {
		t.Run("negative/"+tc.name, func(t *testing.T) {
			mutated := tc.mutate(string(ciBody))
			if mutated == string(ciBody) {
				t.Fatalf("mutation %q did not modify ci.yml", tc.name)
			}
			brokenPath := filepath.Join(tempDir, fmt.Sprintf("ci-broken-%d.yml", i))
			if err := os.WriteFile(brokenPath, []byte(mutated), 0o600); err != nil {
				t.Fatalf("write broken copy: %v", err)
			}
			brokenBytes, err := os.ReadFile(brokenPath)
			if err != nil {
				t.Fatalf("read broken copy: %v", err)
			}
			_, err = validateAll(t, brokenBytes)
			if err == nil {
				t.Fatalf("expected broken workflow copy %q to fail policy validation, but it passed", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("broken copy %q failed with %q, want substring %q", tc.name, err.Error(), tc.wantErr)
			}
		})
	}
}

// jobBlock returns the byte range of a top-level job block in ci.yml text.
func jobBlock(s, job string) (int, int) {
	start := strings.Index(s, "\n  "+job+":\n")
	if start == -1 {
		return -1, -1
	}
	start++
	end := len(s)
	if next := regexp.MustCompile(`\n  [A-Za-z0-9_-]+:\n`).FindStringIndex(s[start:]); next != nil {
		end = start + next[0] + 1
	}
	return start, end
}

// replaceInJob replaces the first occurrence of old inside one job block.
func replaceInJob(s, job, old, replacement string) string {
	start, end := jobBlock(s, job)
	if start < 0 {
		return s
	}
	return s[:start] + strings.Replace(s[start:end], old, replacement, 1) + s[end:]
}

// regexpInJob replaces the first pattern match inside one job block.
func regexpInJob(s, job, pattern, replacement string) string {
	start, end := jobBlock(s, job)
	if start < 0 {
		return s
	}
	block := s[start:end]
	loc := regexp.MustCompile(pattern).FindStringIndex(block)
	if loc == nil {
		return s
	}
	return s[:start] + block[:loc[0]] + replacement + block[loc[1]:] + s[end:]
}

func TestMatrixLegsExpansion(t *testing.T) {
	for _, tc := range []struct {
		name   string
		matrix string
		want   int
	}{
		{"single list", "shard: [0, 1, 2, 3]", 4},
		{"product", "profile: [135, 137]\nmode: [cold, warm]", 4},
		{"exclude one leg", "profile: [135, 137]\nmode: [fresh, transition]\nexclude:\n  - profile: 135\n    mode: transition", 3},
		{"partial exclude removes every match", "profile: [135, 137]\nmode: [cold, warm]\nexclude:\n  - mode: warm", 2},
		{"include merged into existing legs adds none", "profile: [135, 137]\ninclude:\n  - extra: x", 2},
		{"include matching one original leg adds none", "profile: [135, 137]\ninclude:\n  - profile: 137\n    extra: y", 2},
		{"include conflicting with originals adds a leg", "profile: [135, 137]\ninclude:\n  - profile: 139", 3},
		{"include only", "include:\n  - a: 1\n  - a: 2", 2},
		{"exclude then include", "profile: [135, 137]\nmode: [fresh, transition]\nexclude:\n  - profile: 135\n    mode: transition\ninclude:\n  - profile: 135\n    mode: transition", 4},
	} {
		var matrix any
		if err := yaml.Unmarshal([]byte(tc.matrix), &matrix); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		got, err := matrixLegs("job", matrix)
		if err != nil || got != tc.want {
			t.Fatalf("%s: matrixLegs = %d, %v; want %d", tc.name, got, err, tc.want)
		}
	}
	for _, bad := range []string{`"${{ fromJSON(needs.x.outputs.m) }}"`, "shard: []", "shard: [0]\nexclude:\n  - shard: 0", "shard: [0]\nexclude:\n  - other: 1"} {
		var matrix any
		if err := yaml.Unmarshal([]byte(bad), &matrix); err != nil {
			t.Fatalf("%q: %v", bad, err)
		}
		if _, err := matrixLegs("job", matrix); err == nil {
			t.Fatalf("matrixLegs accepted unboundable or empty matrix %q", bad)
		}
	}
}

func TestFairnessAntichainArithmetic(t *testing.T) {
	// a -> {b, c}; c -> d; e is independent of everything but a.
	// Antichains: {a}, {b, c, e}, {b, d, e}: weights b=3 (cap 3 of 5),
	// c=2 (cap 4 of 2 legs), d=1, e=4 (cap 4 of 10) -> max 9.
	body := []byte(`jobs:
  a: {}
  b: {needs: [a], strategy: {max-parallel: 3, matrix: {x: [1, 2, 3, 4, 5]}}}
  c: {needs: a, strategy: {max-parallel: 4, matrix: {x: [1, 2]}}}
  d: {needs: [c]}
  e: {needs: [a], strategy: {max-parallel: 4, matrix: {x: [0,1,2,3,4,5,6,7,8,9]}}}
`)
	report, err := validateFairness(body)
	if err != nil || report.max != 9 || len(report.phases) != 3 || report.phases[0].sum != 9 || !slices.Equal(report.phases[0].jobs, []string{"b", "c", "e"}) {
		t.Fatalf("fairness = %+v, %v; want max 9 from {b c e} over 3 maximal antichains", report, err)
	}
	over := []byte(strings.Replace(string(body), "max-parallel: 3,", "max-parallel: 5,", 1) + "  f: {needs: [a]}\n  g: {needs: [a]}\n")
	if _, err := validateFairness(over); err == nil || !strings.Contains(err.Error(), "worst-case concurrent hosted jobs = 13 > 10") {
		t.Fatalf("fairness over cap: err = %v, want 13 > 10", err)
	}
	for _, bad := range []string{
		"jobs:\n  a: {needs: [b]}\n  b: {needs: [a]}\n",
		"jobs:\n  a: {needs: [missing]}\n",
		"jobs:\n  a: {strategy: {matrix: {x: [1, 2]}}}\n",
	} {
		if _, err := validateFairness([]byte(bad)); err == nil {
			t.Fatalf("validateFairness accepted %q", bad)
		}
	}
}
