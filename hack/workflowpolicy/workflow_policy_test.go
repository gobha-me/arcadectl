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
	const wantEnvtestIf = "${{ !cancelled() && needs.classify.result == 'success' && needs.installer-diagnostics.result == 'success' && needs.kind-install-gc.result == 'success' && needs.kind-install-admission.result == 'success' && needs.kind-install-admission-v3.result == 'success' && needs.kind-install-auth.result == 'success' && needs.kind-install-baseline.result == 'success' && needs.kind-install-precontroller.result == 'success' && needs.classify.outputs.scope != 'docs' && needs.classify.outputs.scope != 'idle' && needs.classify.outputs.scope != 'cheap' }}"
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
		"envtest":                    wantEnvtestIf,
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

	// Rule 1 (Atlas ruling 4): go-policy-checks starts right after classify
	// and installer-diagnostics and must NOT depend on envtest (or any Kind or
	// race job), directly or transitively.
	if err := validateGoPolicyIndependence(&wf); err != nil {
		return nil, err
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
	// code pull request. Capacity-only edges with !cancelled() are checked in 3;
	// envtest's foundation-only result checks with its policy capacity edge are
	// checked in validateEnvtestPolicy below.
	allowedUpstream := []string{
		"classify", "installer-diagnostics", "kind-install-gc", "kind-install-admission",
		"kind-install-admission-v3", "kind-install-auth", "kind-install-baseline", "kind-install-precontroller",
	}
	for _, rejected := range []string{
		"kind-install-binary", "kind-recovery", "kind-install-baseline", "kind-install-precontroller",
		"kind-install-admission", "kind-install-admission-v3", "install-engine-race",
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
	// for race/envtest the item-2 foundation set) must not use success()-only
	// semantics, or an unrelated earlier failure would skip a must-run proof.
	if err := validateCapacityEdges(&wf, wantBulkNeeds); err != nil {
		return nil, err
	}

	// Rule 4 (Atlas ruling 4): envtest waits on go-policy-checks as a capacity
	// edge, uses !cancelled() (never bare success()), requires each foundation
	// result == 'success', and never references go-policy-checks' result.
	if err := validateEnvtestPolicy(&wf, wantBulkNeeds); err != nil {
		return nil, err
	}

	// 4) Exact job conditions and no failure tolerance.
	for _, jobName := range slices.Sorted(maps.Keys(allowedIfs)) {
		wantIf := allowedIfs[jobName]
		job := wf.Jobs[jobName]
		if normalizeSpace(job.If) != wantIf {
			return nil, fmt.Errorf("job %q if condition = %q, want %q", jobName, normalizeSpace(job.If), wantIf)
		}
		if job.ContinueOnError != nil {
			return nil, fmt.Errorf("job %q sets continue-on-error: %v", jobName, job.ContinueOnError)
		}
	}

	if !slices.Equal(wf.Jobs["install-engine-race"].Needs, wantBulkNeeds) {
		return nil, fmt.Errorf("bulk job %q needs = %v, want %v", "install-engine-race", wf.Jobs["install-engine-race"].Needs, wantBulkNeeds)
	}
	if !slices.Equal(wf.Jobs["kind-install-binary"].Needs, []string{"classify", "installer-diagnostics"}) {
		return nil, fmt.Errorf("kind-install-binary needs = %v, want [classify installer-diagnostics] with no capacity edge", wf.Jobs["kind-install-binary"].Needs)
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

	// Rules 2, 3, and 4 exact capacity-edge and max-parallel pins (checked
	// after validateFairness so removing an edge or raising v3 max-parallel to 4
	// reports the 11 > 10 fairness violation first, while lowering or swapping
	// still fails).
	if err := validateRuling4GraphPins(&wf, wantBulkNeeds); err != nil {
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

func normalizeSpace(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// transitiveNeeds computes the transitive needs closure of job start across
// wf.Jobs, terminating safely even if a mutated workflow introduces a cycle.
func transitiveNeeds(wf *workflowFile, start string) []string {
	visited := map[string]bool{}
	var queue []string
	for _, n := range wf.Jobs[start].Needs {
		if !visited[n] {
			visited[n] = true
			queue = append(queue, n)
		}
	}
	for i := 0; i < len(queue); i++ {
		job, ok := wf.Jobs[queue[i]]
		if !ok {
			continue
		}
		for _, n := range job.Needs {
			if !visited[n] {
				visited[n] = true
				queue = append(queue, n)
			}
		}
	}
	return slices.Sorted(maps.Keys(visited))
}

func validateGoPolicyIndependence(wf *workflowFile) error {
	policyJob, ok := wf.Jobs["go-policy-checks"]
	if !ok {
		return fmt.Errorf("required CI job \"go-policy-checks\" is missing")
	}
	if policyJob.Name != "Go and policy checks" {
		return fmt.Errorf("rule 1: go-policy-checks name = %q, want %q", policyJob.Name, "Go and policy checks")
	}
	closure := transitiveNeeds(wf, "go-policy-checks")
	if slices.Contains(closure, "envtest") || slices.Contains(policyJob.Needs, "envtest") {
		return fmt.Errorf("rule 1: Go/policy must not depend on envtest (go-policy-checks transitive needs: %v)", closure)
	}
	for _, dep := range closure {
		if strings.HasPrefix(dep, "kind-") || dep == "install-engine-race" || dep == "envtest" {
			return fmt.Errorf("rule 1: Go/policy must not depend on any Kind, race or envtest job, found %q in transitive needs %v", dep, closure)
		}
	}
	wantPolicyNeeds := []string{"classify", "installer-diagnostics"}
	if !slices.Equal(policyJob.Needs, wantPolicyNeeds) || !slices.Equal(closure, wantPolicyNeeds) {
		return fmt.Errorf("rule 1: go-policy-checks must start right after classify and installer-diagnostics: needs = %v (transitive %v), want %v", policyJob.Needs, closure, wantPolicyNeeds)
	}
	return nil
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
	}
	if wf.Jobs["kind-api"].Name != "Kind authenticated admin API" {
		return fmt.Errorf("rule 3: kind-api name = %q, want %q", wf.Jobs["kind-api"].Name, "Kind authenticated admin API")
	}
	for _, name := range slices.Sorted(maps.Keys(wf.Jobs)) {
		if name == "go-and-policy" || name == "envtest" {
			continue // go-and-policy uses always(); envtest is checked by validateEnvtestPolicy (rule 4).
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
			return fmt.Errorf("rule 3: job %q has capacity-only needs %v but its if %q lacks !cancelled() semantics; an unrelated earlier failure would skip it", name, capacity, job.If)
		}
	}
	return nil
}

func validateEnvtestPolicy(wf *workflowFile, wantFoundations []string) error {
	envtest := wf.Jobs["envtest"]
	cond := normalizeSpace(envtest.If)
	if strings.Contains(cond, "go-policy-checks") {
		return fmt.Errorf("rule 4: envtest if condition must not reference go-policy-checks result (a Go/policy failure must not skip envtest): %s", cond)
	}
	if strings.Contains(cond, "success()") || !strings.HasPrefix(cond, "${{ !cancelled() && ") {
		return fmt.Errorf("rule 4: envtest if condition must use !cancelled() and not bare success() (a Go/policy failure must not skip envtest): %s", cond)
	}
	for _, forbiddenFn := range []string{"failure()", "always()"} {
		if strings.Contains(cond, forbiddenFn) {
			return fmt.Errorf("rule 4: envtest if condition contains forbidden status function %q: %s", forbiddenFn, cond)
		}
	}
	for _, f := range wantFoundations {
		req := fmt.Sprintf("needs.%s.result == 'success'", f)
		if !strings.Contains(cond, req) {
			return fmt.Errorf("rule 4: envtest if condition must require foundation %q (%s): %s", f, req, cond)
		}
	}
	resultRe := regexp.MustCompile(`needs\.([A-Za-z0-9_-]+)\.result`)
	for _, m := range resultRe.FindAllStringSubmatch(cond, -1) {
		if !slices.Contains(wantFoundations, m[1]) {
			return fmt.Errorf("rule 4: envtest if condition references non-foundation result needs.%s.result: %s", m[1], cond)
		}
	}
	for _, f := range wantFoundations {
		if !slices.Contains(envtest.Needs, f) {
			return fmt.Errorf("rule 4: envtest needs %v omits foundation job %q", envtest.Needs, f)
		}
	}
	for _, n := range envtest.Needs {
		if !slices.Contains(wantFoundations, n) && n != "go-policy-checks" {
			return fmt.Errorf("rejected-list job \"envtest\" needs non-foundation job %q", n)
		}
	}
	return nil
}

func validateRuling4GraphPins(wf *workflowFile, wantFoundations []string) error {
	if v3Cap := wf.Jobs["kind-install-admission-v3"].Strategy.MaxParallel; v3Cap != 3 {
		return fmt.Errorf("rule 2: kind-install-admission-v3 strategy.max-parallel = %v, want 3", v3Cap)
	}
	wantAPINeeds := []string{"classify", "installer-diagnostics", "envtest"}
	if !slices.Equal(wf.Jobs["kind-api"].Needs, wantAPINeeds) {
		return fmt.Errorf("rule 3: kind-api needs = %v, want %v (envtest capacity edge required)", wf.Jobs["kind-api"].Needs, wantAPINeeds)
	}
	wantEnvtestNeeds := append(slices.Clone(wantFoundations), "go-policy-checks")
	if !slices.Equal(wf.Jobs["envtest"].Needs, wantEnvtestNeeds) {
		return fmt.Errorf("rule 4: envtest needs = %v, want %v (go-policy-checks capacity edge required)", wf.Jobs["envtest"].Needs, wantEnvtestNeeds)
	}
	return nil
}

type ghEvalContext struct {
	Workflow  string
	EventName string
	Ref       string
	RunID     string
	PRNumber  string
}

func (c ghEvalContext) lookup(ident string) (string, error) {
	switch ident {
	case "github.workflow":
		return c.Workflow, nil
	case "github.event_name":
		return c.EventName, nil
	case "github.ref":
		return c.Ref, nil
	case "github.run_id":
		return c.RunID, nil
	case "github.event.pull_request.number":
		return c.PRNumber, nil
	default:
		return "", fmt.Errorf("unsupported or unknown context lookup %q", ident)
	}
}

type ghTokenKind int

const (
	ghTokEOF ghTokenKind = iota
	ghTokString
	ghTokIdent
	ghTokLParen
	ghTokRParen
	ghTokComma
	ghTokEq
	ghTokNe
	ghTokAnd
	ghTokOr
)

type ghToken struct {
	kind ghTokenKind
	text string
}

func lexGitHubExpr(input string) ([]ghToken, error) {
	var tokens []ghToken
	i := 0
	for i < len(input) {
		ch := input[i]
		if ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' {
			i++
			continue
		}
		switch {
		case ch == '(':
			tokens = append(tokens, ghToken{kind: ghTokLParen, text: "("})
			i++
		case ch == ')':
			tokens = append(tokens, ghToken{kind: ghTokRParen, text: ")"})
			i++
		case ch == ',':
			tokens = append(tokens, ghToken{kind: ghTokComma, text: ","})
			i++
		case strings.HasPrefix(input[i:], "=="):
			tokens = append(tokens, ghToken{kind: ghTokEq, text: "=="})
			i += 2
		case strings.HasPrefix(input[i:], "!="):
			tokens = append(tokens, ghToken{kind: ghTokNe, text: "!="})
			i += 2
		case strings.HasPrefix(input[i:], "&&"):
			tokens = append(tokens, ghToken{kind: ghTokAnd, text: "&&"})
			i += 2
		case strings.HasPrefix(input[i:], "||"):
			tokens = append(tokens, ghToken{kind: ghTokOr, text: "||"})
			i += 2
		case ch == '\'':
			i++
			var sb strings.Builder
			closed := false
			for i < len(input) {
				if input[i] == '\'' {
					if i+1 < len(input) && input[i+1] == '\'' {
						sb.WriteByte('\'')
						i += 2
						continue
					}
					i++
					closed = true
					break
				}
				sb.WriteByte(input[i])
				i++
			}
			if !closed {
				return nil, fmt.Errorf("unterminated string literal in expression %q", input)
			}
			tokens = append(tokens, ghToken{kind: ghTokString, text: sb.String()})
		case (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch == '_':
			start := i
			for i < len(input) {
				c := input[i]
				if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '.' {
					i++
				} else {
					break
				}
			}
			tokens = append(tokens, ghToken{kind: ghTokIdent, text: input[start:i]})
		default:
			return nil, fmt.Errorf("unexpected character %q in expression %q", ch, input)
		}
	}
	tokens = append(tokens, ghToken{kind: ghTokEOF})
	return tokens, nil
}

type ghVal struct {
	isBool bool
	b      bool
	s      string
}

func (v ghVal) truthy() bool {
	if v.isBool {
		return v.b
	}
	return v.s != ""
}

func (v ghVal) str() string {
	if v.isBool {
		if v.b {
			return "true"
		}
		return "false"
	}
	return v.s
}

type ghParser struct {
	tokens []ghToken
	pos    int
	ctx    ghEvalContext
}

func (p *ghParser) peek() ghToken {
	return p.tokens[p.pos]
}

func (p *ghParser) next() ghToken {
	tok := p.tokens[p.pos]
	if tok.kind != ghTokEOF {
		p.pos++
	}
	return tok
}

func (p *ghParser) parseOr() (ghVal, error) {
	left, err := p.parseAnd()
	if err != nil {
		return ghVal{}, err
	}
	for p.peek().kind == ghTokOr {
		p.next()
		right, err := p.parseAnd()
		if err != nil {
			return ghVal{}, err
		}
		if !left.truthy() {
			left = right
		}
	}
	return left, nil
}

func (p *ghParser) parseAnd() (ghVal, error) {
	left, err := p.parseEq()
	if err != nil {
		return ghVal{}, err
	}
	for p.peek().kind == ghTokAnd {
		p.next()
		right, err := p.parseEq()
		if err != nil {
			return ghVal{}, err
		}
		if left.truthy() {
			left = right
		} else {
			left = ghVal{isBool: true, b: false}
		}
	}
	return left, nil
}

func (p *ghParser) parseEq() (ghVal, error) {
	left, err := p.parsePrimary()
	if err != nil {
		return ghVal{}, err
	}
	if p.peek().kind == ghTokEq || p.peek().kind == ghTokNe {
		op := p.next().kind
		right, err := p.parsePrimary()
		if err != nil {
			return ghVal{}, err
		}
		eq := left.str() == right.str()
		if op == ghTokNe {
			eq = !eq
		}
		return ghVal{isBool: true, b: eq}, nil
	}
	return left, nil
}

func (p *ghParser) parsePrimary() (ghVal, error) {
	tok := p.peek()
	switch tok.kind {
	case ghTokString:
		p.next()
		return ghVal{s: tok.text}, nil
	case ghTokLParen:
		p.next()
		val, err := p.parseOr()
		if err != nil {
			return ghVal{}, err
		}
		if p.next().kind != ghTokRParen {
			return ghVal{}, fmt.Errorf("missing closing ')'")
		}
		return val, nil
	case ghTokIdent:
		p.next()
		if p.peek().kind == ghTokLParen {
			p.next()
			if tok.text != "format" {
				return ghVal{}, fmt.Errorf("unsupported function %q", tok.text)
			}
			var args []ghVal
			for p.peek().kind != ghTokRParen {
				if len(args) > 0 {
					if p.next().kind != ghTokComma {
						return ghVal{}, fmt.Errorf("expected ',' in format() arguments")
					}
				}
				arg, err := p.parseOr()
				if err != nil {
					return ghVal{}, err
				}
				args = append(args, arg)
			}
			p.next() // consume ')'
			if len(args) < 2 {
				return ghVal{}, fmt.Errorf("format() requires a template and at least one replacement argument")
			}
			out, err := applyGitHubFormat(args[0].str(), args[1:])
			if err != nil {
				return ghVal{}, err
			}
			return ghVal{s: out}, nil
		}
		val, err := p.ctx.lookup(tok.text)
		if err != nil {
			return ghVal{}, err
		}
		return ghVal{s: val}, nil
	default:
		return ghVal{}, fmt.Errorf("unexpected token %q", tok.text)
	}
}

func applyGitHubFormat(tmpl string, args []ghVal) (string, error) {
	used := make([]bool, len(args))
	var sb strings.Builder
	for i := 0; i < len(tmpl); {
		if tmpl[i] == '{' {
			end := strings.IndexByte(tmpl[i+1:], '}')
			if end < 0 {
				return "", fmt.Errorf("unclosed '{' in format template %q", tmpl)
			}
			idxStr := tmpl[i+1 : i+1+end]
			idx, err := strconv.Atoi(idxStr)
			if err != nil || idx < 0 || idx >= len(args) {
				return "", fmt.Errorf("invalid format placeholder {%s} for %d args in %q", idxStr, len(args), tmpl)
			}
			used[idx] = true
			sb.WriteString(args[idx].str())
			i += end + 2
			continue
		}
		if tmpl[i] == '}' {
			return "", fmt.Errorf("unmatched '}' in format template %q", tmpl)
		}
		sb.WriteByte(tmpl[i])
		i++
	}
	for idx, u := range used {
		if !u {
			return "", fmt.Errorf("unused format argument %d in %q", idx, tmpl)
		}
	}
	return sb.String(), nil
}

func evalGitHubExpr(expr string, ctx ghEvalContext) (ghVal, error) {
	tokens, err := lexGitHubExpr(expr)
	if err != nil {
		return ghVal{}, err
	}
	parser := &ghParser{tokens: tokens, ctx: ctx}
	val, err := parser.parseOr()
	if err != nil {
		return ghVal{}, err
	}
	if parser.peek().kind != ghTokEOF {
		return ghVal{}, fmt.Errorf("unexpected trailing token %q in expression %q", parser.peek().text, expr)
	}
	return val, nil
}

func evalGitHubTemplate(raw string, ctx ghEvalContext) (string, error) {
	if !strings.Contains(raw, "${{") {
		return "", fmt.Errorf("template %q contains no ${{ ... }} expression", raw)
	}
	var sb strings.Builder
	rest := raw
	for len(rest) > 0 {
		start := strings.Index(rest, "${{")
		if start < 0 {
			if strings.Contains(rest, "}}") {
				return "", fmt.Errorf("unmatched '}}' in template %q", raw)
			}
			sb.WriteString(rest)
			break
		}
		if strings.Contains(rest[:start], "}}") {
			return "", fmt.Errorf("unmatched '}}' in template %q", raw)
		}
		sb.WriteString(rest[:start])
		rest = rest[start+3:]
		end := strings.Index(rest, "}}")
		if end < 0 {
			return "", fmt.Errorf("unclosed '${{' in template %q", raw)
		}
		val, err := evalGitHubExpr(rest[:end], ctx)
		if err != nil {
			return "", err
		}
		sb.WriteString(val.str())
		rest = rest[end+2:]
	}
	return sb.String(), nil
}

func validateConcurrency(wf *workflowFile) error {
	const wantCancel = "${{ github.event_name == 'pull_request' }}"
	if len(wf.Concurrency) != 2 {
		return fmt.Errorf("workflow concurrency must have exactly group and cancel-in-progress, got %v", wf.Concurrency)
	}
	groupExpr, ok := wf.Concurrency["group"].(string)
	if !ok || strings.TrimSpace(groupExpr) == "" {
		return fmt.Errorf("workflow concurrency group must be a non-empty expression string, got %#v", wf.Concurrency["group"])
	}
	cancelExpr, ok := wf.Concurrency["cancel-in-progress"].(string)
	if !ok || cancelExpr != wantCancel {
		return fmt.Errorf("workflow concurrency cancel-in-progress = %#v, want %q", wf.Concurrency["cancel-in-progress"], wantCancel)
	}
	innerCancel := strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(cancelExpr), "${{"), "}}")

	// A.1) pull_request: group evaluates to ci-<workflow>-<PR number>, same
	// across runs of the same PR, without run_id; cancel-in-progress is true.
	pr140Run1 := ghEvalContext{Workflow: "CI", EventName: "pull_request", Ref: "refs/pull/140/merge", RunID: "9001", PRNumber: "140"}
	pr140Run2 := ghEvalContext{Workflow: "CI", EventName: "pull_request", Ref: "refs/pull/140/merge", RunID: "9002", PRNumber: "140"}
	pr141Run1 := ghEvalContext{Workflow: "CI", EventName: "pull_request", Ref: "refs/pull/141/merge", RunID: "9003", PRNumber: "141"}
	prOtherWF := ghEvalContext{Workflow: "Other", EventName: "pull_request", Ref: "refs/pull/140/merge", RunID: "9004", PRNumber: "140"}

	gPR1, err := evalGitHubTemplate(groupExpr, pr140Run1)
	if err != nil {
		return fmt.Errorf("workflow concurrency group failed evaluation on PR #140 run 1: %w", err)
	}
	gPR2, err := evalGitHubTemplate(groupExpr, pr140Run2)
	if err != nil {
		return fmt.Errorf("workflow concurrency group failed evaluation on PR #140 run 2: %w", err)
	}
	if gPR1 != "ci-CI-140" || gPR2 != "ci-CI-140" || gPR1 != gPR2 {
		return fmt.Errorf("workflow concurrency group on PR #140 runs 1/2 = (%q, %q), want both %q without run_id", gPR1, gPR2, "ci-CI-140")
	}
	if strings.Contains(gPR1, pr140Run1.RunID) || strings.Contains(gPR2, pr140Run2.RunID) {
		return fmt.Errorf("workflow concurrency PR group must not include run_id, got %q", gPR1)
	}
	if gPR141, err := evalGitHubTemplate(groupExpr, pr141Run1); err != nil || gPR141 != "ci-CI-141" {
		return fmt.Errorf("workflow concurrency group on PR #141 = %q (%v), want %q", gPR141, err, "ci-CI-141")
	}
	if gOther, err := evalGitHubTemplate(groupExpr, prOtherWF); err != nil || gOther != "ci-Other-140" {
		return fmt.Errorf("workflow concurrency group on workflow Other PR #140 = %q (%v), want %q", gOther, err, "ci-Other-140")
	}
	if cancelVal, err := evalGitHubExpr(innerCancel, pr140Run1); err != nil || !cancelVal.isBool || !cancelVal.b {
		return fmt.Errorf("workflow concurrency cancel-in-progress on pull_request evaluated to %v (%v), want true", cancelVal, err)
	}

	// A.2) push / schedule / workflow_dispatch: group includes github.run_id so
	// two runs on refs/heads/main never share a group; cancel-in-progress is false.
	for _, eventName := range []string{"push", "schedule", "workflow_dispatch"} {
		ctx1 := ghEvalContext{Workflow: "CI", EventName: eventName, Ref: "refs/heads/main", RunID: "9101"}
		ctx2 := ghEvalContext{Workflow: "CI", EventName: eventName, Ref: "refs/heads/main", RunID: "9102"}
		g1, err := evalGitHubTemplate(groupExpr, ctx1)
		if err != nil {
			return fmt.Errorf("workflow concurrency group failed evaluation on %s run 1: %w", eventName, err)
		}
		g2, err := evalGitHubTemplate(groupExpr, ctx2)
		if err != nil {
			return fmt.Errorf("workflow concurrency group failed evaluation on %s run 2: %w", eventName, err)
		}
		if !strings.Contains(g1, ctx1.RunID) || !strings.Contains(g2, ctx2.RunID) {
			return fmt.Errorf("workflow concurrency group on %s must include github.run_id, got run1=%q run2=%q", eventName, g1, g2)
		}
		if g1 == g2 {
			return fmt.Errorf("workflow concurrency group on %s produced identical group %q for distinct run_ids", eventName, g1)
		}
		if cancelVal, err := evalGitHubExpr(innerCancel, ctx1); err != nil || !cancelVal.isBool || cancelVal.b {
			return fmt.Errorf("workflow concurrency cancel-in-progress on %s evaluated to %v (%v), want false", eventName, cancelVal, err)
		}
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
	for i, phase := range report.phases {
		if phase.sum > maxConcurrentHostedJobs {
			var terms []string
			for _, name := range phase.jobs {
				terms = append(terms, fmt.Sprintf("%s %d", name, report.jobs[name].weight))
			}
			return report, fmt.Errorf("phase %d worst-case concurrent hosted jobs = %d > %d: %s", i+1, phase.sum, maxConcurrentHostedJobs, strings.Join(terms, " + "))
		}
	}
	return report, nil
}

// expandMatrixCombos expands a literal strategy.matrix the way GitHub does:
// the Cartesian product of its list keys, minus exclude entries that match on
// every key they name, plus each include entry (merged into matching legs or
// appended when it cannot be merged without overwriting an original matrix key).
func expandMatrixCombos(job string, matrix any) ([]map[string]string, error) {
	m, ok := matrix.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("job %q strategy.matrix must be a literal mapping to bound its size, got %T", job, matrix)
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
			return nil, fmt.Errorf("job %q matrix key %q must be a non-empty literal list", job, key)
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
		return nil, err
	}
	for _, ex := range excludes {
		for key := range ex {
			if !slices.Contains(keys, key) {
				return nil, fmt.Errorf("job %q matrix exclude names unknown key %q", job, key)
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
		return nil, err
	}
	var added []map[string]string
	for _, inc := range includes {
		merged := false
		for _, c := range combos {
			compatible := true
			for key, value := range inc {
				if slices.Contains(keys, key) && c[key] != canon(value) {
					compatible = false
				}
			}
			if compatible {
				for key, value := range inc {
					c[key] = canon(value)
				}
				merged = true
			}
		}
		if !merged {
			c := map[string]string{}
			for key, value := range inc {
				c[key] = canon(value)
			}
			added = append(added, c)
		}
	}
	combos = append(combos, added...)
	if len(combos) == 0 {
		return nil, fmt.Errorf("job %q matrix expands to zero legs", job)
	}
	return combos, nil
}

func matrixLegs(job string, matrix any) (int, error) {
	combos, err := expandMatrixCombos(job, matrix)
	if err != nil {
		return 0, err
	}
	return len(combos), nil
}

// expandWorkflowJobNames derives the full-run job name->count multiset from
// the workflow's jobs and matrix expansion (job `name:` templates expanded over
// matrix legs).
func expandWorkflowJobNames(body []byte, wf *workflowFile) (map[string]int, error) {
	var raw struct {
		Jobs map[string]struct {
			Strategy *struct {
				Matrix any `yaml:"matrix"`
			} `yaml:"strategy"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("expandWorkflowJobNames: unmarshal: %w", err)
	}
	counts := map[string]int{}
	for _, jobID := range slices.Sorted(maps.Keys(wf.Jobs)) {
		job := wf.Jobs[jobID]
		tmpl := strings.TrimSpace(job.Name)
		if tmpl == "" {
			tmpl = jobID
		}
		rawJob := raw.Jobs[jobID]
		if rawJob.Strategy == nil || rawJob.Strategy.Matrix == nil {
			if strings.Contains(tmpl, "${{") {
				return nil, fmt.Errorf("non-matrix job %q name %q contains unexpanded expression", jobID, tmpl)
			}
			counts[tmpl]++
			continue
		}
		combos, err := expandMatrixCombos(jobID, rawJob.Strategy.Matrix)
		if err != nil {
			return nil, err
		}
		for _, combo := range combos {
			name := tmpl
			for _, key := range slices.Sorted(maps.Keys(combo)) {
				name = strings.ReplaceAll(name, "${{ matrix."+key+" }}", combo[key])
			}
			if strings.Contains(name, "${{") {
				return nil, fmt.Errorf("matrix job %q expanded name %q retains unexpanded expression", jobID, name)
			}
			counts[name]++
		}
	}
	return counts, nil
}

// extractNightlyExpectedJobs parses and evaluates the expected_jobs table
// embedded in the classify job's nightly step Python.
func extractNightlyExpectedJobs(wf *workflowFile) (map[string]int, error) {
	script, err := extractStepPython(wf, "nightly")
	if err != nil {
		return nil, err
	}
	const extractor = `import ast, json, sys
tree = ast.parse(sys.argv[1])
found = None
for node in tree.body:
    if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id == "expected_jobs":
        found = node.value
        break
if found is None:
    sys.stderr.write("classify nightly step does not define expected_jobs\n")
    sys.exit(2)
expr = ast.Expression(body=found)
ast.fix_missing_locations(expr)
val = eval(compile(expr, "<expected_jobs>", "eval"), {"__builtins__": {"range": range, "map": map, "str": str}}, {})
if not isinstance(val, dict) or not val or any(not isinstance(k, str) or type(v) is not int or v <= 0 for k, v in val.items()):
    sys.stderr.write("expected_jobs is not a non-empty str->positive-int dict\n")
    sys.exit(3)
sys.stdout.write(json.dumps(val))
`
	cmd := exec.Command("python3", "-c", extractor, script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("nightly expected_jobs sync: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	var got map[string]int
	if err := json.Unmarshal(out, &got); err != nil {
		return nil, fmt.Errorf("nightly expected_jobs sync: unmarshal: %w", err)
	}
	return got, nil
}

// verifyNightlyExpectedJobsSync asserts that the nightly step's embedded
// expected_jobs table matches the workflow's expanded job-name multiset.
func verifyNightlyExpectedJobsSync(body []byte, wf *workflowFile) error {
	want, err := expandWorkflowJobNames(body, wf)
	if err != nil {
		return err
	}
	got, err := extractNightlyExpectedJobs(wf)
	if err != nil {
		return err
	}
	if !maps.Equal(got, want) {
		allKeys := map[string]bool{}
		for k := range want {
			allKeys[k] = true
		}
		for k := range got {
			allKeys[k] = true
		}
		for _, k := range slices.Sorted(maps.Keys(allKeys)) {
			if got[k] != want[k] {
				return fmt.Errorf("nightly expected_jobs out of sync with workflow jobs for %q: expected_jobs has %d, workflow expands to %d (total expected_jobs=%d, workflow=%d)", k, got[k], want[k], len(got), len(want))
			}
		}
	}
	return nil
}

// nightlyTimeTokens would indicate a time-window freshness heuristic
// instead of proof by the same main SHA.
var nightlyTimeTokens = []string{"datetime", "timedelta", "time.time", "strptime", "fromisoformat", "utcnow", "created_at", "updated_at", "run_started_at", "created=", "\"created\"", "hours", "date -", "date +"}

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
		name     string
		files    map[string]string
		wantPR   string
		wantPush string
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

// ghStub emulates the read-only GitHub REST API subset allowed by ruling 3:
//   - commits/main
//   - actions/runs/{current_run_id}
//   - contents/.github/workflows/ci.yml?ref={head_sha}
//   - actions/workflows/{workflow_id}/runs?branch=main&head_sha={sha}&status=success&per_page=100
//   - actions/runs/{candidate_id}/attempts/1/jobs?per_page=100
//
// Any non-GET request or unknown endpoint records a test violation in
// GH_STUB_VIOLATION and exits non-zero, rather than silently returning data.
const ghStub = `#!/usr/bin/env python3
import json, os, re, sys, urllib.parse

args = sys.argv[1:]
log_path = os.environ["GH_STUB_LOG"]
prior_calls = []
if os.path.exists(log_path):
    with open(log_path) as log_in:
        prior_calls = [json.loads(line) for line in log_in if line.strip()]
with open(log_path, "a") as log:
    log.write(json.dumps(args) + "\n")
with open(os.environ["GH_STUB_FIXTURE"]) as f:
    fx = json.load(f)

def fail(msg):
    sys.stderr.write(msg + "\n")
    sys.exit(1)

def violate(msg):
    vpath = os.environ.get("GH_STUB_VIOLATION")
    if vpath:
        with open(vpath, "a") as vf:
            vf.write(msg + "\n")
    fail(msg)

def out(obj):
    sys.stdout.write(json.dumps(obj))
    sys.exit(0)

if fx.get("fail_all"):
    fail("HTTP 502: stub outage")
if not args or args[0] != "api":
    violate("stub supports only gh api")
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
    violate("stub refuses non-GET requests: " + str(args))
path, _, query = endpoint.lstrip("/").partition("?")
params = dict(urllib.parse.parse_qsl(query, keep_blank_values=True))
params.update(fields)
if "created" in params:
    violate("time-window filters are not supported")
prefix = "repos/" + fx["repo"] + "/"
if not path.startswith(prefix):
    violate("endpoint missing repos/{repo}/ prefix: " + path)
path = path[len(prefix):]
failing = set(fx.get("fail", []))
runs = fx["runs"]
by_id = {str(r["id"]): r for r in runs}
allowed_content_paths = {".github/workflows/ci.yml"} | {r.get("path", "") for r in runs if r.get("path")}

if path == "commits/main" and not params:
    if "commit" in failing:
        fail("HTTP 502")
    out({"sha": fx["main_sha"]})

m = re.fullmatch(r"actions/runs/(\d+)", path)
if m and not params:
    if "run" in failing:
        fail("HTTP 502")
    if m.group(1) not in by_id:
        fail("HTTP 404")
    out(by_id[m.group(1)])

if path.startswith("contents/"):
    content_path = urllib.parse.unquote(path[len("contents/"):])
    if content_path not in allowed_content_paths or set(params.keys()) != {"ref"} or not params["ref"]:
        violate("unsupported contents endpoint or query: " + endpoint)
    if "contents" in failing:
        fail("HTTP 502")
    prior_contents = sum(
        1 for call in prior_calls
        if any(isinstance(tok, str) and "/contents/" in tok for tok in call)
    )
    blob_sha = fx["blob_sha"]
    if prior_contents >= 1 and "candidate_blob_sha" in fx:
        blob_sha = fx["candidate_blob_sha"]
    out({"sha": blob_sha, "type": "file", "path": content_path})

m = re.fullmatch(r"actions/workflows/(\d+)/runs", path)
if m and set(params.keys()) == {"branch", "head_sha", "status", "per_page"} and params["branch"] == "main" and params["status"] == "success" and params["per_page"] == "100":
    if "runs" in failing:
        fail("HTTP 502")
    current_id = fx.get("current_id")
    selected = [r for r in runs if r["id"] != current_id]
    selected.sort(key=lambda r: r["id"], reverse=True)
    per_page = int(params["per_page"])
    out({"total_count": fx.get("runs_total", len(selected)),
         "workflow_runs": selected[:per_page]})

m = re.fullmatch(r"actions/runs/(\d+)/attempts/1/jobs", path)
if m and set(params.keys()) == {"per_page"} and params["per_page"] == "100":
    if "jobs" in failing:
        fail("HTTP 502")
    if m.group(1) not in by_id:
        fail("HTTP 404")
    jobs = fx["jobs"].get(m.group(1), [])
    per_page = int(params["per_page"])
    out({"total_count": fx.get("jobs_total", len(jobs)),
         "jobs": jobs[:per_page]})

violate("HTTP 404: unsupported stub endpoint " + endpoint)
`

// verifyNightlyGuard runs the nightly step's own Python with a stub gh on
// PATH (never the real gh or network) and requires fail-safe skip=false
// unless a prior successful first-attempt full run (schedule or
// workflow_dispatch) of the same workflow file and workflow blob SHA on the
// exact main commit proves every expanded workflow job succeeded once.
func verifyNightlyGuard(t *testing.T, wf *workflowFile, body []byte) error {
	t.Helper()
	script, err := extractStepPython(wf, "nightly")
	if err != nil {
		return err
	}
	expandedCounts, err := expandWorkflowJobNames(body, wf)
	if err != nil {
		return err
	}
	var fullJobNames []string
	for _, name := range slices.Sorted(maps.Keys(expandedCounts)) {
		for range expandedCounts[name] {
			fullJobNames = append(fullJobNames, name)
		}
	}

	_, step := findStep(wf.Jobs["classify"], "nightly")
	const (
		repo         = "gobha-me/arcadectl"
		sha          = "0123456789abcdef0123456789abcdef01234567"
		otherSHA     = "89abcdef0123456789abcdef0123456789abcdef"
		blobSHA      = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		otherBlobSHA = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		workflowID   = 77
		currentID    = 5000
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
	runWith := func(base map[string]any, key string, val any) map[string]any {
		c := maps.Clone(base)
		c[key] = val
		return c
	}
	current := run(currentID, "schedule", "in_progress", "", sha, "main")
	jobs := func(runID int, runSHA string, mutate func([]map[string]any) []map[string]any) []map[string]any {
		var out []map[string]any
		for i, name := range fullJobNames {
			out = append(out, map[string]any{
				"id": runID*100 + i + 1, "run_id": runID, "run_attempt": 1, "head_sha": runSHA, "name": name,
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
					c["id"] = j["id"].(int) + 500
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
			"repo": repo, "main_sha": sha, "blob_sha": blobSHA, "current_id": currentID,
			"runs": append([]map[string]any{current}, prior...), "jobs": jobsJSON,
		}
	}
	goodPrior := run(4000, "schedule", "completed", "success", sha, "main")
	goodDispatch := run(4000, "workflow_dispatch", "completed", "success", sha, "main")
	proven := func() map[string]any {
		return fixture([]map[string]any{goodPrior}, map[int][]map[string]any{4000: jobs(4000, sha, nil)})
	}
	provenDispatch := func() map[string]any {
		return fixture([]map[string]any{goodDispatch}, map[int][]map[string]any{4000: jobs(4000, sha, nil)})
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
		// Unhappy paths first: API errors (6), truncated pages (ii), single-field negatives (1)-(5), push/PR only (v).
		{"(i) gh api errors on every call", with(proven(), "fail_all", true), false},
		{"(i-b) gh api errors listing jobs", with(proven(), "fail", []string{"jobs"}), false},
		{"(i-c) gh api errors listing runs", with(proven(), "fail", []string{"runs"}), false},
		{"(i-d) gh api errors fetching workflow contents blob", with(proven(), "fail", []string{"contents"}), false},
		{"(ii) truncated run page total_count>=100", with(fixture(append(slices.Clone(page), goodPrior), map[int][]map[string]any{4000: jobs(4000, sha, nil)}), "runs_total", 150), false},
		{"(ii-b) truncated jobs page total_count>=100", with(proven(), "jobs_total", 120), false},
		{"(1a) different workflow file (candidate path differs)", fixture([]map[string]any{runWith(goodPrior, "path", ".github/workflows/other.yml")}, map[int][]map[string]any{4000: jobs(4000, sha, nil)}), false},
		{"(1b) different workflow file (candidate workflow_id differs)", fixture([]map[string]any{runWith(goodPrior, "workflow_id", 999)}, map[int][]map[string]any{4000: jobs(4000, sha, nil)}), false},
		{"(2) different workflow blob sha (contents sha differs for candidate)", with(proven(), "candidate_blob_sha", otherBlobSHA), false},
		{"(3a) different commit (candidate head_sha differs)", fixture([]map[string]any{
			run(4003, "schedule", "completed", "success", otherSHA, "main"),
		}, map[int][]map[string]any{4003: jobs(4003, otherSHA, nil)}), false},
		{"(3b) different commit (main moved since scheduled SHA)", with(proven(), "main_sha", otherSHA), false},
		{"(4a) unsuccessful run (candidate conclusion failure)", fixture([]map[string]any{runWith(goodPrior, "conclusion", "failure")}, map[int][]map[string]any{4000: jobs(4000, sha, nil)}), false},
		{"(4b) prior run with one failed job", fixture([]map[string]any{goodPrior}, map[int][]map[string]any{4000: jobs(4000, sha, setConclusion("Installer engine race shard 0", "failure"))}), false},
		{"(5a) partial run (candidate run_attempt 2)", fixture([]map[string]any{runWith(goodPrior, "run_attempt", 2)}, map[int][]map[string]any{4000: jobs(4000, sha, nil)}), false},
		{"(iv) prior run with Kind lifecycle skipped", fixture([]map[string]any{goodPrior}, map[int][]map[string]any{4000: jobs(4000, sha, setConclusion("Kind lifecycle", "skipped"))}), false},
		{"(iv-b) prior run without a Kind lifecycle job", fixture([]map[string]any{goodPrior}, map[int][]map[string]any{4000: jobs(4000, sha, drop("Kind lifecycle"))}), false},
		{"(iv-c) prior run with two Kind lifecycle jobs", fixture([]map[string]any{goodPrior}, map[int][]map[string]any{4000: jobs(4000, sha, duplicate("Kind lifecycle"))}), false},
		{"(iv-d) prior run without the Go and policy job", fixture([]map[string]any{goodPrior}, map[int][]map[string]any{4000: jobs(4000, sha, drop("Go and policy"))}), false},
		{"(5b) partial run missing one race shard job", fixture([]map[string]any{goodPrior}, map[int][]map[string]any{4000: jobs(4000, sha, drop("Installer engine race shard 31"))}), false},
		{"(v) only push/PR runs of the same SHA", fixture([]map[string]any{
			run(4001, "push", "completed", "success", sha, "main"),
			run(4002, "pull_request", "completed", "success", sha, "topic"),
		}, map[int][]map[string]any{4001: jobs(4001, sha, nil), 4002: jobs(4002, sha, nil)}), false},
		// Positive cases: prior schedule full run and prior workflow_dispatch full run.
		{"(iii) prior successful schedule run of same SHA and workflow blob, every job success", proven(), true},
		{"(iii-b) prior successful workflow_dispatch run of same SHA and workflow blob, every job success", provenDispatch(), true},
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
		fixturePath := filepath.Join(dir, "fixture.json")
		logPath := filepath.Join(dir, "gh.log")
		violationPath := filepath.Join(dir, "gh.violation")
		outputPath := filepath.Join(dir, "github_output")
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
			"GH_STUB_VIOLATION=" + violationPath,
		}, stepEnv...)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("nightly guard %s: must exit 0 and fail safe, got %v\n%s", sc.name, err, out)
		}
		if vBytes, err := os.ReadFile(violationPath); err == nil && len(strings.TrimSpace(string(vBytes))) > 0 {
			return fmt.Errorf("nightly guard %s: stub API contract violation: %s", sc.name, strings.TrimSpace(string(vBytes)))
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
// execution, expected_jobs sync, then the classifier and nightly guard Python
// with fixtures.
func validateAll(t *testing.T, body []byte) (*workflowFile, error) {
	t.Helper()
	wf, err := validateCIWorkflowBytes(body)
	if err != nil {
		return nil, err
	}
	if err := verifyNightlyExpectedJobsSync(body, wf); err != nil {
		return nil, err
	}
	if err := verifyClassifierFailSafe(t, wf); err != nil {
		return nil, fmt.Errorf("classifier: %w", err)
	}
	if err := verifyNightlyGuard(t, wf, body); err != nil {
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
			// Also report independent rule failures when evaluating an override
			// (such as pre-change 6136fe9) so all failing checks are recorded.
			var wf workflowFile
			if yaml.Unmarshal(body, &wf) == nil {
				wantBulkNeeds := []string{
					"classify", "installer-diagnostics", "kind-install-gc", "kind-install-admission",
					"kind-install-admission-v3", "kind-install-auth", "kind-install-baseline", "kind-install-precontroller",
				}
				if err1 := validateGoPolicyIndependence(&wf); err1 != nil {
					t.Logf("R7 rule 1 (go-policy-checks independence) failure: %v", err1)
				}
				if v3Cap := wf.Jobs["kind-install-admission-v3"].Strategy.MaxParallel; v3Cap != 3 {
					t.Logf("R7 rule 2 (v3 max-parallel) failure: rule 2: kind-install-admission-v3 strategy.max-parallel = %v, want 3", v3Cap)
				}
				if err3 := validateCapacityEdges(&wf, wantBulkNeeds); err3 != nil {
					t.Logf("R7 rule 3 (capacity edges) failure: %v", err3)
				} else if wantAPINeeds := []string{"classify", "installer-diagnostics", "envtest"}; !slices.Equal(wf.Jobs["kind-api"].Needs, wantAPINeeds) {
					t.Logf("R7 rule 3 (kind-api needs) failure: rule 3: kind-api needs = %v, want %v (envtest capacity edge required)", wf.Jobs["kind-api"].Needs, wantAPINeeds)
				}
				if err4 := validateEnvtestPolicy(&wf, wantBulkNeeds); err4 != nil {
					t.Logf("R7 rule 4 (envtest policy) failure: %v", err4)
				}
				if wantEnvtestNeeds := append(slices.Clone(wantBulkNeeds), "go-policy-checks"); !slices.Equal(wf.Jobs["envtest"].Needs, wantEnvtestNeeds) {
					t.Logf("R7 rule 4 (envtest needs) failure: rule 4: envtest needs = %v, want %v (go-policy-checks capacity edge required)", wf.Jobs["envtest"].Needs, wantEnvtestNeeds)
				}
				if _, err5 := validateFairness(body); err5 != nil {
					t.Logf("R7 rule 5 (fairness) failure: %v", err5)
				}
				if errA := validateConcurrency(&wf); errA != nil {
					t.Logf("A (concurrency) failure: %v", errA)
				}
				if errC := verifyNightlyExpectedJobsSync(body, &wf); errC != nil {
					t.Logf("C (expected_jobs sync) failure: %v", errC)
				}
				if errB := verifyNightlyGuard(t, &wf, body); errB != nil {
					t.Logf("B (nightly guard) failure: %v", errB)
				}
			}
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
	if err := verifyNightlyExpectedJobsSync(ciBody, wf); err != nil {
		t.Fatalf("real ci.yml nightly expected_jobs out of sync: %v", err)
	}
	if err := verifyClassifierFailSafe(t, wf); err != nil {
		t.Fatalf("real ci.yml classifier failed fail-safe verification: %v", err)
	}
	if err := verifyNightlyGuard(t, wf, ciBody); err != nil {
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
			wantErr: "worst-case concurrent hosted jobs = 13 > 10",
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
				return strings.Replace(s,
					"  group: ${{ github.event_name == 'pull_request' && format('ci-{0}-{1}', github.workflow, github.event.pull_request.number) || format('ci-{0}-{1}-{2}', github.workflow, github.ref, github.run_id) }}",
					"  group: ci-${{ github.workflow }}-${{ github.event_name }}-${{ github.ref }}", 1)
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
				return replaceInJob(s, "classify", "          import json\n", "          import datetime\n          import json\n")
			},
			wantErr: "time-window logic token \"datetime\"",
		},
		{
			name: "nightly guard trusts a truncated page",
			mutate: func(s string) string {
				return replaceInJob(s, "classify",
					"\n                      or not 0 <= count < 100 or len(entries) != count\n                      or any(not isinstance(entry, dict) for entry in entries)\n                      or len({positive_int(entry[\"id\"]) for entry in entries}) != count):",
					"):")
			},
			wantErr: "nightly guard (ii) truncated run page total_count>=100: skip=true, want false",
		},
		{
			name: "nightly guard skips on API error",
			mutate: func(s string) string {
				return replaceInJob(s, "classify", `print("::notice::Identical-commit/workflow full-run proof uncertain; running full CI")`, "skip = True")
			},
			wantErr: "nightly guard (i) gh api errors on every call: skip=true, want false",
		},
		{
			name: "nightly guard does not require a Kind lifecycle job",
			mutate: func(s string) string {
				return replaceInJob(s, "classify",
					"if (len(jobs) == sum(expected_jobs.values())\n                          and Counter(job[\"name\"] for job in jobs) == expected_jobs",
					"if (Counter(job[\"name\"] for job in jobs if job[\"name\"] != \"Kind lifecycle\") == {k: v for k, v in expected_jobs.items() if k != \"Kind lifecycle\"}")
			},
			wantErr: "nightly guard (iv-b) prior run without a Kind lifecycle job: skip=true, want false",
		},
		// Round 6 (Atlas rulings 2 & 3): concurrency run_id/PR group semantics,
		// workflow path and blob SHA checks, run_attempt=1, expected_jobs sync,
		// and run/job conclusion checks.
		{
			name: "r6-(a) run_id dropped from non-PR concurrency group",
			mutate: func(s string) string {
				return strings.Replace(s,
					"format('ci-{0}-{1}-{2}', github.workflow, github.ref, github.run_id)",
					"format('ci-{0}-{1}', github.workflow, github.ref)", 1)
			},
			wantErr: "must include github.run_id",
		},
		{
			name: "r6-(b) PR concurrency group includes run_id",
			mutate: func(s string) string {
				return strings.Replace(s,
					"format('ci-{0}-{1}', github.workflow, github.event.pull_request.number)",
					"format('ci-{0}-{1}-{2}', github.workflow, github.event.pull_request.number, github.run_id)", 1)
			},
			wantErr: "workflow concurrency group on PR #140 runs 1/2",
		},
		{
			name: "r6-(d) old concurrency group expression without run_id restored",
			mutate: func(s string) string {
				return strings.Replace(s,
					"  group: ${{ github.event_name == 'pull_request' && format('ci-{0}-{1}', github.workflow, github.event.pull_request.number) || format('ci-{0}-{1}-{2}', github.workflow, github.ref, github.run_id) }}",
					"  group: ci-${{ github.workflow }}-${{ github.event.pull_request.number || github.ref }}", 1)
			},
			wantErr: "must include github.run_id",
		},
		{
			name: "r6-(e) nightly guard workflow path check removed",
			mutate: func(s string) string {
				s = replaceInJob(s, "classify", "              if path != \".github/workflows/ci.yml\":\n                  raise ValueError(\"unexpected workflow path or @ref suffix\")\n", "")
				return replaceInJob(s, "classify", ` or run["path"] != current["path"]`, "")
			},
			wantErr: "nightly guard (1a) different workflow file (candidate path differs): skip=true, want false",
		},
		{
			name: "r6-(f1) nightly guard workflow blob-sha comparison removed",
			mutate: func(s string) string {
				return replaceInJob(s, "classify", "                  if workflow_blob(run) != current_blob:\n                      raise ValueError(\"workflow blob mismatch\")\n", "")
			},
			wantErr: "nightly guard (2) different workflow blob sha (contents sha differs for candidate): skip=true, want false",
		},
		{
			name: "r6-(f2) nightly guard workflow blob-sha comparison inverted",
			mutate: func(s string) string {
				return replaceInJob(s, "classify", "if workflow_blob(run) != current_blob:", "if workflow_blob(run) == current_blob:")
			},
			wantErr: "nightly guard (2) different workflow blob sha (contents sha differs for candidate): skip=true, want false",
		},
		{
			name: "r6-(g) nightly guard run_attempt check removed",
			mutate: func(s string) string {
				return replaceInJob(s, "classify", "                  if run[\"run_attempt\"] != 1:\n                      continue\n", "")
			},
			wantErr: "nightly guard (5a) partial run (candidate run_attempt 2): skip=true, want false",
		},
		{
			name: "r6-(h) nightly guard expected_jobs table missing one race shard",
			mutate: func(s string) string {
				return replaceInJob(s, "classify",
					`**{f"Installer engine race shard {shard}": 1 for shard in range(32)},`,
					`**{f"Installer engine race shard {shard}": 1 for shard in range(31)},`)
			},
			wantErr: "nightly expected_jobs out of sync with workflow jobs for \"Installer engine race shard 31\"",
		},
		{
			name: "r6-(i) nightly guard expected_jobs count check removed (accepts subset)",
			mutate: func(s string) string {
				return replaceInJob(s, "classify",
					"                  if (len(jobs) == sum(expected_jobs.values())\n                          and Counter(job[\"name\"] for job in jobs) == expected_jobs",
					"                  if (set(job[\"name\"] for job in jobs) <= set(expected_jobs)")
			},
			wantErr: "nightly guard (iv-b) prior run without a Kind lifecycle job: skip=true, want false",
		},
		{
			name: "r6-(j1) nightly guard run conclusion check removed",
			mutate: func(s string) string {
				return replaceInJob(s, "classify", `or run["conclusion"] != "success" `, "")
			},
			wantErr: "nightly guard (4a) unsuccessful run (candidate conclusion failure): skip=true, want false",
		},
		{
			name: "r6-(j2) nightly guard job conclusion check removed",
			mutate: func(s string) string {
				return replaceInJob(s, "classify", ` and job["conclusion"] == "success"`, "")
			},
			wantErr: "nightly guard (4b) prior run with one failed job: skip=true, want false",
		},
		{
			name: "r6-stub-unknown-endpoint rejected by stub contract",
			mutate: func(s string) string {
				return replaceInJob(s, "classify", "actions/workflows/{workflow_id}/runs", "actions/runs")
			},
			wantErr: "stub API contract violation: HTTP 404: unsupported stub endpoint",
		},
		// Round 7 (Atlas ruling 4): go-policy-checks runs early without envtest,
		// v3 max-parallel 3, kind-api waits on envtest (!cancelled()), and
		// envtest waits on go-policy-checks with !cancelled() + explicit
		// foundation result == 'success' checks.
		{
			name: "r7-(a) v3 max-parallel back to 4",
			mutate: func(s string) string {
				return regexpInJob(s, "kind-install-admission-v3", `max-parallel: \d+`, "max-parallel: 4")
			},
			wantErr: "worst-case concurrent hosted jobs = 11 > 10",
		},
		{
			name: "r7-(a2) v3 max-parallel lowered to 2",
			mutate: func(s string) string {
				return regexpInJob(s, "kind-install-admission-v3", `max-parallel: \d+`, "max-parallel: 2")
			},
			wantErr: "rule 2: kind-install-admission-v3 strategy.max-parallel = 2, want 3",
		},
		{
			name: "r7-(b) kind-api envtest edge removed",
			mutate: func(s string) string {
				return regexpInJob(s, "kind-api", `needs: \[[^\]]*\]`, "needs: [classify, installer-diagnostics]")
			},
			wantErr: "worst-case concurrent hosted jobs = 11 > 10",
		},
		{
			name: "r7-(c) go-policy-checks needs envtest again",
			mutate: func(s string) string {
				return regexpInJob(s, "go-policy-checks", `needs: \[[^\]]*\]`, "needs: [classify, installer-diagnostics, envtest]")
			},
			wantErr: "Go/policy must not depend on envtest",
		},
		{
			name: "r7-(c2) go-policy-checks transitively depends on envtest",
			mutate: func(s string) string {
				return regexpInJob(s, "go-policy-checks", `needs: \[[^\]]*\]`, "needs: [classify, installer-diagnostics, kind-recovery]")
			},
			wantErr: "Go/policy must not depend on envtest",
		},
		{
			name: "r7-(c3) go-policy-checks depends on a Kind job",
			mutate: func(s string) string {
				return regexpInJob(s, "go-policy-checks", `needs: \[[^\]]*\]`, "needs: [classify, installer-diagnostics, kind-install-gc]")
			},
			wantErr: "Go/policy must not depend on any Kind, race or envtest job",
		},
		{
			name: "r7-(d) envtest edge on go-policy-checks removed",
			mutate: func(s string) string {
				return replaceInJob(s, "envtest", ", go-policy-checks]", "]")
			},
			wantErr: "worst-case concurrent hosted jobs = 11 > 10",
		},
		{
			name: "r7-(e) envtest if back to bare success() with the policy edge",
			mutate: func(s string) string {
				oldIf := "    if: >-\n      ${{ !cancelled() && needs.classify.result == 'success' && needs.installer-diagnostics.result == 'success' &&\n          needs.kind-install-gc.result == 'success' && needs.kind-install-admission.result == 'success' &&\n          needs.kind-install-admission-v3.result == 'success' && needs.kind-install-auth.result == 'success' &&\n          needs.kind-install-baseline.result == 'success' && needs.kind-install-precontroller.result == 'success' &&\n          needs.classify.outputs.scope != 'docs' && needs.classify.outputs.scope != 'idle' && needs.classify.outputs.scope != 'cheap' }}"
				newIf := "    if: ${{ success() && needs.classify.outputs.scope != 'docs' && needs.classify.outputs.scope != 'idle' && needs.classify.outputs.scope != 'cheap' }}"
				return replaceInJob(s, "envtest", oldIf, newIf)
			},
			wantErr: "rule 4: envtest if condition must use !cancelled() and not bare success()",
		},
		{
			name: "r7-(f) kind-api if with success() instead of !cancelled()",
			mutate: func(s string) string {
				return replaceInJob(s, "kind-api", "if: ${{ !cancelled() &&", "if: ${{ success() &&")
			},
			wantErr: "rule 3: job \"kind-api\" has capacity-only needs [envtest]",
		},
		{
			name: "r7-(g) envtest if referencing needs.go-policy-checks.result == 'success'",
			mutate: func(s string) string {
				return replaceInJob(s, "envtest",
					"needs.kind-install-precontroller.result == 'success' &&",
					"needs.kind-install-precontroller.result == 'success' && needs.go-policy-checks.result == 'success' &&")
			},
			wantErr: "rule 4: envtest if condition must not reference go-policy-checks result",
		},
		{
			name: "r7-(g2) envtest if omits a foundation result == 'success'",
			mutate: func(s string) string {
				return replaceInJob(s, "envtest", "needs.kind-install-gc.result == 'success' && ", "")
			},
			wantErr: "rule 4: envtest if condition must require foundation \"kind-install-gc\"",
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

func TestConcurrencyExpressionEvaluator(t *testing.T) {
	const expr = "${{ github.event_name == 'pull_request' && format('ci-{0}-{1}', github.workflow, github.event.pull_request.number) || format('ci-{0}-{1}-{2}', github.workflow, github.ref, github.run_id) }}"
	pr1 := ghEvalContext{Workflow: "CI", EventName: "pull_request", Ref: "refs/pull/140/merge", RunID: "1001", PRNumber: "140"}
	pr2 := ghEvalContext{Workflow: "CI", EventName: "pull_request", Ref: "refs/pull/140/merge", RunID: "1002", PRNumber: "140"}
	push1 := ghEvalContext{Workflow: "CI", EventName: "push", Ref: "refs/heads/main", RunID: "2001"}
	push2 := ghEvalContext{Workflow: "CI", EventName: "push", Ref: "refs/heads/main", RunID: "2002"}

	gPR1, err := evalGitHubTemplate(expr, pr1)
	if err != nil || gPR1 != "ci-CI-140" {
		t.Fatalf("PR run 1 = %q, %v; want ci-CI-140", gPR1, err)
	}
	gPR2, err := evalGitHubTemplate(expr, pr2)
	if err != nil || gPR2 != gPR1 {
		t.Fatalf("PR run 2 = %q, %v; want %q", gPR2, err, gPR1)
	}
	gPush1, err := evalGitHubTemplate(expr, push1)
	if err != nil || gPush1 != "ci-CI-refs/heads/main-2001" {
		t.Fatalf("push run 1 = %q, %v; want ci-CI-refs/heads/main-2001", gPush1, err)
	}
	gPush2, err := evalGitHubTemplate(expr, push2)
	if err != nil || gPush2 != "ci-CI-refs/heads/main-2002" || gPush1 == gPush2 {
		t.Fatalf("push run 2 = %q, %v; want distinct ci-CI-refs/heads/main-2002", gPush2, err)
	}

	// Reject anything outside the supported expression subset rather than passing.
	for _, unparseable := range []string{
		"static-group-without-expression",
		"${{ }}",
		"${{ github.workflow ",
		"ci-${{ github.workflow }} }}",
		"${{ github.unknown_field }}",
		"${{ runner.os }}",
		"${{ !github.event_name }}",
		"${{ github.event_name == 'pull_request' && }}",
		"${{ format('ci-{0}', github.workflow, github.ref) }}",
		"${{ format('ci-{2}', github.workflow) }}",
		"${{ format('ci-{0', github.workflow) }}",
		"${{ format('ci-0}', github.workflow) }}",
		"${{ join(github.workflow, '-') }}",
		"${{ 'unterminated }}",
		"${{ github.workflow extra }}",
	} {
		if got, err := evalGitHubTemplate(unparseable, pr1); err == nil {
			t.Fatalf("evalGitHubTemplate accepted invalid/unsupported expression %q -> %q", unparseable, got)
		}
	}
}
