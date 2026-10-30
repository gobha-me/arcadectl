package workflowpolicy

import (
	"context"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	yaml "go.yaml.in/yaml/v3"
)

const companionConcurrencyGroup = "${{ github.workflow }}-${{ github.event_name == 'pull_request' && github.ref || format('{0}-{1}', github.sha, github.run_id) }}"

func validateCompanionConcurrency(wf *workflowFile) error {
	group, ok := wf.Concurrency["group"].(string)
	if !ok || group != companionConcurrencyGroup {
		return fmt.Errorf("companion policy requires its reviewed expression")
	}
	for _, event := range []string{"pull_request", "push", "schedule", "workflow_dispatch"} {
		a := ghEvalContext{Workflow: "CI", EventName: event, Ref: "refs/heads/main", SHA: strings.Repeat("a", 40), RunID: "9001"}
		if event == "pull_request" {
			a.Ref = "refs/pull/140/merge"
		}
		b := a
		b.RunID = "9002"
		first, err := evalGitHubTemplate(group, a)
		if err != nil {
			return err
		}
		second, err := evalGitHubTemplate(group, b)
		if err != nil {
			return err
		}
		want := "CI-" + a.SHA + "-" + a.RunID
		if event == "pull_request" {
			want = "CI-" + a.Ref
		}
		if first != want || (first == second) != (event == "pull_request") {
			return fmt.Errorf("companion groups violate PR stability/non-PR isolation for %s", event)
		}
		b.Workflow = "Other"
		other, err := evalGitHubTemplate(group, b)
		if err != nil || other == second {
			return fmt.Errorf("companion groups collide across workflows: %v", err)
		}
	}
	return nil
}

type integratedProof struct{ job, variable, command, file string }

var integratedProofs = []integratedProof{
	{"docs-check", "DOCS_CHECK_RESULT", "make verify-doc-links", "hack/check-doc-links.py"},
	{"golangci-lint", "GOLANGCI_LINT_RESULT", "ARCADECTL_REQUIRE_LINT_TOOL=1 go test ./hack/lintpolicy -count=1\nbash hack/lint-new-findings.sh", ".golangci.yml"},
	{"mutation-gate", "MUTATION_GATE_RESULT", "make mutation-gate", "hack/check-mutation-report.py"},
}

func integrationWorkflow(t *testing.T) *workflowFile {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var wf workflowFile
	if err := yaml.Unmarshal(body, &wf); err != nil {
		t.Fatal(err)
	}
	return &wf
}

// Check the actual aggregate Bash, not a replacement implementation of it.
func validateIntegratedProofs(wf *workflowFile, required []integratedProof) error {
	gate := wf.Jobs["go-and-policy"]
	var step *workflowStep
	for i := range gate.Steps {
		if gate.Steps[i].Name == gateStepName {
			step = &gate.Steps[i]
		}
	}
	if step == nil || step.If != "" || step.ContinueOnError != nil {
		return fmt.Errorf("unconditional aggregate step missing")
	}
	for _, proof := range required {
		job, exists := wf.Jobs[proof.job]
		if !exists || !slices.Contains(gate.Needs, proof.job) || job.ContinueOnError != nil ||
			step.Env[proof.variable] != "${{ needs."+proof.job+".result }}" {
			return fmt.Errorf("integrated %s is missing or not an aggregate prerequisite", proof.job)
		}
		if job.If != "" && job.If != "${{ !cancelled() && needs.classify.outputs.scope != 'idle' }}" {
			return fmt.Errorf("integrated %s can skip a non-idle scope", proof.job)
		}
		found := false
		for _, s := range job.Steps {
			if strings.TrimSpace(s.Run) == proof.command && s.If == "" && s.ContinueOnError == nil {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("integrated %s lacks its unconditional proof command", proof.job)
		}
	}
	for _, scope := range []string{"full", "cheap", "docs", "idle"} {
		for _, proof := range required {
			for _, result := range []string{"success", "failure", "cancelled", "skipped", ""} {
				env := []string{"PATH=" + os.Getenv("PATH"), "CI_SCOPE=" + scope, "CI_EVENT_NAME=pull_request", "CI_REF=refs/pull/1/merge"}
				if scope == "cheap" || scope == "idle" {
					env = []string{"PATH=" + os.Getenv("PATH"), "CI_SCOPE=" + scope, "CI_EVENT_NAME=push", "CI_REF=refs/heads/main"}
					if scope == "idle" {
						env[2] = "CI_EVENT_NAME=schedule"
					}
				}
				for name, value := range step.Env {
					if !strings.HasPrefix(value, "${{ needs.") || !strings.HasSuffix(value, ".result }}") {
						continue
					}
					v := "skipped"
					if name == "CLASSIFY_RESULT" || scope == "full" || scope == "cheap" && (name == "INSTALLER_DIAGNOSTICS_RESULT" || name == "GO_POLICY_CHECKS_RESULT") {
						v = "success"
					}
					for _, p := range required {
						if name == p.variable && scope != "idle" {
							v = "success"
						}
					}
					if name == proof.variable {
						v = result
					}
					env = append(env, name+"="+v)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				cmd := exec.CommandContext(ctx, "bash", "-e", "-c", step.Run)
				cmd.Env = env
				err := cmd.Run()
				cancel()
				want := "success"
				if scope == "idle" {
					want = "skipped"
				}
				if (err == nil) != (result == want) {
					return fmt.Errorf("aggregate accepted/refused %s=%q incorrectly in %s", proof.job, result, scope)
				}
			}
		}
	}
	return nil
}

func TestIntegratedPrerequisiteProofs(t *testing.T) {
	wf := integrationWorkflow(t)
	var required []integratedProof
	for _, proof := range integratedProofs {
		if _, err := os.Stat(filepath.Join("..", "..", proof.file)); err == nil {
			required = append(required, proof)
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
	if err := validateIntegratedProofs(wf, required); err != nil {
		t.Fatal(err)
	}
	// Pairing this standalone source with any prerequisite must reject the
	// missing proof, rather than claiming that docs/cheap scope certifies it.
	for _, proof := range integratedProofs {
		if _, exists := wf.Jobs[proof.job]; !exists && validateIntegratedProofs(wf, []integratedProof{proof}) == nil {
			t.Fatalf("missing integrated %s was accepted", proof.job)
		}
	}
}

func integratedCandidate(t *testing.T) *workflowFile {
	t.Helper()
	wf := integrationWorkflow(t)
	gate := wf.Jobs["go-and-policy"]
	prefix := "quality=success\nif [[ $CI_SCOPE == idle ]]; then quality=skipped; fi\n"
	for _, proof := range integratedProofs {
		wf.Jobs[proof.job] = workflowJob{Steps: []workflowStep{{Run: proof.command}}}
		gate.Needs = append(gate.Needs, proof.job)
		for i := range gate.Steps {
			if gate.Steps[i].Name == gateStepName {
				gate.Steps[i].Env = maps.Clone(gate.Steps[i].Env)
				gate.Steps[i].Env[proof.variable] = "${{ needs." + proof.job + ".result }}"
			}
		}
		prefix += "test \"$" + proof.variable + "\" = \"$quality\"\n"
	}
	for i := range gate.Steps {
		if gate.Steps[i].Name == gateStepName {
			gate.Steps[i].Run = prefix + gate.Steps[i].Run
		}
	}
	wf.Jobs["go-and-policy"] = gate
	return wf
}

func TestIntegratedProofsRejectBypasses(t *testing.T) {
	if err := validateIntegratedProofs(integratedCandidate(t), integratedProofs); err != nil {
		t.Fatal("positive gate control refused:", err)
	}
	if err := verifyGateBehavior(integratedCandidate(t)); err != nil {
		t.Fatal("integrated result tables refused the positive gate control:", err)
	}
	for _, bad := range []string{"missing-needs", "skipped-docs", "tolerated-step", "unwired-result", "aggregate-bypass"} {
		t.Run(bad, func(t *testing.T) {
			wf := integratedCandidate(t)
			job := wf.Jobs["docs-check"]
			gate := wf.Jobs["go-and-policy"]
			switch bad {
			case "missing-needs":
				gate.Needs = slices.DeleteFunc(gate.Needs, func(s string) bool { return s == "docs-check" })
			case "skipped-docs":
				job.If = "${{ needs.classify.outputs.scope != 'docs' }}"
			case "tolerated-step":
				job.Steps[0].ContinueOnError = true
			case "unwired-result":
				delete(gate.Steps[1].Env, "DOCS_CHECK_RESULT")
			case "aggregate-bypass":
				gate.Steps[1].Run = strings.Replace(gate.Steps[1].Run, "test \"$DOCS_CHECK_RESULT\" = \"$quality\"", ":", 1)
			}
			wf.Jobs["docs-check"], wf.Jobs["go-and-policy"] = job, gate
			if err := validateIntegratedProofs(wf, integratedProofs); err == nil {
				t.Fatal("integrated proof bypass accepted")
			}
		})
	}
}

func TestCompanionConcurrencyPolicy(t *testing.T) {
	wf := integrationWorkflow(t)
	wf.Concurrency["group"] = companionConcurrencyGroup
	if err := validateConcurrency(wf); err != nil {
		t.Fatal("reviewed companion policy refused:", err)
	}
	for _, bad := range []string{"${{ github.workflow }}-${{ github.ref }}", strings.Replace(companionConcurrencyGroup, "github.run_id", "github.sha", 1)} {
		wf.Concurrency["group"] = bad
		if err := validateConcurrency(wf); err == nil {
			t.Fatal("shared non-PR group accepted")
		}
	}
	wf.Concurrency["group"], wf.Concurrency["cancel-in-progress"] = companionConcurrencyGroup, true
	if err := validateConcurrency(wf); err == nil {
		t.Fatal("all-event cancellation accepted")
	}
}
