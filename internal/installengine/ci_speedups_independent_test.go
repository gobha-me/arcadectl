// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	yaml "go.yaml.in/yaml/v3"
)

type ciSpeedupsWorkflow struct {
	Jobs map[string]ciSpeedupsJob `yaml:"jobs"`
}

type ciSpeedupsJob struct {
	Name            string            `yaml:"name"`
	RunsOn          string            `yaml:"runs-on"`
	Container       any               `yaml:"container"`
	If              string            `yaml:"if"`
	ContinueOnError any               `yaml:"continue-on-error"`
	Needs           []string          `yaml:"needs"`
	TimeoutMinutes  int               `yaml:"timeout-minutes"`
	Env             map[string]string `yaml:"env"`
	Strategy        struct {
		FailFast    *bool `yaml:"fail-fast"`
		MaxParallel int   `yaml:"max-parallel"`
		Matrix      struct {
			Check   []string `yaml:"check"`
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
	Steps []ciSpeedupsStep `yaml:"steps"`
}

type ciSpeedupsStep struct {
	If              string            `yaml:"if"`
	ContinueOnError any               `yaml:"continue-on-error"`
	Name            string            `yaml:"name"`
	Uses            string            `yaml:"uses"`
	Run             string            `yaml:"run"`
	Env             map[string]string `yaml:"env"`
	With            map[string]any    `yaml:"with"`
}

func loadCISpeedupsWorkflow(t *testing.T) (ciSpeedupsWorkflow, []string) {
	t.Helper()
	raw, err := os.ReadFile("../../.github/workflows/ci.yml")
	if err != nil {
		t.Fatalf("read workflow: %v", err)
	}
	var wf ciSpeedupsWorkflow
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		t.Fatalf("unmarshal workflow: %v", err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		t.Fatal("parse workflow YAML AST")
	}
	var order []string
	rootMap := doc.Content[0]
	for i := 0; i+1 < len(rootMap.Content); i += 2 {
		if rootMap.Content[i].Value == "jobs" && rootMap.Content[i+1].Kind == yaml.MappingNode {
			jobsNode := rootMap.Content[i+1]
			for j := 0; j+1 < len(jobsNode.Content); j += 2 {
				order = append(order, jobsNode.Content[j].Value)
			}
		}
	}
	return wf, order
}

func cloneCISpeedupsJob(job ciSpeedupsJob) ciSpeedupsJob {
	out := job
	out.Needs = slices.Clone(job.Needs)
	if job.Env != nil {
		out.Env = make(map[string]string, len(job.Env))
		for k, v := range job.Env {
			out.Env[k] = v
		}
	}
	if job.Strategy.FailFast != nil {
		ff := *job.Strategy.FailFast
		out.Strategy.FailFast = &ff
	}
	out.Strategy.Matrix.Check = slices.Clone(job.Strategy.Matrix.Check)
	out.Strategy.Matrix.Shard = slices.Clone(job.Strategy.Matrix.Shard)
	out.Strategy.Matrix.Part = slices.Clone(job.Strategy.Matrix.Part)
	out.Strategy.Matrix.Profile = slices.Clone(job.Strategy.Matrix.Profile)
	out.Strategy.Matrix.Mode = slices.Clone(job.Strategy.Matrix.Mode)
	out.Strategy.Matrix.Exclude = slices.Clone(job.Strategy.Matrix.Exclude)
	out.Steps = make([]ciSpeedupsStep, len(job.Steps))
	for i, step := range job.Steps {
		s := step
		if step.Env != nil {
			s.Env = make(map[string]string, len(step.Env))
			for k, v := range step.Env {
				s.Env[k] = v
			}
		}
		if step.With != nil {
			s.With = make(map[string]any, len(step.With))
			for k, v := range step.With {
				s.With[k] = v
			}
		}
		out.Steps[i] = s
	}
	return out
}

func cloneCISpeedupsWorkflow(wf ciSpeedupsWorkflow) ciSpeedupsWorkflow {
	out := ciSpeedupsWorkflow{Jobs: make(map[string]ciSpeedupsJob, len(wf.Jobs))}
	for k, v := range wf.Jobs {
		out.Jobs[k] = cloneCISpeedupsJob(v)
	}
	return out
}

func checkCISpeedupsDiagnosticsMatrix(job ciSpeedupsJob) error {
	wantChecks := []string{"cli", "controls", "discovery", "observation", "benchmarks", "wrappers", "vet"}
	wantRuns := []string{
		"go test -race -p 1 -timeout=5m ./cmd/arcadectl-installer -count=1",
		"go test -race -tags=kindinstall -p 1 -timeout=5m ./internal/installengine -run '^(TestInstallerAdmissionCIProfilesAndFailClosedRequiredGate|TestEnvtestPartitionsCompleteCompiledUnion|TestEnvtestPartitionsRefuseInvalidInputs|TestEnvtestPartitionsAllPartsAndFailures|TestInstallerBinaryProgressCapture|TestInstallerBinaryRequestPipelineCapture|TestInstallerBinaryParentContext|TestLifecycleCostsBoundedCommandAndInvocationIsolation|TestLifecycleCostsConcurrentRefusalsAndCancellation)$' -count=1",
		"go test -race -p 1 -timeout=5m -v ./internal/installengine -run '^(TestDiscoveryReplyMemo.*|TestProofDiscovery.*|TestBaselineContainment.*|TestBaselineDenied(EightLanes|Index).*)$' -count=1",
		"go test -race -p 1 -timeout=5m ./internal/installobserve -run '^TestCollectionDiagnostic.*$' -count=1\ngo test -race -p 1 -timeout=5m ./internal/installengine -run '^(TestFixtureTypedCollectionDiagnostic.*|TestFixtureObservationDiagnostic.*|TestFixtureAdmissionSettle.*)$' -count=1\n",
		"go test -p 1 -timeout=2m ./internal/installengine -run '^$' -bench '^(BenchmarkDiscoveryReplyConversion|BenchmarkBaselineDeniedDescriptorMembership)$' -benchmem -benchtime=250ms -count=1",
		"go test -race -p 1 -timeout=1m ./hack/profile-installer-wrappers -count=1\ngo run -p 1 ./hack/profile-installer-wrappers '${{ github.event.pull_request.head.sha || github.sha }}'\n",
		"go vet -tags=kindinstall -p 1 ./cmd/arcadectl-installer ./internal/installengine ./internal/installobserve",
	}
	if job.Name != "Installer CLI and diagnostic controls" || job.RunsOn != "ubuntu-24.04" || job.TimeoutMinutes != 20 {
		return fmt.Errorf("unexpected diagnostics runner or timeout")
	}
	if len(job.Needs) != 0 || job.If != "" || job.ContinueOnError != nil {
		return fmt.Errorf("diagnostics job has unexpected prerequisites or condition")
	}
	if len(job.Env) != 2 || job.Env["GOMAXPROCS"] != "2" || job.Env["GOMEMLIMIT"] != "1GiB" {
		return fmt.Errorf("diagnostics job altered bounded Go env")
	}
	if job.Strategy.FailFast == nil || *job.Strategy.FailFast || job.Strategy.MaxParallel != 0 {
		return fmt.Errorf("diagnostics matrix must set fail-fast: false without max-parallel cap")
	}
	if !slices.Equal(job.Strategy.Matrix.Check, wantChecks) || len(job.Strategy.Matrix.Exclude) != 0 || len(job.Strategy.Matrix.Profile) != 0 || len(job.Strategy.Matrix.Mode) != 0 || len(job.Strategy.Matrix.Shard) != 0 || len(job.Strategy.Matrix.Part) != 0 {
		return fmt.Errorf("diagnostics matrix check list mismatch: %v", job.Strategy.Matrix.Check)
	}
	if len(job.Steps) != 2+len(wantChecks) {
		return fmt.Errorf("diagnostics step count mismatch: %d", len(job.Steps))
	}
	if job.Steps[0].Uses != "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1" || job.Steps[0].With["ref"] != "${{ github.event.pull_request.head.sha || github.sha }}" || job.Steps[0].If != "" || job.Steps[0].ContinueOnError != nil || job.Steps[0].Run != "" {
		return fmt.Errorf("diagnostics checkout step altered")
	}
	if job.Steps[1].Uses != "actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e" || job.Steps[1].With["go-version-file"] != "go.mod" || job.Steps[1].With["cache"] != true || job.Steps[1].If != "" || job.Steps[1].ContinueOnError != nil || job.Steps[1].Run != "" {
		return fmt.Errorf("diagnostics setup-go step altered")
	}
	for i, checkName := range wantChecks {
		step := job.Steps[2+i]
		wantIf := "matrix.check == '" + checkName + "'"
		if step.If != wantIf || step.ContinueOnError != nil || len(step.Env) != 0 || step.Uses != "" || step.Run != wantRuns[i] {
			return fmt.Errorf("diagnostics step %d (%s) altered", 2+i, checkName)
		}
	}
	return nil
}

func TestCISpeedupsDiagnosticsParallelMatrix(t *testing.T) {
	wf, _ := loadCISpeedupsWorkflow(t)
	diag, present := wf.Jobs["installer-diagnostics"]
	if !present {
		t.Fatal("installer-diagnostics job missing")
	}

	// Unhappy paths first: verify every invariant in checkCISpeedupsDiagnosticsMatrix can fail.
	trueVal := true
	for _, mutate := range []struct {
		name string
		fn   func(*ciSpeedupsJob)
	}{
		{"nil-fail-fast", func(j *ciSpeedupsJob) { j.Strategy.FailFast = nil }},
		{"true-fail-fast", func(j *ciSpeedupsJob) { j.Strategy.FailFast = &trueVal }},
		{"max-parallel-set", func(j *ciSpeedupsJob) { j.Strategy.MaxParallel = 2 }},
		{"omitted-check", func(j *ciSpeedupsJob) { j.Strategy.Matrix.Check = j.Strategy.Matrix.Check[:6] }},
		{"extra-check", func(j *ciSpeedupsJob) { j.Strategy.Matrix.Check = append(j.Strategy.Matrix.Check, "extra") }},
		{"reordered-checks", func(j *ciSpeedupsJob) {
			j.Strategy.Matrix.Check[0], j.Strategy.Matrix.Check[1] = j.Strategy.Matrix.Check[1], j.Strategy.Matrix.Check[0]
		}},
		{"timeout-changed", func(j *ciSpeedupsJob) { j.TimeoutMinutes = 25 }},
		{"needs-added", func(j *ciSpeedupsJob) { j.Needs = []string{"kind-images"} }},
		{"job-if-added", func(j *ciSpeedupsJob) { j.If = "${{ !cancelled() }}" }},
		{"job-continue-on-error", func(j *ciSpeedupsJob) { j.ContinueOnError = true }},
		{"env-changed", func(j *ciSpeedupsJob) { j.Env["GOMAXPROCS"] = "4" }},
		{"setup-step-conditional", func(j *ciSpeedupsJob) { j.Steps[0].If = "matrix.check == 'cli'" }},
		{"check-step-unconditional", func(j *ciSpeedupsJob) { j.Steps[2].If = "" }},
		{"check-step-wrong-selector", func(j *ciSpeedupsJob) { j.Steps[2].If = "matrix.check == 'vet'" }},
		{"check-step-tolerates-error", func(j *ciSpeedupsJob) { j.Steps[3].ContinueOnError = true }},
		{"check-step-command-altered", func(j *ciSpeedupsJob) { j.Steps[4].Run += " -short" }},
	} {
		bad := cloneCISpeedupsJob(diag)
		// Ensure base fixture is valid before applying single-fault mutation when running on head.
		if checkCISpeedupsDiagnosticsMatrix(bad) == nil {
			mutate.fn(&bad)
			if checkCISpeedupsDiagnosticsMatrix(bad) == nil {
				t.Fatalf("diagnostics validator accepted mutant %s", mutate.name)
			}
		}
	}

	if err := checkCISpeedupsDiagnosticsMatrix(diag); err != nil {
		t.Fatalf("installer-diagnostics parallel matrix check failed: %v", err)
	}
}

func checkCISpeedupsJobOrderAndBinaryMatrix(wf ciSpeedupsWorkflow, order []string) error {
	wantOrder := []string{
		"installer-diagnostics",
		"kind-images",
		"kind-install-binary",
		"kind-install-baseline",
		"kind-install-gc",
		"kind-install-precontroller",
		"kind-install-admission",
		"kind-install-admission-v3",
		"kind-install-auth",
		"kind-api",
		"kind-recovery",
		"install-engine-race",
		"envtest",
		"go-policy-checks",
		"go-and-policy",
		"kind-lifecycle",
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
	if !slices.Equal(order, wantOrder) || len(wf.Jobs) != len(wantOrder) {
		return fmt.Errorf("workflow job order mismatch: got %v, want %v", order, wantOrder)
	}
	for name, wantMinutes := range wantTimeouts {
		job, ok := wf.Jobs[name]
		if !ok || job.TimeoutMinutes != wantMinutes {
			return fmt.Errorf("job %s timeout got %d, want %d", name, job.TimeoutMinutes, wantMinutes)
		}
	}
	binary := wf.Jobs["kind-install-binary"]
	if !slices.Equal(binary.Needs, []string{"installer-diagnostics", "kind-images"}) || binary.If != "" || binary.ContinueOnError != nil {
		return fmt.Errorf("kind-install-binary prerequisites altered: needs=%v if=%q", binary.Needs, binary.If)
	}
	if binary.Strategy.FailFast == nil || *binary.Strategy.FailFast || binary.Strategy.MaxParallel != 0 {
		return fmt.Errorf("kind-install-binary fail-fast or max-parallel altered")
	}
	if !slices.Equal(binary.Strategy.Matrix.Profile, []int{137, 135}) || !slices.Equal(binary.Strategy.Matrix.Mode, []string{"transition", "fresh"}) {
		return fmt.Errorf("kind-install-binary matrix order must launch 137 transition first: profile=%v mode=%v", binary.Strategy.Matrix.Profile, binary.Strategy.Matrix.Mode)
	}
	if len(binary.Strategy.Matrix.Exclude) != 1 || binary.Strategy.Matrix.Exclude[0].Profile != 135 || binary.Strategy.Matrix.Exclude[0].Mode != "transition" {
		return fmt.Errorf("kind-install-binary matrix exclude altered: %+v", binary.Strategy.Matrix.Exclude)
	}
	return nil
}

func TestCISpeedupsJobOrderingAndSignedBinaryTransitionPriority(t *testing.T) {
	wf, order := loadCISpeedupsWorkflow(t)

	// Unhappy paths first: verify job-order, timeout, and transition-first matrix validator rejects perturbations.
	if checkCISpeedupsJobOrderAndBinaryMatrix(wf, order) == nil {
		trueVal := true
		for _, mutate := range []struct {
			name string
			fn   func(*ciSpeedupsWorkflow, *[]string)
		}{
			{"drop-kind-images-from-order", func(w *ciSpeedupsWorkflow, o *[]string) {
				*o = slices.Delete(slices.Clone(*o), 1, 2)
			}},
			{"binary-after-baseline", func(w *ciSpeedupsWorkflow, o *[]string) {
				(*o)[2], (*o)[3] = (*o)[3], (*o)[2]
			}},
			{"loosen-recovery-timeout", func(w *ciSpeedupsWorkflow, o *[]string) {
				j := w.Jobs["kind-recovery"]
				j.TimeoutMinutes = 120
				w.Jobs["kind-recovery"] = j
			}},
			{"loosen-binary-timeout", func(w *ciSpeedupsWorkflow, o *[]string) {
				j := w.Jobs["kind-install-binary"]
				j.TimeoutMinutes = 360
				w.Jobs["kind-install-binary"] = j
			}},
			{"binary-profile-135-first", func(w *ciSpeedupsWorkflow, o *[]string) {
				j := w.Jobs["kind-install-binary"]
				j.Strategy.Matrix.Profile = []int{135, 137}
				w.Jobs["kind-install-binary"] = j
			}},
			{"binary-mode-fresh-first", func(w *ciSpeedupsWorkflow, o *[]string) {
				j := w.Jobs["kind-install-binary"]
				j.Strategy.Matrix.Mode = []string{"fresh", "transition"}
				w.Jobs["kind-install-binary"] = j
			}},
			{"binary-drop-exclude", func(w *ciSpeedupsWorkflow, o *[]string) {
				j := w.Jobs["kind-install-binary"]
				j.Strategy.Matrix.Exclude = nil
				w.Jobs["kind-install-binary"] = j
			}},
			{"binary-fail-fast-true", func(w *ciSpeedupsWorkflow, o *[]string) {
				j := w.Jobs["kind-install-binary"]
				j.Strategy.FailFast = &trueVal
				w.Jobs["kind-install-binary"] = j
			}},
			{"binary-extra-foundation-need", func(w *ciSpeedupsWorkflow, o *[]string) {
				j := w.Jobs["kind-install-binary"]
				j.Needs = []string{"installer-diagnostics", "kind-images", "kind-install-baseline"}
				w.Jobs["kind-install-binary"] = j
			}},
			{"binary-omit-kind-images-need", func(w *ciSpeedupsWorkflow, o *[]string) {
				j := w.Jobs["kind-install-binary"]
				j.Needs = []string{"installer-diagnostics"}
				w.Jobs["kind-install-binary"] = j
			}},
		} {
			badWF := cloneCISpeedupsWorkflow(wf)
			badOrder := slices.Clone(order)
			mutate.fn(&badWF, &badOrder)
			if checkCISpeedupsJobOrderAndBinaryMatrix(badWF, badOrder) == nil {
				t.Fatalf("order/matrix validator accepted mutant %s", mutate.name)
			}
		}
	}

	if err := checkCISpeedupsJobOrderAndBinaryMatrix(wf, order); err != nil {
		t.Fatalf("workflow job order and transition priority check failed: %v", err)
	}
}

func checkCISpeedupsSharedImagesAndGate(wf ciSpeedupsWorkflow) error {
	producer, ok := wf.Jobs["kind-images"]
	if !ok {
		return fmt.Errorf("kind-images producer job missing")
	}
	if producer.Name != "Shared exact-source Kind runtime images" || producer.RunsOn != "ubuntu-24.04" || producer.TimeoutMinutes != 20 || len(producer.Needs) != 0 || producer.If != "" || producer.ContinueOnError != nil {
		return fmt.Errorf("kind-images root job envelope invalid")
	}
	if len(producer.Steps) != 3 {
		return fmt.Errorf("kind-images step count got %d, want 3", len(producer.Steps))
	}
	if producer.Steps[0].Uses != "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1" || producer.Steps[0].With["ref"] != "${{ github.event.pull_request.head.sha || github.sha }}" || producer.Steps[0].If != "" || producer.Steps[0].ContinueOnError != nil {
		return fmt.Errorf("kind-images checkout step invalid")
	}
	if producer.Steps[1].Run != "bash ./hack/kind-runtime-images.sh export \"$GITHUB_WORKSPACE\" \"$RUNNER_TEMP/kind-images\"" || producer.Steps[1].If != "" || producer.Steps[1].ContinueOnError != nil {
		return fmt.Errorf("kind-images export step invalid: %q", producer.Steps[1].Run)
	}
	uploadWith := producer.Steps[2].With
	if producer.Steps[2].Uses != "actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9" || producer.Steps[2].If != "" || producer.Steps[2].ContinueOnError != nil ||
		uploadWith["name"] != "kind-images-${{ github.run_id }}-${{ github.run_attempt }}" ||
		uploadWith["path"] != "${{ runner.temp }}/kind-images/" ||
		uploadWith["compression-level"] != 0 ||
		uploadWith["if-no-files-found"] != "error" ||
		uploadWith["retention-days"] != 1 {
		return fmt.Errorf("kind-images upload-artifact step invalid: %+v", uploadWith)
	}

	consumers := []string{
		"kind-install-binary",
		"kind-install-baseline",
		"kind-install-gc",
		"kind-install-precontroller",
		"kind-install-admission",
		"kind-install-admission-v3",
		"kind-install-auth",
		"kind-api",
		"kind-recovery",
		"kind-lifecycle",
	}
	const wantLoadRun = "bash ./hack/kind-runtime-images.sh load \"$GITHUB_WORKSPACE\" \"$RUNNER_TEMP/kind-images\"\necho \"ARCADECTL_KIND_IMAGE_DIR=$RUNNER_TEMP/kind-images\" >> \"$GITHUB_ENV\"\n"
	for _, name := range consumers {
		job, exists := wf.Jobs[name]
		if !exists {
			return fmt.Errorf("Kind consumer %s missing", name)
		}
		if !slices.Equal(job.Needs, []string{"installer-diagnostics", "kind-images"}) || job.ContinueOnError != nil {
			return fmt.Errorf("Kind consumer %s needs mismatch: %v", name, job.Needs)
		}
		wantIf := "${{ !cancelled() && needs.kind-images.result == 'success' }}"
		if name == "kind-install-binary" {
			wantIf = ""
		}
		if job.If != wantIf {
			return fmt.Errorf("Kind consumer %s condition got %q, want %q", name, job.If, wantIf)
		}
		downloadIdx, loadIdx, setupGoIdx, makeIdx := -1, -1, -1, -1
		for idx, step := range job.Steps {
			if step.Uses == "actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333" {
				if step.If != "" || step.ContinueOnError != nil || step.With["name"] != "kind-images-${{ github.run_id }}-${{ github.run_attempt }}" || step.With["path"] != "${{ runner.temp }}/kind-images/" {
					return fmt.Errorf("Kind consumer %s download-artifact step invalid", name)
				}
				downloadIdx = idx
			}
			if step.Run == wantLoadRun {
				if step.If != "" || step.ContinueOnError != nil {
					return fmt.Errorf("Kind consumer %s load step conditional or tolerates failure", name)
				}
				loadIdx = idx
			}
			if strings.HasPrefix(step.Uses, "actions/setup-go@") {
				setupGoIdx = idx
			}
			if strings.HasPrefix(step.Run, "make test-kind-") {
				makeIdx = idx
			}
		}
		if downloadIdx <= 0 || loadIdx != downloadIdx+1 || setupGoIdx <= loadIdx || makeIdx <= setupGoIdx {
			return fmt.Errorf("Kind consumer %s step ordering invalid: download=%d load=%d setupGo=%d make=%d", name, downloadIdx, loadIdx, setupGoIdx, makeIdx)
		}
	}

	gate, exists := wf.Jobs["go-and-policy"]
	if !exists {
		return fmt.Errorf("go-and-policy gate missing")
	}
	wantGateNeeds := []string{
		"installer-diagnostics", "install-engine-race", "kind-install-admission", "kind-install-admission-v3",
		"kind-install-binary", "kind-install-baseline", "kind-install-gc",
		"kind-install-precontroller", "kind-install-auth", "kind-api", "kind-recovery", "envtest",
		"kind-lifecycle", "go-policy-checks", "kind-images",
	}
	if !slices.Equal(gate.Needs, wantGateNeeds) || gate.If != "${{ always() }}" || gate.ContinueOnError != nil || len(gate.Steps) != 2 {
		return fmt.Errorf("go-and-policy gate needs or condition invalid")
	}
	gateStep := gate.Steps[1]
	if gateStep.If != "" || gateStep.ContinueOnError != nil || gateStep.Env["KIND_IMAGES_RESULT"] != "${{ needs.kind-images.result }}" || !strings.Contains(gateStep.Run, "test \"$KIND_IMAGES_RESULT\" = success") {
		return fmt.Errorf("go-and-policy gate step missing KIND_IMAGES_RESULT binding or assertion")
	}
	return nil
}

func TestCISpeedupsSharedImagesProducerConsumersAndRequiredGate(t *testing.T) {
	wf, _ := loadCISpeedupsWorkflow(t)

	// Unhappy paths first: verify every producer, consumer, and gate invariant can fail.
	if checkCISpeedupsSharedImagesAndGate(wf) == nil {
		for _, mutate := range []struct {
			name string
			fn   func(*ciSpeedupsWorkflow)
		}{
			{"delete-kind-images", func(w *ciSpeedupsWorkflow) { delete(w.Jobs, "kind-images") }},
			{"kind-images-non-root", func(w *ciSpeedupsWorkflow) {
				j := w.Jobs["kind-images"]
				j.Needs = []string{"installer-diagnostics"}
				w.Jobs["kind-images"] = j
			}},
			{"kind-images-wrong-export", func(w *ciSpeedupsWorkflow) {
				j := w.Jobs["kind-images"]
				j.Steps[1].Run = "bash ./hack/kind-runtime-images.sh export ."
				w.Jobs["kind-images"] = j
			}},
			{"kind-images-wrong-upload-name", func(w *ciSpeedupsWorkflow) {
				j := w.Jobs["kind-images"]
				j.Steps[2].With["name"] = "kind-images"
				w.Jobs["kind-images"] = j
			}},
			{"consumer-missing-kind-images-need", func(w *ciSpeedupsWorkflow) {
				j := w.Jobs["kind-api"]
				j.Needs = []string{"installer-diagnostics"}
				w.Jobs["kind-api"] = j
			}},
			{"consumer-missing-kind-images-if-guard", func(w *ciSpeedupsWorkflow) {
				j := w.Jobs["kind-lifecycle"]
				j.If = "${{ !cancelled() }}"
				w.Jobs["kind-lifecycle"] = j
			}},
			{"consumer-missing-load-step", func(w *ciSpeedupsWorkflow) {
				j := w.Jobs["kind-install-auth"]
				j.Steps[2].Run = "true"
				w.Jobs["kind-install-auth"] = j
			}},
			{"gate-missing-kind-images-need", func(w *ciSpeedupsWorkflow) {
				j := w.Jobs["go-and-policy"]
				j.Needs = j.Needs[:len(j.Needs)-1]
				w.Jobs["go-and-policy"] = j
			}},
			{"gate-missing-kind-images-env", func(w *ciSpeedupsWorkflow) {
				j := w.Jobs["go-and-policy"]
				delete(j.Steps[1].Env, "KIND_IMAGES_RESULT")
				w.Jobs["go-and-policy"] = j
			}},
			{"gate-missing-kind-images-test", func(w *ciSpeedupsWorkflow) {
				j := w.Jobs["go-and-policy"]
				j.Steps[1].Run = strings.ReplaceAll(j.Steps[1].Run, "test \"$KIND_IMAGES_RESULT\" = success\n", "")
				w.Jobs["go-and-policy"] = j
			}},
		} {
			bad := cloneCISpeedupsWorkflow(wf)
			mutate.fn(&bad)
			if checkCISpeedupsSharedImagesAndGate(bad) == nil {
				t.Fatalf("shared-images/gate validator accepted mutant %s", mutate.name)
			}
		}
	}

	if err := checkCISpeedupsSharedImagesAndGate(wf); err != nil {
		t.Fatalf("shared images producer/consumer/gate check failed: %v", err)
	}

	// Execute the actual go-and-policy shell script: unhappy paths first for KIND_IMAGES_RESULT, then happy path.
	gateRun := wf.Jobs["go-and-policy"].Steps[1].Run
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
	for _, badResult := range []string{"failure", "cancelled", "skipped", ""} {
		cmd := exec.Command("sh", "-e", "-c", gateRun)
		cmd.Env = append(append(os.Environ(), baseEnv...), "KIND_IMAGES_RESULT="+badResult)
		if cmd.Run() == nil {
			t.Fatalf("go-and-policy gate succeeded when KIND_IMAGES_RESULT=%q", badResult)
		}
	}
	cmd := exec.Command("sh", "-e", "-c", gateRun)
	cmd.Env = append(append(os.Environ(), baseEnv...), "KIND_IMAGES_RESULT=success")
	if err := cmd.Run(); err != nil {
		t.Fatalf("go-and-policy gate failed when all 15 results succeeded: %v", err)
	}
}

func checkCISpeedupsConsumerWiring(lifecycleSh, apiKindGo, targetAuthKindGo string) error {
	const wantSyntheticBranch = `if [[ "$lifecycle_suite" == synthetic ]]; then
  # This controller has lifecycletest code; production artifacts cannot replace it.
  run_bounded 360 docker build "${controller_build_args[@]}" --tag "$controller_tag" "$repository_root"
else
  run_bounded 360 bash "$repository_root/hack/kind-runtime-images.sh" prepare controller \
    "$repository_root" "$candidate_sha" "$source_date_epoch" "$source_dirty" "$controller_tag"
fi`
	if !strings.Contains(lifecycleSh, wantSyntheticBranch) {
		return fmt.Errorf("hack/test-kind-lifecycle.sh does not preserve synthetic docker build while preparing shared production controller")
	}
	const wantAPIPrepare = `public("", "bash", "./hack/kind-runtime-images.sh", "prepare", "api", root, sha, epoch, boolText(dirty), imageTag)`
	if !strings.Contains(apiKindGo, wantAPIPrepare) || strings.Contains(apiKindGo, `"Dockerfile.api"`) {
		return fmt.Errorf("internal/install/api_kind_test.go does not prepare API image via hack/kind-runtime-images.sh")
	}
	const wantTargetPrepare = `public("", "bash", "./hack/kind-runtime-images.sh", "prepare", role, sourceRoot, sourceSHA, sourceEpoch, sourceDirty, tag)`
	if !strings.Contains(targetAuthKindGo, wantTargetPrepare) || !strings.Contains(targetAuthKindGo, `if sourceRoot == root {`) || !strings.Contains(targetAuthKindGo, `previous.API = build("arcadectl-api-predecessor", "Dockerfile.api", sourceRoot, installrender.LegacySourceSHA, oldEpoch, "false")`) {
		return fmt.Errorf("internal/installengine/target_auth_kind_test.go does not wire current images through hack/kind-runtime-images.sh while retaining predecessor docker build")
	}
	return nil
}

func TestCISpeedupsKindConsumerWiringInLifecycleAndGoFixtures(t *testing.T) {
	lifecycleBytes, err := os.ReadFile("../../hack/test-kind-lifecycle.sh")
	if err != nil {
		t.Fatalf("read hack/test-kind-lifecycle.sh: %v", err)
	}
	apiKindBytes, err := os.ReadFile("../install/api_kind_test.go")
	if err != nil {
		t.Fatalf("read internal/install/api_kind_test.go: %v", err)
	}
	targetAuthBytes, err := os.ReadFile("target_auth_kind_test.go")
	if err != nil {
		t.Fatalf("read internal/installengine/target_auth_kind_test.go: %v", err)
	}
	lifecycleSh := string(lifecycleBytes)
	apiKindGo := string(apiKindBytes)
	targetAuthGo := string(targetAuthBytes)

	// Unhappy paths first: verify wiring checker rejects regressions in any of the three files.
	if checkCISpeedupsConsumerWiring(lifecycleSh, apiKindGo, targetAuthGo) == nil {
		if checkCISpeedupsConsumerWiring(strings.ReplaceAll(lifecycleSh, "prepare controller", "build controller"), apiKindGo, targetAuthGo) == nil {
			t.Fatal("wiring checker accepted missing prepare controller in hack/test-kind-lifecycle.sh")
		}
		if checkCISpeedupsConsumerWiring(strings.ReplaceAll(lifecycleSh, `if [[ "$lifecycle_suite" == synthetic ]]; then`, `if false; then`), apiKindGo, targetAuthGo) == nil {
			t.Fatal("wiring checker accepted removal of synthetic controller build path")
		}
		if checkCISpeedupsConsumerWiring(lifecycleSh, strings.ReplaceAll(apiKindGo, `"prepare", "api"`, `"build", "api"`), targetAuthGo) == nil {
			t.Fatal("wiring checker accepted missing prepare api in api_kind_test.go")
		}
		if checkCISpeedupsConsumerWiring(lifecycleSh, apiKindGo, strings.ReplaceAll(targetAuthGo, `if sourceRoot == root {`, `if false {`)) == nil {
			t.Fatal("wiring checker accepted removal of sourceRoot == root branch in target_auth_kind_test.go")
		}
	}

	if err := checkCISpeedupsConsumerWiring(lifecycleSh, apiKindGo, targetAuthGo); err != nil {
		t.Fatalf("Kind consumer wiring check failed: %v", err)
	}
}

func initTempRuntimeImagesRepo(t *testing.T, marker string) (string, string, string) {
	t.Helper()
	repo := filepath.Join(t.TempDir(), "repo")
	if err := os.MkdirAll(repo, 0700); err != nil {
		t.Fatal(err)
	}
	controllerDockerfile := fmt.Sprintf(`FROM scratch
ARG VCS_REF
ARG SOURCE_DATE_EPOCH
ARG SOURCE_DIRTY
ARG LIFECYCLE_TEST=false
COPY Dockerfile /arcadectl-controller
LABEL org.opencontainers.image.revision=$VCS_REF arcade.gobha.me/source-dirty=$SOURCE_DIRTY arcade.gobha.me/test-marker=%s arcade.gobha.me/lifecycle-test=$LIFECYCLE_TEST
USER 65532:65532
ENTRYPOINT ["/arcadectl-controller"]
`, marker)
	apiDockerfile := fmt.Sprintf(`FROM scratch
ARG VCS_REF
ARG SOURCE_DATE_EPOCH
ARG SOURCE_DIRTY
COPY Dockerfile.api /arcadectl-api
LABEL org.opencontainers.image.revision=$VCS_REF arcade.gobha.me/source-dirty=$SOURCE_DIRTY arcade.gobha.me/test-marker=%s
USER 65532:65532
ENTRYPOINT ["/arcadectl-api"]
`, marker)
	if err := os.WriteFile(filepath.Join(repo, "Dockerfile"), []byte(controllerDockerfile), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "Dockerfile.api"), []byte(apiDockerfile), 0600); err != nil {
		t.Fatal(err)
	}
	runGit := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = repo
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=Test",
			"GIT_AUTHOR_EMAIL=test@example.invalid",
			"GIT_COMMITTER_NAME=Test",
			"GIT_COMMITTER_EMAIL=test@example.invalid",
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v (%s)", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	runGit("init", "-q")
	runGit("add", "Dockerfile", "Dockerfile.api")
	runGit("commit", "-q", "-m", "initial")
	sha := runGit("rev-parse", "HEAD")
	epoch := runGit("show", "-s", "--format=%ct", "HEAD")
	return repo, sha, epoch
}

func writeBundleChecksums(t *testing.T, bundle string) {
	t.Helper()
	var lines []string
	for _, name := range []string{"images.tar", "source-sha", "source-epoch", "api.id", "controller.id"} {
		data, err := os.ReadFile(filepath.Join(bundle, name))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		lines = append(lines, fmt.Sprintf("%x  %s\n", sum, name))
	}
	if err := os.WriteFile(filepath.Join(bundle, "SHA256SUMS"), []byte(strings.Join(lines, "")), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestCISpeedupsRuntimeImagesScriptCliAndDirtyRefusals(t *testing.T) {
	scriptPath, err := filepath.Abs("../../hack/kind-runtime-images.sh")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(scriptPath); err != nil {
		t.Fatalf("hack/kind-runtime-images.sh unavailable: %v", err)
	}
	repo, sha, epoch := initTempRuntimeImagesRepo(t, "cli-refusals")
	bundle := filepath.Join(t.TempDir(), "bundle")
	if err := os.MkdirAll(bundle, 0700); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"images.tar":    "placeholder",
		"source-sha":    sha + "\n",
		"source-epoch":  epoch + "\n",
		"api.id":        "sha256:" + strings.Repeat("a", 64) + "\n",
		"controller.id": "sha256:" + strings.Repeat("b", 64) + "\n",
	} {
		if err := os.WriteFile(filepath.Join(bundle, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeBundleChecksums(t, bundle)

	runScript := func(extraEnv []string, args ...string) (string, error) {
		cmd := exec.Command("bash", append([]string{scriptPath}, args...)...)
		cmd.Env = append(os.Environ(), extraEnv...)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	// Unhappy paths for CLI argument parsing and subcommand dispatch.
	for _, tc := range []struct {
		name string
		env  []string
		args []string
		want string
	}{
		{"no-args", nil, nil, "expected export, load or prepare"},
		{"unknown-subcommand", nil, []string{"bogus"}, "expected export, load or prepare"},
		{"export-too-few-args", nil, []string{"export", repo}, "export requires source root and output directory"},
		{"export-too-many-args", nil, []string{"export", repo, bundle, "extra"}, "export requires source root and output directory"},
		{"load-too-few-args", nil, []string{"load", repo}, "load requires source root and bundle directory"},
		{"load-too-many-args", nil, []string{"load", repo, bundle, "extra"}, "load requires source root and bundle directory"},
		{"prepare-too-few-args", nil, []string{"prepare", "api", repo, sha, epoch, "false"}, "prepare requires role, source root, SHA, epoch, dirty state and owned tag"},
		{"prepare-invalid-role", nil, []string{"prepare", "worker", repo, sha, epoch, "false", "tag:latest"}, "unsupported runtime image role"},
		{"prepare-shared-dirty-consumer", []string{"ARCADECTL_KIND_IMAGE_DIR=" + bundle}, []string{"prepare", "api", repo, sha, epoch, "true", "tag:latest"}, "shared images require a clean consumer checkout"},
		{"prepare-shared-sha-mismatch", []string{"ARCADECTL_KIND_IMAGE_DIR=" + bundle}, []string{"prepare", "api", repo, strings.Repeat("0", 40), epoch, "false", "tag:latest"}, "shared source mismatch"},
		{"prepare-shared-epoch-mismatch", []string{"ARCADECTL_KIND_IMAGE_DIR=" + bundle}, []string{"prepare", "api", repo, sha, "12345", "false", "tag:latest"}, "shared timestamp mismatch"},
	} {
		out, err := runScript(tc.env, tc.args...)
		if err == nil || !strings.Contains(out, tc.want) {
			t.Fatalf("case %s: expected failure containing %q, got err=%v out=%q", tc.name, tc.want, err, out)
		}
	}

	// Malformed image ID in bundle must be rejected before docker image tag.
	if err := os.WriteFile(filepath.Join(bundle, "api.id"), []byte("not-a-sha256-digest\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := runScript([]string{"ARCADECTL_KIND_IMAGE_DIR=" + bundle}, "prepare", "api", repo, sha, epoch, "false", "tag:latest"); err == nil || !strings.Contains(out, "invalid shared image identity") {
		t.Fatalf("expected invalid shared image identity failure, got err=%v out=%q", err, out)
	}
	if err := os.WriteFile(filepath.Join(bundle, "api.id"), []byte("sha256:"+strings.Repeat("a", 64)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	// Corrupt checksum in bundle must fail load.
	if err := os.WriteFile(filepath.Join(bundle, "source-epoch"), []byte("999999\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := runScript(nil, "load", repo, bundle); err == nil {
		t.Fatalf("load accepted corrupt SHA256SUMS: %s", out)
	}

	// Valid checksums but wrong epoch must fail load with timestamp mismatch.
	writeBundleChecksums(t, bundle)
	if out, err := runScript(nil, "load", repo, bundle); err == nil || !strings.Contains(out, "bundle timestamp mismatch") {
		t.Fatalf("expected bundle timestamp mismatch, got err=%v out=%q", err, out)
	}

	// Valid checksums but wrong commit SHA must fail load with foreign commit error.
	if err := os.WriteFile(filepath.Join(bundle, "source-sha"), []byte(strings.Repeat("f", 40)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundle, "source-epoch"), []byte(epoch+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	writeBundleChecksums(t, bundle)
	if out, err := runScript(nil, "load", repo, bundle); err == nil || !strings.Contains(out, "bundle belongs to another commit") {
		t.Fatalf("expected foreign commit rejection, got err=%v out=%q", err, out)
	}

	// Dirty source tree must fail export immediately.
	if err := os.WriteFile(filepath.Join(repo, "untracked.txt"), []byte("dirty"), 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := runScript(nil, "export", repo, filepath.Join(t.TempDir(), "out")); err == nil || !strings.Contains(out, "export requires a clean exact-source checkout") {
		t.Fatalf("expected dirty checkout rejection on export, got err=%v out=%q", err, out)
	}
}

func requireScratchDocker(t *testing.T) {
	t.Helper()
	// Every CI job in .github/workflows/ci.yml that executes internal/installengine
	// tests (install-engine-race, envtest, installer-diagnostics, and kind-install-*)
	// runs on ubuntu-24.04 GitHub-hosted VM runners without a container: job wrapper,
	// where the Docker CLI and daemon are always provisioned. Fail closed when CI=true.
	ci := strings.EqualFold(strings.TrimSpace(os.Getenv("CI")), "true")
	if _, err := exec.LookPath("docker"); err != nil {
		if ci {
			t.Fatalf("requireScratchDocker: docker CLI missing from PATH (%q) while CI=true: %v", os.Getenv("PATH"), err)
		}
		t.Skipf("requireScratchDocker: skipping local scratch-image test because docker CLI was not found in PATH (%q): %v", os.Getenv("PATH"), err)
	}
	if out, err := exec.Command("docker", "info").CombinedOutput(); err != nil {
		detail := strings.TrimSpace(string(out))
		if ci {
			t.Fatalf("requireScratchDocker: docker daemon unreachable (`docker info` failed) while CI=true: %v (%s)", err, detail)
		}
		t.Skipf("requireScratchDocker: skipping local scratch-image test because docker daemon is unreachable (`docker info` failed): %v (%s)", err, detail)
	}
}

func setupFakeDockerShim(t *testing.T, sha string) (string, string, string, string, string) {
	t.Helper()
	shimDir := filepath.Join(t.TempDir(), "bin")
	stateDir := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(shimDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(t.TempDir(), "docker.log")
	if err := os.WriteFile(logPath, nil, 0600); err != nil {
		t.Fatal(err)
	}
	freshAPIID := "sha256:" + strings.Repeat("a", 64)
	freshControllerID := "sha256:" + strings.Repeat("b", 64)
	shimScript := `#!/usr/bin/env bash
set -euo pipefail
key_of() { printf '%s' "$1" | tr ':/' '__'; }
printf 'cmd=%s env_kind_image_dir=%s\n' "$*" "${ARCADECTL_KIND_IMAGE_DIR-}" >> "$FAKE_DOCKER_LOG"

case "${1:-}" in
  info)
    if [[ "${FAKE_DOCKER_INFO_FAIL:-0}" == "1" ]]; then
      echo "Cannot connect to the Docker daemon at unix:///nonexistent/docker.sock. Is the docker daemon running?" >&2
      exit 1
    fi
    exit 0
    ;;
  build)
    tag=""
    dockerfile=""
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --tag) tag="$2"; shift 2 ;;
        --file) dockerfile="$2"; shift 2 ;;
        *) shift ;;
      esac
    done
    tkey=$(key_of "$tag")
    if [[ "$dockerfile" == *Dockerfile.api ]]; then
      printf '%s\n' "$FAKE_DOCKER_FRESH_API_ID" > "$FAKE_DOCKER_STATE_DIR/id_$tkey"
      printf 'api\n' > "$FAKE_DOCKER_STATE_DIR/role_$tkey"
    else
      printf '%s\n' "$FAKE_DOCKER_FRESH_CONTROLLER_ID" > "$FAKE_DOCKER_STATE_DIR/id_$tkey"
      printf 'controller\n' > "$FAKE_DOCKER_STATE_DIR/role_$tkey"
    fi
    exit 0
    ;;
  image)
    shift
    case "${1:-}" in
      save)
        shift
        out=""
        while [[ $# -gt 0 ]]; do
          case "$1" in
            --output) out="$2"; shift 2 ;;
            *) shift ;;
          esac
        done
        printf 'fake-docker-archive-v1\n' > "$out"
        exit 0
        ;;
      load)
        shift
        in_file=""
        while [[ $# -gt 0 ]]; do
          case "$1" in
            --input) in_file="$2"; shift 2 ;;
            *) shift ;;
          esac
        done
        [[ -f "$in_file" ]]
        exit 0
        ;;
      tag)
        src="$2"
        dst="$3"
        skey=$(key_of "$src")
        dkey=$(key_of "$dst")
        if [[ -f "$FAKE_DOCKER_STATE_DIR/id_$skey" ]]; then
          cp "$FAKE_DOCKER_STATE_DIR/id_$skey" "$FAKE_DOCKER_STATE_DIR/id_$dkey"
        else
          printf '%s\n' "$src" > "$FAKE_DOCKER_STATE_DIR/id_$dkey"
        fi
        if [[ -f "$FAKE_DOCKER_STATE_DIR/role_$skey" ]]; then
          cp "$FAKE_DOCKER_STATE_DIR/role_$skey" "$FAKE_DOCKER_STATE_DIR/role_$dkey"
        fi
        exit 0
        ;;
      inspect)
        fmt="$3"
        target="$4"
        tkey=$(key_of "$target")
        resolved="$target"
        if [[ -f "$FAKE_DOCKER_STATE_DIR/id_$tkey" ]]; then
          resolved=$(cat "$FAKE_DOCKER_STATE_DIR/id_$tkey")
        fi
        role=""
        if [[ -f "$FAKE_DOCKER_STATE_DIR/role_$tkey" ]]; then
          role=$(cat "$FAKE_DOCKER_STATE_DIR/role_$tkey")
        elif [[ "$target" == *api* || "$resolved" == "$FAKE_DOCKER_FRESH_API_ID" || "$resolved" == "${FAKE_DOCKER_ALT_API_ID:-}" ]]; then
          role="api"
        elif [[ "$target" == *controller* || "$resolved" == "$FAKE_DOCKER_FRESH_CONTROLLER_ID" || "$resolved" == "${FAKE_DOCKER_ALT_CONTROLLER_ID:-}" ]]; then
          role="controller"
        fi
        case "$fmt" in
          '{{.Id}}') printf '%s\n' "$resolved" ;;
          '{{.Os}}/{{.Architecture}}') printf '%s\n' "${FAKE_DOCKER_PLATFORM:-linux/amd64}" ;;
          '{{index .Config.Labels "org.opencontainers.image.revision"}}') printf '%s\n' "${FAKE_DOCKER_SHA}" ;;
          '{{index .Config.Labels "arcade.gobha.me/source-dirty"}}') printf '%s\n' "${FAKE_DOCKER_DIRTY:-false}" ;;
          '{{.Config.User}}') printf '%s\n' "${FAKE_DOCKER_USER:-65532:65532}" ;;
          '{{json .Config.Entrypoint}}') printf '["/arcadectl-%s"]\n' "$role" ;;
          *) echo "unexpected inspect format: $fmt" >&2; exit 2 ;;
        esac
        exit 0
        ;;
    esac
    ;;
esac
echo "unexpected fake docker invocation: $*" >&2
exit 2
`
	shimFile := filepath.Join(shimDir, "docker")
	if err := os.WriteFile(shimFile, []byte(shimScript), 0700); err != nil {
		t.Fatal(err)
	}
	_ = sha
	return shimDir, stateDir, logPath, freshAPIID, freshControllerID
}

func TestCISpeedupsRuntimeImagesBundleIntegrityAndTamperRefusal(t *testing.T) {
	scriptPath, err := filepath.Abs("../../hack/kind-runtime-images.sh")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(scriptPath); err != nil {
		t.Fatalf("hack/kind-runtime-images.sh unavailable: %v", err)
	}
	repo, sha, epoch := initTempRuntimeImagesRepo(t, "bundle-integrity")
	shimDir, stateDir, logPath, freshAPIID, freshControllerID := setupFakeDockerShim(t, sha)
	altAPIID := "sha256:" + strings.Repeat("c", 64)
	altControllerID := "sha256:" + strings.Repeat("d", 64)

	runWithShim := func(extraEnv []string, args ...string) (string, string, error) {
		if err := os.WriteFile(logPath, nil, 0600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("bash", append([]string{scriptPath}, args...)...)
		baseEnv := []string{
			"PATH=" + shimDir + string(os.PathListSeparator) + os.Getenv("PATH"),
			"FAKE_DOCKER_LOG=" + logPath,
			"FAKE_DOCKER_STATE_DIR=" + stateDir,
			"FAKE_DOCKER_SHA=" + sha,
			"FAKE_DOCKER_FRESH_API_ID=" + freshAPIID,
			"FAKE_DOCKER_FRESH_CONTROLLER_ID=" + freshControllerID,
			"FAKE_DOCKER_ALT_API_ID=" + altAPIID,
			"FAKE_DOCKER_ALT_CONTROLLER_ID=" + altControllerID,
		}
		cmd.Env = append(append(os.Environ(), baseEnv...), extraEnv...)
		out, runErr := cmd.CombinedOutput()
		logBytes, logErr := os.ReadFile(logPath)
		if logErr != nil {
			t.Fatal(logErr)
		}
		return string(out), string(logBytes), runErr
	}

	bundle := filepath.Join(t.TempDir(), "bundle")
	if out, _, err := runWithShim(nil, "export", repo, bundle); err != nil {
		t.Fatalf("export with docker shim failed: %v (%s)", err, out)
	}
	origTar, err := os.ReadFile(filepath.Join(bundle, "images.tar"))
	if err != nil {
		t.Fatal(err)
	}
	origAPIID, err := os.ReadFile(filepath.Join(bundle, "api.id"))
	if err != nil {
		t.Fatal(err)
	}
	origControllerID, err := os.ReadFile(filepath.Join(bundle, "controller.id"))
	if err != nil {
		t.Fatal(err)
	}
	origSums, err := os.ReadFile(filepath.Join(bundle, "SHA256SUMS"))
	if err != nil {
		t.Fatal(err)
	}
	restoreBundle := func() {
		t.Helper()
		for name, content := range map[string][]byte{
			"images.tar":    origTar,
			"api.id":        origAPIID,
			"controller.id": origControllerID,
			"SHA256SUMS":    origSums,
		} {
			if err := os.WriteFile(filepath.Join(bundle, name), content, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}

	// Unhappy paths first: tamper with artifacts or SHA256SUMS while keeping source-sha,
	// source-epoch, and image ID formats valid so only sha256sum --check --strict can catch it.
	for _, tc := range []struct {
		name   string
		tamper func()
	}{
		{
			name: "tampered-images-tar",
			tamper: func() {
				if err := os.WriteFile(filepath.Join(bundle, "images.tar"), []byte("tampered-archive-payload\n"), 0600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "tampered-api-id-artifact",
			tamper: func() {
				if err := os.WriteFile(filepath.Join(bundle, "api.id"), []byte(altAPIID+"\n"), 0600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "tampered-controller-id-artifact",
			tamper: func() {
				if err := os.WriteFile(filepath.Join(bundle, "controller.id"), []byte(altControllerID+"\n"), 0600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "tampered-sha256sums-digest",
			tamper: func() {
				corrupted := make([]byte, len(origSums))
				copy(corrupted, origSums)
				if corrupted[0] == '0' {
					corrupted[0] = '1'
				} else {
					corrupted[0] = '0'
				}
				if err := os.WriteFile(filepath.Join(bundle, "SHA256SUMS"), corrupted, 0600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "strict-malformed-sha256sums-line",
			tamper: func() {
				withJunk := append(slices.Clone(origSums), []byte("malformed-checksum-line\n")...)
				if err := os.WriteFile(filepath.Join(bundle, "SHA256SUMS"), withJunk, 0600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "missing-sha256sums",
			tamper: func() {
				if err := os.Remove(filepath.Join(bundle, "SHA256SUMS")); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		restoreBundle()
		tc.tamper()
		out, dockerLog, err := runWithShim(nil, "load", repo, bundle)
		if err == nil {
			t.Fatalf("case %s: load succeeded on tampered bundle (out=%q, dockerLog=%q)", tc.name, out, dockerLog)
		}
		if strings.Contains(dockerLog, "image load") {
			t.Fatalf("case %s: load invoked `docker image load` despite tampered checksums (dockerLog=%q)", tc.name, dockerLog)
		}
	}

	// Also verify prepare refuses tampered image identity or image metadata before `docker image tag`.
	restoreBundle()
	if err := os.WriteFile(filepath.Join(bundle, "api.id"), []byte("tampered-non-digest\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if out, dockerLog, err := runWithShim([]string{"ARCADECTL_KIND_IMAGE_DIR=" + bundle}, "prepare", "api", repo, sha, epoch, "false", "arcadectl-api:test"); err == nil || !strings.Contains(out, "invalid shared image identity") || strings.Contains(dockerLog, "image tag") {
		t.Fatalf("prepare accepted tampered api.id: err=%v out=%q dockerLog=%q", err, out, dockerLog)
	}
	restoreBundle()
	if out, dockerLog, err := runWithShim([]string{"ARCADECTL_KIND_IMAGE_DIR=" + bundle, "FAKE_DOCKER_SHA=deadbeef"}, "prepare", "api", repo, sha, epoch, "false", "arcadectl-api:test"); err == nil || !strings.Contains(out, "source mismatch") || strings.Contains(dockerLog, "image tag") {
		t.Fatalf("prepare accepted tampered image revision label: err=%v out=%q dockerLog=%q", err, out, dockerLog)
	}

	// Happy path: untampered bundle passes checksum verification, loads archive, and prepares both roles.
	restoreBundle()
	out, dockerLog, err := runWithShim(nil, "load", repo, bundle)
	if err != nil {
		t.Fatalf("load failed on untampered bundle: %v (%s)", err, out)
	}
	if !strings.Contains(dockerLog, "cmd=image load --input "+filepath.Join(bundle, "images.tar")) {
		t.Fatalf("load did not invoke expected `docker image load`: %q", dockerLog)
	}
	for _, role := range []string{"api", "controller"} {
		out, dockerLog, err = runWithShim([]string{"ARCADECTL_KIND_IMAGE_DIR=" + bundle}, "prepare", role, repo, sha, epoch, "false", "arcadectl-"+role+":consumer")
		if err != nil {
			t.Fatalf("prepare %s failed on untampered bundle: %v (%s)", role, err, out)
		}
		if !strings.Contains(dockerLog, "cmd=image tag ") {
			t.Fatalf("prepare %s did not tag shared image: %q", role, dockerLog)
		}
	}
}

func TestCISpeedupsRuntimeImagesProducerIgnoresInheritedBundleEnv(t *testing.T) {
	scriptPath, err := filepath.Abs("../../hack/kind-runtime-images.sh")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(scriptPath); err != nil {
		t.Fatalf("hack/kind-runtime-images.sh unavailable: %v", err)
	}
	repo, sha, epoch := initTempRuntimeImagesRepo(t, "producer-env")
	shimDir, stateDir, logPath, freshAPIID, freshControllerID := setupFakeDockerShim(t, sha)
	poisonAPIID := "sha256:" + strings.Repeat("1", 64)
	poisonControllerID := "sha256:" + strings.Repeat("2", 64)

	// Construct a valid-looking pre-existing bundle matching repo's exact SHA and epoch,
	// but containing poisoned image IDs so we can detect if export inherits ARCADECTL_KIND_IMAGE_DIR.
	poisonBundle := filepath.Join(t.TempDir(), "poison-inherited-bundle")
	if err := os.MkdirAll(poisonBundle, 0700); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"images.tar":    "poison-archive\n",
		"source-sha":    sha + "\n",
		"source-epoch":  epoch + "\n",
		"api.id":        poisonAPIID + "\n",
		"controller.id": poisonControllerID + "\n",
	} {
		if err := os.WriteFile(filepath.Join(poisonBundle, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeBundleChecksums(t, poisonBundle)

	runWithShim := func(extraEnv []string, args ...string) (string, string, error) {
		if err := os.WriteFile(logPath, nil, 0600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("bash", append([]string{scriptPath}, args...)...)
		baseEnv := []string{
			"PATH=" + shimDir + string(os.PathListSeparator) + os.Getenv("PATH"),
			"FAKE_DOCKER_LOG=" + logPath,
			"FAKE_DOCKER_STATE_DIR=" + stateDir,
			"FAKE_DOCKER_SHA=" + sha,
			"FAKE_DOCKER_FRESH_API_ID=" + freshAPIID,
			"FAKE_DOCKER_FRESH_CONTROLLER_ID=" + freshControllerID,
			"FAKE_DOCKER_ALT_API_ID=" + poisonAPIID,
			"FAKE_DOCKER_ALT_CONTROLLER_ID=" + poisonControllerID,
		}
		cmd.Env = append(append(os.Environ(), baseEnv...), extraEnv...)
		out, runErr := cmd.CombinedOutput()
		logBytes, logErr := os.ReadFile(logPath)
		if logErr != nil {
			t.Fatal(logErr)
		}
		return string(out), string(logBytes), runErr
	}

	// Control check first: consumer `prepare` WITH ARCADECTL_KIND_IMAGE_DIR=poisonBundle
	// consumes the bundle via `docker image tag` and fails when pointed at a missing dir.
	if out, _, err := runWithShim([]string{"ARCADECTL_KIND_IMAGE_DIR=/nonexistent-bundle-dir"}, "prepare", "api", repo, sha, epoch, "false", "arcadectl-api:control"); err == nil {
		t.Fatalf("consumer prepare unexpectedly succeeded with nonexistent ARCADECTL_KIND_IMAGE_DIR: %s", out)
	}
	if out, dockerLog, err := runWithShim([]string{"ARCADECTL_KIND_IMAGE_DIR=" + poisonBundle}, "prepare", "api", repo, sha, epoch, "false", "arcadectl-api:control"); err != nil || !strings.Contains(dockerLog, "cmd=image tag "+poisonAPIID) {
		t.Fatalf("consumer prepare did not consume ARCADECTL_KIND_IMAGE_DIR as expected: err=%v out=%q log=%q", err, out, dockerLog)
	}

	// Producer check 1: export with ARCADECTL_KIND_IMAGE_DIR=poisonBundle MUST unset
	// ARCADECTL_KIND_IMAGE_DIR, invoke `docker build` (never `docker image tag`), and
	// export the freshly built image IDs rather than inheriting poisonAPIID/poisonControllerID.
	outBundle1 := filepath.Join(t.TempDir(), "exported-1")
	out, dockerLog, err := runWithShim([]string{"ARCADECTL_KIND_IMAGE_DIR=" + poisonBundle}, "export", repo, outBundle1)
	if err != nil {
		t.Fatalf("export with inherited poison bundle failed: %v (%s)", err, out)
	}
	if strings.Contains(dockerLog, "cmd=image tag") {
		t.Fatalf("producer export inherited ARCADECTL_KIND_IMAGE_DIR and called `docker image tag`: %q", dockerLog)
	}
	for _, line := range strings.Split(strings.TrimSpace(dockerLog), "\n") {
		if strings.HasPrefix(line, "cmd=build ") && !strings.HasSuffix(line, "env_kind_image_dir=") {
			t.Fatalf("producer export leaked non-empty ARCADECTL_KIND_IMAGE_DIR into prepare/docker build: %q", line)
		}
	}
	if !strings.Contains(dockerLog, "--tag arcadectl-api:kind-shared") || !strings.Contains(dockerLog, "--tag arcadectl-controller:kind-shared") {
		t.Fatalf("producer export did not run fresh `docker build` for both roles: %q", dockerLog)
	}
	gotAPIBytes, err := os.ReadFile(filepath.Join(outBundle1, "api.id"))
	if err != nil {
		t.Fatal(err)
	}
	gotControllerBytes, err := os.ReadFile(filepath.Join(outBundle1, "controller.id"))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(gotAPIBytes)); got != freshAPIID {
		t.Fatalf("exported api.id got %q (poison=%q), want fresh %q", got, poisonAPIID, freshAPIID)
	}
	if got := strings.TrimSpace(string(gotControllerBytes)); got != freshControllerID {
		t.Fatalf("exported controller.id got %q (poison=%q), want fresh %q", got, poisonControllerID, freshControllerID)
	}

	// Producer check 2: export with ARCADECTL_KIND_IMAGE_DIR pointing to a nonexistent directory
	// MUST also succeed because the producer clears ARCADECTL_KIND_IMAGE_DIR.
	outBundle2 := filepath.Join(t.TempDir(), "exported-2")
	if out, dockerLog, err := runWithShim([]string{"ARCADECTL_KIND_IMAGE_DIR=/nonexistent-bundle-dir"}, "export", repo, outBundle2); err != nil || strings.Contains(dockerLog, "cmd=image tag") {
		t.Fatalf("export with nonexistent ARCADECTL_KIND_IMAGE_DIR failed: err=%v out=%q log=%q", err, out, dockerLog)
	}
}

func TestCISpeedupsRequireScratchDockerLoudSkipAndCIFatal(t *testing.T) {
	if os.Getenv("ARCADECTL_TEST_SCRATCH_DOCKER_SUBPROC") == "1" {
		requireScratchDocker(t)
		return
	}

	// Verify in .github/workflows/ci.yml that kind-images is present and every job
	// (including install-engine-race and envtest, which run this package's tests)
	// runs directly on ubuntu-24.04 without a container: job wrapper.
	wf, _ := loadCISpeedupsWorkflow(t)
	if _, ok := wf.Jobs["kind-images"]; !ok {
		t.Fatal("kind-images job missing from workflow")
	}
	for name, job := range wf.Jobs {
		if job.RunsOn != "ubuntu-24.04" || job.Container != nil {
			t.Fatalf("job %s runs-on=%q container=%v, want ubuntu-24.04 host runner with Docker available", name, job.RunsOn, job.Container)
		}
	}

	emptyBin := filepath.Join(t.TempDir(), "empty-bin")
	if err := os.MkdirAll(emptyBin, 0700); err != nil {
		t.Fatal(err)
	}
	brokenDockerBin, stateDir, logPath, _, _ := setupFakeDockerShim(t, "deadbeef")

	runSubproc := func(pathEnv, ciEnv, infoFail string) (string, error) {
		cmd := exec.Command(os.Args[0], "-test.v", "-test.run=^TestCISpeedupsRequireScratchDockerLoudSkipAndCIFatal$")
		var cleanEnv []string
		for _, kv := range os.Environ() {
			if strings.HasPrefix(kv, "PATH=") || strings.HasPrefix(kv, "CI=") || strings.HasPrefix(kv, "FAKE_DOCKER_") {
				continue
			}
			cleanEnv = append(cleanEnv, kv)
		}
		cleanEnv = append(cleanEnv,
			"ARCADECTL_TEST_SCRATCH_DOCKER_SUBPROC=1",
			"PATH="+pathEnv,
			"CI="+ciEnv,
			"FAKE_DOCKER_LOG="+logPath,
			"FAKE_DOCKER_STATE_DIR="+stateDir,
			"FAKE_DOCKER_INFO_FAIL="+infoFail,
		)
		cmd.Env = cleanEnv
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	// 1. Missing docker CLI + CI=true -> must FAIL (t.Fatalf).
	if out, err := runSubproc(emptyBin, "true", "0"); err == nil || !strings.Contains(out, "requireScratchDocker: docker CLI missing from PATH") {
		t.Fatalf("expected t.Fatalf when docker is missing from PATH and CI=true, got err=%v out=%q", err, out)
	}

	// 2. Unreachable docker daemon (`docker info` fails) + CI=true -> must FAIL (t.Fatalf).
	if out, err := runSubproc(brokenDockerBin+string(os.PathListSeparator)+os.Getenv("PATH"), "true", "1"); err == nil || !strings.Contains(out, "requireScratchDocker: docker daemon unreachable (`docker info` failed) while CI=true") {
		t.Fatalf("expected t.Fatalf when `docker info` fails and CI=true, got err=%v out=%q", err, out)
	}

	// 3. Missing docker CLI + CI="" -> must SKIP with explicit missing-CLI reason.
	outMissingSkip, err := runSubproc(emptyBin, "", "0")
	if err != nil || !strings.Contains(outMissingSkip, "--- SKIP:") || !strings.Contains(outMissingSkip, "requireScratchDocker: skipping local scratch-image test because docker CLI was not found in PATH") {
		t.Fatalf("expected explicit missing-CLI skip when CI is unset, got err=%v out=%q", err, outMissingSkip)
	}

	// 4. Unreachable docker daemon (`docker info` fails) + CI="" -> must SKIP with distinct explicit daemon-unreachable reason.
	outDaemonSkip, err := runSubproc(brokenDockerBin+string(os.PathListSeparator)+os.Getenv("PATH"), "", "1")
	if err != nil || !strings.Contains(outDaemonSkip, "--- SKIP:") || !strings.Contains(outDaemonSkip, "requireScratchDocker: skipping local scratch-image test because docker daemon is unreachable (`docker info` failed)") {
		t.Fatalf("expected explicit daemon-unreachable skip when CI is unset, got err=%v out=%q", err, outDaemonSkip)
	}

	// 5. Healthy docker CLI and daemon -> must PASS without skipping.
	if out, err := runSubproc(brokenDockerBin+string(os.PathListSeparator)+os.Getenv("PATH"), "true", "0"); err != nil || !strings.Contains(out, "--- PASS:") {
		t.Fatalf("expected pass when docker CLI and daemon succeed, got err=%v out=%q", err, out)
	}
}

func TestCISpeedupsRuntimeImagesScriptWithScratchDocker(t *testing.T) {
	scriptPath, err := filepath.Abs("../../hack/kind-runtime-images.sh")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(scriptPath); err != nil {
		t.Fatalf("hack/kind-runtime-images.sh unavailable: %v", err)
	}
	requireScratchDocker(t)

	randBytes := make([]byte, 6)
	if _, err := rand.Read(randBytes); err != nil {
		t.Fatal(err)
	}
	marker := "agy-127-" + hex.EncodeToString(randBytes)

	// Record any pre-existing arcadectl-{api,controller}:kind-shared image IDs so we restore them on cleanup.
	savedShared := map[string]string{}
	for _, sharedTag := range []string{"arcadectl-api:kind-shared", "arcadectl-controller:kind-shared"} {
		if out, err := exec.Command("docker", "image", "inspect", "--format", "{{.Id}}", sharedTag).Output(); err == nil {
			savedShared[sharedTag] = strings.TrimSpace(string(out))
		}
	}
	var ownedTags []string
	var ownedImageIDs []string
	t.Cleanup(func() {
		for _, tag := range ownedTags {
			_ = exec.Command("docker", "image", "rm", "-f", tag).Run()
		}
		for sharedTag, prevID := range savedShared {
			if prevID != "" {
				_ = exec.Command("docker", "image", "tag", prevID, sharedTag).Run()
			}
		}
		for _, sharedTag := range []string{"arcadectl-api:kind-shared", "arcadectl-controller:kind-shared"} {
			if savedShared[sharedTag] == "" {
				_ = exec.Command("docker", "image", "rm", "-f", sharedTag).Run()
			}
		}
		for _, id := range ownedImageIDs {
			_ = exec.Command("docker", "image", "rm", "-f", id).Run()
		}
	})

	repo, sha, epoch := initTempRuntimeImagesRepo(t, marker)
	commitFiles := func() (string, string) {
		t.Helper()
		for _, args := range [][]string{
			{"add", "Dockerfile", "Dockerfile.api"},
			{"commit", "-q", "-m", "update"},
		} {
			cmd := exec.Command("git", args...)
			cmd.Dir = repo
			cmd.Env = append(os.Environ(),
				"GIT_AUTHOR_NAME=Test",
				"GIT_AUTHOR_EMAIL=test@example.invalid",
				"GIT_COMMITTER_NAME=Test",
				"GIT_COMMITTER_EMAIL=test@example.invalid",
			)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("git %v: %v (%s)", args, err, out)
			}
		}
		shaOut, err := exec.Command("git", "-C", repo, "rev-parse", "HEAD").Output()
		if err != nil {
			t.Fatal(err)
		}
		epochOut, err := exec.Command("git", "-C", repo, "show", "-s", "--format=%ct", "HEAD").Output()
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(shaOut)), strings.TrimSpace(string(epochOut))
	}

	// Unhappy paths first with real docker builds: metadata verification failures and broken export build.
	for _, tc := range []struct {
		name       string
		dockerfile string
		wantErr    string
	}{
		{
			name: "user-mismatch",
			dockerfile: fmt.Sprintf(`FROM scratch
ARG VCS_REF
ARG SOURCE_DIRTY
LABEL org.opencontainers.image.revision=$VCS_REF arcade.gobha.me/source-dirty=$SOURCE_DIRTY arcade.gobha.me/test-marker=%s-user
USER 1000:1000
ENTRYPOINT ["/arcadectl-api"]
`, marker),
			wantErr: "user mismatch",
		},
		{
			name: "entrypoint-mismatch",
			dockerfile: fmt.Sprintf(`FROM scratch
ARG VCS_REF
ARG SOURCE_DIRTY
LABEL org.opencontainers.image.revision=$VCS_REF arcade.gobha.me/source-dirty=$SOURCE_DIRTY arcade.gobha.me/test-marker=%s-ep
USER 65532:65532
ENTRYPOINT ["/wrong-binary"]
`, marker),
			wantErr: "entrypoint mismatch",
		},
		{
			name: "revision-mismatch",
			dockerfile: fmt.Sprintf(`FROM scratch
ARG SOURCE_DIRTY
LABEL org.opencontainers.image.revision=deadbeef arcade.gobha.me/source-dirty=$SOURCE_DIRTY arcade.gobha.me/test-marker=%s-rev
USER 65532:65532
ENTRYPOINT ["/arcadectl-api"]
`, marker),
			wantErr: "source mismatch",
		},
		{
			name: "dirty-label-mismatch",
			dockerfile: fmt.Sprintf(`FROM scratch
ARG VCS_REF
LABEL org.opencontainers.image.revision=$VCS_REF arcade.gobha.me/source-dirty=true arcade.gobha.me/test-marker=%s-dirty
USER 65532:65532
ENTRYPOINT ["/arcadectl-api"]
`, marker),
			wantErr: "source state mismatch",
		},
	} {
		if err := os.WriteFile(filepath.Join(repo, "Dockerfile.api"), []byte(tc.dockerfile), 0600); err != nil {
			t.Fatal(err)
		}
		badTag := "arcadectl-test-" + marker + ":" + tc.name
		ownedTags = append(ownedTags, badTag)
		cmd := exec.Command("bash", scriptPath, "prepare", "api", repo, sha, epoch, "false", badTag)
		cmd.Env = append(os.Environ(), "ARCADECTL_KIND_IMAGE_DIR=")
		out, err := cmd.CombinedOutput()
		if idOut, idErr := exec.Command("docker", "image", "inspect", "--format", "{{.Id}}", badTag).Output(); idErr == nil {
			ownedImageIDs = append(ownedImageIDs, strings.TrimSpace(string(idOut)))
		}
		if err == nil || !strings.Contains(string(out), tc.wantErr) {
			t.Fatalf("metadata case %s: expected error %q, got err=%v out=%q", tc.name, tc.wantErr, err, out)
		}
	}

	// Restore valid Dockerfile.api and commit clean tree for export/load/prepare happy-path and partial-failure proof.
	validAPI := fmt.Sprintf(`FROM scratch
ARG VCS_REF
ARG SOURCE_DATE_EPOCH
ARG SOURCE_DIRTY
COPY Dockerfile.api /arcadectl-api
LABEL org.opencontainers.image.revision=$VCS_REF arcade.gobha.me/source-dirty=$SOURCE_DIRTY arcade.gobha.me/test-marker=%s-valid
USER 65532:65532
ENTRYPOINT ["/arcadectl-api"]
`, marker)
	if err := os.WriteFile(filepath.Join(repo, "Dockerfile.api"), []byte(validAPI), 0600); err != nil {
		t.Fatal(err)
	}
	sha, epoch = commitFiles()

	bundleDir := filepath.Join(t.TempDir(), "kind-images")
	exportCmd := exec.Command("bash", scriptPath, "export", repo, bundleDir)
	// Even if ARCADECTL_KIND_IMAGE_DIR is set in the caller environment, export must ignore it and build fresh.
	exportCmd.Env = append(os.Environ(), "ARCADECTL_KIND_IMAGE_DIR=/nonexistent-bundle-dir")
	if out, err := exportCmd.CombinedOutput(); err != nil {
		t.Fatalf("export failed: %v (%s)", err, out)
	}
	for _, role := range []string{"api", "controller"} {
		idBytes, err := os.ReadFile(filepath.Join(bundleDir, role+".id"))
		if err != nil {
			t.Fatalf("missing %s.id: %v", role, err)
		}
		ownedImageIDs = append(ownedImageIDs, strings.TrimSpace(string(idBytes)))
	}

	// Verify load succeeds on the exported bundle.
	if out, err := exec.Command("bash", scriptPath, "load", repo, bundleDir).CombinedOutput(); err != nil {
		t.Fatalf("load failed: %v (%s)", err, out)
	}

	// Verify consumer prepare retags the exact exported image IDs for both api and controller without rebuilding.
	for _, role := range []string{"api", "controller"} {
		consumerTag := "arcadectl-test-" + marker + ":consumer-" + role
		ownedTags = append(ownedTags, consumerTag)
		prepCmd := exec.Command("bash", scriptPath, "prepare", role, repo, sha, epoch, "false", consumerTag)
		prepCmd.Env = append(os.Environ(), "ARCADECTL_KIND_IMAGE_DIR="+bundleDir)
		if out, err := prepCmd.CombinedOutput(); err != nil {
			t.Fatalf("prepare %s from shared bundle failed: %v (%s)", role, err, out)
		}
		gotID, err := exec.Command("docker", "image", "inspect", "--format", "{{.Id}}", consumerTag).Output()
		if err != nil {
			t.Fatalf("inspect consumer tag %s: %v", consumerTag, err)
		}
		wantID, err := os.ReadFile(filepath.Join(bundleDir, role+".id"))
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(string(gotID)) != strings.TrimSpace(string(wantID)) {
			t.Fatalf("consumer tag %s image ID got %q, want %q", consumerTag, strings.TrimSpace(string(gotID)), strings.TrimSpace(string(wantID)))
		}
	}
}
