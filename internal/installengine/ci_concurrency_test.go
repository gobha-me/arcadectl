// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"os"
	"path/filepath"
	"testing"

	yaml "go.yaml.in/yaml/v3"
)

const (
	wantWorkflowConcurrencyGroup            = "${{ github.workflow }}-${{ github.ref }}"
	wantWorkflowConcurrencyCancelInProgress = "${{ github.event_name == 'pull_request' }}"
)

func validWorkflowConcurrency(group string, cancelInProgress any) bool {
	cancelExpr, ok := cancelInProgress.(string)
	return ok && group == wantWorkflowConcurrencyGroup && cancelExpr == wantWorkflowConcurrencyCancelInProgress
}

func TestWorkflowConcurrencyCancelsPullRequestsOnly(t *testing.T) {
	if !validWorkflowConcurrency(wantWorkflowConcurrencyGroup, wantWorkflowConcurrencyCancelInProgress) {
		t.Fatal("PR-only workflow concurrency positive control refused")
	}
	for _, bad := range []struct {
		group            string
		cancelInProgress any
	}{
		{"", wantWorkflowConcurrencyCancelInProgress},
		{"ci-${{ github.workflow }}-${{ github.ref }}", wantWorkflowConcurrencyCancelInProgress},
		{"installer-performance-${{ github.ref }}", wantWorkflowConcurrencyCancelInProgress},
		{"ci-${{ github.workflow }}-${{ github.ref }}", true},
		{"installer-performance-${{ github.ref }}", true},
		{wantWorkflowConcurrencyGroup, nil},
		{wantWorkflowConcurrencyGroup, true},
		{wantWorkflowConcurrencyGroup, false},
		{wantWorkflowConcurrencyGroup, "true"},
		{wantWorkflowConcurrencyGroup, "${{ true }}"},
		{wantWorkflowConcurrencyGroup, "${{ github.event_name != 'push' }}"},
	} {
		if validWorkflowConcurrency(bad.group, bad.cancelInProgress) {
			t.Fatalf("unsafe workflow concurrency accepted: group=%q cancel-in-progress=%v", bad.group, bad.cancelInProgress)
		}
	}

	const workflowDir = "../../.github/workflows"
	entries, err := os.ReadDir(workflowDir)
	if err != nil {
		t.Fatalf("workflow directory %s unavailable: %v", workflowDir, err)
	}
	workflowCount := 0
	for _, entry := range entries {
		ext := filepath.Ext(entry.Name())
		if entry.IsDir() || (ext != ".yml" && ext != ".yaml") {
			continue
		}
		workflowCount++
		path := filepath.Join(workflowDir, entry.Name())
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("workflow source %s unavailable: %v", path, err)
		}
		var workflow struct {
			Concurrency struct {
				Group            string `yaml:"group"`
				CancelInProgress any    `yaml:"cancel-in-progress"`
			} `yaml:"concurrency"`
			Jobs map[string]struct {
				Concurrency any `yaml:"concurrency"`
			} `yaml:"jobs"`
		}
		if err := yaml.Unmarshal(body, &workflow); err != nil {
			t.Fatalf("workflow %s malformed: %v", path, err)
		}
		if !validWorkflowConcurrency(workflow.Concurrency.Group, workflow.Concurrency.CancelInProgress) {
			t.Fatalf("workflow %s concurrency must pin group=%q and cancel-in-progress=%q; got group=%q cancel-in-progress=%v",
				path, wantWorkflowConcurrencyGroup, wantWorkflowConcurrencyCancelInProgress,
				workflow.Concurrency.Group, workflow.Concurrency.CancelInProgress)
		}
		if len(workflow.Jobs) == 0 {
			t.Fatalf("workflow %s declares no jobs", path)
		}
		for name, job := range workflow.Jobs {
			if job.Concurrency != nil {
				t.Fatalf("workflow %s job %s overrides top-level concurrency: %v", path, name, job.Concurrency)
			}
		}
	}
	if workflowCount == 0 {
		t.Fatal("no YAML workflows found")
	}
}
