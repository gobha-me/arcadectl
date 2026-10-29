// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
)

func evidenceFixture() (request, runMetadata, []string, []job) {
	request := request{Repository: "gobha-me/arcadectl", SHA: strings.Repeat("a", 40), RunID: 42}
	run := runMetadata{ID: 42, Name: "CI", Path: workflowPath, Event: "pull_request", SHA: request.SHA, Branch: "feature", Attempt: 1, Status: "completed", Conclusion: "success"}
	run.Repository.Name = request.Repository
	names := []string{"Foundation", "Native proof"}
	jobs := []job{{ID: 1, RunID: 42, Attempt: 1, SHA: request.SHA, Name: names[0], Status: "completed", Conclusion: "success"}, {ID: 2, RunID: 42, Attempt: 1, SHA: request.SHA, Name: names[1], Status: "completed", Conclusion: "success"}}
	return request, run, names, jobs
}

func TestEvidenceCannotTurnFailedOrIncompleteProofIntoPass(t *testing.T) {
	for _, test := range []struct {
		name    string
		verdict string
		edit    func(*request, *runMetadata, *[]string, *[]job)
	}{
		{"complete", "pass", func(*request, *runMetadata, *[]string, *[]job) {}},
		{"failed-job-with-successful-run", "fail", func(_ *request, _ *runMetadata, _ *[]string, j *[]job) { (*j)[1].Conclusion = "failure" }},
		{"cancelled-job", "fail", func(_ *request, _ *runMetadata, _ *[]string, j *[]job) { (*j)[1].Conclusion = "cancelled" }},
		{"skipped-proof", "fail", func(_ *request, _ *runMetadata, _ *[]string, j *[]job) { (*j)[1].Conclusion = "skipped" }},
		{"timed-out-proof", "fail", func(_ *request, _ *runMetadata, _ *[]string, j *[]job) { (*j)[1].Conclusion = "timed_out" }},
		{"missing-proof", "fail", func(_ *request, _ *runMetadata, _ *[]string, j *[]job) { *j = (*j)[:1] }},
		{"duplicate-name", "fail", func(_ *request, _ *runMetadata, _ *[]string, j *[]job) { *j = append(*j, (*j)[0]) }},
		{"duplicate-id", "fail", func(_ *request, _ *runMetadata, _ *[]string, j *[]job) { (*j)[1].ID = 1 }},
		{"unexpected-job", "fail", func(_ *request, _ *runMetadata, _ *[]string, j *[]job) { (*j)[1].Name = "PRIVATE-EVIDENCE-CANARY" }},
		{"wrong-run-source", "fail", func(_ *request, r *runMetadata, _ *[]string, _ *[]job) { r.SHA = strings.Repeat("b", 40) }},
		{"wrong-run-repository", "fail", func(_ *request, r *runMetadata, _ *[]string, _ *[]job) { r.Repository.Name = "foreign/repository" }},
		{"wrong-workflow-file", "fail", func(_ *request, r *runMetadata, _ *[]string, _ *[]job) { r.Path = ".github/workflows/diagnostic.yml" }},
		{"wrong-run-id", "fail", func(_ *request, r *runMetadata, _ *[]string, _ *[]job) { r.ID++ }},
		{"wrong-job-source", "fail", func(_ *request, _ *runMetadata, _ *[]string, j *[]job) { (*j)[1].SHA = strings.Repeat("b", 40) }},
		{"wrong-job-run", "fail", func(_ *request, _ *runMetadata, _ *[]string, j *[]job) { (*j)[1].RunID++ }},
		{"future-job-attempt", "fail", func(_ *request, _ *runMetadata, _ *[]string, j *[]job) { (*j)[1].Attempt++ }},
		{"failed-run-with-successful-jobs", "fail", func(_ *request, r *runMetadata, _ *[]string, _ *[]job) { r.Conclusion = "failure" }},
		{"unknown-event", "fail", func(_ *request, r *runMetadata, _ *[]string, _ *[]job) { r.Event = "PRIVATE-EVIDENCE-CANARY" }},
		{"unknown-job-state", "fail", func(_ *request, _ *runMetadata, _ *[]string, j *[]job) { (*j)[1].Status = "PRIVATE-EVIDENCE-CANARY" }},
		{"unknown-job-conclusion", "fail", func(_ *request, _ *runMetadata, _ *[]string, j *[]job) {
			(*j)[1].Conclusion = "PRIVATE-EVIDENCE-CANARY"
		}},
		{"candidate-is-not-main", "fail", func(q *request, _ *runMetadata, _ *[]string, _ *[]job) { q.MainOnly = true }},
		{"main-proof", "pass", func(q *request, r *runMetadata, _ *[]string, _ *[]job) {
			q.MainOnly = true
			r.Event = "schedule"
			r.Branch = "main"
		}},
		{"rerun-disallowed-by-policy", "fail", func(q *request, r *runMetadata, _ *[]string, _ *[]job) { q.FirstAttempt = true; r.Attempt = 2 }},
		{"rerun-recorded-with-reused-same-source-jobs", "pass", func(_ *request, r *runMetadata, _ *[]string, _ *[]job) { r.Attempt = 2 }},
		{"empty-proof-set", "fail", func(_ *request, _ *runMetadata, n *[]string, j *[]job) { *n = nil; *j = nil }},
		{"queued-proof", "pending", func(_ *request, r *runMetadata, _ *[]string, j *[]job) {
			r.Status = "in_progress"
			r.Conclusion = ""
			(*j)[1].Status = "queued"
			(*j)[1].Conclusion = ""
		}},
		{"jobs-not-yet-created", "pending", func(_ *request, r *runMetadata, _ *[]string, j *[]job) {
			r.Status = "queued"
			r.Conclusion = ""
			*j = nil
		}},
		{"contradictory-job", "fail", func(_ *request, _ *runMetadata, _ *[]string, j *[]job) { (*j)[1].Status = "in_progress" }},
		{"contradictory-run", "fail", func(_ *request, r *runMetadata, _ *[]string, _ *[]job) { r.Status = "in_progress" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			q, r, names, jobs := evidenceFixture()
			test.edit(&q, &r, &names, &jobs)
			result := validate(q, r, names, jobs, strings.Repeat("c", 40))
			if result.Verdict != test.verdict {
				t.Fatalf("verdict=%s want=%s reasons=%v", result.Verdict, test.verdict, result.Reasons)
			}
			body, err := json.Marshal(result)
			if err != nil || bytes.Contains(body, []byte("PRIVATE")) {
				t.Fatal("untrusted producer label escaped into evidence")
			}
		})
	}
}

func TestExpectedJobsExpandsEveryFiniteMatrixCombinationAndExclusion(t *testing.T) {
	body := []byte(`name: CI
jobs:
  foundation:
    name: Foundation
  native:
    name: Native ${{ matrix.profile }} ${{matrix.mode}}
    strategy:
      matrix:
        profile: [135, 137]
        mode: [cold, warm]
        exclude:
          - profile: 135
            mode: warm
`)
	name, jobs, err := expectedJobs(body)
	want := []string{"Foundation", "Native 135 cold", "Native 137 cold", "Native 137 warm"}
	if err != nil || name != "CI" || !slices.Equal(jobs, want) {
		t.Fatal("finite matrix coverage changed", name, jobs, err)
	}
	for _, bad := range []string{
		"name: CI\njobs: {}",
		"name: CI\njobs:\n  a: {name: Duplicate}\n  b: {name: Duplicate}",
		"name: CI\njobs:\n  a: {name: '${{ secrets.PRIVATE }}'}",
		"name: CI\njobs:\n  a:\n    name: '${{ matrix.missing }}'\n    strategy:\n      matrix: {x: [1, 2]}",
		"name: CI\njobs:\n  a:\n    name: Matrix\n    strategy:\n      matrix: {include: [{x: 1}]}",
		"name: CI\njobs:\n  a:\n    name: '${{ matrix.x }}'\n    strategy:\n      matrix: {x: []}",
		"name: CI\njobs:\n  a:\n    name: '${{ matrix.x }}'\n    strategy:\n      matrix: '${{ fromJSON(needs.a.outputs.x) }}'",
	} {
		if _, _, err := expectedJobs([]byte(bad)); err == nil {
			t.Fatal("unsupported, incomplete or ambiguous workflow was accepted")
		}
	}
}

func TestCollectorPaginatesAllJobsAndRejectsChangingSnapshots(t *testing.T) {
	q, metadata, _, _ := evidenceFixture()
	var values []string
	for i := 0; i < 60; i++ {
		values = append(values, fmt.Sprint(i))
	}
	workflow := []byte("name: CI\njobs:\n  proof:\n    name: Proof ${{ matrix.a }} ${{ matrix.b }}\n    strategy:\n      matrix:\n        a: [" + strings.Join(values, ",") + "]\n        b: [one, two]\n")
	_, names, err := expectedJobs(workflow)
	if err != nil || len(names) != 120 {
		t.Fatal("pagination control workflow unavailable", err)
	}
	all := make([]job, len(names))
	for i, name := range names {
		all[i] = job{ID: int64(i + 1), RunID: q.RunID, Attempt: 1, SHA: q.SHA, Name: name, Status: "completed", Conclusion: "success"}
	}
	for _, fault := range []string{"none", "truncated", "changing-total", "changing-attempt", "remote-error", "wrong-workflow-name"} {
		t.Run(fault, func(t *testing.T) {
			runReads, pages := 0, 0
			execute := func(_ context.Context, executable string, args ...string) ([]byte, error) {
				key := executable + " " + strings.Join(args, " ")
				switch key {
				case "git show " + q.SHA + ":" + workflowPath:
					return workflow, nil
				case "git rev-parse " + q.SHA + ":" + workflowPath:
					return []byte(strings.Repeat("c", 40)), nil
				case "gh api --hostname github.com repos/gobha-me/arcadectl/actions/runs/42":
					runReads++
					copy := metadata
					if fault == "changing-attempt" && runReads == 2 {
						copy.Attempt++
					}
					if fault == "wrong-workflow-name" {
						copy.Name = "Diagnostic"
					}
					return json.Marshal(copy)
				case "gh api --hostname github.com repos/gobha-me/arcadectl/actions/runs/42/jobs?filter=latest&per_page=100&page=1":
					pages++
					if fault == "remote-error" {
						return nil, errors.New("PRIVATE-EVIDENCE-CANARY")
					}
					return json.Marshal(map[string]any{"total_count": 120, "jobs": all[:100]})
				case "gh api --hostname github.com repos/gobha-me/arcadectl/actions/runs/42/jobs?filter=latest&per_page=100&page=2":
					pages++
					total, tail := 120, all[100:]
					if fault == "changing-total" {
						total++
					}
					if fault == "truncated" {
						tail = nil
					}
					return json.Marshal(map[string]any{"total_count": total, "jobs": tail})
				default:
					t.Fatalf("collector attempted an unexpected command: %s", key)
					return nil, errEvidence
				}
			}
			result, err := collect(t.Context(), q, execute)
			if fault == "none" {
				if err != nil || result.Verdict != "pass" || len(result.Checks) != 120 || pages != 2 || runReads != 2 {
					t.Fatal("complete paginated evidence did not pass", result.Verdict, err)
				}
			} else if err == nil {
				t.Fatal("unstable, truncated, wrong-workflow or unavailable evidence was accepted")
			}
		})
	}
}

func TestCollectorCLIRejectsInvalidArgumentsAndWithholdsProviderErrors(t *testing.T) {
	for _, args := range [][]string{nil, {"--sha", "PRIVATE-EVIDENCE-CANARY", "--run-id", "42"}, {"--repo", "owner/..", "--sha", strings.Repeat("a", 40), "--run-id", "42"}} {
		var stdout, stderr bytes.Buffer
		code := run(args, &stdout, &stderr, func(context.Context, string, ...string) ([]byte, error) {
			t.Fatal("invalid arguments executed a command")
			return nil, errEvidence
		})
		if code != 2 || strings.Contains(stderr.String(), "PRIVATE") || stdout.Len() != 0 {
			t.Fatal("invalid invocation leaked arguments or did not fail")
		}
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{"--sha", strings.Repeat("a", 40), "--run-id", "42"}, &stdout, &stderr, func(context.Context, string, ...string) ([]byte, error) {
		return nil, errors.New("PRIVATE-EVIDENCE-CANARY")
	})
	if code != 2 || strings.Contains(stdout.String()+stderr.String(), "PRIVATE") || !strings.Contains(stdout.String(), `"verdict":"unavailable"`) {
		t.Fatal("unavailable evidence did not remain distinct from a pass, or leaked provider text")
	}
}
