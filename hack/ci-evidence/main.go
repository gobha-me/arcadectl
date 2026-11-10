// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

// ci-evidence reads GitHub Actions evidence. It never sets statuses, reruns CI,
// publishes artifacts, or makes a release decision beyond complete CI proof.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	yaml "go.yaml.in/yaml/v3"
)

const workflowPath = ".github/workflows/ci.yml"

// Keep each jobs response bounded while retaining 32 pages / 2,048 jobs.
const jobsPerPage = 64

var errEvidence = errors.New("CI evidence is unavailable or inconsistent")
var fullSHA = regexp.MustCompile(`^[0-9a-f]{40}$`)
var repositoryName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.-]+$`)
var matrixExpression = regexp.MustCompile(`\$\{\{\s*matrix\.([A-Za-z0-9_]+)\s*\}\}`)

type request struct {
	Repository, SHA string
	RunID           int64
	MainOnly        bool
	FirstAttempt    bool
}

type workflow struct {
	Name string `yaml:"name"`
	Jobs map[string]struct {
		Name     string `yaml:"name"`
		Strategy struct {
			Matrix map[string]any `yaml:"matrix"`
		} `yaml:"strategy"`
	} `yaml:"jobs"`
}

type runMetadata struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	Path       string `json:"path"`
	Event      string `json:"event"`
	SHA        string `json:"head_sha"`
	Branch     string `json:"head_branch"`
	Attempt    int    `json:"run_attempt"`
	Status     string `json:"status"`
	Conclusion string `json:"conclusion"`
	Repository struct {
		Name string `json:"full_name"`
	} `json:"repository"`
}

type job struct {
	ID         int64  `json:"id"`
	RunID      int64  `json:"run_id"`
	Attempt    int    `json:"run_attempt"`
	SHA        string `json:"head_sha"`
	Name       string `json:"name"`
	Status     string `json:"status"`
	Conclusion string `json:"conclusion"`
}

type check struct {
	Name       string `json:"name"`
	Status     string `json:"status"`
	Conclusion string `json:"conclusion"`
	Attempt    int    `json:"attempt"`
	URL        string `json:"url,omitempty"`
}

type report struct {
	Schema        string   `json:"schema"`
	Repository    string   `json:"repository"`
	SHA           string   `json:"sha"`
	RunID         int64    `json:"run_id"`
	Attempt       int      `json:"attempt"`
	Event         string   `json:"event"`
	RunStatus     string   `json:"run_status"`
	RunConclusion string   `json:"run_conclusion"`
	URL           string   `json:"url"`
	WorkflowBlob  string   `json:"workflow_blob"`
	Expected      int      `json:"expected_jobs"`
	Verdict       string   `json:"verdict"`
	Reasons       []string `json:"reasons"`
	Checks        []check  `json:"checks"`
}

type command func(context.Context, string, ...string) ([]byte, error)

func expectedJobs(body []byte) (string, []string, error) {
	var source workflow
	if yaml.Unmarshal(body, &source) != nil || source.Name == "" || len(source.Jobs) == 0 {
		return "", nil, errEvidence
	}
	seen := map[string]bool{}
	for id, job := range source.Jobs {
		name := job.Name
		if name == "" {
			name = id
			if len(job.Strategy.Matrix) != 0 {
				return "", nil, errEvidence // implicit matrix display names are unsupported
			}
		}
		combinations := []map[string]any{{}}
		keys := make([]string, 0, len(job.Strategy.Matrix))
		for key := range job.Strategy.Matrix {
			if key == "include" {
				return "", nil, errEvidence // fail closed on unimplemented matrix semantics
			}
			if key != "exclude" {
				keys = append(keys, key)
			}
		}
		sort.Strings(keys)
		for _, key := range keys {
			values, ok := job.Strategy.Matrix[key].([]any)
			if !ok || len(values) == 0 || len(values) > 64 {
				return "", nil, errEvidence
			}
			var expanded []map[string]any
			for _, previous := range combinations {
				for _, value := range values {
					switch value.(type) {
					case string, int, bool:
					default:
						return "", nil, errEvidence
					}
					copy := make(map[string]any, len(previous)+1)
					for k, v := range previous {
						copy[k] = v
					}
					copy[key] = value
					expanded = append(expanded, copy)
					if len(expanded) > 512 {
						return "", nil, errEvidence
					}
				}
			}
			combinations = expanded
		}
		var exclusions []any
		if raw, exists := job.Strategy.Matrix["exclude"]; exists {
			var ok bool
			exclusions, ok = raw.([]any)
			if !ok {
				return "", nil, errEvidence
			}
		}
		for _, combination := range combinations {
			excluded := false
			for _, raw := range exclusions {
				entry, ok := raw.(map[string]any)
				if !ok || len(entry) == 0 {
					return "", nil, errEvidence
				}
				matches := true
				for key, value := range entry {
					actual, exists := combination[key]
					if !exists {
						return "", nil, errEvidence
					}
					matches = matches && reflect.DeepEqual(actual, value)
				}
				excluded = excluded || matches
			}
			if excluded {
				continue
			}
			valid := true
			expanded := matrixExpression.ReplaceAllStringFunc(name, func(expression string) string {
				key := matrixExpression.FindStringSubmatch(expression)[1]
				value, exists := combination[key]
				valid = valid && exists
				return fmt.Sprint(value)
			})
			if !valid || strings.Contains(expanded, "${{") || strings.TrimSpace(expanded) == "" || seen[expanded] || len(seen) >= 2048 {
				return "", nil, errEvidence
			}
			seen[expanded] = true
		}
	}
	if len(seen) == 0 {
		return "", nil, errEvidence
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return source.Name, names, nil
}

func validate(request request, run runMetadata, names []string, jobs []job, blob string) report {
	result := report{Schema: "arcadectl.ci-evidence/v1", Repository: request.Repository, SHA: request.SHA, RunID: request.RunID, Attempt: run.Attempt, Event: run.Event,
		RunStatus: run.Status, RunConclusion: run.Conclusion,
		URL: fmt.Sprintf("https://github.com/%s/actions/runs/%d", request.Repository, request.RunID), WorkflowBlob: blob, Expected: len(names), Verdict: "pass", Reasons: []string{}, Checks: []check{}}
	reasons := map[string]bool{}
	if !slices.Contains([]string{"queued", "in_progress", "waiting", "pending", "requested", "completed"}, run.Status) {
		result.RunStatus = "unknown"
	}
	if !slices.Contains([]string{"", "success", "failure", "cancelled", "timed_out", "skipped", "neutral", "action_required", "stale", "startup_failure"}, run.Conclusion) {
		result.RunConclusion = "unknown"
		reasons["unknown-run-conclusion"] = true
	}
	if len(names) == 0 {
		reasons["empty-workflow"] = true
	}
	switch run.Event {
	case "pull_request", "push", "schedule", "workflow_dispatch":
	default:
		result.Event = "unknown"
		reasons["unknown-run-event"] = true
	}
	if run.ID != request.RunID || run.SHA != request.SHA || run.Repository.Name != request.Repository || run.Path != workflowPath || run.Attempt < 1 {
		reasons["run-identity-mismatch"] = true
	}
	if request.MainOnly && (run.Branch != "main" || run.Event != "push" && run.Event != "schedule" && run.Event != "workflow_dispatch") {
		reasons["not-main-evidence"] = true
	}
	if request.FirstAttempt && run.Attempt != 1 {
		reasons["not-first-attempt"] = true
	}
	expected := map[string]bool{}
	for _, name := range names {
		expected[name] = true
	}
	seen, identities := map[string]bool{}, map[int64]bool{}
	pending := false
	for _, item := range jobs {
		if !expected[item.Name] {
			reasons["unexpected-job"] = true
			continue // do not project arbitrary producer names
		}
		if seen[item.Name] || identities[item.ID] {
			reasons["duplicate-job"] = true
		}
		seen[item.Name], identities[item.ID] = true, true
		if item.ID <= 0 || item.RunID != run.ID || item.SHA != request.SHA || item.Attempt < 1 || item.Attempt > run.Attempt {
			reasons["job-identity-mismatch"] = true
		}
		entry := check{Name: item.Name, Status: item.Status, Conclusion: item.Conclusion, Attempt: item.Attempt,
			URL: fmt.Sprintf("https://github.com/%s/actions/runs/%d/job/%d", request.Repository, run.ID, item.ID)}
		if item.Status != "completed" && item.Conclusion != "" {
			reasons["inconsistent-job-state"] = true
		}
		switch item.Status {
		case "completed":
			if item.Conclusion != "success" {
				reasons["job-not-success"] = true
			}
		case "queued", "in_progress", "waiting", "pending", "requested":
			pending = true
		default:
			entry.Status = "unknown"
			reasons["unknown-job-status"] = true
		}
		switch item.Conclusion {
		case "", "success", "failure", "cancelled", "timed_out", "skipped", "neutral", "action_required", "stale", "startup_failure":
		default:
			entry.Conclusion = "unknown"
			reasons["unknown-job-conclusion"] = true
		}
		result.Checks = append(result.Checks, entry)
	}
	for _, name := range names {
		if !seen[name] {
			result.Checks = append(result.Checks, check{Name: name, Status: "missing"})
			if run.Status == "completed" {
				reasons["missing-job"] = true
			} else {
				pending = true
			}
		}
	}
	if run.Status != "completed" && run.Conclusion != "" {
		reasons["inconsistent-run-state"] = true
	}
	if run.Status == "completed" {
		if run.Conclusion != "success" {
			reasons["run-not-success"] = true
		}
	} else if slices.Contains([]string{"queued", "in_progress", "waiting", "pending", "requested"}, run.Status) {
		pending = true
	} else {
		reasons["unknown-run-status"] = true
	}
	if len(reasons) > 0 {
		result.Verdict = "fail"
	} else if pending {
		result.Verdict = "pending"
	}
	for reason := range reasons {
		result.Reasons = append(result.Reasons, reason)
	}
	sort.Strings(result.Reasons)
	sort.Slice(result.Checks, func(i, j int) bool { return result.Checks[i].Name < result.Checks[j].Name })
	return result
}

func collect(ctx context.Context, request request, execute command) (report, error) {
	workflow, err := execute(ctx, "git", "show", request.SHA+":"+workflowPath)
	if err != nil {
		return report{}, errEvidence
	}
	workflowName, names, err := expectedJobs(workflow)
	if err != nil {
		return report{}, err
	}
	blob, err := execute(ctx, "git", "rev-parse", request.SHA+":"+workflowPath)
	if err != nil || !fullSHA.MatchString(strings.TrimSpace(string(blob))) {
		return report{}, errEvidence
	}
	endpoint := fmt.Sprintf("repos/%s/actions/runs/%d", request.Repository, request.RunID)
	readRun := func() (runMetadata, error) {
		body, err := execute(ctx, "gh", "api", "--hostname", "github.com", endpoint)
		var run runMetadata
		if err != nil || json.Unmarshal(body, &run) != nil || run.Name != workflowName {
			return run, errEvidence
		}
		return run, nil
	}
	run, err := readRun()
	if err != nil {
		return report{}, err
	}
	var jobs []job
	total := -1
	for page := 1; page <= 32; page++ {
		body, err := execute(ctx, "gh", "api", "--hostname", "github.com", fmt.Sprintf("%s/jobs?filter=latest&per_page=%d&page=%d", endpoint, jobsPerPage, page))
		var data struct {
			Total int   `json:"total_count"`
			Jobs  []job `json:"jobs"`
		}
		if err != nil || json.Unmarshal(body, &data) != nil || data.Total < 0 || data.Total > 2048 || len(data.Jobs) > jobsPerPage || total >= 0 && data.Total != total {
			return report{}, errEvidence
		}
		total = data.Total
		jobs = append(jobs, data.Jobs...)
		if len(jobs) == total {
			break
		}
		if len(data.Jobs) == 0 || len(jobs) > total || page == 32 {
			return report{}, errEvidence
		}
	}
	closing, err := readRun()
	if err != nil || closing != run {
		return report{}, errEvidence // never mix attempts or changing run snapshots
	}
	return validate(request, run, names, jobs, strings.TrimSpace(string(blob))), nil
}

func run(args []string, stdout, stderr io.Writer, execute command) int {
	flags := flag.NewFlagSet("ci-evidence", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var request request
	flags.StringVar(&request.Repository, "repo", "gobha-me/arcadectl", "repository owner/name")
	flags.StringVar(&request.SHA, "sha", "", "exact full source SHA, available in local git")
	flags.Int64Var(&request.RunID, "run-id", 0, "GitHub Actions CI run")
	flags.BoolVar(&request.MainOnly, "main", false, "require a main push, schedule or manual full run")
	flags.BoolVar(&request.FirstAttempt, "first-attempt", false, "require the first run attempt")
	if flags.Parse(args) != nil || flags.NArg() != 0 || !repositoryName.MatchString(request.Repository) || strings.HasSuffix(request.Repository, "/.") || strings.HasSuffix(request.Repository, "/..") || !fullSHA.MatchString(request.SHA) || request.RunID <= 0 {
		_, _ = fmt.Fprintln(stderr, "invalid CI evidence arguments")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	result, err := collect(ctx, request, execute)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, errEvidence)
		_ = json.NewEncoder(stdout).Encode(report{Schema: "arcadectl.ci-evidence/v1", Repository: request.Repository, SHA: request.SHA, RunID: request.RunID, Verdict: "unavailable", Reasons: []string{"evidence-unavailable"}, Checks: []check{}})
		return 2
	}
	if json.NewEncoder(stdout).Encode(result) != nil {
		_, _ = fmt.Fprintln(stderr, "CI evidence output unavailable")
		return 2
	}
	switch result.Verdict {
	case "pass":
		return 0
	case "pending":
		return 3
	default:
		return 1
	}
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return exec.CommandContext(ctx, name, args...).Output()
	}))
}
