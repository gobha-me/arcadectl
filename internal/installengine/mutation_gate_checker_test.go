// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// gremlinsOutputResult mirrors Gremlins v0.6.0 internal/report/internal/structure.go OutputResult.
type gremlinsOutputResult struct {
	GoModule          string               `json:"go_module"`
	Files             []gremlinsOutputFile `json:"files"`
	TestEfficacy      float64              `json:"test_efficacy"`
	MutationsCoverage float64              `json:"mutations_coverage"`
	MutantsTotal      int                  `json:"mutants_total"`
	MutantsKilled     int                  `json:"mutants_killed"`
	MutantsLived      int                  `json:"mutants_lived"`
	MutantsNotViable  int                  `json:"mutants_not_viable"`
	MutantsNotCovered int                  `json:"mutants_not_covered"`
	ElapsedTime       float64              `json:"elapsed_time"`
	MutatorStatistics gremlinsMutatorType  `json:"mutator_statistics"`
}

type gremlinsOutputFile struct {
	Filename  string             `json:"file_name"`
	Mutations []gremlinsMutation `json:"mutations"`
}

type gremlinsMutation struct {
	Type   string `json:"type"`
	Status string `json:"status"`
	Line   int    `json:"line"`
	Column int    `json:"column"`
}

type gremlinsMutatorType struct {
	ArithmeticBase       int `json:"arithmetic_base,omitempty"`
	ConditionalsNegation int `json:"conditionals_negation,omitempty"`
	ConditionalsBoundary int `json:"conditionals_boundary,omitempty"`
}

// buildGremlinsReport computes top-level counts and percentages using Gremlins v0.6.0
// internal/report/report.go rules:
//   - test_efficacy = killed / (killed + lived) * 100
//   - mutations_coverage = (killed + lived) / (killed + lived + not_covered) * 100
//   - mutants_total = lived + killed + not_viable (excludes NOT COVERED and TIMED OUT)
func buildGremlinsReport(files []gremlinsOutputFile) gremlinsOutputResult {
	var killed, lived, notCovered, notViable int
	var stats gremlinsMutatorType
	for _, f := range files {
		for _, m := range f.Mutations {
			switch m.Status {
			case "KILLED":
				killed++
			case "LIVED":
				lived++
			case "NOT COVERED":
				notCovered++
			case "NOT VIABLE":
				notViable++
			}
			switch m.Type {
			case "ARITHMETIC_BASE":
				stats.ArithmeticBase++
			case "CONDITIONALS_NEGATION":
				stats.ConditionalsNegation++
			case "CONDITIONALS_BOUNDARY":
				stats.ConditionalsBoundary++
			}
		}
	}
	var efficacy, coverage float64
	if killed > 0 {
		efficacy = float64(killed) / float64(killed+lived) * 100
	}
	if killed+lived > 0 {
		coverage = float64(killed+lived) / float64(killed+lived+notCovered) * 100
	}
	return gremlinsOutputResult{
		GoModule:          "github.com/gobha-me/arcadectl",
		Files:             files,
		TestEfficacy:      efficacy,
		MutationsCoverage: coverage,
		MutantsTotal:      lived + killed + notViable,
		MutantsKilled:     killed,
		MutantsLived:      lived,
		MutantsNotViable:  notViable,
		MutantsNotCovered: notCovered,
		ElapsedTime:       1.25,
		MutatorStatistics: stats,
	}
}

func makeKilledMutations(count int) []gremlinsMutation {
	mutations := make([]gremlinsMutation, 0, count)
	for i := range count {
		mutations = append(mutations, gremlinsMutation{
			Type:   "CONDITIONALS_NEGATION",
			Status: "KILLED",
			Line:   10 + i,
			Column: 9,
		})
	}
	return mutations
}

func runMutationChecker(t *testing.T, report gremlinsOutputResult, extraArgs ...string) (int, string) {
	t.Helper()
	checkerPath := "../../hack/check-mutation-report.py"
	if override := os.Getenv("ARCADECTL_MUTATION_CHECKER"); override != "" {
		checkerPath = override
	}
	reportPath := filepath.Join(t.TempDir(), "adminauth.json")
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal report fixture: %v", err)
	}
	if err := os.WriteFile(reportPath, raw, 0o600); err != nil {
		t.Fatalf("write report fixture: %v", err)
	}
	args := append([]string{checkerPath, reportPath, "90", "90"}, extraArgs...)
	cmd := exec.Command("python3", args...)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return 0, string(out)
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("run python3 %v: %v\n%s", args, err, string(out))
	}
	return exitErr.ExitCode(), string(out)
}

func TestMutationGateChecker(t *testing.T) {
	t.Run("a_one_timed_out_mutant_fails_exit_1_and_names_mutant", func(t *testing.T) {
		mutations := append(makeKilledMutations(9), gremlinsMutation{
			Type:   "CONDITIONALS_NEGATION",
			Status: "TIMED OUT",
			Line:   84,
			Column: 14,
		})
		report := buildGremlinsReport([]gremlinsOutputFile{
			{Filename: "verifier.go", Mutations: mutations},
		})
		code, out := runMutationChecker(t, report)
		if code != 1 {
			t.Fatalf("exit code = %d, want 1; output:\n%s", code, out)
		}
		if !strings.Contains(out, "TIMED OUT: verifier.go:84:14 CONDITIONALS_NEGATION") {
			t.Fatalf("output did not name timed-out mutant file:line:col mutator:\n%s", out)
		}
		if !strings.HasPrefix(out, "FAIL ") {
			t.Fatalf("output did not start with FAIL:\n%s", out)
		}
	})

	t.Run("b_one_not_viable_mutant_fails_exit_1_and_names_mutant", func(t *testing.T) {
		mutations := append(makeKilledMutations(9), gremlinsMutation{
			Type:   "CONDITIONALS_BOUNDARY",
			Status: "NOT VIABLE",
			Line:   210,
			Column: 41,
		})
		report := buildGremlinsReport([]gremlinsOutputFile{
			{Filename: "credential.go", Mutations: mutations},
		})
		code, out := runMutationChecker(t, report)
		if code != 1 {
			t.Fatalf("exit code = %d, want 1; output:\n%s", code, out)
		}
		if !strings.Contains(out, "NOT VIABLE: credential.go:210:41 CONDITIONALS_BOUNDARY") {
			t.Fatalf("output did not name not-viable mutant file:line:col mutator:\n%s", out)
		}
		if !strings.HasPrefix(out, "FAIL ") {
			t.Fatalf("output did not start with FAIL:\n%s", out)
		}
	})

	t.Run("c_timeouts_over_20_percent_exit_2_inconclusive", func(t *testing.T) {
		// 7 KILLED + 2 TIMED OUT = 9 total -> 2/9 = 22.22% > 20% -> exit 2 INCONCLUSIVE.
		over20 := append(makeKilledMutations(7),
			gremlinsMutation{Type: "CONDITIONALS_NEGATION", Status: "TIMED OUT", Line: 84, Column: 14},
			gremlinsMutation{Type: "CONDITIONALS_BOUNDARY", Status: "TIMED OUT", Line: 129, Column: 40},
		)
		overReport := buildGremlinsReport([]gremlinsOutputFile{
			{Filename: "verifier.go", Mutations: over20},
		})
		codeOver, outOver := runMutationChecker(t, overReport)
		if codeOver != 2 {
			t.Fatalf(">20%% timeout exit code = %d, want 2; output:\n%s", codeOver, outOver)
		}
		if !strings.Contains(outOver, "INCONCLUSIVE") || !strings.Contains(outOver, "timed-out mutants exceed 20% of all mutants") {
			t.Fatalf(">20%% timeout output missing INCONCLUSIVE message:\n%s", outOver)
		}
		if !strings.Contains(outOver, "TIMED OUT: verifier.go:84:14 CONDITIONALS_NEGATION") ||
			!strings.Contains(outOver, "TIMED OUT: verifier.go:129:40 CONDITIONALS_BOUNDARY") {
			t.Fatalf(">20%% timeout output did not name timed-out mutants:\n%s", outOver)
		}
	})

	t.Run("c_timeouts_exact_20_percent_exit_1_not_2", func(t *testing.T) {
		// 8 KILLED + 2 TIMED OUT = 10 total -> 2/10 = 20.00% (exactly 20%) -> exit 1 (FAIL), not 2.
		exact20 := append(makeKilledMutations(8),
			gremlinsMutation{Type: "CONDITIONALS_NEGATION", Status: "TIMED OUT", Line: 84, Column: 14},
			gremlinsMutation{Type: "CONDITIONALS_BOUNDARY", Status: "TIMED OUT", Line: 129, Column: 40},
		)
		exactReport := buildGremlinsReport([]gremlinsOutputFile{
			{Filename: "verifier.go", Mutations: exact20},
		})
		codeExact, outExact := runMutationChecker(t, exactReport)
		if codeExact != 1 {
			t.Fatalf("exact 20%% timeout exit code = %d, want 1 (not 2); output:\n%s", codeExact, outExact)
		}
		if strings.Contains(outExact, "INCONCLUSIVE") || !strings.HasPrefix(outExact, "FAIL ") {
			t.Fatalf("exact 20%% timeout output = %q, want FAIL without INCONCLUSIVE", outExact)
		}
	})

	t.Run("d_timed_out_never_counted_as_killed_in_printed_counts", func(t *testing.T) {
		mutations := append(makeKilledMutations(9),
			gremlinsMutation{Type: "CONDITIONALS_BOUNDARY", Status: "LIVED", Line: 100, Column: 14},
			gremlinsMutation{Type: "CONDITIONALS_NEGATION", Status: "NOT COVERED", Line: 62, Column: 22},
			gremlinsMutation{Type: "CONDITIONALS_NEGATION", Status: "TIMED OUT", Line: 210, Column: 19},
			gremlinsMutation{Type: "CONDITIONALS_BOUNDARY", Status: "TIMED OUT", Line: 210, Column: 41},
		)
		report := buildGremlinsReport([]gremlinsOutputFile{
			{Filename: "credential.go", Mutations: mutations},
		})
		code, out := runMutationChecker(t, report)
		if code != 1 {
			t.Fatalf("exit code = %d, want 1; output:\n%s", code, out)
		}
		wantCounts := "killed=9, survived(lived)=1, not covered=1, timed out=2, not viable=0, total=13"
		if !strings.Contains(out, wantCounts) {
			t.Fatalf("printed counts missing %q; output:\n%s", wantCounts, out)
		}
		if strings.Contains(out, "killed=11") {
			t.Fatalf("timed-out mutants were counted as killed:\n%s", out)
		}
	})

	t.Run("e_clean_report_exits_0", func(t *testing.T) {
		mutations := append(makeKilledMutations(18),
			gremlinsMutation{Type: "CONDITIONALS_BOUNDARY", Status: "LIVED", Line: 100, Column: 14},
			gremlinsMutation{Type: "CONDITIONALS_NEGATION", Status: "NOT COVERED", Line: 62, Column: 22},
		)
		report := buildGremlinsReport([]gremlinsOutputFile{
			{Filename: "credential.go", Mutations: mutations[:10]},
			{Filename: "verifier.go", Mutations: mutations[10:]},
		})
		code, out := runMutationChecker(t, report)
		if code != 0 {
			t.Fatalf("clean report exit code = %d, want 0; output:\n%s", code, out)
		}
		if !strings.HasPrefix(out, "PASS ") || strings.Contains(out, "FAIL") || strings.Contains(out, "INCONCLUSIVE") {
			t.Fatalf("clean report unexpected output:\n%s", out)
		}
	})

	t.Run("f_inconsistent_top_level_vs_per_status_counts_fails_exit_1", func(t *testing.T) {
		baseMutations := append(makeKilledMutations(9),
			gremlinsMutation{Type: "CONDITIONALS_NEGATION", Status: "TIMED OUT", Line: 84, Column: 14},
		)
		base := buildGremlinsReport([]gremlinsOutputFile{
			{Filename: "verifier.go", Mutations: baseMutations},
		})

		cases := []struct {
			name   string
			mutate func(*gremlinsOutputResult)
			want   string
		}{
			{
				name: "timed_out_inflating_mutants_killed",
				mutate: func(r *gremlinsOutputResult) {
					r.Files[0].Mutations[9].Status = "KILLED"
					// Top-level killed remains 9 while per-status KILLED is 10.
				},
				want: "invalid mutants_killed",
			},
			{
				name: "mutants_killed_mismatch_on_clean_statuses",
				mutate: func(r *gremlinsOutputResult) {
					r.Files[0].Mutations = makeKilledMutations(10)
					r.MutantsKilled = 9
					r.MutantsTotal = 10
				},
				want: "invalid mutants_killed",
			},
			{
				name: "mutants_total_includes_timed_out_or_not_covered",
				mutate: func(r *gremlinsOutputResult) {
					r.MutantsTotal = 10 // Should be 9 because TIMED OUT is excluded from mutants_total.
				},
				want: "invalid mutants_total",
			},
			{
				name: "mutants_lived_mismatch",
				mutate: func(r *gremlinsOutputResult) {
					r.Files[0].Mutations = makeKilledMutations(10)
					r.MutantsKilled = 10
					r.MutantsLived = 1
					r.MutantsTotal = 11
				},
				want: "invalid mutants_lived",
			},
			{
				name: "mutants_not_covered_mismatch",
				mutate: func(r *gremlinsOutputResult) {
					r.Files[0].Mutations = makeKilledMutations(10)
					r.MutantsKilled = 10
					r.MutantsTotal = 10
					r.MutantsNotCovered = 2
				},
				want: "invalid mutants_not_covered",
			},
			{
				name: "mutants_not_viable_mismatch",
				mutate: func(r *gremlinsOutputResult) {
					r.Files[0].Mutations = makeKilledMutations(10)
					r.MutantsKilled = 10
					r.MutantsTotal = 10
					r.MutantsNotViable = 1
				},
				want: "invalid mutants_not_viable",
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				report := base
				report.Files = []gremlinsOutputFile{
					{
						Filename:  base.Files[0].Filename,
						Mutations: append([]gremlinsMutation(nil), base.Files[0].Mutations...),
					},
				}
				tc.mutate(&report)
				code, out := runMutationChecker(t, report)
				if code != 1 {
					t.Fatalf("%s: exit code = %d, want 1; output:\n%s", tc.name, code, out)
				}
				if !strings.Contains(out, tc.want) {
					t.Fatalf("%s: output %q does not contain %q", tc.name, out, tc.want)
				}
			})
		}
	})
}
