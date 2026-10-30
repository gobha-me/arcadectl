// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"slices"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

// Exact pre-baseline installer hotfix descendant, distinct from the unchanged
// authentic predecessor API/controller runtime. The original installer remains
// immutable evidence, not a successful certification. Preserve this lineage
// through the read-only PR ref after squash; never build the moving tip.
const binaryHistoricalInstallerSource = "2106372de2f2c8bb636e2369a04b1d2ccaeaca48"
const binaryHistoricalInstallerTree = "77589f36c0840e1266878eb35ce38146d2761e6a"
const binaryHistoricalInstallerDiagnosticBase = "15c63004cd1ddab3f561acaf783348faf72b7ee7"
const binaryHistoricalInstallerDiagnosticBaseTree = "f6ed281f6bfb2896e2dab14297cdf4e37e5f970c"
const binaryHistoricalInstallerBase = "2e897ca3b76617ac63c4a294d7ba8c908dcc368b"
const binaryHistoricalInstallerBaseTree = "6ba09e173b112c60a7c38d78cebf62e6d2859ec9"

func historicalInstallerDiagnosticTestArguments() []string {
	return []string{"test", "-p", "1", "-count=1", "-timeout=10m", "./internal/installengine", "-run",
		"^(TestHistoricalAccountingDiagnosticErasesToOriginal|" +
			"TestHistoricalAccountingTokenOraclePreservesSemanticWhitespace|" +
			"TestHistoricalAccountingDiagnosticMatchesUntracedResult|" +
			"TestHistoricalAccountingDiagnosticWarmV2|" +
			"TestHistoricalAccountingDiagnosticPreservesOriginalPhaseNumbers|" +
			"TestAdmissionPhaseTraceClosedStagesAndNoArbitraryValues)$"}
}

// The anchored selector must match real untagged test declarations in the
// archived source, not merely let go test succeed with zero selected roots.
func historicalInstallerDiagnosticDeclarationsMatch(sources map[string][]byte) bool {
	if len(sources) != 2 {
		return false
	}
	wanted := map[string]bool{
		"TestHistoricalAccountingDiagnosticErasesToOriginal":              false,
		"TestHistoricalAccountingTokenOraclePreservesSemanticWhitespace":  false,
		"TestHistoricalAccountingDiagnosticMatchesUntracedResult":         false,
		"TestHistoricalAccountingDiagnosticWarmV2":                        false,
		"TestHistoricalAccountingDiagnosticPreservesOriginalPhaseNumbers": false,
		"TestAdmissionPhaseTraceClosedStagesAndNoArbitraryValues":         false,
	}
	for _, name := range []string{"fixture_accounting_diagnostic_hotfix_test.go", "admission_trace_test.go"} {
		source := sources[name]
		if len(source) == 0 || len(source) > 262144 || bytes.Contains(source, []byte("//go:build")) || bytes.Contains(source, []byte("// +build")) {
			return false
		}
		file, err := parser.ParseFile(token.NewFileSet(), name, source, 0)
		if err != nil || file.Name.Name != "installengine" {
			return false
		}
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok {
				continue
			}
			seen, required := wanted[function.Name.Name]
			if required {
				if seen || function.Recv != nil {
					return false
				}
				wanted[function.Name.Name] = true
			}
		}
	}
	for _, seen := range wanted {
		if !seen {
			return false
		}
	}
	return true
}

func TestInstallerHistoricalSourceAcquisitionSurvivesSquash(t *testing.T) {
	body, err := os.ReadFile("../../.github/workflows/ci.yml")
	if err != nil {
		t.Fatal("required installer CI unavailable")
	}
	var workflow struct {
		Jobs map[string]struct {
			Steps []struct {
				Name string
				If   string
				Run  string
				Env  map[string]string
			}
		}
	}
	if yaml.Unmarshal(body, &workflow) != nil {
		t.Fatal("required installer CI malformed")
	}
	want := fmt.Sprintf(`git fetch --no-tags --no-recurse-submodules --no-write-fetch-head \
  https://github.com/gobha-me/arcadectl.git \
  '+refs/pull/62/head:refs/arcadectl-fixtures/pr62'
test "$(git rev-parse '%s^{commit}')" = %s
git merge-base --is-ancestor %s refs/arcadectl-fixtures/pr62
test "$(git rev-parse '%s^{tree}')" = %s
test "$(git rev-parse '%s^')" = %s
test "$(git rev-parse '%s^{tree}')" = %s
test "$(git rev-parse '%s^')" = %s
test "$(git rev-parse '%s^{tree}')" = %s`, binaryHistoricalInstallerSource, binaryHistoricalInstallerSource, binaryHistoricalInstallerSource, binaryHistoricalInstallerSource, binaryHistoricalInstallerTree, binaryHistoricalInstallerSource, binaryHistoricalInstallerDiagnosticBase, binaryHistoricalInstallerDiagnosticBase, binaryHistoricalInstallerDiagnosticBaseTree, binaryHistoricalInstallerDiagnosticBase, binaryHistoricalInstallerBase, binaryHistoricalInstallerBase, binaryHistoricalInstallerBaseTree)
	const wantBinaryRun = `if [[ "$INSTALL_BINARY_MODE" == transition ]]; then
  bash ./hack/ci-no-progress-watchdog.sh 30 "137 transition" \
    make test-kind-install-binary INSTALL_BINARY_PROFILE="$INSTALL_BINARY_PROFILE" INSTALL_BINARY_MODE="$INSTALL_BINARY_MODE"
else
  make test-kind-install-binary INSTALL_BINARY_PROFILE="$INSTALL_BINARY_PROFILE" INSTALL_BINARY_MODE="$INSTALL_BINARY_MODE"
fi`
	count, binaryRuns, acquired := 0, 0, false
	for _, step := range workflow.Jobs["kind-install-binary"].Steps {
		if step.Name == "Acquire exact historical installer source" {
			count++
			if step.If != "matrix.mode == 'transition'" || strings.TrimSpace(step.Run) != want {
				t.Fatal("historical acquisition changed authority, exact source/tree or transition scope")
			}
			acquired = true
		}
		if strings.Contains(step.Run, "make test-kind-install-binary") {
			binaryRuns++
			if !acquired || step.If != "" || len(step.Env) != 2 || step.Env["INSTALL_BINARY_PROFILE"] != "${{ matrix.profile }}" || step.Env["INSTALL_BINARY_MODE"] != "${{ matrix.mode }}" || strings.TrimSpace(step.Run) != wantBinaryRun {
				t.Fatal("native transition command changed or can run before authentic historical source acquisition")
			}
		}
	}
	if count != 1 || binaryRuns != 1 {
		t.Fatal("exactly one authentic source acquisition and native binary gate are required")
	}
	t.Run("diagnostic-tests-before-build", func(t *testing.T) {
		wantArguments := []string{"test", "-p", "1", "-count=1", "-timeout=10m", "./internal/installengine", "-run",
			"^(TestHistoricalAccountingDiagnosticErasesToOriginal|TestHistoricalAccountingTokenOraclePreservesSemanticWhitespace|TestHistoricalAccountingDiagnosticMatchesUntracedResult|TestHistoricalAccountingDiagnosticWarmV2|TestHistoricalAccountingDiagnosticPreservesOriginalPhaseNumbers|TestAdmissionPhaseTraceClosedStagesAndNoArbitraryValues)$"}
		if !slices.Equal(historicalInstallerDiagnosticTestArguments(), wantArguments) {
			t.Fatal("historical diagnostic test gate changed scope or bounds")
		}
		source, err := os.ReadFile("installer_binary_historical_kind_test.go")
		if err != nil {
			t.Fatal("historical binary builder source unavailable")
		}
		set := token.NewFileSet()
		file, err := parser.ParseFile(set, "historical-builder", source, 0)
		if err != nil {
			t.Fatal("historical binary builder source invalid")
		}
		var calls []string
		var positions []int
		var builder *ast.BlockStmt
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Name.Name != "buildHistoricalInstallerBinary" {
				continue
			}
			if builder != nil {
				t.Fatal("historical binary builder ambiguous")
			}
			builder = function.Body
			for index, statement := range function.Body.List {
				expression, ok := statement.(*ast.ExprStmt)
				if !ok {
					continue
				}
				call, ok := expression.X.(*ast.CallExpr)
				if !ok {
					continue
				}
				name, ok := call.Fun.(*ast.Ident)
				if !ok || name.Name != "run" {
					continue
				}
				var encoded bytes.Buffer
				if format.Node(&encoded, set, call) != nil {
					t.Fatal("historical build sequence unavailable")
				}
				calls = append(calls, encoded.String())
				positions = append(positions, index)
			}
		}
		wantCalls := []string{
			`run(root, "git", "archive", "--format=tar", "--output="+archive, binaryHistoricalInstallerSource)`,
			`run(root, "tar", "--extract", "--file", archive, "--directory", sourceRoot, "--no-same-owner")`,
			`run(sourceRoot, "go", historicalInstallerDiagnosticTestArguments()...)`,
			`run(sourceRoot, "go", "build", "-p", "1", "-trimpath", "-o", binary, "./cmd/arcadectl-installer")`,
		}
		for index, expected := range wantCalls {
			expression, err := parser.ParseExpr(expected)
			var encoded bytes.Buffer
			if err != nil || format.Node(&encoded, token.NewFileSet(), expression) != nil {
				t.Fatal("historical build sequence control invalid")
			}
			wantCalls[index] = encoded.String()
		}
		if !slices.Equal(calls, wantCalls) {
			t.Fatal("historical diagnostic tests skipped or not before binary build")
		}
		var declarationChecks []int
		for index, statement := range builder.List {
			guard, ok := statement.(*ast.IfStmt)
			if !ok {
				continue
			}
			condition, ok := guard.Cond.(*ast.UnaryExpr)
			if !ok || condition.Op != token.NOT {
				continue
			}
			call, ok := condition.X.(*ast.CallExpr)
			if !ok {
				continue
			}
			name, ok := call.Fun.(*ast.Ident)
			if ok && name.Name == "historicalInstallerDiagnosticDeclarationsMatch" {
				var encoded bytes.Buffer
				if format.Node(&encoded, set, call) != nil || encoded.String() != "historicalInstallerDiagnosticDeclarationsMatch(diagnosticSources)" || guard.Init != nil || guard.Else != nil || len(guard.Body.List) != 1 {
					t.Fatal("historical declaration guard unavailable")
				}
				encoded.Reset()
				failure, ok := guard.Body.List[0].(*ast.ExprStmt)
				if !ok || format.Node(&encoded, set, failure.X) != nil || encoded.String() != `t.Fatal("historical diagnostic roots absent or not selected")` {
					t.Fatal("historical declaration failure does not stop binary build")
				}
				declarationChecks = append(declarationChecks, index)
			}
		}
		if len(declarationChecks) != 1 || declarationChecks[0] <= positions[1] || declarationChecks[0] >= positions[2] {
			t.Fatal("historical selected-test declaration guard missing")
		}
	})
	t.Run("diagnostic-test-declarations", func(t *testing.T) {
		roots := []string{
			"TestHistoricalAccountingDiagnosticErasesToOriginal",
			"TestHistoricalAccountingTokenOraclePreservesSemanticWhitespace",
			"TestHistoricalAccountingDiagnosticMatchesUntracedResult",
			"TestHistoricalAccountingDiagnosticWarmV2",
			"TestHistoricalAccountingDiagnosticPreservesOriginalPhaseNumbers",
			"TestAdmissionPhaseTraceClosedStagesAndNoArbitraryValues",
		}
		first, second := "fixture_accounting_diagnostic_hotfix_test.go", "admission_trace_test.go"
		good := map[string][]byte{first: []byte("package installengine\nimport \"testing\"\n"), second: []byte("package installengine\nimport \"testing\"\n")}
		for index, root := range roots {
			name := first
			if index == len(roots)-1 {
				name = second
			}
			good[name] = append(good[name], []byte("func "+root+"(t *testing.T) {}\n")...)
		}
		if !historicalInstallerDiagnosticDeclarationsMatch(good) {
			t.Fatal("complete selected declarations refused")
		}
		for _, change := range []func(map[string][]byte){
			func(m map[string][]byte) { delete(m, first) },
			func(m map[string][]byte) { m["other_test.go"] = m[first] },
			func(m map[string][]byte) {
				m[first] = bytes.ReplaceAll(m[first], []byte(roots[0]), []byte("TestUnselected"))
			},
			func(m map[string][]byte) {
				m[first] = append(m[first], []byte("func "+roots[0]+"(t *testing.T) {}\n")...)
			},
			func(m map[string][]byte) { m[first] = append([]byte("//go:build ignore\n\n"), m[first]...) },
			func(m map[string][]byte) {
				m[first] = bytes.ReplaceAll(m[first], []byte("package installengine"), []byte("package foreign"))
			},
			func(m map[string][]byte) {
				m[first] = bytes.ReplaceAll(m[first], []byte("func "+roots[0]), []byte("func (x *X) "+roots[0]))
			},
		} {
			bad := map[string][]byte{first: bytes.Clone(good[first]), second: bytes.Clone(good[second])}
			change(bad)
			if historicalInstallerDiagnosticDeclarationsMatch(bad) {
				t.Fatal("incomplete or unselected diagnostic declaration accepted")
			}
		}
	})
}
