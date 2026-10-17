// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

// Exact unmodified pre-baseline installer, distinct from the authentic
// predecessor API/controller runtime. Squash-only main does not contain this
// PR ancestor; fetch its preserved read-only PR ref, never build the moving tip.
const binaryHistoricalInstallerSource = "2e897ca3b76617ac63c4a294d7ba8c908dcc368b"
const binaryHistoricalInstallerTree = "6ba09e173b112c60a7c38d78cebf62e6d2859ec9"

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
test "$(git rev-parse '%s^{tree}')" = %s`, binaryHistoricalInstallerSource, binaryHistoricalInstallerSource, binaryHistoricalInstallerSource, binaryHistoricalInstallerSource, binaryHistoricalInstallerTree)
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
			if !acquired || strings.TrimSpace(step.Run) != "make test-kind-install-binary INSTALL_BINARY_PROFILE='${{ matrix.profile }}' INSTALL_BINARY_MODE='${{ matrix.mode }}'" {
				t.Fatal("native transition command changed or can run before authentic historical source acquisition")
			}
		}
	}
	if count != 1 || binaryRuns != 1 {
		t.Fatal("exactly one authentic source acquisition and native binary gate are required")
	}
}
