// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"errors"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// Shell fixtures test partitioning/failure propagation without launching a
// second Go compiler or test suite inside the shared developer pod.
func TestInstallerRaceShardsDiscoverUnicodeTestsAndKeepCompleteTrees(t *testing.T) {
	script, err := filepath.Abs("../../hack/test-installengine-race-shard.sh")
	if err != nil {
		t.Fatal(err)
	}
	names := []string{"TestAlpha", "TestÉclair", "TestΓamma", "ExampleRead", "FuzzCorpus", "TestZulu", "Test_123"}
	stub := `go() {
  if [[ "$*" == 'test -race -p 1 -list . ./internal/installengine' ]]; then
    printf '%s\n' TestAlpha TestÉclair TestΓamma ExampleRead FuzzCorpus TestZulu Test_123 'ok fake-package 0.001s'
  else
    printf '%s\n' "$*"
  fi
}
export -f go
exec bash "$@"`
	combined := []string{}
	for shard := 0; shard < 4; shard++ {
		output, err := exec.Command("bash", "-c", stub, "shard-fixture", script, strconv.Itoa(shard), "--list-only").CombinedOutput()
		if err != nil {
			t.Fatalf("shard discovery: %v %s", err, output)
		}
		selected := strings.Fields(string(output))
		combined = append(combined, selected...)
		for i, name := range selected {
			if name != names[shard+i*4] {
				t.Fatal("wrong round-robin assignment", shard)
			}
		}
		output, err = exec.Command("bash", "-c", stub, "shard-fixture", script, strconv.Itoa(shard)).CombinedOutput()
		if err != nil {
			t.Fatalf("shard execution: %v %s", err, output)
		}
		pattern := []string{}
		for _, name := range selected {
			pattern = append(pattern, "^"+name+"$")
		}
		if !strings.HasSuffix(string(output), "test -race -p 1 -timeout=20m ./internal/installengine -run "+strings.Join(pattern, "|")+" -count=1\n") {
			t.Fatal("changed execution flags or unanchored tree selection")
		}
	}
	slices.Sort(names)
	slices.Sort(combined)
	if !slices.Equal(names, combined) {
		t.Fatal("duplicate or omitted compiled tests")
	}
	for _, args := range [][]string{nil, {"-1"}, {"4"}, {"x"}, {"0", "--unreviewed"}, {"0", "--list-only", "extra"}} {
		command := exec.Command("bash", append([]string{"-c", "go() { return 93; }\nexport -f go\nexec bash \"$@\"", "invalid-argument-fixture", script}, args...)...)
		if err := command.Run(); err == nil {
			t.Fatal("invalid shard arguments accepted")
		} else {
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 2 {
				t.Fatal("invalid shard did not fail before discovery", err)
			}
		}
	}
	for _, failure := range []string{"go() { return 23; }", "go() { printf '%s\n' 'ok fake-package 0.001s'; }", "go() { if [[ \"$*\" == *'-list .'* ]]; then printf '%s\\n' TestA TestB TestC TestD; else return 23; fi; }"} {
		command := exec.Command("bash", "-c", failure+"\nexport -f go\nexec bash \"$@\"", "failure-fixture", script, "0")
		if err := command.Run(); err == nil {
			t.Fatal("discovery, empty gate or selected test failure was swallowed")
		}
	}
}
