// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"errors"
	"fmt"
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
	names := []string{"TestAlpha", "TestÉclair", "TestΓamma", "ExampleRead", "FuzzCorpus", "TestZulu", "Test_123", "TestEight", "TestNine", "TestTen", "TestEleven", "TestTwelve", "TestThirteen", "TestFourteen", "TestFifteen", "TestSixteen", "TestSeventeen", "TestEighteen", "TestNineteen"}
	for i := 20; i <= 33; i++ {
		names = append(names, "TestExtra"+strconv.Itoa(i))
	}
	stub := `go() {
  if [[ "$*" == 'test -race -p 1 -list . ./internal/installengine' ]]; then
    printf '%s\n' ` + strings.Join(names, " ") + ` 'ok fake-package 0.001s'
  else
    printf '%s\n' "$*"
  fi
}

export -f go
exec bash "$@"`
	combined := []string{}
	partitions := make([][]string, 32)
	for shard := 0; shard < 32; shard++ {
		output, err := exec.Command("bash", "-c", stub, "shard-fixture", script, strconv.Itoa(shard), "--list-only").CombinedOutput()
		if err != nil {
			t.Fatalf("shard discovery: %v %s", err, output)
		}
		selected := strings.Fields(string(output))
		partitions[shard] = slices.Clone(selected)
		combined = append(combined, selected...)
		for i, name := range selected {
			if name != names[shard+i*32] {
				t.Fatal("wrong round-robin assignment", shard)
			}
		}
		output, err = exec.Command("bash", "-c", stub, "shard-fixture", script, strconv.Itoa(shard)).CombinedOutput()
		if err != nil {
			t.Fatalf("shard execution: %v %s", err, output)
		}
		if !strings.HasPrefix(string(output), fmt.Sprintf("Installer engine race shard %d/32: %d of %d discovered tests\n", shard, len(selected), len(names))) {
			t.Fatal("reported shard coverage disagreed with actual partition")
		}
		pattern := []string{}
		for _, name := range selected {
			pattern = append(pattern, "^"+name+"$")
		}
		if !strings.HasSuffix(string(output), "test -race -p 1 -timeout=20m ./internal/installengine -run "+strings.Join(pattern, "|")+" -count=1\n") {
			t.Fatal("changed execution flags or unanchored tree selection")
		}
	}
	// Refinement preserves discovery order and only subdivides each original
	// worker's test trees. It must not combine unrelated formerly passing sets.
	for parent := 0; parent < 8; parent++ {
		original := []string{}
		for i := parent; i < len(names); i += 8 {
			original = append(original, names[i])
		}
		for child := 0; child < 4; child++ {
			want := []string{}
			for i := child; i < len(original); i += 4 {
				want = append(want, original[i])
			}
			if !slices.Equal(partitions[parent+child*8], want) {
				t.Fatal("new worker did not preserve ordered original-shard refinement")
			}
		}
	}
	slices.Sort(names)
	slices.Sort(combined)
	if !slices.Equal(names, combined) {
		t.Fatal("duplicate or omitted compiled tests")
	}
	for _, args := range [][]string{nil, {"-1"}, {"32"}, {"40"}, {"01"}, {"015"}, {"031"}, {"x"}, {"0", "--unreviewed"}, {"0", "--list-only", "extra"}} {
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
	for _, option := range [][]string{nil, {"--list-only"}} {
		args := append([]string{"-c", "go() { printf '%s\\n' TestOnly; }\nexport -f go\nexec bash \"$@\"", "empty-assignment-fixture", script, "31"}, option...)
		if exec.Command("bash", args...).Run() == nil {
			t.Fatal("empty assigned shard became a passing gate")
		}
	}
}
