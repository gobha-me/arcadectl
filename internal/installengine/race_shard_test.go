// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// Shell fixtures verify complete compiled coverage without starting another
// Go compiler or test suite in the shared developer pod.
func raceShardScript(t *testing.T, weights string) string {
	t.Helper()
	body, err := os.ReadFile("../../hack/test-installengine-race-shard.sh")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "test-installengine-race-shard.sh")
	if os.WriteFile(script, body, 0600) != nil || os.WriteFile(filepath.Join(dir, "installengine-race-weights.txt"), []byte(weights), 0600) != nil {
		t.Fatal("shard fixture unavailable")
	}
	return script
}

func raceShardStub(names []string) string {
	return `go() {
  if [[ "$*" == 'test -race -p 1 -list . ./internal/installengine' ]]; then
    printf '%s\n' ` + strings.Join(names, " ") + ` 'ok fake-package 0.001s'
  else
    printf '%s\n' "$*"
  fi
}
export -f go
exec bash "$@"`
}

func TestInstallerRaceShardsDiscoverUnicodeTestsAndKeepCompleteTrees(t *testing.T) {
	script := raceShardScript(t, "# scheduling only\nTestHeavy 900\nTestMedium 300\nTestLight 200\n")
	names := []string{"TestAlpha", "TestÉclair", "TestΓamma", "ExampleRead", "FuzzCorpus", "TestZulu", "Test_123", "TestHeavy", "TestMedium", "TestLight"}
	for i := 0; i < 40; i++ {
		names = append(names, "TestExtra"+strconv.Itoa(i))
	}
	// Independent greedy scheduling oracle. Unknown compiled names are included,
	// not rejected or omitted; scheduling metadata is never an execution allowlist.
	ordered := slices.Clone(names)
	weights := map[string]int{"TestHeavy": 900, "TestMedium": 300, "TestLight": 200}
	weight := func(name string) int {
		if v, ok := weights[name]; ok {
			return v
		}
		return 60
	}
	slices.SortFunc(ordered, func(a, b string) int {
		if weight(a) != weight(b) {
			return weight(b) - weight(a)
		}
		return strings.Compare(a, b)
	})
	loads := make([]int, 32)
	want := make([][]string, 32)
	for _, name := range ordered {
		selected := 0
		for i := 1; i < 32; i++ {
			if loads[i] < loads[selected] {
				selected = i
			}
		}
		want[selected] = append(want[selected], name)
		loads[selected] += weight(name)
	}
	combined := []string{}
	for shard := 0; shard < 32; shard++ {
		args := []string{"-c", raceShardStub(names), "shard-fixture", script, strconv.Itoa(shard)}
		output, err := exec.Command("bash", append(slices.Clone(args), "--list-only")...).CombinedOutput()
		if err != nil {
			t.Fatalf("shard discovery: %v %s", err, output)
		}
		selected := strings.Fields(string(output))
		if !slices.Equal(selected, want[shard]) {
			t.Fatal("nondeterministic weighted assignment", shard, selected, want[shard])
		}
		combined = append(combined, selected...)
		reversed := slices.Clone(names)
		slices.Reverse(reversed)
		output, err = exec.Command("bash", "-c", raceShardStub(reversed), "reverse-discovery-fixture", script, strconv.Itoa(shard), "--list-only").CombinedOutput()
		if err != nil || !slices.Equal(strings.Fields(string(output)), selected) {
			t.Fatal("discovery ordering changed deterministic scheduling")
		}
		output, err = exec.Command("bash", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("shard execution: %v %s", err, output)
		}
		report := fmt.Sprintf("Installer engine race shard %d/32: %d of %d discovered tests\n", shard, len(selected), len(names))
		if !strings.HasPrefix(string(output), report) {
			t.Fatal("reported coverage disagreed with partition")
		}
		pattern := []string{}
		for _, name := range selected {
			pattern = append(pattern, "^"+name+"$")
			if !strings.Contains(string(output), "Selected: "+name+"\n") {
				t.Fatal("selected tree missing from timing diagnostics")
			}
		}
		if !strings.HasSuffix(string(output), "test -race -p 1 -timeout=20m -v ./internal/installengine -run "+strings.Join(pattern, "|")+" -count=1\n") {
			t.Fatal("changed bounded race flags or unanchored tree selection")
		}
	}
	slices.Sort(names)
	slices.Sort(combined)
	if !slices.Equal(names, combined) {
		t.Fatal("duplicate or omitted compiled tests")
	}
}

func TestInstallerRaceShardsRefuseInvalidInputsAndPropagateFailures(t *testing.T) {
	script := raceShardScript(t, "TestA 60\n")
	for _, args := range [][]string{nil, {"-1"}, {"32"}, {"40"}, {"01"}, {"015"}, {"031"}, {"x"}, {"0", "--unreviewed"}, {"0", "--list-only", "extra"}} {
		command := exec.Command("bash", append([]string{"-c", "go() { return 93; }\nexport -f go\nexec bash \"$@\"", "invalid-argument-fixture", script}, args...)...)
		err := command.Run()
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 2 {
			t.Fatal("invalid arguments did not refuse before discovery", err)
		}
	}
	for _, failure := range []string{"go() { return 23; }", "go() { printf '%s\\n' 'ok fake-package 0.001s'; }", "go() { if [[ \"$*\" == *'-list .'* ]]; then printf '%s\\n' TestA TestB TestC TestD; else return 23; fi; }"} {
		if exec.Command("bash", "-c", failure+"\nexport -f go\nexec bash \"$@\"", "failure-fixture", script, "0").Run() == nil {
			t.Fatal("discovery, empty gate or test failure swallowed")
		}
	}
	for _, weights := range []string{"", "# empty\n", "TestA 0\n", "TestA -1\n", "TestA 01\n", "TestA 1201\n", "TestA abc\n", "TestA 60 extra\n", "TestA 60\nTestA 60\n", "TestStale 60\n"} {
		bad := raceShardScript(t, weights)
		for _, args := range [][]string{{"0"}, {"0", "--list-only"}} {
			if exec.Command("bash", append([]string{"-c", raceShardStub([]string{"TestA", "TestB"}), "bad-weight-fixture", bad}, args...)...).Run() == nil {
				t.Fatal("invalid scheduling metadata accepted", weights)
			}
		}
	}
	if exec.Command("bash", "-c", raceShardStub([]string{"TestA", "TestA"}), "duplicate-discovery-fixture", script, "0", "--list-only").Run() == nil {
		t.Fatal("duplicate compiled name accepted")
	}
	for _, option := range [][]string{nil, {"--list-only"}} {
		args := append([]string{"-c", raceShardStub([]string{"TestA"}), "empty-assignment-fixture", script, "31"}, option...)
		if exec.Command("bash", args...).Run() == nil {
			t.Fatal("empty assignment became passing gate")
		}
	}
}

func TestInstallerRaceShardsReserveFullBudgetTrees(t *testing.T) {
	for _, c := range []struct {
		reserved, ordinary int
		nearBudget         bool
	}{
		{1, 63, false}, {2, 62, false}, {31, 3, false}, {32, 0, false}, {30, 23, true},
	} {
		t.Run(fmt.Sprintf("reserved%d-ordinary%d-near%t", c.reserved, c.ordinary, c.nearBudget), func(t *testing.T) {
			var names []string
			var weights strings.Builder
			want := make([][]string, 32)
			for i := range c.reserved {
				name := fmt.Sprintf("TestReserved%02d", i)
				names = append(names, name)
				fmt.Fprintf(&weights, "%s 1200\n", name)
				want[i] = []string{name}
			}
			if c.nearBudget {
				names = append(names, "TestNearBudget")
				weights.WriteString("TestNearBudget 1199\n")
				want[30] = []string{"TestNearBudget"}
			}
			for i := range c.ordinary {
				name := fmt.Sprintf("TestUnweighted%03d", i)
				names = append(names, name)
				// Equal default costs have a closed-form round-robin partition.
				// With30 reservations,1199 first loads worker30. Twenty60s
				// trees load worker31 to1200; tree20 then returns to worker30.
				worker := c.reserved + i%(32-c.reserved)
				if c.nearBudget {
					worker = 31
					if i == 20 || i == 22 {
						worker = 30
					}
				}
				want[worker] = append(want[worker], name)
			}
			script := raceShardScript(t, weights.String())
			reversed := slices.Clone(names)
			slices.Reverse(reversed)
			var combined []string
			for shard := range 32 {
				for _, discovered := range [][]string{names, reversed} {
					args := []string{"-c", raceShardStub(discovered), "reserved-fixture", script, strconv.Itoa(shard)}
					output, err := exec.Command("bash", append(slices.Clone(args), "--list-only")...).CombinedOutput()
					if err != nil || !slices.Equal(strings.Fields(string(output)), want[shard]) {
						t.Fatalf("reserved partition shard%d: %v %s; want%v", shard, err, output, want[shard])
					}
					output, err = exec.Command("bash", args...).CombinedOutput()
					var pattern []string
					for _, name := range want[shard] {
						pattern = append(pattern, "^"+name+"$")
					}
					if err != nil || !strings.HasSuffix(string(output), "test -race -p 1 -timeout=20m -v ./internal/installengine -run "+strings.Join(pattern, "|")+" -count=1\n") {
						t.Fatalf("reserved execution changed trees or flags: %v %s", err, output)
					}
				}
				combined = append(combined, want[shard]...)
			}
			slices.Sort(names)
			slices.Sort(combined)
			if !slices.Equal(names, combined) {
				t.Fatal("reserved partition omitted or duplicated compiled trees")
			}
		})
	}
	for _, c := range []struct{ reserved, ordinary int }{{32, 1}, {33, 0}} {
		var names []string
		var weights strings.Builder
		for i := range c.reserved {
			name := fmt.Sprintf("TestReserved%02d", i)
			names = append(names, name)
			fmt.Fprintf(&weights, "%s 1200\n", name)
		}
		for i := range c.ordinary {
			names = append(names, fmt.Sprintf("TestUnweighted%03d", i))
		}
		script := raceShardScript(t, weights.String())
		for _, shard := range []string{"0", "31"} {
			for _, option := range [][]string{nil, {"--list-only"}} {
				args := append([]string{"-c", raceShardStub(names), "reservation-overflow", script, shard}, option...)
				output, err := exec.Command("bash", args...).CombinedOutput()
				if err == nil || strings.Contains(string(output), "test -race -p 1 -timeout=") || strings.Contains(string(output), "Selected:") {
					t.Fatalf("reservation overflow launched or omitted trees: %v %s", err, output)
				}
			}
		}
	}
	// An exclusive assignment still propagates the actual race-process failure.
	script := raceShardScript(t, "TestReserved 1200\n")
	failure := `go() {
  if [[ "$*" == *'-list .'* ]]; then printf '%s\n' TestReserved; else return 23; fi
}
export -f go
exec bash "$@"`
	err := exec.Command("bash", "-c", failure, "reserved-failure", script, "0").Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 23 {
		t.Fatal("exclusive race failure swallowed", err)
	}
}
