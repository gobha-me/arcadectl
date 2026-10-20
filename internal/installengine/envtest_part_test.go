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

// Exported shell-function stubs exercise the scheduler without a compiler,
// native control plane, downloads, or cluster access.
func envtestPartScript(t *testing.T, weights string) string {
	t.Helper()
	body, err := os.ReadFile("../../hack/test-envtest-part.sh")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "test-envtest-part.sh")
	if os.WriteFile(script, body, 0600) != nil || os.WriteFile(filepath.Join(dir, "installengine-race-weights.txt"), []byte(weights), 0600) != nil {
		t.Fatal("envtest partition fixture unavailable")
	}
	return script
}

func envtestPartQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func envtestPartStub(plain, tagged []string, failure string) string {
	listing := func(names []string) string {
		var quoted []string
		for _, name := range names {
			quoted = append(quoted, envtestPartQuote(name))
		}
		return "printf '%s\\n' " + strings.Join(quoted, " ") + " 'ok fake-package 0.001s'"
	}
	return `go() {
  case "$*" in
    'test -p 1 -list . ./internal/installengine') ` + listing(plain) + ` ;;
    'test -tags=envtest -p 1 -list . ./internal/installengine') ` + listing(tagged) + ` ;;
    *) printf 'RUN %s\n' "$*"
       ` + failure + ` ;;
  esac
}
export -f go
exec bash "$@"`
}

func envtestPartInvoke(script, stub string, args ...string) ([]byte, error) {
	return exec.Command("bash", append([]string{"-c", stub, "envtest-part-fixture", script}, args...)...).CombinedOutput()
}

func envtestPartNames() []string {
	names := []string{"TestReserved", "TestHeavy", "TestÉclair", "TestΓamma", "FuzzCorpus", "ExampleRead", "TestNewOrdinary"}
	for i := range 90 {
		names = append(names, fmt.Sprintf("TestOrdinary%03d", i))
	}
	return names
}

func TestEnvtestPartitionsCompleteCompiledUnion(t *testing.T) {
	plain := envtestPartNames()
	// No naming convention identifies these compiled tagged-only roots.
	tagged := append(slices.Clone(plain), "TestNativeWithoutEnvtestPrefix", "ExampleNative", "FuzzNativeSeed")
	weights := map[string]int{"TestReserved": 1200, "TestHeavy": 900}
	script := envtestPartScript(t, "TestReserved 1200\nTestHeavy 900\n")
	ordered := slices.Clone(tagged)
	isNative := func(name string) bool { return !slices.Contains(plain, name) }
	weight := func(name string) int {
		if value := weights[name]; value != 0 {
			return value
		}
		return 60
	}
	exclusive := func(name string) bool { return isNative(name) || weight(name) == 1200 }
	slices.SortFunc(ordered, func(a, b string) int {
		if exclusive(a) != exclusive(b) {
			if exclusive(a) {
				return -1
			}
			return 1
		}
		if weight(a) != weight(b) {
			return weight(b) - weight(a)
		}
		return strings.Compare(a, b)
	})
	var want [32][]string
	var load [32]int
	reserved := 0
	for _, name := range ordered {
		worker := reserved
		if exclusive(name) {
			reserved++
		} else {
			for i := reserved + 1; i < 32; i++ {
				if load[i] < load[worker] {
					worker = i
				}
			}
			load[worker] += weight(name)
		}
		want[worker] = append(want[worker], name)
	}
	reversedPlain, reversedTagged := slices.Clone(plain), slices.Clone(tagged)
	slices.Reverse(reversedPlain)
	slices.Reverse(reversedTagged)
	var union []string
	for worker := range 32 {
		part := strconv.Itoa(worker)
		for _, stub := range []string{envtestPartStub(plain, tagged, ":"), envtestPartStub(reversedPlain, reversedTagged, ":")} {
			output, err := envtestPartInvoke(script, stub, part, "--list-only")
			if err != nil || !slices.Equal(strings.Fields(string(output)), want[worker]) {
				t.Fatalf("compiled partition worker %d: %v %s", worker, err, output)
			}
		}
		output, err := envtestPartInvoke(script, envtestPartStub(plain, tagged, ":"), part)
		var pattern []string
		for _, name := range want[worker] {
			pattern = append(pattern, "^"+name+"$")
		}
		command := "RUN test -tags=envtest -p 1 -timeout=30m -v ./internal/installengine -run " + strings.Join(pattern, "|") + " -count=1\n"
		if err != nil || !strings.HasSuffix(string(output), command) || strings.Count(string(output), "RUN ") != 1 {
			t.Fatalf("complete bounded tree execution changed: %v %s", err, output)
		}
		if worker < reserved && len(want[worker]) != 1 {
			t.Fatal("native or full-budget tree shared its worker")
		}
		union = append(union, want[worker]...)
	}
	slices.Sort(union)
	slices.Sort(tagged)
	if !slices.Equal(union, tagged) {
		t.Fatal("complete tagged union omitted or duplicated a compiled root")
	}
	// All thirty-two workers may be exclusive when no shared work remains.
	allExclusive := []string{"TestReserved"}
	for i := range 31 {
		allExclusive = append(allExclusive, fmt.Sprintf("TestNativeExclusive%02d", i))
	}
	exclusiveScript := envtestPartScript(t, "TestReserved 1200\n")
	output, err := envtestPartInvoke(exclusiveScript, envtestPartStub([]string{"TestReserved"}, allExclusive, ":"), "--all")
	if err != nil || strings.Count(string(output), "RUN ") != 33 {
		t.Fatalf("complete exclusive partition refused: %v %s", err, output)
	}
}

func TestEnvtestPartitionsRefuseInvalidInputs(t *testing.T) {
	plain := envtestPartNames()
	tagged := append(slices.Clone(plain), "TestNewNative")
	script := envtestPartScript(t, "TestReserved 1200\n")
	for _, args := range [][]string{nil, {"-1"}, {"32"}, {"01"}, {"031"}, {"x"}, {"--all", "--list-only"}, {"base-packages", "--list-only"}, {"0", ""}, {"0", "unknown"}, {"0", "--list-only", "extra"}} {
		output, err := envtestPartInvoke(script, "go() { echo UNEXPECTED; return 93; }; export -f go; exec bash \"$@\"", args...)
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 2 || strings.Contains(string(output), "UNEXPECTED") {
			t.Fatalf("invalid arguments reached discovery: %v %s", err, output)
		}
	}
	for _, weights := range []string{"", "# empty\n", "TestReserved 0\n", "TestReserved 01\n", "TestReserved 1201\n", "TestReserved abc\n", "TestReserved 60 extra\n", "TestReserved 60\nTestReserved 60\n", "TestStale 60\n"} {
		bad := envtestPartScript(t, weights)
		for _, args := range [][]string{{"0"}, {"0", "--list-only"}, {"--all"}} {
			output, err := envtestPartInvoke(bad, envtestPartStub(plain, tagged, ":"), args...)
			if err == nil || strings.Contains(string(output), "RUN ") {
				t.Fatalf("bad weights reached execution: %v %s", err, output)
			}
		}
	}
	for _, c := range []struct{ plain, tagged []string }{
		{nil, tagged}, {plain, nil},
		{plain, slices.Clone(plain)},
		{append(slices.Clone(plain), plain[0]), tagged}, {plain, append(slices.Clone(tagged), tagged[0])},
		{plain, tagged[1:]},
		{plain, append(slices.Clone(tagged), "TestBad/name")},
		{plain, append(slices.Clone(tagged), "TestBad name")},
		{plain, append(slices.Clone(tagged), "TestBad ")},
		{[]string{"TestReserved"}, []string{"TestReserved"}},
		{[]string{"TestReserved"}, []string{"TestReserved", "TestNewNative"}},
	} {
		for _, args := range [][]string{{"0"}, {"31", "--list-only"}, {"--all"}} {
			output, err := envtestPartInvoke(script, envtestPartStub(c.plain, c.tagged, ":"), args...)
			if err == nil || strings.Contains(string(output), "RUN ") {
				t.Fatalf("invalid compiled union reached execution: %v %s", err, output)
			}
		}
	}
	for _, discovery := range []string{
		"go() { return 23; }",
		"go() { if [[ \"$*\" == 'test -tags=envtest -p 1 -list . ./internal/installengine' ]]; then return 23; else printf '%s\\n' TestReserved; fi; }",
	} {
		output, err := envtestPartInvoke(script, discovery+"; export -f go; exec bash \"$@\"", "--all")
		if err == nil || strings.Contains(string(output), "RUN ") {
			t.Fatal("discovery failure swallowed")
		}
	}
	for _, ordinary := range []int{0, 1} {
		var natives []string
		for i := range 32 - ordinary {
			natives = append(natives, fmt.Sprintf("TestNative%02d", i))
		}
		// The reserved ordinary root adds one more exclusive assignment.
		tooMany := append([]string{"TestReserved"}, natives...)
		if ordinary == 1 {
			tooMany = append(tooMany, "TestShared")
		}
		p := []string{"TestReserved"}
		if ordinary == 1 {
			p = append(p, "TestShared")
		}
		output, err := envtestPartInvoke(script, envtestPartStub(p, tooMany, ":"), "--all")
		if err == nil || strings.Contains(string(output), "RUN ") {
			t.Fatal("exclusive overflow or missing shared capacity accepted")
		}
	}
}

func TestEnvtestPartitionsAllPartsAndFailures(t *testing.T) {
	plain := envtestPartNames()
	tagged := append(slices.Clone(plain), "TestNewNative")
	script := envtestPartScript(t, "TestReserved 1200\n")
	base := "RUN test -tags=envtest -p 1 -timeout=30m -count=1 ./api/v1alpha1 ./internal/controller ./internal/install ./internal/installcontract\n"
	output, err := envtestPartInvoke(script, "go() { printf 'RUN %s\\n' \"$*\"; }; export -f go; exec bash \"$@\"", "base-packages")
	if err != nil || string(output) != base {
		t.Fatalf("base packages changed or performed discovery: %v %s", err, output)
	}
	for _, failure := range []string{":", "return 23", "if [[ \"$*\" == *'./internal/installengine -run '* ]]; then return 23; fi", "if [[ \"$*\" == *'./api/v1alpha1 '* ]]; then return 24; fi"} {
		stub := strings.ReplaceAll(envtestPartStub(plain, tagged, failure), "printf '%s\\n' ", "printf 'DISCOVERY\\n' >&2; printf '%s\\n' ")
		output, err = envtestPartInvoke(script, stub, "--all")
		text := string(output)
		if (err == nil) != (failure == ":") || strings.Count(text, "RUN ") != 33 || strings.Count(text, "DISCOVERY\n") != 2 || !strings.HasPrefix(strings.TrimPrefix(text, "DISCOVERY\nDISCOVERY\n"), base) {
			t.Fatalf("all-parts failure changed complete attempted coverage: %v %s", err, output)
		}
		for worker := range 32 {
			if strings.Count(string(output), fmt.Sprintf("Envtest engine part %d/32:", worker)) != 1 {
				t.Fatal("all-parts mode omitted or repeated an engine worker")
			}
		}
	}
	output, err = envtestPartInvoke(script, envtestPartStub(plain, tagged, "return 23"), "0")
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 23 || strings.Count(string(output), "RUN ") != 1 {
		t.Fatal("individual engine execution failure swallowed")
	}
	output, err = envtestPartInvoke(script, envtestPartStub(plain, tagged, "return 24"), "base-packages")
	if !errors.As(err, &exit) || exit.ExitCode() != 24 || string(output) != base {
		t.Fatal("base package execution failure swallowed")
	}
}
