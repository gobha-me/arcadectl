// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package install

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestKindSoakRunnerBoundariesAndEvidence(t *testing.T) {
	for _, test := range []struct {
		name, ci, childExit, evidence string
		args                          []string
		dirty                         bool
		wantCode, wantRounds          int
	}{
		{name: "offline-plan", args: []string{"--plan"}},
		{name: "long-plan", args: []string{"long", "--plan"}},
		{name: "upgrade-plan", args: []string{"upgrade", "--plan"}},
		{name: "outside-ci", wantCode: 2},
		{name: "false-ci", ci: "false", wantCode: 2},
		{name: "unknown-mode", ci: "true", args: []string{"ambient"}, wantCode: 2},
		{name: "cluster-argument", ci: "true", args: []string{"short", "--kubeconfig=ambient"}, wantCode: 2},
		{name: "symlink-artifacts", ci: "true", wantCode: 1},
		{name: "status-unavailable", ci: "true", wantCode: 1},
		{name: "dirty-source", ci: "true", dirty: true, wantCode: 1},
		{name: "short", ci: "true", evidence: "valid", wantRounds: 1},
		{name: "long", ci: "true", args: []string{"long"}, evidence: "valid", wantRounds: 12},
		{name: "upgrade", ci: "true", args: []string{"upgrade"}, wantRounds: 1},
		{name: "changed-source", ci: "true", evidence: "valid", wantCode: 1, wantRounds: 1},
		{name: "child-timeout", ci: "true", childExit: "124", wantCode: 124, wantRounds: 1},
		{name: "child-failed", ci: "true", childExit: "43", wantCode: 43, wantRounds: 1},
		{name: "missing-evidence", ci: "true", evidence: "missing", wantCode: 1, wantRounds: 1},
		{name: "source-mismatch", ci: "true", evidence: "wrong-source", wantCode: 1, wantRounds: 1},
		{name: "dirty-evidence", ci: "true", evidence: "dirty", wantCode: 1, wantRounds: 1},
		{name: "observed-overlap", ci: "true", evidence: "overlap", wantCode: 1, wantRounds: 1},
		{name: "duplicate-key", ci: "true", evidence: "duplicate", wantCode: 1, wantRounds: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			hack := filepath.Join(root, "hack")
			bin := filepath.Join(root, "bin")
			for _, directory := range []string{hack, bin} {
				if err := os.Mkdir(directory, 0700); err != nil {
					t.Fatal(err)
				}
			}
			write := func(path, body string) {
				t.Helper()
				if err := os.WriteFile(path, []byte(body), 0700); err != nil {
					t.Fatal(err)
				}
			}
			runner, err := os.ReadFile(filepath.Join(repositoryRoot(t), "hack", "test-kind-soak.sh"))
			if err != nil {
				t.Fatal(err)
			}
			write(filepath.Join(hack, "test-kind-soak.sh"), string(runner))
			// Subprocess boundaries are fixtures; the actual runner bytes above are
			// exercised unchanged. No Go test, Docker daemon or Kubernetes is started.
			write(filepath.Join(bin, "git"), `#!/bin/sh
case "$1" in
 rev-parse)
 count=0
 if [ -f "$SOAK_GIT_READS" ]; then read -r count < "$SOAK_GIT_READS"; fi
 count=$((count + 1))
 printf '%s\n' "$count" > "$SOAK_GIT_READS"
 if [ "$SOAK_CHANGE" = true ] && [ "$count" -ge 4 ]; then printf '%040d\n' 2; else printf '%040d\n' 1; fi ;;
 status) [ "$SOAK_STATUS_FAIL" != true ] || exit 47; if [ "$SOAK_DIRTY" = true ]; then echo ' M source.go'; fi ;;
 *) exit 91 ;;
esac
`)
			write(filepath.Join(bin, "timeout"), `#!/bin/sh
[ "$1" = --foreground ] && [ "$2" = --kill-after=30s ] && [ "$3" = "$SOAK_BOUND" ] || exit 92
printf 'bounded\n' >> "$SOAK_TIMEOUT_LOG"
shift 3
exec "$@"
`)
			write(filepath.Join(bin, "go"), `#!/bin/sh
[ "${KUBECONFIG+x}" != x ] || exit 93
printf '%s\n' "$*" >> "$SOAK_LOG"
exit "${SOAK_EXIT:-0}"
`)
			write(filepath.Join(hack, "test-kind-factorio.sh"), `#!/usr/bin/env bash
set -eu
[[ ${KUBECONFIG+x} != x ]] || exit 93
printf 'factorio\n' >> "$SOAK_LOG"
[[ ${SOAK_EXIT:-0} == 0 ]] || exit "$SOAK_EXIT"
[[ $SOAK_EVIDENCE != missing ]] || exit 0
mkdir "$ARCADECTL_E2E_ARTIFACT_ROOT/fixture"
sha=0000000000000000000000000000000000000001
[[ $SOAK_EVIDENCE != wrong-source ]] || sha=0000000000000000000000000000000000000002
dirty=false
[[ $SOAK_EVIDENCE != dirty ]] || dirty=true
overlap=1
[[ $SOAK_EVIDENCE != overlap ]] || overlap=2
{
 printf 'candidate_sha=%s\nsource_dirty=%s\nmax_running_factorio_containers=%s\n' "$sha" "$dirty" "$overlap"
 if [[ $SOAK_EVIDENCE == duplicate ]]; then printf 'source_dirty=false\n'; fi
} > "$ARCADECTL_E2E_ARTIFACT_ROOT/fixture/evidence.txt"
`)
			if test.name == "symlink-artifacts" {
				if err := os.Symlink(bin, filepath.Join(root, "artifacts")); err != nil {
					t.Fatal(err)
				}
			}
			log := filepath.Join(root, "children.log")
			bound := "25m"
			if test.name == "upgrade" {
				bound = "345m"
			}
			timeoutLog := filepath.Join(root, "timeouts.log")
			code := test.childExit
			if code == "" {
				code = "0"
			}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "bash", append([]string{filepath.Join(hack, "test-kind-soak.sh")}, test.args...)...)
			cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "CI="+test.ci, "SOAK_LOG="+log, "SOAK_EXIT="+code, "SOAK_EVIDENCE="+test.evidence, "SOAK_DIRTY="+strconv.FormatBool(test.dirty), "KUBECONFIG=ambient-must-not-be-used", "SOAK_BOUND="+bound, "SOAK_TIMEOUT_LOG="+timeoutLog, "SOAK_CHANGE="+strconv.FormatBool(test.name == "changed-source"), "SOAK_GIT_READS="+filepath.Join(root, "git-reads"), "SOAK_STATUS_FAIL="+strconv.FormatBool(test.name == "status-unavailable"))
			output, err := cmd.CombinedOutput()
			got := 0
			if err != nil {
				var exit *exec.ExitError
				if !errors.As(err, &exit) {
					t.Fatal(err)
				}
				got = exit.ExitCode()
			}
			if ctx.Err() != nil || got != test.wantCode {
				t.Fatalf("exit=%d want=%d: %s", got, test.wantCode, output)
			}
			if test.name == "status-unavailable" && !strings.Contains(string(output), "could not observe source state; refusing soak") {
				t.Fatal("unavailable source lacked fixed refusal guidance")
			}
			if test.wantRounds > 0 && test.wantCode != 0 && !strings.Contains(string(output), "sanitized evidence:") {
				t.Fatal("failed round omitted evidence guidance")
			}
			body, readErr := os.ReadFile(log)
			if test.wantRounds == 0 {
				if !os.IsNotExist(readErr) {
					t.Fatal("refused/offline runner started a child")
				}
				return
			}
			if readErr != nil || strings.Count(string(body), "\n") != test.wantRounds {
				t.Fatalf("child count: %q %v", body, readErr)
			}
			timeouts, err := os.ReadFile(timeoutLog)
			if err != nil || strings.Count(string(timeouts), "\n") != test.wantRounds {
				t.Fatal("child lacked exact outer deadline")
			}
			if test.name == "upgrade" && string(body) != "test -tags=kindinstall -p 1 -timeout=340m -v ./internal/installengine -run ^TestKindSignedInstallerBinaryLifecycle$/^kubernetes-1[.]37[.]0$/^transition$ -count=1\n" {
				t.Fatalf("upgrade target changed: %s", body)
			}
			summaries, err := filepath.Glob(filepath.Join(root, "artifacts", "lifecycle-soak", "run.*", "summary.tsv"))
			if err != nil || len(summaries) != 1 {
				t.Fatal("missing unique summary")
			}
			summary, err := os.ReadFile(summaries[0])
			if err != nil || strings.Count(string(summary), "\n") != test.wantRounds+1 {
				t.Fatalf("incomplete summary: %s %v", summary, err)
			}
			rows := strings.Split(strings.TrimSpace(string(summary)), "\n")
			fields := strings.Split(rows[len(rows)-1], "\t")
			if len(fields) != 5 || fields[3] != strconv.Itoa(test.wantCode) {
				t.Fatalf("summary lost child/verification result: %s", summary)
			}
		})
	}
}
