// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package install

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestKindJourneyRunnerRefusesAmbientExecutionAndPreservesFailure(t *testing.T) {
	for _, test := range []struct {
		name, ci, argument, childExit string
		wantCode                      int
		wantRun                       bool
	}{
		{"offline-plan", "", "--plan", "0", 0, false},
		{"outside-ci", "", "", "0", 2, false},
		{"false-ci", "false", "", "0", 2, false},
		{"unknown-option", "true", "--cluster=ambient", "0", 2, false},
		{"ci-success", "true", "", "0", 0, true},
		{"ci-failure", "true", "", "42", 42, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			log := filepath.Join(dir, "go.args")
			if err := os.WriteFile(filepath.Join(dir, "go"), []byte("#!/bin/sh\n[ \"${KUBECONFIG+x}\" != x ] || exit 93\nprintf '%s\\n' \"$@\" >\"$JOURNEY_LOG\"\nexit \"$JOURNEY_EXIT\"\n"), 0700); err != nil {
				t.Fatal(err)
			}
			deadlineLog := filepath.Join(dir, "deadline.log")
			deadline := "#!/bin/sh\n[ \"$1\" = --foreground ] && [ \"$2\" = 35m ] || exit 94\nprintf bounded >\"$JOURNEY_DEADLINE_LOG\"\nshift 2\nexec \"$@\"\n"
			if err := os.WriteFile(filepath.Join(dir, "timeout"), []byte(deadline), 0700); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			args := []string{filepath.Join(repositoryRoot(t), "hack", "test-kind-journey.sh")}
			if test.argument != "" {
				args = append(args, test.argument)
			}
			command := exec.CommandContext(ctx, "bash", args...)
			command.Env = append(os.Environ(), "CI="+test.ci, "PATH="+dir+":"+os.Getenv("PATH"), "JOURNEY_LOG="+log, "JOURNEY_EXIT="+test.childExit, "JOURNEY_DEADLINE_LOG="+deadlineLog, "KUBECONFIG=ambient-must-not-be-used")
			output, err := command.CombinedOutput()
			code := 0
			if err != nil {
				exit, ok := err.(*exec.ExitError)
				if !ok {
					t.Fatal(err)
				}
				code = exit.ExitCode()
			}
			if ctx.Err() != nil || code != test.wantCode {
				t.Fatalf("runner exit=%d want=%d: %s", code, test.wantCode, output)
			}
			body, readErr := os.ReadFile(log)
			if !test.wantRun {
				if !os.IsNotExist(readErr) {
					t.Fatal("refused/offline runner launched Go")
				}
				return
			}
			deadlineBody, err := os.ReadFile(deadlineLog)
			if err != nil || string(deadlineBody) != "bounded" {
				t.Fatal("runner lost exact outer deadline")
			}
			want := "test\n-tags=kindapi\n-p\n1\n-timeout=33m\n-v\n./internal/install\n-run\n^TestKindAuthenticatedAdmin$\n-count=1\n"
			if readErr != nil || string(body) != want {
				t.Fatalf("native suite invocation changed: %s error=%v", body, readErr)
			}
			if strings.Contains(string(body), "kubeconfig") || strings.Contains(string(body), "kubectl") {
				t.Fatal("journey runner gained ambient cluster access")
			}
		})
	}
}
