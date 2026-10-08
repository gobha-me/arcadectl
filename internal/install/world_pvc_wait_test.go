// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package install

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWorldPVCWaitCoversCreationAndBindingInOneDeadline(t *testing.T) {
	// Exercise the actual sourced helper without kubectl or a cluster. Advance
	// a mock clock in the parent sleep, not the command-substitution child.
	// Only late-bound uses Bash's real elapsed clock.
	const script = `set -euo pipefail
source "$repository_root/hack/world-pvc-wait.sh"
# Unsetting removes SECONDS' special elapsed-time behavior. Otherwise a real
# wall-clock tick can race with our mock sleep even in a millisecond fixture.
if [[ "$mode" != late-bound ]]; then unset SECONDS; fi
SECONDS=0
printf '0\n' > "$counter"
: > "$trace"
# Deterministically tick between the loop condition and budget calculation.
# DEBUG inheritance lets this exercise the real helper without changing it.
if [[ "$mode" == rollover ]]; then
  set -T
  trap 'if [[ "$BASH_COMMAND" == "remaining=\$((deadline - SECONDS))" ]]; then SECONDS=$budget; fi' DEBUG
fi
sleep() { [[ "$1" == 1 ]] || exit 8; SECONDS=$((SECONDS + 1)); }
kube_bounded() {
  local calls
  read -r calls < "$counter"
  printf '%s\n' "$((calls + 1))" > "$counter"
  printf '%s\n' "$1" >> "$trace"
  if [[ "$mode" == legacy ]]; then
    [[ "$2" == wait ]] || exit 8
    printf 'Error from server (NotFound): persistentvolumeclaims "world" not found\n' >&2
    return 1
  fi
  [[ $# == 8 && "$2" == get && "$3" == persistentvolumeclaim && "$4" == world &&
    "$5" == --namespace && "$6" == isolated-test && "$7" == --ignore-not-found &&
    "$8" == '--output=jsonpath={.status.phase}' ]] || exit 8
  case "$mode" in
    delayed) case "$calls" in 0) : ;; 1) printf Pending ;; *) printf Bound ;; esac ;;
    disappears) case "$calls" in 0) printf Pending ;; 1) : ;; *) printf Bound ;; esac ;;
    absent) : ;;
    pending) printf Pending ;;
    malformed) printf 'Bound\nPending' ;;
    bound|capped) printf Bound ;;
    late-bound) command sleep 1; printf Bound ;;
    forbidden|transport|timeout)
      printf 'PRIVATE-ERROR-CANARY\n' >&2
      case "$mode" in forbidden) return 1 ;; transport) return 7 ;; timeout) return 124 ;; esac ;;
    pending-then-forbidden)
      if (( calls == 0 )); then printf Pending; else printf 'PRIVATE-ERROR-CANARY\n' >&2; return 1; fi ;;
    *) exit 8 ;;
  esac
}
if [[ "$mode" == legacy ]]; then
  kube_bounded 130 wait pvc/world --namespace isolated-test --for=jsonpath='{.status.phase}'=Bound --timeout=120s
else
  wait_world_pvc_bound world isolated-test "$budget"
fi
`
	for _, fixture := range []struct {
		mode, budget, trace, diagnostic string
		success                         bool
	}{
		{"legacy", "3", "130\n", "NotFound", false},
		{"delayed", "3", "3\n2\n1\n", "", true},
		{"disappears", "3", "3\n2\n1\n", "", true},
		{"bound", "3", "3\n", "", true},
		{"capped", "35", "30\n", "", true},
		{"absent", "3", "3\n2\n1\n", "timed out", false},
		{"pending", "3", "3\n2\n1\n", "timed out", false},
		{"malformed", "3", "3\n2\n1\n", "timed out", false},
		{"late-bound", "1", "1\n", "timed out", false},
		{"rollover", "3", "", "timed out", false},
		{"forbidden", "3", "3\n", "could not observe", false},
		{"transport", "3", "3\n", "could not observe", false},
		{"timeout", "3", "3\n", "could not observe", false},
		{"pending-then-forbidden", "3", "3\n2\n", "could not observe", false},
	} {
		t.Run(fixture.mode, func(t *testing.T) {
			dir := t.TempDir()
			trace := filepath.Join(dir, "trace")
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, "bash", "-ec", script)
			command.Env = append(os.Environ(), "repository_root="+repositoryRoot(t), "mode="+fixture.mode,
				"budget="+fixture.budget, "counter="+filepath.Join(dir, "counter"), "trace="+trace)
			output, err := command.CombinedOutput()
			if ctx.Err() != nil || (err == nil) != fixture.success || strings.Contains(string(output), "PRIVATE-ERROR-CANARY") {
				t.Fatal("PVC wait result or private-output boundary changed")
			}
			if !fixture.success {
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ExitCode() != 1 || !strings.Contains(string(output), fixture.diagnostic) {
					t.Fatal("negative fixture failed outside its intended refusal branch")
				}
			} else if len(output) != 0 {
				t.Fatal("successful wait unexpectedly emitted output")
			}
			calls, err := os.ReadFile(trace)
			if err != nil || string(calls) != fixture.trace {
				t.Fatalf("wait did not preserve one deadline and immediate error refusal: %q, %v", calls, err)
			}
		})
	}
}

func TestControllerCreatedWorldPVCWaitSitesUseBoundedHelper(t *testing.T) {
	lifecycle := string(recoveryFixtureFile(t, "hack", "test-kind-lifecycle.sh"))
	recovery := string(recoveryFixtureFile(t, "hack", "kind-recovery-scenarios.sh"))
	if !strings.Contains(lifecycle, `source "$repository_root/hack/world-pvc-wait.sh"`) ||
		strings.Count(lifecycle, `wait_world_pvc_bound "$claim_name" "$namespace" 120`) != 1 ||
		strings.Count(lifecycle, `wait_world_pvc_bound "$claim_name" "$namespace" 90`) != 1 ||
		strings.Count(lifecycle, `wait_world_pvc_bound "$destroy_claim_name" "$namespace" 90`) != 1 ||
		strings.Count(recovery, `wait_world_pvc_bound "$claim_name" "$namespace" 120`) != 1 {
		t.Fatal("controller-created world claim waits lost the shared helper or original budgets")
	}
	for _, contents := range []string{lifecycle, recovery} {
		for _, oldWait := range []string{`wait persistentvolumeclaim/"$claim_name"`, `wait pvc/"$claim_name"`, `wait persistentvolumeclaim/"$destroy_claim_name"`} {
			if strings.Contains(contents, oldWait) {
				t.Fatal("controller-created claim still has an immediate named wait")
			}
		}
	}
}
