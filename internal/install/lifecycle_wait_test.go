// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package install

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Execute the actual shared helper and both actual call-site blocks, without
// Kubernetes. Missing/Pending claims and read errors must never advance to the
// stopped-server gate; creation and binding share the original single budget.
func TestLifecyclePVCBindingWaitsForCreation(t *testing.T) {
	source := string(recoveryFixtureFile(t, "hack", "test-kind-lifecycle.sh"))
	const helper = `source "$repository_root/hack/world-pvc-wait.sh"`
	if strings.Count(source, helper) != 1 {
		t.Fatal("shared bounded world-binding helper missing or ambiguous")
	}
	for _, seconds := range []int{120, 90} {
		t.Run(fmt.Sprintf("%d-second-path", seconds), func(t *testing.T) {
			marker := fmt.Sprintf(`wait_world_pvc_bound "$claim_name" "$namespace" %d`, seconds)
			start := strings.Index(source, marker)
			if start < 0 || strings.Count(source, marker) != 1 {
				t.Fatal("PVC creation wait missing or ambiguous")
			}
			tail := source[start:]
			lines := strings.SplitN(tail, "\n", 3)
			if len(lines) != 3 {
				t.Fatal("PVC binding wait missing")
			}
			block := strings.Join(lines[:2], "\n")
			want := fmt.Sprintf(`wait_server "$server_name" Stopped RuntimeStopped %d`, seconds)
			if !strings.HasSuffix(strings.TrimSpace(block), want) {
				t.Fatal("original stopped-server wait/deadline changed or not immediately gated by binding")
			}
			for _, scenario := range []struct {
				name, mode, diagnostic string
				calls                  int
				succeeds               bool
			}{
				{"delayed-create-and-bind", "delayed", "", 4, true},
				{"never-created", "absent", "timed out waiting for world PVC creation and binding", seconds, false},
				{"never-bound", "pending", "timed out waiting for world PVC creation and binding", seconds, false},
				{"read-error", "error", "could not observe world PVC binding", 1, false},
			} {
				t.Run(scenario.name, func(t *testing.T) {
					setup := fmt.Sprintf(`namespace=fixture-namespace
claim_name=fixture-world
server_name=fixture-server
unset SECONDS
SECONDS=0
printf '0\n' > "$counter"
sleep() { [[ "$1" == 1 ]] || exit 91; SECONDS=$((SECONDS + 1)); }
kube_bounded() {
  local attempts remaining=$((%d - SECONDS))
  (( remaining <= 30 )) || remaining=30
  [[ $# == 8 && "$1" == "$remaining" && "$2" == get && "$3" == persistentvolumeclaim &&
     "$4" == fixture-world && "$5" == --namespace && "$6" == fixture-namespace &&
     "$7" == --ignore-not-found && "$8" == '--output=jsonpath={.status.phase}' ]] || exit 92
  read -r attempts < "$counter"
  attempts=$((attempts + 1))
  printf '%%s\n' "$attempts" > "$counter"
  case "$mode" in
    delayed) case "$attempts" in 1|2) : ;; 3) printf Pending ;; *) printf Bound ;; esac ;;
    absent) : ;;
    pending) printf Pending ;;
    error) printf 'PRIVATE-READ-CANARY\n' >&2; return 2 ;;
    *) exit 93 ;;
  esac
}
wait_server() {
  [[ "$*" == 'fixture-server Stopped RuntimeStopped %d' ]] || exit 93
  local attempts
  read -r attempts < "$counter"
  (( attempts == 4 )) || exit 94
  printf 'Stopped gate reached\n' >&2
}
`, seconds, seconds)
					counter := filepath.Join(t.TempDir(), "counter")
					ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
					defer cancel()
					command := exec.CommandContext(ctx, "bash", "-ec", setup+helper+"\n"+block)
					command.Env = append(os.Environ(), "repository_root="+repositoryRoot(t), "counter="+counter, "mode="+scenario.mode)
					output, err := command.CombinedOutput()
					if ctx.Err() != nil || (err == nil) != scenario.succeeds || strings.Contains(string(output), "Stopped gate reached") != scenario.succeeds || strings.Contains(string(output), "PRIVATE-READ-CANARY") {
						t.Fatalf("creation/binding ordering: %v, %s", err, output)
					}
					if !scenario.succeeds && !strings.Contains(string(output), scenario.diagnostic) {
						t.Fatalf("read exhaustion did not fail closed: %v, %s", err, output)
					}
					calls, readErr := os.ReadFile(counter)
					if readErr != nil || string(calls) != fmt.Sprintf("%d\n", scenario.calls) {
						t.Fatal("binding wait exceeded its single budget or did not refuse a read error immediately")
					}
				})
			}
		})
	}
}
