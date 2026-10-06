// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package install

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Execute the actual helper and both actual call-site blocks, without Kubernetes
// or a cluster. A named kubectl wait fails on an initial 404; creation must be
// observed first, and an exhausted/erroring read must never reach the Bound gate.
func TestLifecyclePVCBindingWaitsForCreation(t *testing.T) {
	source := string(recoveryFixtureFile(t, "hack", "test-kind-lifecycle.sh"))
	begin := strings.Index(source, "wait_present() {")
	end := strings.Index(source, "\nwait_pod_phase() {")
	if begin < 0 || end <= begin {
		t.Fatal("bounded presence helper missing")
	}
	helper := source[begin:end]
	for _, seconds := range []int{120, 90} {
		t.Run(fmt.Sprintf("%d-second-path", seconds), func(t *testing.T) {
			marker := fmt.Sprintf(`wait_present persistentvolumeclaim "$claim_name" %d`, seconds)
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
			want := fmt.Sprintf(`kube_bounded %d wait persistentvolumeclaim/"$claim_name" --namespace "$namespace" --for=jsonpath='{.status.phase}'=Bound --timeout=%ds >/dev/null`, seconds+10, seconds)
			if !strings.HasSuffix(strings.TrimSpace(block), want) {
				t.Fatal("original Bound wait/deadline changed or not immediately gated")
			}
			for _, scenario := range []struct {
				name               string
				presentAfter, code int
				succeeds           bool
			}{
				{"delayed-create", 4, 1, true},
				{"never-created", seconds + 1, 1, false},
				{"read-error", seconds + 1, 2, false},
			} {
				t.Run(scenario.name, func(t *testing.T) {
					setup := fmt.Sprintf(`namespace=fixture-namespace
claim_name=fixture-world
attempts=0
sleep() { [[ "$1" == 1 ]] || exit 91; SECONDS=$((SECONDS + 1)); }
kube() {
  [[ "$*" == 'get persistentvolumeclaim fixture-world --namespace fixture-namespace' ]] || exit 92
  attempts=$((attempts + 1))
  (( attempts >= %d )) && return 0
  return %d
}
kube_bounded() {
  [[ "$*" == '%d wait persistentvolumeclaim/fixture-world --namespace fixture-namespace --for=jsonpath={.status.phase}=Bound --timeout=%ds' ]] || exit 93
  (( attempts == 4 )) || exit 94
  printf 'Bound gate reached\n' >&2
}
`, scenario.presentAfter, scenario.code, seconds+10, seconds)
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					command := exec.CommandContext(ctx, "bash", "-ec", setup+helper+"\n"+block)
					output, err := command.CombinedOutput()
					if (err == nil) != scenario.succeeds || strings.Contains(string(output), "Bound gate reached") != scenario.succeeds {
						t.Fatalf("creation/binding ordering: %v, %s", err, output)
					}
					if !scenario.succeeds && !strings.Contains(string(output), "timed out waiting for persistentvolumeclaim/fixture-world to exist") {
						t.Fatalf("read exhaustion did not fail closed: %v, %s", err, output)
					}
				})
			}
		})
	}
}
