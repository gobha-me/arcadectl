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

func TestRecoveryOptionalEndpointRaceIsOwnedAndSingleSend(t *testing.T) {
	// No API server or real kubectl: exercise the actual sourced helper with a
	// deterministic deletion/replacement between its original GET and PATCH.
	const script = `set -euo pipefail
source "$repository_root/hack/kind-recovery-scenarios.sh"
namespace=isolated-test
server_name=lifecycle
mock_original_uid=10000000-0000-4000-8000-000000000001
mock_server_uid=20000000-0000-4000-8000-000000000001
mock_replacement_uid=30000000-0000-4000-8000-000000000001
case "$mode" in
  *-uid-dashes) mock_bad_uid=------------------------------------ ;;
  *-uid-no-separators) mock_bad_uid=300000000000400080000000000000000001 ;;
  *-uid-wrong-placement) mock_bad_uid=3000000-00000-4000-8000-000000000001 ;;
  *-uid-nil) mock_bad_uid=00000000-0000-0000-0000-000000000000 ;;
esac
case "$mode" in
  initial-uid-*) mock_original_uid=$mock_bad_uid ;;
  server-uid-*) mock_server_uid=$mock_bad_uid ;;
  replacement-uid-*) mock_replacement_uid=$mock_bad_uid ;;
esac
printf '0\n' > "$counter"
die() { printf '%s\n' "$*" >&2; exit 9; }
service() {
  jq -cn --arg uid "$1" --arg owner "$2" '{apiVersion:"v1",kind:"Service",
    metadata:{name:"lifecycle",namespace:"isolated-test",uid:$uid,ownerReferences:[
      {apiVersion:"arcade.gobha.me/v1alpha1",kind:"GameServer",name:"lifecycle",uid:$owner,controller:true}]},
    spec:{type:"LoadBalancer",clusterIP:"10.0.0.4"}}'
}
kube() {
  printf '%s/%s\n' "$1" "$2" >> "$trace"
  case "$1/$2" in
    get/service)
      local reads
      read -r reads < "$counter"
      printf '%s\n' "$((reads+1))" > "$counter"
      if (( reads == 0 )); then
        case "$mode" in
          initially-absent) return 0 ;;
          initial-get-error) return 1 ;;
          initial-foreign) service "$mock_original_uid" "$mock_replacement_uid" ;;
          *) service "$mock_original_uid" "$mock_server_uid" ;;
        esac
      else
        case "$mode" in
          absent) return 0 ;;
          replacement|replacement-uid-*) service "$mock_replacement_uid" "$mock_server_uid" ;;
          foreign) service "$mock_replacement_uid" "$mock_replacement_uid" ;;
          malformed) printf '{}\n' ;;
          wrong-name) service "$mock_replacement_uid" "$mock_server_uid" | jq '.metadata.name="foreign"' ;;
          wrong-namespace) service "$mock_replacement_uid" "$mock_server_uid" | jq '.metadata.namespace="foreign"' ;;
          wrong-api) service "$mock_replacement_uid" "$mock_server_uid" | jq '.apiVersion="foreign/v1"' ;;
          wrong-kind) service "$mock_replacement_uid" "$mock_server_uid" | jq '.kind="Foreign"' ;;
          wrong-type) service "$mock_replacement_uid" "$mock_server_uid" | jq '.spec.type="NodePort"' ;;
          wrong-address) service "$mock_replacement_uid" "$mock_server_uid" | jq '.spec.clusterIP="foreign"' ;;
          wrong-owner-api) service "$mock_replacement_uid" "$mock_server_uid" | jq '.metadata.ownerReferences[0].apiVersion="foreign/v1"' ;;
          extra-controller) service "$mock_replacement_uid" "$mock_server_uid" | jq '.metadata.ownerReferences += [.metadata.ownerReferences[0]]' ;;
          missing-owner) service "$mock_replacement_uid" "$mock_server_uid" | jq 'del(.metadata.ownerReferences)' ;;
          get-error) return 1 ;;
          *) service "$mock_original_uid" "$mock_server_uid" ;;
        esac
      fi ;;
    get/gameserver) printf '%s' "$mock_server_uid" ;;
    patch/service)
      local patch=''
      while (( $# > 0 )); do
        if [[ "$1" == --patch ]]; then patch=$2; break; fi
        shift
      done
      jq -e --arg uid "$mock_original_uid" 'length == 2 and
        .[0] == {op:"test",path:"/metadata/uid",value:$uid} and
        .[1] == {op:"add",path:"/status/loadBalancer",value:{ingress:[{ip:"10.0.0.4"}]}}' <<< "$patch" >/dev/null || exit 8
      [[ "$mode" == success ]] && return 0
      printf 'PRIVATE-ERROR-CANARY\n' >&2
      return 1 ;;
    *) exit 7 ;;
  esac
}
if [[ "$legacy" == 1 ]]; then
  # Original GET->UID-guarded PATCH control: deletion/recreation fails under
  # errexit. This independently reproduces the precise pre-fix boundary.
  observed=$(kube get service "$server_name" --namespace "$namespace" --ignore-not-found --output=json)
  kube patch service "$server_name" --namespace "$namespace" --subresource=status --type=json \
    --patch "$(jq -cn --arg uid "$(jq -r '.metadata.uid' <<< "$observed")" '
      [{op:"test",path:"/metadata/uid",value:$uid},
       {op:"add",path:"/status/loadBalancer",value:{ingress:[{ip:"10.0.0.4"}]}}]')" >/dev/null 2>&1
else
  recovery_publish_player_endpoint_if_present
fi
`
	for _, fixture := range []struct {
		mode    string
		legacy  bool
		success bool
		patches int
		reads   int
	}{
		{"absent", true, false, 1, 1},
		{"replacement", true, false, 1, 1},
		{"success", false, true, 1, 1},
		{"absent", false, true, 1, 2},
		{"replacement", false, true, 1, 2},
		{"initially-absent", false, true, 0, 1},
		{"initial-get-error", false, false, 0, 1},
		{"initial-foreign", false, false, 0, 1},
		{"same-original", false, false, 1, 2},
		{"foreign", false, false, 1, 2},
		{"malformed", false, false, 1, 2},
		{"wrong-name", false, false, 1, 2},
		{"wrong-namespace", false, false, 1, 2},
		{"wrong-api", false, false, 1, 2},
		{"wrong-kind", false, false, 1, 2},
		{"wrong-type", false, false, 1, 2},
		{"wrong-address", false, false, 1, 2},
		{"wrong-owner-api", false, false, 1, 2},
		{"extra-controller", false, false, 1, 2},
		{"missing-owner", false, false, 1, 2},
		{"get-error", false, false, 1, 2},
		{"initial-uid-dashes", false, false, 0, 1},
		{"initial-uid-no-separators", false, false, 0, 1},
		{"initial-uid-wrong-placement", false, false, 0, 1},
		{"initial-uid-nil", false, false, 0, 1},
		{"server-uid-dashes", false, false, 0, 1},
		{"server-uid-no-separators", false, false, 0, 1},
		{"server-uid-wrong-placement", false, false, 0, 1},
		{"server-uid-nil", false, false, 0, 1},
		{"replacement-uid-dashes", false, false, 1, 2},
		{"replacement-uid-no-separators", false, false, 1, 2},
		{"replacement-uid-wrong-placement", false, false, 1, 2},
		{"replacement-uid-nil", false, false, 1, 2},
	} {
		name := fixture.mode
		if fixture.legacy {
			name += "-legacy"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			trace := filepath.Join(dir, "trace")
			legacy := "0"
			if fixture.legacy {
				legacy = "1"
			}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, "bash", "-ec", script)
			command.Env = append(os.Environ(), "repository_root="+repositoryRoot(t), "mode="+fixture.mode,
				"legacy="+legacy, "counter="+filepath.Join(dir, "counter"), "trace="+trace)
			output, err := command.CombinedOutput()
			if ctx.Err() != nil || (err == nil) != fixture.success || strings.Contains(string(output), "PRIVATE-ERROR-CANARY") {
				t.Fatal("endpoint race outcome or private-output boundary changed")
			}
			if !fixture.success {
				var exit *exec.ExitError
				wantExit := 9 // Only the intentional fail-closed die, not mock/timeout errors.
				if fixture.legacy {
					wantExit = 1
				}
				if !errors.As(err, &exit) || exit.ExitCode() != wantExit {
					t.Fatal("negative fixture failed outside its intended refusal branch")
				}
			}
			calls, err := os.ReadFile(trace)
			gameserverReads := 1
			if fixture.legacy || fixture.mode == "initially-absent" || fixture.mode == "initial-get-error" || strings.HasPrefix(fixture.mode, "initial-uid-") {
				gameserverReads = 0
			}
			if err != nil || strings.Count(string(calls), "patch/service\n") != fixture.patches || strings.Count(string(calls), "get/service\n") != fixture.reads || strings.Count(string(calls), "get/gameserver\n") != gameserverReads {
				t.Fatal("endpoint helper replayed or skipped its fixed UID-guarded send")
			}
		})
	}
}
