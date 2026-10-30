#!/usr/bin/env bash
# Copyright 2026 gobha-me
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
umask 077
readonly repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mode=short
plan=false
if [[ ${1:-} != --plan && $# -gt 0 ]]; then mode=$1; shift; fi
if [[ ${1:-} == --plan ]]; then plan=true; shift; fi
if [[ $# != 0 ]]; then
  echo 'usage: test-kind-soak.sh [short|long|upgrade] [--plan]' >&2
  exit 2
fi
case "$mode" in
  short) rounds=1; bound=25m ;;
  long) rounds=12; bound=25m ;;
  upgrade) rounds=1; bound=345m ;;
  *) echo 'unsupported soak mode' >&2; exit 2 ;;
esac
readonly mode plan rounds bound
if [[ "$plan" == true ]]; then
  printf 'CI only; mode=%s rounds=%s per-round-bound=%s kill-grace=30s; owned disposable clusters only.\n' "$mode" "$rounds" "$bound"
  if [[ "$mode" == upgrade ]]; then
    echo 'go test -tags=kindinstall -p 1 -timeout=340m -v ./internal/installengine -run ^TestKindSignedInstallerBinaryLifecycle$/^kubernetes-1[.]37[.]0$/^transition$ -count=1'
    echo 'Component proof with nonbinding retained claims; no running-world upgrade certification.'
  else
    echo 'bash hack/test-kind-factorio.sh (fresh cluster/world per round, not a continuous-world soak)'
  fi
  exit 0
fi
if [[ ${CI:-} != true ]]; then
  echo 'soak execution requires CI=true on a disposable runner; use --plan offline' >&2
  exit 2
fi
cd "$repository_root"
source_sha="$(git rev-parse HEAD 2>/dev/null)" || { echo 'could not observe source head; refusing soak' >&2; exit 1; }
readonly source_sha
[[ "$source_sha" =~ ^[0-9a-f]{40}$ ]] || { echo 'exact source SHA unavailable' >&2; exit 1; }
assert_source() {
  local head status
  head=$(git rev-parse HEAD 2>/dev/null) || { echo 'could not observe source head; refusing soak' >&2; return 1; }
  status=$(git status --porcelain 2>/dev/null) || { echo 'could not observe source state; refusing soak' >&2; return 1; }
  [[ "$head" == "$source_sha" && -z "$status" ]] || {
    echo 'soak requires the unchanged clean exact source' >&2
    return 1
  }
}
assert_source
readonly artifact_root="$repository_root/artifacts/lifecycle-soak"
[[ ! -L "$repository_root/artifacts" && ! -L "$artifact_root" ]] || { echo 'unsafe evidence directory' >&2; exit 1; }
mkdir -p "$artifact_root"
evidence_root="$(mktemp -d "$artifact_root/run.XXXXXXXX")"
readonly evidence_root
readonly summary="$evidence_root/summary.tsv"
printf 'source_sha\tmode\tround\texit_status\telapsed_seconds\n' > "$summary"
export GOMAXPROCS=2 GOMEMLIMIT=1GiB
unset KUBECONFIG
verify_factorio_evidence() {
  local directory=$1 evidence key expected actual
  local -a files
  mapfile -t files < <(find "$directory" -type f -name evidence.txt)
  [[ ${#files[@]} == 1 ]] || { echo 'exactly one successful Factorio evidence file required' >&2; return 1; }
  evidence=${files[0]}
  for key in candidate_sha source_dirty max_running_factorio_containers; do
    case "$key" in
      candidate_sha) expected=$source_sha ;;
      source_dirty) expected=false ;;
      max_running_factorio_containers) expected=1 ;;
    esac
    actual=$(awk -F= -v key="$key" '$1 == key { count++; value=substr($0,length(key)+2) } END { if(count != 1) exit 1; print value }' "$evidence") || return 1
    [[ "$actual" == "$expected" ]] || { echo 'Factorio evidence identity/overlap mismatch' >&2; return 1; }
  done
}
for ((round=1; round<=rounds; round++)); do
  assert_source
  round_root="$evidence_root/round-$round"
  mkdir "$round_root"
  export ARCADECTL_E2E_ARTIFACT_ROOT="$round_root"
  started=$SECONDS
  status=0
  if [[ "$mode" == upgrade ]]; then
    timeout --foreground --kill-after=30s "$bound" \
      go test -tags=kindinstall -p 1 -timeout=340m -v ./internal/installengine \
      -run '^TestKindSignedInstallerBinaryLifecycle$/^kubernetes-1[.]37[.]0$/^transition$' -count=1 || status=$?
  else
    timeout --foreground --kill-after=30s "$bound" bash "$repository_root/hack/test-kind-factorio.sh" || status=$?
    if [[ "$status" == 0 ]]; then verify_factorio_evidence "$round_root" || status=1; fi
  fi
  if [[ "$status" == 0 ]]; then assert_source || status=1; fi
  printf '%s\t%s\t%s\t%s\t%s\n' "$source_sha" "$mode" "$round" "$status" "$((SECONDS-started))" >> "$summary"
  if [[ "$status" != 0 ]]; then
    printf 'soak refused at round %s; sanitized evidence: %s\n' "$round" "$evidence_root" >&2
    exit "$status"
  fi
  printf 'soak round %s/%s completed; evidence: %s\n' "$round" "$rounds" "$round_root"
done
printf 'soak component sequence completed; evidence: %s\n' "$evidence_root"
