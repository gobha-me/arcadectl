#!/usr/bin/env bash
# Copyright 2026 gobha-me
# SPDX-License-Identifier: Apache-2.0

# Separate CI workers, not concurrent builds inside the developer pod. Discover
# compiled top-level tests rather than maintaining a prefix allowlist that can
# silently omit new tests. Reviewed weights only guide scheduling: every new
# compiled name still runs. Distribute indivisible trees by descending cost,
# breaking ties by bytewise name and then lowest worker index. Weights are
# estimates, not certified duration bounds; each process retains its 20m budget.
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 || ! $1 =~ ^([0-9]|[12][0-9]|3[01])$ || ${2:-} != "" && ${2:-} != --list-only ]]; then
  echo 'Usage: bash hack/test-installengine-race-shard.sh SHARD [--list-only] (SHARD: 0..31)' >&2
  exit 2
fi
engine_race_shard_index=$1
engine_race_shard_count=32

engine_race_listing=$(go test -race -p 1 -list . ./internal/installengine)
mapfile -t engine_race_tests < <(printf '%s\n' "$engine_race_listing" | awk '/^(Test|Example|Fuzz)[^[:space:]]*$/')
if [[ ${#engine_race_tests[@]} -eq 0 ]]; then
  echo 'No installer engine tests discovered; refusing an empty race gate.' >&2
  exit 1
fi

engine_race_weight_file=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/installengine-race-weights.txt
engine_race_assignment=$(printf '%s\n' "${engine_race_tests[@]}" | awk '
  FILENAME != "-" {
    if ($0 ~ /^[[:space:]]*(#|$)/) next
    if (NF != 2 || $2 !~ /^[1-9][0-9]*$/ || $2 > 1200 || ($1 in weights)) {
      print "Malformed or duplicate installer race weight." > "/dev/stderr"
      failed = 1; exit 1
    }
    weights[$1] = $2; weightCount++; next
  }
  {
    if (NF != 1 || ($1 in discovered)) {
      print "Duplicate or malformed compiled installer test." > "/dev/stderr"
      failed = 1; exit 1
    }
    discovered[$1] = 1
  }
  END {
    if (failed) exit 1
    if (!weightCount) {
      print "Empty installer race weights." > "/dev/stderr"; exit 1
    }
    for (name in weights) if (!(name in discovered)) {
      print "Stale installer race weight: " name > "/dev/stderr"; failed = 1
    }
    if (failed) exit 1
    for (name in discovered) print name, (name in weights ? weights[name] : 60)
  }
' "$engine_race_weight_file" - | LC_ALL=C sort -k2,2nr -k1,1 | awk -v workers="$engine_race_shard_count" -v selected="$engine_race_shard_index" '
  {
    worker = 0
    for (i = 1; i < workers; i++) if (load[i] < load[worker]) worker = i
    load[worker] += $2
    if (worker == selected) print $1
  }
')
mapfile -t engine_race_selected < <(printf '%s\n' "$engine_race_assignment" | awk 'NF')
if [[ ${#engine_race_selected[@]} -eq 0 ]]; then
  echo 'No tests assigned to installer engine shard; review the shard count.' >&2
  exit 1
fi
if [[ ${2:-} == --list-only ]]; then
  printf '%s\n' "${engine_race_selected[@]}"
  exit 0
fi

# Go function names contain no regex syntax. Pin both ends so a name cannot
# select a neighboring top-level test. Its entire subtest tree still runs.
engine_race_pattern=''
for engine_race_name in "${engine_race_selected[@]}"; do
  engine_race_pattern+="${engine_race_pattern:+|}^${engine_race_name}$"
done
printf 'Installer engine race shard %s/%s: %s of %s discovered tests\n' "$engine_race_shard_index" "$engine_race_shard_count" "${#engine_race_selected[@]}" "${#engine_race_tests[@]}"
printf 'Selected: %s\n' "${engine_race_selected[@]}"
go test -race -p 1 -timeout=20m -v ./internal/installengine -run "$engine_race_pattern" -count=1
