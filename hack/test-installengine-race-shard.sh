#!/usr/bin/env bash
# Copyright 2026 gobha-me
# SPDX-License-Identifier: Apache-2.0

# Separate CI workers, not concurrent builds inside the developer pod. Discover
# compiled top-level tests rather than maintaining a prefix allowlist that can
# silently omit new tests. Each name belongs to exactly one round-robin shard.
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 || ! $1 =~ ^[0-7]$ || ${2:-} != "" && ${2:-} != --list-only ]]; then
  echo 'Usage: bash hack/test-installengine-race-shard.sh {0|1|2|3|4|5|6|7} [--list-only]' >&2
  exit 2
fi
engine_race_shard_index=$1
engine_race_shard_count=8

engine_race_listing=$(go test -race -p 1 -list . ./internal/installengine)
mapfile -t engine_race_tests < <(printf '%s\n' "$engine_race_listing" | awk '/^(Test|Example|Fuzz)[^[:space:]]*$/')
if [[ ${#engine_race_tests[@]} -eq 0 ]]; then
  echo 'No installer engine tests discovered; refusing an empty race gate.' >&2
  exit 1
fi

engine_race_selected=()
for engine_race_index in "${!engine_race_tests[@]}"; do
  if (( engine_race_index % engine_race_shard_count == engine_race_shard_index )); then
    engine_race_selected+=("${engine_race_tests[$engine_race_index]}")
  fi
done
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
go test -race -p 1 -timeout=20m ./internal/installengine -run "$engine_race_pattern" -count=1
