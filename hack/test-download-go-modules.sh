#!/usr/bin/env bash
# Copyright 2026 gobha-me
# SPDX-License-Identifier: Apache-2.0

# Hermetic: only shell builtins and an absolute /bin/sh child. No real Go,
# sleep, temporary files, network or dependency-cache changes are permitted.
set -euo pipefail

readonly helper="${BASH_SOURCE[0]%/*}/download-go-modules.sh"
readonly production_body="$(<"$helper")"

check_case() {
  local name=$1 first=$2 second=$3 third=$4 wait_first=$5 wait_second=$6
  local expected_status=$7 expected_go=$8 expected_sleep=$9 expected_trace=${10}
  local output status line go_calls=0 sleep_calls=0
  if output=$(
    {
      printf '%s\n' 'go_first=$1; go_second=$2; go_third=$3; sleep_first=$4; sleep_second=$5'
      printf '%s\n' 'go_calls=0; sleep_calls=0'
      printf '%s\n' 'go() {'
      printf '%s\n' '  if [ "$#" -ne 2 ] || [ "$1" != mod ] || [ "$2" != download ]; then printf "invalid-go-arguments\n"; return 125; fi'
      printf '%s\n' '  go_calls=$((go_calls + 1))'
      printf '%s\n' '  case "$go_calls" in 1) go_status=$go_first ;; 2) go_status=$go_second ;; 3) go_status=$go_third ;; *) printf "excess-go-call\n"; return 125 ;; esac'
      printf '%s\n' '  printf "go mod download:%s\n" "$go_status"'
      printf '%s\n' '  return "$go_status"'
      printf '%s\n' '}'
      printf '%s\n' 'sleep() {'
      printf '%s\n' '  if [ "$#" -ne 1 ] || [ "$1" != 2 ]; then printf "invalid-sleep-arguments\n"; return 125; fi'
      printf '%s\n' '  sleep_calls=$((sleep_calls + 1))'
      printf '%s\n' '  case "$sleep_calls" in 1) sleep_status=$sleep_first ;; 2) sleep_status=$sleep_second ;; *) printf "excess-sleep-call\n"; return 125 ;; esac'
      printf '%s\n' '  printf "sleep 2:%s\n" "$sleep_status"'
      printf '%s\n' '  return "$sleep_status"'
      printf '%s\n' '}'
      printf '%s\n' "$production_body"
    } | PATH=/dev/null /bin/sh -s -- "$first" "$second" "$third" "$wait_first" "$wait_second"
  ); then
    status=0
  else
    status=$?
  fi
  while IFS= read -r line; do
    case "$line" in
      'go mod download:'*) ((go_calls += 1)) ;;
      'sleep 2:'*) ((sleep_calls += 1)) ;;
      *) printf 'Unexpected dependency-download trace: %s\n' "$name" >&2; return 1 ;;
    esac
  done <<<"$output"
  if [[ $status != "$expected_status" || $go_calls != "$expected_go" || $sleep_calls != "$expected_sleep" || $output != "$expected_trace" ]]; then
    printf 'Dependency-download retry control failed: %s\n' "$name" >&2
    return 1
  fi
}

check_case success-first 0 91 92 93 94 0 1 0 'go mod download:0'
check_case success-second 1 0 92 0 94 0 2 1 $'go mod download:1\nsleep 2:0\ngo mod download:0'
check_case success-third 1 2 0 0 0 0 3 2 $'go mod download:1\nsleep 2:0\ngo mod download:2\nsleep 2:0\ngo mod download:0'
check_case permanent-error 23 24 25 0 0 25 3 2 $'go mod download:23\nsleep 2:0\ngo mod download:24\nsleep 2:0\ngo mod download:25'
check_case go-130 130 0 0 0 0 130 1 0 'go mod download:130'
check_case go-137 1 137 0 0 0 137 2 1 $'go mod download:1\nsleep 2:0\ngo mod download:137'
check_case sleep-130 1 0 0 130 0 130 1 1 $'go mod download:1\nsleep 2:130'
check_case sleep-137 1 2 0 0 137 137 2 2 $'go mod download:1\nsleep 2:0\ngo mod download:2\nsleep 2:137'
check_case sleep-error 1 0 0 7 0 7 1 1 $'go mod download:1\nsleep 2:7'
printf 'Dependency-download retry controls passed (9 scenarios).\n'
