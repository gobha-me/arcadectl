#!/usr/bin/env bash
# Copyright 2026 gobha-me
# SPDX-License-Identifier: Apache-2.0

# Separate hosted workers retain the complete tagged suite, not a name-prefix
# allowlist. Tagged-only trees and full-budget ordinary trees own whole workers.
# Weights schedule ordinary trees only; every new compiled name is included.
set -euo pipefail

usage() {
  echo 'Usage: bash hack/test-envtest-part.sh {base-packages|0..31|--all} [--list-only (engine only)]' >&2
  exit 2
}
[[ $# -ge 1 && $# -le 2 ]] || usage
envtest_part=$1
case "$envtest_part" in
  base-packages|--all) [[ $# -eq 1 ]] || usage ;;
  *) [[ "$envtest_part" =~ ^([0-9]|[12][0-9]|3[01])$ ]] || usage
     [[ $# -eq 1 || $2 == --list-only ]] || usage ;;
esac

run_base() {
  go test -tags=envtest -p 1 -timeout=30m -count=1 ./api/v1alpha1 ./internal/controller ./internal/install ./internal/installcontract
}
if [[ $envtest_part == base-packages ]]; then
  run_base
  exit 0
fi

# Reject malformed/duplicate apparent roots rather than silently filtering them.
# UTF-8 Go identifiers remain intact; ASCII regex/shell punctuation is forbidden.
compiled_roots() {
  awk '
    /^(Test|Example|Fuzz)/ {
      if (NF != 1 || $0 ~ /[[:space:][:cntrl:]]/ || ($0 in seen)) {
        print "Malformed or duplicate compiled envtest root." > "/dev/stderr"; failed=1; exit 1
      }
      punctuation="`~!@#$%^&*()-=+[{]}\\|;:\047\",<.>/?"
      for (i=1; i<=length($0); i++) if (index(punctuation, substr($0,i,1))) {
        print "Unsafe compiled envtest root." > "/dev/stderr"; failed=1; exit 1
      }
      seen[$0]=1; count++; print
    }
    END { if (failed) exit 1; if (!count) { print "Empty compiled envtest census." > "/dev/stderr"; exit 1 } }
  '
}
envtest_plain_listing=$(go test -p 1 -list . ./internal/installengine)
envtest_tagged_listing=$(go test -tags=envtest -p 1 -list . ./internal/installengine)
envtest_plain_roots=$(printf '%s\n' "$envtest_plain_listing" | compiled_roots)
envtest_tagged_roots=$(printf '%s\n' "$envtest_tagged_listing" | compiled_roots)
mapfile -t envtest_plain_names <<< "$envtest_plain_roots"
mapfile -t envtest_tagged_names <<< "$envtest_tagged_roots"
envtest_weights=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/installengine-race-weights.txt
envtest_plan=$(
  { printf 'P %s\n' "${envtest_plain_names[@]}"; printf 'T %s\n' "${envtest_tagged_names[@]}"; } |
  awk '
    FILENAME != "-" {
      if ($0 ~ /^[[:space:]]*(#|$)/) next
      if (NF != 2 || $2 !~ /^[1-9][0-9]*$/ || $2 > 1200 || ($1 in weights)) {
        print "Malformed or duplicate envtest scheduling weight." > "/dev/stderr"; failed=1; exit 1
      }
      weights[$1]=$2; weightCount++; next
    }
    {
      if (NF != 2 || ($1 != "P" && $1 != "T")) { failed=1; exit 1 }
      if ($1 == "P") plain[$2]=1; else tagged[$2]=1
    }
    END {
      if (failed) exit 1
      if (!weightCount) { print "Empty envtest scheduling weights." > "/dev/stderr"; exit 1 }
      for (name in plain) if (!(name in tagged)) {
        print "Tagged build omitted an ordinary compiled root: " name > "/dev/stderr"; failed=1
      }
      for (name in weights) if (!(name in plain)) {
        print "Stale ordinary envtest scheduling weight: " name > "/dev/stderr"; failed=1
      }
      for (name in tagged) if (!(name in plain)) taggedOnly++
      if (!taggedOnly) {
        print "Empty compiled envtest-only census." > "/dev/stderr"; failed=1
      }
      if (failed) exit 1
      for (name in tagged) {
        weight=(name in weights ? weights[name] : 60)
        exclusive=(!(name in plain) || weight == 1200)
        print exclusive, weight, name
      }
    }
  ' "$envtest_weights" - | LC_ALL=C sort -k1,1nr -k2,2nr -k3,3 |
  awk '
    BEGIN { workers=32; reserved=0 }
    {
      if ($1 == 1) {
        if (reserved >= workers) { print "Too many exclusive envtest trees." > "/dev/stderr"; failed=1; exit 1 }
        worker=reserved++
      } else {
        if (reserved == workers) { print "No shared envtest worker remains." > "/dev/stderr"; failed=1; exit 1 }
        worker=reserved
        for (i=reserved+1; i<workers; i++) if (load[i] < load[worker]) worker=i
        load[worker]+=$2
      }
      counts[worker]++; assigned[NR]=worker " " $3
    }
    END {
      if (failed) exit 1
      for (i=0; i<workers; i++) if (!counts[i]) {
        print "Empty envtest engine worker; review the complete partition." > "/dev/stderr"; failed=1
      }
      if (failed) exit 1
      for (i=1; i<=NR; i++) print assigned[i]
    }
  '
)

run_engine() {
  local selected_text pattern='' name
  local -a selected
  selected_text=$(printf '%s\n' "$envtest_plan" | awk -v part="$1" '$1 == part {print $2}')
  [[ -n $selected_text ]] || return 1
  mapfile -t selected <<< "$selected_text"
  if [[ ${2:-} == --list-only ]]; then
    printf '%s\n' "${selected[@]}"
    return
  fi
  for name in "${selected[@]}"; do pattern+="${pattern:+|}^${name}$"; done
  printf 'Envtest engine part %s/32: %s of %s compiled roots\n' "$1" "${#selected[@]}" "${#envtest_tagged_names[@]}"
  printf 'Selected: %s\n' "${selected[@]}"
  go test -tags=envtest -p 1 -timeout=30m -v ./internal/installengine -run "$pattern" -count=1
}

if [[ $envtest_part != --all ]]; then
  run_engine "$envtest_part" "${2:-}"
  exit 0
fi

# The whole partition was validated BEFORE even the base packages can run.
# Attempt every part after an execution failure, but preserve a nonzero result.
envtest_status=0
if run_base; then :; else envtest_status=$?; fi
for ((envtest_index=0; envtest_index<32; envtest_index++)); do
  if run_engine "$envtest_index"; then :; else
    envtest_failure=$?
    if [[ $envtest_status == 0 ]]; then envtest_status=$envtest_failure; fi
  fi
done
exit "$envtest_status"
