#!/usr/bin/env bash
# Copyright 2026 gobha-me
# SPDX-License-Identifier: Apache-2.0

# A GameServer's claim is created asynchronously. A named kubectl wait can
# fail before that claim exists, so cover creation and binding in ONE budget.
# The caller supplies kube_bounded; never suppress errors other than NotFound
# (which kubectl's --ignore-not-found turns into a successful empty result).
wait_world_pvc_bound() {
  local name=$1 claim_namespace=$2 seconds=$3 phase remaining command_seconds
  local deadline=$((SECONDS + seconds))
  while (( SECONDS < deadline )); do
    remaining=$((deadline - SECONDS))
    # The clock may tick after the loop condition. GNU timeout 0s disables
    # its deadline, so never dispatch with an exhausted or negative budget.
    (( remaining > 0 )) || break
    command_seconds=$remaining
    (( command_seconds <= 30 )) || command_seconds=30
    if ! phase=$(kube_bounded "$command_seconds" get persistentvolumeclaim "$name" \
      --namespace "$claim_namespace" --ignore-not-found --output=jsonpath='{.status.phase}' 2>/dev/null); then
      printf 'error: could not observe world PVC binding\n' >&2
      return 1
    fi
    # Do not accept a result arriving after the shared deadline.
    if [[ "$phase" == Bound ]] && (( SECONDS < deadline )); then
      return 0
    fi
    (( SECONDS < deadline )) || break
    sleep 1
  done
  printf 'error: timed out waiting for world PVC creation and binding\n' >&2
  return 1
}
