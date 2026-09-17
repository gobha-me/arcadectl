#!/usr/bin/env bash
# Copyright 2026 gobha-me
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

readonly repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly kubectl_command=${KUBECTL:-kubectl}
readonly namespace=arcadectl-system

servers=$("$kubectl_command" get gameservers.arcade.gobha.me --namespace "$namespace" \
  --output=jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.desiredState}{"\t"}{.status.phase}{"\t"}{.metadata.generation}{"\t"}{.status.observedGeneration}{"\n"}{end}')
readonly servers
unsafe_servers=$(awk -F '\t' 'NF > 0 && ($2 != "Stopped" || $3 != "Stopped" || $4 == "" || $5 == "" || $4 != $5) { print }' <<<"$servers")
readonly unsafe_servers
if [[ -n "$unsafe_servers" ]]; then
  echo "refusing uninstall because every GameServer must be desired Stopped and observed Stopped at its current generation:" >&2
  printf '%s\n' "$unsafe_servers" >&2
  exit 1
fi

"$kubectl_command" delete --filename "$repository_root/config/install/uninstall.yaml" --ignore-not-found=true

echo "controller removed; namespace, CRD, GameServers, and retained PVCs were not deleted"
