#!/usr/bin/env bash
# Copyright 2026 gobha-me
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <controller-image@sha256:digest>" >&2
  exit 2
fi

readonly repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly kubectl_command=${KUBECTL:-kubectl}
controller_manifest=$(mktemp)
readonly controller_manifest
trap 'rm -f -- "$controller_manifest"' EXIT

"$repository_root/hack/render-controller.sh" "$1" >"$controller_manifest"

"$kubectl_command" apply -f "$repository_root/config/install/anchors.yaml"
for custom_resource_definition in \
  gameservers.arcade.gobha.me \
  gamebackups.arcade.gobha.me \
  gamerestores.arcade.gobha.me; do
  "$kubectl_command" wait --for=condition=Established \
    "customresourcedefinition/$custom_resource_definition" --timeout=60s
done
"$kubectl_command" apply -f "$controller_manifest"
"$kubectl_command" rollout status deployment/arcadectl-controller --namespace arcadectl-system --timeout=120s
