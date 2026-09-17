#!/usr/bin/env bash
# Copyright 2026 gobha-me
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <canonical-controller-image@sha256:digest>" >&2
  exit 2
fi

readonly repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly anchors_output="$repository_root/config/install/anchors.yaml"
readonly controller_output="$repository_root/config/install/controller.yaml"
anchors_temporary=$(mktemp "$repository_root/config/install/.anchors.yaml.XXXXXX")
controller_temporary=$(mktemp "$repository_root/config/install/.controller.yaml.XXXXXX")
readonly anchors_temporary controller_temporary
trap 'rm -f -- "$anchors_temporary" "$controller_temporary"' EXIT

for manifest in \
  "$repository_root/config/install/namespace.yaml" \
  "$repository_root/config/crd/bases/arcade.gobha.me_gameservers.yaml" \
  "$repository_root/config/crd/bases/arcade.gobha.me_gamebackups.yaml" \
  "$repository_root/config/crd/bases/arcade.gobha.me_gamerestores.yaml"; do
  printf '%s\n' "$(<"$manifest")"
done >"$anchors_temporary"
"$repository_root/hack/render-controller.sh" "$1" >"$controller_temporary"
mv -f -- "$anchors_temporary" "$anchors_output"
mv -f -- "$controller_temporary" "$controller_output"
trap - EXIT
