#!/usr/bin/env bash
# Copyright 2026 gobha-me
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <controller-image@sha256:digest>" >&2
  exit 2
fi

readonly controller_image=$1
if ! grep -Eq '^[a-z0-9][a-z0-9._:/-]*@sha256:[0-9a-f]{64}$' <<<"$controller_image"; then
  echo "controller image must be a lowercase repository pinned by sha256 digest" >&2
  exit 2
fi

readonly repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly install_directory="$repository_root/config/install"
readonly template="$install_directory/deployment.yaml.tmpl"

if [[ $(grep -Fo '@@CONTROLLER_IMAGE@@' "$template" | wc -l) -ne 1 ]]; then
  echo "controller Deployment template must contain exactly one image placeholder" >&2
  exit 1
fi

for manifest in \
  "$install_directory/service-account.yaml" \
  "$repository_root/config/rbac/role.yaml" \
  "$install_directory/role-binding.yaml"; do
  printf '%s\n' "$(<"$manifest")"
done

rendered=$(sed "s|@@CONTROLLER_IMAGE@@|$controller_image|g" "$template")
readonly rendered
if grep -Fq '@@CONTROLLER_IMAGE@@' <<<"$rendered"; then
  echo "controller image placeholder remains after rendering" >&2
  exit 1
fi
printf '%s\n' "$rendered"
