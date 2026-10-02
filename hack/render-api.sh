#!/usr/bin/env bash
# Copyright 2026 gobha-me
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
if [[ $# -ne 1 ]] || ! [[ $1 =~ ^[a-z0-9][a-z0-9._:/-]*@sha256:[0-9a-f]{64}$ ]]; then
  echo "usage: $0 <api-image@sha256:digest>" >&2
  exit 2
fi
readonly api_image=$1
readonly repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly api_directory="$repository_root/config/api"
readonly template="$api_directory/deployment.yaml.tmpl"
if [[ $(grep -Fo '@@API_IMAGE@@' "$template" | wc -l) -ne 1 ]]; then
  echo "API Deployment must contain exactly one image placeholder" >&2
  exit 1
fi
for manifest in service-account.yaml role.yaml service.yaml; do
  printf '%s\n' "$(<"$api_directory/$manifest")"
done
sed "s|@@API_IMAGE@@|$api_image|g" "$template"
