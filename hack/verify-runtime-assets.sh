#!/usr/bin/env bash
# Copyright 2026 gobha-me
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

readonly repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly factorio_dockerfile="$repository_root/images/factorio/Dockerfile"
readonly factorio_entrypoint="$repository_root/images/factorio/secure-entrypoint.sh"
readonly materializer="$repository_root/internal/platform/kube/materialize.sh"

bash -n "$factorio_entrypoint"
sh -n "$materializer"
grep -Eq '^FROM factoriotools/factorio@sha256:[0-9a-f]{64}$' "$factorio_dockerfile"
grep -Fq 'sha256sum -c -' "$factorio_dockerfile"
grep -Fq 'export BASH_XTRACEFD=9' "$factorio_entrypoint"
