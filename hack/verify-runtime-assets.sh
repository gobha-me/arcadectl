#!/usr/bin/env bash
# Copyright 2026 gobha-me
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

readonly repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly controller_dockerfile="$repository_root/Dockerfile"
readonly factorio_dockerfile="$repository_root/images/factorio/Dockerfile"
readonly factorio_entrypoint="$repository_root/images/factorio/secure-entrypoint.sh"
readonly factorio_readiness="$repository_root/images/factorio/readiness-probe.sh"
readonly materializer="$repository_root/internal/platform/kube/materialize.sh"

bash -n "$factorio_entrypoint"
bash -n "$factorio_readiness"
sh -n "$materializer"
bash -n "$repository_root/hack/generate-install.sh"
bash -n "$repository_root/hack/render-controller.sh"
bash -n "$repository_root/hack/install.sh"
bash -n "$repository_root/hack/uninstall.sh"
grep -Fq 'golang:1.26.0-alpine3.23@sha256:d4c4845f5d60c6a974c6000ce58ae079328d03ab7f721a0734277e69905473e5' "$controller_dockerfile"
grep -Fq 'ENV GOTOOLCHAIN=local GOFLAGS=-mod=readonly' "$controller_dockerfile"
grep -Fq 'FROM scratch' "$controller_dockerfile"
grep -Fq 'find /rootfs -exec touch -d "@$SOURCE_DATE_EPOCH" {} +' "$controller_dockerfile"
grep -Fq 'USER 65532:65532' "$controller_dockerfile"
grep -Eq '^FROM factoriotools/factorio@sha256:[0-9a-f]{64}$' "$factorio_dockerfile"
grep -Fq 'sha256sum -c -' "$factorio_dockerfile"
grep -Fq 'COPY --chmod=0555 readiness-probe.sh /arcadectl/readiness' "$factorio_dockerfile"
grep -Fq 'export BASH_XTRACEFD=9' "$factorio_entrypoint"
if grep -Eq '(echo|printf|set -x)' "$factorio_readiness"; then
  echo "Factorio readiness helper must not emit probe details" >&2
  exit 1
fi
