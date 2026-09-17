#!/usr/bin/env bash
# Copyright 2026 gobha-me
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

readonly repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly controller_dockerfile="$repository_root/Dockerfile"
readonly factorio_dockerfile="$repository_root/images/factorio/Dockerfile"
readonly conformance_dockerfile="$repository_root/images/conformance/Dockerfile"
readonly factorio_entrypoint="$repository_root/images/factorio/secure-entrypoint.sh"
readonly factorio_readiness="$repository_root/images/factorio/readiness-probe.sh"
readonly materializer="$repository_root/internal/platform/kube/materialize.sh"
readonly lifecycle_harness="$repository_root/hack/test-kind-lifecycle.sh"
readonly factorio_harness="$repository_root/hack/test-kind-factorio.sh"
readonly diagnostic_redaction="$repository_root/hack/redact-diagnostics.sed"

bash -n "$factorio_entrypoint"
bash -n "$factorio_readiness"
sh -n "$materializer"
bash -n "$repository_root/hack/generate-install.sh"
bash -n "$repository_root/hack/render-controller.sh"
bash -n "$repository_root/hack/install.sh"
bash -n "$repository_root/hack/uninstall.sh"
bash -n "$lifecycle_harness"
bash -n "$factorio_harness"
grep -Fq 'golang:1.26.0-alpine3.23@sha256:d4c4845f5d60c6a974c6000ce58ae079328d03ab7f721a0734277e69905473e5' "$controller_dockerfile"
grep -Fq 'ENV GOTOOLCHAIN=local GOFLAGS=-mod=readonly' "$controller_dockerfile"
grep -Fq 'FROM scratch' "$controller_dockerfile"
grep -Fq 'find /rootfs -exec touch -d "@$SOURCE_DATE_EPOCH" {} +' "$controller_dockerfile"
grep -Fq 'USER 65532:65532' "$controller_dockerfile"
grep -Fq 'ARG LIFECYCLE_TEST=false' "$controller_dockerfile"
grep -Fq 'true) set -- -tags=lifecycletest' "$controller_dockerfile"
grep -Fq 'arcade.gobha.me/source-dirty="$SOURCE_DIRTY"' "$controller_dockerfile"
grep -Eq '^FROM factoriotools/factorio@sha256:[0-9a-f]{64}$' "$factorio_dockerfile"
grep -Fq 'sha256sum -c -' "$factorio_dockerfile"
grep -Fq 'COPY --chmod=0555 readiness-probe.sh /arcadectl/readiness' "$factorio_dockerfile"
grep -Fq 'export BASH_XTRACEFD=9' "$factorio_entrypoint"
if grep -Eq '(echo|printf|set -x)' "$factorio_readiness"; then
  echo "Factorio readiness helper must not emit probe details" >&2
  exit 1
fi
grep -Fq 'golang:1.26.0-alpine3.23@sha256:d4c4845f5d60c6a974c6000ce58ae079328d03ab7f721a0734277e69905473e5' "$conformance_dockerfile"
grep -Fq 'FROM scratch' "$conformance_dockerfile"
grep -Fq 'USER 65532:65532' "$conformance_dockerfile"
grep -Fq 'arcade.gobha.me/purpose="isolated-lifecycle-test-fixture"' "$conformance_dockerfile"
grep -Fq 'arcade.gobha.me/source-dirty="$SOURCE_DIRTY"' "$conformance_dockerfile"
grep -Fq "readonly kind_version=v0.33.0" "$lifecycle_harness"
grep -Fq "kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5" "$lifecycle_harness"
grep -Fq "registry.k8s.io/kubectl@sha256:5ed410ebac5dc976cc717098994dcdb29bbbd38f6bd65f582311f5be4ba719cf" "$lifecycle_harness"
grep -Fq "registry:3.0.0@sha256:6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e" "$lifecycle_harness"
grep -Fq 'arcade.gobha.me/e2e-run' "$lifecycle_harness"
grep -Fq 'ARCADECTL_LIFECYCLE_SUITE=factorio' "$factorio_harness"
if grep -Eq 'kind delete cluster --all|docker (system|network|volume) prune|docker network rm' "$lifecycle_harness"; then
  echo "Lifecycle harness contains a broad destructive operation" >&2
  exit 1
fi
if grep -Eq 'kind delete cluster --all|docker (system|network|volume) prune|docker network rm' "$factorio_harness"; then
  echo "Factorio lifecycle harness contains a broad destructive operation" >&2
  exit 1
fi
redaction_fixture=$(printf '%s\n' \
  'password=plain-value token:token-value Authorization: Bearer authorization-value' \
  '{"secret":"json two word value","auth":"docker value"}' \
  "{'password':'single quoted value'}" \
  'https://username:url-value@example.invalid/path' \
  | sed -E -f "$diagnostic_redaction")
for forbidden in plain-value token-value authorization-value 'json two word value' 'docker value' 'single quoted value' url-value; do
  if grep -Fq "$forbidden" <<<"$redaction_fixture"; then
    echo "Diagnostics redaction missed fixture value: $forbidden" >&2
    exit 1
  fi
done
