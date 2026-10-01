#!/usr/bin/env bash
# Copyright 2026 gobha-me
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

readonly repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly controller_dockerfile="$repository_root/Dockerfile"
readonly factorio_dockerfile="$repository_root/images/factorio/Dockerfile"
readonly conformance_dockerfile="$repository_root/images/conformance/Dockerfile"
readonly minio_dockerfile="$repository_root/images/minio-fixture/Dockerfile"
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
grep -Fq 'restic/restic@sha256:39d9072fb5651c80d75c7a811612eb60b4c06b32ffe87c2e9f3c7222e1797e76' "$controller_dockerfile"
grep -Fq 'ENV GOTOOLCHAIN=local GOMAXPROCS=2 GOFLAGS="-mod=readonly -p=2"' "$controller_dockerfile"
grep -Fq 'go build -trimpath -ldflags="-s -w -buildid=" -o /out/arcadectl-backup-worker ./cmd/arcadectl-backup-worker' "$controller_dockerfile"
grep -Fq 'go build -trimpath -ldflags="-s -w -buildid=" -o /out/arcadectl-restore-worker ./cmd/arcadectl-restore-worker' "$controller_dockerfile"
grep -Fq 'go build -trimpath -ldflags="-s -w -buildid=" -o /out/arcadectl-backup-authorizer ./cmd/arcadectl-backup-authorizer' "$controller_dockerfile"
grep -Fq 'go build -trimpath -ldflags="-s -w -buildid=" -o /out/arcadectl-restore-authorizer ./cmd/arcadectl-restore-authorizer' "$controller_dockerfile"
grep -Fq 'COPY --from=restic /usr/bin/restic /rootfs/restic' "$controller_dockerfile"
grep -Fq 'COPY --from=restic /etc/ssl/certs/ca-certificates.crt /rootfs/etc/ssl/certs/ca-certificates.crt' "$controller_dockerfile"
runtime_copies=$(awk '/^FROM scratch/ { runtime=1; next } runtime && /^COPY / { count++ } END { print count+0 }' "$controller_dockerfile")
if [[ "$runtime_copies" != 1 ]]; then
  echo "Controller runtime must copy only its fully timestamp-normalized root filesystem" >&2
  exit 1
fi
grep -Fq 'cp licenses/restic-LICENSE /rootfs/licenses/restic-LICENSE' "$controller_dockerfile"
grep -Fq 'BSD 2-Clause License' "$repository_root/licenses/restic-LICENSE"
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
grep -Fq 'golang:1.26.0-alpine3.23@sha256:d4c4845f5d60c6a974c6000ce58ae079328d03ab7f721a0734277e69905473e5' "$minio_dockerfile"
grep -Fq 'ADD --checksum=sha256:45521908307306e925c98d629e1c17d78c8b72b6ee242b1bfb1409f7d8ee5841' "$minio_dockerfile"
grep -Fq 'https://codeload.github.com/minio/minio/tar.gz/9e49d5e7a648f00e26f2246f4dc28e6b07f8c84a' "$minio_dockerfile"
grep -Fq 'GOTOOLCHAIN=local GOMAXPROCS=2 GOMEMLIMIT=1GiB GOFLAGS="-mod=readonly -p=1"' "$minio_dockerfile"
grep -Fq 'COPY Dockerfile /out/licenses/build-recipe.Dockerfile' "$minio_dockerfile"
grep -Fq 'cp LICENSE CREDITS /out/licenses/' "$minio_dockerfile"
grep -Fq 'cp /tmp/minio-source.tar.gz /out/licenses/' "$minio_dockerfile"
grep -Fq 'cp /etc/ssl/certs/ca-certificates.crt /out/etc/ssl/certs/ca-certificates.crt' "$minio_dockerfile"
grep -Fq "find /out -exec touch -d '@1760549395' {} +" "$minio_dockerfile"
minio_runtime_copies=$(awk '/^FROM scratch/ { runtime=1; next } runtime && /^COPY / { count++ } END { print count+0 }' "$minio_dockerfile")
if [[ "$minio_runtime_copies" != 1 ]]; then
  echo "MinIO fixture runtime must copy only its fully timestamp-normalized root filesystem" >&2
  exit 1
fi
grep -Fq 'FROM scratch' "$minio_dockerfile"
grep -Fq 'USER 65532:65532' "$minio_dockerfile"
grep -Fq '/minio/health/cluster' "$lifecycle_harness"
grep -Fq 'assert_worker_evidence_private "$first_worker_pod" backup-worker' "$lifecycle_harness"
grep -Fq 'independently inspecting repository artifacts without mounting source worlds' "$lifecycle_harness"
grep -Fq 'kind: GameBackup' "$lifecycle_harness"
grep -Fq 'repository credential canary escaped' "$lifecycle_harness"
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
