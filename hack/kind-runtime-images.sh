#!/usr/bin/env bash
# Copyright 2026 gobha-me
# SPDX-License-Identifier: Apache-2.0

# Share only exact-source production images. Registries, digest resolution,
# cluster imports and ownership-checked cleanup remain local to each fixture.
set -Eeuo pipefail

die() { echo "Kind runtime image: $*" >&2; exit 1; }

verify_image() {
  local image=$1 role=$2 sha=$3 dirty=$4
  [[ $(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$image") == linux/amd64 ]] || die 'platform mismatch'
  [[ $(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$image") == "$sha" ]] || die 'source mismatch'
  [[ $(docker image inspect --format '{{index .Config.Labels "arcade.gobha.me/source-dirty"}}' "$image") == "$dirty" ]] || die 'source state mismatch'
  [[ $(docker image inspect --format '{{.Config.User}}' "$image") == 65532:65532 ]] || die 'user mismatch'
  [[ $(docker image inspect --format '{{json .Config.Entrypoint}}' "$image") == "[\"/arcadectl-$role\"]" ]] || die 'entrypoint mismatch'
}

case ${1:-} in
  export)
    [[ $# == 3 ]] || die 'export requires source root and output directory'
    root=$2 bundle=$3
    [[ -z $(git -C "$root" status --porcelain) ]] || die 'export requires a clean exact-source checkout'
    mkdir -p "$bundle"
    git -C "$root" rev-parse HEAD >"$bundle/source-sha"
    git -C "$root" show -s --format=%ct HEAD >"$bundle/source-epoch"
    sha=$(cat "$bundle/source-sha") epoch=$(cat "$bundle/source-epoch")
    # Two independent builds; each Dockerfile already bounds Go concurrency.
    # Wait for both even on failure, and never publish a partial bundle.
    pids=()
    for role in api controller; do
      (
        # Disable artifact selection for the producer, even if inherited locally.
        ARCADECTL_KIND_IMAGE_DIR= bash "$0" prepare "$role" "$root" "$sha" "$epoch" false "arcadectl-$role:kind-shared"
        docker image inspect --format '{{.Id}}' "arcadectl-$role:kind-shared" >"$bundle/$role.id"
      ) &
      pids+=("$!")
    done
    failed=0
    for pid in "${pids[@]}"; do
      wait "$pid" || failed=1
    done
    [[ $failed == 0 ]] || die 'production image build failed'
    docker image save --output "$bundle/images.tar" arcadectl-api:kind-shared arcadectl-controller:kind-shared
    (cd "$bundle" && sha256sum images.tar source-sha source-epoch api.id controller.id >SHA256SUMS)
    ;;
  load)
    [[ $# == 3 ]] || die 'load requires source root and bundle directory'
    root=$2 bundle=$3
    (cd "$bundle" && sha256sum --check --strict SHA256SUMS)
    [[ $(cat "$bundle/source-sha") == "$(git -C "$root" rev-parse HEAD)" ]] || die 'bundle belongs to another commit'
    [[ $(cat "$bundle/source-epoch") == "$(git -C "$root" show -s --format=%ct HEAD)" ]] || die 'bundle timestamp mismatch'
    docker image load --input "$bundle/images.tar"
    for role in api controller; do
      image=$(cat "$bundle/$role.id")
      [[ $image =~ ^sha256:[0-9a-f]{64}$ ]] || die 'invalid image identity'
      verify_image "$image" "$role" "$(cat "$bundle/source-sha")" false
    done
    ;;
  prepare)
    [[ $# == 7 ]] || die 'prepare requires role, source root, SHA, epoch, dirty state and owned tag'
    role=$2 root=$3 sha=$4 epoch=$5 dirty=$6 tag=$7
    case $role in
      api) dockerfile=Dockerfile.api ;;
      controller) dockerfile=Dockerfile ;;
      *) die 'unsupported runtime image role' ;;
    esac
    if [[ -n ${ARCADECTL_KIND_IMAGE_DIR:-} ]]; then
      bundle=$ARCADECTL_KIND_IMAGE_DIR
      # An explicitly requested bundle must never silently fall back to a build.
      [[ $dirty == false ]] || die 'shared images require a clean consumer checkout'
      [[ $(cat "$bundle/source-sha") == "$sha" ]] || die 'shared source mismatch'
      [[ $(cat "$bundle/source-epoch") == "$epoch" ]] || die 'shared timestamp mismatch'
      image=$(cat "$bundle/$role.id")
      [[ $image =~ ^sha256:[0-9a-f]{64}$ ]] || die 'invalid shared image identity'
      verify_image "$image" "$role" "$sha" "$dirty"
      docker image tag "$image" "$tag"
    else
      args=(--file "$root/$dockerfile" --build-arg "VCS_REF=$sha" --build-arg "SOURCE_DATE_EPOCH=$epoch" --build-arg "SOURCE_DIRTY=$dirty")
      [[ $role != controller ]] || args+=(--build-arg LIFECYCLE_TEST=false)
      docker build "${args[@]}" --tag "$tag" "$root"
    fi
    verify_image "$tag" "$role" "$sha" "$dirty"
    ;;
  *) die 'expected export, load or prepare' ;;
esac
