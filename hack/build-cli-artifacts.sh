#!/usr/bin/env bash
# Copyright 2026 gobha-me
# SPDX-License-Identifier: Apache-2.0
set -Eeuo pipefail
umask 077
export LC_ALL=C TZ=UTC

fail() { printf 'artifact build refused: %s\n' "$1" >&2; exit 1; }
[[ $# == 1 ]] || fail 'one new output-directory argument is required'
readonly artifact_root="$(git rev-parse --show-toplevel)"
cd "$artifact_root"
[[ -z "$(git status --porcelain --untracked-files=no)" ]] || fail 'tracked source is dirty'
readonly artifact_sha="$(git rev-parse --verify HEAD^{commit})"
readonly artifact_epoch="$(git show -s --format=%ct "$artifact_sha")"
[[ "$artifact_sha" =~ ^[0-9a-f]{40}$ && "$artifact_epoch" =~ ^[1-9][0-9]*$ ]] || fail 'invalid source identity'
readonly artifact_required_go="go$(sed -n 's/^go \([0-9][0-9.]*\)$/\1/p' go.mod)"
readonly artifact_go="$(go env GOROOT)/bin/go"
export GOTOOLCHAIN=local GOWORK=off GOFLAGS= GOENV=off GO111MODULE=on CGO_ENABLED=0
export GOEXPERIMENT= GOAMD64=v1 GOARM64=v8.0
[[ "$("$artifact_go" env GOVERSION)" == "$artifact_required_go" ]] || fail 'use the exact go.mod toolchain'
[[ ! -e "$1" && ! -L "$1" ]] || fail 'output directory must not exist'
readonly artifact_output="$(python3 -c 'import os,sys; print(os.path.abspath(sys.argv[1]))' "$1")"
readonly artifact_work="$(mktemp -d)"
trap 'rm -rf -- "$artifact_work"' EXIT
mkdir "$artifact_work/source" "$artifact_work/build"
git archive --format=tar "$artifact_sha" | tar --extract --directory "$artifact_work/source" --no-same-owner --no-same-permissions
readonly artifact_ldflags="-buildid= -X github.com/gobha-me/arcadectl/internal/buildinfo.SourceSHA=$artifact_sha -X github.com/gobha-me/arcadectl/internal/buildinfo.SourceEpoch=$artifact_epoch"
for artifact_arch in amd64 arm64; do
  (
    cd "$artifact_work/source"
    GOOS=linux GOARCH="$artifact_arch" GOMAXPROCS=2 GOMEMLIMIT=1GiB \
      "$artifact_go" build -p=1 -mod=readonly -trimpath -buildvcs=false -ldflags "$artifact_ldflags" \
      -o "$artifact_work/build/arcadectl-$artifact_arch" ./cmd/arcadectl
  )
  "$artifact_go" version -m -json "$artifact_work/build/arcadectl-$artifact_arch" > "$artifact_work/build/modules-$artifact_arch.json"
done
python3 "$artifact_work/source/hack/pack-cli-artifacts.py" \
  "$artifact_work" "$artifact_output" "$artifact_sha" "$artifact_epoch" "$artifact_required_go"
printf 'Built local unsigned CLI artifacts for source %s\n' "$artifact_sha"
