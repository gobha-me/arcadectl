#!/usr/bin/env bash
set -euo pipefail

go tool controller-gen \
  object:headerFile=hack/boilerplate.go.txt \
  crd:crdVersions=v1 \
  paths=./api/... \
  output:crd:artifacts:config=config/crd/bases
go tool controller-gen \
  rbac:roleName=arcadectl-controller \
  paths=./internal/controller/... \
  output:rbac:artifacts:config=config/rbac

generated_paths=(
  api/v1alpha1/zz_generated.deepcopy.go
  config/crd/bases
  config/rbac
)

if ! git diff --quiet -- "${generated_paths[@]}" ||
  [[ -n "$(git ls-files --others --exclude-standard -- "${generated_paths[@]}")" ]]; then
  git diff -- "${generated_paths[@]}"
  git status --short -- "${generated_paths[@]}"
  echo "generated API artifacts are out of date; run 'make generate'" >&2
  exit 1
fi
