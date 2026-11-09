#!/usr/bin/env bash
# Copyright 2026 gobha-me
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
readonly repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ $# -gt 1 ]]; then
  echo 'usage: test-kind-journey.sh [--plan]' >&2
  exit 2
fi
if [[ ${1:-} == --plan ]]; then
  echo 'CI only: creates and removes its own digest-pinned Kind cluster and registry.'
  echo 'timeout --foreground 35m env -u KUBECONFIG GOMAXPROCS=2 GOMEMLIMIT=1GiB go test -tags=kindapi -p 1 -timeout=33m -v ./internal/install -run ^TestKindAuthenticatedAdmin$ -count=1'
  exit 0
fi
if [[ $# != 0 || ${CI:-} != true ]]; then
  echo 'journey execution requires CI=true and an owned disposable runner; use --plan for offline inspection' >&2
  exit 2
fi
cd "$repository_root"
exec timeout --foreground 35m env -u KUBECONFIG GOMAXPROCS=2 GOMEMLIMIT=1GiB \
  go test -tags=kindapi -p 1 -timeout=33m -v ./internal/install \
  -run '^TestKindAuthenticatedAdmin$' -count=1
