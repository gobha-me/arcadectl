#!/usr/bin/env bash
# Copyright 2026 gobha-me
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

# The event's base SHA is passed as data, never interpolated into shell source.
# Missing history must fail instead of silently accepting a baseline-only scan.
if [[ ! ${LINT_BASE_SHA:-} =~ ^[0-9a-f]{40}$ ]] ||
   ! git cat-file -e "${LINT_BASE_SHA}^{commit}"; then
  echo 'Lint diff base must identify an available commit' >&2
  exit 2
fi

golangci-lint run --config=.golangci-new.yml --issues-exit-code=1 \
  --new-from-merge-base="$LINT_BASE_SHA" ./...
