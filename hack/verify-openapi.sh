#!/usr/bin/env bash
# Copyright 2026 gobha-me
# SPDX-License-Identifier: Apache-2.0
set -Eeuo pipefail
readonly openapi_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly openapi_temporary="$(mktemp)"
trap 'rm -f "$openapi_temporary"' EXIT
cd "$openapi_root"
GOMAXPROCS=2 GOMEMLIMIT=1GiB go run -p=1 ./api/admin/v1/cmd/openapi >"$openapi_temporary"
cmp api/admin/v1/openapi.json "$openapi_temporary"
