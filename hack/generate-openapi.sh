#!/usr/bin/env bash
# Copyright 2026 gobha-me
# SPDX-License-Identifier: Apache-2.0
set -Eeuo pipefail
readonly openapi_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$openapi_root"
GOMAXPROCS=2 GOMEMLIMIT=1GiB go run -p=1 ./api/admin/v1/cmd/openapi >api/admin/v1/openapi.json
