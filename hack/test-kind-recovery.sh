#!/usr/bin/env bash
# Copyright 2026 gobha-me
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail
readonly recovery_repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export ARCADECTL_LIFECYCLE_SUITE=recovery
exec "$recovery_repository_root/hack/test-kind-lifecycle.sh" "$@"
