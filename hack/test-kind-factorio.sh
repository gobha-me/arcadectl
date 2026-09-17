#!/usr/bin/env bash
# Copyright 2026 gobha-me
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

readonly repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export ARCADECTL_LIFECYCLE_SUITE=factorio
exec "$repository_root/hack/test-kind-lifecycle.sh"
