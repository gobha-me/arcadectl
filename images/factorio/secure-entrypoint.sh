#!/bin/bash
# Copyright 2026 gobha-me
# SPDX-License-Identifier: Apache-2.0

set -eu

# The upstream entrypoint enables shell tracing and later expands its generated
# RCON password into Factorio's argv. Keep normal application output on stdout
# and stderr, but route Bash's trace stream to a private sink before delegating.
exec 9>/dev/null
export BASH_XTRACEFD=9

exec /docker-entrypoint.sh "$@"
