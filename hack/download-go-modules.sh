#!/bin/sh
# Copyright 2026 gobha-me
# SPDX-License-Identifier: Apache-2.0

# Build-time dependency transport only; never wrap builds or security proofs.
set -u

attempt=1
while :; do
  if go mod download; then
    exit 0
  else
    status=$?
  fi
  if [ "$status" -ge 128 ] || [ "$attempt" -ge 3 ]; then
    exit "$status"
  fi
  if sleep 2; then
    attempt=$((attempt + 1))
  else
    exit "$?"
  fi
done
