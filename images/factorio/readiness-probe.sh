#!/bin/bash
# Copyright 2026 gobha-me
# SPDX-License-Identifier: Apache-2.0

# Keep private readiness details out of kubelet probe output and Pod Events.
if { exec 3<>/dev/tcp/127.0.0.1/27015; } 2>/dev/null; then
  exec 3<&-
  exec 3>&-
  exit 0
fi
exit 1
