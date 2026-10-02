#!/usr/bin/env bash
# Copyright 2026 gobha-me
# SPDX-License-Identifier: Apache-2.0
# Fixture-only: Deployment availability does not prove Service reachability.

repository_health_init_container() {
  local image=$1
  local script='attempt=0
while [ "$attempt" -lt 30 ]; do
  attempt=$((attempt + 1))
  if timeout 2 wget -q -T 2 -O /dev/null http://minio:9000/minio/health/cluster; then
    exit 0
  fi
  if [ "$attempt" -lt 30 ]; then sleep 1; fi
done
echo "fixture repository Service health deadline exhausted" >&2
exit 1'
  jq -cn --arg image "$image" --arg script "$script" \
    '{name:"repository-service-health",image:$image,imagePullPolicy:"IfNotPresent",
      command:["/bin/sh","-ec",$script],
      resources:{requests:{cpu:"10m",memory:"8Mi"},limits:{cpu:"100m",memory:"16Mi"}},
      securityContext:{runAsNonRoot:true,runAsUser:65532,runAsGroup:65532,
        allowPrivilegeEscalation:false,readOnlyRootFilesystem:true,
        capabilities:{drop:["ALL"]},seccompProfile:{type:"RuntimeDefault"}}}'
}
