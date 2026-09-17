#!/usr/bin/env bash
# Copyright 2026 gobha-me
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail
umask 077

readonly kind_version=v0.33.0
readonly kind_node_image='kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5'
readonly kubectl_image='registry.k8s.io/kubectl@sha256:5ed410ebac5dc976cc717098994dcdb29bbbd38f6bd65f582311f5be4ba719cf'
readonly registry_image='registry:3.0.0@sha256:6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e'
readonly namespace=arcadectl-system
readonly server_name=lifecycle
readonly claim_name=lifecycle-conformance-echo-state
readonly collision_name=collision

readonly repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workspace=$(mktemp -d "${TMPDIR:-/tmp}/arcadectl-kind-lifecycle.XXXXXX")
readonly workspace
run_suffix=$(basename "$workspace" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9' | tail -c 12)
readonly run_suffix
readonly run_id="lifecycle-$run_suffix"
readonly cluster_name="arcadectl-e2e-$run_suffix"
readonly registry_name="$cluster_name-registry"
readonly kubeconfig="$workspace/kubeconfig"
readonly ownership_file="$workspace/ownership"
readonly kubectl_wrapper="$workspace/kubectl"
readonly artifact_root="${ARCADECTL_E2E_ARTIFACT_ROOT:-$repository_root/artifacts/kind-lifecycle}"
readonly artifact_directory="$artifact_root/$run_id"
readonly docker_config="$workspace/docker-config"
readonly redaction_rules="$repository_root/hack/redact-diagnostics.sed"

mkdir -p "$docker_config"
chmod 0700 "$docker_config"
export DOCKER_CONFIG="$docker_config"

registry_created=false
cluster_created=false
registry_cleanup_armed=false
cluster_cleanup_armed=false
cluster_marker_created=false
registry_id=
kubectl_extract_id=
registry_port=
node_names=
node_ids=
controller_tag=
synthetic_tag=

say() {
  printf '==> %s\n' "$*"
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

run_bounded() {
  local seconds=$1
  shift
  timeout --foreground "${seconds}s" "$@"
}

kube() {
  kube_bounded 30 "$@"
}

kube_bounded() {
  local seconds=$1
  shift
  run_bounded "$seconds" "$kubectl_wrapper" "$@"
}

redact_stream() {
  sed -E -f "$redaction_rules"
}

collect_diagnostics() {
  mkdir -p "$artifact_root" || return 1
  if [[ -e "$artifact_directory" || -L "$artifact_directory" ]]; then
    printf 'refusing to overwrite existing diagnostics path: %s\n' "$artifact_directory" >&2
    return 1
  fi
  mkdir "$artifact_directory" || return 1
  chmod 0700 "$artifact_directory"
  {
    printf 'run_id=%s\ncluster=%s\nregistry=%s\n' "$run_id" "$cluster_name" "$registry_name"
    printf 'kind_node_image=%s\nkubectl_image=%s\nregistry_image=%s\n' "$kind_node_image" "$kubectl_image" "$registry_image"
  } >"$artifact_directory/inputs.txt"
  {
    git -C "$repository_root" rev-parse HEAD 2>/dev/null || true
    git -C "$repository_root" status --short 2>/dev/null || true
    go tool kind version 2>/dev/null || true
    docker version --format 'client={{.Client.Version}} server={{.Server.Version}}' 2>/dev/null || true
  } >"$artifact_directory/source-and-tools.txt"

  if [[ -x "$kubectl_wrapper" && -s "$kubeconfig" ]]; then
    run_bounded 20 "$kubectl_wrapper" get gameservers.arcade.gobha.me --namespace "$namespace" \
      --output='custom-columns=NAME:.metadata.name,GEN:.metadata.generation,OBSERVED:.status.observedGeneration,DESIRED:.spec.desiredState,PHASE:.status.phase,READY:.status.conditions[?(@.type=="Ready")].reason' \
      >"$artifact_directory/gameservers.txt" 2>&1 || true
    run_bounded 20 "$kubectl_wrapper" get pods,deployments,services,configmaps,persistentvolumeclaims \
      --namespace "$namespace" --output=wide >"$artifact_directory/objects.txt" 2>&1 || true
    run_bounded 20 "$kubectl_wrapper" get persistentvolumes --output=wide >"$artifact_directory/persistent-volumes.txt" 2>&1 || true
    run_bounded 20 "$kubectl_wrapper" get events --namespace "$namespace" \
      --sort-by=.metadata.creationTimestamp \
      --output='custom-columns=TIME:.metadata.creationTimestamp,TYPE:.type,REASON:.reason,REGARDING:.involvedObject.kind,NAME:.involvedObject.name,COUNT:.count,MESSAGE:.message' 2>&1 \
      | redact_stream >"$artifact_directory/events.txt" || true
    run_bounded 20 "$kubectl_wrapper" logs deployment/arcadectl-controller --namespace "$namespace" --tail=500 2>&1 \
      | redact_stream >"$artifact_directory/controller.log" || true
    run_bounded 20 "$kubectl_wrapper" logs --selector=app.kubernetes.io/name=game-server --namespace "$namespace" --all-containers=true --tail=500 2>&1 \
      | redact_stream >"$artifact_directory/game.log" || true
    run_bounded 20 "$kubectl_wrapper" logs --selector="arcade.gobha.me/e2e-run=$run_id" --namespace "$namespace" --all-containers=true --tail=500 2>&1 \
      | redact_stream >"$artifact_directory/probes.log" || true
    run_bounded 20 "$kubectl_wrapper" get pods --namespace "$namespace" \
      --output='custom-columns=NAME:.metadata.name,INIT_IMAGE:.spec.initContainers[*].image,INIT_IMAGE_ID:.status.initContainerStatuses[*].imageID,IMAGE:.spec.containers[*].image,IMAGE_ID:.status.containerStatuses[*].imageID,PHASE:.status.phase' \
      >"$artifact_directory/image-ids.txt" 2>&1 || true
  fi
  if docker inspect "$registry_name" >/dev/null 2>&1; then
    run_bounded 10 docker logs "$registry_name" 2>&1 | redact_stream >"$artifact_directory/registry.log" || true
  fi
  {
    printf 'controller_tag=%s\nsynthetic_tag=%s\n' "$controller_tag" "$synthetic_tag"
    [[ -z "$controller_tag" ]] || docker image inspect "$controller_tag" --format 'controller_id={{.Id}} controller_digests={{json .RepoDigests}}' 2>/dev/null || true
    [[ -z "$synthetic_tag" ]] || docker image inspect "$synthetic_tag" --format 'synthetic_id={{.Id}} synthetic_digests={{json .RepoDigests}}' 2>/dev/null || true
  } >"$artifact_directory/docker-images.txt"
  find "$artifact_directory" -type f -exec chmod 0600 {} +
  printf 'sanitized failure diagnostics: %s\n' "$artifact_directory" >&2
}

verify_registry_ownership() {
  [[ "$registry_cleanup_armed" == true && -s "$ownership_file" ]] || return 1
  grep -Fxq "run_id=$run_id" "$ownership_file" || return 1
  grep -Fxq "registry=$registry_name" "$ownership_file" || return 1
  grep -Fxq 'registry_preflight_absent=true' "$ownership_file" || return 1
  local current_id
  current_id=$(docker inspect --format '{{.Id}}' "$registry_name" 2>/dev/null) || return 1
  [[ -z "$registry_id" || "$current_id" == "$registry_id" ]] || return 1
  [[ $(docker inspect --format '{{index .Config.Labels "arcade.gobha.me/e2e-run"}}' "$registry_name" 2>/dev/null) == "$run_id" ]] || return 1
}

verify_cluster_ownership() {
  [[ "$cluster_cleanup_armed" == true && -s "$ownership_file" ]] || return 1
  grep -Fxq "run_id=$run_id" "$ownership_file" || return 1
  grep -Fxq "cluster=$cluster_name" "$ownership_file" || return 1
  grep -Fxq 'cluster_preflight_absent=true' "$ownership_file" || return 1
  local current_ids current_id marker marker_status=0
  current_ids=$(docker ps --all --filter "label=io.x-k8s.kind.cluster=$cluster_name" --format '{{.ID}}') || return 1
  while IFS= read -r current_id; do
    [[ -n "$current_id" ]] || continue
    [[ $(docker inspect --format '{{index .Config.Labels "io.x-k8s.kind.cluster"}}' "$current_id" 2>/dev/null) == "$cluster_name" ]] || return 1
    if [[ -n "$node_ids" ]]; then
      grep -Fxq "$(docker inspect --format '{{.Id}}' "$current_id" 2>/dev/null)" <<<"$node_ids" || return 1
    fi
  done <<<"$current_ids"
  if [[ "$cluster_marker_created" == true && -x "$kubectl_wrapper" && -s "$kubeconfig" ]]; then
    marker=$(run_bounded 10 "$kubectl_wrapper" get configmap arcadectl-e2e-owner --namespace kube-system --output=jsonpath='{.data.run-id}' 2>/dev/null) || marker_status=$?
    if [[ "$marker_status" -eq 0 && "$marker" != "$run_id" ]]; then
      return 1
    fi
  fi
  return 0
}

cleanup() {
  local cleanup_status=0 clusters current_nodes registry_names image_references
  set +e
  local cluster_present=false
  if ! clusters=$(go tool kind get clusters 2>/dev/null); then
    printf 'could not enumerate kind clusters during cleanup\n' >&2
    cleanup_status=1
    clusters=
  fi
  if ! current_nodes=$(docker ps --all --filter "label=io.x-k8s.kind.cluster=$cluster_name" --format '{{.ID}}'); then
    printf 'could not enumerate Docker nodes during cleanup\n' >&2
    cleanup_status=1
    current_nodes=
  fi
  if grep -Fxq "$cluster_name" <<<"$clusters" || [[ -n "$current_nodes" ]]; then
    cluster_present=true
  fi
  if [[ "$cluster_present" == true ]]; then
    if verify_cluster_ownership; then
      say "deleting owned kind cluster $cluster_name"
      run_bounded 120 go tool kind delete cluster --name "$cluster_name" || cleanup_status=1
    else
      printf 'refusing to delete cluster %s because ownership proof is incomplete; inspect Docker label io.x-k8s.kind.cluster=%s\n' "$cluster_name" "$cluster_name" >&2
      cleanup_status=1
    fi
  fi
  if ! registry_names=$(docker ps --all --filter "name=^/${registry_name}$" --format '{{.Names}}'); then
    printf 'could not enumerate Docker registries during cleanup\n' >&2
    cleanup_status=1
    registry_names=
  fi
  if grep -Fxq "$registry_name" <<<"$registry_names"; then
    if verify_registry_ownership; then
      say "deleting owned registry $registry_name"
      run_bounded 30 docker rm --force "$registry_name" >/dev/null || cleanup_status=1
    else
      printf 'refusing to delete registry %s because ownership proof is incomplete\n' "$registry_name" >&2
      cleanup_status=1
    fi
  fi
  if [[ -n "$kubectl_extract_id" ]] && docker inspect "$kubectl_extract_id" >/dev/null 2>&1; then
    if [[ $(docker inspect --format '{{index .Config.Labels "arcade.gobha.me/e2e-run"}}' "$kubectl_extract_id" 2>/dev/null) == "$run_id" ]]; then
      run_bounded 30 docker rm --force "$kubectl_extract_id" >/dev/null || cleanup_status=1
    else
      printf 'refusing to delete kubectl extraction container %s because ownership proof is incomplete\n' "$kubectl_extract_id" >&2
      cleanup_status=1
    fi
  fi
  if ! image_references=$(docker image ls --format '{{.Repository}}:{{.Tag}}'); then
    printf 'could not enumerate Docker images during cleanup\n' >&2
    cleanup_status=1
    image_references=
  fi
  if [[ -n "$controller_tag" ]]; then
    if grep -Fxq "$controller_tag" <<<"$image_references"; then
      docker image rm "$controller_tag" >/dev/null 2>&1 || cleanup_status=1
    fi
  fi
  if [[ -n "$synthetic_tag" ]]; then
    if grep -Fxq "$synthetic_tag" <<<"$image_references"; then
      docker image rm "$synthetic_tag" >/dev/null 2>&1 || cleanup_status=1
    fi
  fi
  if ! clusters=$(go tool kind get clusters 2>/dev/null); then
    printf 'could not verify kind cluster absence after cleanup\n' >&2
    cleanup_status=1
    clusters=
  fi
  if grep -Fxq "$cluster_name" <<<"$clusters"; then
    printf 'owned cluster %s still exists after cleanup\n' "$cluster_name" >&2
    cleanup_status=1
  fi
  if ! registry_names=$(docker ps --all --filter "name=^/${registry_name}$" --format '{{.Names}}'); then
    printf 'could not verify registry absence after cleanup\n' >&2
    cleanup_status=1
    registry_names=
  fi
  if grep -Fxq "$registry_name" <<<"$registry_names"; then
    printf 'owned registry %s still exists after cleanup\n' "$registry_name" >&2
    cleanup_status=1
  fi
  if ! current_nodes=$(docker ps --all --filter "label=io.x-k8s.kind.cluster=$cluster_name" --format '{{.ID}}'); then
    printf 'could not verify kind node absence after cleanup\n' >&2
    cleanup_status=1
    current_nodes=
  fi
  if [[ -n "$current_nodes" ]]; then
    printf 'containers for owned cluster %s still exist after cleanup\n' "$cluster_name" >&2
    cleanup_status=1
  fi
  if ! image_references=$(docker image ls --format '{{.Repository}}:{{.Tag}}'); then
    printf 'could not verify task image absence after cleanup\n' >&2
    cleanup_status=1
    image_references=
  fi
  if [[ -n "$controller_tag" ]] && grep -Fxq "$controller_tag" <<<"$image_references"; then
    printf 'task controller image tag still exists after cleanup: %s\n' "$controller_tag" >&2
    cleanup_status=1
  fi
  if [[ -n "$synthetic_tag" ]] && grep -Fxq "$synthetic_tag" <<<"$image_references"; then
    printf 'task synthetic image tag still exists after cleanup: %s\n' "$synthetic_tag" >&2
    cleanup_status=1
  fi
  if [[ "$cleanup_status" -eq 0 ]]; then
    rm -rf -- "$workspace" || cleanup_status=1
    if [[ -e "$workspace" || -L "$workspace" ]]; then
      cleanup_status=1
    fi
    if [[ "$cleanup_status" -ne 0 ]]; then
      printf 'failed to remove private task workspace: %s\n' "$workspace" >&2
    fi
  else
    printf 'preserving task workspace for cleanup recovery: %s\n' "$workspace" >&2
  fi
  return "$cleanup_status"
}

finish() {
  local status=$?
  local cleanup_status=0
  trap - EXIT
  set +e
  if [[ "$status" -ne 0 ]]; then
    collect_diagnostics
  fi
  cleanup || cleanup_status=$?
  if [[ "$status" -eq 0 && "$cleanup_status" -ne 0 ]]; then
    collect_diagnostics
    status=$cleanup_status
  fi
  exit "$status"
}
trap finish EXIT

for command in awk basename chmod curl docker find git go grep head mktemp sed seq sleep tail timeout tr; do
  command -v "$command" >/dev/null 2>&1 || die "required command is unavailable: $command"
done
docker info >/dev/null 2>&1 || die "Docker daemon is unavailable"
[[ $(go tool kind version) == kind\ "$kind_version"* ]] || die "go tool kind is not $kind_version"
clusters_before=$(go tool kind get clusters 2>/dev/null) || die "could not enumerate kind clusters during ownership preflight"
if grep -Fxq "$cluster_name" <<<"$clusters_before"; then
  die "refusing to adopt existing kind cluster $cluster_name"
fi
registries_before=$(docker ps --all --filter "name=^/${registry_name}$" --format '{{.Names}}') \
  || die "could not enumerate Docker registries during ownership preflight"
if grep -Fxq "$registry_name" <<<"$registries_before"; then
  die "refusing to adopt existing registry $registry_name"
fi
{
  printf 'run_id=%s\ncluster=%s\nregistry=%s\n' "$run_id" "$cluster_name" "$registry_name"
  printf 'cluster_preflight_absent=true\nregistry_preflight_absent=true\n'
} >"$ownership_file"
chmod 0600 "$ownership_file"

run_bounded 30 docker pull "$kubectl_image" >/dev/null
kubectl_extract_id=$(docker create \
  --name "$cluster_name-kubectl-extract" \
  --label "arcade.gobha.me/e2e-run=$run_id" \
  "$kubectl_image")
run_bounded 30 docker cp "$kubectl_extract_id:/bin/kubectl" "$workspace/kubectl-bin"
run_bounded 30 docker rm "$kubectl_extract_id" >/dev/null
kubectl_extract_id=
chmod 0700 "$workspace/kubectl-bin"
run_bounded 10 "$workspace/kubectl-bin" version --client --output=json \
  | grep -Fq '"gitVersion": "v1.37.0"' \
  || die "pinned kubectl image did not provide kubectl v1.37.0"

cat >"$kubectl_wrapper" <<EOF
#!/usr/bin/env bash
set -euo pipefail
exec "$workspace/kubectl-bin" --kubeconfig="$kubeconfig" "\$@"
EOF
chmod 0700 "$kubectl_wrapper"

candidate_sha=$(git -C "$repository_root" rev-parse HEAD) || die "could not resolve source HEAD"
source_date_epoch=$(git -C "$repository_root" show -s --format=%ct HEAD) || die "could not resolve source timestamp"
source_status=$(git -C "$repository_root" status --porcelain=v1 --untracked-files=all) || die "could not inspect source state"
source_dirty=false
[[ -z "$source_status" ]] || source_dirty=true
readonly candidate_sha source_date_epoch source_dirty

say "starting pinned local registry"
registry_cleanup_armed=true
registry_id=$(run_bounded 60 docker run --detach --pull=always --restart=no \
  --publish 127.0.0.1::5000 \
  --name "$registry_name" \
  --label "arcade.gobha.me/e2e-run=$run_id" \
  "$registry_image")
registry_created=true
registry_port=$(docker port "$registry_name" 5000/tcp | awk -F: 'END { print $NF }')
[[ "$registry_port" =~ ^[0-9]+$ ]] || die "could not resolve the task registry port"
for _ in $(seq 1 30); do
  if curl --fail --silent --show-error "http://127.0.0.1:$registry_port/v2/" >/dev/null; then
    break
  fi
  sleep 1
done
curl --fail --silent --show-error "http://127.0.0.1:$registry_port/v2/" >/dev/null || die "task registry did not become ready"

readonly registry_host="127.0.0.1:$registry_port"
controller_tag="$registry_host/arcadectl-controller:$run_id"
synthetic_tag="$registry_host/gobha-me/arcadectl-conformance-server:$run_id"

say "building lifecycle-only controller image"
run_bounded 360 docker build \
  --build-arg "VCS_REF=$candidate_sha" \
  --build-arg "SOURCE_DATE_EPOCH=$source_date_epoch" \
  --build-arg LIFECYCLE_TEST=true \
  --build-arg "SOURCE_DIRTY=$source_dirty" \
  --tag "$controller_tag" \
  "$repository_root"
say "building synthetic lifecycle server image"
run_bounded 360 docker build \
  --file "$repository_root/images/conformance/Dockerfile" \
  --build-arg "VCS_REF=$candidate_sha" \
  --build-arg "SOURCE_DATE_EPOCH=$source_date_epoch" \
  --build-arg "SOURCE_DIRTY=$source_dirty" \
  --tag "$synthetic_tag" \
  "$repository_root"
run_bounded 120 docker push "$controller_tag" >/dev/null
run_bounded 120 docker push "$synthetic_tag" >/dev/null

resolve_digest() {
  local tag=$1 repository=${1%:*} reference
  reference=$(docker image inspect "$tag" --format '{{range .RepoDigests}}{{println .}}{{end}}' | grep -E "^${repository//./\\.}@sha256:[0-9a-f]{64}$" | head -n 1)
  [[ -n "$reference" ]] || return 1
  printf '%s\n' "${reference##*@}"
}

controller_digest=$(resolve_digest "$controller_tag") || die "controller registry digest is unavailable"
synthetic_digest=$(resolve_digest "$synthetic_tag") || die "synthetic registry digest is unavailable"
readonly controller_digest synthetic_digest
readonly controller_image="$registry_host/arcadectl-controller@$controller_digest"
readonly synthetic_image="ghcr.io/gobha-me/arcadectl-conformance-server@$synthetic_digest"

say "creating task-owned kind cluster $cluster_name"
cat >"$workspace/kind.yaml" <<'EOF'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
containerdConfigPatches:
  - |-
    [plugins."io.containerd.cri.v1.images".registry]
      config_path = "/etc/containerd/certs.d"
EOF
cluster_cleanup_armed=true
run_bounded 240 go tool kind create cluster \
  --name "$cluster_name" \
  --image "$kind_node_image" \
  --config "$workspace/kind.yaml" \
  --kubeconfig "$kubeconfig" \
  --wait 180s
cluster_created=true
run_bounded 30 docker network connect kind "$registry_name"
node_names=$(go tool kind get nodes --name "$cluster_name")
[[ -n "$node_names" ]] || die "kind returned no owned nodes"
node_ids=
while IFS= read -r node; do
  [[ -n "$node" ]] || continue
  [[ $(docker inspect --format '{{index .Config.Labels "io.x-k8s.kind.cluster"}}' "$node") == "$cluster_name" ]] || die "kind node ownership label mismatch"
  node_ids+="$(docker inspect --format '{{.Id}}' "$node")"$'\n'
done <<<"$node_names"
{
  printf 'run_id=%s\ncluster=%s\nregistry=%s\nregistry_id=%s\n' "$run_id" "$cluster_name" "$registry_name" "$registry_id"
  printf 'cluster_preflight_absent=true\nregistry_preflight_absent=true\n'
  printf 'nodes=%s\nnode_ids=%s\n' "$node_names" "$node_ids"
} >"$ownership_file"

while IFS= read -r node; do
  [[ -n "$node" ]] || continue
  local_registry_path="/etc/containerd/certs.d/127.0.0.1:$registry_port"
  run_bounded 10 docker exec "$node" mkdir -p "$local_registry_path" /etc/containerd/certs.d/ghcr.io
  printf '[host."http://%s:5000"]\n  capabilities = ["pull", "resolve"]\n' "$registry_name" \
    | run_bounded 10 docker exec --interactive "$node" tee "$local_registry_path/hosts.toml" >/dev/null
  printf 'server = "https://ghcr.io"\n[host."http://%s:5000"]\n  capabilities = ["pull", "resolve"]\n' "$registry_name" \
    | run_bounded 10 docker exec --interactive "$node" tee /etc/containerd/certs.d/ghcr.io/hosts.toml >/dev/null
  run_bounded 120 docker exec "$node" ctr --namespace k8s.io images pull \
    --hosts-dir /etc/containerd/certs.d "$controller_image" >/dev/null
  run_bounded 120 docker exec "$node" ctr --namespace k8s.io images pull \
    --hosts-dir /etc/containerd/certs.d "$synthetic_image" >/dev/null
done <<<"$node_names"

kube create configmap arcadectl-e2e-owner --namespace kube-system \
  --from-literal="run-id=$run_id" --from-literal="cluster=$cluster_name"
cluster_marker_created=true

say "installing generated controller artifacts by registry digest"
run_bounded 180 env KUBECTL="$kubectl_wrapper" "$repository_root/hack/install.sh" "$controller_image"
[[ $(kube auth can-i delete persistentvolumeclaims \
  --as=system:serviceaccount:arcadectl-system:arcadectl-controller --namespace "$namespace") == no ]] \
  || die "controller unexpectedly has PVC deletion authority"

wait_server() {
  local name=$1 wanted_phase=$2 wanted_ready_reason=$3 seconds=$4 observed
  local deadline=$((SECONDS + seconds))
  while (( SECONDS < deadline )); do
    observed=$(kube get gameserver "$name" --namespace "$namespace" \
      --output=jsonpath='{.metadata.generation}|{.status.observedGeneration}|{.status.phase}|{.status.conditions[?(@.type=="Ready")].reason}' 2>/dev/null || true)
    IFS='|' read -r generation observed_generation phase ready_reason <<<"$observed"
    if [[ -n "$generation" && "$generation" == "$observed_generation" && "$phase" == "$wanted_phase" && "$ready_reason" == "$wanted_ready_reason" ]]; then
      return 0
    fi
    sleep 2
  done
  printf 'timed out waiting for GameServer %s phase=%s Ready.reason=%s; observed %s\n' "$name" "$wanted_phase" "$wanted_ready_reason" "$observed" >&2
  return 1
}

wait_absent() {
  local resource=$1 name=$2 seconds=$3 observed=
  local deadline=$((SECONDS + seconds))
  while (( SECONDS < deadline )); do
    if observed=$(kube get "$resource" "$name" --namespace "$namespace" --ignore-not-found --output=name 2>/dev/null); then
      if [[ -z "$observed" ]]; then
        return 0
      fi
    fi
    sleep 1
  done
  printf 'timed out waiting for %s/%s to be absent\n' "$resource" "$name" >&2
  return 1
}

assert_absent() {
  local identity=$1 observed
  observed=$(kube get "$identity" --namespace "$namespace" --ignore-not-found --output=name) \
    || die "could not verify absence of $identity"
  [[ -z "$observed" ]] || die "$identity was partially created before a last-stage collision"
}

wait_selector_absent() {
  local resource=$1 selector=$2 seconds=$3 observed=
  local deadline=$((SECONDS + seconds))
  while (( SECONDS < deadline )); do
    if observed=$(kube get "$resource" --namespace "$namespace" --selector="$selector" --output=name 2>/dev/null); then
      if [[ -z "$observed" ]]; then
        return 0
      fi
    fi
    sleep 1
  done
  printf 'timed out waiting for %s selected by %s to be absent; observed %s\n' "$resource" "$selector" "$observed" >&2
  return 1
}

wait_present() {
  local resource=$1 name=$2 seconds=$3
  local deadline=$((SECONDS + seconds))
  while (( SECONDS < deadline )); do
    if kube get "$resource" "$name" --namespace "$namespace" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  printf 'timed out waiting for %s/%s to exist\n' "$resource" "$name" >&2
  return 1
}

wait_pod_phase() {
  local name=$1 wanted=$2 seconds=$3 phase=
  local deadline=$((SECONDS + seconds))
  while (( SECONDS < deadline )); do
    phase=$(kube get pod "$name" --namespace "$namespace" --output=jsonpath='{.status.phase}' 2>/dev/null || true)
    [[ "$phase" == "$wanted" ]] && return 0
    [[ "$phase" == Failed ]] && break
    sleep 1
  done
  printf 'timed out waiting for Pod %s phase=%s; observed %s\n' "$name" "$wanted" "$phase" >&2
  return 1
}

patch_player_service() {
  local name=$1 cluster_ip=
  for _ in $(seq 1 60); do
    cluster_ip=$(kube get service "$name" --namespace "$namespace" --output=jsonpath='{.spec.clusterIP}' 2>/dev/null || true)
    [[ "$cluster_ip" =~ ^[0-9a-fA-F:.]+$ ]] && break
    sleep 1
  done
  [[ "$cluster_ip" =~ ^[0-9a-fA-F:.]+$ ]] || die "Service $name did not receive a ClusterIP"
  kube patch service "$name" --namespace "$namespace" --subresource=status --type=merge \
    --patch "{\"status\":{\"loadBalancer\":{\"ingress\":[{\"ip\":\"$cluster_ip\",\"ports\":[{\"port\":8080,\"protocol\":\"TCP\"}]}]}}}" >/dev/null
  printf '%s\n' "$cluster_ip"
}

assert_pvc_identity() {
  local wanted_uid=$1 wanted_pv=$2 observed
  observed=$(kube get persistentvolumeclaim "$claim_name" --namespace "$namespace" \
    --output=jsonpath='{.metadata.uid}|{.spec.volumeName}|{.metadata.ownerReferences}')
  [[ "$observed" == "$wanted_uid|$wanted_pv|" ]] || die "retained PVC identity changed: $observed"
}

assert_runtime_absent() {
  local name=$1
  wait_absent configmap "$name-configuration" 60
  wait_absent deployment "$name" 60
  wait_absent service "$name" 60
  local selector="app.kubernetes.io/name=game-server,app.kubernetes.io/instance=$name"
  wait_selector_absent replicasets "$selector" 60
  wait_selector_absent pods "$selector" 60
}

assert_game_image() {
  local name=$1 output count image image_id
  output=$(kube get pods --namespace "$namespace" \
    --selector="app.kubernetes.io/name=game-server,app.kubernetes.io/instance=$name" \
    --output=jsonpath='{range .items[*]}{.spec.containers[?(@.name=="game")].image}|{.status.containerStatuses[?(@.name=="game")].imageID}{"\n"}{end}')
  count=$(awk 'NF { count++ } END { print count + 0 }' <<<"$output")
  [[ "$count" -eq 1 ]] || die "expected exactly one game Pod for $name, observed $count"
  IFS='|' read -r image image_id <<<"$output"
  [[ "$image" == "$synthetic_image" ]] || die "game Pod image is not the intended digest: $image"
  [[ "$image_id" == *"$synthetic_digest"* ]] || die "game Pod imageID does not prove the intended digest: $image_id"
}

assert_controller_image() {
  local output image image_id
  output=$(kube get pods --namespace "$namespace" --selector=app.kubernetes.io/name=arcadectl-controller \
    --output=jsonpath='{range .items[*]}{.spec.containers[?(@.name=="controller")].image}|{.status.containerStatuses[?(@.name=="controller")].imageID}{"\n"}{end}')
  [[ $(awk 'NF { count++ } END { print count + 0 }' <<<"$output") -eq 1 ]] || die "expected exactly one controller Pod"
  IFS='|' read -r image image_id <<<"$output"
  [[ "$image" == "$controller_image" ]] || die "controller Pod image is not the intended digest: $image"
  [[ "$image_id" == *"$controller_digest"* ]] || die "controller Pod imageID does not prove the intended digest: $image_id"
}

probe_state() {
  local name=$1
  local probe_name="${name}-service-probe"
  kube_bounded 40 delete pod "$probe_name" --namespace "$namespace" --ignore-not-found --wait=true --timeout=30s >/dev/null
  cat >"$workspace/probe.yaml" <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $probe_name
  namespace: $namespace
  labels:
    arcade.gobha.me/e2e-run: $run_id
spec:
  restartPolicy: Never
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 65532
    runAsGroup: 65532
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: probe
      image: $synthetic_image
      imagePullPolicy: IfNotPresent
      command: ["/arcadectl-conformance-server", "get", "http://$name:8080/state"]
      resources:
        requests: {cpu: 5m, memory: 8Mi}
        limits: {cpu: 50m, memory: 32Mi}
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities: {drop: ["ALL"]}
EOF
  kube apply --filename "$workspace/probe.yaml" >/dev/null
  wait_pod_phase "$probe_name" Succeeded 60
  kube logs "$probe_name" --namespace "$namespace"
  kube_bounded 40 delete pod "$probe_name" --namespace "$namespace" --wait=true --timeout=30s >/dev/null
}

verify_marker_while_stopped() {
  cat >"$workspace/verifier.yaml" <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: lifecycle-storage-verifier
  namespace: $namespace
  labels:
    arcade.gobha.me/e2e-run: $run_id
spec:
  restartPolicy: Never
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 65532
    runAsGroup: 65532
    fsGroup: 65532
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: verifier
      image: $synthetic_image
      imagePullPolicy: IfNotPresent
      command: ["/arcadectl-conformance-server", "read-marker"]
      resources:
        requests: {cpu: 5m, memory: 8Mi}
        limits: {cpu: 50m, memory: 32Mi}
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities: {drop: ["ALL"]}
      volumeMounts:
        - name: state
          mountPath: /srv/world
          readOnly: true
  volumes:
    - name: state
      persistentVolumeClaim:
        claimName: $claim_name
EOF
  kube apply --filename "$workspace/verifier.yaml" >/dev/null
  wait_pod_phase lifecycle-storage-verifier Succeeded 60
  local marker
  marker=$(kube logs lifecycle-storage-verifier --namespace "$namespace")
  [[ "$marker" == first-seed ]] || die "retained marker changed while stopped: $marker"
  kube_bounded 70 delete pod lifecycle-storage-verifier --namespace "$namespace" --wait=true --timeout=60s >/dev/null
}

cat >"$workspace/persistent-volume.yaml" <<EOF
apiVersion: v1
kind: PersistentVolume
metadata:
  name: arcadectl-e2e-world-$run_suffix
  labels:
    arcade.gobha.me/e2e-run: $run_id
spec:
  capacity:
    storage: 64Mi
  accessModes: ["ReadWriteOnce"]
  persistentVolumeReclaimPolicy: Retain
  storageClassName: ""
  claimRef:
    namespace: $namespace
    name: $claim_name
  hostPath:
    path: /var/arcadectl-e2e/$run_id
    type: DirectoryOrCreate
EOF
while IFS= read -r node; do
  [[ -n "$node" ]] || continue
  run_bounded 10 docker exec "$node" install -d -o 65532 -g 65532 -m 0770 "/var/arcadectl-e2e/$run_id"
done <<<"$node_names"
kube apply --filename "$workspace/persistent-volume.yaml" >/dev/null

cat >"$workspace/server.yaml" <<EOF
apiVersion: arcade.gobha.me/v1alpha1
kind: GameServer
metadata:
  name: $server_name
  namespace: $namespace
spec:
  game: conformance-echo
  imageDigest: $synthetic_digest
  desiredState: Stopped
  compute:
    cpuRequest: 10m
    cpuLimit: 100m
    memoryRequest: 16Mi
    memoryLimit: 64Mi
  storage:
    size: 64Mi
    storageClassName: ""
  settings:
    seed: first-seed
    motd: first-message
EOF

say "creating stopped server and retained storage"
kube apply --filename "$workspace/server.yaml" >/dev/null
kube_bounded 100 wait persistentvolumeclaim/"$claim_name" --namespace "$namespace" --for=jsonpath='{.status.phase}'=Bound --timeout=90s >/dev/null
wait_server "$server_name" Stopped RuntimeStopped 90
assert_runtime_absent "$server_name"
pvc_uid=$(kube get persistentvolumeclaim "$claim_name" --namespace "$namespace" --output=jsonpath='{.metadata.uid}')
pv_name=$(kube get persistentvolumeclaim "$claim_name" --namespace "$namespace" --output=jsonpath='{.spec.volumeName}')
server_uid=$(kube get gameserver "$server_name" --namespace "$namespace" --output=jsonpath='{.metadata.uid}')
readonly pvc_uid pv_name server_uid
[[ -n "$pvc_uid" && "$pv_name" == "arcadectl-e2e-world-$run_suffix" ]] || die "retained PVC identity is incomplete"
assert_pvc_identity "$pvc_uid" "$pv_name"
assert_controller_image

say "starting server and proving reachable current readiness"
kube patch gameserver "$server_name" --namespace "$namespace" --type=merge --patch '{"spec":{"desiredState":"Running"}}' >/dev/null
wait_present deployment "$server_name" 60
kube_bounded 100 rollout status deployment/"$server_name" --namespace "$namespace" --timeout=90s >/dev/null
player_address=$(patch_player_service "$server_name")
wait_server "$server_name" Ready Ready 90
observed_endpoint=$(kube get gameserver "$server_name" --namespace "$namespace" --output=jsonpath='{.status.endpoints[0].name}|{.status.endpoints[0].protocol}|{.status.endpoints[0].address}|{.status.endpoints[0].port}')
[[ "$observed_endpoint" == "players|TCP|$player_address|8080" ]] || die "unexpected published endpoint: $observed_endpoint"
state=$(probe_state "$server_name")
grep -Fxq 'marker=first-seed' <<<"$state" || die "initial state lacks retained marker"
grep -Fxq 'seed=first-seed' <<<"$state" || die "initial state lacks current seed"
grep -Fxq 'motd=first-message' <<<"$state" || die "initial state lacks current MOTD"
initial_boots=$(awk -F= '$1 == "boots" { print $2 }' <<<"$state")
[[ "$initial_boots" =~ ^[1-9][0-9]*$ ]] || die "initial boot count is invalid"
assert_game_image "$server_name"
assert_pvc_identity "$pvc_uid" "$pv_name"

say "stopping without deleting data"
kube patch gameserver "$server_name" --namespace "$namespace" --type=merge --patch '{"spec":{"desiredState":"Stopped"}}' >/dev/null
wait_server "$server_name" Stopped RuntimeStopped 90
assert_runtime_absent "$server_name"
assert_pvc_identity "$pvc_uid" "$pv_name"
verify_marker_while_stopped

say "restarting from retained data"
kube patch gameserver "$server_name" --namespace "$namespace" --type=merge --patch '{"spec":{"desiredState":"Running"}}' >/dev/null
wait_present deployment "$server_name" 60
kube_bounded 100 rollout status deployment/"$server_name" --namespace "$namespace" --timeout=90s >/dev/null
patch_player_service "$server_name" >/dev/null
wait_server "$server_name" Ready Ready 90
state=$(probe_state "$server_name")
grep -Fxq 'marker=first-seed' <<<"$state" || die "restart changed retained marker"
restart_boots=$(awk -F= '$1 == "boots" { print $2 }' <<<"$state")
(( restart_boots > initial_boots )) || die "restart did not advance boot evidence"
assert_pvc_identity "$pvc_uid" "$pv_name"

say "updating settings through a new workload generation"
old_pod_uid=$(kube get pods --namespace "$namespace" --selector="app.kubernetes.io/instance=$server_name" --output=jsonpath='{.items[0].metadata.uid}')
old_deployment_generation=$(kube get deployment "$server_name" --namespace "$namespace" --output=jsonpath='{.metadata.generation}')
kube patch gameserver "$server_name" --namespace "$namespace" --type=merge \
  --patch '{"spec":{"settings":{"seed":"second-seed","motd":"updated-message"}}}' >/dev/null
kube_bounded 100 rollout status deployment/"$server_name" --namespace "$namespace" --timeout=90s >/dev/null
wait_server "$server_name" Ready Ready 90
new_pod_uid=$(kube get pods --namespace "$namespace" --selector="app.kubernetes.io/instance=$server_name" --output=jsonpath='{.items[0].metadata.uid}')
new_deployment_generation=$(kube get deployment "$server_name" --namespace "$namespace" --output=jsonpath='{.metadata.generation}')
[[ "$new_pod_uid" != "$old_pod_uid" ]] || die "settings update did not replace the game Pod"
(( new_deployment_generation > old_deployment_generation )) || die "settings update did not advance Deployment generation"
state=$(probe_state "$server_name")
grep -Fxq 'marker=first-seed' <<<"$state" || die "settings update changed retained marker"
grep -Fxq 'seed=second-seed' <<<"$state" || die "settings update did not materialize the new seed"
grep -Fxq 'motd=updated-message' <<<"$state" || die "settings update did not materialize the new MOTD"
assert_game_image "$server_name"
assert_pvc_identity "$pvc_uid" "$pv_name"

say "redeploying the controller without changing game state"
old_controller_name=$(kube get pods --namespace "$namespace" --selector=app.kubernetes.io/name=arcadectl-controller --output=jsonpath='{.items[0].metadata.name}')
old_controller_uid=$(kube get pods --namespace "$namespace" --selector=app.kubernetes.io/name=arcadectl-controller --output=jsonpath='{.items[0].metadata.uid}')
old_game_pod_uid=$(kube get pods --namespace "$namespace" --selector="app.kubernetes.io/instance=$server_name" --output=jsonpath='{.items[0].metadata.uid}')
kube rollout restart deployment/arcadectl-controller --namespace "$namespace" >/dev/null
kube_bounded 100 wait pod/"$old_controller_name" --namespace "$namespace" --for=delete --timeout=90s >/dev/null
kube_bounded 130 rollout status deployment/arcadectl-controller --namespace "$namespace" --timeout=120s >/dev/null
new_controller_uid=$(kube get pods --namespace "$namespace" --selector=app.kubernetes.io/name=arcadectl-controller --output=jsonpath='{.items[0].metadata.uid}')
[[ "$new_controller_uid" != "$old_controller_uid" ]] || die "controller redeploy did not replace its Pod"
kube_bounded 70 delete deployment "$server_name" --namespace "$namespace" --wait=true --timeout=60s >/dev/null
wait_present deployment "$server_name" 60
kube_bounded 100 rollout status deployment/"$server_name" --namespace "$namespace" --timeout=90s >/dev/null
wait_server "$server_name" Ready Ready 90
new_game_pod_uid=$(kube get pods --namespace "$namespace" --selector="app.kubernetes.io/instance=$server_name" --output=jsonpath='{.items[0].metadata.uid}')
[[ "$new_game_pod_uid" != "$old_game_pod_uid" ]] || die "controller redeploy reconciliation did not replace the game Pod"
assert_controller_image
assert_game_image "$server_name"
assert_pvc_identity "$pvc_uid" "$pv_name"
grep -Fxq 'marker=first-seed' <<<"$(probe_state "$server_name")" || die "controller redeploy changed retained marker"

say "deleting and recreating GameServer around retained data"
kube_bounded 70 delete gameserver "$server_name" --namespace "$namespace" --wait=true --timeout=60s >/dev/null
assert_runtime_absent "$server_name"
assert_pvc_identity "$pvc_uid" "$pv_name"
verify_marker_while_stopped
sed -e 's/desiredState: Stopped/desiredState: Running/' \
  -e 's/seed: first-seed/seed: third-seed/' \
  -e 's/motd: first-message/motd: recreated-message/' \
  "$workspace/server.yaml" >"$workspace/recreated-server.yaml"
kube apply --filename "$workspace/recreated-server.yaml" >/dev/null
new_server_uid=$(kube get gameserver "$server_name" --namespace "$namespace" --output=jsonpath='{.metadata.uid}')
[[ "$new_server_uid" != "$server_uid" ]] || die "recreated GameServer did not receive a new UID"
wait_present deployment "$server_name" 60
kube_bounded 100 rollout status deployment/"$server_name" --namespace "$namespace" --timeout=90s >/dev/null
patch_player_service "$server_name" >/dev/null
wait_server "$server_name" Ready Ready 90
state=$(probe_state "$server_name")
grep -Fxq 'marker=first-seed' <<<"$state" || die "GameServer recreation changed retained marker"
grep -Fxq 'seed=third-seed' <<<"$state" || die "GameServer recreation did not apply current settings"
assert_pvc_identity "$pvc_uid" "$pv_name"

say "proving a last-stage foreign Service collision causes zero partial mutation"
cat >"$workspace/collision-service.yaml" <<EOF
apiVersion: v1
kind: Service
metadata:
  name: $collision_name
  namespace: $namespace
  labels:
    arcade.gobha.me/foreign-sentinel: untouched
spec:
  selector:
    arcade.gobha.me/foreign-sentinel: untouched
  ports:
    - name: foreign
      protocol: TCP
      port: 9999
      targetPort: 9999
EOF
kube apply --filename "$workspace/collision-service.yaml" >/dev/null
foreign_before=$(kube get service "$collision_name" --namespace "$namespace" \
  --output=jsonpath='{.metadata.uid}|{.metadata.resourceVersion}|{.metadata.generation}|{.metadata.labels}|{.metadata.annotations}|{.metadata.finalizers}|{.metadata.ownerReferences}|{.spec}')

cat >"$workspace/collision-server.yaml" <<EOF
apiVersion: arcade.gobha.me/v1alpha1
kind: GameServer
metadata:
  name: $collision_name
  namespace: $namespace
spec:
  game: conformance-echo
  imageDigest: $synthetic_digest
  desiredState: Running
  compute:
    cpuRequest: 10m
    cpuLimit: 100m
    memoryRequest: 16Mi
    memoryLimit: 64Mi
  storage:
    size: 64Mi
    storageClassName: ""
  settings:
    seed: collision-seed
    motd: collision-message
EOF
kube apply --filename "$workspace/collision-server.yaml" >/dev/null
wait_server "$collision_name" Failed ResourceCollision 90
foreign_after=$(kube get service "$collision_name" --namespace "$namespace" \
  --output=jsonpath='{.metadata.uid}|{.metadata.resourceVersion}|{.metadata.generation}|{.metadata.labels}|{.metadata.annotations}|{.metadata.finalizers}|{.metadata.ownerReferences}|{.spec}')
[[ "$foreign_after" == "$foreign_before" ]] || die "foreign Service changed during collision: $foreign_before -> $foreign_after"
for identity in \
  "persistentvolumeclaim/$collision_name-conformance-echo-state" \
  "configmap/$collision_name-configuration" \
  "deployment/$collision_name"; do
  assert_absent "$identity"
done
kube_bounded 70 delete gameserver "$collision_name" --namespace "$namespace" --wait=true --timeout=60s >/dev/null
kube_bounded 70 delete service "$collision_name" --namespace "$namespace" --wait=true --timeout=60s >/dev/null

say "stopping and safely uninstalling the controller"
kube patch gameserver "$server_name" --namespace "$namespace" --type=merge --patch '{"spec":{"desiredState":"Stopped"}}' >/dev/null
wait_server "$server_name" Stopped RuntimeStopped 90
assert_runtime_absent "$server_name"
assert_pvc_identity "$pvc_uid" "$pv_name"
verify_marker_while_stopped
run_bounded 120 env KUBECTL="$kubectl_wrapper" "$repository_root/hack/uninstall.sh"
wait_absent deployment arcadectl-controller 60
wait_selector_absent replicasets app.kubernetes.io/name=arcadectl-controller 60
wait_selector_absent pods app.kubernetes.io/name=arcadectl-controller 60
kube get namespace "$namespace" >/dev/null
kube get customresourcedefinition gameservers.arcade.gobha.me >/dev/null
kube get gameserver "$server_name" --namespace "$namespace" >/dev/null
assert_pvc_identity "$pvc_uid" "$pv_name"

say "isolated lifecycle proof passed (source_head=$candidate_sha source_dirty=$source_dirty)"
