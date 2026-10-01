#!/usr/bin/env bash
# Copyright 2026 gobha-me
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail
umask 077

readonly kind_version=v0.33.0
readonly kind_node_image='kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5'
readonly kubectl_image='registry.k8s.io/kubectl@sha256:5ed410ebac5dc976cc717098994dcdb29bbbd38f6bd65f582311f5be4ba719cf'
readonly registry_image='registry:3.0.0@sha256:6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e'
readonly restic_inspector_image='restic/restic@sha256:39d9072fb5651c80d75c7a811612eb60b4c06b32ffe87c2e9f3c7222e1797e76'
readonly lifecycle_suite="${ARCADECTL_LIFECYCLE_SUITE:-synthetic}"
case "$lifecycle_suite" in
  synthetic|factorio) ;;
  *) printf 'error: unsupported lifecycle suite: %s\n' "$lifecycle_suite" >&2; exit 2 ;;
esac
readonly namespace=arcadectl-system
readonly server_name=lifecycle
if [[ "$lifecycle_suite" == factorio ]]; then
  readonly claim_name=lifecycle-factorio-world
else
  readonly claim_name=lifecycle-conformance-echo-state
fi
readonly collision_name=collision

readonly repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workspace=$(mktemp -d "${TMPDIR:-/tmp}/arcadectl-kind-lifecycle.XXXXXX")
readonly workspace
run_suffix=$(basename "$workspace" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9' | tail -c 12)
readonly run_suffix
readonly run_id="$lifecycle_suite-lifecycle-$run_suffix"
readonly cluster_name="arcadectl-$lifecycle_suite-$run_suffix"
readonly registry_name="$cluster_name-registry"
readonly kubeconfig="$workspace/kubeconfig"
readonly ownership_file="$workspace/ownership"
readonly kubectl_wrapper="$workspace/kubectl"
if [[ "$lifecycle_suite" == factorio ]]; then
  readonly artifact_root="${ARCADECTL_E2E_ARTIFACT_ROOT:-$repository_root/artifacts/factorio-lifecycle}"
else
  readonly artifact_root="${ARCADECTL_E2E_ARTIFACT_ROOT:-$repository_root/artifacts/kind-lifecycle}"
fi
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
minio_tag=
factorio_a_tag=
factorio_b_tag=
overlap_monitor_pid=

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
    [[ ! -L "$artifact_directory" && -d "$artifact_directory" ]] || {
      printf 'refusing unsafe existing diagnostics path: %s\n' "$artifact_directory" >&2
      return 1
    }
    grep -Fxq "$run_id" "$artifact_directory/.run-id" 2>/dev/null || {
      printf 'refusing unowned existing diagnostics path: %s\n' "$artifact_directory" >&2
      return 1
    }
  else
    mkdir "$artifact_directory" || return 1
    chmod 0700 "$artifact_directory"
    printf '%s\n' "$run_id" >"$artifact_directory/.run-id"
  fi
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
    printf 'controller_tag=%s\nsynthetic_tag=%s\nfactorio_a_tag=%s\nfactorio_b_tag=%s\n' \
      "$controller_tag" "$synthetic_tag" "$factorio_a_tag" "$factorio_b_tag"
    [[ -z "$controller_tag" ]] || docker image inspect "$controller_tag" --format 'controller_id={{.Id}} controller_digests={{json .RepoDigests}}' 2>/dev/null || true
    [[ -z "$synthetic_tag" ]] || docker image inspect "$synthetic_tag" --format 'synthetic_id={{.Id}} synthetic_digests={{json .RepoDigests}}' 2>/dev/null || true
    [[ -z "$factorio_a_tag" ]] || docker image inspect "$factorio_a_tag" --format 'factorio_a_id={{.Id}} factorio_a_digests={{json .RepoDigests}}' 2>/dev/null || true
    [[ -z "$factorio_b_tag" ]] || docker image inspect "$factorio_b_tag" --format 'factorio_b_id={{.Id}} factorio_b_digests={{json .RepoDigests}}' 2>/dev/null || true
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
    if [[ "$marker_status" -ne 0 || "$marker" != "$run_id" ]]; then
      return 1
    fi
  fi
  return 0
}

cleanup() {
  local cleanup_status=0 clusters current_nodes registry_names image_references
  set +e
  if [[ -n "$overlap_monitor_pid" ]]; then
    kill "$overlap_monitor_pid" >/dev/null 2>&1 || true
    wait "$overlap_monitor_pid" >/dev/null 2>&1 || true
    overlap_monitor_pid=
  fi
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
  if [[ -n "$minio_tag" ]] && grep -Fxq "$minio_tag" <<<"$image_references"; then
    docker image rm "$minio_tag" >/dev/null 2>&1 || cleanup_status=1
  fi
  if [[ -n "$factorio_a_tag" ]]; then
    if grep -Fxq "$factorio_a_tag" <<<"$image_references"; then
      docker image rm "$factorio_a_tag" >/dev/null 2>&1 || cleanup_status=1
    fi
  fi
  if [[ -n "$factorio_b_tag" ]]; then
    if grep -Fxq "$factorio_b_tag" <<<"$image_references"; then
      docker image rm "$factorio_b_tag" >/dev/null 2>&1 || cleanup_status=1
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
  if [[ -n "$minio_tag" ]] && grep -Fxq "$minio_tag" <<<"$image_references"; then
    printf 'task MinIO image tag still exists after cleanup: %s\n' "$minio_tag" >&2
    cleanup_status=1
  fi
  if [[ -n "$factorio_a_tag" ]] && grep -Fxq "$factorio_a_tag" <<<"$image_references"; then
    printf 'task Factorio A image tag still exists after cleanup: %s\n' "$factorio_a_tag" >&2
    cleanup_status=1
  fi
  if [[ -n "$factorio_b_tag" ]] && grep -Fxq "$factorio_b_tag" <<<"$image_references"; then
    printf 'task Factorio B image tag still exists after cleanup: %s\n' "$factorio_b_tag" >&2
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

for command in awk basename chmod cp curl date docker find git go grep head jq mktemp sed seq sha256sum sleep tail timeout touch tr; do
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
if [[ "$lifecycle_suite" == factorio ]]; then
  factorio_a_tag="$registry_host/gobha-me/arcadectl-factorio:$run_id-a"
  factorio_b_tag="$registry_host/gobha-me/arcadectl-factorio:$run_id-b"
else
  synthetic_tag="$registry_host/gobha-me/arcadectl-conformance-server:$run_id"
  minio_tag="$registry_host/arcadectl-minio-fixture:$run_id"
fi

controller_build_args=(
  --build-arg "VCS_REF=$candidate_sha"
  --build-arg "SOURCE_DATE_EPOCH=$source_date_epoch"
  --build-arg "SOURCE_DIRTY=$source_dirty"
)
if [[ "$lifecycle_suite" == synthetic ]]; then
  controller_build_args+=(--build-arg LIFECYCLE_TEST=true)
fi
say "building $lifecycle_suite controller image"
run_bounded 360 docker build "${controller_build_args[@]}" --tag "$controller_tag" "$repository_root"

if [[ "$lifecycle_suite" == factorio ]]; then
  say "building two immutable Factorio lifecycle variants"
  run_bounded 600 docker build \
    --file "$repository_root/images/factorio/Dockerfile" \
    --label arcade.gobha.me/lifecycle-variant=a \
    --tag "$factorio_a_tag" \
    "$repository_root/images/factorio"
  run_bounded 600 docker build \
    --file "$repository_root/images/factorio/Dockerfile" \
    --label arcade.gobha.me/lifecycle-variant=b \
    --tag "$factorio_b_tag" \
    "$repository_root/images/factorio"
else
  say "building synthetic lifecycle server image"
  run_bounded 360 docker build \
    --file "$repository_root/images/conformance/Dockerfile" \
    --build-arg "VCS_REF=$candidate_sha" \
    --build-arg "SOURCE_DATE_EPOCH=$source_date_epoch" \
    --build-arg "SOURCE_DIRTY=$source_dirty" \
    --tag "$synthetic_tag" \
    "$repository_root"
  say "building MinIO fixture from checksum-pinned official source"
  run_bounded 600 docker build \
    --file "$repository_root/images/minio-fixture/Dockerfile" \
    --tag "$minio_tag" "$repository_root/images/minio-fixture"
fi
run_bounded 120 docker push "$controller_tag" >/dev/null
if [[ "$lifecycle_suite" == factorio ]]; then
  run_bounded 240 docker push "$factorio_a_tag" >/dev/null
  run_bounded 240 docker push "$factorio_b_tag" >/dev/null
else
  run_bounded 120 docker push "$synthetic_tag" >/dev/null
  run_bounded 120 docker push "$minio_tag" >/dev/null
fi

resolve_digest() {
  local tag=$1 repository=${1%:*} reference
  reference=$(docker image inspect "$tag" --format '{{range .RepoDigests}}{{println .}}{{end}}' | grep -E "^${repository//./\\.}@sha256:[0-9a-f]{64}$" | head -n 1)
  [[ -n "$reference" ]] || return 1
  printf '%s\n' "${reference##*@}"
}

controller_digest=$(resolve_digest "$controller_tag") || die "controller registry digest is unavailable"
readonly controller_image="$registry_host/arcadectl-controller@$controller_digest"
if [[ "$lifecycle_suite" == factorio ]]; then
  factorio_a_digest=$(resolve_digest "$factorio_a_tag") || die "Factorio A registry digest is unavailable"
  factorio_b_digest=$(resolve_digest "$factorio_b_tag") || die "Factorio B registry digest is unavailable"
  [[ "$factorio_a_digest" != "$factorio_b_digest" ]] || die "Factorio lifecycle variants resolved to the same digest"
  readonly factorio_a_digest factorio_b_digest
  readonly factorio_a_image="ghcr.io/gobha-me/arcadectl-factorio@$factorio_a_digest"
  readonly factorio_b_image="ghcr.io/gobha-me/arcadectl-factorio@$factorio_b_digest"
else
  synthetic_digest=$(resolve_digest "$synthetic_tag") || die "synthetic registry digest is unavailable"
  readonly synthetic_digest
  readonly synthetic_image="ghcr.io/gobha-me/arcadectl-conformance-server@$synthetic_digest"
  minio_digest=$(resolve_digest "$minio_tag") || die "MinIO fixture registry digest is unavailable"
  readonly minio_image="$registry_host/arcadectl-minio-fixture@$minio_digest"
fi
readonly controller_digest

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
  if [[ "$lifecycle_suite" == factorio ]]; then
    run_bounded 240 docker exec "$node" ctr --namespace k8s.io images pull \
      --hosts-dir /etc/containerd/certs.d "$factorio_a_image" >/dev/null
    run_bounded 240 docker exec "$node" ctr --namespace k8s.io images pull \
      --hosts-dir /etc/containerd/certs.d "$factorio_b_image" >/dev/null
  else
    run_bounded 120 docker exec "$node" ctr --namespace k8s.io images pull \
      --hosts-dir /etc/containerd/certs.d "$synthetic_image" >/dev/null
  fi
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
    --output=jsonpath='{.metadata.uid}|{.spec.volumeName}|{.metadata.ownerReferences}|{.metadata.labels.arcade\.gobha\.me/data-identity}')
  [[ "$observed" == "$wanted_uid|$wanted_pv||$data_identity" ]] || die "retained PVC identity changed: $observed"
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

prove_backup_worker_admission_boundary() {
  local probe_name="backup-admission-$run_suffix"
  local denial_output= accepted=false
  cat >"$workspace/backup-admission-ungated.yaml" <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $probe_name
  namespace: $namespace
  labels:
    app.kubernetes.io/managed-by: arcadectl
    app.kubernetes.io/name: backup-worker
spec:
  restartPolicy: Never
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 65532
    runAsGroup: 65532
    seccompProfile: {type: RuntimeDefault}
  containers:
    - name: probe
      image: $controller_image
      command: ["/arcadectl-controller", "--help"]
      resources:
        requests: {cpu: 1m, memory: 8Mi}
        limits: {cpu: 10m, memory: 16Mi}
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities: {drop: [ALL]}
EOF
  local deadline=$((SECONDS + 30))
  while (( SECONDS < deadline )); do
    if ! denial_output=$(kube create --dry-run=server --filename "$workspace/backup-admission-ungated.yaml" 2>&1); then
      if grep -Fq 'must enter admission with exactly one execution gate' <<<"$denial_output"; then
        accepted=true
        break
      fi
      die "unexpected backup admission denial: $denial_output"
    fi
    sleep 1
  done
  [[ "$accepted" == true ]] || die "backup admission policy did not reject an ungated worker Pod"

  sed '/  containers:/i\  schedulingGates:\n    - name: arcade.gobha.me/backup-authorized' \
    "$workspace/backup-admission-ungated.yaml" >"$workspace/backup-admission-gated.yaml"
  kube create --filename "$workspace/backup-admission-gated.yaml" >/dev/null
  [[ $(kube get pod "$probe_name" --namespace "$namespace" --output=jsonpath='{.status.phase}|{.spec.nodeName}|{.spec.schedulingGates[0].name}') == "Pending||arcade.gobha.me/backup-authorized" ]] \
    || die "admission probe did not remain unscheduled behind the exact gate"

  if denial_output=$(kube set image "pod/$probe_name" 'probe=registry.invalid/forbidden:latest' --namespace "$namespace" 2>&1); then
    die "backup admission policy allowed executable Pod mutation"
  fi
  grep -Fq 'executable fields are immutable' <<<"$denial_output" \
    || die "unexpected executable-mutation denial: $denial_output"
  if denial_output=$(kube patch pod "$probe_name" --namespace "$namespace" --type=json --patch='[
    {"op":"add","path":"/metadata/annotations","value":{"arcade.gobha.me/backup-pod-authorized":"forged"}},
    {"op":"remove","path":"/spec/schedulingGates/0"}
  ]' 2>&1); then
    die "backup admission policy allowed a non-controller to remove the execution gate"
  fi
  grep -Fq 'Only the Arcadectl controller may authorize' <<<"$denial_output" \
    || die "unexpected gate-removal denial: $denial_output"
  kube delete pod "$probe_name" --namespace "$namespace" --wait=true >/dev/null
}

prove_storage_boundary() {
  local boundary_namespace="arcadectl-storage-boundary-$run_suffix"
  local boundary_class="arcadectl-storage-boundary-$run_suffix"
  local boundary_pv="arcadectl-storage-boundary-$run_suffix"
  cat >"$workspace/storage-boundary.yaml" <<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: $boundary_namespace
---
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: $boundary_class
provisioner: kubernetes.io/no-provisioner
volumeBindingMode: Immediate
---
apiVersion: v1
kind: PersistentVolume
metadata:
  name: $boundary_pv
spec:
  capacity: {storage: 8Mi}
  accessModes: [ReadWriteOnce]
  persistentVolumeReclaimPolicy: Retain
  storageClassName: $boundary_class
  hostPath:
    path: /var/arcadectl-storage-boundary/$run_id
    type: DirectoryOrCreate
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: retained
  namespace: $boundary_namespace
spec:
  accessModes: [ReadWriteOnce]
  storageClassName: $boundary_class
  volumeName: $boundary_pv
  resources:
    requests: {storage: 8Mi}
EOF
  say "proving StorageClass deletion, namespace deletion, and Retain reclaim boundaries"
  kube apply --filename "$workspace/storage-boundary.yaml" >/dev/null
  kube_bounded 70 wait persistentvolumeclaim/retained --namespace "$boundary_namespace" --for=jsonpath='{.status.phase}'=Bound --timeout=60s >/dev/null
  kube delete storageclass "$boundary_class" --wait=true >/dev/null
  [[ $(kube get persistentvolumeclaim retained --namespace "$boundary_namespace" --output=jsonpath='{.status.phase}|{.spec.volumeName}') == "Bound|$boundary_pv" ]] \
    || die "deleting a StorageClass changed its already-bound PVC"
  [[ $(kube get persistentvolume "$boundary_pv" --output=jsonpath='{.status.phase}|{.spec.persistentVolumeReclaimPolicy}') == 'Bound|Retain' ]] \
    || die "storage-boundary PV lost its Retain contract before namespace deletion"
  kube_bounded 70 delete namespace "$boundary_namespace" --wait=true --timeout=60s >/dev/null
  kube_bounded 70 wait persistentvolume/"$boundary_pv" --for=jsonpath='{.status.phase}'=Released --timeout=60s >/dev/null
  [[ $(kube get persistentvolume "$boundary_pv" --output=jsonpath='{.spec.persistentVolumeReclaimPolicy}') == Retain ]] \
    || die "namespace deletion did not preserve the Retain-policy PV"
  kube delete persistentvolume "$boundary_pv" --wait=true >/dev/null
  [[ -z $(kube get namespace "$boundary_namespace" --ignore-not-found --output=name) ]] || die "storage-boundary namespace remained"
  [[ -z $(kube get storageclass "$boundary_class" --ignore-not-found --output=name) ]] || die "storage-boundary StorageClass remained"
  [[ -z $(kube get persistentvolume "$boundary_pv" --ignore-not-found --output=name) ]] || die "storage-boundary PV remained"
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

run_factorio_lifecycle() {
  local verifier_image='busybox@sha256:9db7b59979c38555a39def84a31fb98b5296952f9e3afd4f6f11f05b07adfab0'
  local invalid_name=invalid-factorio
  local transition_name transition_started transition_finished
  local transitions_file="$workspace/transitions.tsv"
  printf 'transition\tstarted_epoch\tfinished_epoch\tduration_seconds\tresult\n' >"$transitions_file"

  begin_transition() {
    transition_name=$1
    transition_started=$(date +%s)
  }

  end_transition() {
    transition_finished=$(date +%s)
    printf '%s\t%s\t%s\t%s\tpassed\n' "$transition_name" "$transition_started" "$transition_finished" "$((transition_finished - transition_started))" >>"$transitions_file"
  }

  patch_factorio_service() {
    local cluster_ip=
    for _ in $(seq 1 60); do
      cluster_ip=$(kube get service "$server_name" --namespace "$namespace" --output=jsonpath='{.spec.clusterIP}' 2>/dev/null || true)
      [[ "$cluster_ip" =~ ^[0-9a-fA-F:.]+$ ]] && break
      sleep 1
    done
    [[ "$cluster_ip" =~ ^[0-9a-fA-F:.]+$ ]] || die "Factorio Service did not receive a ClusterIP"
    kube patch service "$server_name" --namespace "$namespace" --subresource=status --type=merge \
      --patch "{\"status\":{\"loadBalancer\":{\"ingress\":[{\"ip\":\"$cluster_ip\",\"ports\":[{\"port\":34197,\"protocol\":\"UDP\"}]}]}}}" >/dev/null
    printf '%s\n' "$cluster_ip"
  }

  assert_factorio_image() {
    local wanted_image=$1 wanted_digest=$2 output count image image_id
    output=$(kube get pods --namespace "$namespace" \
      --selector="app.kubernetes.io/name=game-server,app.kubernetes.io/instance=$server_name" \
      --output=jsonpath='{range .items[*]}{.spec.containers[?(@.name=="game")].image}|{.status.containerStatuses[?(@.name=="game")].imageID}{"\n"}{end}')
    count=$(awk 'NF { count++ } END { print count + 0 }' <<<"$output")
    [[ "$count" -eq 1 ]] || die "expected exactly one Factorio Pod, observed $count"
    IFS='|' read -r image image_id <<<"$output"
    [[ "$image" == "$wanted_image" ]] || die "Factorio Pod image is not the intended digest: $image"
    [[ "$image_id" == *"$wanted_digest"* ]] || die "Factorio Pod imageID does not prove the intended digest: $image_id"
  }

  assert_factorio_workload_contract() {
    local expected
    expected=$(kube get deployment "$server_name" --namespace "$namespace" \
      --output=jsonpath='{.spec.strategy.type}|{.spec.template.spec.securityContext.runAsUser}|{.spec.template.spec.securityContext.runAsGroup}|{.spec.template.spec.securityContext.fsGroup}|{.spec.template.spec.containers[?(@.name=="game")].ports[0].name}|{.spec.template.spec.containers[?(@.name=="game")].ports[0].protocol}|{.spec.template.spec.containers[?(@.name=="game")].ports[0].containerPort}')
    [[ "$expected" == 'Recreate|845|845|845|game|UDP|34197' ]] || die "unexpected Factorio workload contract: $expected"
    expected=$(kube get service "$server_name" --namespace "$namespace" \
      --output=jsonpath='{range .spec.ports[*]}{.name}|{.protocol}|{.port}{"\n"}{end}')
    [[ "$expected" == 'game|UDP|34197' ]] || die "Factorio Service exposed an unexpected endpoint: $expected"
    ! grep -Fqi rcon <<<"$expected" || die "Factorio Service exposed administrator RCON"
  }

  verify_factorio_storage() {
    kube_bounded 40 delete pod factorio-storage-verifier --namespace "$namespace" --ignore-not-found --wait=true --timeout=30s >/dev/null
    cat >"$workspace/factorio-verifier.yaml" <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: factorio-storage-verifier
  namespace: $namespace
  labels:
    arcade.gobha.me/e2e-run: $run_id
spec:
  restartPolicy: Never
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 845
    runAsGroup: 845
    fsGroup: 845
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: verifier
      image: $verifier_image
      imagePullPolicy: IfNotPresent
      command: ["/bin/sh", "-ec"]
      args:
        - |
          test "\$(cat /factorio/.arcadectl-world-id)" = "$run_id"
          set -- /factorio/saves/*.zip
          test -s "\$1"
          test "\$(stat -c '%u:%g' "\$1")" = "845:845"
          test "\$(stat -c '%u:%g' /factorio/config/server-settings.json)" = "845:845"
          grep -Fq '"name": "Arcadectl lifecycle proof"' /factorio/config/server-settings.json
          printf 'world-identity=preserved\nsave=present\nownership=845:845\n'
      resources:
        requests: {cpu: 5m, memory: 8Mi}
        limits: {cpu: 50m, memory: 32Mi}
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities: {drop: ["ALL"]}
      volumeMounts:
        - name: world
          mountPath: /factorio
          readOnly: true
  volumes:
    - name: world
      persistentVolumeClaim:
        claimName: $claim_name
EOF
    kube apply --filename "$workspace/factorio-verifier.yaml" >/dev/null
    wait_pod_phase factorio-storage-verifier Succeeded 90
    [[ $(kube logs factorio-storage-verifier --namespace "$namespace") == $'world-identity=preserved\nsave=present\nownership=845:845' ]] \
      || die "Factorio storage verifier returned unexpected evidence"
    kube_bounded 70 delete pod factorio-storage-verifier --namespace "$namespace" --wait=true --timeout=60s >/dev/null
  }

  create_factorio_server_manifest() {
    local digest=$1 desired=$2 destination=$3 retained_identity=${4:-} retained_uid=${5:-} reattach_block=
    if [[ -n "$retained_identity" ]]; then
      printf -v reattach_block '    reattach:\n      identity: %s\n      claims:\n        - path: world\n          claimRef:\n            name: %s\n            uid: %s\n' \
        "$retained_identity" "$claim_name" "$retained_uid"
    fi
    cat >"$destination" <<EOF
apiVersion: arcade.gobha.me/v1alpha1
kind: GameServer
metadata:
  name: $server_name
  namespace: $namespace
spec:
  game: factorio
  imageDigest: $digest
  desiredState: $desired
  compute:
    cpuRequest: 100m
    cpuLimit: "2"
    memoryRequest: 256Mi
    memoryLimit: 2Gi
  storage:
    size: 512Mi
    storageClassName: ""
$reattach_block  settings:
    name: Arcadectl lifecycle proof
    description: Isolated non-public lifecycle evidence
    maxPlayers: 4
    visibility: private
EOF
  }

  cat >"$workspace/invalid-factorio.yaml" <<EOF
apiVersion: arcade.gobha.me/v1alpha1
kind: GameServer
metadata:
  name: $invalid_name
  namespace: $namespace
spec:
  game: factorio
  imageDigest: $factorio_a_digest
  desiredState: Running
  compute: {cpuRequest: 100m, cpuLimit: "1", memoryRequest: 128Mi, memoryLimit: 1Gi}
  storage: {size: 512Mi, storageClassName: ""}
  settings: {name: Invalid proof, visibility: public}
EOF
  say "proving bounded Factorio validation failure before child mutation"
  begin_transition invalid-spec
  kube apply --filename "$workspace/invalid-factorio.yaml" >/dev/null
  wait_server "$invalid_name" Failed InvalidSpec 90
  invalid_message=$(kube get gameserver "$invalid_name" --namespace "$namespace" --output=jsonpath='{.status.conditions[?(@.type=="SpecValid")].message}')
  [[ "$invalid_message" == 'settings are invalid; correct them to match the selected game adapter schema and rendering limits' ]] \
    || die "invalid settings status was not bounded and actionable: $invalid_message"
  for identity in \
    "persistentvolumeclaim/$invalid_name-factorio-world" \
    "configmap/$invalid_name-configuration" \
    "deployment/$invalid_name" \
    "service/$invalid_name"; do
    assert_absent "$identity"
  done
  kube_bounded 70 delete gameserver "$invalid_name" --namespace "$namespace" --wait=true --timeout=60s >/dev/null
  end_transition

  cat >"$workspace/factorio-pv.yaml" <<EOF
apiVersion: v1
kind: PersistentVolume
metadata:
  name: arcadectl-factorio-world-$run_suffix
  labels:
    arcade.gobha.me/e2e-run: $run_id
spec:
  capacity: {storage: 512Mi}
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
    run_bounded 10 docker exec "$node" install -d -o 845 -g 845 -m 0770 "/var/arcadectl-e2e/$run_id"
    printf '%s\n' "$run_id" | run_bounded 10 docker exec --interactive "$node" sh -c \
      "umask 077; cat > '/var/arcadectl-e2e/$run_id/.arcadectl-world-id'; chown 845:845 '/var/arcadectl-e2e/$run_id/.arcadectl-world-id'"
  done <<<"$node_names"
  kube apply --filename "$workspace/factorio-pv.yaml" >/dev/null
  create_factorio_server_manifest "$factorio_a_digest" Stopped "$workspace/factorio-server.yaml"

  say "creating stopped Factorio server and binding retained world"
  begin_transition create-stopped
  kube apply --filename "$workspace/factorio-server.yaml" >/dev/null
  kube_bounded 130 wait persistentvolumeclaim/"$claim_name" --namespace "$namespace" --for=jsonpath='{.status.phase}'=Bound --timeout=120s >/dev/null
  wait_server "$server_name" Stopped RuntimeStopped 120
  assert_runtime_absent "$server_name"
  pvc_uid=$(kube get persistentvolumeclaim "$claim_name" --namespace "$namespace" --output=jsonpath='{.metadata.uid}')
  pv_name=$(kube get persistentvolumeclaim "$claim_name" --namespace "$namespace" --output=jsonpath='{.spec.volumeName}')
  data_identity=$(kube get persistentvolumeclaim "$claim_name" --namespace "$namespace" --output=jsonpath='{.metadata.labels.arcade\.gobha\.me/data-identity}')
  server_uid=$(kube get gameserver "$server_name" --namespace "$namespace" --output=jsonpath='{.metadata.uid}')
  [[ -n "$pvc_uid" && -n "$data_identity" && "$pv_name" == "arcadectl-factorio-world-$run_suffix" ]] || die "Factorio PVC identity is incomplete"
  assert_pvc_identity "$pvc_uid" "$pv_name"
  assert_controller_image
  end_transition

  say "starting the certified Factorio runtime"
  begin_transition start
  kube patch gameserver "$server_name" --namespace "$namespace" --type=merge --patch '{"spec":{"desiredState":"Running"}}' >/dev/null
  wait_present deployment "$server_name" 90
  kube_bounded 250 rollout status deployment/"$server_name" --namespace "$namespace" --timeout=240s >/dev/null
  factorio_address=$(patch_factorio_service)
  wait_server "$server_name" Ready Ready 120
  factorio_endpoint=$(kube get gameserver "$server_name" --namespace "$namespace" --output=jsonpath='{.status.endpoints[0].name}|{.status.endpoints[0].protocol}|{.status.endpoints[0].address}|{.status.endpoints[0].port}')
  [[ "$factorio_endpoint" == "game|UDP|$factorio_address|34197" ]] || die "unexpected Factorio endpoint: $factorio_endpoint"
  assert_factorio_workload_contract
  assert_factorio_image "$factorio_a_image" "$factorio_a_digest"
  initial_game_pod_uid=$(kube get pods --namespace "$namespace" --selector="app.kubernetes.io/instance=$server_name" --output=jsonpath='{.items[0].metadata.uid}')
  end_transition

  say "stopping Factorio and verifying its real save from a separate read-only Pod"
  begin_transition stop
  kube patch gameserver "$server_name" --namespace "$namespace" --type=merge --patch '{"spec":{"desiredState":"Stopped"}}' >/dev/null
  wait_server "$server_name" Stopped RuntimeStopped 120
  assert_runtime_absent "$server_name"
  assert_pvc_identity "$pvc_uid" "$pv_name"
  verify_factorio_storage
  end_transition

  say "starting Factorio again from retained data"
  begin_transition restart
  kube patch gameserver "$server_name" --namespace "$namespace" --type=merge --patch '{"spec":{"desiredState":"Running"}}' >/dev/null
  wait_present deployment "$server_name" 90
  kube_bounded 250 rollout status deployment/"$server_name" --namespace "$namespace" --timeout=240s >/dev/null
  patch_factorio_service >/dev/null
  wait_server "$server_name" Ready Ready 120
  restarted_game_pod_uid=$(kube get pods --namespace "$namespace" --selector="app.kubernetes.io/instance=$server_name" --output=jsonpath='{.items[0].metadata.uid}')
  [[ "$restarted_game_pod_uid" != "$initial_game_pod_uid" ]] || die "Factorio restart did not replace the Pod"
  assert_factorio_image "$factorio_a_image" "$factorio_a_digest"
  end_transition

  say "updating Factorio by immutable digest with overlap monitoring"
  begin_transition image-update
  overlap_file="$workspace/max-running-factorio-containers"
  overlap_stop="$workspace/stop-overlap-monitor"
  overlap_ready="$workspace/overlap-monitor-ready"
  (
    maximum=0
    while [[ ! -e "$overlap_stop" ]]; do
      running=$(kube get pods --namespace "$namespace" --selector="app.kubernetes.io/instance=$server_name" \
        --output=jsonpath='{range .items[*]}{.status.containerStatuses[?(@.name=="game")].state.running.startedAt}{"\n"}{end}' 2>/dev/null \
        | awk 'NF { count++ } END { print count + 0 }')
      if (( running > maximum )); then
        maximum=$running
      fi
      touch "$overlap_ready"
      sleep 1
    done
    printf '%s\n' "$maximum" >"$overlap_file"
  ) &
  overlap_monitor_pid=$!
  for _ in $(seq 1 10); do
    [[ -e "$overlap_ready" ]] && break
    sleep 1
  done
  [[ -e "$overlap_ready" ]] || die "Factorio overlap monitor did not start"
  kube patch gameserver "$server_name" --namespace "$namespace" --type=merge \
    --patch "{\"spec\":{\"imageDigest\":\"$factorio_b_digest\"}}" >/dev/null
  kube_bounded 310 rollout status deployment/"$server_name" --namespace "$namespace" --timeout=300s >/dev/null
  patch_factorio_service >/dev/null
  wait_server "$server_name" Ready Ready 120
  touch "$overlap_stop"
  wait "$overlap_monitor_pid"
  overlap_monitor_pid=
  max_running_factorio=$(cat "$overlap_file")
  [[ "$max_running_factorio" == 1 ]] || die "Factorio image update observed $max_running_factorio running game containers; expected exactly one maximum"
  updated_game_pod_uid=$(kube get pods --namespace "$namespace" --selector="app.kubernetes.io/instance=$server_name" --output=jsonpath='{.items[0].metadata.uid}')
  [[ "$updated_game_pod_uid" != "$restarted_game_pod_uid" ]] || die "Factorio image update did not replace the Pod"
  assert_factorio_workload_contract
  assert_factorio_image "$factorio_b_image" "$factorio_b_digest"
  assert_pvc_identity "$pvc_uid" "$pv_name"
  end_transition

  say "redeploying the controller without replacing Factorio"
  begin_transition controller-redeploy
  old_controller_name=$(kube get pods --namespace "$namespace" --selector=app.kubernetes.io/name=arcadectl-controller --output=jsonpath='{.items[0].metadata.name}')
  old_controller_uid=$(kube get pod "$old_controller_name" --namespace "$namespace" --output=jsonpath='{.metadata.uid}')
  stable_game_pod_uid=$(kube get pods --namespace "$namespace" --selector="app.kubernetes.io/instance=$server_name" --output=jsonpath='{.items[0].metadata.uid}')
  kube rollout restart deployment/arcadectl-controller --namespace "$namespace" >/dev/null
  kube_bounded 130 wait pod/"$old_controller_name" --namespace "$namespace" --for=delete --timeout=120s >/dev/null
  kube_bounded 190 rollout status deployment/arcadectl-controller --namespace "$namespace" --timeout=180s >/dev/null
  new_controller_uid=$(kube get pods --namespace "$namespace" --selector=app.kubernetes.io/name=arcadectl-controller --output=jsonpath='{.items[0].metadata.uid}')
  [[ "$new_controller_uid" != "$old_controller_uid" ]] || die "controller redeploy did not replace its Pod"
  [[ $(kube get pods --namespace "$namespace" --selector="app.kubernetes.io/instance=$server_name" --output=jsonpath='{.items[0].metadata.uid}') == "$stable_game_pod_uid" ]] \
    || die "controller redeploy unnecessarily replaced Factorio"
  wait_server "$server_name" Ready Ready 120
  assert_controller_image
  end_transition

  say "deleting and recreating Factorio around the retained world"
  begin_transition gameserver-recreation
  kube_bounded 100 delete gameserver "$server_name" --namespace "$namespace" --wait=true --timeout=90s >/dev/null
  assert_runtime_absent "$server_name"
  assert_pvc_identity "$pvc_uid" "$pv_name"
  verify_factorio_storage
  create_factorio_server_manifest "$factorio_b_digest" Running "$workspace/recreated-factorio-server.yaml"
  kube apply --filename "$workspace/recreated-factorio-server.yaml" >/dev/null
  naive_server_uid=$(kube get gameserver "$server_name" --namespace "$namespace" --output=jsonpath='{.metadata.uid}')
  [[ "$naive_server_uid" != "$server_uid" ]] || die "naive Factorio recreation did not receive a new UID"
  wait_server "$server_name" Failed RetainedDataReferenceRequired 90
  assert_runtime_absent "$server_name"
  assert_pvc_identity "$pvc_uid" "$pv_name"
  verify_factorio_storage
  kube_bounded 70 delete gameserver "$server_name" --namespace "$namespace" --wait=true --timeout=60s >/dev/null
  create_factorio_server_manifest "$factorio_b_digest" Running "$workspace/recreated-factorio-server.yaml" "$data_identity" "$pvc_uid"
  kube apply --filename "$workspace/recreated-factorio-server.yaml" >/dev/null
  new_server_uid=$(kube get gameserver "$server_name" --namespace "$namespace" --output=jsonpath='{.metadata.uid}')
  [[ "$new_server_uid" != "$server_uid" && "$new_server_uid" != "$naive_server_uid" ]] || die "exact Factorio recreation did not receive a new UID"
  wait_present deployment "$server_name" 90
  kube_bounded 250 rollout status deployment/"$server_name" --namespace "$namespace" --timeout=240s >/dev/null
  patch_factorio_service >/dev/null
  wait_server "$server_name" Ready Ready 120
  assert_factorio_image "$factorio_b_image" "$factorio_b_digest"
  assert_pvc_identity "$pvc_uid" "$pv_name"
  factorio_runtime_image_id=$(kube get pods --namespace "$namespace" --selector="app.kubernetes.io/instance=$server_name" \
    --output=jsonpath='{.items[0].status.containerStatuses[?(@.name=="game")].imageID}')
  controller_runtime_image_id=$(kube get pods --namespace "$namespace" --selector=app.kubernetes.io/name=arcadectl-controller \
    --output=jsonpath='{.items[0].status.containerStatuses[?(@.name=="controller")].imageID}')
  end_transition

  say "stopping Factorio, recording evidence, and safely uninstalling"
  begin_transition final-stop-and-uninstall
  kube patch gameserver "$server_name" --namespace "$namespace" --type=merge --patch '{"spec":{"desiredState":"Stopped"}}' >/dev/null
  wait_server "$server_name" Stopped RuntimeStopped 120
  assert_runtime_absent "$server_name"
  assert_pvc_identity "$pvc_uid" "$pv_name"
  verify_factorio_storage
  wait_selector_absent jobs arcade.gobha.me/data-operation 60
  wait_selector_absent pods arcade.gobha.me/data-operation 60
  wait_selector_absent leases arcade.gobha.me/data-identity 60
  run_bounded 120 env KUBECTL="$kubectl_wrapper" "$repository_root/hack/uninstall.sh"
  wait_absent deployment arcadectl-controller 60
  wait_selector_absent replicasets app.kubernetes.io/name=arcadectl-controller 60
  wait_selector_absent pods app.kubernetes.io/name=arcadectl-controller 60
  kube get validatingadmissionpolicy arcadectl-backup-worker-gate >/dev/null
  kube get validatingadmissionpolicybinding arcadectl-backup-worker-gate >/dev/null
  kube get namespace "$namespace" >/dev/null
  kube get customresourcedefinition gameservers.arcade.gobha.me >/dev/null
  kube get gameserver "$server_name" --namespace "$namespace" >/dev/null
  assert_pvc_identity "$pvc_uid" "$pv_name"
  end_transition

  mkdir -p "$artifact_root"
  [[ ! -e "$artifact_directory" && ! -L "$artifact_directory" ]] || die "refusing to overwrite Factorio evidence path: $artifact_directory"
  mkdir "$artifact_directory"
  chmod 0700 "$artifact_directory"
  printf '%s\n' "$run_id" >"$artifact_directory/.run-id"
  cp "$transitions_file" "$artifact_directory/transitions.tsv"
  {
    printf 'run_id=%s\ncluster=%s\ncandidate_sha=%s\nsource_dirty=%s\n' "$run_id" "$cluster_name" "$candidate_sha" "$source_dirty"
    printf 'kind_node_image=%s\nkubectl_image=%s\nregistry_image=%s\n' "$kind_node_image" "$kubectl_image" "$registry_image"
    printf 'controller_image=%s\nfactorio_image_a=%s\nfactorio_image_b=%s\n' "$controller_image" "$factorio_a_image" "$factorio_b_image"
    printf 'controller_runtime_image_id=%s\nfactorio_runtime_image_id=%s\n' "$controller_runtime_image_id" "$factorio_runtime_image_id"
    printf 'pvc_uid=%s\npv_name=%s\ndata_identity=%s\ninitial_gameserver_uid=%s\nrecreated_gameserver_uid=%s\n' "$pvc_uid" "$pv_name" "$data_identity" "$server_uid" "$new_server_uid"
    printf 'initial_game_pod_uid=%s\nrestarted_game_pod_uid=%s\nupdated_game_pod_uid=%s\nmax_running_factorio_containers=%s\n' \
      "$initial_game_pod_uid" "$restarted_game_pod_uid" "$updated_game_pod_uid" "$max_running_factorio"
  } >"$artifact_directory/evidence.txt"
  kube get gameserver "$server_name" --namespace "$namespace" \
    --output='custom-columns=NAME:.metadata.name,GEN:.metadata.generation,OBSERVED:.status.observedGeneration,DESIRED:.spec.desiredState,PHASE:.status.phase,READY:.status.conditions[?(@.type=="Ready")].reason' \
    >"$artifact_directory/gameserver.txt"
  {
    go tool kind version
    docker version --format 'docker_client={{.Client.Version}} docker_server={{.Server.Version}}'
    kube version --output=json
  } >"$artifact_directory/tools-and-cluster.txt"
  find "$artifact_directory" -type f -exec chmod 0600 {} +
  say "certified Factorio lifecycle proof passed (source_head=$candidate_sha source_dirty=$source_dirty evidence=$artifact_directory)"
}

say "proving backup worker admission cannot be bypassed"
prove_backup_worker_admission_boundary
prove_storage_boundary

if [[ "$lifecycle_suite" == factorio ]]; then
  run_factorio_lifecycle
  exit 0
fi

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
data_identity=$(kube get persistentvolumeclaim "$claim_name" --namespace "$namespace" --output=jsonpath='{.metadata.labels.arcade\.gobha\.me/data-identity}')
server_uid=$(kube get gameserver "$server_name" --namespace "$namespace" --output=jsonpath='{.metadata.uid}')
readonly pvc_uid pv_name data_identity server_uid
[[ -n "$pvc_uid" && -n "$data_identity" && "$pv_name" == "arcadectl-e2e-world-$run_suffix" ]] || die "retained PVC identity is incomplete"
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
naive_server_uid=$(kube get gameserver "$server_name" --namespace "$namespace" --output=jsonpath='{.metadata.uid}')
[[ "$naive_server_uid" != "$server_uid" ]] || die "naive recreation did not receive a new UID"
wait_server "$server_name" Failed RetainedDataReferenceRequired 60
assert_runtime_absent "$server_name"
assert_pvc_identity "$pvc_uid" "$pv_name"
verify_marker_while_stopped
kube_bounded 70 delete gameserver "$server_name" --namespace "$namespace" --wait=true --timeout=60s >/dev/null
awk -v identity="$data_identity" -v claim="$claim_name" -v uid="$pvc_uid" '
  { print }
  /^    storageClassName:/ {
    print "    reattach:"
    print "      identity: " identity
    print "      claims:"
    print "        - path: state"
    print "          claimRef:"
    print "            name: " claim
    print "            uid: " uid
  }
' "$workspace/recreated-server.yaml" >"$workspace/exact-recreated-server.yaml"
kube apply --filename "$workspace/exact-recreated-server.yaml" >/dev/null
new_server_uid=$(kube get gameserver "$server_name" --namespace "$namespace" --output=jsonpath='{.metadata.uid}')
[[ "$new_server_uid" != "$server_uid" && "$new_server_uid" != "$naive_server_uid" ]] || die "exact recreation did not receive a new UID"
wait_present deployment "$server_name" 60
kube_bounded 100 rollout status deployment/"$server_name" --namespace "$namespace" --timeout=90s >/dev/null
patch_player_service "$server_name" >/dev/null
wait_server "$server_name" Ready Ready 90
state=$(probe_state "$server_name")
grep -Fxq 'marker=first-seed' <<<"$state" || die "GameServer recreation changed retained marker"
grep -Fxq 'seed=third-seed' <<<"$state" || die "GameServer recreation did not apply current settings"
assert_pvc_identity "$pvc_uid" "$pv_name"

wait_backup() {
  local name=$1 wanted_runtime=$2 seconds=$3 observed generation observed_generation phase verification runtime_phase
  local fence_generation server_generation server_desired
  local runtime_network_patched=false
  local deadline=$((SECONDS + seconds))
  while (( SECONDS < deadline )); do
    if [[ "$wanted_runtime" == Ready && "$runtime_network_patched" == false ]]; then
      fence_generation=$(kube get gamebackup "$name" --namespace "$namespace" --output=jsonpath='{.status.fence.gameServer.generation}' 2>/dev/null || true)
      IFS='|' read -r server_generation server_desired <<<"$(kube get gameserver "$server_name" --namespace "$namespace" \
        --output=jsonpath='{.metadata.generation}|{.spec.desiredState}' 2>/dev/null || true)"
      if [[ "$fence_generation" =~ ^[0-9]+$ && "$server_generation" =~ ^[0-9]+$ && \
        "$server_generation" -gt "$fence_generation" && "$server_desired" == Running ]] && \
        kube get service "$server_name" --namespace "$namespace" >/dev/null 2>&1; then
        patch_player_service "$server_name" >/dev/null
        runtime_network_patched=true
      fi
    fi
    observed=$(kube get gamebackup "$name" --namespace "$namespace" \
      --output=jsonpath='{.metadata.generation}|{.status.observedGeneration}|{.status.phase}|{.status.artifact.verification.result}|{.status.runtime.phase}' 2>/dev/null || true)
    IFS='|' read -r generation observed_generation phase verification runtime_phase <<<"$observed"
    if [[ -n "$generation" && "$generation" == "$observed_generation" && "$phase" == Succeeded && \
      "$verification" == Verified && "$runtime_phase" == "$wanted_runtime" ]]; then
      return 0
    fi
    sleep 2
  done
  printf 'timed out waiting for GameBackup %s; observed %s\n' "$name" "$observed" >&2
  return 1
}

assert_backup_artifact() {
  local name=$1 expected_runtime=$2 artifact
  artifact=$(kube get gamebackup "$name" --namespace "$namespace" \
    --output=jsonpath='{.status.source.gameServer.uid}|{.status.source.paths[0].name}|{.status.source.paths[0].claimRef.uid}|{.status.artifact.id}|{.status.artifact.manifestDigest}|{.status.artifact.pathCount}|{.status.artifact.verification.result}|{.status.runtime.phase}')
  IFS='|' read -r artifact_server_uid artifact_path artifact_claim_uid artifact_id artifact_digest artifact_paths artifact_verification artifact_runtime <<<"$artifact"
  [[ "$artifact_server_uid" == "$new_server_uid" ]] || die "$name recorded the wrong source GameServer UID"
  [[ "$artifact_path" == state && "$artifact_claim_uid" == "$pvc_uid" ]] || die "$name recorded the wrong retained path identity"
  [[ "$artifact_id" =~ ^backup-[0-9a-f]{64}$ ]] || die "$name did not publish a deterministic artifact ID"
  [[ "$artifact_digest" =~ ^sha256:[0-9a-f]{64}$ ]] || die "$name did not publish a canonical manifest digest"
  [[ "$artifact_paths" == 1 && "$artifact_verification" == Verified ]] || die "$name did not verify every declared path"
  [[ "$artifact_runtime" == "$expected_runtime" ]] || die "$name did not settle the requested runtime disposition"
}

assert_no_repository_credentials() {
  local canary
  for canary in "$repository_access_key" "$repository_secret_key" "$repository_password"; do
    if grep -Fq "$canary" "$@"; then
      die "repository credential canary escaped into public worker evidence or stored artifact"
    fi
  done
}

assert_worker_evidence_private() {
  local pod=$1 container=$2
  kube logs "$pod" --namespace "$namespace" --container="$container" \
    >"$workspace/worker-log" 2>"$workspace/worker-log-error" \
    || die "could not capture worker logs before cleanup"
  kube get pod "$pod" --namespace "$namespace" --output=json >"$workspace/worker-pod"
  assert_no_repository_credentials "$workspace/worker-log" "$workspace/worker-log-error" "$workspace/worker-pod"
}

say "starting isolated pinned MinIO for real cold-backup proof"
repository_secret_name=backup-repository
repository_access_key="access-$run_suffix"
repository_secret_key="object-$run_suffix-canary"
repository_password="restic-$run_suffix-canary"
cat >"$workspace/backup-repository.yaml" <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: $repository_secret_name
  namespace: $namespace
immutable: true
type: Opaque
stringData:
  repository: s3:http://minio:9000/arcadectl
  password: $repository_password
  awsAccessKeyID: $repository_access_key
  awsSecretAccessKey: $repository_secret_key
---
apiVersion: v1
kind: Service
metadata:
  name: minio
  namespace: $namespace
  labels:
    arcade.gobha.me/e2e-run: $run_id
spec:
  selector:
    arcade.gobha.me/e2e-component: minio
  ports:
    - name: s3
      port: 9000
      targetPort: s3
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: minio
  namespace: $namespace
spec:
  replicas: 1
  selector:
    matchLabels:
      arcade.gobha.me/e2e-component: minio
  template:
    metadata:
      labels:
        arcade.gobha.me/e2e-component: minio
        arcade.gobha.me/e2e-run: $run_id
    spec:
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        runAsGroup: 65532
        fsGroup: 65532
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: minio
          image: $minio_image
          imagePullPolicy: IfNotPresent
          args: ["server", "/data", "--address", ":9000"]
          env:
            - name: HOME
              value: /tmp
            - name: MINIO_BROWSER
              value: "off"
            - name: MINIO_ROOT_USER
              valueFrom:
                secretKeyRef:
                  name: $repository_secret_name
                  key: awsAccessKeyID
            - name: MINIO_ROOT_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: $repository_secret_name
                  key: awsSecretAccessKey
          ports:
            - name: s3
              containerPort: 9000
          readinessProbe:
            httpGet:
              path: /minio/health/cluster
              port: s3
          resources:
            requests:
              cpu: 50m
              memory: 128Mi
            limits:
              cpu: 500m
              memory: 512Mi
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
          volumeMounts:
            - name: data
              mountPath: /data
            - name: tmp
              mountPath: /tmp
      volumes:
        - name: data
          emptyDir:
            sizeLimit: 256Mi
        - name: tmp
          emptyDir:
            sizeLimit: 64Mi
EOF
kube apply --filename "$workspace/backup-repository.yaml" >/dev/null
kube_bounded 130 rollout status deployment/minio --namespace "$namespace" --timeout=120s >/dev/null

cat >"$workspace/restic-init.yaml" <<EOF
apiVersion: batch/v1
kind: Job
metadata:
  name: restic-init
  namespace: $namespace
  labels:
    arcade.gobha.me/e2e-run: $run_id
spec:
  backoffLimit: 1
  activeDeadlineSeconds: 120
  template:
    metadata:
      labels:
        arcade.gobha.me/e2e-run: $run_id
    spec:
      automountServiceAccountToken: false
      restartPolicy: Never
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        runAsGroup: 65532
        fsGroup: 65532
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: restic-init
          image: $controller_image
          imagePullPolicy: IfNotPresent
          command: ["/restic"]
          args: ["--no-cache", "--repo", "s3:http://minio:9000/arcadectl", "--password-file", "/credentials/password", "init"]
          env:
            - name: HOME
              value: /work
            - name: TMPDIR
              value: /work
            - name: RESTIC_CACHE_DIR
              value: /work/cache
            - name: AWS_ACCESS_KEY_ID
              valueFrom:
                secretKeyRef:
                  name: $repository_secret_name
                  key: awsAccessKeyID
            - name: AWS_SECRET_ACCESS_KEY
              valueFrom:
                secretKeyRef:
                  name: $repository_secret_name
                  key: awsSecretAccessKey
          resources:
            requests:
              cpu: 50m
              memory: 64Mi
            limits:
              cpu: 500m
              memory: 256Mi
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
          volumeMounts:
            - name: credentials
              mountPath: /credentials
              readOnly: true
            - name: work
              mountPath: /work
      volumes:
        - name: credentials
          secret:
            secretName: $repository_secret_name
            defaultMode: 0444
        - name: work
          emptyDir:
            sizeLimit: 64Mi
EOF
kube apply --filename "$workspace/restic-init.yaml" >/dev/null
kube_bounded 130 wait job/restic-init --namespace "$namespace" --for=condition=complete --timeout=120s >/dev/null
kube_bounded 70 delete job/restic-init --namespace "$namespace" --wait=true --timeout=60s >/dev/null

backup_utility_image='busybox@sha256:9db7b59979c38555a39def84a31fb98b5296952f9e3afd4f6f11f05b07adfab0'
cat >"$workspace/restic-seed.yaml" <<EOF
apiVersion: batch/v1
kind: Job
metadata:
  name: restic-seed
  namespace: $namespace
  labels:
    arcade.gobha.me/e2e-run: $run_id
spec:
  backoffLimit: 0
  activeDeadlineSeconds: 120
  template:
    metadata:
      labels:
        arcade.gobha.me/e2e-run: $run_id
    spec:
      automountServiceAccountToken: false
      restartPolicy: Never
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        runAsGroup: 65532
        fsGroup: 65532
        seccompProfile:
          type: RuntimeDefault
      initContainers:
        - name: seed
          image: $backup_utility_image
          imagePullPolicy: IfNotPresent
          command: ["/bin/sh", "-ec"]
          args: ["dd if=/dev/urandom of=/seed/payload.bin bs=1024 count=65536"]
          resources:
            requests: {cpu: 5m, memory: 8Mi}
            limits: {cpu: 50m, memory: 32Mi}
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: {drop: ["ALL"]}
          volumeMounts:
            - {name: seed, mountPath: /seed}
      containers:
        - name: restic-seed
          image: $controller_image
          imagePullPolicy: IfNotPresent
          command: ["/restic"]
          args: ["--no-cache", "--repo", "s3:http://minio:9000/arcadectl", "--password-file", "/credentials/password", "backup", "--quiet", "/seed/payload.bin"]
          env:
            - name: HOME
              value: /work
            - name: TMPDIR
              value: /work
            - name: RESTIC_CACHE_DIR
              value: /work/cache
            - name: AWS_ACCESS_KEY_ID
              valueFrom:
                secretKeyRef: {name: $repository_secret_name, key: awsAccessKeyID}
            - name: AWS_SECRET_ACCESS_KEY
              valueFrom:
                secretKeyRef: {name: $repository_secret_name, key: awsSecretAccessKey}
          resources:
            requests: {cpu: 25m, memory: 32Mi}
            limits: {cpu: 250m, memory: 128Mi}
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: {drop: ["ALL"]}
          volumeMounts:
            - {name: credentials, mountPath: /credentials, readOnly: true}
            - {name: work, mountPath: /work}
            - {name: seed, mountPath: /seed, readOnly: true}
      volumes:
        - name: credentials
          secret: {secretName: $repository_secret_name, defaultMode: 0444}
        - name: work
          emptyDir: {sizeLimit: 64Mi}
        - name: seed
          emptyDir: {sizeLimit: 80Mi}
EOF
kube apply --filename "$workspace/restic-seed.yaml" >/dev/null
kube_bounded 130 wait job/restic-seed --namespace "$namespace" --for=condition=complete --timeout=120s >/dev/null
kube_bounded 70 delete job/restic-seed --namespace "$namespace" --wait=true --timeout=60s >/dev/null

repository_uid=$(kube get secret "$repository_secret_name" --namespace "$namespace" --output=jsonpath='{.metadata.uid}')
repository_version=$(kube get secret "$repository_secret_name" --namespace "$namespace" --output=jsonpath='{.metadata.resourceVersion}')
running_generation=$(kube get gameserver "$server_name" --namespace "$namespace" --output=jsonpath='{.metadata.generation}')
[[ -n "$repository_uid" && -n "$repository_version" && -n "$running_generation" ]] || die "backup exact-reference inputs are incomplete"

cat >"$workspace/running-backup.yaml" <<EOF
apiVersion: arcade.gobha.me/v1alpha1
kind: GameBackup
metadata:
  name: running-backup
  namespace: $namespace
spec:
  source:
    name: $server_name
    uid: $new_server_uid
    generation: $running_generation
    desiredState: Running
  repositorySecretRef:
    name: $repository_secret_name
    uid: $repository_uid
    resourceVersion: "$repository_version"
  restartPolicy: RestorePreviousState
  retentionPolicy: Retain
EOF

say "interrupting real Restic verification and proving same-operation lock recovery"
kube scale deployment/arcadectl-controller --namespace "$namespace" --replicas=0 >/dev/null
kube_bounded 70 wait pod --namespace "$namespace" --selector=app.kubernetes.io/name=arcadectl-controller --for=delete --timeout=60s >/dev/null
kube apply --filename "$workspace/running-backup.yaml" >/dev/null
running_backup_uid=$(kube get gamebackup running-backup --namespace "$namespace" --output=jsonpath='{.metadata.uid}')
[[ -n "$running_backup_uid" ]] || die "running backup did not receive a UID"
backup_name_digest=$(printf 'arcadectl/backup-job/%s' "$running_backup_uid" | sha256sum | awk '{print $1}')
running_backup_job="backup-${backup_name_digest:0:32}"

cat >"$workspace/restic-interruption.yaml" <<EOF
apiVersion: batch/v1
kind: Job
metadata:
  name: restic-interruption
  namespace: $namespace
  labels:
    arcade.gobha.me/e2e-run: $run_id
spec:
  backoffLimit: 0
  activeDeadlineSeconds: 120
  template:
    metadata:
      labels:
        arcade.gobha.me/e2e-run: $run_id
    spec:
      hostname: $running_backup_job
      shareProcessNamespace: true
      automountServiceAccountToken: false
      restartPolicy: Never
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        runAsGroup: 65532
        fsGroup: 65532
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: interrupted-verifier
          image: $controller_image
          imagePullPolicy: IfNotPresent
          command: ["/restic"]
          args: ["--no-cache", "--repo", "s3:http://minio:9000/arcadectl", "--password-file", "/credentials/password", "--limit-download", "1", "check", "--read-data"]
          env:
            - name: HOME
              value: /work
            - name: TMPDIR
              value: /work
            - name: RESTIC_CACHE_DIR
              value: /work/cache
            - name: AWS_ACCESS_KEY_ID
              valueFrom:
                secretKeyRef: {name: $repository_secret_name, key: awsAccessKeyID}
            - name: AWS_SECRET_ACCESS_KEY
              valueFrom:
                secretKeyRef: {name: $repository_secret_name, key: awsSecretAccessKey}
          resources:
            requests: {cpu: 25m, memory: 32Mi}
            limits: {cpu: 250m, memory: 128Mi}
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: {drop: ["ALL"]}
          volumeMounts:
            - {name: credentials, mountPath: /credentials, readOnly: true}
            - {name: work, mountPath: /work}
        - name: interrupter
          image: $backup_utility_image
          imagePullPolicy: IfNotPresent
          command: ["/bin/sh", "-ec"]
          args:
            - |
              attempts=0
              while [ "\$attempts" -lt 30 ]; do
                pid="\$(pidof restic 2>/dev/null || true)"
                if [ -n "\$pid" ]; then
                  sleep 3
                  kill -KILL \$pid
                  echo verification-interrupted
                  exit 0
                fi
                attempts=\$((attempts + 1))
                sleep 1
              done
              echo restic-process-not-found >&2
              exit 1
          resources:
            requests: {cpu: 5m, memory: 8Mi}
            limits: {cpu: 50m, memory: 32Mi}
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: {drop: ["ALL"]}
      volumes:
        - name: credentials
          secret: {secretName: $repository_secret_name, defaultMode: 0444}
        - name: work
          emptyDir: {sizeLimit: 64Mi}
EOF
kube apply --filename "$workspace/restic-interruption.yaml" >/dev/null
kube_bounded 130 wait job/restic-interruption --namespace "$namespace" --for=condition=failed --timeout=120s >/dev/null
interruption_pod=$(kube get pods --namespace "$namespace" --selector=job-name=restic-interruption --output=jsonpath='{.items[0].metadata.name}')
interrupted_exit=$(kube get pod "$interruption_pod" --namespace "$namespace" --output=jsonpath='{.status.containerStatuses[?(@.name=="interrupted-verifier")].state.terminated.exitCode}')
[[ "$interrupted_exit" == 137 ]] || die "Restic verification was not forcefully interrupted: exit $interrupted_exit"
[[ $(kube logs "$interruption_pod" --namespace "$namespace" --container=interrupter) == verification-interrupted ]] \
  || die "Restic interruption sidecar did not confirm the fault"
[[ -z $(kube get gamebackup running-backup --namespace "$namespace" --output=jsonpath='{.status.artifact.id}') ]] \
  || die "interrupted verification published a usable artifact"
kube_bounded 70 delete job/restic-interruption --namespace "$namespace" --wait=true --timeout=60s >/dev/null

kube scale deployment/arcadectl-controller --namespace "$namespace" --replicas=1 >/dev/null
kube_bounded 130 rollout status deployment/arcadectl-controller --namespace "$namespace" --timeout=120s >/dev/null
say "refusing a live overlapping backup worker and serializing its retry"
wait_present job "$running_backup_job" 90
overlap_deadline=$((SECONDS + 90))
first_worker_pod=
first_worker_uid=
worker_lease=
while (( SECONDS < overlap_deadline )); do
  first_worker_pod=$(kube get pods --namespace "$namespace" --selector="arcade.gobha.me/backup-uid=$running_backup_uid" \
    --output=jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
  first_worker_uid=$(kube get pod "$first_worker_pod" --namespace "$namespace" --output=jsonpath='{.metadata.uid}' 2>/dev/null || true)
  first_worker_phase=$(kube get pod "$first_worker_pod" --namespace "$namespace" --output=jsonpath='{.status.phase}' 2>/dev/null || true)
  worker_lease=$(kube get leases --namespace "$namespace" --selector="arcade.gobha.me/backup-uid=$running_backup_uid" \
    --output=jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
  worker_holder=$(kube get lease "$worker_lease" --namespace "$namespace" \
    --output=go-template='{{index .metadata.annotations "arcade.gobha.me/worker-pod-uid"}}' 2>/dev/null || true)
  if [[ -n "$first_worker_uid" && "$first_worker_phase" == Running && "$worker_holder" == "$first_worker_uid" ]]; then
    break
  fi
  sleep 1
done
[[ -n "$first_worker_uid" && "$first_worker_phase" == Running && "$worker_holder" == "$first_worker_uid" ]] \
  || die "first backup worker never acquired its Pod-UID execution claim while live"
worker_container_id=$(kube get pod "$first_worker_pod" --namespace "$namespace" \
  --output=jsonpath='{.status.containerStatuses[?(@.name=="backup-worker")].containerID}')
worker_container_id=${worker_container_id#containerd://}
[[ "$worker_container_id" =~ ^[0-9a-f]{64}$ ]] || die "authorized worker container identity is invalid"
worker_pid=$(docker exec "$cluster_name-control-plane" crictl inspect "$worker_container_id" | jq -r '.info.pid // empty')
[[ "$worker_pid" =~ ^[1-9][0-9]*$ ]] || die "authorized worker runtime PID is invalid"
docker exec "$cluster_name-control-plane" kill -STOP "$worker_pid"
[[ $(kube get pod "$first_worker_pod" --namespace "$namespace" --output=jsonpath='{.status.phase}') == Running ]] \
  || die "authorized worker did not remain live after the deterministic pause"
say "refusing controller uninstall while a backup worker is active"
if uninstall_output=$(run_bounded 30 env KUBECTL="$kubectl_wrapper" "$repository_root/hack/uninstall.sh" 2>&1); then
  die "safe uninstall accepted an active backup worker"
fi
[[ "$uninstall_output" == *"every GameBackup must be terminal"* ]] \
  || die "safe uninstall did not report the active GameBackup boundary"
kube get deployment arcadectl-controller --namespace "$namespace" >/dev/null
kube get validatingadmissionpolicy arcadectl-backup-worker-gate >/dev/null
kube get validatingadmissionpolicybinding arcadectl-backup-worker-gate >/dev/null
kube scale deployment/arcadectl-controller --namespace "$namespace" --replicas=0 >/dev/null
kube_bounded 70 wait pod --namespace "$namespace" --selector=app.kubernetes.io/name=arcadectl-controller --for=delete --timeout=60s >/dev/null
[[ $(kube get pod "$first_worker_pod" --namespace "$namespace" --output=jsonpath='{.status.phase}') == Running ]] \
  || die "first backup worker did not remain live for the overlap proof"

running_job_uid=$(kube get job "$running_backup_job" --namespace "$namespace" --output=jsonpath='{.metadata.uid}')
overlap_pod="backup-overlap-$run_suffix"
cat >"$workspace/backup-overlap.yaml" <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $overlap_pod
  namespace: $namespace
  annotations:
    arcade.gobha.me/e2e-run: $run_id
  labels:
    arcade.gobha.me/backup-uid: $running_backup_uid
    arcade.gobha.me/e2e-run: $run_id
  ownerReferences:
    - apiVersion: batch/v1
      kind: Job
      name: $running_backup_job
      uid: $running_job_uid
      controller: true
      blockOwnerDeletion: true
spec:
  hostname: $running_backup_job
  serviceAccountName: $running_backup_job-authority
  automountServiceAccountToken: false
  restartPolicy: Never
  schedulingGates:
    - name: arcade.gobha.me/backup-authorized
  securityContext:
    runAsNonRoot: true
    runAsUser: 65532
    runAsGroup: 65532
    supplementalGroups: [65532]
    seccompProfile: {type: RuntimeDefault}
  initContainers:
    - name: backup-authorizer
      image: $controller_image
      imagePullPolicy: IfNotPresent
      command: ["/arcadectl-backup-authorizer"]
      env:
        - name: POD_NAMESPACE
          valueFrom: {fieldRef: {fieldPath: metadata.namespace}}
        - name: POD_UID
          valueFrom: {fieldRef: {fieldPath: metadata.uid}}
      resources:
        requests: {cpu: 5m, memory: 16Mi}
        limits: {cpu: 50m, memory: 32Mi}
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities: {drop: ["ALL"]}
      volumeMounts:
        - {name: input, mountPath: /arcadectl/input, readOnly: true}
        - {name: credentials, mountPath: /arcadectl/authorized-credentials}
        - {name: authority, mountPath: /var/run/secrets/kubernetes.io/serviceaccount, readOnly: true}
  containers:
    - name: overlap-sentinel
      image: $backup_utility_image
      imagePullPolicy: IfNotPresent
      command: ["/bin/sh", "-ec", "sleep 300"]
      resources:
        requests: {cpu: 5m, memory: 8Mi}
        limits: {cpu: 50m, memory: 32Mi}
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities: {drop: ["ALL"]}
      volumeMounts:
        - {name: source, mountPath: /arcadectl/source/state, readOnly: true}
  volumes:
    - name: input
      configMap: {name: $running_backup_job-input, defaultMode: 0444}
    - name: credentials
      emptyDir: {sizeLimit: 2Mi}
    - name: source
      persistentVolumeClaim: {claimName: $claim_name, readOnly: true}
    - name: authority
      projected:
        defaultMode: 0444
        sources:
          - serviceAccountToken: {path: token, expirationSeconds: 600}
          - configMap:
              name: kube-root-ca.crt
              items: [{key: ca.crt, path: ca.crt}]
EOF
kube apply --filename "$workspace/backup-overlap.yaml" >/dev/null
overlap_uid=$(kube get pod "$overlap_pod" --namespace "$namespace" --output=jsonpath='{.metadata.uid}')
[[ -n "$overlap_uid" ]] || die "gated overlap probe did not receive a Pod UID"
kube get pod "$overlap_pod" --namespace "$namespace" --output=json \
  | jq --arg uid "$overlap_uid" \
      '.metadata.annotations["arcade.gobha.me/backup-pod-authorized"] = $uid | del(.spec.schedulingGates)' \
  | kube replace --filename - --as=system:serviceaccount:arcadectl-system:arcadectl-controller >/dev/null
actual_overlap_owner=$(kube get pod "$overlap_pod" --namespace "$namespace" \
  --output=go-template='{{range .metadata.ownerReferences}}{{if eq .kind "Job"}}{{.uid}}{{end}}{{end}}')
actual_overlap_claim=$(kube get pod "$overlap_pod" --namespace "$namespace" \
  --output=jsonpath='{.spec.volumes[?(@.name=="source")].persistentVolumeClaim.claimName}')
[[ "$actual_overlap_owner" == "$running_job_uid" && "$actual_overlap_claim" == "$claim_name" ]] \
  || die "overlap probe did not retain the exact Job ownership and source claim"
overlap_deadline=$((SECONDS + 60))
overlap_exit=
while (( SECONDS < overlap_deadline )); do
  overlap_exit=$(kube get pod "$overlap_pod" --namespace "$namespace" \
    --output=jsonpath='{.status.initContainerStatuses[?(@.name=="backup-authorizer")].state.terminated.exitCode}' 2>/dev/null || true)
  [[ -n "$overlap_exit" ]] && break
  sleep 1
done
[[ "$overlap_exit" == 12 ]] || die "overlapping worker authorizer exit was $overlap_exit, want 12"
[[ $(kube get pod "$first_worker_pod" --namespace "$namespace" --output=jsonpath='{.status.phase}') == Running ]] \
  || die "first backup worker was not live when the overlap was refused"
[[ $(kube get lease "$worker_lease" --namespace "$namespace" \
  --output=go-template='{{index .metadata.annotations "arcade.gobha.me/worker-pod-uid"}}') == "$first_worker_uid" ]] \
  || die "overlapping worker replaced the live execution holder"
assert_worker_evidence_private "$overlap_pod" backup-authorizer
kube_bounded 70 delete pod "$overlap_pod" --namespace "$namespace" --wait=true --timeout=60s >/dev/null
docker exec "$cluster_name-control-plane" kill -KILL "$worker_pid"
kube_bounded 70 wait job/"$running_backup_job" --namespace "$namespace" --for=condition=failed --timeout=60s >/dev/null
assert_worker_evidence_private "$first_worker_pod" backup-authorizer
assert_worker_evidence_private "$first_worker_pod" backup-worker
[[ -z $(kube get gamebackup running-backup --namespace "$namespace" --output=jsonpath='{.status.artifact.id}') ]] \
  || die "force-stopped authorized worker published a usable artifact"

kube scale deployment/arcadectl-controller --namespace "$namespace" --replicas=1 >/dev/null
kube_bounded 130 rollout status deployment/arcadectl-controller --namespace "$namespace" --timeout=120s >/dev/null
say "backing up a running server and restoring its prior Ready state"
wait_backup running-backup Ready 240
running_backup_attempts=$(kube get gamebackup running-backup --namespace "$namespace" --output=jsonpath='{.status.attempts}')
[[ "$running_backup_attempts" =~ ^[0-9]+$ && "$running_backup_attempts" -ge 2 ]] \
  || die "live worker overlap did not converge through a bounded serialized retry"
wait_server "$server_name" Ready Ready 90
assert_backup_artifact running-backup Ready
assert_pvc_identity "$pvc_uid" "$pv_name"
grep -Fxq 'marker=first-seed' <<<"$(probe_state "$server_name")" || die "running cold backup changed retained world bytes"

say "backing up an already-stopped server and leaving it stopped"
kube patch gameserver "$server_name" --namespace "$namespace" --type=merge --patch '{"spec":{"desiredState":"Stopped"}}' >/dev/null
wait_server "$server_name" Stopped RuntimeStopped 90
assert_runtime_absent "$server_name"
stopped_generation=$(kube get gameserver "$server_name" --namespace "$namespace" --output=jsonpath='{.metadata.generation}')
sed -e 's/name: running-backup/name: stopped-backup/' \
  -e "s/generation: $running_generation/generation: $stopped_generation/" \
  -e 's/desiredState: Running/desiredState: Stopped/' \
  -e 's/restartPolicy: RestorePreviousState/restartPolicy: LeaveStopped/' \
  "$workspace/running-backup.yaml" >"$workspace/stopped-backup.yaml"
kube apply --filename "$workspace/stopped-backup.yaml" >/dev/null
wait_backup stopped-backup Stopped 240
assert_backup_artifact stopped-backup Stopped
assert_runtime_absent "$server_name"
assert_pvc_identity "$pvc_uid" "$pv_name"
verify_marker_while_stopped

say "independently inspecting repository artifacts without mounting source worlds"
cat >"$workspace/artifact-inspector.yaml" <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: artifact-inspector
  namespace: $namespace
  labels:
    arcade.gobha.me/e2e-run: $run_id
spec:
  automountServiceAccountToken: false
  restartPolicy: Never
  activeDeadlineSeconds: 180
  securityContext:
    runAsNonRoot: true
    runAsUser: 65532
    runAsGroup: 65532
    fsGroup: 65532
    seccompProfile: {type: RuntimeDefault}
  containers:
    - name: inspector
      image: $restic_inspector_image
      imagePullPolicy: IfNotPresent
      command: ["/bin/sh", "-ec", "sleep 170"]
      env:
        - {name: RESTIC_REPOSITORY, value: "s3:http://minio:9000/arcadectl"}
        - {name: RESTIC_PASSWORD_FILE, value: /credentials/password}
        - name: AWS_ACCESS_KEY_ID
          valueFrom:
            secretKeyRef: {name: $repository_secret_name, key: awsAccessKeyID}
        - name: AWS_SECRET_ACCESS_KEY
          valueFrom:
            secretKeyRef: {name: $repository_secret_name, key: awsSecretAccessKey}
      resources:
        requests: {cpu: 5m, memory: 32Mi}
        limits: {cpu: 250m, memory: 128Mi}
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities: {drop: ["ALL"]}
      volumeMounts:
        - {name: credentials, mountPath: /credentials, readOnly: true}
  volumes:
    - name: credentials
      secret: {secretName: $repository_secret_name, defaultMode: 0444}
EOF
kube apply --filename "$workspace/artifact-inspector.yaml" >/dev/null
kube_bounded 100 wait pod/artifact-inspector --namespace "$namespace" --for=condition=Ready --timeout=90s >/dev/null
for backup in running-backup stopped-backup; do
  artifact_id=$(kube get gamebackup "$backup" --namespace "$namespace" --output=jsonpath='{.status.artifact.id}')
  artifact_digest=$(kube get gamebackup "$backup" --namespace "$namespace" --output=jsonpath='{.status.artifact.manifestDigest}')
  kube exec artifact-inspector --namespace "$namespace" -- /usr/bin/restic --no-cache \
    snapshots --json --tag "arcadectl-artifact=$artifact_id" \
    >"$workspace/repository-snapshots" 2>"$workspace/repository-error" \
    || die "could not inspect exact repository snapshot"
  snapshot_id=$(jq -er --arg digest "arcadectl-manifest=${artifact_digest#sha256:}" \
    'if length == 1 and (.[0].tags | index($digest)) != null then .[0].id else error("snapshot identity mismatch") end' \
    "$workspace/repository-snapshots")
  [[ "$snapshot_id" =~ ^[0-9a-f]{64}$ ]] || die "repository snapshot identity is invalid"
  kube exec artifact-inspector --namespace "$namespace" -- /usr/bin/restic --no-cache \
    dump "$snapshot_id" /arcadectl/work/manifest.json \
    >"$workspace/repository-manifest" 2>"$workspace/repository-error" \
    || die "could not retrieve repository manifest"
  stored_digest=$(sha256sum "$workspace/repository-manifest" | awk '{print "sha256:" $1}')
  [[ "$stored_digest" == "$artifact_digest" ]] || die "independent repository manifest digest mismatch"
  jq -e --arg uid "$new_server_uid" --arg claim "$pvc_uid" --arg id "$artifact_id" \
    '.artifactID == $id and .serverUID == $uid and (.paths | length) == 1 and .paths[0].name == "state" and .paths[0].claimUID == $claim' \
    "$workspace/repository-manifest" >/dev/null || die "independent repository manifest identity mismatch"
  kube exec artifact-inspector --namespace "$namespace" -- /usr/bin/restic --no-cache ls --json "$snapshot_id" \
    >"$workspace/repository-inventory" 2>"$workspace/repository-error" \
    || die "could not inspect complete repository file inventory"
  jq -r 'select(.type == "file") | .path' "$workspace/repository-inventory" >"$workspace/repository-paths"
  [[ -s "$workspace/repository-paths" ]] || die "repository file inventory is empty"
  while IFS= read -r repository_path; do
    [[ "$repository_path" == /arcadectl/work/manifest.json || "$repository_path" == /arcadectl/source/state/* ]] \
      || die "repository contains a file outside the declared world and manifest"
    kube exec artifact-inspector --namespace "$namespace" -- /usr/bin/restic --no-cache dump "$snapshot_id" "$repository_path" \
      >"$workspace/repository-file" 2>"$workspace/repository-error" \
      || die "could not independently read repository file"
    assert_no_repository_credentials "$workspace/repository-file" "$workspace/repository-error"
  done <"$workspace/repository-paths"
  assert_no_repository_credentials "$workspace/repository-manifest" "$workspace/repository-inventory" "$workspace/repository-snapshots"
done
kube_bounded 70 delete pod/artifact-inspector --namespace "$namespace" --wait=true --timeout=60s >/dev/null

backup_public_evidence=$(kube get gamebackups --namespace "$namespace" --output=yaml)
backup_events=$(kube get events --namespace "$namespace" --output=yaml)
backup_controller_logs=$(kube logs deployment/arcadectl-controller --namespace "$namespace")
for canary in "$repository_access_key" "$repository_secret_key" "$repository_password"; do
  if grep -Fq "$canary" <<<"$backup_public_evidence$backup_events$backup_controller_logs"; then
    die "repository credential canary escaped into API status, events, or controller logs"
  fi
done

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
wait_selector_absent jobs arcade.gobha.me/data-operation 60
wait_selector_absent pods arcade.gobha.me/data-operation 60
wait_selector_absent leases arcade.gobha.me/data-identity 60
say "refusing uninstall when the installed admission policy has drifted"
kube patch validatingadmissionpolicy arcadectl-backup-worker-gate --type=json \
  --patch='[{"op":"replace","path":"/spec/validations/3/expression","value":"true"}]' >/dev/null
if drift_uninstall_output=$(run_bounded 30 env KUBECTL="$kubectl_wrapper" "$repository_root/hack/uninstall.sh" 2>&1); then
  die "safe uninstall accepted a policy that permits arbitrary gate removal"
fi
[[ "$drift_uninstall_output" == *"differs from the shipped specification"* ]] \
  || die "safe uninstall did not reject the exact admission-policy drift"
[[ $(kube get deployment arcadectl-controller --namespace "$namespace" --output=jsonpath='{.spec.replicas}') == 1 ]] \
  || die "unsafe policy caused uninstall to scale the controller"
kube apply --filename "$repository_root/config/install/backup-worker-admission-policy.yaml" >/dev/null
run_bounded 120 env KUBECTL="$kubectl_wrapper" "$repository_root/hack/uninstall.sh"
wait_absent deployment arcadectl-controller 60
wait_selector_absent replicasets app.kubernetes.io/name=arcadectl-controller 60
wait_selector_absent pods app.kubernetes.io/name=arcadectl-controller 60
kube get validatingadmissionpolicy arcadectl-backup-worker-gate >/dev/null
kube get validatingadmissionpolicybinding arcadectl-backup-worker-gate >/dev/null
retained_authority="$running_backup_job-authority"
kube get serviceaccount "$retained_authority" --namespace "$namespace" >/dev/null
kube get role "$retained_authority" --namespace "$namespace" >/dev/null
kube get rolebinding "$retained_authority" --namespace "$namespace" >/dev/null
cat >"$workspace/post-uninstall-authority-probe.yaml" <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: post-uninstall-authority-probe
  namespace: $namespace
spec:
  serviceAccountName: $retained_authority
  automountServiceAccountToken: false
  restartPolicy: Never
  securityContext:
    runAsNonRoot: true
    runAsUser: 65532
    runAsGroup: 65532
    seccompProfile: {type: RuntimeDefault}
  containers:
    - name: probe
      image: $controller_image
      command: ["/arcadectl-controller", "--help"]
      resources:
        requests: {cpu: 1m, memory: 8Mi}
        limits: {cpu: 10m, memory: 16Mi}
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities: {drop: [ALL]}
EOF
if post_uninstall_denial=$(kube create --dry-run=server --filename "$workspace/post-uninstall-authority-probe.yaml" 2>&1); then
  die "retained backup authority escaped the post-uninstall admission gate"
fi
grep -Fq 'must enter admission with exactly one execution gate' <<<"$post_uninstall_denial" \
  || die "unexpected post-uninstall backup authority denial: $post_uninstall_denial"
kube get namespace "$namespace" >/dev/null
kube get customresourcedefinition gameservers.arcade.gobha.me >/dev/null
kube get gameserver "$server_name" --namespace "$namespace" >/dev/null
assert_pvc_identity "$pvc_uid" "$pv_name"

say "isolated lifecycle proof passed (source_head=$candidate_sha source_dirty=$source_dirty)"
