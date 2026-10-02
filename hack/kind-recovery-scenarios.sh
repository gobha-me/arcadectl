#!/usr/bin/env bash
# Copyright 2026 gobha-me
# SPDX-License-Identifier: Apache-2.0
# Sourced only by the ownership-checked recovery mode of test-kind-lifecycle.sh.

readonly recovery_io_image='busybox@sha256:9db7b59979c38555a39def84a31fb98b5296952f9e3afd4f6f11f05b07adfab0'
readonly recovery_csi_namespace=arcadectl-recovery-csi
readonly recovery_marker_a_sha256="$(head -c 8388608 /dev/zero | sha256sum | awk '{print $1}')"

recovery_record() {
  printf '%s\t%s\n' "$(date +%s)" "$*" >>"$workspace/recovery-transitions.tsv"
}

# Kind has no LoadBalancer implementation. Publish the fixture's own ClusterIP
# whenever reconciliation recreates its player Service, including failure
# settlement. This does not substitute for runtime or world-byte validation.
recovery_publish_player_endpoint_if_present() {
  local service address uid server_uid
  service=$(kube get service "$server_name" --namespace "$namespace" --ignore-not-found --output=json)
  [[ -n "$service" ]] || return 0
  address=$(jq -r '.spec.clusterIP' <<<"$service")
  uid=$(jq -r '.metadata.uid' <<<"$service")
  [[ "$address" =~ ^[0-9a-fA-F:.]+$ && "$uid" =~ ^[0-9a-f-]{36}$ ]] \
    || die "recovery player Service lacks an exact identity and ClusterIP"
  server_uid=$(kube get gameserver "$server_name" --namespace "$namespace" --output=jsonpath='{.metadata.uid}')
  [[ "$server_uid" =~ ^[0-9a-f-]{36}$ ]] || die "recovery endpoint publication lacks the live exact GameServer UID"
  jq -e --arg server "$server_name" --arg uid "$server_uid" '.spec.type == "LoadBalancer" and
    ([.metadata.ownerReferences[]? | select(.controller == true)] | length) == 1 and
    any(.metadata.ownerReferences[]?; .kind == "GameServer" and .name == $server and .uid == $uid and .controller == true)' \
    <<<"$service" >/dev/null || die "recovery player Service is not the owned game runtime"
  kube patch service "$server_name" --namespace "$namespace" --subresource=status --type=json \
    --patch "$(jq -cn --arg uid "$uid" --arg address "$address" '
      [{op:"test",path:"/metadata/uid",value:$uid},
       {op:"add",path:"/status/loadBalancer",value:{ingress:[{ip:$address}]}}]')" >/dev/null
}

recovery_start() {
  kube patch gameserver "$server_name" --namespace "$namespace" --type=merge --patch '{"spec":{"desiredState":"Running"}}' >/dev/null
  wait_present service "$server_name" 90
  recovery_publish_player_endpoint_if_present
  wait_server "$server_name" Ready Ready 180
}

recovery_stop() {
  kube patch gameserver "$server_name" --namespace "$namespace" --type=merge --patch '{"spec":{"desiredState":"Stopped"}}' >/dev/null
  wait_server "$server_name" Stopped RuntimeStopped 120
  assert_runtime_absent "$server_name"
}

recovery_world_io() {
  local claim=$1 action=$2 script readonly_mount=true
  case "$action" in
    seed-a) script='head -c 8388608 /dev/zero > /world/.arcadectl-marker-a; test "$(sha256sum /world/.arcadectl-marker-a | cut -d " " -f 1)" = "$MARKER_A_SHA256"; sha256sum /world/.arcadectl-marker-a'; readonly_mount=false ;;
    seed-b) script='printf marker-b > /world/.arcadectl-marker-b; sha256sum /world/.arcadectl-marker-b'; readonly_mount=false ;;
    verify-ab) script='test "$(wc -c < /world/.arcadectl-marker-a)" = 8388608; test "$(sha256sum /world/.arcadectl-marker-a | cut -d " " -f 1)" = "$MARKER_A_SHA256"; test "$(cat /world/.arcadectl-marker-b)" = marker-b; sha256sum /world/.arcadectl-marker-a /world/.arcadectl-marker-b; find /world -type f -name "*.zip" -size +0 | head -n 1 | grep .' ;;
    verify-a-only) script='test "$(wc -c < /world/.arcadectl-marker-a)" = 8388608; test "$(sha256sum /world/.arcadectl-marker-a | cut -d " " -f 1)" = "$MARKER_A_SHA256"; test ! -e /world/.arcadectl-marker-b; sha256sum /world/.arcadectl-marker-a; find /world -type f -name "*.zip" -size +0 | head -n 1 | grep .' ;;
    *) die "unknown bounded world IO action" ;;
  esac
  jq -cn --arg ns "$namespace" --arg run "$run_id" --arg image "$recovery_io_image" \
    --arg claim "$claim" --arg script "$script" --arg hash "$recovery_marker_a_sha256" --argjson readonly "$readonly_mount" \
    '{apiVersion:"v1",kind:"Pod",metadata:{name:"recovery-world-io",namespace:$ns,labels:{"arcade.gobha.me/e2e-run":$run}},
      spec:{automountServiceAccountToken:false,restartPolicy:"Never",activeDeadlineSeconds:90,
        securityContext:{runAsNonRoot:true,runAsUser:845,runAsGroup:845,fsGroup:845,seccompProfile:{type:"RuntimeDefault"}},
        containers:[{name:"io",image:$image,command:["sh","-ec",$script],env:[{name:"MARKER_A_SHA256",value:$hash}],
          resources:{requests:{cpu:"5m",memory:"8Mi"},limits:{cpu:"100m",memory:"32Mi"}},
          securityContext:{allowPrivilegeEscalation:false,readOnlyRootFilesystem:true,capabilities:{drop:["ALL"]}},
          volumeMounts:[{name:"world",mountPath:"/world",readOnly:$readonly}]}],
        volumes:[{name:"world",persistentVolumeClaim:{claimName:$claim,readOnly:$readonly}}]}}' \
    >"$workspace/recovery-world-io.json"
  kube create --filename "$workspace/recovery-world-io.json" >/dev/null
  wait_pod_phase recovery-world-io Succeeded 110
  kube logs recovery-world-io --namespace "$namespace" >>"$workspace/recovery-marker-evidence.txt"
  kube_bounded 70 delete pod recovery-world-io --namespace "$namespace" --wait=true --timeout=60s >/dev/null
}

recovery_wait_operation() {
  local resource=$1 name=$2 phase=$3 seconds=$4 deadline observed
  deadline=$((SECONDS + seconds))
  while (( SECONDS < deadline )); do
    observed=$(kube get "$resource" "$name" --namespace "$namespace" --output=json)
    if jq -e --arg phase "$phase" '.status.phase == $phase and .status.observedGeneration == .metadata.generation' \
      <<<"$observed" >/dev/null; then
      return 0
    fi
    if [[ "$phase" == Succeeded ]] && jq -e '.status.phase == "Failed" or .status.phase == "Cancelled"' \
      <<<"$observed" >/dev/null; then
      die "$resource/$name failed before its required successful proof"
    fi
    # Restart settlement waits for a published player endpoint in Kind.
    recovery_publish_player_endpoint_if_present
    sleep 2
  done
  die "$resource/$name did not reach current $phase within the bounded wait"
}

recovery_repository_ref() {
  kube get secret "$1" --namespace "$namespace" --output=jsonpath='{.metadata.name}|{.metadata.uid}|{.metadata.resourceVersion}' \
    | awk -F'|' '{printf "{\"name\":\"%s\",\"uid\":\"%s\",\"resourceVersion\":\"%s\"}", $1,$2,$3}'
}

# The API, rather than a name-only lookup, enforces deletion identity. This
# helper is intentionally limited to the unmanaged disposable filler claim.
recovery_delete_exact() {
  local kind=$1 name=$2 uid=$3
  [[ "$kind" == pvc && "$name" == recovery-capacity-filler && "$uid" =~ ^[0-9a-f-]{36}$ ]] \
    || die "refusing deletion outside the exact recovery filler"
  verify_cluster_ownership || die "lost disposable cluster ownership before fixture deletion"
  kube get pvc "$name" --namespace "$namespace" --output=json | jq -e --arg uid "$uid" --arg run "$run_id" \
    '.metadata.uid == $uid and .metadata.labels["arcade.gobha.me/e2e-run"] == $run and .spec.storageClassName == "arcadectl-world-filler"' \
    >/dev/null || die "filler deletion identity or ownership changed"
  jq -cn --arg uid "$uid" '{apiVersion:"v1",kind:"DeleteOptions",preconditions:{uid:$uid},propagationPolicy:"Foreground"}' \
    >"$workspace/recovery-delete-options.json"
  kube delete --raw "/api/v1/namespaces/$namespace/persistentvolumeclaims/$name" \
    --filename "$workspace/recovery-delete-options.json" >/dev/null
}

recovery_wait_settled_failure() {
  local name=$1 reason=$2 result uid
  # Restic's pinned backend retries some authentication/storage failures for
  # up to fifteen minutes. Observe its actual failure, not an artificial kill.
  recovery_wait_operation gamerestore "$name" Failed 1200
  result=$(kube get gamerestore "$name" --namespace "$namespace" --output=json)
  jq -e --arg reason "$reason" '.metadata.generation as $generation | .status.completedAt != null and .status.activationStartedAt == null
    and (.status.conditions | any(.type == "Complete" and .status == "False" and .reason == $reason
      and .observedGeneration == $generation))' <<<"$result" >/dev/null \
    || die "restore failure lacks current durable completion and expected refusal reason"
  if jq -e '.status.fence != null' <<<"$result" >/dev/null; then
    jq -e '.status.runtime.phase == "Ready" and .status.runtime.gameServer.desiredState == "Running"
      and .status.runtime.gameServer.uid == .spec.target.uid' <<<"$result" >/dev/null \
      || die "fenced restore failed before exact previous runtime settlement"
  fi
  uid=$(jq -r '.metadata.uid' <<<"$result")
  recovery_fault_wait_cleanup "$uid"
}

recovery_assert_original() {
  wait_server "$server_name" Ready Ready 150
  kube get gameserver "$server_name" --namespace "$namespace" --output=json \
    | jq -e --arg identity "$recovery_original_identity" --arg claim "$claim_name" --arg uid "$recovery_original_pvc_uid" \
      '(.status.activeData // .status.observedData).identity == $identity and .status.observedData.identity == $identity
       and (.status.observedData.claims | length) == 1 and .status.observedData.claims[0].claimRef.name == $claim
       and .status.observedData.claims[0].claimRef.uid == $uid' >/dev/null \
    || die "failure redirected the original world selection"
  kube get pvc "$claim_name" --namespace "$namespace" --output=json \
    | jq -e --arg uid "$recovery_original_pvc_uid" --arg pv "$recovery_original_pv" \
      '.metadata.uid == $uid and .spec.volumeName == $pv and .status.phase == "Bound"' >/dev/null \
    || die "failure changed original PVC or binding"
  kube get pv "$recovery_original_pv" --output=json \
    | jq -e --arg uid "$recovery_original_pv_uid" --arg handle "$recovery_original_handle" --arg claim "$recovery_original_pvc_uid" \
      '.metadata.uid == $uid and .spec.csi.volumeHandle == $handle and .spec.claimRef.uid == $claim' >/dev/null \
    || die "failure changed original backing storage identity"
  recovery_stop
  recovery_world_io "$claim_name" verify-ab
  recovery_start
  recovery_record "original A+B readback and real Factorio Ready reverified"
}

recovery_create_backup() {
  local name=$1 secret=$2 server reference
  server=$(kube get gameserver "$server_name" --namespace "$namespace" --output=json)
  reference=$(recovery_repository_ref "$secret")
  jq -cn --arg name "$name" --arg ns "$namespace" --argjson server "$server" --argjson repository "$reference" \
    '{apiVersion:"arcade.gobha.me/v1alpha1",kind:"GameBackup",metadata:{name:$name,namespace:$ns},
      spec:{source:{name:$server.metadata.name,uid:$server.metadata.uid,generation:$server.metadata.generation,desiredState:$server.spec.desiredState},
        sourceData:($server.status.activeData // $server.status.observedData),repositorySecretRef:$repository,
        restartPolicy:"LeaveStopped",retentionPolicy:"Retain"}}' >"$workspace/backup-$name.json"
  kube create --filename "$workspace/backup-$name.json" >/dev/null
  recovery_wait_operation gamebackup "$name" Succeeded 300
  recovery_record "backup $name repository-verified"
}

recovery_create_restore() {
  local name=$1 backup=$2 secret=$3 server reference backup_uid
  server=$(kube get gameserver "$server_name" --namespace "$namespace" --output=json)
  reference=$(recovery_repository_ref "$secret")
  backup_uid=$(kube get gamebackup "$backup" --namespace "$namespace" --output=jsonpath='{.metadata.uid}')
  jq -cn --arg name "$name" --arg ns "$namespace" --arg backup "$backup" --arg uid "$backup_uid" \
    --argjson server "$server" --argjson repository "$reference" \
    '{apiVersion:"arcade.gobha.me/v1alpha1",kind:"GameRestore",metadata:{name:$name,namespace:$ns},
      spec:{backupRef:{name:$backup,uid:$uid},
        target:{name:$server.metadata.name,uid:$server.metadata.uid,generation:$server.metadata.generation,desiredState:$server.spec.desiredState},
        targetData:($server.status.activeData // $server.status.observedData),repositorySecretRef:$repository,
        restartPolicy:"RestorePreviousState"}}' >"$workspace/restore-$name.json"
  kube create --filename "$workspace/restore-$name.json" >/dev/null
}

recovery_install_csi() {
  say "installing digest-pinned test CSI with finite independent capacity pools"
  sed "s/__RUN_ID__/$run_id/g" "$repository_root/hack/csi-hostpath/fixture.yaml" >"$workspace/recovery-csi.yaml"
  kube create --filename "$workspace/recovery-csi.yaml" >/dev/null
  kube_bounded 190 rollout status statefulset/arcadectl-csi-hostpath --namespace "$recovery_csi_namespace" --timeout=180s >/dev/null
  cat >"$workspace/recovery-sentinel.yaml" <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: unrelated-recovery-sentinel
  namespace: $namespace
  labels: {arcade.gobha.me/foreign-sentinel: untouched}
data: {sentinel: preserve}
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: unrelated-recovery-sentinel
  namespace: $namespace
  labels: {arcade.gobha.me/foreign-sentinel: untouched}
spec:
  accessModes: [ReadWriteOnce]
  storageClassName: arcadectl-sentinel
  resources: {requests: {storage: 64Mi}}
EOF
  kube create --filename "$workspace/recovery-sentinel.yaml" >/dev/null
  kube_bounded 130 wait pvc/unrelated-recovery-sentinel --namespace "$namespace" --for=jsonpath='{.status.phase}'=Bound --timeout=120s >/dev/null
  recovery_sentinel_uid=$(kube get pvc unrelated-recovery-sentinel --namespace "$namespace" --output=jsonpath='{.metadata.uid}')
  recovery_sentinel_config_uid=$(kube get configmap unrelated-recovery-sentinel --namespace "$namespace" --output=jsonpath='{.metadata.uid}')
  recovery_capture_sentinel_storage_identity
  recovery_record "CSI dynamic provisioning smoke passed sentinel=$recovery_sentinel_uid"
  local sentinel_pv node deadline
  sentinel_pv=$(kube get pvc unrelated-recovery-sentinel --namespace "$namespace" --output=jsonpath='{.spec.volumeName}')
  deadline=$((SECONDS + 90))
  node=$(head -n 1 <<<"$node_names")
  while ! kube get csinode "$node" --output=json | jq -e '.spec.drivers | any(.name == "hostpath.csi.k8s.io")' >/dev/null; do
    (( SECONDS < deadline )) || die "CSI driver was not registered with the owned node"
    sleep 2
  done
  jq -cn --arg ns "$namespace" --arg image "$recovery_io_image" --arg run "$run_id" \
    '{apiVersion:"v1",kind:"Pod",metadata:{name:"recovery-csi-smoke",namespace:$ns,labels:{"arcade.gobha.me/e2e-run":$run}},
      spec:{automountServiceAccountToken:false,restartPolicy:"Never",activeDeadlineSeconds:120,
        securityContext:{runAsNonRoot:true,runAsUser:845,runAsGroup:845,fsGroup:845,seccompProfile:{type:"RuntimeDefault"}},
        containers:[{name:"io",image:$image,command:["sh","-ec","printf sentinel > /world/.recovery-csi-smoke; sync; sleep 110"],
          resources:{requests:{cpu:"5m",memory:"8Mi"},limits:{cpu:"100m",memory:"32Mi"}},
          securityContext:{allowPrivilegeEscalation:false,readOnlyRootFilesystem:true,capabilities:{drop:["ALL"]}},
          volumeMounts:[{name:"world",mountPath:"/world"}]}],
        volumes:[{name:"world",persistentVolumeClaim:{claimName:"unrelated-recovery-sentinel"}}]}}' \
    >"$workspace/recovery-csi-smoke.json"
  kube create --filename "$workspace/recovery-csi-smoke.json" >/dev/null
  kube_bounded 100 wait pod/recovery-csi-smoke --namespace "$namespace" --for=condition=Ready --timeout=90s >/dev/null
  kube get volumeattachments --output=json | jq -e --arg pv "$sentinel_pv" \
    '.items | any(.spec.source.persistentVolumeName == $pv and .status.attached == true)' >/dev/null \
    || die "CSI-mounted smoke Pod lacks actual attached VolumeAttachment evidence"
  kube exec recovery-csi-smoke --namespace "$namespace" --container=io -- sh -ec \
    'test "$(cat /world/.recovery-csi-smoke)" = sentinel; sha256sum /world/.recovery-csi-smoke' \
    >>"$workspace/recovery-marker-evidence.txt"
  kube_bounded 70 delete pod recovery-csi-smoke --namespace "$namespace" --wait=true --timeout=60s >/dev/null
  deadline=$((SECONDS + 90))
  while kube get volumeattachments --output=json | jq -e --arg pv "$sentinel_pv" \
    '.items | any(.spec.source.persistentVolumeName == $pv)' >/dev/null; do
    (( SECONDS < deadline )) || die "CSI smoke volume did not detach"
    sleep 2
  done
  recovery_record "CSI registration, mount, attachment, sentinel readback and detachment smoke passed"
}

recovery_install_repository() {
  repository_secret_name=recovery-repository
  repository_access_key="access-$run_suffix"
  repository_secret_key="object-$run_suffix-canary"
  repository_password="restic-$run_suffix-canary"
  sed -e "s|@@RUN_ID@@|$run_id|g" -e "s|@@MINIO_IMAGE@@|$minio_image|g" \
    -e "s|@@REPOSITORY_PASSWORD@@|$repository_password|g" \
    -e "s|@@ACCESS_KEY@@|$repository_access_key|g" -e "s|@@OBJECT_KEY@@|$repository_secret_key|g" \
    "$repository_root/hack/recovery-repository.yaml.tmpl" >"$workspace/recovery-repository.yaml"
  kube create --filename "$workspace/recovery-repository.yaml" >/dev/null
  kube_bounded 190 rollout status deployment/minio --namespace "$namespace" --timeout=180s >/dev/null
  jq -cn --arg ns "$namespace" --arg run "$run_id" --arg image "$controller_image" \
    --argjson health "$(repository_health_init_container "$recovery_io_image")" \
    '{apiVersion:"batch/v1",kind:"Job",metadata:{name:"recovery-restic-init",namespace:$ns,labels:{"arcade.gobha.me/e2e-run":$run}},
      spec:{backoffLimit:0,activeDeadlineSeconds:120,template:{metadata:{labels:{"arcade.gobha.me/e2e-run":$run}},
        spec:{automountServiceAccountToken:false,restartPolicy:"Never",initContainers:[$health],
          securityContext:{runAsNonRoot:true,runAsUser:65532,runAsGroup:65532,fsGroup:65532,seccompProfile:{type:"RuntimeDefault"}},
          containers:[{name:"init",image:$image,command:["/restic"],
            args:["--no-cache","--repo","s3:http://minio:9000/arcadectl","--password-file","/credentials/password","init"],
            env:[{name:"HOME",value:"/work"},{name:"TMPDIR",value:"/work"},
              {name:"AWS_ACCESS_KEY_ID",valueFrom:{secretKeyRef:{name:"recovery-repository",key:"awsAccessKeyID"}}},
              {name:"AWS_SECRET_ACCESS_KEY",valueFrom:{secretKeyRef:{name:"recovery-repository",key:"awsSecretAccessKey"}}}],
            resources:{requests:{cpu:"50m",memory:"64Mi"},limits:{cpu:"500m",memory:"256Mi"}},
            securityContext:{allowPrivilegeEscalation:false,readOnlyRootFilesystem:true,capabilities:{drop:["ALL"]}},
            volumeMounts:[{name:"credentials",mountPath:"/credentials",readOnly:true},{name:"work",mountPath:"/work"}]}],
          volumes:[{name:"credentials",secret:{secretName:"recovery-repository",defaultMode:292}},{name:"work",emptyDir:{sizeLimit:"64Mi"}}]}}}}' \
    >"$workspace/recovery-restic-init.json"
  kube create --filename "$workspace/recovery-restic-init.json" >/dev/null
  kube_bounded 130 wait job/recovery-restic-init --namespace "$namespace" --for=condition=complete --timeout=120s >/dev/null
  kube_bounded 70 delete job recovery-restic-init --namespace "$namespace" --wait=true --timeout=60s >/dev/null
  recovery_record "real CSI-backed MinIO repository initialized"
}

recovery_create_original() {
  cat >"$workspace/recovery-server.yaml" <<EOF
apiVersion: arcade.gobha.me/v1alpha1
kind: GameServer
metadata:
  name: $server_name
  namespace: $namespace
spec:
  game: factorio
  imageDigest: $factorio_a_digest
  desiredState: Stopped
  compute: {cpuRequest: 256m, cpuLimit: "1", memoryRequest: 256Mi, memoryLimit: 2Gi}
  storage: {size: 512Mi, storageClassName: arcadectl-world-retain}
  settings: {name: Recovery proof, visibility: private}
EOF
  kube create --filename "$workspace/recovery-server.yaml" >/dev/null
  kube_bounded 130 wait pvc/"$claim_name" --namespace "$namespace" --for=jsonpath='{.status.phase}'=Bound --timeout=120s >/dev/null
  wait_server "$server_name" Stopped RuntimeStopped 120
  recovery_original_pvc_uid=$(kube get pvc "$claim_name" --namespace "$namespace" --output=jsonpath='{.metadata.uid}')
  recovery_original_pv=$(kube get pvc "$claim_name" --namespace "$namespace" --output=jsonpath='{.spec.volumeName}')
  recovery_original_pv_uid=$(kube get pv "$recovery_original_pv" --output=jsonpath='{.metadata.uid}')
  recovery_original_handle=$(kube get pv "$recovery_original_pv" --output=jsonpath='{.spec.csi.volumeHandle}')
  recovery_original_identity=$(kube get pvc "$claim_name" --namespace "$namespace" --output=jsonpath='{.metadata.labels.arcade\.gobha\.me/data-identity}')
  [[ -n "$recovery_original_handle" && -n "$recovery_original_identity" ]] || die "original CSI world has no durable backing identity"
  recovery_world_io "$claim_name" seed-a
  recovery_start
  recovery_stop
  recovery_record "real Factorio Ready and nonempty save before backup"

  say "proving decommission and exact recreation independently of backup"
  local old_uid new_uid data
  old_uid=$(kube get gameserver "$server_name" --namespace "$namespace" --output=jsonpath='{.metadata.uid}')
  data=$(kube get gameserver "$server_name" --namespace "$namespace" --output=json | jq -c '.status.observedData')
  kube_bounded 70 delete gameserver "$server_name" --namespace "$namespace" --wait=true --timeout=60s >/dev/null
  [[ $(kube get pvc "$claim_name" --namespace "$namespace" --output=jsonpath='{.metadata.uid}') == "$recovery_original_pvc_uid" ]] \
    || die "decommission changed the original PVC"
  kube create --filename "$workspace/recovery-server.yaml" >/dev/null
  kube patch gameserver "$server_name" --namespace "$namespace" --type=merge --patch '{"spec":{"desiredState":"Running"}}' >/dev/null
  wait_server "$server_name" Failed RetainedDataReferenceRequired 90
  assert_runtime_absent "$server_name"
  kube_bounded 70 delete gameserver "$server_name" --namespace "$namespace" --wait=true --timeout=60s >/dev/null
  kube create --dry-run=client --filename "$workspace/recovery-server.yaml" --output=json \
    | jq --argjson data "$data" '.spec.storage.reattach = $data' >"$workspace/recovery-reattach-server.json"
  kube create --filename "$workspace/recovery-reattach-server.json" >/dev/null
  wait_server "$server_name" Stopped RuntimeStopped 120
  new_uid=$(kube get gameserver "$server_name" --namespace "$namespace" --output=jsonpath='{.metadata.uid}')
  [[ "$new_uid" != "$old_uid" ]] || die "recreated server UID did not change"
  recovery_start
  recovery_stop
  recovery_world_io "$claim_name" verify-a-only
  recovery_record "backup-independent exact-UID decommission/reattach passed old=$old_uid new=$new_uid"
}

run_recovery_scenarios() {
  local diagnostic_fault=${ARCADECTL_RECOVERY_DIAGNOSTIC_FAULT:-}
  case "$diagnostic_fault" in
    ''|bad-credentials|capacity|worker-crash|corruption|filesystem-full) ;;
    *) die "unknown bounded recovery diagnostic fault" ;;
  esac
  if [[ -n "$diagnostic_fault" ]]; then
    [[ "${ARCADECTL_RECOVERY_POSTFAULTS_ONLY:-false}" != true &&
      "${ARCADECTL_RECOVERY_SMOKE_ONLY:-false}" != true ]] \
      || die "single-fault diagnosis cannot be combined with another partial mode"
  fi
  recovery_extra_canaries=()
  # shellcheck source=hack/kind-recovery-faults.sh
  source "$repository_root/hack/kind-recovery-faults.sh"
  source "$repository_root/hack/kind-recovery-storage-fault.sh"
  source "$repository_root/hack/kind-recovery-corruption.sh"
  source "$repository_root/hack/kind-recovery-identity.sh"
  source "$repository_root/hack/kind-recovery-success.sh"
  source "$repository_root/hack/kind-recovery-cleanup.sh"
  source "$repository_root/hack/kind-recovery-cleanup-proof.sh"
  printf 'epoch\ttransition\n' >"$workspace/recovery-transitions.tsv"
  recovery_install_csi
  if [[ "${ARCADECTL_RECOVERY_SMOKE_ONLY:-false}" == true ]]; then
    say "CSI registration/provisioning/mount/attach/detach smoke passed only; no full recovery evidence claimed"
    return 0
  fi
  recovery_create_original
  recovery_install_repository
  recovery_create_backup original-backup "$repository_secret_name"
  recovery_world_io "$claim_name" seed-b
  recovery_start
  if [[ "${ARCADECTL_RECOVERY_POSTFAULTS_ONLY:-false}" == true ]]; then
    say "diagnostic post-fault journey only; no full failure-matrix evidence claimed"
    recovery_record "diagnostic post-fault journey selected; bad credentials, capacity, crash, corruption and ENOSPC omitted"
  elif [[ -n "$diagnostic_fault" ]]; then
    say "diagnostic single-fault journey only ($diagnostic_fault); no full failure-matrix evidence claimed"
    recovery_record "diagnostic single fault=$diagnostic_fault selected; all other fault groups omitted"
    case "$diagnostic_fault" in
      bad-credentials) recovery_fault_bad_credentials ;;
      capacity) recovery_fault_capacity ;;
      worker-crash) recovery_fault_worker_crash ;;
      corruption) recovery_fault_corrupt_snapshot ;;
      filesystem-full) recovery_fault_filesystem_full ;;
    esac
  else
    recovery_fault_bad_credentials
    recovery_fault_capacity
    recovery_fault_worker_crash
    recovery_fault_corrupt_snapshot
    recovery_fault_filesystem_full
  fi
  recovery_fault_identity_races
  recovery_prove_restore_after_controller_restart
  recovery_prove_destroy_after_recovery
  kube get gamebackups,gamerestores,gamedestroys --namespace "$namespace" --output=json \
    >"$workspace/recovery-operations.json"
  local evidence canary
  evidence=$(kube get events --namespace "$namespace" --output=json)
  evidence+=$(kube logs deployment/arcadectl-controller --namespace "$namespace")
  evidence+=$(kube logs deployment/arcadectl-destroy-controller --namespace "$namespace")
  evidence+=$(<"$workspace/recovery-operations.json")
  for canary in "$repository_password" "$repository_access_key" "$repository_secret_key" "${recovery_extra_canaries[@]}"; do
    if grep -Fq "$canary" <<<"$evidence"; then die "recovery credential canary escaped into status/events/controller logs"; fi
  done
  recovery_cleanup_fixtures
  collect_diagnostics
  if [[ "${ARCADECTL_RECOVERY_POSTFAULTS_ONLY:-false}" == true || -n "$diagnostic_fault" ]]; then
    say "partial diagnostic recovery journey passed only; full recovery proof still required (source_head=$candidate_sha source_dirty=$source_dirty); evidence=$artifact_directory"
  else
    say "real Factorio recovery/failure-safety proof passed (source_head=$candidate_sha source_dirty=$source_dirty); evidence=$artifact_directory"
  fi
}
