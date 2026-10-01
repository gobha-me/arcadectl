#!/usr/bin/env bash
# Copyright 2026 gobha-me
# SPDX-License-Identifier: Apache-2.0
# Sourced only by the ownership-checked disposable Kind recovery harness.

# Restic runs with repository credentials supplied exclusively through the
# immutable fixture Secret. Its raw output is never copied into test evidence.
# For list-packs, retain only native 64-hex pack IDs in the private workspace.
recovery_corruption_restic_job() {
  local name=$1 secret=$2 arguments=$3 pack_file=${4:-}
  jq -cn --arg ns "$namespace" --arg run "$run_id" --arg name "$name" \
    --arg secret "$secret" --arg image "$controller_image" --argjson arguments "$arguments" \
    '{apiVersion:"batch/v1",kind:"Job",metadata:{name:$name,namespace:$ns,labels:{"arcade.gobha.me/e2e-run":$run}},
      spec:{backoffLimit:0,activeDeadlineSeconds:120,template:{metadata:{labels:{"arcade.gobha.me/e2e-run":$run}},
        spec:{automountServiceAccountToken:false,restartPolicy:"Never",
          securityContext:{runAsNonRoot:true,runAsUser:65532,runAsGroup:65532,fsGroup:65532,seccompProfile:{type:"RuntimeDefault"}},
          containers:[{name:"restic",image:$image,command:["/restic"],
            args:(["--no-cache","--password-file","/credentials/password"]+$arguments),
            env:[{name:"HOME",value:"/work"},{name:"TMPDIR",value:"/work"},{name:"GOMAXPROCS",value:"2"},{name:"GOMEMLIMIT",value:"192MiB"},
              {name:"RESTIC_REPOSITORY",valueFrom:{secretKeyRef:{name:$secret,key:"repository"}}},
              {name:"AWS_ACCESS_KEY_ID",valueFrom:{secretKeyRef:{name:$secret,key:"awsAccessKeyID"}}},
              {name:"AWS_SECRET_ACCESS_KEY",valueFrom:{secretKeyRef:{name:$secret,key:"awsSecretAccessKey"}}}],
            resources:{requests:{cpu:"50m",memory:"64Mi"},limits:{cpu:"500m",memory:"256Mi"}},
            securityContext:{allowPrivilegeEscalation:false,readOnlyRootFilesystem:true,capabilities:{drop:["ALL"]}},
            volumeMounts:[{name:"credentials",mountPath:"/credentials",readOnly:true},{name:"work",mountPath:"/work"}]}],
          volumes:[{name:"credentials",secret:{secretName:$secret,defaultMode:292}},{name:"work",emptyDir:{sizeLimit:"64Mi"}}]}}}}' \
    >"$workspace/$name.json"
  kube create --filename "$workspace/$name.json" >/dev/null
  kube_bounded 130 wait "job/$name" --namespace "$namespace" --for=condition=complete --timeout=120s >/dev/null
  if [[ -n "$pack_file" ]]; then
    kube_bounded 20 logs "job/$name" --namespace "$namespace" --container=restic \
      | awk 'length($0) == 64 && $0 !~ /[^0-9a-f]/ { print }' >"$pack_file"
    [[ -s "$pack_file" ]] || die "corruption fixture repository has no native Restic pack IDs"
  fi
  kube_bounded 70 delete job "$name" --namespace "$namespace" --wait=true --timeout=60s >/dev/null
}

recovery_corruption_wait_repository_detached() {
  local pv=$1 deadline observed
  deadline=$((SECONDS + 90))
  while :; do
    observed=$(kube get volumeattachments --output=json) || die "cannot observe corruption fixture repository attachment"
    if jq -e --arg pv "$pv" '.items | all(.spec.source.persistentVolumeName != $pv)' <<<"$observed" >/dev/null; then
      return 0
    fi
    (( SECONDS < deadline )) || die "corruption fixture repository did not detach"
    sleep 2
  done
}

recovery_corruption_assert_repository_identity() {
  local claim_uid=$1 pv=$2 pv_uid=$3 handle=$4 deployment_uid=$5
  verify_cluster_ownership || die "corruption fixture lost disposable cluster ownership"
  kube get pvc recovery-repository-data --namespace "$namespace" --output=json \
    | jq -e --arg uid "$claim_uid" --arg pv "$pv" --arg run "$run_id" '
      .metadata.uid == $uid and .metadata.deletionTimestamp == null and
      .metadata.labels["arcade.gobha.me/e2e-run"] == $run and
      .spec.storageClassName == "arcadectl-repository" and .spec.volumeName == $pv and .status.phase == "Bound"' \
    >/dev/null || die "corruption fixture repository PVC identity or ownership changed"
  kube get pv "$pv" --output=json | jq -e --arg uid "$pv_uid" --arg claim "$claim_uid" \
    --arg handle "$handle" --arg ns "$namespace" '
      .metadata.uid == $uid and .metadata.deletionTimestamp == null and
      .spec.storageClassName == "arcadectl-repository" and .spec.persistentVolumeReclaimPolicy == "Delete" and
      .spec.claimRef.name == "recovery-repository-data" and .spec.claimRef.namespace == $ns and .spec.claimRef.uid == $claim and
      .spec.csi.driver == "hostpath.csi.k8s.io" and .spec.csi.volumeHandle == $handle' \
    >/dev/null || die "corruption fixture repository PV or CSI identity changed"
  kube get deployment minio --namespace "$namespace" --output=json | jq -e --arg uid "$deployment_uid" --arg run "$run_id" '
    .metadata.uid == $uid and .metadata.deletionTimestamp == null and
    .metadata.labels["arcade.gobha.me/e2e-run"] == $run and
    .spec.template.metadata.labels["arcade.gobha.me/e2e-run"] == $run and
    any(.spec.template.spec.volumes[]; .name == "data" and .persistentVolumeClaim.claimName == "recovery-repository-data")' \
    >/dev/null || die "corruption fixture MinIO deployment identity or backing claim changed"
}

# Kubernetes PVC references are local to each Pod namespace. An empty allowed
# UID requires no users; otherwise every user must be exactly that owned Pod.
recovery_corruption_assert_repository_users() {
  local allowed_uid=${1:-}
  kube get pods --all-namespaces --output=json | jq -e --arg ns "$namespace" --arg uid "$allowed_uid" --arg run "$run_id" '
    [.items[] | select(.metadata.namespace == $ns) |
      select(any(.spec.volumes[]?; .persistentVolumeClaim.claimName == "recovery-repository-data"))] as $users |
    if $uid == "" then ($users | length) == 0 else
      ($users | length) == 1 and $users[0].metadata.uid == $uid and
      $users[0].metadata.labels["arcade.gobha.me/e2e-run"] == $run end' \
    >/dev/null || die "corruption fixture repository has an unexpected Pod user"
}

# Corrupt one real Restic pack object's MinIO backing metadata while MinIO is
# offline. The separate prefix contains a real successful GameBackup, so this
# exercises production repository preflight without manufacturing artifact
# status or damaging the reusable original-backup repository.
recovery_fault_corrupt_snapshot() {
  local secret=recovery-corrupt-repository prefix="corrupt-$run_suffix"
  local pack_file="$workspace/corruption-pack-ids.txt" pack pv deadline observed script result restore_uid
  local claim_uid pv_uid handle deployment_uid minio_pod minio_uid replica_name replica_uid writer_uid
  [[ "$prefix" =~ ^corrupt-[a-z0-9-]+$ ]] || die "corruption fixture prefix is invalid"
  recovery_stop
  jq -cn --arg ns "$namespace" --arg run "$run_id" --arg name "$secret" \
    --arg repository "s3:http://minio:9000/arcadectl/$prefix" --arg password "$repository_password" \
    --arg access "$repository_access_key" --arg object "$repository_secret_key" \
    '{apiVersion:"v1",kind:"Secret",metadata:{name:$name,namespace:$ns,labels:{"arcade.gobha.me/e2e-run":$run}},
      immutable:true,type:"Opaque",stringData:{repository:$repository,password:$password,awsAccessKeyID:$access,awsSecretAccessKey:$object}}' \
    >"$workspace/corruption-repository-secret.json"
  kube create --filename "$workspace/corruption-repository-secret.json" >/dev/null
  recovery_corruption_restic_job recovery-corrupt-init "$secret" '["init"]'
  recovery_create_backup corrupt-backup "$secret"
  recovery_corruption_restic_job recovery-corrupt-list "$secret" '["list","packs"]' "$pack_file"
  pack=$(LC_ALL=C sort "$pack_file" | sed -n '1p')
  [[ "$pack" =~ ^[0-9a-f]{64}$ ]] || die "corruption fixture pack identity is invalid"
  # The failed restore must return the original world to its running state.
  recovery_start

  observed=$(kube get pvc recovery-repository-data --namespace "$namespace" --output=json)
  claim_uid=$(jq -r '.metadata.uid' <<<"$observed")
  pv=$(jq -r '.spec.volumeName' <<<"$observed")
  observed=$(kube get pv "$pv" --output=json)
  pv_uid=$(jq -r '.metadata.uid' <<<"$observed")
  handle=$(jq -r '.spec.csi.volumeHandle' <<<"$observed")
  deployment_uid=$(kube get deployment minio --namespace "$namespace" --output=jsonpath='{.metadata.uid}')
  [[ "$claim_uid" =~ ^[0-9a-f-]{36}$ && "$pv_uid" =~ ^[0-9a-f-]{36}$ && "$deployment_uid" =~ ^[0-9a-f-]{36}$ &&
    "$handle" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] \
    || die "corruption fixture repository identities are incomplete"
  minio_pod=$(kube get pods --namespace "$namespace" \
    --selector="arcade.gobha.me/e2e-component=minio,arcade.gobha.me/e2e-run=$run_id" --output=json)
  jq -e '(.items | length) == 1 and .items[0].status.phase == "Running" and
    any(.items[0].spec.containers[]; .name == "minio")' <<<"$minio_pod" >/dev/null \
    || die "corruption fixture requires one running owned MinIO Pod"
  minio_uid=$(jq -r '.items[0].metadata.uid' <<<"$minio_pod")
  replica_name=$(jq -r '.items[0].metadata.ownerReferences[] | select(.kind == "ReplicaSet" and .controller == true) | .name' <<<"$minio_pod")
  replica_uid=$(jq -r '.items[0].metadata.ownerReferences[] | select(.kind == "ReplicaSet" and .controller == true) | .uid' <<<"$minio_pod")
  kube get replicaset "$replica_name" --namespace "$namespace" --output=json \
    | jq -e --arg uid "$replica_uid" --arg deployment "$deployment_uid" '
      .metadata.uid == $uid and any(.metadata.ownerReferences[];
        .kind == "Deployment" and .name == "minio" and .uid == $deployment and .controller == true)' \
    >/dev/null || die "corruption fixture MinIO Pod does not belong to the pinned deployment"
  recovery_corruption_assert_repository_users "$minio_uid"
  recovery_corruption_assert_repository_identity "$claim_uid" "$pv" "$pv_uid" "$handle" "$deployment_uid"
  kube scale deployment/minio --namespace "$namespace" --replicas=0 >/dev/null
  deadline=$((SECONDS + 90))
  while :; do
    observed=$(kube get pods --namespace "$namespace" \
      --selector="arcade.gobha.me/e2e-component=minio,arcade.gobha.me/e2e-run=$run_id" --output=json) \
      || die "cannot observe stopped MinIO fixture"
    if jq -e '.items | length == 0' <<<"$observed" >/dev/null; then
      break
    fi
    (( SECONDS < deadline )) || die "MinIO fixture did not stop before physical corruption"
    sleep 2
  done
  recovery_corruption_wait_repository_detached "$pv"
  recovery_corruption_assert_repository_identity "$claim_uid" "$pv" "$pv_uid" "$handle" "$deployment_uid"
  recovery_corruption_assert_repository_users

  # MinIO's pinned XLv2 implementation puts each object at bucket/key/xl.meta;
  # small objects may store inline content there. Changing its known magic byte
  # deterministically invalidates this exact pack object in either layout.
  # The canonical path check rejects symlink escapes before any write.
  script='prefix=$1; pack=$2
    test "$(id -u)" = 65532
    test "$(id -g)" = 65532
    case "$prefix" in corrupt-*) ;; *) exit 1 ;; esac
    case "$prefix" in *[!a-z0-9-]*) exit 1 ;; esac
    test "${#pack}" = 64
    case "$pack" in *[!0-9a-f]*) exit 1 ;; esac
    shard=$(printf "%.2s" "$pack")
    meta="/repository/arcadectl/$prefix/data/$shard/$pack/xl.meta"
    test -f "$meta" && test ! -L "$meta"
    test "$(readlink -f "$meta")" = "$meta"
    test "$(head -c 4 "$meta")" = "XL2 "
    before=$(sha256sum "$meta" | awk "{print \$1}")
    size=$(wc -c < "$meta")
    printf "!" | dd of="$meta" bs=1 count=1 conv=notrunc 2>/dev/null
    sync
    after=$(sha256sum "$meta" | awk "{print \$1}")
    test "$before" != "$after"
    test "$(wc -c < "$meta")" = "$size"
    printf "%s %s %s %s\n" "$pack" "$size" "$before" "$after"'
  # Hold the mounted helper inert until the API identities have been rechecked.
  # Physical corruption happens only in the explicit exec below.
  jq -cn --arg ns "$namespace" --arg run "$run_id" --arg image "$recovery_io_image" \
    '{apiVersion:"v1",kind:"Pod",metadata:{name:"recovery-corrupt-storage",namespace:$ns,labels:{"arcade.gobha.me/e2e-run":$run}},
      spec:{automountServiceAccountToken:false,restartPolicy:"Never",activeDeadlineSeconds:180,
        securityContext:{runAsNonRoot:true,runAsUser:65532,runAsGroup:65532,fsGroup:65532,seccompProfile:{type:"RuntimeDefault"}},
        containers:[{name:"corrupt",image:$image,command:["sh","-ec","sleep 150"],
          resources:{requests:{cpu:"5m",memory:"8Mi"},limits:{cpu:"100m",memory:"32Mi"}},
          securityContext:{allowPrivilegeEscalation:false,readOnlyRootFilesystem:true,capabilities:{drop:["ALL"]}},
          volumeMounts:[{name:"repository",mountPath:"/repository"}]}],
        volumes:[{name:"repository",persistentVolumeClaim:{claimName:"recovery-repository-data"}}]}}' \
    >"$workspace/corruption-storage-pod.json"
  kube create --filename "$workspace/corruption-storage-pod.json" >/dev/null
  writer_uid=$(kube get pod recovery-corrupt-storage --namespace "$namespace" --output=jsonpath='{.metadata.uid}')
  [[ "$writer_uid" =~ ^[0-9a-f-]{36}$ ]] || die "corruption helper has no exact Pod UID"
  kube_bounded 110 wait pod/recovery-corrupt-storage --namespace "$namespace" --for=condition=Ready --timeout=100s >/dev/null
  observed=$(kube get pod recovery-corrupt-storage --namespace "$namespace" --output=json)
  jq -e --arg uid "$writer_uid" --arg image "$recovery_io_image" --arg run "$run_id" '
    .metadata.uid == $uid and .metadata.deletionTimestamp == null and .metadata.labels["arcade.gobha.me/e2e-run"] == $run and
    .status.phase == "Running" and .spec.automountServiceAccountToken == false and
    .spec.securityContext.runAsUser == 65532 and .spec.securityContext.runAsGroup == 65532 and
    (.spec.initContainers // [] | length) == 0 and (.spec.containers | length) == 1 and
    .spec.containers[0].name == "corrupt" and .spec.containers[0].image == $image and
    .spec.containers[0].command == ["sh","-ec","sleep 150"] and (.spec.containers[0].env // [] | length) == 0 and
    (.spec.volumes | length) == 1 and .spec.volumes[0].name == "repository" and
    .spec.volumes[0].persistentVolumeClaim.claimName == "recovery-repository-data"' \
    <<<"$observed" >/dev/null || die "corruption helper execution identity changed before physical write"
  recovery_corruption_assert_repository_users "$writer_uid"
  recovery_corruption_assert_repository_identity "$claim_uid" "$pv" "$pv_uid" "$handle" "$deployment_uid"
  [[ $(kube get deployment minio --namespace "$namespace" --output=jsonpath='{.spec.replicas}') == 0 ]] \
    || die "MinIO fixture resumed before physical corruption"
  kube_bounded 30 exec recovery-corrupt-storage --namespace "$namespace" --container=corrupt -- \
    sh -ec "$script" corrupt "$prefix" "$pack" \
    >>"$workspace/recovery-marker-evidence.txt"
  [[ $(kube get pod recovery-corrupt-storage --namespace "$namespace" --output=jsonpath='{.metadata.uid}') == "$writer_uid" ]] \
    || die "corruption helper Pod identity changed before cleanup"
  kube_bounded 70 delete pod recovery-corrupt-storage --namespace "$namespace" --wait=true --timeout=60s >/dev/null
  recovery_corruption_wait_repository_detached "$pv"
  recovery_corruption_assert_repository_users
  recovery_corruption_assert_repository_identity "$claim_uid" "$pv" "$pv_uid" "$handle" "$deployment_uid"
  kube scale deployment/minio --namespace "$namespace" --replicas=1 >/dev/null
  kube_bounded 190 rollout status deployment/minio --namespace "$namespace" --timeout=180s >/dev/null
  recovery_record "physical corruption applied to one native pack in isolated repository prefix"

  recovery_create_restore recovery-corrupt-restore corrupt-backup "$secret"
  restore_uid=$(kube get gamerestore recovery-corrupt-restore --namespace "$namespace" --output=jsonpath='{.metadata.uid}')
  recovery_wait_settled_failure recovery-corrupt-restore VerificationFailed
  result=$(kube get gamerestore recovery-corrupt-restore --namespace "$namespace" --output=json)
  jq -e --arg uid "$restore_uid" '.metadata.uid == $uid and .status.phase == "Failed" and
    .status.fence == null and .status.preflightVerifiedAt == null and
    (.status.candidateData // [] | length) == 0 and (.status.activeData // [] | length) == 0 and
    .status.candidateVerification == null and .status.activationStartedAt == null' \
    <<<"$result" >/dev/null || die "corrupt repository restore crossed the repository-only preflight boundary"
  kube get pvc --namespace "$namespace" --selector="arcade.gobha.me/restore-uid=$restore_uid" --output=json \
    | jq -e '.items | length == 0' >/dev/null || die "corrupt repository restore provisioned candidate claims"
  recovery_assert_original
  recovery_corruption_restic_job recovery-primary-check "$repository_secret_name" '["check","--read-data-subset=100%"]'
  recovery_record "corrupt snapshot refused during preflight; original world Ready and original repository check100% passed"
}
