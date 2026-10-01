#!/usr/bin/env bash
# Copyright 2026 gobha-me
# SPDX-License-Identifier: Apache-2.0
# Positive recovery proof, run only inside the disposable owned Kind cluster.

recovery_assert_current_complete() {
  local resource=$1 name=$2 phase=$3 status=$4 reason=$5 result
  result=$(kube get "$resource" "$name" --namespace "$namespace" --output=json)
  jq -e --arg phase "$phase" --arg status "$status" --arg reason "$reason" '
    .metadata.generation as $generation |
    .status.phase == $phase and .status.observedGeneration == $generation and
    ([.status.conditions[]? | select(.type == "Complete")] | length) == 1 and
    (.status.conditions | any(.type == "Complete" and .status == $status and
      .reason == $reason and .observedGeneration == $generation))' <<<"$result" >/dev/null \
    || die "$resource/$name lacks a current Complete=$status/$reason condition at $phase"
}

recovery_prove_restore_after_controller_restart() (
  say "proving fresh-claim Factorio recovery across a real controller restart"
  local fixture pod uid node id pid paused=false restore_uid workers worker_uid job_uid
  local deadline state controllers controller_name controller_uid controller_container_id replacement
  local candidate claim_uid candidate_identity candidate_path pv handle game live_server
  fixture=$(kube get pods --namespace "$namespace" --selector=arcade.gobha.me/e2e-component=minio --output=json)
  jq -e --arg run "$run_id" '.items | length == 1 and .[0].metadata.labels["arcade.gobha.me/e2e-run"] == $run' \
    <<<"$fixture" >/dev/null || die "recovery restart requires one owned repository fixture"
  pod=$(jq -r '.items[0].metadata.name' <<<"$fixture")
  uid=$(jq -r '.items[0].metadata.uid' <<<"$fixture")
  node=$(jq -r '.items[0].spec.nodeName' <<<"$fixture")
  id=$(jq -r '.items[0].status.containerStatuses[] | select(.name == "minio") | .containerID' <<<"$fixture")
  id=${id#containerd://}
  pid=$(run_bounded 10 docker exec "$node" crictl inspect "$id" | jq -r '.info.pid // empty')
  trap 'if [[ "$paused" == true ]]; then recovery_fault_signal_owned "$node" "$id" "$uid" minio "$pid" CONT >/dev/null 2>&1 || :; fi' EXIT
  recovery_fault_signal_owned "$node" "$id" "$uid" minio "$pid" STOP \
    || die "cannot hold the owned repository before recovery preflight"
  paused=true
  recovery_create_restore successful-recovery original-backup "$repository_secret_name"
  restore_uid=$(kube get gamerestore successful-recovery --namespace "$namespace" --output=jsonpath='{.metadata.uid}')
  deadline=$((SECONDS + 150))
  while (( SECONDS < deadline )); do
    workers=$(kube get pods --namespace "$namespace" \
      --selector "arcade.gobha.me/restore-uid=$restore_uid,arcade.gobha.me/restore-stage=Preflight" --output=json)
    if jq -e '.items | length == 1 and .[0].status.phase == "Running"
      and any(.[0].status.containerStatuses[]?; .name == "restore-worker" and .state.running != null)' \
      <<<"$workers" >/dev/null; then break; fi
    sleep 1
  done
  jq -e '.items | length == 1 and .[0].status.phase == "Running"' <<<"$workers" >/dev/null \
    || die "recovery preflight did not expose an active worker before controller restart"
  worker_uid=$(jq -r '.items[0].metadata.uid' <<<"$workers")
  job_uid=$(jq -r '.items[0].metadata.ownerReferences[] | select(.kind == "Job" and .controller == true) | .uid' <<<"$workers")
  assert_controller_image
  controllers=$(kube get pods --namespace "$namespace" --selector=app.kubernetes.io/name=arcadectl-controller --output=json)
  jq -e '.items | length == 1 and .[0].status.phase == "Running" and
    any(.[0].status.containerStatuses[]?; .name == "controller" and .ready == true and
      .state.running != null and (.containerID | startswith("containerd://")))' <<<"$controllers" >/dev/null \
    || die "controller restart requires one exact running controller Pod"
  controller_name=$(jq -r '.items[0].metadata.name' <<<"$controllers")
  controller_uid=$(jq -r '.items[0].metadata.uid' <<<"$controllers")
  controller_container_id=$(jq -r '.items[0].status.containerStatuses[] | select(.name == "controller") | .containerID' \
    <<<"$controllers")
  jq -cn --arg uid "$controller_uid" '{apiVersion:"v1",kind:"DeleteOptions",preconditions:{uid:$uid}}' \
    >"$workspace/recovery-controller-delete.json"
  verify_cluster_ownership || die "lost ownership before controller fault injection"
  kube delete --raw "/api/v1/namespaces/$namespace/pods/$controller_name" \
    --filename "$workspace/recovery-controller-delete.json" >/dev/null
  wait_absent pod "$controller_name" 90
  kube_bounded 160 rollout status deployment/arcadectl-controller --namespace "$namespace" --timeout=150s >/dev/null
  replacement=$(kube get pods --namespace "$namespace" --selector=app.kubernetes.io/name=arcadectl-controller --output=json)
  jq -e --arg old "$controller_uid" --arg old_container "$controller_container_id" '
    .items | length == 1 and .[0].metadata.uid != $old and .[0].status.phase == "Running" and
    any(.[0].status.containerStatuses[]?; .name == "controller" and .ready == true and
      .state.running != null and (.containerID | startswith("containerd://")) and .containerID != $old_container)' \
    <<<"$replacement" >/dev/null || die "controller fault did not create a distinct runtime"
  assert_controller_image
  workers=$(kube get pods --namespace "$namespace" \
    --selector "arcade.gobha.me/restore-uid=$restore_uid,arcade.gobha.me/restore-stage=Preflight" --output=json)
  jq -e --arg uid "$worker_uid" --arg job "$job_uid" '.items | length == 1 and .[0].metadata.uid == $uid
    and any(.[0].metadata.ownerReferences[]; .kind == "Job" and .uid == $job)' <<<"$workers" >/dev/null \
    || die "controller restart duplicated or replaced the still-authorized preflight worker"
  recovery_fault_signal_owned "$node" "$id" "$uid" minio "$pid" CONT || die "cannot resume the exact owned repository"
  paused=false
  recovery_record "controller restart old=$controller_uid new=$(jq -r '.items[0].metadata.uid' <<<"$replacement") preserved worker=$worker_uid job=$job_uid"
  recovery_wait_operation gamerestore successful-recovery Succeeded 420
  recovery_assert_current_complete gamerestore successful-recovery Succeeded True Completed
  state=$(kube get gamerestore successful-recovery --namespace "$namespace" --output=json)
  jq -e --arg original_claim "$claim_name" --arg original_uid "$recovery_original_pvc_uid" '
    .status.preflightVerifiedAt != null and .status.activationStartedAt != null and .status.completedAt != null and
    .status.populateAttempts == 1 and (.status.populateRetryPending // false) == false and
    .status.artifact.provenance.backupRef == .spec.backupRef and
    .status.artifact.provenance.repositorySecretRef == .spec.repositorySecretRef and
    .status.artifact.verification.result == "Verified" and .status.artifact.verification.verifiedAt != null and
    .status.artifact.pathCount == (.status.source.paths | length) and
    .status.candidateVerification.result == "Verified" and .status.candidateVerification.verifiedAt != null and
    .status.candidateVerification.manifestDigest == .status.artifact.manifestDigest and
    .status.candidateVerification.pathCount == (.status.source.paths | length) and
    (.status.source.paths | length) == 1 and (.status.candidateData | length) == 1 and
    (.status.previousData | length) == 1 and .status.activeData == .status.candidateData and
    .status.previousDataIdentity == .spec.targetData.identity and
    .status.previousData[0].name == .status.source.paths[0].name and
    .status.previousData[0].mountPath == .status.source.paths[0].mountPath and
    .status.previousData[0].claimRef == .status.source.paths[0].claimRef and
    .status.previousData[0].name == .spec.targetData.claims[0].path and
    .status.previousData[0].claimRef == .spec.targetData.claims[0].claimRef and
    .status.previousData[0].claimRef.name == $original_claim and
    .status.previousData[0].claimRef.uid == $original_uid and
    .status.candidateData[0].name == .status.source.paths[0].name and
    .status.candidateData[0].mountPath == .status.source.paths[0].mountPath and
    .status.candidateData[0].claimRef.name != .status.previousData[0].claimRef.name and
    .status.candidateData[0].claimRef.uid != .status.previousData[0].claimRef.uid and
    .status.runtime.phase == "Ready" and .status.runtime.gameServer.name == .spec.target.name and
    .status.runtime.gameServer.uid == .spec.target.uid and .status.runtime.gameServer.desiredState == "Running" and
    .status.runtime.gameServer.generation == .status.runtimeJournal.candidateStartGeneration' <<<"$state" >/dev/null \
    || die "successful recovery omitted candidate verification, activation or exact running settlement"
  candidate=$(jq -r '.status.candidateData[0].claimRef.name' <<<"$state")
  claim_uid=$(jq -r '.status.candidateData[0].claimRef.uid' <<<"$state")
  candidate_path=$(jq -r '.status.candidateData[0].name' <<<"$state")
  [[ "$claim_uid" != "$recovery_original_pvc_uid" ]] || die "successful restore reused original PVC"
  kube get pvc "$candidate" --namespace "$namespace" --output=json | jq -e \
    --arg uid "$claim_uid" --arg path "$candidate_path" '
      .metadata.uid == $uid and .status.phase == "Bound" and
      .metadata.labels["arcade.gobha.me/data-path"] == $path and
      (.metadata.labels["arcade.gobha.me/data-identity"] | length) > 0' >/dev/null \
    || die "restored candidate PVC lacks its exact bound data topology"
  pv=$(kube get pvc "$candidate" --namespace "$namespace" --output=jsonpath='{.spec.volumeName}')
  handle=$(kube get pv "$pv" --output=jsonpath='{.spec.csi.volumeHandle}')
  [[ -n "$handle" && "$handle" != "$recovery_original_handle" ]] || die "restored CSI world aliases original backing storage"
  wait_server "$server_name" Ready Ready 150
  live_server=$(kube get gameserver "$server_name" --namespace "$namespace" --output=json)
  candidate_identity=$(jq -r '.status.activeData.identity' <<<"$live_server")
  jq -e --arg uid "$(jq -r '.spec.target.uid' <<<"$state")" --arg identity "$candidate_identity" \
    --arg path "$candidate_path" --arg claim "$candidate" --arg claim_uid "$claim_uid" '
      .metadata.uid == $uid and .metadata.generation == .status.observedGeneration and
      .spec.desiredState == "Running" and .status.phase == "Ready" and
      .status.activeData == .status.observedData and .status.activeData.identity == $identity and
      (.status.activeData.claims | length) == 1 and .status.activeData.claims[0].path == $path and
      .status.activeData.claims[0].claimRef.name == $claim and
      .status.activeData.claims[0].claimRef.uid == $claim_uid' <<<"$live_server" >/dev/null \
    || die "running GameServer does not select the exact verified candidate topology"
  [[ $(kube get pvc "$candidate" --namespace "$namespace" \
    --output=jsonpath='{.metadata.labels.arcade\.gobha\.me/data-identity}') == "$candidate_identity" ]] \
    || die "restored candidate PVC data identity differs from the running selection"
  game=$(kube get pods --namespace "$namespace" \
    --selector="app.kubernetes.io/name=game-server,app.kubernetes.io/instance=$server_name" --output=json)
  jq -e --arg claim "$candidate" '.items | length == 1 and .[0].status.phase == "Running"
    and any(.[0].spec.volumes[]; .persistentVolumeClaim.claimName == $claim)' <<<"$game" >/dev/null \
    || die "running Factorio Pod does not mount the restored candidate"
  kube_bounded 20 exec "$(jq -r '.items[0].metadata.name' <<<"$game")" --namespace "$namespace" --container=game \
    -- sh -ec 'test "$(wc -c < /factorio/.arcadectl-marker-a)" = 8388608; test "$(sha256sum /factorio/.arcadectl-marker-a | cut -d " " -f 1)" = "$1"; test ! -e /factorio/.arcadectl-marker-b; sha256sum /factorio/.arcadectl-marker-a' recovery "$recovery_marker_a_sha256" \
    >>"$workspace/recovery-marker-evidence.txt"
  recovery_stop
  recovery_world_io "$candidate" verify-a-only
  recovery_world_io "$claim_name" verify-ab
  recovery_fault_wait_cleanup "$restore_uid"
  recovery_record "successful-recovery candidate=$claim_uid handle=$handle running Factorio marker A proved; B absent; original A+B retained"
)

recovery_wait_destroy_target_detached() {
  local claim=$1 claim_uid=$2 pv=$3 pv_uid=$4 backup_uid=$5
  local users attachments deadline=$((SECONDS + 150))
  verify_cluster_ownership || die "destroy detach proof lost the owned Kind cluster"
  while :; do
    kube get pvc "$claim" --namespace "$namespace" --output=json | jq -e \
      --arg uid "$claim_uid" --arg pv "$pv" --arg backup "$backup_uid" '
        .metadata.uid == $uid and .metadata.deletionTimestamp == null and
        .spec.volumeName == $pv and .status.phase == "Bound" and
        .metadata.annotations["arcade.gobha.me/cold-backup-uid"] == $backup' >/dev/null \
      || die "destroy target claim identity or cold continuity changed while awaiting detach"
    kube get pv "$pv" --output=json | jq -e --arg uid "$pv_uid" --arg claim "$claim_uid" --arg ns "$namespace" '
      .metadata.uid == $uid and .metadata.deletionTimestamp == null and
      .spec.claimRef.uid == $claim and .spec.claimRef.namespace == $ns and
      .spec.persistentVolumeReclaimPolicy == "Retain" and .spec.csi.driver == "hostpath.csi.k8s.io"' >/dev/null \
      || die "destroy target backing identity changed while awaiting detach"
    users=$(kube get pods --namespace "$namespace" --output=json)
    attachments=$(kube get volumeattachments --output=json)
    if jq -e --arg claim "$claim" '[.items[] |
      select(any(.spec.volumes[]?; .persistentVolumeClaim.claimName == $claim))] | length == 0' \
      <<<"$users" >/dev/null && jq -e --arg pv "$pv" '[.items[] |
      select(.spec.source.persistentVolumeName == $pv)] | length == 0' <<<"$attachments" >/dev/null; then
      recovery_record "destroy target=$claim_uid backup=$backup_uid remains cold; all Pod users and exact PV attachments absent"
      return 0
    fi
    (( SECONDS < deadline )) || die "destroy target did not detach after its successful cold backup"
    sleep 2
  done
}

recovery_prove_destroy_after_recovery() {
  say "proving destroy refusals and fresh verified deletion only after successful real recovery"
  local server selection candidate candidate_uid pv pv_uid backup backup_uid repository request name challenge stale result
  local artifact manifest_digest server_uid server_generation current delete_options
  server=$(kube get gameserver "$server_name" --namespace "$namespace" --output=json)
  selection=$(jq -c '.status.activeData // .status.observedData' <<<"$server")
  jq -e '(.identity | length) > 0 and (.claims | length) == 1 and
    (.claims[0].path | length) > 0 and (.claims[0].claimRef.name | length) > 0 and
    (.claims[0].claimRef.uid | length) > 0 and (.claims[0].claimRef.namespace // null) == null' \
    <<<"$selection" >/dev/null || die "destroy target selection is not one complete exact Factorio world"
  candidate=$(jq -r '.claims[0].claimRef.name' <<<"$selection")
  candidate_uid=$(jq -r '.claims[0].claimRef.uid' <<<"$selection")
  [[ "$candidate_uid" != "$recovery_original_pvc_uid" ]] || die "destroy target aliases original source"
  pv=$(kube get pvc "$candidate" --namespace "$namespace" --output=jsonpath='{.spec.volumeName}')
  pv_uid=$(kube get pv "$pv" --output=jsonpath='{.metadata.uid}')
  recovery_create_backup restored-world-backup "$repository_secret_name"
  recovery_assert_current_complete gamebackup restored-world-backup Succeeded True Completed
  backup=$(kube get gamebackup restored-world-backup --namespace "$namespace" --output=json)
  backup_uid=$(jq -r '.metadata.uid' <<<"$backup")
  [[ $(kube get pvc "$candidate" --namespace "$namespace" --output=jsonpath='{.metadata.annotations.arcade\.gobha\.me/cold-backup-uid}') == "$backup_uid" ]] \
    || die "fresh restored-world backup omitted durable cold continuity"
  recovery_wait_destroy_target_detached "$candidate" "$candidate_uid" "$pv" "$pv_uid" "$backup_uid"
  repository=$(recovery_repository_ref "$repository_secret_name")
  server=$(kube get gameserver "$server_name" --namespace "$namespace" --output=json)
  server_uid=$(jq -r '.metadata.uid' <<<"$server")
  server_generation=$(jq -r '.metadata.generation' <<<"$server")
  jq -e --arg uid "$server_uid" --argjson generation "$server_generation" --argjson selection "$selection" '
    .metadata.uid == $uid and .metadata.deletionTimestamp == null and
    .metadata.generation == $generation and .status.observedGeneration == $generation and
    .spec.desiredState == "Stopped" and
    .status.phase == "Stopped" and .status.activeData == $selection and .status.observedData == $selection' \
    <<<"$server" >/dev/null || die "fresh backup target is not the exact current stopped GameServer selection"
  jq -e --arg uid "$server_uid" --arg backup_uid "$backup_uid" --argjson generation "$server_generation" \
    --argjson selection "$selection" --argjson repository "$repository" '
    .spec.source.uid == $uid and .spec.source.generation == $generation and
    .spec.source.desiredState == "Stopped" and .spec.sourceData == $selection and
    .status.phase == "Succeeded" and .status.observedGeneration == .metadata.generation and
    .status.artifact.provenance.backupRef.name == .metadata.name and
    .status.artifact.provenance.backupRef.uid == $backup_uid and
    .status.artifact.provenance.repositorySecretRef == $repository and
    .status.artifact.verification.result == "Verified" and .status.artifact.verification.verifiedAt != null and
    .status.artifact.pathCount == ($selection.claims | length)' <<<"$backup" >/dev/null \
    || die "fresh backup does not pin verified current stopped data"
  request=$(jq -cn --arg ns "$namespace" --argjson server "$server" --argjson data "$selection" \
    --arg uid "$backup_uid" --argjson repository "$repository" \
    '{apiVersion:"arcade.gobha.me/v1alpha1",kind:"GameDestroy",metadata:{name:"recovery-destroy",namespace:$ns},
      spec:{mode:"VerifiedBackup",target:{gameServer:{name:$server.metadata.name,uid:$server.metadata.uid},game:$server.spec.game,data:$data},
        backupRef:{name:"restored-world-backup",uid:$uid},repositorySecretRef:$repository}}')
  jq '.metadata.name="recovery-destroy-unsafe-denied" |
    .metadata.annotations={"arcade.gobha.me/unsafe-requested-by":"system:serviceaccount:arcadectl-system:arcadectl-destroy-admin"} |
    .spec.mode="UnsafeNoBackup" | .spec.unsafeReason="Recovery proof must not bypass verified backup" |
    del(.spec.backupRef,.spec.repositorySecretRef)' <<<"$request" >"$workspace/recovery-destroy-unsafe-denied.json"
  if kube create --dry-run=server --filename "$workspace/recovery-destroy-unsafe-denied.json" \
    >"$workspace/recovery-destroy-unsafe-refusal.txt" 2>&1; then
    die "ordinary recovery identity created an unsafe no-backup destroy"
  fi
  grep -Fq 'distinct Arcadectl destroy admin identity' "$workspace/recovery-destroy-unsafe-refusal.txt" \
    || die "unsafe no-backup refusal was not the exact administrator admission policy"
  assert_absent gamedestroy/recovery-destroy-unsafe-denied
  current=$(kube get gameserver "$server_name" --namespace "$namespace" --output=json)
  jq -e --arg uid "$server_uid" --argjson generation "$server_generation" --argjson selection "$selection" '
    .metadata.uid == $uid and .metadata.deletionTimestamp == null and
    .metadata.generation == $generation and .status.observedGeneration == $generation and
    .spec.desiredState == "Stopped" and
    .status.phase == "Stopped" and .status.activeData == $selection and .status.observedData == $selection' \
    <<<"$current" >/dev/null || die "unsafe destroy denial changed the existing stopped target"
  [[ $(kube get pvc "$candidate" --namespace "$namespace" --output=jsonpath='{.metadata.uid}') == "$candidate_uid" ]] \
    || die "unsafe destroy denial changed the retained candidate"
  jq 'del(.spec.backupRef)' <<<"$request" >"$workspace/recovery-destroy-missing.json"
  if kube create --filename "$workspace/recovery-destroy-missing.json" >"$workspace/recovery-destroy-refusal.txt" 2>&1; then
    die "destroy accepted a missing backup reference"
  fi
  grep -Fq 'Invalid' "$workspace/recovery-destroy-refusal.txt" || die "missing backup refusal was not API validation"
  assert_absent gamedestroy/recovery-destroy
  for name in missing-backup stale-backup; do
    if [[ "$name" == missing-backup ]]; then
      jq '.metadata.name="recovery-destroy-missing-backup" | .spec.backupRef.name="nonexistent-backup"' <<<"$request"
    else
      jq '.metadata.name="recovery-destroy-stale-backup" | .spec.backupRef.uid="00000000-0000-4000-8000-000000000001"' <<<"$request"
    fi >"$workspace/recovery-destroy-$name.json"
    kube create --filename "$workspace/recovery-destroy-$name.json" >/dev/null
    recovery_wait_operation gamedestroy "recovery-destroy-$name" Failed 90
    recovery_assert_current_complete gamedestroy "recovery-destroy-$name" Failed False PreflightRejected
    kube get gamedestroy "recovery-destroy-$name" --namespace "$namespace" --output=json \
      | jq -e '.status.completedAt != null and .status.verification == null and
        any(.status.conditions[]; .type == "Complete" and
          .message == "exact succeeded backup and stopped runtime evidence are unavailable") and
        (.status.deletionJournal // [] | length) == 0' >/dev/null \
      || die "invalid backup destroy crossed the deletion boundary"
  done
  # Remove only the stopped GameServer; this must preserve both exact worlds.
  current=$(kube get gameserver "$server_name" --namespace "$namespace" --output=json)
  jq -e --arg uid "$server_uid" --argjson selection "$selection" --argjson request "$request" \
    --argjson generation "$server_generation" '
      .metadata.uid == $uid and .metadata.uid == $request.spec.target.gameServer.uid and
      .metadata.name == $request.spec.target.gameServer.name and .metadata.deletionTimestamp == null and
      .metadata.generation == $generation and .status.observedGeneration == $generation and
      .spec.game == $request.spec.target.game and .spec.desiredState == "Stopped" and .status.phase == "Stopped" and
      .status.activeData == $selection and .status.observedData == $selection and
      $request.spec.target.data == $selection' <<<"$current" >/dev/null \
    || die "refusing to remove a changed, reused or unsettled GameServer before destroy"
  [[ $(kube get pvc "$candidate" --namespace "$namespace" --output=jsonpath='{.metadata.uid}') == "$candidate_uid" ]] \
    || die "refusing to remove the GameServer after its selected PVC identity changed"
  delete_options="$workspace/recovery-gameserver-delete.json"
  jq -cn --arg uid "$server_uid" \
    '{apiVersion:"v1",kind:"DeleteOptions",preconditions:{uid:$uid},propagationPolicy:"Foreground"}' \
    >"$delete_options"
  verify_cluster_ownership || die "lost ownership before exact stopped GameServer removal"
  kube delete --raw "/apis/arcade.gobha.me/v1alpha1/namespaces/$namespace/gameservers/$server_name" \
    --filename "$delete_options" >/dev/null
  wait_absent gameserver "$server_name" 60
  assert_runtime_absent "$server_name"
  printf '%s\n' "$request" >"$workspace/recovery-destroy.json"
  kube create --filename "$workspace/recovery-destroy.json" >/dev/null
  recovery_wait_operation gamedestroy recovery-destroy Preview 90
  recovery_assert_current_complete gamedestroy recovery-destroy Preview Unknown Accepted
  result=$(kube get gamedestroy recovery-destroy --namespace "$namespace" --output=json)
  challenge=$(jq -r '.status.preview.challenge' <<<"$result")
  jq -e '.status.preview.restoreGuidance != "" and (.status.deletionJournal // [] | length) == 0' <<<"$result" >/dev/null \
    || die "unconfirmed preview mutated world or omitted recovery guidance"
  [[ $(kube get pvc "$candidate" --namespace "$namespace" --output=jsonpath='{.metadata.uid}') == "$candidate_uid" ]] \
    || die "preview changed retained candidate"
  jq '.metadata.name="recovery-destroy-stale-confirmation"' <<<"$request" >"$workspace/recovery-destroy-stale-confirmation.json"
  kube create --filename "$workspace/recovery-destroy-stale-confirmation.json" >/dev/null
  recovery_wait_operation gamedestroy recovery-destroy-stale-confirmation Preview 90
  recovery_assert_current_complete gamedestroy recovery-destroy-stale-confirmation Preview Unknown Accepted
  stale=$(jq -cn --arg challenge "$challenge" '{spec:{confirmationChallenge:$challenge}}')
  if kube patch gamedestroy recovery-destroy-stale-confirmation --namespace "$namespace" --type=merge --patch "$stale" \
    >"$workspace/recovery-destroy-stale-refusal.txt" 2>&1; then die "another request's stale challenge authorized destruction"; fi
  grep -Fq 'Invalid' "$workspace/recovery-destroy-stale-refusal.txt" || die "stale confirmation refusal was not API validation"
  kube patch gamedestroy recovery-destroy-stale-confirmation --namespace "$namespace" --type=merge \
    --patch '{"spec":{"cancelRequested":true}}' >/dev/null
  recovery_wait_operation gamedestroy recovery-destroy-stale-confirmation Cancelled 90
  recovery_assert_current_complete gamedestroy recovery-destroy-stale-confirmation Cancelled False Cancelled
  kube get gamedestroy recovery-destroy-stale-confirmation --namespace "$namespace" --output=json | jq -e \
    '.status.completedAt != null and .status.verification == null and
      (.status.deletionJournal // [] | length) == 0' >/dev/null \
    || die "cancelled stale-confirmation destroy crossed the verification or deletion boundary"
  kube patch gamedestroy recovery-destroy --namespace "$namespace" --type=merge --patch "$stale" >/dev/null
  recovery_wait_operation gamedestroy recovery-destroy Succeeded 360
  recovery_assert_current_complete gamedestroy recovery-destroy Succeeded True Destroyed
  result=$(kube get gamedestroy recovery-destroy --namespace "$namespace" --output=json)
  artifact=$(jq -r '.status.artifact.id' <<<"$backup")
  manifest_digest=$(jq -r '.status.artifact.manifestDigest' <<<"$backup")
  jq -e --arg uid "$candidate_uid" --arg claim "$candidate" --arg artifact "$artifact" \
    --arg digest "$manifest_digest" --arg backup_uid "$backup_uid" --argjson repository "$repository" \
    --argjson selection "$selection" '.status.completedAt != null and
    .spec.target.data == $selection and .status.verification.backupRef.name == "restored-world-backup" and
    .status.verification.backupRef.uid == $backup_uid and
    .status.verification.repositorySecretRef == $repository and
    .status.verification.artifactID == $artifact and .status.verification.manifestDigest == $digest and
    .status.verification.pathCount == ($selection.claims | length) and
    .status.verification.verifiedAt != null and .status.verification.coldAt != null and
    (.status.deletionJournal | length) == ($selection.claims | length) and
    .status.deletionJournal[0].path == $selection.claims[0].path and
    .status.deletionJournal[0].claimRef == $selection.claims[0].claimRef and
    .status.deletionJournal[0].claimRef.name == $claim and
    .status.deletionJournal[0].claimRef.uid == $uid and
    .status.deletionJournal[0].requestedAt != null and
    .status.deletionJournal[0].observedDeletedAt != null' <<<"$result" >/dev/null \
    || die "destroy succeeded without fresh repository proof and exact observed PVC deletion"
  wait_absent pvc "$candidate" 90
  kube_bounded 100 wait "pv/$pv" --for=jsonpath='{.status.phase}'=Released --timeout=90s >/dev/null
  [[ $(kube get pv "$pv" --output=jsonpath='{.metadata.uid}') == "$pv_uid" ]] || die "Retain PV identity changed"
  [[ $(kube get pvc "$claim_name" --namespace "$namespace" --output=jsonpath='{.metadata.uid}') == "$recovery_original_pvc_uid" ]] \
    || die "confirmed destroy affected original recovery source"
  recovery_world_io "$claim_name" verify-ab
  recovery_record "destroy refusals proved; fresh verified candidate=$candidate_uid deleted; retained PV=$pv_uid Released; original A+B recoverable"
}
