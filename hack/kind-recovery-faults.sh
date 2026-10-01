#!/usr/bin/env bash
# Copyright 2026 gobha-me
# SPDX-License-Identifier: Apache-2.0
# Sourced only by the ownership-checked, disposable Kind recovery harness.

recovery_fault_wait_cleanup() {
  local uid=$1 deadline=$((SECONDS + 120)) remaining
  while (( SECONDS < deadline )); do
    remaining=$(kube get jobs,pods,leases,configmaps,serviceaccounts,roles,rolebindings \
      --namespace "$namespace" --selector "arcade.gobha.me/restore-uid=$uid" --output=json)
    if jq -e '.items | length == 0' <<<"$remaining" >/dev/null; then
      return 0
    fi
    sleep 2
  done
  die "failed recovery operation retained worker or lease authority"
}

recovery_fault_bad_credentials() {
  say "injecting real repository credential failure without changing its immutable Secret"
  local secret_ref repository_claim_uid repository_handle rotated restore_uid result
  secret_ref=$(recovery_repository_ref "$repository_secret_name")
  repository_claim_uid=$(kube get pvc recovery-repository-data --namespace "$namespace" --output=jsonpath='{.metadata.uid}')
  repository_handle=$(kube get pvc recovery-repository-data --namespace "$namespace" --output=jsonpath='{.spec.volumeName}')
  repository_handle=$(kube get pv "$repository_handle" --output=jsonpath='{.spec.csi.volumeHandle}')
  [[ -n "$repository_claim_uid" && -n "$repository_handle" ]] || die "credential fault requires persistent repository storage"
  rotated="rotated-$run_suffix-canary"
  recovery_extra_canaries+=("$rotated")
  # Replace only the server's credential. Client authority still refers to the
  # original immutable Secret revision, so failure must occur inside Restic.
  jq -cn --arg password "$rotated" \
    '{spec:{template:{spec:{containers:[{name:"minio",env:[{name:"MINIO_ROOT_PASSWORD",value:$password,valueFrom:null}]}]}}}}' \
    >"$workspace/recovery-credential-fault-patch.json"
  kube patch deployment minio --namespace "$namespace" --type=strategic \
    --patch-file "$workspace/recovery-credential-fault-patch.json" >/dev/null
  kube_bounded 190 rollout status deployment/minio --namespace "$namespace" --timeout=180s >/dev/null
  recovery_record "credential fault server rotation settled; immutable client authority unchanged"
  recovery_create_restore bad-credentials original-backup "$repository_secret_name"
  restore_uid=$(kube get gamerestore bad-credentials --namespace "$namespace" --output=jsonpath='{.metadata.uid}')
  recovery_wait_settled_failure bad-credentials VerificationFailed
  result=$(kube get gamerestore bad-credentials --namespace "$namespace" --output=json)
  jq -e '.status.phase == "Failed" and .status.fence == null and .status.preflightVerifiedAt == null
    and (.status.candidateData // [] | length) == 0 and .status.candidateVerification == null
    and .status.activationStartedAt == null and (.status.activeData // [] | length) == 0' \
    <<<"$result" >/dev/null || die "credential failure crossed repository-only preflight boundary"
  kube get pvc --namespace "$namespace" --selector "arcade.gobha.me/restore-uid=$restore_uid" --output=json \
    | jq -e '.items | length == 0' >/dev/null || die "credential fault provisioned candidate claims"
  recovery_fault_wait_cleanup "$restore_uid"
  [[ $(recovery_repository_ref "$repository_secret_name") == "$secret_ref" ]] \
    || die "credential fault changed immutable repository authority"
  jq -cn --arg secret "$repository_secret_name" \
    '{spec:{template:{spec:{containers:[{name:"minio",env:[{name:"MINIO_ROOT_PASSWORD",value:null,
      valueFrom:{secretKeyRef:{name:$secret,key:"awsSecretAccessKey"}}}]}]}}}}' \
    >"$workspace/recovery-credential-repair-patch.json"
  kube patch deployment minio --namespace "$namespace" --type=strategic \
    --patch-file "$workspace/recovery-credential-repair-patch.json" >/dev/null
  kube_bounded 190 rollout status deployment/minio --namespace "$namespace" --timeout=180s >/dev/null
  local repository_pv repaired_handle
  [[ $(kube get pvc recovery-repository-data --namespace "$namespace" --output=jsonpath='{.metadata.uid}') == "$repository_claim_uid" ]] \
    || die "repository credential repair replaced persistent storage"
  repository_pv=$(kube get pvc recovery-repository-data --namespace "$namespace" --output=jsonpath='{.spec.volumeName}')
  repaired_handle=$(kube get pv "$repository_pv" --output=jsonpath='{.spec.csi.volumeHandle}')
  [[ "$repaired_handle" == "$repository_handle" ]] || die "repository credential repair changed CSI backing handle"
  recovery_assert_original
  recovery_record "fault bad-credentials uid=$restore_uid Failed/VerificationFailed before fence or candidate; original preserved"
}

recovery_fault_capacity() {
  say "exhausting the fixture world pool and waiting for the real five-minute provisioning deadline"
  local filler_uid filler_pv filler_pv_uid filler_handle restore_uid candidates candidate candidate_uid
  local deadline result events candidate_pv candidate_handle
  # Original=512Mi, filler=3584Mi: all 4Gi of this separate CSI capacity pool
  # is allocated. Repository and unrelated sentinel pools remain unaffected.
  jq -cn --arg ns "$namespace" --arg run "$run_id" \
    '{apiVersion:"v1",kind:"PersistentVolumeClaim",metadata:{name:"recovery-capacity-filler",namespace:$ns,
      labels:{"arcade.gobha.me/e2e-run":$run}},spec:{accessModes:["ReadWriteOnce"],
      storageClassName:"arcadectl-world-filler",resources:{requests:{storage:"3584Mi"}}}}' \
    >"$workspace/recovery-capacity-filler.json"
  kube create --filename "$workspace/recovery-capacity-filler.json" >/dev/null
  kube_bounded 130 wait pvc/recovery-capacity-filler --namespace "$namespace" \
    --for=jsonpath='{.status.phase}'=Bound --timeout=120s >/dev/null
  filler_uid=$(kube get pvc recovery-capacity-filler --namespace "$namespace" --output=jsonpath='{.metadata.uid}')
  filler_pv=$(kube get pvc recovery-capacity-filler --namespace "$namespace" --output=jsonpath='{.spec.volumeName}')
  filler_pv_uid=$(kube get pv "$filler_pv" --output=jsonpath='{.metadata.uid}')
  filler_handle=$(kube get pv "$filler_pv" --output=jsonpath='{.spec.csi.volumeHandle}')
  [[ -n "$filler_uid" && -n "$filler_pv_uid" && -n "$filler_handle" && "$filler_handle" != "$recovery_original_handle" ]] \
    || die "capacity filler does not identify independent CSI backing storage"
  kube get pv "$filler_pv" --output=json | jq -e --arg uid "$filler_uid" \
    '.spec.persistentVolumeReclaimPolicy == "Delete" and .spec.claimRef.uid == $uid' >/dev/null \
    || die "capacity filler must be exact fixture-owned Delete-policy storage"
  recovery_record "capacity filler pvc=$filler_uid pv=$filler_pv_uid handle=$filler_handle 3584Mi Bound"
  recovery_create_restore storage-exhausted original-backup "$repository_secret_name"
  restore_uid=$(kube get gamerestore storage-exhausted --namespace "$namespace" --output=jsonpath='{.metadata.uid}')
  deadline=$((SECONDS + 180))
  while (( SECONDS < deadline )); do
    candidates=$(kube get pvc --namespace "$namespace" --selector "arcade.gobha.me/restore-uid=$restore_uid" --output=json)
    if jq -e '.items | length == 1' <<<"$candidates" >/dev/null; then
      break
    fi
    sleep 2
  done
  jq -e '.items | length == 1' <<<"$candidates" >/dev/null || die "capacity fault did not create one exact managed candidate"
  candidate=$(jq -r '.items[0].metadata.name' <<<"$candidates")
  candidate_uid=$(jq -r '.items[0].metadata.uid' <<<"$candidates")
  [[ -n "$candidate_uid" && "$candidate_uid" != "$recovery_original_pvc_uid" ]] || die "capacity candidate aliases original PVC"
  jq -e '.items[0].status.phase == "Pending" and (.items[0].spec.volumeName // "") == ""' \
    <<<"$candidates" >/dev/null || die "capacity candidate bound despite the exhausted finite pool"
  deadline=$((SECONDS + 90))
  while (( SECONDS < deadline )); do
    events=$(kube get events --namespace "$namespace" --field-selector "involvedObject.uid=$candidate_uid" --output=json)
    if jq -e '.items | any(.reason == "ProvisioningFailed" and (.message | contains("ResourceExhausted")))' \
      <<<"$events" >/dev/null; then
      break
    fi
    sleep 2
  done
  jq -e '.items | any(.reason == "ProvisioningFailed" and (.message | contains("ResourceExhausted")))' \
    <<<"$events" >/dev/null || die "capacity fault lacks actual CSI ResourceExhausted evidence"
  recovery_record "fault storage-exhausted uid=$restore_uid candidate=$candidate_uid Pending CSI ResourceExhausted"
  recovery_wait_settled_failure storage-exhausted StorageUnavailable
  result=$(kube get gamerestore storage-exhausted --namespace "$namespace" --output=json)
  jq -e '.status.phase == "Failed" and .status.preflightVerifiedAt != null and .status.fence != null
    and .status.candidateVerification == null and .status.activationStartedAt == null
    and (.status.candidateData // [] | length) == 0 and (.status.activeData // [] | length) == 0
    and ((.status.completedAt | fromdateiso8601) - (.status.fence.establishedAt | fromdateiso8601)) >= 300' \
    <<<"$result" >/dev/null || die "capacity fault skipped real provisioning deadline or reached candidate activation"
  kube get pvc "$candidate" --namespace "$namespace" --output=json | jq -e --arg uid "$candidate_uid" \
    '.metadata.uid == $uid and .status.phase == "Pending" and (.spec.volumeName // "") == ""' >/dev/null \
    || die "failed capacity restore did not retain its exact Pending candidate"
  recovery_fault_wait_cleanup "$restore_uid"
  recovery_assert_original
  # Release only the recorded unmanaged fixture, never the retained candidate.
  recovery_delete_exact pvc recovery-capacity-filler "$filler_uid"
  wait_absent pvc recovery-capacity-filler 90
  wait_absent pv "$filler_pv" 120
  kube_bounded 190 wait pvc/"$candidate" --namespace "$namespace" \
    --for=jsonpath='{.status.phase}'=Bound --timeout=180s >/dev/null
  candidate_pv=$(kube get pvc "$candidate" --namespace "$namespace" --output=jsonpath='{.spec.volumeName}')
  candidate_handle=$(kube get pv "$candidate_pv" --output=jsonpath='{.spec.csi.volumeHandle}')
  [[ -n "$candidate_handle" && "$candidate_handle" != "$recovery_original_handle" && "$candidate_handle" != "$filler_handle" ]] \
    || die "late-bound failed candidate lacks independent CSI backing identity"
  kube get pvc "$candidate" --namespace "$namespace" --output=json | jq -e --arg uid "$candidate_uid" \
    '.metadata.uid == $uid' >/dev/null || die "capacity repair replaced the retained candidate identity"
  # Observe several reconciliations after binding: late storage must not revive
  # an operation whose durable terminal failure was already recorded.
  deadline=$((SECONDS + 20))
  while (( SECONDS < deadline )); do
    kube get gamerestore storage-exhausted --namespace "$namespace" --output=json | jq -e \
      '.status.phase == "Failed" and .status.candidateVerification == null and .status.activationStartedAt == null
        and (.status.activeData // [] | length) == 0' >/dev/null \
      || die "late candidate binding revived the terminal failed restore"
    sleep 2
  done
  recovery_fault_wait_cleanup "$restore_uid"
  recovery_assert_original
  recovery_record "fault storage-exhausted settled Failed/StorageUnavailable; late candidate=$candidate_uid handle=$candidate_handle Bound without revival"
}

# Signal only a still-running container in an exact Pod on an owned Kind node.
# Do not print the CRI inspect document: it can contain credential environment.
recovery_fault_signal_owned() {
  local node=$1 container_id=$2 pod_uid=$3 container_name=$4 pid=$5 signal=$6 inspect
  [[ "$container_id" =~ ^[0-9a-f]{64}$ && "$pid" =~ ^[1-9][0-9]*$ ]] || return 1
  [[ $'\n'"$node_names"$'\n' == *$'\n'"$node"$'\n'* ]] || return 1
  [[ $(docker inspect "$node" --format '{{index .Config.Labels "io.x-k8s.kind.cluster"}}') == "$cluster_name" ]] || return 1
  inspect=$(docker exec "$node" crictl inspect "$container_id") || return 1
  jq -e --arg id "$container_id" --arg uid "$pod_uid" --arg ns "$namespace" \
    --arg name "$container_name" --arg pid "$pid" \
    '.status.id == $id and .status.state == "CONTAINER_RUNNING" and .status.metadata.name == $name
      and .status.labels["io.kubernetes.pod.uid"] == $uid
      and .status.labels["io.kubernetes.pod.namespace"] == $ns and (.info.pid | tostring) == $pid' \
    <<<"$inspect" >/dev/null || return 1
  # Runtime PID reuse must not turn a fault into a signal to an unrelated task.
  docker exec "$node" sh -ec 'grep -F "$2" "/proc/$1/cgroup" >/dev/null; kill -"$3" "$1"' \
    sh "$pid" "$container_id" "$signal"
}

recovery_fault_worker_crash() (
  say "crashing all three exact authorized populate workers with bounded retries"
  local restore_uid minio_pod minio_uid minio_node minio_id minio_pid minio_paused=false
  local deadline state pod pod_name pod_uid node container_id pid job_name job_uid attempt
  local leases candidate_ref= current_candidate candidate_identity exit_state candidate uid backing_handle
  local previous_pod_uid= previous_job_uid=
  minio_pod=$(kube get pods --namespace "$namespace" --selector=arcade.gobha.me/e2e-component=minio --output=json)
  jq -e --arg run "$run_id" '.items | length == 1 and .[0].metadata.labels["arcade.gobha.me/e2e-run"] == $run' \
    <<<"$minio_pod" >/dev/null || die "worker-crash fault requires one exact owned MinIO Pod"
  minio_uid=$(jq -r '.items[0].metadata.uid' <<<"$minio_pod")
  minio_node=$(jq -r '.items[0].spec.nodeName' <<<"$minio_pod")
  minio_id=$(jq -r '.items[0].status.containerStatuses[] | select(.name == "minio") | .containerID' <<<"$minio_pod")
  minio_id=${minio_id#containerd://}
  minio_pid=$(docker exec "$minio_node" crictl inspect "$minio_id" | jq -r '.info.pid // empty')
  # A subshell-local EXIT trap resumes the fixture even when any assertion dies.
  # The parent harness's owned Kind teardown is the final containment boundary.
  trap 'if [[ "$minio_paused" == true ]]; then recovery_fault_signal_owned "$minio_node" "$minio_id" "$minio_uid" minio "$minio_pid" CONT >/dev/null 2>&1 || :; fi' EXIT
  recovery_create_restore worker-crash original-backup "$repository_secret_name"
  restore_uid=$(kube get gamerestore worker-crash --namespace "$namespace" --output=jsonpath='{.metadata.uid}')
  deadline=$((SECONDS + 180))
  while (( SECONDS < deadline )); do
    state=$(kube get gamerestore worker-crash --namespace "$namespace" --output=json)
    if jq -e '.status.preflightVerifiedAt != null and .status.fence != null and .status.candidateVerification == null' \
      <<<"$state" >/dev/null; then
      break
    fi
    sleep 0.2
  done
  jq -e '.status.preflightVerifiedAt != null and .status.fence != null and .status.candidateVerification == null' \
    <<<"$state" >/dev/null || die "worker-crash restore did not establish repository proof and cold fence"
  for attempt in 1 2 3; do
    # Auxiliary fixture pause makes capture deterministic even for a tiny save.
    # It begins only after preflight, and is removed before the worker is killed.
    if [[ "$minio_paused" == false ]]; then
      recovery_fault_signal_owned "$minio_node" "$minio_id" "$minio_uid" minio "$minio_pid" STOP \
        || die "could not pause the exact owned repository fixture"
      minio_paused=true
    fi
    recovery_record "worker-crash attempt=$attempt auxiliary owned-MinIO pause after verified preflight"
    deadline=$((SECONDS + 180))
    pod=
    while (( SECONDS < deadline )); do
      pod=$(kube get pods --namespace "$namespace" \
        --selector "arcade.gobha.me/restore-uid=$restore_uid,arcade.gobha.me/restore-stage=Populate" --output=json)
      state=$(kube get gamerestore worker-crash --namespace "$namespace" --output=json)
      if jq -e --argjson attempt "$attempt" '.status.phase == "Running" and .status.populateAttempts == $attempt
        and .status.candidateVerification == null and .status.activationStartedAt == null' <<<"$state" >/dev/null \
        && jq -e '.items | length == 1 and .[0].status.phase == "Running"
          and any(.[0].status.containerStatuses[]?; .name == "restore-worker" and .state.running != null)' \
          <<<"$pod" >/dev/null; then
        break
      fi
      sleep 0.2
    done
    jq -e '.items | length == 1 and .[0].status.phase == "Running"' <<<"$pod" >/dev/null \
      || die "populate attempt did not expose one live worker"
    pod_name=$(jq -r '.items[0].metadata.name' <<<"$pod")
    pod_uid=$(jq -r '.items[0].metadata.uid' <<<"$pod")
    node=$(jq -r '.items[0].spec.nodeName' <<<"$pod")
    job_name=$(jq -r '.items[0].metadata.ownerReferences[] | select(.kind == "Job" and .controller == true) | .name' <<<"$pod")
    job_uid=$(jq -r '.items[0].metadata.ownerReferences[] | select(.kind == "Job" and .controller == true) | .uid' <<<"$pod")
    container_id=$(jq -r '.items[0].status.containerStatuses[] | select(.name == "restore-worker") | .containerID' <<<"$pod")
    container_id=${container_id#containerd://}
    [[ -n "$job_uid" && "$pod_uid" != "$previous_pod_uid" && "$job_uid" != "$previous_job_uid" ]] \
      || die "populate retry reused a previous worker identity"
    pid=$(docker exec "$node" crictl inspect "$container_id" | jq -r '.info.pid // empty')
    recovery_fault_signal_owned "$node" "$container_id" "$pod_uid" restore-worker "$pid" STOP \
      || die "could not pause the exact populate worker runtime"
    # Re-read after the stop: executable authority and candidate identities must
    # agree with the current durable attempt, not an earlier sampled Pod.
    pod=$(kube get pod "$pod_name" --namespace "$namespace" --output=json)
    state=$(kube get gamerestore worker-crash --namespace "$namespace" --output=json)
    jq -e --arg uid "$pod_uid" --arg job "$job_uid" '.metadata.uid == $uid
      and (.spec.schedulingGates // [] | length) == 0
      and .metadata.annotations["arcade.gobha.me/restore-pod-authorized"] == $uid
      and any(.metadata.ownerReferences[]; .kind == "Job" and .uid == $job and .controller == true)' \
      <<<"$pod" >/dev/null || die "paused populate Pod lacks exact owner and gate authorization"
    kube get job "$job_name" --namespace "$namespace" --output=json | jq -e --arg uid "$job_uid" --arg restore "$restore_uid" \
      '.metadata.uid == $uid and any(.metadata.ownerReferences[]; .kind == "GameRestore" and .uid == $restore and .controller == true)' \
      >/dev/null || die "paused worker Job does not belong to the exact restore"
    jq -e --arg uid "$job_uid" --argjson attempt "$attempt" '.status.phase == "Running"
      and .status.populateAttempts == $attempt and .status.populateJobUID == $uid
      and .status.candidateVerification == null and .status.activationStartedAt == null' \
      <<<"$state" >/dev/null || die "paused worker differs from durable populate attempt"
    current_candidate=$(jq -c '.status.candidateData' <<<"$state")
    [[ "$current_candidate" != null && "$current_candidate" != '[]' ]] || die "worker lacks exact candidate identities"
    if [[ -z "$candidate_ref" ]]; then candidate_ref=$current_candidate; fi
    [[ "$current_candidate" == "$candidate_ref" ]] || die "populate retry changed retained candidate identities"
    jq -e --argjson paths "$current_candidate" '[.spec.volumes[]? | .persistentVolumeClaim.claimName // empty] | sort
      == ($paths | map(.claimRef.name) | sort)' <<<"$pod" >/dev/null \
      || die "populate worker mounted something other than its exact candidate claims"
    candidate=$(jq -r '.[0].claimRef.name' <<<"$current_candidate")
    candidate_identity=$(kube get pvc "$candidate" --namespace "$namespace" \
      --output=jsonpath='{.metadata.labels.arcade\.gobha\.me/data-identity}')
    leases=$(kube get leases --namespace "$namespace" --selector "arcade.gobha.me/restore-uid=$restore_uid" --output=json)
    jq -e --arg pod "$pod_uid" --arg restore "$restore_uid" --arg identity "$candidate_identity" \
      '.items | any(.spec.holderIdentity == $restore and .metadata.labels["arcade.gobha.me/data-identity"] == $identity
      and .metadata.annotations["arcade.gobha.me/worker-pod-uid"] == $pod)' <<<"$leases" >/dev/null \
      || die "paused populate worker lacks Pod-UID execution lease"
    docker exec "$node" sh -ec 'test "$(awk "/^State:/ {print \$2}" "/proc/$1/status")" = T' sh "$pid" \
      || die "populate runtime was not actually stopped"
    recovery_fault_signal_owned "$minio_node" "$minio_id" "$minio_uid" minio "$minio_pid" CONT \
      || die "could not resume exact repository fixture"
    minio_paused=false
    recovery_fault_signal_owned "$node" "$container_id" "$pod_uid" restore-worker "$pid" KILL \
      || die "could not kill the exact paused populate runtime"
    recovery_record "worker-crash attempt=$attempt pod=$pod_uid job=$job_uid SIGSTOP verified; MinIO resumed; SIGKILL delivered"
    if (( attempt < 3 )); then
      # Hold the next tiny retry while confirming this actual process exit.
      recovery_fault_signal_owned "$minio_node" "$minio_id" "$minio_uid" minio "$minio_pid" STOP \
        || die "could not hold the repository fixture for the next retry"
      minio_paused=true
    fi
    deadline=$((SECONDS + 30))
    while (( SECONDS < deadline )); do
      exit_state=$(docker exec "$node" crictl inspect "$container_id")
      if jq -e '.status.state == "CONTAINER_EXITED" and .status.exitCode == 137' <<<"$exit_state" >/dev/null; then break; fi
      sleep 0.2
    done
    jq -e '.status.state == "CONTAINER_EXITED" and .status.exitCode == 137' <<<"$exit_state" >/dev/null \
      || die "populate SIGKILL did not produce actual exit 137"
    recovery_record "worker-crash attempt=$attempt exact container exited 137"
    previous_pod_uid=$pod_uid
    previous_job_uid=$job_uid
  done
  recovery_wait_settled_failure worker-crash VerificationFailed
  state=$(kube get gamerestore worker-crash --namespace "$namespace" --output=json)
  jq -e '.status.phase == "Failed" and .status.populateAttempts == 3 and .status.candidateVerification == null
    and .status.activationStartedAt == null and (.status.activeData // [] | length) == 0' <<<"$state" >/dev/null \
    || die "three crashed populate attempts did not settle without activation"
  [[ $(jq -c '.status.candidateData' <<<"$state") == "$candidate_ref" ]] || die "terminal failed restore lost retained candidates"
  while IFS='|' read -r candidate uid; do
    [[ "$uid" != "$recovery_original_pvc_uid" ]] || die "crashed candidate aliases the original claim"
    kube get pvc "$candidate" --namespace "$namespace" --output=json | jq -e --arg uid "$uid" \
      '.metadata.uid == $uid and .metadata.deletionTimestamp == null and .status.phase == "Bound"' >/dev/null \
      || die "crashed worker candidate was deleted or replaced"
    backing_handle=$(kube get pvc "$candidate" --namespace "$namespace" --output=jsonpath='{.spec.volumeName}')
    backing_handle=$(kube get pv "$backing_handle" --output=jsonpath='{.spec.csi.volumeHandle}')
    [[ -n "$backing_handle" && "$backing_handle" != "$recovery_original_handle" ]] \
      || die "crashed retained candidate aliases original CSI backing storage"
  done < <(jq -r '.status.candidateData[] | [.claimRef.name,.claimRef.uid] | join("|")' <<<"$state")
  recovery_fault_wait_cleanup "$restore_uid"
  recovery_assert_original
  recovery_record "fault worker-crash uid=$restore_uid all three authorized attempts killed; original A+B preserved; candidates retained; authority absent"
)
