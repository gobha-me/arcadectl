#!/usr/bin/env bash
# Copyright 2026 gobha-me
# SPDX-License-Identifier: Apache-2.0
# Sourced only by the ownership-checked, disposable Kind recovery harness.

recovery_fault_filesystem_full() {
  say "injecting bounded filesystem exhaustion below one fresh restore candidate"
  local restore_name=filesystem-full
  local policy_name="arcadectl-test-hold-$run_suffix"
  local binding_name="$policy_name"
  local controller_replicas restore_uid policy_uid binding_uid policy_status deadline
  local candidates candidate candidate_uid candidate_pv candidate_pv_uid candidate_handle
  local pods pod pod_uid jobs job_uid attempts result
  local node node_count node_id plugin_pods plugin_pod plugin_pod_uid plugin_container_id
  local candidate_directory mount_source node_mount plugin_mountinfo plugin_mount
  local statfs block_size blocks free_blocks available_blocks available_bytes used_bytes
  local full_seen=false worker_mount_seen=false worker_id worker_pid worker_statfs worker_uid
  local job_uids_file="$workspace/recovery-filesystem-full-jobs.tsv"
  local mount_evidence_file="$workspace/recovery-filesystem-full-evidence.txt"

  controller_replicas=$(kube get deployment arcadectl-controller --namespace "$namespace" \
    --output=jsonpath='{.spec.replicas}')
  [[ "$controller_replicas" == 1 ]] || die "filesystem-full fault requires exactly one controller replica"
  kube scale deployment/arcadectl-controller --namespace "$namespace" --replicas=0 >/dev/null
  kube_bounded 70 wait pod --namespace "$namespace" --selector=app.kubernetes.io/name=arcadectl-controller \
    --for=delete --timeout=60s >/dev/null

  # The operation exists before its exact admission hold, but no controller is
  # running and therefore no worker or candidate can yet exist.
  recovery_create_restore "$restore_name" original-backup "$repository_secret_name"
  restore_uid=$(kube get gamerestore "$restore_name" --namespace "$namespace" --output=jsonpath='{.metadata.uid}')
  [[ "$restore_uid" =~ ^[0-9a-f-]{36}$ ]] || die "filesystem-full restore lacks an exact UID"
  kube get jobs,pods,persistentvolumeclaims --namespace "$namespace" \
    --selector "arcade.gobha.me/restore-uid=$restore_uid" --output=json \
    | jq -e '.items | length == 0' >/dev/null \
    || die "filesystem-full restore was processed while its controller was stopped"

  jq -cn --arg name "$policy_name" --arg run "$run_id" --arg ns "$namespace" --arg uid "$restore_uid" '
    {apiVersion:"admissionregistration.k8s.io/v1",kind:"ValidatingAdmissionPolicy",
      metadata:{name:$name,labels:{"arcade.gobha.me/e2e-run":$run}},
      spec:{failurePolicy:"Fail",matchConstraints:{matchPolicy:"Equivalent",resourceRules:[{
        apiGroups:[""],apiVersions:["v1"],operations:["UPDATE"],resources:["pods"],scope:"Namespaced"}]},
        matchConditions:[{name:"exact-populate-worker",expression:(
          "oldObject != null && request.namespace == \"" + $ns +
          "\" && has(oldObject.metadata.labels) && \"arcade.gobha.me/restore-uid\" in oldObject.metadata.labels" +
          " && oldObject.metadata.labels[\"arcade.gobha.me/restore-uid\"] == \"" + $uid +
          "\" && \"arcade.gobha.me/restore-stage\" in oldObject.metadata.labels" +
          " && oldObject.metadata.labels[\"arcade.gobha.me/restore-stage\"] == \"Populate\"")}],
        validations:[{expression:(
          "!(has(oldObject.spec.schedulingGates) && " +
          "oldObject.spec.schedulingGates.exists(g, g.name == \"arcade.gobha.me/restore-authorized\") && " +
          "(!has(object.spec.schedulingGates) || " +
          "!object.spec.schedulingGates.exists(g, g.name == \"arcade.gobha.me/restore-authorized\")))"),
          message:"The disposable filesystem-full fixture is still preparing the exact candidate."}]}}' \
    >"$workspace/recovery-filesystem-full-policy.json"
  jq -cn --arg name "$binding_name" --arg run "$run_id" --arg policy "$policy_name" '
    {apiVersion:"admissionregistration.k8s.io/v1",kind:"ValidatingAdmissionPolicyBinding",
      metadata:{name:$name,labels:{"arcade.gobha.me/e2e-run":$run}},
      spec:{policyName:$policy,validationActions:["Deny"]}}' \
    >"$workspace/recovery-filesystem-full-binding.json"
  kube create --filename "$workspace/recovery-filesystem-full-policy.json" >/dev/null
  policy_uid=$(kube get validatingadmissionpolicy "$policy_name" --output=jsonpath='{.metadata.uid}')
  deadline=$((SECONDS + 60))
  while (( SECONDS < deadline )); do
    policy_status=$(kube get validatingadmissionpolicy "$policy_name" --output=json)
    if jq -e '.status.observedGeneration == .metadata.generation and .status.typeChecking != null' \
      <<<"$policy_status" >/dev/null; then
      jq -e '(.status.typeChecking.expressionWarnings // []) | length == 0' <<<"$policy_status" >/dev/null \
        || die "filesystem-full admission hold has CEL typechecking warnings"
      break
    fi
    sleep 1
  done
  jq -e '.status.observedGeneration == .metadata.generation and
    ((.status.typeChecking.expressionWarnings // []) | length == 0)' <<<"$policy_status" >/dev/null \
    || die "filesystem-full admission hold was not accepted"
  kube create --filename "$workspace/recovery-filesystem-full-binding.json" >/dev/null
  binding_uid=$(kube get validatingadmissionpolicybinding "$binding_name" --output=jsonpath='{.metadata.uid}')
  [[ -n "$policy_uid" && -n "$binding_uid" ]] || die "filesystem-full admission hold lacks exact identities"
  recovery_record "filesystem-full hold restore=$restore_uid policy=$policy_uid binding=$binding_uid installed before reconciliation"

  kube scale deployment/arcadectl-controller --namespace "$namespace" --replicas=1 >/dev/null
  kube_bounded 190 rollout status deployment/arcadectl-controller --namespace "$namespace" --timeout=180s >/dev/null

  # Preflight remains free to run. The additional policy holds only the exact
  # populate Pod after its Job has been validated and unsuspended.
  deadline=$((SECONDS + 420))
  candidates='{"items":[]}'
  pods='{"items":[]}'
  while (( SECONDS < deadline )); do
    result=$(kube get gamerestore "$restore_name" --namespace "$namespace" --output=json)
    jq -e '.status.phase != "Failed" and .status.phase != "Cancelled" and .status.activationStartedAt == null' \
      <<<"$result" >/dev/null || die "filesystem-full restore settled before its exact candidate was held"
    candidates=$(kube get pvc --namespace "$namespace" \
      --selector "arcade.gobha.me/restore-uid=$restore_uid" --output=json)
    pods=$(kube get pods --namespace "$namespace" \
      --selector "arcade.gobha.me/restore-uid=$restore_uid,arcade.gobha.me/restore-stage=Populate" --output=json)
    if jq -e '(.items | length) == 1 and .items[0].status.phase == "Bound"' <<<"$candidates" >/dev/null &&
      jq -e '.items | length == 1' <<<"$pods" >/dev/null; then
      break
    fi
    sleep 2
  done
  jq -e '(.items | length) == 1 and .items[0].status.phase == "Bound"' <<<"$candidates" >/dev/null \
    || die "filesystem-full fault did not obtain one bound candidate"
  jq -e '.items | length == 1' <<<"$pods" >/dev/null \
    || die "filesystem-full fault did not hold one exact populate Pod"
  candidate=$(jq -r '.items[0].metadata.name' <<<"$candidates")
  candidate_uid=$(jq -r '.items[0].metadata.uid' <<<"$candidates")
  candidate_pv=$(jq -r '.items[0].spec.volumeName' <<<"$candidates")
  candidate_pv_uid=$(kube get pv "$candidate_pv" --output=jsonpath='{.metadata.uid}')
  candidate_handle=$(kube get pv "$candidate_pv" --output=jsonpath='{.spec.csi.volumeHandle}')
  [[ -n "$candidate" && -n "$candidate_uid" && -n "$candidate_pv" && -n "$candidate_pv_uid" ]] \
    || die "filesystem-full candidate identity is incomplete"
  [[ "$candidate_uid" != "$recovery_original_pvc_uid" && "$candidate_pv_uid" != "$recovery_original_pv_uid" ]] \
    || die "filesystem-full candidate aliases original storage"
  [[ "$candidate_handle" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] \
    || die "filesystem-full candidate CSI handle is not an exact UUID"
  [[ "$candidate_handle" != "$recovery_original_handle" ]] || die "filesystem-full candidate aliases the original CSI handle"
  kube get pv "$candidate_pv" --output=json | jq -e --arg uid "$candidate_uid" --arg pvuid "$candidate_pv_uid" \
    --arg handle "$candidate_handle" '
      .metadata.uid == $pvuid and .spec.claimRef.uid == $uid and
      .spec.csi.driver == "hostpath.csi.k8s.io" and .spec.csi.volumeHandle == $handle' >/dev/null \
    || die "filesystem-full candidate PV does not bind the exact CSI identity"

  pod=$(jq -c '.items[0]' <<<"$pods")
  pod_uid=$(jq -r '.metadata.uid' <<<"$pod")
  jq -e --arg uid "$restore_uid" --arg candidate "$candidate" '
    .metadata.labels["arcade.gobha.me/restore-uid"] == $uid and
    .metadata.labels["arcade.gobha.me/restore-stage"] == "Populate" and
    (.metadata.annotations["arcade.gobha.me/restore-pod-authorized"] // "") == "" and
    .status.phase == "Pending" and (.spec.nodeName // "") == "" and
    (.status.initContainerStatuses // [] | length) == 0 and
    (.status.containerStatuses // [] | length) == 0 and
    (.spec.schedulingGates | length) == 1 and
    .spec.schedulingGates[0].name == "arcade.gobha.me/restore-authorized" and
    ([.spec.volumes[]? | select(.persistentVolumeClaim.claimName == $candidate)] | length) == 1' \
    <<<"$pod" >/dev/null || die "filesystem-full populate Pod crossed its scheduling gate"
  kube get pods --namespace "$namespace" --output=json | jq -e --arg claim "$candidate" --arg uid "$pod_uid" '
    [.items[] | select(any(.spec.volumes[]?; .persistentVolumeClaim.claimName == $claim))] as $users |
    ($users | length) == 1 and $users[0].metadata.uid == $uid and ($users[0].spec.nodeName // "") == ""' >/dev/null \
    || die "filesystem-full candidate has a scheduled or unexpected Pod user"
  kube get volumeattachments --output=json | jq -e --arg pv "$candidate_pv" '
    [.items[] | select(.spec.source.persistentVolumeName == $pv)] | length == 0' >/dev/null \
    || die "filesystem-full candidate was attached before the bounded mount was installed"

  node_count=$(awk 'NF { count++ } END { print count + 0 }' <<<"$node_names")
  [[ "$node_count" -eq 1 ]] || die "filesystem-full fault is certified only for one owned Kind node"
  node=$(awk 'NF { print; exit }' <<<"$node_names")
  verify_cluster_ownership || die "filesystem-full fault lost base Kind ownership"
  [[ $(docker inspect --format '{{index .Config.Labels "io.x-k8s.kind.cluster"}}' "$node") == "$cluster_name" ]] \
    || die "filesystem-full target node is not owned by this Kind run"
  node_id=$(docker inspect --format '{{.Id}}' "$node")
  grep -Fxq "$node_id" <<<"$node_ids" || die "filesystem-full target node identity changed"
  plugin_pods=$(kube get pods --namespace "$recovery_csi_namespace" \
    --selector "app.kubernetes.io/name=arcadectl-csi-hostpath,arcade.gobha.me/test-run=$run_id" --output=json)
  jq -e --arg node "$node" '
    (.items | length) == 1 and .items[0].spec.nodeName == $node and .items[0].status.phase == "Running" and
    any(.items[0].spec.containers[]; .name == "hostpath") and
    any(.items[0].status.containerStatuses[]?; .name == "hostpath" and .ready == true and
      .state.running != null and (.containerID | startswith("containerd://")))' <<<"$plugin_pods" >/dev/null \
    || die "filesystem-full fault cannot identify the exact running CSI plugin"
  plugin_pod=$(jq -r '.items[0].metadata.name' <<<"$plugin_pods")
  plugin_pod_uid=$(jq -r '.items[0].metadata.uid' <<<"$plugin_pods")
  plugin_container_id=$(jq -r '.items[0].status.containerStatuses[] | select(.name == "hostpath") | .containerID' \
    <<<"$plugin_pods")

  candidate_directory="/var/lib/csi-hostpath-data/$candidate_handle"
  mount_source="arcadectl-enospc-$run_suffix"
  run_bounded 10 docker exec "$node" sh -ceu '
    path=$1
    test -d "$path"
    test ! -L "$path"
    test -z "$(find "$path" -mindepth 1 -maxdepth 1 -print -quit)"
    ! mountpoint -q "$path"
  ' sh "$candidate_directory" || die "filesystem-full candidate directory is not a fresh unmounted CSI child"
  run_bounded 10 docker exec "$node" mount -t tmpfs \
    -o size=2m,nr_inodes=1024,mode=0770,uid=845,gid=845 "$mount_source" "$candidate_directory"

  node_mount=$(run_bounded 10 docker exec "$node" findmnt -rn -M "$candidate_directory" -o TARGET,SOURCE,FSTYPE,OPTIONS)
  awk -v target="$candidate_directory" -v source="$mount_source" '
    $1 == target && $2 == source && $3 == "tmpfs" && $4 ~ /(^|,)rw(,|$)/ { found=1 }
    END { exit !found }' <<<"$node_mount" \
    || die "filesystem-full node mount does not match the exact bounded tmpfs"
  kube get pod "$plugin_pod" --namespace "$recovery_csi_namespace" --output=json | jq -e \
    --arg uid "$plugin_pod_uid" --arg node "$node" --arg container "$plugin_container_id" '
      .metadata.uid == $uid and .spec.nodeName == $node and .status.phase == "Running" and
      any(.status.containerStatuses[]?; .name == "hostpath" and .containerID == $container and
        .ready == true and .state.running != null)' >/dev/null \
    || die "filesystem-full CSI plugin identity or runtime changed before propagation proof"
  deadline=$((SECONDS + 30))
  plugin_mount=''
  while (( SECONDS < deadline )); do
    plugin_mountinfo=$(kube exec "$plugin_pod" --namespace "$recovery_csi_namespace" --container=hostpath -- \
      cat /proc/self/mountinfo)
    plugin_mount=$(awk -v target="/csi-data-dir/$candidate_handle" -v source="$mount_source" '
      $5 == target {
        for (i=7; i<=NF; i++) if ($i == "-" && $(i+1) == "tmpfs" && $(i+2) == source) found=1
      }
      found { print; exit }
      END { exit !found }' <<<"$plugin_mountinfo") || true
    [[ -n "$plugin_mount" ]] && break
    sleep 1
  done
  [[ -n "$plugin_mount" ]] || die "filesystem-full tmpfs did not propagate into the CSI plugin namespace"
  kube get pod "$plugin_pod" --namespace "$recovery_csi_namespace" --output=json | jq -e \
    --arg uid "$plugin_pod_uid" --arg node "$node" --arg container "$plugin_container_id" '
      .metadata.uid == $uid and .spec.nodeName == $node and .status.phase == "Running" and
      any(.status.containerStatuses[]?; .name == "hostpath" and .containerID == $container and
        .ready == true and .state.running != null)' >/dev/null \
    || die "filesystem-full CSI plugin changed during propagation proof"
  {
    printf 'restore_uid=%s\ncandidate_pvc=%s\ncandidate_pvc_uid=%s\n' "$restore_uid" "$candidate" "$candidate_uid"
    printf 'candidate_pv=%s\ncandidate_pv_uid=%s\ncandidate_handle=%s\n' "$candidate_pv" "$candidate_pv_uid" "$candidate_handle"
    printf 'node=%s\nnode_id=%s\nplugin_pod_uid=%s\n' "$node" "$node_id" "$plugin_pod_uid"
    printf 'node_mount=%s\nplugin_mount=%s\n' "$node_mount" "$plugin_mount"
  } >"$mount_evidence_file"
  recovery_record "filesystem-full candidate=$candidate_uid pv=$candidate_pv_uid handle=$candidate_handle exact 2Mi tmpfs visible in node and plugin"

  # Removing only these exact, run-labelled objects releases normal controller
  # authorization. The base restore-worker policy remains in force.
  kube get validatingadmissionpolicybinding "$binding_name" --output=json | jq -e \
    --arg uid "$binding_uid" --arg run "$run_id" --arg policy "$policy_name" '
      .metadata.uid == $uid and .metadata.labels["arcade.gobha.me/e2e-run"] == $run and
      .spec.policyName == $policy' >/dev/null || die "filesystem-full admission binding identity changed"
  kube_bounded 40 delete validatingadmissionpolicybinding "$binding_name" --wait=true --timeout=30s >/dev/null
  kube get validatingadmissionpolicy "$policy_name" --output=json | jq -e \
    --arg uid "$policy_uid" --arg run "$run_id" '
      .metadata.uid == $uid and .metadata.labels["arcade.gobha.me/e2e-run"] == $run' >/dev/null \
    || die "filesystem-full admission policy identity changed"
  kube_bounded 40 delete validatingadmissionpolicy "$policy_name" --wait=true --timeout=30s >/dev/null
  recovery_record "filesystem-full exact populate gate released after dual-namespace mount proof"

  printf 'attempt\tjob_uid\n' >"$job_uids_file"
  deadline=$((SECONDS + 720))
  while (( SECONDS < deadline )); do
    result=$(kube get gamerestore "$restore_name" --namespace "$namespace" --output=json)
    attempts=$(jq -r '.status.populateAttempts // 0' <<<"$result")
    job_uid=$(jq -r '.status.populateJobUID // ""' <<<"$result")
    if [[ "$attempts" =~ ^[1-3]$ && "$job_uid" =~ ^[0-9a-f-]{36}$ ]]; then
      if awk -v attempt="$attempts" '$1 == attempt { found=1 } END { exit !found }' "$job_uids_file"; then
        awk -v attempt="$attempts" -v uid="$job_uid" '$1 == attempt && $2 == uid { found=1 } END { exit !found }' \
          "$job_uids_file" || die "filesystem-full attempt changed its journaled Job UID"
      else
        printf '%s\t%s\n' "$attempts" "$job_uid" >>"$job_uids_file"
      fi
    fi
    jobs=$(kube get jobs --namespace "$namespace" \
      --selector "arcade.gobha.me/restore-uid=$restore_uid,arcade.gobha.me/restore-stage=Populate" --output=json)
    pods=$(kube get pods --namespace "$namespace" \
      --selector "arcade.gobha.me/restore-uid=$restore_uid,arcade.gobha.me/restore-stage=Populate" --output=json)
    jq -e '(.items | length) <= 1' <<<"$jobs" >/dev/null \
      || die "filesystem-full restore overlapped populate Jobs"
    jq -e '(.items | length) <= 1' <<<"$pods" >/dev/null \
      || die "filesystem-full restore overlapped populate Pods"
    if [[ "$worker_mount_seen" == false ]] && jq -e '.items | length == 1 and .[0].status.phase == "Running"
      and any(.[0].status.containerStatuses[]?; .name == "restore-worker" and .state.running != null)' \
      <<<"$pods" >/dev/null; then
      worker_uid=$(jq -r '.items[0].metadata.uid' <<<"$pods")
      worker_id=$(jq -r '.items[0].status.containerStatuses[] | select(.name == "restore-worker") | .containerID' <<<"$pods")
      worker_id=${worker_id#containerd://}
      worker_pid=$(run_bounded 10 docker exec "$node" crictl inspect "$worker_id" \
        | jq -r --arg uid "$worker_uid" --arg id "$worker_id" \
          'select(.status.id == $id and .status.state == "CONTAINER_RUNNING" and .status.labels["io.kubernetes.pod.uid"] == $uid) | .info.pid // empty') || worker_pid=
      if [[ "$worker_id" =~ ^[0-9a-f]{64}$ && "$worker_pid" =~ ^[1-9][0-9]*$ ]]; then
        # Read the actual worker's mount namespace without requiring tools in
        # its scratch image. A racing process exit is retried on the next Pod.
        worker_statfs=$(run_bounded 10 docker exec "$node" sh -ec \
          'grep -F "$2" "/proc/$1/cgroup" >/dev/null; stat -f -c "%S %b" "/proc/$1/root/arcadectl/candidate/world"' \
          sh "$worker_pid" "$worker_id" 2>/dev/null) || worker_statfs=
        if [[ -n "$worker_statfs" ]]; then
          read -r block_size blocks <<<"$worker_statfs"
          (( block_size * blocks == 2097152 )) || die "actual populate worker did not mount the bounded 2Mi candidate filesystem"
          worker_mount_seen=true
          printf 'actual_worker_pod_uid=%s container_id=%s candidate_filesystem_bytes=2097152\n' \
            "$worker_uid" "$worker_id" >>"$mount_evidence_file"
        fi
      fi
    fi
    if jq -e '.items | length == 1' <<<"$jobs" >/dev/null && [[ -n "$job_uid" ]]; then
      jq -e --arg uid "$job_uid" '.items[0].metadata.uid == $uid' <<<"$jobs" >/dev/null \
        || die "filesystem-full running Job differs from the durable attempt journal"
    fi
    candidates=$(kube get pvc --namespace "$namespace" \
      --selector "arcade.gobha.me/restore-uid=$restore_uid" --output=json)
    jq -e --arg name "$candidate" --arg uid "$candidate_uid" --arg pv "$candidate_pv" '
      (.items | length) == 1 and .items[0].metadata.name == $name and
      .items[0].metadata.uid == $uid and .items[0].spec.volumeName == $pv' <<<"$candidates" >/dev/null \
      || die "filesystem-full retry replaced its retained candidate"
    [[ $(kube get pv "$candidate_pv" --output=jsonpath='{.metadata.uid}|{.spec.csi.volumeHandle}') == \
      "$candidate_pv_uid|$candidate_handle" ]] || die "filesystem-full retry changed candidate CSI backing"

    statfs=$(run_bounded 10 docker exec "$node" stat -f -c '%S %b %f %a' "$candidate_directory")
    read -r block_size blocks free_blocks available_blocks <<<"$statfs"
    [[ "$block_size" =~ ^[0-9]+$ && "$blocks" =~ ^[0-9]+$ && "$free_blocks" =~ ^[0-9]+$ &&
      "$available_blocks" =~ ^[0-9]+$ ]] || die "filesystem-full statfs evidence is malformed"
    available_bytes=$((block_size * available_blocks))
    used_bytes=$((block_size * (blocks - free_blocks)))
    if (( available_bytes == 0 && used_bytes > 0 )); then
      full_seen=true
    fi
    if jq -e '.status.phase == "Failed"' <<<"$result" >/dev/null; then
      break
    fi
    jq -e '.status.candidateVerification == null and .status.activationStartedAt == null and
      (.status.activeData // [] | length) == 0' <<<"$result" >/dev/null \
      || die "filesystem-full restore crossed candidate activation before terminal failure"
    recovery_publish_player_endpoint_if_present
    sleep 1
  done
  jq -e --arg original "$recovery_original_pvc_uid" '.status.phase == "Failed" and .status.populateAttempts == 3 and
    .status.candidateVerification == null and .status.activationStartedAt == null and
    (.status.activeData // [] | length) == 0 and (.status.previousData | length) == 1 and
    .status.previousData[0].claimRef.uid == $original' <<<"$result" >/dev/null \
    || die "filesystem-full restore did not fail before activation after exactly three attempts"
  [[ "$full_seen" == true ]] || die "filesystem-full workers failed without observed zero-available-block statfs evidence"
  [[ "$worker_mount_seen" == true ]] || die "filesystem-full proof did not observe the 2Mi filesystem in an actual populate worker"
  [[ $(awk 'NR > 1 { count++; seen[$2]=1 } END { for (uid in seen) unique++; print count + 0 ":" unique + 0 }' \
    "$job_uids_file") == 3:3 ]] \
    || die "filesystem-full fault did not observe three distinct serialized Job identities"
  {
    printf 'terminal_statfs_block_size=%s blocks=%s free_blocks=%s available_blocks=%s used_bytes=%s\n' \
      "$block_size" "$blocks" "$free_blocks" "$available_blocks" "$used_bytes"
    run_bounded 10 docker exec "$node" df -B1 "$candidate_directory"
    run_bounded 10 docker exec "$node" find "$candidate_directory" -xdev -type f -printf '%s %p\n'
  } >>"$mount_evidence_file"

  recovery_wait_settled_failure "$restore_name" VerificationFailed
  recovery_fault_wait_cleanup "$restore_uid"
  deadline=$((SECONDS + 120))
  while (( SECONDS < deadline )); do
    if kube get volumeattachments --output=json | jq -e --arg pv "$candidate_pv" '
      [.items[] | select(.spec.source.persistentVolumeName == $pv)] | length == 0' >/dev/null; then
      break
    fi
    sleep 2
  done
  kube get volumeattachments --output=json | jq -e --arg pv "$candidate_pv" '
    [.items[] | select(.spec.source.persistentVolumeName == $pv)] | length == 0' >/dev/null \
    || die "filesystem-full candidate remained attached after worker cleanup"
  kube get pods --all-namespaces --output=json | jq -e --arg ns "$namespace" --arg claim "$candidate" '
    [.items[] | select(.metadata.namespace == $ns) |
      select(any(.spec.volumes[]?; .persistentVolumeClaim.claimName == $claim))] | length == 0' >/dev/null \
    || die "filesystem-full candidate retained a Pod user after worker cleanup"

  verify_cluster_ownership || die "filesystem-full fault lost Kind ownership before unmount"
  [[ $(docker inspect --format '{{.Id}}' "$node") == "$node_id" ]] \
    || die "filesystem-full Kind node changed before unmount"
  node_mount=$(run_bounded 10 docker exec "$node" findmnt -rn -M "$candidate_directory" -o TARGET,SOURCE,FSTYPE,OPTIONS)
  awk -v target="$candidate_directory" -v source="$mount_source" '
    $1 == target && $2 == source && $3 == "tmpfs" { found=1 }
    END { exit !found }' <<<"$node_mount" \
    || die "filesystem-full exact tmpfs identity was lost before unmount"
  kube get pod "$plugin_pod" --namespace "$recovery_csi_namespace" --output=json | jq -e \
    --arg uid "$plugin_pod_uid" --arg node "$node" --arg container "$plugin_container_id" '
      .metadata.uid == $uid and .spec.nodeName == $node and .status.phase == "Running" and
      any(.status.containerStatuses[]?; .name == "hostpath" and .containerID == $container and
        .ready == true and .state.running != null)' >/dev/null \
    || die "filesystem-full CSI plugin identity or runtime changed before unmount propagation proof"
  plugin_mountinfo=$(kube exec "$plugin_pod" --namespace "$recovery_csi_namespace" --container=hostpath -- \
    cat /proc/self/mountinfo)
  awk -v target="/csi-data-dir/$candidate_handle" -v source="$mount_source" '
    $5 == target {
      for (i=7; i<=NF; i++) if ($i == "-" && $(i+1) == "tmpfs" && $(i+2) == source) found=1
    }
    END { exit !found }' <<<"$plugin_mountinfo" \
    || die "filesystem-full plugin mount identity was lost before unmount"
  run_bounded 10 docker exec "$node" umount "$candidate_directory"
  if run_bounded 10 docker exec "$node" mountpoint -q "$candidate_directory"; then
    die "filesystem-full exact tmpfs remained mounted after ordinary unmount"
  fi
  deadline=$((SECONDS + 30))
  while (( SECONDS < deadline )); do
    plugin_mountinfo=$(kube exec "$plugin_pod" --namespace "$recovery_csi_namespace" --container=hostpath -- \
      cat /proc/self/mountinfo)
    if ! awk -v target="/csi-data-dir/$candidate_handle" '$5 == target { found=1 } END { exit !found }' \
      <<<"$plugin_mountinfo"; then
      break
    fi
    sleep 1
  done
  ! awk -v target="/csi-data-dir/$candidate_handle" '$5 == target { found=1 } END { exit !found }' \
    <<<"$plugin_mountinfo" || die "filesystem-full tmpfs remained visible in the plugin after unmount"

  recovery_assert_original
  recovery_record "fault filesystem-full uid=$restore_uid attempts=3 candidate=$candidate_uid handle=$candidate_handle actual 2Mi filesystem exhausted; original A+B preserved; ordinary exact unmount passed"
}
