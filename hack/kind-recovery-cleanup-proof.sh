#!/usr/bin/env bash
# Copyright 2026 gobha-me
# SPDX-License-Identifier: Apache-2.0
# Additional proofs for the disposable, ownership-checked recovery harness.
# Capture the sentinel identity immediately after its initial Bound state,
# before any faults. Run the byte proofs after scoped cleanup but before the
# separate whole-owned-Kind teardown. None of these helpers deletes storage.

recovery_proof_assert_sentinel_identity() {
  [[ "${recovery_sentinel_uid:-}" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ &&
     "${recovery_sentinel_config_uid:-}" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ &&
     "${recovery_sentinel_pv:-}" =~ ^[a-z0-9][a-z0-9.-]*$ &&
     "${recovery_sentinel_pv_uid:-}" =~ ^[0-9a-f-]{36}$ &&
     "${recovery_sentinel_handle:-}" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] \
    || die "sentinel backing identity was not captured before faults"
  kube get pvc unrelated-recovery-sentinel --namespace "$namespace" --output=json \
    | jq -e --arg uid "$recovery_sentinel_uid" --arg pv "$recovery_sentinel_pv" '
      .metadata.uid == $uid and .metadata.deletionTimestamp == null and
      .metadata.labels["arcade.gobha.me/foreign-sentinel"] == "untouched" and
      .spec.storageClassName == "arcadectl-sentinel" and .spec.volumeName == $pv and
      .status.phase == "Bound"' >/dev/null \
    || die "sentinel claim identity or binding changed"
  kube get pv "$recovery_sentinel_pv" --output=json \
    | jq -e --arg uid "$recovery_sentinel_pv_uid" --arg handle "$recovery_sentinel_handle" \
      --arg claim "$recovery_sentinel_uid" --arg ns "$namespace" '
      .metadata.uid == $uid and .metadata.deletionTimestamp == null and .status.phase == "Bound" and
      .spec.storageClassName == "arcadectl-sentinel" and .spec.persistentVolumeReclaimPolicy == "Delete" and
      .spec.csi.driver == "hostpath.csi.k8s.io" and .spec.csi.volumeHandle == $handle and
      .spec.claimRef.name == "unrelated-recovery-sentinel" and .spec.claimRef.namespace == $ns and
      .spec.claimRef.uid == $claim' >/dev/null \
    || die "sentinel PV identity or CSI backing changed"
  kube get configmap unrelated-recovery-sentinel --namespace "$namespace" --output=json \
    | jq -e --arg uid "$recovery_sentinel_config_uid" '
      .metadata.uid == $uid and .metadata.deletionTimestamp == null and
      .metadata.labels["arcade.gobha.me/foreign-sentinel"] == "untouched" and .data.sentinel == "preserve"' >/dev/null \
    || die "sentinel ConfigMap identity or content changed"
}

recovery_capture_sentinel_storage_identity() {
  local claim volume
  verify_cluster_ownership || die "sentinel capture requires the owned disposable Kind cluster"
  [[ "${recovery_sentinel_uid:-}" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ &&
     "${recovery_sentinel_config_uid:-}" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] \
    || die "initial sentinel claim or ConfigMap UID was not captured"
  # Do not replace the pre-fault baseline if this helper is accidentally called
  # again after faults: a second invocation must prove the existing baseline.
  if [[ -n "${recovery_sentinel_pv_uid:-}" ]]; then
    recovery_proof_assert_sentinel_identity
    return
  fi
  claim=$(kube get pvc unrelated-recovery-sentinel --namespace "$namespace" --output=json)
  jq -e --arg uid "$recovery_sentinel_uid" '
    .metadata.uid == $uid and .metadata.deletionTimestamp == null and .status.phase == "Bound" and
    .metadata.labels["arcade.gobha.me/foreign-sentinel"] == "untouched" and
    .spec.storageClassName == "arcadectl-sentinel" and
    (.spec.volumeName | type == "string" and test("^[a-z0-9][a-z0-9.-]*$"))' \
    <<<"$claim" >/dev/null || die "initial sentinel claim is not the exact Bound fixture"
  recovery_sentinel_pv=$(jq -r '.spec.volumeName' <<<"$claim")
  volume=$(kube get pv "$recovery_sentinel_pv" --output=json)
  jq -e --arg claim "$recovery_sentinel_uid" --arg ns "$namespace" '
    .metadata.deletionTimestamp == null and .status.phase == "Bound" and
    (.metadata.uid | test("^[0-9a-f-]{36}$")) and
    .spec.storageClassName == "arcadectl-sentinel" and .spec.persistentVolumeReclaimPolicy == "Delete" and
    .spec.csi.driver == "hostpath.csi.k8s.io" and
    (.spec.csi.volumeHandle | test("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")) and
    .spec.claimRef.name == "unrelated-recovery-sentinel" and .spec.claimRef.namespace == $ns and
    .spec.claimRef.uid == $claim' <<<"$volume" >/dev/null \
    || die "initial sentinel PV is not the exact hostpath CSI binding"
  recovery_sentinel_pv_uid=$(jq -r '.metadata.uid' <<<"$volume")
  recovery_sentinel_handle=$(jq -r '.spec.csi.volumeHandle' <<<"$volume")
  readonly recovery_sentinel_uid recovery_sentinel_config_uid
  readonly recovery_sentinel_pv recovery_sentinel_pv_uid recovery_sentinel_handle
  recovery_proof_assert_sentinel_identity
  recovery_record "pre-fault sentinel backing captured claim=$recovery_sentinel_uid pv=$recovery_sentinel_pv_uid handle=$recovery_sentinel_handle"
}

recovery_verify_sentinel_storage() {
  local name=recovery-sentinel-readback uid observed digest expected deadline
  verify_cluster_ownership || die "sentinel readback requires the owned disposable Kind cluster"
  recovery_proof_assert_sentinel_identity
  kube get pods --namespace "$namespace" --output=json | jq -e '
    [.items[] | select(any(.spec.volumes[]?; .persistentVolumeClaim.claimName == "unrelated-recovery-sentinel"))] |
    length == 0' >/dev/null || die "sentinel has an unexpected Pod user before readback"
  # Start inert, then verify exact Pod identity/security and actual attachment
  # before executing any read. Both the claim and mount are read-only.
  jq -cn --arg ns "$namespace" --arg run "$run_id" --arg image "$recovery_io_image" --arg name "$name" '
    {apiVersion:"v1",kind:"Pod",metadata:{name:$name,namespace:$ns,labels:{"arcade.gobha.me/e2e-run":$run}},
      spec:{automountServiceAccountToken:false,restartPolicy:"Never",activeDeadlineSeconds:150,
        securityContext:{runAsNonRoot:true,runAsUser:845,runAsGroup:845,fsGroup:845,seccompProfile:{type:"RuntimeDefault"}},
        containers:[{name:"io",image:$image,command:["sh","-ec","sleep 140"],
          resources:{requests:{cpu:"5m",memory:"8Mi"},limits:{cpu:"100m",memory:"32Mi"}},
          securityContext:{allowPrivilegeEscalation:false,readOnlyRootFilesystem:true,capabilities:{drop:["ALL"]}},
          volumeMounts:[{name:"world",mountPath:"/world",readOnly:true}]}],
        volumes:[{name:"world",persistentVolumeClaim:{claimName:"unrelated-recovery-sentinel",readOnly:true}}]}}' \
    >"$workspace/recovery-sentinel-readback.json"
  kube create --filename "$workspace/recovery-sentinel-readback.json" >/dev/null
  uid=$(kube get pod "$name" --namespace "$namespace" --output=jsonpath='{.metadata.uid}')
  [[ "$uid" =~ ^[0-9a-f-]{36}$ ]] || die "sentinel probe lacks an exact Pod UID"
  kube_bounded 100 wait "pod/$name" --namespace "$namespace" --for=condition=Ready --timeout=90s >/dev/null
  observed=$(kube get pod "$name" --namespace "$namespace" --output=json)
  jq -e --arg uid "$uid" --arg run "$run_id" --arg image "$recovery_io_image" '
    .metadata.uid == $uid and .metadata.deletionTimestamp == null and
    .metadata.labels["arcade.gobha.me/e2e-run"] == $run and .spec.automountServiceAccountToken == false and
    (.spec.hostNetwork // false) == false and (.spec.hostPID // false) == false and
    (.spec.hostIPC // false) == false and
    .spec.securityContext.runAsUser == 845 and .spec.securityContext.runAsGroup == 845 and
    .spec.securityContext.fsGroup == 845 and .spec.securityContext.runAsNonRoot == true and
    .spec.securityContext.seccompProfile.type == "RuntimeDefault" and
    (.spec.containers | length) == 1 and (.spec.initContainers // [] | length) == 0 and
    (.spec.ephemeralContainers // [] | length) == 0 and (.spec.volumes | length) == 1 and
    .spec.containers[0].name == "io" and .spec.containers[0].image == $image and
    .spec.containers[0].command == ["sh","-ec","sleep 140"] and
    (.spec.containers[0].env // [] | length) == 0 and (.spec.containers[0].envFrom // [] | length) == 0 and
    .spec.containers[0].securityContext.allowPrivilegeEscalation == false and
    (.spec.containers[0].securityContext.privileged // false) == false and
    .spec.containers[0].securityContext.readOnlyRootFilesystem == true and
    .spec.containers[0].securityContext.capabilities.drop == ["ALL"] and
    .spec.containers[0].volumeMounts == [{name:"world",mountPath:"/world",readOnly:true}] and
    .spec.volumes[0].name == "world" and
    .spec.volumes[0].persistentVolumeClaim == {claimName:"unrelated-recovery-sentinel",readOnly:true}' \
    <<<"$observed" >/dev/null || die "sentinel readback Pod identity or read-only security shape changed"
  recovery_proof_assert_sentinel_identity
  kube get pods --namespace "$namespace" --output=json | jq -e --arg uid "$uid" '
    [.items[] | select(any(.spec.volumes[]?; .persistentVolumeClaim.claimName == "unrelated-recovery-sentinel"))] |
    length == 1 and .[0].metadata.uid == $uid' >/dev/null || die "sentinel probe is not its sole claim user"
  kube get volumeattachments --output=json | jq -e --arg pv "$recovery_sentinel_pv" --arg node "$(jq -r '.spec.nodeName' <<<"$observed")" '
    [.items[] | select(.spec.source.persistentVolumeName == $pv)] |
    length == 1 and .[0].status.attached == true and .[0].spec.nodeName == $node' >/dev/null \
    || die "sentinel readback lacks its exact attached CSI volume"
  expected=$(printf sentinel | sha256sum | awk '{print $1}')
  digest=$(kube_bounded 15 exec "$name" --namespace "$namespace" --container=io -- sh -ec '
    test "$(id -u)" = 845; test "$(id -g)" = 845
    test -f /world/.recovery-csi-smoke; test ! -L /world/.recovery-csi-smoke
    test "$(readlink -f /world/.recovery-csi-smoke)" = /world/.recovery-csi-smoke
    test "$(wc -c < /world/.recovery-csi-smoke)" = 8
    test "$(cat /world/.recovery-csi-smoke)" = sentinel
    sha256sum /world/.recovery-csi-smoke | cut -d " " -f 1')
  [[ "$digest" == "$expected" ]] || die "sentinel persisted-byte readback hash changed"
  # This exact-UID Pod deletion is the only mutation after probe creation.
  verify_cluster_ownership || die "sentinel probe cleanup lost owned Kind identity"
  [[ $(kube get pod "$name" --namespace "$namespace" --output=jsonpath='{.metadata.uid}') == "$uid" ]] \
    || die "sentinel readback Pod UID changed before deletion"
  jq -cn --arg uid "$uid" '{apiVersion:"v1",kind:"DeleteOptions",preconditions:{uid:$uid},propagationPolicy:"Foreground"}' \
    >"$workspace/recovery-sentinel-delete-options.json"
  kube delete --raw "/api/v1/namespaces/$namespace/pods/$name" \
    --filename "$workspace/recovery-sentinel-delete-options.json" >/dev/null
  wait_absent pod "$name" 90 || die "sentinel readback Pod did not disappear"
  deadline=$((SECONDS + 90))
  while :; do
    observed=$(kube get volumeattachments --output=json) \
      || die "sentinel detach proof could not read VolumeAttachments"
    jq -e '(.items | type) == "array"' <<<"$observed" >/dev/null \
      || die "sentinel detach proof received invalid VolumeAttachment evidence"
    if jq -e --arg pv "$recovery_sentinel_pv" '
      [.items[] | select(.spec.source.persistentVolumeName == $pv)] | length == 0' \
      <<<"$observed" >/dev/null; then break; fi
    (( SECONDS < deadline )) || die "sentinel readback CSI volume did not detach"
    sleep 2
  done
  observed=$(kube get volumeattachments --output=json) \
    || die "final sentinel detach proof could not read VolumeAttachments"
  jq -e --arg pv "$recovery_sentinel_pv" '(.items | type) == "array" and
    ([.items[] | select(.spec.source.persistentVolumeName == $pv)] | length) == 0' \
    <<<"$observed" >/dev/null || die "final sentinel detach proof is not successfully empty"
  recovery_proof_assert_sentinel_identity
  kube get pods --namespace "$namespace" --output=json | jq -e '
    [.items[] | select(any(.spec.volumes[]?; .persistentVolumeClaim.claimName == "unrelated-recovery-sentinel"))] |
    length == 0' >/dev/null || die "sentinel has an unexpected Pod user after readback cleanup"
  recovery_record "foreign sentinel exact PVC/PV/CSI identities preserved; read-only uid845 readback sha256=$digest; probe absent and detached"
}

recovery_assert_retained_fixture_bytes() {
  local record=$1 handle uid claim_uid node node_id path original=false
  verify_cluster_ownership || die "retained-byte proof requires the owned disposable Kind cluster"
  jq -e --arg ns "$namespace" '
    .kind == "PersistentVolume" and (.metadata.uid | test("^[0-9a-f-]{36}$")) and
    (.metadata.name | test("^[a-z0-9][a-z0-9.-]*$")) and
    .spec.claimRef.namespace == $ns and (.spec.claimRef.uid | test("^[0-9a-f-]{36}$")) and
    .spec.storageClassName == "arcadectl-world-retain" and .spec.persistentVolumeReclaimPolicy == "Retain" and
    .spec.csi.driver == "hostpath.csi.k8s.io" and
    (.spec.csi.volumeHandle | test("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"))' \
    <<<"$record" >/dev/null || die "retained-byte proof has invalid captured PV evidence"
  assert_absent "pv/$(jq -r '.metadata.name' <<<"$record")"
  handle=$(jq -r '.spec.csi.volumeHandle' <<<"$record")
  uid=$(jq -r '.metadata.uid' <<<"$record")
  claim_uid=$(jq -r '.spec.claimRef.uid' <<<"$record")
  if [[ "$uid" == "$recovery_original_pv_uid" || "$claim_uid" == "$recovery_original_pvc_uid" ]]; then
    [[ "$uid" == "$recovery_original_pv_uid" && "$claim_uid" == "$recovery_original_pvc_uid" &&
       "$handle" == "$recovery_original_handle" && "$recovery_marker_a_sha256" =~ ^[0-9a-f]{64}$ ]] \
      || die "original retained-byte evidence no longer matches its pre-fault identity"
    original=true
  fi
  [[ $(printf '%s\n' "$node_names" | awk 'NF { count++ } END { print count+0 }') == 1 ]] \
    || die "retained-byte proof requires the single owned Kind node"
  node=$(awk 'NF { print; exit }' <<<"$node_names")
  [[ "$node" =~ ^[a-z0-9][a-z0-9.-]*$ ]] || die "retained-byte proof has invalid Kind node name"
  node_id=$(run_bounded 10 docker inspect --format '{{.Id}}' "$node")
  [[ "$node_id" =~ ^[0-9a-f]{64}$ ]] && grep -Fxq "$node_id" <<<"$node_ids" \
    || die "retained-byte proof Kind node container identity changed"
  [[ $(run_bounded 10 docker inspect --format '{{index .Config.Labels "io.x-k8s.kind.cluster"}}' "$node_id") == "$cluster_name" ]] \
    || die "retained-byte proof node is not in the owned Kind cluster"
  path="/var/lib/csi-hostpath-data/$handle"
  # Only a validated UUID child of this exact test-owned CSI root is read.
  # No deletion is performed: Retain means API cleanup must leave bytes here.
  run_bounded 15 docker exec "$node_id" sh -ec '
    root=/var/lib/csi-hostpath-data; path=$1; original=$2; expected=$3
    test -d "$root"; test ! -L "$root"; test "$(readlink -f "$root")" = "$root"
    test -d "$path"; test ! -L "$path"; test "$(readlink -f "$path")" = "$path"
    if [ "$original" = true ]; then
      for marker in .arcadectl-marker-a .arcadectl-marker-b; do
        test -f "$path/$marker"; test ! -L "$path/$marker"
        test "$(readlink -f "$path/$marker")" = "$path/$marker"
      done
      test "$(wc -c < "$path/.arcadectl-marker-a")" = 8388608
      test "$(sha256sum "$path/.arcadectl-marker-a" | cut -d " " -f 1)" = "$expected"
      test "$(wc -c < "$path/.arcadectl-marker-b")" = 8
      test "$(cat "$path/.arcadectl-marker-b")" = marker-b
    fi' recovery "$path" "$original" "$recovery_marker_a_sha256" \
    || die "retained CSI directory or original A+B bytes did not survive PV API deletion"
  if [[ "$original" == true ]]; then
    recovery_record "original retained CSI directory remains after PV API deletion; marker A exact8Mi sha256=$recovery_marker_a_sha256 and marker B exactcontent proved"
  else
    recovery_record "retained candidate CSI directory remains after PV API deletion pv=$uid handle=$handle; no erasure or candidate-byte-content claim"
  fi
}

recovery_assert_scoped_cr_terminal() {
  local record=$1 expected
  case "$(jq -r '.kind' <<<"$record")" in
    GameBackup) expected=arcade.gobha.me/backup-protection ;;
    GameRestore) expected=arcade.gobha.me/restore-protection ;;
    GameDestroy) expected=arcade.gobha.me/destroy-protection ;;
    *) die "scoped cleanup terminal proof received an unsupported operation kind" ;;
  esac
  # Other legitimate finalizers are allowed; exactly one of this operation's
  # protection finalizers must be present before normal deletion begins.
  jq -e --arg expected "$expected" '
    .metadata.deletionTimestamp == null and (.metadata.generation | type) == "number" and
    .status.observedGeneration == .metadata.generation and
    (.status.completedAt | type) == "string" and (.status.completedAt | length) > 0 and
    (.status.phase == "Succeeded" or .status.phase == "Failed" or .status.phase == "Cancelled") and
    ([.metadata.finalizers[]? | select(. == $expected)] | length) == 1 and
    ([.status.conditions[]? | select(.type == "Complete")] | length) == 1' \
    <<<"$record" >/dev/null || die "scoped cleanup operation lacks its exact current terminal/finalizer evidence"
  # Bind the Complete condition to the parent generation explicitly, rather
  # than resolving .metadata against the condition object inside any().
  jq -e '. as $operation |
    [.status.conditions[] | select(.type == "Complete")][0] |
    .observedGeneration == $operation.metadata.generation and
    .status == (if $operation.status.phase == "Succeeded" then "True" else "False" end)' \
    <<<"$record" >/dev/null || die "scoped cleanup operation Complete condition disagrees with its current terminal phase"
}
