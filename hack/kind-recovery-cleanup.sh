#!/usr/bin/env bash
# Copyright 2026 gobha-me
# SPDX-License-Identifier: Apache-2.0
# Sourced only by the ownership-checked, disposable Kind recovery harness.

recovery_cleanup_ledger() {
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$(date +%s)" "$1" "$2" "$3" "$4" "$5" \
    >>"$workspace/recovery-cleanup.tsv"
}

recovery_cleanup_assert_sentinel() {
  kube get pvc unrelated-recovery-sentinel --namespace "$namespace" --output=json \
    | jq -e --arg uid "$recovery_sentinel_uid" '
      .metadata.uid == $uid and .metadata.deletionTimestamp == null and
      .metadata.labels["arcade.gobha.me/foreign-sentinel"] == "untouched" and
      .spec.storageClassName == "arcadectl-sentinel" and .status.phase == "Bound"' >/dev/null \
    || die "scoped fixture cleanup changed the unrelated sentinel claim"
  kube get configmap unrelated-recovery-sentinel --namespace "$namespace" --output=json \
    | jq -e --arg uid "$recovery_sentinel_config_uid" '
      .metadata.uid == $uid and .metadata.deletionTimestamp == null and
      .metadata.labels["arcade.gobha.me/foreign-sentinel"] == "untouched" and .data.sentinel == "preserve"' >/dev/null \
    || die "scoped fixture cleanup changed the unrelated sentinel ConfigMap"
}

# All callers establish task ownership before this exact-UID mutation. Ordinary
# finalizers remain enabled; neither force deletion nor finalizer patches exist.
recovery_cleanup_delete_exact() {
  local resource=$1 name=$2 uid=$3 identity=${4:-} path current
  [[ "$name" =~ ^[a-z0-9][a-z0-9.-]*$ && "$uid" =~ ^[0-9a-f-]{36}$ ]] \
    || die "scoped fixture deletion has an invalid identity"
  verify_cluster_ownership || die "scoped fixture deletion lost Kind ownership"
  current=$(kube get "$resource" "$name" --namespace "$namespace" --output=json) \
    || die "scoped fixture deletion could not read its exact object"
  [[ $(jq -r '.metadata.uid' <<<"$current") == "$uid" ]] \
    || die "scoped fixture deletion object identity changed"
  case "$resource" in
    gamebackups|gamerestores|gamedestroys)
      recovery_assert_scoped_cr_terminal "$current"
      path="/apis/arcade.gobha.me/v1alpha1/namespaces/$namespace/$resource/$name" ;;
    persistentvolumes)
      path="/api/v1/persistentvolumes/$name" ;;
    persistentvolumeclaims|services|secrets)
      path="/api/v1/namespaces/$namespace/$resource/$name" ;;
    deployments)
      path="/apis/apps/v1/namespaces/$namespace/deployments/$name" ;;
    *) die "scoped fixture deletion resource is outside its inventory" ;;
  esac
  jq -cn --arg uid "$uid" '{apiVersion:"v1",kind:"DeleteOptions",preconditions:{uid:$uid},propagationPolicy:"Foreground"}' \
    >"$workspace/recovery-cleanup-delete-options.json"
  recovery_cleanup_ledger delete-request "$resource" "$name" "$uid" "uid-precondition; ordinary-finalizers"
  if [[ -n "$identity" ]]; then
    [[ "$resource" == persistentvolumeclaims && "$identity" == "system:serviceaccount:$namespace:arcadectl-destroy-controller" ]] \
      || die "fixture cleanup impersonation is outside retained claim deletion"
    kube --as="$identity" delete --raw "$path" --filename "$workspace/recovery-cleanup-delete-options.json" >/dev/null
  else
    kube delete --raw "$path" --filename "$workspace/recovery-cleanup-delete-options.json" >/dev/null
  fi
  wait_absent "$resource" "$name" 150 || die "scoped fixture object did not drain its ordinary finalizers"
  recovery_cleanup_ledger absent "$resource" "$name" "$uid" "exact-name absent after uid-preconditioned delete"
}

recovery_cleanup_prove_delete_denied() {
  local name=$1 uid=$2 denial path
  verify_cluster_ownership || die "live admission proof requires the owned disposable Kind cluster"
  [[ $(kube get pvc "$name" --namespace "$namespace" --output=jsonpath='{.metadata.uid}') == "$uid" ]] \
    || die "live admission proof claim UID changed"
  jq -cn --arg uid "$uid" '{apiVersion:"v1",kind:"DeleteOptions",preconditions:{uid:$uid},propagationPolicy:"Foreground"}' \
    >"$workspace/recovery-cleanup-dry-run-delete.json"
  # Raw DELETE accepts the API query dryRun=All. Do not use --dry-run with
  # --raw: kubectl does not translate that flag for its raw DELETE path.
  # The harness admin is authorized by RBAC, but is not the dedicated destroy
  # identity. Therefore an explicit VAP denial proves the product boundary.
  path="/api/v1/namespaces/$namespace/persistentvolumeclaims/$name?dryRun=All"
  if denial=$(kube delete --raw "$path" --filename "$workspace/recovery-cleanup-dry-run-delete.json" 2>&1); then
    die "ordinary identity unexpectedly passed retained-world PVC DELETE admission"
  fi
  [[ "$denial" == *"arcadectl-retained-world-pvc-delete"* &&
     "$denial" == *"Only the dedicated Arcadectl destroy controller may delete a retained world PVC."* ]] \
    || die "retained-world DELETE failed without the required live VAP denial"
  [[ $(kube get pvc "$name" --namespace "$namespace" --output=jsonpath='{.metadata.uid}') == "$uid" ]] \
    || die "live dry-run admission proof changed the retained claim"
  recovery_cleanup_ledger admission-denied persistentvolumeclaims "$name" "$uid" "ordinary identity; actual DELETE dryRun=All; exact VAP denial"
}

recovery_cleanup_assert_storage_unused() {
  local claim=$1 pv=$2
  kube get pods --all-namespaces --output=json | jq -e --arg ns "$namespace" --arg claim "$claim" '
    [.items[] | select(.metadata.namespace == $ns) |
      select(any(.spec.volumes[]?; .persistentVolumeClaim.claimName == $claim))] | length == 0' >/dev/null \
    || die "scoped fixture storage still has a Pod user"
  kube get volumeattachments --output=json | jq -e --arg pv "$pv" '
    [.items[] | select(.spec.source.persistentVolumeName == $pv)] | length == 0' >/dev/null \
    || die "scoped fixture storage is still attached"
}

# Backup authority is UID-labelled, not instance-labelled. Match captured
# operation UIDs across every worker/authority kind so a missing instance label
# cannot hide a live Pod, Role or ServiceAccount from the drainage proof.
recovery_cleanup_remaining_authority() {
  local operations=$1
  kube get jobs,pods,leases,configmaps,serviceaccounts,roles,rolebindings --namespace "$namespace" --output=json \
    | jq --arg server "$server_name" --slurpfile captured "$operations" '
      [$captured[0][] | select(.kind == "GameBackup") | .metadata.uid] as $backups |
      [$captured[0][] | select(.kind == "GameRestore") | .metadata.uid] as $restores |
      [$captured[0][] | select(.kind == "GameDestroy") | .metadata.uid] as $destroys |
      {items:[.items[] | select(.metadata.labels["app.kubernetes.io/instance"] == $server or
        (.metadata.labels["arcade.gobha.me/backup-uid"] as $uid | $backups | index($uid) != null) or
        (.metadata.labels["arcade.gobha.me/restore-uid"] as $uid | $restores | index($uid) != null) or
        (.metadata.labels["arcade.gobha.me/destroy-uid"] as $uid | $destroys | index($uid) != null))]}'
}

# Prove scoped absence while the foreign sentinel and CSI/controller fixtures
# remain live. The later whole-owned-Kind teardown is a separate boundary.
# Direct retained-PVC/PV deletion here is explicit disposable-fixture cleanup,
# not evidence for the separately exercised product GameDestroy operation.
recovery_cleanup_fixtures() {
  say "cleaning exact recovery fixtures while preserving the unrelated sentinel"
  local operations="$workspace/recovery-cleanup-operations.json"
  local claims="$workspace/recovery-cleanup-world-claims.json"
  local volumes="$workspace/recovery-cleanup-world-volumes.json"
  local resource name uid claim claim_uid pv pv_uid handle record
  local inventory known_restore_uids journal_claim_uids expected_claim_uids deployment_uid repository_claim_uid repository_pv repository_pv_uid repository_handle
  local service_uid secret_inventory secret_uid deadline users remaining
  local live_support="$workspace/recovery-cleanup-live-support.json" policy_uid binding_uid support_uid
  verify_cluster_ownership || die "recovery cleanup requires its owned disposable Kind cluster"
  printf 'epoch\taction\tresource\tname\tuid\tevidence\n' >"$workspace/recovery-cleanup.tsv"
  recovery_cleanup_assert_sentinel
  assert_absent "gameserver/$server_name"
  kube get deployments arcadectl-controller arcadectl-destroy-controller --namespace "$namespace" --output=json \
    | jq '.items | map({name:.metadata.name,uid:.metadata.uid})' >"$live_support"
  jq -e 'length == 2 and all(.uid | test("^[0-9a-f-]{36}$"))' "$live_support" >/dev/null \
    || die "scoped cleanup cannot pin its installed operators"
  inventory=$(kube get statefulset arcadectl-csi-hostpath --namespace "$recovery_csi_namespace" --output=json)
  jq -e --arg run "$run_id" '.metadata.deletionTimestamp == null and
    .metadata.labels["arcade.gobha.me/test-run"] == $run' <<<"$inventory" >/dev/null \
    || die "scoped cleanup cannot pin its owned CSI fixture"
  support_uid=$(jq -r '.metadata.uid' <<<"$inventory")
  policy_uid=$(kube get validatingadmissionpolicy arcadectl-retained-world-pvc-delete --output=jsonpath='{.metadata.uid}')
  binding_uid=$(kube get validatingadmissionpolicybinding arcadectl-retained-world-pvc-delete --output=jsonpath='{.metadata.uid}')

  kube get gamebackups,gamerestores,gamedestroys --namespace "$namespace" --output=json \
    | jq --arg server "$server_name" '.items | map(select(
      (.kind == "GameBackup" and .spec.source.name == $server) or
      (.kind == "GameRestore" and .spec.target.name == $server) or
      (.kind == "GameDestroy" and .spec.target.gameServer.name == $server)))' >"$operations"
  jq -e 'length > 0 and all(.metadata.deletionTimestamp == null and
    .status.observedGeneration == .metadata.generation and .status.completedAt != null and
    (.status.phase == "Succeeded" or .status.phase == "Failed" or .status.phase == "Cancelled"))' \
    "$operations" >/dev/null || die "recovery cleanup found an unsettled operation"
  while IFS= read -r record; do
    recovery_assert_scoped_cr_terminal "$record"
  done < <(jq -c '.[]' "$operations")
  known_restore_uids=$(jq -c '[.[] | select(.kind == "GameRestore") | .metadata.uid]' "$operations")
  journal_claim_uids=$(jq -c '[.[] | select(.kind == "GameRestore") | .status.candidateData[]?.claimRef.uid] | unique' "$operations")
  # Start with immutable original/journal identities and known restore UIDs,
  # not desired labels/class. Drift must cause failure rather than hide storage.
  kube get pvc --namespace "$namespace" --output=json | jq --arg server "$server_name" \
    --arg original "$recovery_original_pvc_uid" --argjson restores "$known_restore_uids" --argjson journal "$journal_claim_uids" '
    .items | map(select(.metadata.uid == $original or
      (.metadata.uid as $uid | $journal | index($uid) != null) or
      (.metadata.labels["arcade.gobha.me/restore-uid"] as $uid | $restores | index($uid) != null) or
      (.metadata.labels["app.kubernetes.io/managed-by"] == "arcadectl" and
       .metadata.labels["app.kubernetes.io/instance"] == $server)))' >"$claims"
  jq -e --arg original "$recovery_original_pvc_uid" --arg identity "$recovery_original_identity" \
    --arg server "$server_name" --argjson restores "$known_restore_uids" '
    any(.metadata.uid == $original) and all(.metadata.deletionTimestamp == null and .status.phase == "Bound" and
      .metadata.labels["app.kubernetes.io/managed-by"] == "arcadectl" and
      .metadata.labels["app.kubernetes.io/instance"] == $server and .spec.storageClassName == "arcadectl-world-retain" and
      .metadata.labels["arcade.gobha.me/data-policy"] == "retain" and
      (.metadata.labels["arcade.gobha.me/data-identity"] | type) == "string" and
      (.metadata.labels["arcade.gobha.me/data-identity"] | length) > 0 and
      (.metadata.labels["arcade.gobha.me/data-path"] | type) == "string" and
      (.metadata.labels["arcade.gobha.me/data-path"] | length) > 0 and
      (.metadata.uid != $original or .metadata.labels["arcade.gobha.me/data-identity"] == $identity) and
      (.metadata.uid == $original or
       (.metadata.labels["arcade.gobha.me/restore-uid"] as $uid | $restores | index($uid) != null)))' \
    "$claims" >/dev/null || die "recovery cleanup found a world claim without original or restore provenance"
  # Include the already-deleted successful GameDestroy target. Its Released
  # Retain-policy PV still belongs to this disposable test, even without a PVC.
  expected_claim_uids=$(jq -cn --slurpfile claims "$claims" --slurpfile operations "$operations" \
    --arg original "$recovery_original_pvc_uid" --argjson journal "$journal_claim_uids" '
    ([$original] + $journal + [$claims[0][].metadata.uid] +
      [$operations[0][] | select(.kind == "GameDestroy" and .status.phase == "Succeeded") |
        .spec.target.data.claims[].claimRef.uid]) | unique')
  kube get pv --output=json | jq --arg ns "$namespace" --argjson uids "$expected_claim_uids" '
    .items | map(select(.spec.claimRef.namespace == $ns and
      (.spec.claimRef.uid as $uid | $uids | index($uid) != null)))' >"$volumes"
  jq -e 'length > 0 and all(.metadata.deletionTimestamp == null and
    .spec.storageClassName == "arcadectl-world-retain" and .spec.persistentVolumeReclaimPolicy == "Retain" and
    .spec.csi.driver == "hostpath.csi.k8s.io" and
    (.spec.csi.volumeHandle | test("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")) and
    (.status.phase == "Bound" or .status.phase == "Released"))' "$volumes" >/dev/null \
    || die "recovery cleanup retained PV inventory is not exact fixture CSI storage"
  jq -e --arg original "$recovery_original_pv_uid" --arg handle "$recovery_original_handle" '
    any(.metadata.uid == $original and .spec.csi.volumeHandle == $handle)' "$volumes" >/dev/null \
    || die "recovery cleanup lost the original retained PV identity"
  jq -e --slurpfile claims "$claims" --argjson uids "$expected_claim_uids" '
    . as $volumes | $uids | all(. as $uid |
      ([$volumes[] | select(.spec.claimRef.uid == $uid)] | length) == 1) and
    ($claims[0] | all(. as $claim | $volumes | any(
      .metadata.name == $claim.spec.volumeName and .spec.claimRef.uid == $claim.metadata.uid and
      .spec.claimRef.name == $claim.metadata.name)))' "$volumes" >/dev/null \
    || die "recovery cleanup claim/PV inventory is incomplete or aliased"

  # Preserve identities before deleting CRs; their ordinary controllers drain
  # finalizers and scoped worker authority while still installed and healthy.
  while IFS='|' read -r resource name uid; do
    recovery_cleanup_delete_exact "$resource" "$name" "$uid"
  done < <(jq -r '.[] | [(
    if .kind == "GameBackup" then "gamebackups" elif .kind == "GameRestore" then "gamerestores" else "gamedestroys" end),
    .metadata.name,.metadata.uid] | join("|")' "$operations")
  deadline=$((SECONDS + 150))
  while :; do
    remaining=$(recovery_cleanup_remaining_authority "$operations")
    if jq -e '.items | length == 0' <<<"$remaining" >/dev/null; then break; fi
    (( SECONDS < deadline )) || die "recovery cleanup retained server worker or lease authority"
    sleep 2
  done

  while IFS='|' read -r claim claim_uid pv; do
    record=$(jq -c --arg pv "$pv" '.[] | select(.metadata.name == $pv)' "$volumes")
    pv_uid=$(jq -r '.metadata.uid' <<<"$record")
    handle=$(jq -r '.spec.csi.volumeHandle' <<<"$record")
    kube get pvc "$claim" --namespace "$namespace" --output=json | jq -e --arg uid "$claim_uid" --arg pv "$pv" \
      --arg server "$server_name" --arg original "$recovery_original_pvc_uid" --argjson restores "$known_restore_uids" '
      .metadata.uid == $uid and .spec.volumeName == $pv and .status.phase == "Bound" and .metadata.deletionTimestamp == null and
      .metadata.labels["app.kubernetes.io/managed-by"] == "arcadectl" and .metadata.labels["app.kubernetes.io/instance"] == $server and
      .spec.storageClassName == "arcadectl-world-retain" and .metadata.labels["arcade.gobha.me/data-policy"] == "retain" and
      (.metadata.uid == $original or (.metadata.labels["arcade.gobha.me/restore-uid"] as $uid | $restores | index($uid) != null))' \
      >/dev/null || die "retained fixture claim identity changed before cleanup deletion"
    kube get pv "$pv" --output=json | jq -e --arg uid "$pv_uid" --arg claim "$claim_uid" --arg handle "$handle" '
      .metadata.uid == $uid and .spec.claimRef.uid == $claim and .spec.csi.volumeHandle == $handle and
      .spec.csi.driver == "hostpath.csi.k8s.io" and .spec.persistentVolumeReclaimPolicy == "Retain"' >/dev/null \
      || die "retained fixture backing identity changed before cleanup deletion"
    recovery_cleanup_assert_storage_unused "$claim" "$pv"
    recovery_cleanup_prove_delete_denied "$claim" "$claim_uid"
    recovery_cleanup_delete_exact persistentvolumeclaims "$claim" "$claim_uid" \
      "system:serviceaccount:$namespace:arcadectl-destroy-controller"
  done < <(jq -r '.[] | [.metadata.name,.metadata.uid,.spec.volumeName] | join("|")' "$claims")

  while IFS='|' read -r pv pv_uid claim claim_uid handle; do
    assert_absent "pvc/$claim"
    recovery_cleanup_assert_storage_unused "$claim" "$pv"
    kube_bounded 130 wait "pv/$pv" --for=jsonpath='{.status.phase}'=Released --timeout=120s >/dev/null
    record=$(kube get pv "$pv" --output=json) || die "retained PV proof could not read its fresh identity"
    jq -e --arg uid "$pv_uid" --arg claim "$claim_uid" --arg claimName "$claim" --arg handle "$handle" --arg ns "$namespace" '
      .metadata.uid == $uid and .metadata.deletionTimestamp == null and .status.phase == "Released" and
      .spec.claimRef.uid == $claim and .spec.claimRef.name == $claimName and .spec.claimRef.namespace == $ns and
      .spec.csi.driver == "hostpath.csi.k8s.io" and .spec.csi.volumeHandle == $handle and
      .spec.storageClassName == "arcadectl-world-retain" and .spec.persistentVolumeReclaimPolicy == "Retain"' <<<"$record" >/dev/null \
      || die "retained fixture PV identity changed after claim release"
    recovery_cleanup_delete_exact persistentvolumes "$pv" "$pv_uid"
    recovery_assert_retained_fixture_bytes "$record"
    recovery_cleanup_ledger retained-bytes persistentvolumes "$pv" "$pv_uid" "API absent; exact owned-node CSI directory remains; original requires A+B"
  done < <(jq -r '.[] | [.metadata.name,.metadata.uid,.spec.claimRef.name,.spec.claimRef.uid,.spec.csi.volumeHandle] | join("|")' "$volumes")
  recovery_record "exact fixture world PVC/PV API objects absent; Retain-policy backing bytes remain confined to owned Kind until node teardown"

  inventory=$(kube get deployment minio --namespace "$namespace" --output=json)
  jq -e --arg run "$run_id" '.metadata.deletionTimestamp == null and .metadata.labels["arcade.gobha.me/e2e-run"] == $run and
    .spec.template.metadata.labels["arcade.gobha.me/e2e-run"] == $run and
    any(.spec.template.spec.volumes[]; .persistentVolumeClaim.claimName == "recovery-repository-data")' \
    <<<"$inventory" >/dev/null || die "repository cleanup MinIO deployment is not the owned fixture"
  deployment_uid=$(jq -r '.metadata.uid' <<<"$inventory")
  inventory=$(kube get pvc recovery-repository-data --namespace "$namespace" --output=json)
  jq -e --arg run "$run_id" '.metadata.deletionTimestamp == null and .metadata.labels["arcade.gobha.me/e2e-run"] == $run and
    .spec.storageClassName == "arcadectl-repository" and .status.phase == "Bound"' <<<"$inventory" >/dev/null \
    || die "repository cleanup claim is not the owned fixture"
  repository_claim_uid=$(jq -r '.metadata.uid' <<<"$inventory")
  repository_pv=$(jq -r '.spec.volumeName' <<<"$inventory")
  inventory=$(kube get pv "$repository_pv" --output=json)
  jq -e --arg uid "$repository_claim_uid" --arg ns "$namespace" '
    .spec.claimRef.uid == $uid and .spec.claimRef.namespace == $ns and .spec.claimRef.name == "recovery-repository-data" and
    .spec.storageClassName == "arcadectl-repository" and .spec.persistentVolumeReclaimPolicy == "Delete" and
    .spec.csi.driver == "hostpath.csi.k8s.io" and
    (.spec.csi.volumeHandle | test("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"))' <<<"$inventory" >/dev/null \
    || die "repository cleanup PV does not match the exact owned CSI claim"
  repository_pv_uid=$(jq -r '.metadata.uid' <<<"$inventory")
  repository_handle=$(jq -r '.spec.csi.volumeHandle' <<<"$inventory")
  recovery_cleanup_delete_exact deployments minio "$deployment_uid"
  deadline=$((SECONDS + 120))
  while :; do
    users=$(kube get pods --namespace "$namespace" --output=json)
    remaining=$(kube get volumeattachments --output=json)
    if jq -e '[.items[] | select(any(.spec.volumes[]?; .persistentVolumeClaim.claimName == "recovery-repository-data"))] | length == 0' \
      <<<"$users" >/dev/null && jq -e --arg pv "$repository_pv" '.items | all(.spec.source.persistentVolumeName != $pv)' \
      <<<"$remaining" >/dev/null; then break; fi
    (( SECONDS < deadline )) || die "repository cleanup storage did not detach after MinIO removal"
    sleep 2
  done
  kube get pvc recovery-repository-data --namespace "$namespace" --output=json | jq -e --arg uid "$repository_claim_uid" \
    --arg pv "$repository_pv" --arg run "$run_id" '.metadata.uid == $uid and .spec.volumeName == $pv and
      .metadata.labels["arcade.gobha.me/e2e-run"] == $run and .spec.storageClassName == "arcadectl-repository"' >/dev/null \
    || die "repository claim identity changed before final deletion"
  kube get pv "$repository_pv" --output=json | jq -e --arg uid "$repository_pv_uid" --arg claim "$repository_claim_uid" \
    --arg handle "$repository_handle" '.metadata.uid == $uid and .spec.claimRef.uid == $claim and
      .spec.csi.volumeHandle == $handle and .spec.persistentVolumeReclaimPolicy == "Delete"' >/dev/null \
    || die "repository backing identity changed before final deletion"
  recovery_cleanup_assert_storage_unused recovery-repository-data "$repository_pv"
  recovery_cleanup_delete_exact persistentvolumeclaims recovery-repository-data "$repository_claim_uid"
  wait_absent pv "$repository_pv" 150 || die "repository Delete-policy PV did not disappear through CSI cleanup"
  recovery_cleanup_ledger absent persistentvolumes "$repository_pv" "$repository_pv_uid" "Delete-policy CSI cleanup; repository backing deletion not a retained-world proof"
  inventory=$(kube get service minio --namespace "$namespace" --output=json)
  jq -e --arg run "$run_id" '.metadata.labels["arcade.gobha.me/e2e-run"] == $run' <<<"$inventory" >/dev/null \
    || die "repository Service cleanup ownership changed"
  service_uid=$(jq -r '.metadata.uid' <<<"$inventory")
  recovery_cleanup_delete_exact services minio "$service_uid"
  secret_inventory=$(kube get secrets --namespace "$namespace" --output=json | jq '
    [.items[] | select(.metadata.name == "recovery-repository" or .metadata.name == "recovery-corrupt-repository" or
      .metadata.name == "recovery-identity-uid" or .metadata.name == "recovery-identity-revision") |
      {name:.metadata.name,uid:.metadata.uid,run:.metadata.labels["arcade.gobha.me/e2e-run"],immutable:.immutable}]')
  jq -e --arg run "$run_id" 'any(.name == "recovery-repository") and all(.run == $run and .immutable == true)' \
    <<<"$secret_inventory" >/dev/null || die "fake repository Secret cleanup ownership changed"
  while IFS='|' read -r name secret_uid; do
    recovery_cleanup_delete_exact secrets "$name" "$secret_uid"
  done < <(jq -r '.[] | [.name,.uid] | join("|")' <<<"$secret_inventory")
  assert_absent secret/recovery-repository
  assert_absent secret/recovery-corrupt-repository
  assert_absent secret/recovery-identity-uid
  assert_absent secret/recovery-identity-revision
  assert_absent pvc/recovery-repository-data
  assert_absent deployment/minio
  assert_absent service/minio

  kube get gamebackups,gamerestores,gamedestroys --namespace "$namespace" --output=json | jq -e \
    --arg server "$server_name" --slurpfile captured "$operations" '
    [.items[] | . as $current | select((.metadata.uid as $uid | [$captured[0][].metadata.uid] | index($uid) != null) or
      any($captured[0][]; .kind == $current.kind and .metadata.name == $current.metadata.name) or
      (.kind == "GameBackup" and .spec.source.name == $server) or
      (.kind == "GameRestore" and .spec.target.name == $server) or
      (.kind == "GameDestroy" and .spec.target.gameServer.name == $server))] | length == 0' >/dev/null \
    || die "scoped recovery operations remained after cleanup"
  kube get pvc --namespace "$namespace" --output=json | jq -e --arg server "$server_name" \
    --argjson uids "$expected_claim_uids" --argjson restores "$known_restore_uids" --slurpfile captured "$claims" '
    [.items[] | select((.metadata.uid as $uid | $uids | index($uid) != null) or
      (.metadata.name as $name | [$captured[0][].metadata.name] | index($name) != null) or
      (.metadata.labels["arcade.gobha.me/restore-uid"] as $uid | $restores | index($uid) != null) or
      (.metadata.labels["app.kubernetes.io/managed-by"] == "arcadectl" and
       .metadata.labels["app.kubernetes.io/instance"] == $server))] | length == 0' >/dev/null \
    || die "scoped recovery world claims remained after cleanup"
  kube get pv --output=json | jq -e --arg ns "$namespace" --argjson uids "$expected_claim_uids" \
    --slurpfile captured "$volumes" --arg repository "$repository_pv" --arg repositoryUID "$repository_pv_uid" '
    [.items[] | select(.metadata.name == $repository or .metadata.uid == $repositoryUID or
      (.metadata.uid as $uid | [$captured[0][].metadata.uid] | index($uid) != null) or
      (.metadata.name as $name | [$captured[0][].metadata.name] | index($name) != null) or
      (.spec.claimRef.namespace == $ns and (.spec.claimRef.uid as $uid | $uids | index($uid) != null)))] |
    length == 0' >/dev/null || die "scoped recovery exact PV identities or claim bindings remained after cleanup"
  recovery_cleanup_remaining_authority "$operations" | jq -e '.items | length == 0' >/dev/null \
    || die "scoped recovery worker or authority returned after cleanup"
  while IFS='|' read -r name uid; do
    kube get deployment "$name" --namespace "$namespace" --output=json | jq -e --arg uid "$uid" '
      .metadata.uid == $uid and .metadata.deletionTimestamp == null and .spec.replicas == 1 and
      .status.observedGeneration == .metadata.generation and .status.availableReplicas == 1 and
      .status.readyReplicas == 1 and .status.updatedReplicas == 1 and
      any(.status.conditions[]; .type == "Available" and .status == "True")' >/dev/null \
      || die "scoped recovery cleanup did not leave its exact installed operator healthy"
    recovery_cleanup_ledger preserved deployments "$name" "$uid" "exact UID; current available ready updated replica"
  done < <(jq -r '.[] | [.name,.uid] | join("|")' "$live_support")
  kube get statefulset arcadectl-csi-hostpath --namespace "$recovery_csi_namespace" --output=json \
    | jq -e --arg uid "$support_uid" --arg run "$run_id" '
      .metadata.uid == $uid and .metadata.deletionTimestamp == null and .metadata.labels["arcade.gobha.me/test-run"] == $run and
      .spec.replicas == 1 and .status.observedGeneration == .metadata.generation and
      .status.readyReplicas == 1 and .status.currentReplicas == 1 and .status.updatedReplicas == 1 and
      .status.currentRevision == .status.updateRevision' >/dev/null \
    || die "scoped cleanup did not leave its exact owned CSI fixture healthy"
  recovery_cleanup_ledger preserved statefulsets arcadectl-csi-hostpath "$support_uid" "owned run; current ready CSI replica"
  kube get validatingadmissionpolicy arcadectl-retained-world-pvc-delete --output=json \
    | jq -e --arg uid "$policy_uid" '.metadata.uid == $uid and .metadata.deletionTimestamp == null and .spec.failurePolicy == "Fail"' \
      >/dev/null || die "scoped cleanup removed or replaced the live retained-world VAP"
  kube get validatingadmissionpolicybinding arcadectl-retained-world-pvc-delete --output=json \
    | jq -e --arg uid "$binding_uid" --arg ns "$namespace" '
      .metadata.uid == $uid and .metadata.deletionTimestamp == null and
      .spec.policyName == "arcadectl-retained-world-pvc-delete" and .spec.validationActions == ["Deny"] and
      .spec.matchResources.namespaceSelector.matchLabels["kubernetes.io/metadata.name"] == $ns' >/dev/null \
    || die "scoped cleanup removed or replaced the live retained-world VAP binding"
  recovery_cleanup_ledger preserved validatingadmissionpolicies arcadectl-retained-world-pvc-delete "$policy_uid" "same UID; fail closed; binding Deny still live"
  recovery_cleanup_assert_sentinel
  recovery_verify_sentinel_storage
  recovery_cleanup_ledger preserved persistentvolumeclaims unrelated-recovery-sentinel "$recovery_sentinel_uid" \
    "same PVC/PV/CSI handle; read-only uid845 sentinel hash verified; helper absent and detached"
  recovery_cleanup_ledger preserved configmaps unrelated-recovery-sentinel "$recovery_sentinel_config_uid" "same UID and sentinel=preserve"
  recovery_cleanup_ledger scoped-complete fixtures "$server_name" - "operations world API repository fixtures absent; sentinel and CSI/operators still live; whole-Kind teardown separate"
  recovery_record "scoped operations, world API objects and fake repository fixtures absent; foreign sentinel PVC/ConfigMap exact UIDs preserved; CSI/operators left for whole-owned-Kind teardown"
}
