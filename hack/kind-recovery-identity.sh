#!/usr/bin/env bash
# Copyright 2026 gobha-me
# SPDX-License-Identifier: Apache-2.0
# Sourced only by the ownership-checked disposable Kind recovery harness.

recovery_identity_wait_backup_cleanup() {
  local uid=$1 remaining deadline=$((SECONDS + 120))
  while (( SECONDS < deadline )); do
    # Successful backups retain their owned input/RBAC objects until the
    # historical record is deleted. No worker Pod, Job or active lease may
    # survive; later scoped CR cleanup must also prove those owned objects gone.
    remaining=$(kube get jobs,pods,leases \
      --namespace "$namespace" --selector "arcade.gobha.me/backup-uid=$uid" --output=json)
    if jq -e '.items | length == 0' <<<"$remaining" >/dev/null; then return 0; fi
    sleep 2
  done
  die "identity-race backup retained an exact worker Job, Pod or operation lease"
}

recovery_identity_delete_secret() {
  local name=$1 uid=$2
  [[ "$name" == recovery-identity-uid && "$uid" =~ ^[0-9a-f-]{36}$ ]] \
    || die "refusing identity-race deletion outside the exact cloned Secret"
  verify_cluster_ownership || die "lost disposable cluster ownership before Secret replacement"
  kube get secret "$name" --namespace "$namespace" --output=json | jq -e --arg uid "$uid" --arg run "$run_id" \
    '.metadata.uid == $uid and .metadata.labels["arcade.gobha.me/e2e-run"] == $run and .immutable == true' >/dev/null \
    || die "cloned Secret replacement identity or ownership changed"
  jq -cn --arg uid "$uid" '{apiVersion:"v1",kind:"DeleteOptions",preconditions:{uid:$uid},propagationPolicy:"Foreground"}' \
    >"$workspace/recovery-identity-delete-options.json"
  kube delete --raw "/api/v1/namespaces/$namespace/secrets/$name" \
    --filename "$workspace/recovery-identity-delete-options.json" >/dev/null
  wait_absent secret "$name" 60
}

recovery_fault_identity_races() (
  say "racing exact repository Secret UID and resourceVersion before activation"
  local original_secret original_backup mode secret backup restore old_ref new_ref backup_uid restore_uid result
  local controller_paused=false
  original_secret=$(recovery_repository_ref "$repository_secret_name")
  original_backup=$(kube get gamebackup original-backup --namespace "$namespace" --output=json \
    | jq -c '{uid:.metadata.uid,artifact:.status.artifact,source:.status.source}')
  # Keep the production-shaped original backup and repository authority intact.
  # Each race owns a cloned immutable Secret and an independently real backup.
  trap 'if [[ "$controller_paused" == true ]]; then kube scale deployment/arcadectl-controller --namespace "$namespace" --replicas=1 >/dev/null 2>&1 || :; fi' EXIT
  for mode in uid revision; do
    secret="recovery-identity-$mode"
    backup="identity-$mode-backup"
    restore="identity-$mode-race"
    kube get secret "$repository_secret_name" --namespace "$namespace" --output=json \
      | jq --arg name "$secret" --arg ns "$namespace" --arg run "$run_id" \
        '{apiVersion:"v1",kind:"Secret",metadata:{name:$name,namespace:$ns,labels:{"arcade.gobha.me/e2e-run":$run}},
          immutable:true,type:.type,data:.data}' >"$workspace/recovery-identity-$mode-secret.json"
    kube create --filename "$workspace/recovery-identity-$mode-secret.json" >/dev/null
    recovery_create_backup "$backup" "$secret"
    backup_uid=$(kube get gamebackup "$backup" --namespace "$namespace" --output=jsonpath='{.metadata.uid}')
    recovery_identity_wait_backup_cleanup "$backup_uid"
    recovery_start
    old_ref=$(recovery_repository_ref "$secret")
    kube scale deployment/arcadectl-controller --namespace "$namespace" --replicas=0 >/dev/null
    controller_paused=true
    kube_bounded 100 wait pod --namespace "$namespace" --selector=app.kubernetes.io/name=arcadectl-controller \
      --for=delete --timeout=90s >/dev/null
    kube get pods --namespace "$namespace" --selector=app.kubernetes.io/name=arcadectl-controller --output=json \
      | jq -e '.items | length == 0' >/dev/null || die "identity race did not stop the ordinary controller"
    recovery_create_restore "$restore" "$backup" "$secret"
    restore_uid=$(kube get gamerestore "$restore" --namespace "$namespace" --output=jsonpath='{.metadata.uid}')
    kube get gamerestore "$restore" --namespace "$namespace" --output=json | jq -e --argjson ref "$old_ref" \
      '.spec.repositorySecretRef == $ref and (.status.phase // "") == ""
        and .status.fence == null and .status.preflightVerifiedAt == null and (.status.candidateData // [] | length) == 0' \
      >/dev/null || die "identity-race request was not pinned and inert before replacement"
    if [[ "$mode" == uid ]]; then
      recovery_identity_delete_secret "$secret" "$(jq -r '.uid' <<<"$old_ref")"
      kube create --filename "$workspace/recovery-identity-$mode-secret.json" >/dev/null
    else
      # Kubernetes immutable Secrets still permit metadata changes. Changing a
      # label/annotation increments RV without weakening immutable data or UID.
      kube patch secret "$secret" --namespace "$namespace" --type=merge \
        --patch '{"metadata":{"annotations":{"arcade.gobha.me/recovery-identity-revision":"after-request"}}}' >/dev/null
    fi
    new_ref=$(recovery_repository_ref "$secret")
    jq -en --argjson old "$old_ref" --argjson new "$new_ref" --arg mode "$mode" \
      '$old.name == $new.name and $old.resourceVersion != $new.resourceVersion
        and (if $mode == "uid" then $old.uid != $new.uid else $old.uid == $new.uid end)' >/dev/null \
      || die "identity race did not change exactly the intended live authority"
    recovery_record "identity race=$mode restore=$restore_uid old=$(jq -r '.uid+"/"+.resourceVersion' <<<"$old_ref") new=$(jq -r '.uid+"/"+.resourceVersion' <<<"$new_ref")"
    kube scale deployment/arcadectl-controller --namespace "$namespace" --replicas=1 >/dev/null
    kube_bounded 190 rollout status deployment/arcadectl-controller --namespace "$namespace" --timeout=180s >/dev/null
    controller_paused=false
    # Controller does not read credential bytes. The real repository-only
    # authorizer rejects the stale exact reference, producing VerificationFailed.
    recovery_wait_settled_failure "$restore" VerificationFailed
    result=$(kube get gamerestore "$restore" --namespace "$namespace" --output=json)
    jq -e '.status.phase == "Failed" and .status.fence == null and .status.preflightVerifiedAt == null
      and (.status.candidateData // [] | length) == 0 and .status.candidateVerification == null
      and .status.activationStartedAt == null and (.status.activeData // [] | length) == 0' \
      <<<"$result" >/dev/null || die "identity race crossed repository-only preflight boundary"
    kube get pvc --namespace "$namespace" --selector "arcade.gobha.me/restore-uid=$restore_uid" --output=json \
      | jq -e '.items | length == 0' >/dev/null || die "identity race provisioned a candidate world"
    recovery_fault_wait_cleanup "$restore_uid"
    [[ $(recovery_repository_ref "$repository_secret_name") == "$original_secret" ]] \
      || die "identity race changed the original repository Secret"
    [[ $(kube get gamebackup original-backup --namespace "$namespace" --output=json \
      | jq -c '{uid:.metadata.uid,artifact:.status.artifact,source:.status.source}') == "$original_backup" ]] \
      || die "identity race changed original backup provenance"
    recovery_assert_original
    recovery_record "fault identity-$mode-race uid=$restore_uid rejected before fence/candidate; original authority, backup and A+B preserved"
  done
)
