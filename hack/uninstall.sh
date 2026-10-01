#!/usr/bin/env bash
# Copyright 2026 gobha-me
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

readonly repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly kubectl_command=${KUBECTL:-kubectl}
readonly namespace=arcadectl-system

command -v jq >/dev/null || { echo "jq is required to verify the retained admission policy" >&2; exit 1; }

assert_admission_gate() {
  local operation policy_name policy binding expected_policy expected_binding denial_output
  for operation in backup restore; do
    policy_name="arcadectl-$operation-worker-gate"
    policy=$("$kubectl_command" get validatingadmissionpolicies.admissionregistration.k8s.io \
      "$policy_name" --output=json | jq -ceS '.spec | objects')
    expected_policy=$("$kubectl_command" create --dry-run=client --validate=false \
      --filename "$repository_root/config/install/$operation-worker-admission-policy.yaml" \
      --output=json | jq -ceS '.spec | objects')
    if [[ "$policy" != "$expected_policy" ]]; then
      echo "refusing uninstall because the retained $operation-worker admission policy differs from the shipped specification" >&2
      return 1
    fi
    binding=$("$kubectl_command" get validatingadmissionpolicybindings.admissionregistration.k8s.io \
      "$policy_name" --output=json | jq -ceS '.spec | objects')
    expected_binding=$("$kubectl_command" create --dry-run=client --validate=false \
      --filename "$repository_root/config/install/$operation-worker-admission-policy-binding.yaml" \
      --output=json | jq -ceS '.spec | objects')
    if [[ "$binding" != "$expected_binding" ]]; then
      echo "refusing uninstall because the retained $operation-worker admission binding differs from the shipped specification" >&2
      return 1
    fi
    if denial_output=$("$kubectl_command" create --dry-run=server --filename=- 2>&1 <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: arcadectl-uninstall-admission-probe
  namespace: $namespace
  labels:
    app.kubernetes.io/managed-by: arcadectl
    app.kubernetes.io/name: $operation-worker
spec:
  automountServiceAccountToken: false
  restartPolicy: Never
  securityContext:
    runAsNonRoot: true
    runAsUser: 65532
    runAsGroup: 65532
    seccompProfile: {type: RuntimeDefault}
  containers:
    - name: probe
      image: example.invalid/arcadectl-uninstall-probe@sha256:0000000000000000000000000000000000000000000000000000000000000000
      command: ["/never-run"]
      resources:
        requests: {cpu: 1m, memory: 8Mi}
        limits: {cpu: 1m, memory: 8Mi}
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities: {drop: [ALL]}
EOF
    ); then
      echo "refusing uninstall because the retained $operation-worker admission gate accepted an ungated Pod" >&2
      return 1
    fi
    if ! grep -Fq "Arcadectl $operation worker Pods must enter admission with exactly one execution gate" <<<"$denial_output"; then
      echo "refusing uninstall because the retained $operation-worker admission gate could not be proved effective" >&2
      return 1
    fi
  done
}

assert_candidate_pvc_gate() {
  local policy binding expected_policy expected_binding denial_output
  policy=$("$kubectl_command" get validatingadmissionpolicies.admissionregistration.k8s.io \
    arcadectl-restore-candidate-pvc-create --output=json | jq -ceS '.spec | objects')
  expected_policy=$("$kubectl_command" create --dry-run=client --validate=false \
    --filename "$repository_root/config/install/restore-candidate-pvc-admission-policy.yaml" \
    --output=json | jq -ceS '.spec | objects')
  if [[ "$policy" != "$expected_policy" ]]; then
    echo "refusing uninstall because the retained restore-candidate PVC admission policy differs from the shipped specification" >&2
    return 1
  fi
  binding=$("$kubectl_command" get validatingadmissionpolicybindings.admissionregistration.k8s.io \
    arcadectl-restore-candidate-pvc-create --output=json | jq -ceS '.spec | objects')
  expected_binding=$("$kubectl_command" create --dry-run=client --validate=false \
    --filename "$repository_root/config/install/restore-candidate-pvc-admission-policy-binding.yaml" \
    --output=json | jq -ceS '.spec | objects')
  if [[ "$binding" != "$expected_binding" ]]; then
    echo "refusing uninstall because the retained restore-candidate PVC admission binding differs from the shipped specification" >&2
    return 1
  fi
  if denial_output=$("$kubectl_command" create --dry-run=server --filename=- 2>&1 <<EOF
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: restore-uninstall-admission-probe
  namespace: $namespace
spec:
  accessModes: [ReadWriteOnce]
  resources:
    requests:
      storage: 1Mi
EOF
  ); then
    echo "refusing uninstall because the retained restore-candidate PVC policy accepted an unauthorized create" >&2
    return 1
  fi
  if ! grep -Fq 'Only the Arcadectl controller may create restore candidate PVCs' <<<"$denial_output"; then
    echo "refusing uninstall because the retained restore-candidate PVC policy could not be proved effective" >&2
    return 1
  fi
}

assert_safe_state() {
  local servers unsafe_servers backups unsafe_backups restores unsafe_restores jobs unsafe_jobs pods unsafe_pods leases unsafe_leases
  assert_admission_gate
  assert_candidate_pvc_gate
  servers=$("$kubectl_command" get gameservers.arcade.gobha.me --namespace "$namespace" \
    --output=jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.desiredState}{"\t"}{.status.phase}{"\t"}{.metadata.generation}{"\t"}{.status.observedGeneration}{"\t"}{.metadata.deletionTimestamp}{"\n"}{end}')
  unsafe_servers=$(awk -F '\t' 'NF > 0 && ($2 != "Stopped" || $3 != "Stopped" || $4 == "" || $5 == "" || $4 != $5 || $6 != "") { print }' <<<"$servers")
  if [[ -n "$unsafe_servers" ]]; then
    echo "refusing uninstall because every GameServer must be non-deleting, desired Stopped, and observed Stopped at its current generation:" >&2
    printf '%s\n' "$unsafe_servers" >&2
    return 1
  fi

  backups=$("$kubectl_command" get gamebackups.arcade.gobha.me --namespace "$namespace" \
    --output=jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.status.phase}{"\t"}{.metadata.generation}{"\t"}{.status.observedGeneration}{"\t"}{.metadata.deletionTimestamp}{"\n"}{end}')
  unsafe_backups=$(awk -F '\t' 'NF > 0 && (($2 != "Succeeded" && $2 != "Failed" && $2 != "Cancelled") || $3 == "" || $4 == "" || $3 != $4 || $5 != "") { print }' <<<"$backups")
  if [[ -n "$unsafe_backups" ]]; then
    echo "refusing uninstall because every GameBackup must be terminal, observed at its current generation, and not deleting:" >&2
    printf '%s\n' "$unsafe_backups" >&2
    return 1
  fi

  restores=$("$kubectl_command" get gamerestores.arcade.gobha.me --namespace "$namespace" \
    --output=jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.status.phase}{"\t"}{.metadata.generation}{"\t"}{.status.observedGeneration}{"\t"}{.metadata.deletionTimestamp}{"\n"}{end}')
  unsafe_restores=$(awk -F '\t' 'NF > 0 && (($2 != "Succeeded" && $2 != "Failed" && $2 != "Cancelled") || $3 == "" || $4 == "" || $3 != $4 || $5 != "") { print }' <<<"$restores")
  if [[ -n "$unsafe_restores" ]]; then
    echo "refusing uninstall because every GameRestore must be terminal, observed at its current generation, and not deleting:" >&2
    printf '%s\n' "$unsafe_restores" >&2
    return 1
  fi

  jobs=$("$kubectl_command" get jobs.batch --namespace "$namespace" \
    --output=jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.metadata.labels.app\.kubernetes\.io/managed-by}{"\t"}{.metadata.labels.app\.kubernetes\.io/name}{"\t"}{.metadata.labels.arcade\.gobha\.me/data-operation}{"\n"}{end}')
  unsafe_jobs=$(awk -F '\t' 'NF > 0 && ($1 ~ /^(backup|restore)-/ || ($2 == "arcadectl" && ($3 == "backup-worker" || $3 == "restore-worker")) || $4 != "") { print }' <<<"$jobs")
  pods=$("$kubectl_command" get pods --namespace "$namespace" \
    --output=jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.metadata.labels.app\.kubernetes\.io/managed-by}{"\t"}{.metadata.labels.app\.kubernetes\.io/name}{"\t"}{.metadata.labels.arcade\.gobha\.me/data-operation}{"\t"}{.spec.serviceAccountName}{"\t"}{range .metadata.ownerReferences[*]}{.apiVersion}{"/"}{.kind}{"/"}{.name}{" "}{end}{"\n"}{end}')
  unsafe_pods=$(awk -F '\t' 'NF > 0 && ($1 ~ /^(backup|restore)-/ || ($2 == "arcadectl" && ($3 == "backup-worker" || $3 == "restore-worker")) || $4 != "" || $5 ~ /^(backup|restore)-/ || $6 ~ /batch\/v1\/Job\/(backup|restore)-/) { print }' <<<"$pods")
  leases=$("$kubectl_command" get leases.coordination.k8s.io --namespace "$namespace" \
    --output=jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.metadata.labels.app\.kubernetes\.io/managed-by}{"\t"}{.metadata.labels.arcade\.gobha\.me/data-identity}{"\n"}{end}')
  unsafe_leases=$(awk -F '\t' 'NF > 0 && ($1 ~ /^data-operation-/ || ($2 == "arcadectl" && $3 != "")) { print }' <<<"$leases")
  if [[ -n "$unsafe_jobs" || -n "$unsafe_pods" || -n "$unsafe_leases" ]]; then
    echo "refusing uninstall because data-operation Jobs, Pods, or Leases still exist:" >&2
    printf '%s\n' "$unsafe_jobs" "$unsafe_pods" "$unsafe_leases" | sed '/^$/d' >&2
    return 1
  fi
}

assert_safe_state

controller_replicas=$("$kubectl_command" get deployment arcadectl-controller --namespace "$namespace" \
  --ignore-not-found --output=jsonpath='{.spec.replicas}')
readonly controller_replicas
if [[ -n "$controller_replicas" && ! "$controller_replicas" =~ ^[0-9]+$ ]]; then
  echo "refusing uninstall because the controller replica count is invalid" >&2
  exit 1
fi

controller_scaled=false
restore_controller() {
  local exit_code=$?
  trap - EXIT
  if [[ "$controller_scaled" == true ]]; then
    echo "uninstall did not complete; restoring the controller to $controller_replicas replicas" >&2
    "$kubectl_command" scale deployment/arcadectl-controller --namespace "$namespace" --replicas="$controller_replicas" >&2 || true
    "$kubectl_command" rollout status deployment/arcadectl-controller --namespace "$namespace" --timeout=120s >&2 || true
  fi
  exit "$exit_code"
}
trap restore_controller EXIT

if [[ -n "$controller_replicas" && "$controller_replicas" -gt 0 ]]; then
  "$kubectl_command" scale deployment/arcadectl-controller --namespace "$namespace" --replicas=0 >/dev/null
  controller_scaled=true
fi

deadline=$((SECONDS + 120))
while true; do
  controller_pods=$("$kubectl_command" get pods --namespace "$namespace" \
    --selector=app.kubernetes.io/name=arcadectl-controller --output=name)
  if [[ -z "$controller_pods" ]]; then
    break
  fi
  if (( SECONDS >= deadline )); then
    echo "timed out waiting for the controller Pods to stop; refusing uninstall" >&2
    exit 1
  fi
  sleep 1
done

# Re-read every safety boundary after the controller is quiescent. New intent
# can remain pending for a later reinstall, but no controller can start work
# between this check and removal of its namespaced authority.
assert_safe_state

"$kubectl_command" delete --filename "$repository_root/config/install/uninstall.yaml" --ignore-not-found=true
controller_scaled=false
trap - EXIT

echo "controller removed; admission gates, namespace, CRDs, operation records, and retained PVCs were not deleted"
