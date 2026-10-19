// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installrender"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Frozen pre-Images constructor from a566074. Keep the whole manifest copy as
// an independent semantic/benchmark oracle; never use this in production.
func manifestAdmissionCreateProbe(plan *installrender.Plan, policyName, account, name string) (*unstructured.Unstructured, *unstructured.Unstructured, int, error) {
	nonce := strings.TrimPrefix(name, "arcadectl-probe-")
	if !plan.IsTrusted() || !addressPart(account) || !strings.HasPrefix(name, "arcadectl-probe-") || !nonceID.MatchString(nonce) {
		return nil, nil, 0, ErrInvalid
	}
	known := false
	for _, resource := range plan.ResourceMetadata() {
		if resource.Kind == "ValidatingAdmissionPolicy" && resource.Name == policyName {
			known = true
		}
	}
	if !known {
		return nil, nil, 0, ErrInvalid
	}
	meta := map[string]any{"name": name, "namespace": plan.Namespace()}
	positive := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": meta, "spec": map[string]any{"accessModes": []any{"ReadWriteOnce"}, "resources": map[string]any{"requests": map[string]any{"storage": "1Mi"}}, "storageClassName": "", "volumeMode": "Filesystem"}}}
	is := func(stem string) bool { return policyName == stem || strings.HasPrefix(policyName, stem+"-") }
	switch {
	case is("arcadectl-backup-worker-gate"), is("arcadectl-restore-worker-gate"), is("arcadectl-destroy-worker-gate"):
		worker := "backup"
		if is("arcadectl-restore-worker-gate") {
			worker = "restore"
		}
		if is("arcadectl-destroy-worker-gate") {
			worker = "destroy"
		}
		meta["labels"] = map[string]any{"app.kubernetes.io/managed-by": "arcadectl", "app.kubernetes.io/name": worker + "-worker"}
		positive.SetKind("Pod")
		// Explicit native defaults were independently certified on both exact
		// declared profiles. No token volume, sidecar, environment, owner,
		// node assignment or authorization annotation is allowed.
		positive.Object["spec"] = map[string]any{
			"serviceAccountName": account, "serviceAccount": account, "automountServiceAccountToken": false, "enableServiceLinks": false,
			"restartPolicy": "Never", "dnsPolicy": "ClusterFirst", "schedulerName": "default-scheduler", "terminationGracePeriodSeconds": int64(30), "priority": int64(0), "preemptionPolicy": "PreemptLowerPriority",
			"securityContext": map[string]any{"runAsNonRoot": true, "runAsUser": int64(65532), "runAsGroup": int64(65532), "seccompProfile": map[string]any{"type": "RuntimeDefault"}},
			"containers":      []any{map[string]any{"name": "probe", "image": plan.Manifest().Images.Controller, "command": []any{"arcadectl-admission-probe"}, "imagePullPolicy": "IfNotPresent", "resources": map[string]any{}, "terminationMessagePath": "/dev/termination-log", "terminationMessagePolicy": "File", "securityContext": map[string]any{"allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true, "capabilities": map[string]any{"drop": []any{"ALL"}}}}},
			"tolerations":     []any{map[string]any{"key": "node.kubernetes.io/not-ready", "operator": "Exists", "effect": "NoExecute", "tolerationSeconds": int64(300)}, map[string]any{"key": "node.kubernetes.io/unreachable", "operator": "Exists", "effect": "NoExecute", "tolerationSeconds": int64(300)}},
			"schedulingGates": []any{map[string]any{"name": "arcade.gobha.me/" + worker + "-authorized"}},
		}
		negative := positive.DeepCopy()
		unstructured.RemoveNestedField(negative.Object, "spec", "schedulingGates")
		return positive, negative, 1, nil
	case is("arcadectl-restore-candidate-pvc-create"):
		negative := positive.DeepCopy()
		negative.SetName("restore-" + name)
		return positive, negative, 0, nil
	case is("arcadectl-retained-world-pvc-delete"):
		meta["labels"] = map[string]any{"app.kubernetes.io/managed-by": "arcadectl", "app.kubernetes.io/instance": name, "arcade.gobha.me/data-identity": "probe-world", "arcade.gobha.me/data-policy": "retain", "arcade.gobha.me/data-path": "data"}
		negative := positive.DeepCopy()
		negative.SetAnnotations(map[string]string{"arcade.gobha.me/cold-backup-uid": "unearned-backup"})
		return positive, negative, 0, nil
	case is("arcadectl-destroy-unsafe-admin"):
		positive.SetAPIVersion("arcade.gobha.me/v1alpha1")
		positive.SetKind("GameDestroy")
		positive.Object["spec"] = map[string]any{"target": map[string]any{"gameServer": map[string]any{"name": name, "uid": "probe-server-uid"}, "game": "admission-probe", "data": map[string]any{"identity": "probe-world", "claims": []any{map[string]any{"path": "data", "claimRef": map[string]any{"name": name, "uid": "probe-claim-uid"}}}}}, "mode": "VerifiedBackup", "backupRef": map[string]any{"name": name, "uid": "probe-backup-uid"}, "repositorySecretRef": map[string]any{"name": name, "uid": "probe-repository-uid", "resourceVersion": "1"}, "cancelRequested": false}
		negative := positive.DeepCopy()
		unstructured.RemoveNestedField(negative.Object, "spec", "backupRef")
		unstructured.RemoveNestedField(negative.Object, "spec", "repositorySecretRef")
		_ = unstructured.SetNestedField(negative.Object, "UnsafeNoBackup", "spec", "mode")
		_ = unstructured.SetNestedField(negative.Object, "isolated admission probe", "spec", "unsafeReason")
		negative.SetAnnotations(map[string]string{"arcade.gobha.me/unsafe-requested-by": "system:serviceaccount:" + plan.Namespace() + ":arcadectl-destroy-admin"})
		return positive, negative, 0, nil
	}
	return nil, nil, 0, ErrInvalid
}

func BenchmarkAdmissionCreateProbeImages(b *testing.B) {
	for _, profile := range []string{installrender.Profile135, installrender.Profile137} {
		plan := fixturePlanProfile(b, "isolated-probe-images", profile)
		for _, stem := range []string{"arcadectl-backup-worker-gate", "arcadectl-restore-worker-gate", "arcadectl-destroy-worker-gate", "arcadectl-restore-candidate-pvc-create", "arcadectl-destroy-unsafe-admin"} {
			policy := ""
			for _, resource := range plan.ResourceMetadata() {
				if resource.Kind == "ValidatingAdmissionPolicy" && strings.HasPrefix(resource.Name, stem) {
					if policy != "" {
						b.Fatal("ambiguous signed policy")
					}
					policy = resource.Name
				}
			}
			if policy == "" {
				b.Fatal("signed benchmark policy missing")
			}
			const name = "arcadectl-probe-0123456789abcdef0123456789abcdef"
			oldP, oldN, oldIndex, oldErr := manifestAdmissionCreateProbe(plan, policy, "arcadectl-controller", name)
			newP, newN, newIndex, newErr := admissionCreateProbe(plan, policy, "arcadectl-controller", name)
			if oldErr != nil || newErr != nil || oldIndex != newIndex || !reflect.DeepEqual(oldP, newP) || !reflect.DeepEqual(oldN, newN) {
				b.Fatal("complete constructor oracle mismatch")
			}
			for _, variant := range []struct {
				name      string
				construct func(*installrender.Plan, string, string, string) (*unstructured.Unstructured, *unstructured.Unstructured, int, error)
			}{{"manifest", manifestAdmissionCreateProbe}, {"images", admissionCreateProbe}} {
				b.Run(profile+"/"+stem+"/"+variant.name, func(b *testing.B) {
					b.ReportAllocs()
					for b.Loop() {
						positive, negative, index, err := variant.construct(plan, policy, "arcadectl-controller", name)
						if err != nil {
							b.Fatal("closed probe constructor refused")
						}
						runtime.KeepAlive(positive)
						runtime.KeepAlive(negative)
						runtime.KeepAlive(index)
					}
				})
			}
		}
	}
}
