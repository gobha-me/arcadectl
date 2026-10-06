// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"encoding/json"
	"reflect"
	"strings"
	"time"

	arcadev1 "github.com/gobha-me/arcadectl/api/v1alpha1"
	"github.com/gobha-me/arcadectl/internal/installrender"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	strictjson "sigs.k8s.io/json"
)

// Closed CREATE probes, not caller-configurable workloads. The caller must
// separately pin the original signed policy/binding and ServiceAccount UIDs
// before and after all probes. Neither accepted dry-run metadata nor these
// fictitious target references confer live ownership or execution authority.
func admissionCreateProbe(plan *installrender.Plan, policyName, account, name string) (*unstructured.Unstructured, *unstructured.Unstructured, int, error) {
	nonce := strings.TrimPrefix(name, "arcadectl-probe-")
	if !plan.IsTrusted() || !addressPart(account) || !strings.HasPrefix(name, "arcadectl-probe-") || !nonceID.MatchString(nonce) {
		return nil, nil, 0, ErrInvalid
	}
	known := false
	for _, resource := range plan.Resources() {
		if resource.Object.GetKind() == "ValidatingAdmissionPolicy" && resource.Object.GetName() == policyName {
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

// Validate the complete accepted object, not just HTTP 201. Read-only generated
// metadata is bounded; desired spec/labels/annotations remain exact. Status has
// only the independently certified native initial shape. No returned fields
// are ever promoted to desired configuration or ownership evidence.
func validAdmissionProbeResult(expected, result *unstructured.Unstructured, start, end time.Time) bool {
	if expected == nil || result == nil || start.IsZero() || end.Before(start) || result.GetAPIVersion() != expected.GetAPIVersion() || result.GetKind() != expected.GetKind() {
		return false
	}
	for key := range result.Object {
		if key != "apiVersion" && key != "kind" && key != "metadata" && key != "spec" && key != "status" {
			return false
		}
	}
	if !reflect.DeepEqual(expected.Object["spec"], result.Object["spec"]) {
		return false
	}
	var meta metav1.ObjectMeta
	switch result.GetKind() {
	case "Pod":
		var pod corev1.Pod
		if decodeServing(result, &pod) != nil {
			return false
		}
		meta = pod.ObjectMeta
		if len(pod.Status.Conditions) != 1 {
			return false
		}
		condition := pod.Status.Conditions[0]
		if !condition.LastProbeTime.IsZero() || condition.LastTransitionTime.IsZero() || condition.LastTransitionTime.Time.Before(start.Truncate(time.Second)) || condition.LastTransitionTime.Time.After(end.Add(time.Second)) {
			return false
		}
		condition.LastTransitionTime = metav1.Time{}
		if !reflect.DeepEqual(condition, corev1.PodCondition{Type: corev1.PodScheduled, Status: corev1.ConditionFalse, Reason: "SchedulingGated", Message: "Scheduling is blocked due to non-empty scheduling gates"}) {
			return false
		}
		pod.Status.Conditions = nil
		if !reflect.DeepEqual(pod.Status, corev1.PodStatus{Phase: corev1.PodPending, QOSClass: corev1.PodQOSBestEffort}) {
			return false
		}
		if !reflect.DeepEqual(result.Object["status"], map[string]any{"phase": "Pending", "qosClass": "BestEffort", "conditions": []any{map[string]any{"type": "PodScheduled", "status": "False", "reason": "SchedulingGated", "message": "Scheduling is blocked due to non-empty scheduling gates", "lastProbeTime": nil, "lastTransitionTime": podConditionTime(result)}}}) {
			return false
		}
	case "PersistentVolumeClaim":
		var pvc corev1.PersistentVolumeClaim
		if decodeServing(result, &pvc) != nil || !reflect.DeepEqual(pvc.Status, corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimPending}) {
			return false
		}
		meta = pvc.ObjectMeta
		if !reflect.DeepEqual(result.Object["status"], map[string]any{"phase": "Pending"}) {
			return false
		}
	case "GameDestroy":
		var destroy arcadev1.GameDestroy
		if decodeServing(result, &destroy) != nil {
			return false
		}
		if _, present := result.Object["status"]; present || !reflect.DeepEqual(destroy.Status, arcadev1.GameDestroyStatus{}) {
			return false
		}
		meta = destroy.ObjectMeta
	default:
		return false
	}
	wantGeneration := int64(1)
	if result.GetKind() == "PersistentVolumeClaim" {
		wantGeneration = 0
	}
	if meta.Name != expected.GetName() || meta.Namespace != expected.GetNamespace() || !receiptUID.MatchString(string(meta.UID)) || !meta.CreationTimestamp.Time.Equal(meta.CreationTimestamp.Time.Truncate(time.Second)) || meta.CreationTimestamp.IsZero() || meta.CreationTimestamp.Time.Before(start.Truncate(time.Second)) || meta.CreationTimestamp.Time.After(end.Add(time.Second)) || meta.Generation != wantGeneration || meta.ResourceVersion != "" {
		return false
	}
	if !reflect.DeepEqual(meta.Labels, expected.GetLabels()) || !reflect.DeepEqual(meta.Annotations, expected.GetAnnotations()) || meta.GenerateName != "" || meta.SelfLink != "" || meta.DeletionTimestamp != nil || meta.DeletionGracePeriodSeconds != nil || len(meta.OwnerReferences) != 0 {
		return false
	}
	if result.GetKind() == "PersistentVolumeClaim" && !reflect.DeepEqual(meta.Finalizers, []string{"kubernetes.io/pvc-protection"}) || result.GetKind() != "PersistentVolumeClaim" && len(meta.Finalizers) != 0 {
		return false
	}
	if len(meta.ManagedFields) != 1 {
		return false
	}
	field := meta.ManagedFields[0]
	if field.Manager != "arcadectl-installer" || field.Operation != metav1.ManagedFieldsOperationUpdate || field.APIVersion != result.GetAPIVersion() || field.FieldsType != "FieldsV1" || field.FieldsV1 == nil || field.Time == nil || field.Time.IsZero() || field.Time.Time.Before(start.Truncate(time.Second)) || field.Time.Time.After(end.Add(time.Second)) || field.Subresource != "" {
		return false
	}
	fieldset := admissionProbeFieldset(expected)
	if fieldset == nil {
		return false
	}
	var actualFields map[string]any
	if strictErrors, err := strictjson.UnmarshalStrict(field.FieldsV1.Raw, &actualFields); err != nil || len(strictErrors) != 0 || !reflect.DeepEqual(actualFields, fieldset) {
		return false
	}
	// The exact raw metadata comparison additionally rejects null optionals
	// that Go's typed decoder would otherwise collapse to absent fields.
	wantMeta := map[string]any{"name": meta.Name, "namespace": meta.Namespace, "uid": string(meta.UID), "creationTimestamp": meta.CreationTimestamp.UTC().Format(time.RFC3339), "managedFields": []any{map[string]any{"manager": "arcadectl-installer", "operation": "Update", "apiVersion": result.GetAPIVersion(), "fieldsType": "FieldsV1", "fieldsV1": fieldset, "time": field.Time.UTC().Format(time.RFC3339)}}}
	if wantGeneration != 0 {
		wantMeta["generation"] = wantGeneration
	}
	if len(expected.GetLabels()) > 0 {
		wantMeta["labels"] = expected.Object["metadata"].(map[string]any)["labels"]
	}
	if len(expected.GetAnnotations()) > 0 {
		wantMeta["annotations"] = expected.Object["metadata"].(map[string]any)["annotations"]
	}
	if result.GetKind() == "PersistentVolumeClaim" {
		wantMeta["finalizers"] = []any{"kubernetes.io/pvc-protection"}
	}
	return reflect.DeepEqual(result.Object["metadata"], wantMeta)
}

func podConditionTime(result *unstructured.Unstructured) string {
	var pod corev1.Pod
	if decodeServing(result, &pod) != nil || len(pod.Status.Conditions) != 1 {
		return ""
	}
	return pod.Status.Conditions[0].LastTransitionTime.UTC().Format(time.RFC3339)
}

// Fixed schema-aware fieldsets certified on both profiles. Only the signed
// factory's expected object is an input: never infer ownership from a returned
// body, status, sidecar or webhook mutation. Even informational bookkeeping
// must have the native closed shape; it is still not ownership authority.
func admissionProbeFieldset(expected *unstructured.Unstructured) map[string]any {
	f := func(keys ...string) map[string]any {
		m := map[string]any{}
		for _, key := range keys {
			if key == "." {
				m[key] = map[string]any{}
			} else {
				m["f:"+key] = map[string]any{}
			}
		}
		return m
	}
	result := map[string]any{}
	if len(expected.GetLabels()) > 0 {
		labels := f(".")
		for key := range expected.GetLabels() {
			labels["f:"+key] = map[string]any{}
		}
		result["f:metadata"] = map[string]any{"f:labels": labels}
	}
	switch expected.GetKind() {
	case "Pod":
		spec := f("automountServiceAccountToken", "dnsPolicy", "enableServiceLinks", "preemptionPolicy", "priority", "restartPolicy", "schedulerName", "serviceAccount", "serviceAccountName", "terminationGracePeriodSeconds", "tolerations")
		container := f(".", "command", "image", "imagePullPolicy", "name", "resources", "terminationMessagePath", "terminationMessagePolicy")
		security := f(".", "allowPrivilegeEscalation", "readOnlyRootFilesystem")
		security["f:capabilities"] = f(".", "drop")
		container["f:securityContext"] = security
		spec["f:containers"] = map[string]any{`k:{"name":"probe"}`: container}
		gates, found, err := unstructured.NestedSlice(expected.Object, "spec", "schedulingGates")
		if err != nil || !found || len(gates) != 1 {
			return nil
		}
		gate, err := json.Marshal(gates[0])
		if err != nil {
			return nil
		}
		spec["f:schedulingGates"] = map[string]any{".": map[string]any{}, "k:" + string(gate): f(".", "name")}
		podSecurity := f(".", "runAsGroup", "runAsNonRoot", "runAsUser")
		podSecurity["f:seccompProfile"] = f(".", "type")
		spec["f:securityContext"] = podSecurity
		result["f:spec"] = spec
	case "PersistentVolumeClaim":
		spec := f("accessModes", "storageClassName", "volumeMode")
		spec["f:resources"] = map[string]any{"f:requests": f(".", "storage")}
		result["f:spec"] = spec
	case "GameDestroy":
		spec := f(".", "cancelRequested", "mode")
		mode, found, err := unstructured.NestedString(expected.Object, "spec", "mode")
		if err != nil || !found {
			return nil
		}
		switch mode {
		case "VerifiedBackup":
			if len(expected.GetAnnotations()) != 0 {
				return nil
			}
			spec["f:backupRef"] = f(".", "name", "uid")
			spec["f:repositorySecretRef"] = f(".", "name", "resourceVersion", "uid")
		case "UnsafeNoBackup":
			const audit = "arcade.gobha.me/unsafe-requested-by"
			annotations := expected.GetAnnotations()
			if len(annotations) != 1 || annotations[audit] != "system:serviceaccount:"+expected.GetNamespace()+":arcadectl-destroy-admin" {
				return nil
			}
			if _, present, _ := unstructured.NestedFieldNoCopy(expected.Object, "spec", "backupRef"); present {
				return nil
			}
			if _, present, _ := unstructured.NestedFieldNoCopy(expected.Object, "spec", "repositorySecretRef"); present {
				return nil
			}
			spec["f:unsafeReason"] = f()
			meta, _ := result["f:metadata"].(map[string]any)
			if meta == nil {
				meta = map[string]any{}
				result["f:metadata"] = meta
			}
			meta["f:annotations"] = f(".", audit)
		default:
			return nil
		}
		target := f(".", "game")
		target["f:gameServer"] = f(".", "name", "uid")
		data := f(".", "identity")
		claim := f(".", "path")
		claim["f:claimRef"] = f(".", "name", "uid")
		data["f:claims"] = map[string]any{".": map[string]any{}, `k:{"path":"data"}`: claim}
		target["f:data"] = data
		spec["f:target"] = target
		result["f:spec"] = spec
	default:
		return nil
	}
	return result
}
