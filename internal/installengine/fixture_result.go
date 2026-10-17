// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"reflect"
	"time"

	arcadev1 "github.com/gobha-me/arcadectl/api/v1alpha1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

type fixtureResultPhase uint8

const (
	fixtureDryRunResult fixtureResultPhase = iota + 1
	fixtureAcknowledgedResult
	fixtureStableResult
)

// Pure whole-shape validation, NOT freshness, permission or cleanup authority.
// The provider must independently bind an uncached original wire observation to
// current journal/policy/cold/descendant witnesses. A canonical RV is not a fresh
// read; manager strings are bookkeeping, not authenticated software identities.
// Dry-run UIDs never become ownership. Persistent UIDs must already be durable
// original ACKs; pending effects cannot be repaired here. GameDestroy's absent
// status is deliberately restricted to the application-controller-cold proof.
func (f *fixtureLedger) validateResult(slot int, phase fixtureResultPhase, result *unstructured.Unstructured, observedAt time.Time) error {
	if observedAt.IsZero() || observedAt.Year() < 1 || observedAt.Year() > 9999 || result == nil || phase < fixtureDryRunResult || phase > fixtureStableResult {
		return ErrFixtures
	}
	want, err := f.object(slot)
	if err != nil {
		return ErrFixtures
	}
	entry := f.document.Entries[slot]
	if phase == fixtureDryRunResult {
		if entry.State != fixturePlanned || entry.OriginalUID != "" || result.GetResourceVersion() != "" {
			return ErrFixtures
		}
	} else if entry.State != fixtureOriginal || !nativeFixtureUID(string(entry.OriginalUID)) || result.GetUID() != entry.OriginalUID || !fixtureRV(result.GetResourceVersion()) {
		return ErrFixtures
	}
	if !nativeFixtureUID(string(result.GetUID())) || result.GetAPIVersion() != want.GetAPIVersion() || result.GetKind() != want.GetKind() || !reflect.DeepEqual(result.Object["spec"], want.Object["spec"]) {
		return ErrFixtures
	}
	for key := range result.Object {
		if want.GetKind() == "ServiceAccount" {
			if key != "apiVersion" && key != "kind" && key != "metadata" && key != "automountServiceAccountToken" {
				return ErrFixtures
			}
			continue
		}
		if key != "apiVersion" && key != "kind" && key != "metadata" && key != "spec" && key != "status" {
			return ErrFixtures
		}
	}
	var meta metav1.ObjectMeta
	switch result.GetKind() {
	case "ServiceAccount":
		value, ok := result.Object["automountServiceAccountToken"].(bool)
		var typed corev1.ServiceAccount
		if !ok || value || decodeServing(result, &typed) != nil || typed.AutomountServiceAccountToken == nil || *typed.AutomountServiceAccountToken {
			return ErrFixtures
		}
		meta = typed.ObjectMeta
	case "Pod":
		var typed corev1.Pod
		if decodeServing(result, &typed) != nil {
			return ErrFixtures
		}
		meta = typed.ObjectMeta
	case "Job":
		var typed batchv1.Job
		if decodeServing(result, &typed) != nil {
			return ErrFixtures
		}
		meta = typed.ObjectMeta
	case "PersistentVolumeClaim":
		var typed corev1.PersistentVolumeClaim
		if decodeServing(result, &typed) != nil {
			return ErrFixtures
		}
		meta = typed.ObjectMeta
	case "GameDestroy":
		var typed arcadev1.GameDestroy
		if decodeServing(result, &typed) != nil {
			return ErrFixtures
		}
		meta = typed.ObjectMeta
	default:
		return ErrFixtures
	}
	ceiling := observedAt.UTC().Add(time.Second)
	creation := meta.CreationTimestamp.Time
	if creation.IsZero() || creation.Year() < 1 || creation.Year() > 9999 || creation.After(ceiling) {
		return ErrFixtures
	}
	status, err := fixtureResultStatus(result, phase, creation, ceiling)
	if err != nil {
		return ErrFixtures
	}
	if result.GetKind() == "GameDestroy" || result.GetKind() == "ServiceAccount" {
		if _, present := result.Object["status"]; present {
			return ErrFixtures
		}
	} else if !reflect.DeepEqual(result.Object["status"], status) {
		return ErrFixtures
	}
	fieldset := fixtureResultFieldset(want)
	if fieldset == nil {
		return ErrFixtures
	}
	count := 1
	if phase == fixtureStableResult && (want.GetKind() == "Job" || want.GetKind() == "PersistentVolumeClaim") {
		count = 2
	}
	if len(meta.ManagedFields) != count {
		return ErrFixtures
	}
	fields := make([]any, count)
	for index, field := range meta.ManagedFields {
		// Field management precedes REST creation stamping. The independently
		// sampled native timestamps need not share an ordering across seconds.
		if field.Time == nil || field.Time.IsZero() || field.Time.Year() < 1 || field.Time.Year() > 9999 || field.Time.Time.After(ceiling) {
			return ErrFixtures
		}
		manager, subresource := "arcadectl-installer", ""
		owned := fieldset
		if index == 1 {
			manager, subresource = "kube-controller-manager", "status"
			owned = map[string]any{"f:status": fixtureFieldLeaves("phase")}
			if want.GetKind() == "Job" {
				owned = map[string]any{"f:status": fixtureFieldLeaves("conditions", "ready", "terminating", "uncountedTerminatedPods")}
			}
		}
		value := map[string]any{"manager": manager, "operation": "Update", "apiVersion": want.GetAPIVersion(), "fieldsType": "FieldsV1", "fieldsV1": owned, "time": field.Time.UTC().Format(time.RFC3339)}
		if subresource != "" {
			value["subresource"] = subresource
		}
		fields[index] = value
	}
	metadata := map[string]any{"name": want.GetName(), "namespace": want.GetNamespace(), "uid": string(result.GetUID()), "creationTimestamp": creation.UTC().Format(time.RFC3339), "managedFields": fields}
	if phase != fixtureDryRunResult {
		metadata["resourceVersion"] = result.GetResourceVersion()
	}
	if want.GetKind() != "PersistentVolumeClaim" && want.GetKind() != "ServiceAccount" {
		metadata["generation"] = int64(1)
	} else if want.GetKind() == "PersistentVolumeClaim" {
		metadata["finalizers"] = []any{"kubernetes.io/pvc-protection"}
	}
	for _, key := range []string{"labels", "annotations", "ownerReferences"} {
		if value, present := want.Object["metadata"].(map[string]any)[key]; present {
			metadata[key] = value
		}
	}
	// Exact raw equality rejects unknown fields AND explicit null/zero optional
	// metadata/status that typed Kubernetes decoding would collapse to absence.
	if !reflect.DeepEqual(result.Object["metadata"], metadata) {
		return ErrFixtures
	}
	return nil
}

func fixtureResultTime(raw any, earliest, latest time.Time) bool {
	value, ok := raw.(string)
	if !ok {
		return false
	}
	parsed, err := time.Parse(time.RFC3339, value)
	return err == nil && !parsed.IsZero() && parsed.Year() >= 1 && parsed.Year() <= 9999 && value == parsed.UTC().Format(time.RFC3339) && !parsed.Before(earliest) && !parsed.After(latest)
}

func fixtureResultStatus(o *unstructured.Unstructured, phase fixtureResultPhase, creation, ceiling time.Time) (map[string]any, error) {
	switch o.GetKind() {
	case "GameDestroy", "ServiceAccount":
		return nil, nil
	case "PersistentVolumeClaim":
		value := "Pending"
		if phase == fixtureStableResult {
			value = "Lost"
		}
		return map[string]any{"phase": value}, nil
	case "Job":
		if phase != fixtureStableResult {
			return map[string]any{}, nil
		}
		probe, _, _ := unstructured.NestedFieldNoCopy(o.Object, "status", "conditions")
		conditions, ok := probe.([]any)
		if !ok || len(conditions) != 1 {
			return nil, ErrFixtures
		}
		condition, ok := conditions[0].(map[string]any)
		if !ok || !fixtureResultTime(condition["lastProbeTime"], creation, ceiling) || !fixtureResultTime(condition["lastTransitionTime"], creation, ceiling) {
			return nil, ErrFixtures
		}
		return map[string]any{"conditions": []any{map[string]any{"type": "Suspended", "status": "True", "reason": "JobSuspended", "message": "Job suspended", "lastProbeTime": condition["lastProbeTime"], "lastTransitionTime": condition["lastTransitionTime"]}}, "ready": int64(0), "terminating": int64(0), "uncountedTerminatedPods": map[string]any{}}, nil
	case "Pod":
		probe, _, _ := unstructured.NestedFieldNoCopy(o.Object, "status", "conditions")
		conditions, ok := probe.([]any)
		if !ok || len(conditions) != 1 {
			return nil, ErrFixtures
		}
		condition, ok := conditions[0].(map[string]any)
		if !ok || !fixtureResultTime(condition["lastTransitionTime"], creation, ceiling) {
			return nil, ErrFixtures
		}
		return map[string]any{"phase": "Pending", "qosClass": "BestEffort", "conditions": []any{map[string]any{"type": "PodScheduled", "status": "False", "reason": "SchedulingGated", "message": "Scheduling is blocked due to non-empty scheduling gates", "lastProbeTime": nil, "lastTransitionTime": condition["lastTransitionTime"]}}}, nil
	}
	return nil, ErrFixtures
}

func fixtureFieldLeaves(keys ...string) map[string]any {
	fields := map[string]any{}
	for _, key := range keys {
		if key != "." {
			key = "f:" + key
		}
		fields[key] = map[string]any{}
	}
	return fields
}

// Schema-aware fieldsets come only from the closed desired constructor, never
// from returned managed fields or a caller's objects. Exact native profiles
// share these shapes; unrelated manager/spec/status authority is refused.
func fixtureResultFieldset(want *unstructured.Unstructured) map[string]any {
	if want == nil {
		return nil
	}
	var fields map[string]any
	if want.GetKind() == "ServiceAccount" {
		fields = fixtureFieldLeaves("automountServiceAccountToken")
	} else if want.GetKind() == "Job" {
		template, found, err := unstructured.NestedMap(want.Object, "spec", "template")
		if err != nil || !found {
			return nil
		}
		pod := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": template["metadata"], "spec": template["spec"]}}
		podFields := admissionProbeFieldset(pod)
		if podFields == nil {
			return nil
		}
		spec := fixtureFieldLeaves("suspend", "parallelism", "completions", "backoffLimit", "manualSelector", "selector", "completionMode", "podReplacementPolicy")
		spec["f:template"] = podFields
		fields = map[string]any{"f:spec": spec}
	} else {
		fields = admissionProbeFieldset(want)
		if fields == nil {
			return nil
		}
	}
	meta, _ := fields["f:metadata"].(map[string]any)
	if meta == nil {
		meta = map[string]any{}
	}
	if labels := want.GetLabels(); len(labels) > 0 {
		values := fixtureFieldLeaves(".")
		for key := range labels {
			values["f:"+key] = map[string]any{}
		}
		meta["f:labels"] = values
	}
	if annotations := want.GetAnnotations(); len(annotations) > 0 {
		values := fixtureFieldLeaves(".")
		for key := range annotations {
			values["f:"+key] = map[string]any{}
		}
		meta["f:annotations"] = values
	}
	if owners := want.GetOwnerReferences(); len(owners) > 0 {
		if len(owners) != 1 || !nativeFixtureUID(string(owners[0].UID)) {
			return nil
		}
		meta["f:ownerReferences"] = map[string]any{".": map[string]any{}, `k:{"uid":"` + string(owners[0].UID) + `"}`: map[string]any{}}
	}
	if len(meta) > 0 {
		fields["f:metadata"] = meta
	}
	return fields
}
