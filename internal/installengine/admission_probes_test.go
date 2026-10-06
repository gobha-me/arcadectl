// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installrender"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func probeResultFixture(t *testing.T, expected *unstructured.Unstructured, now time.Time) *unstructured.Unstructured {
	t.Helper()
	result := expected.DeepCopy()
	result.SetUID("dryrun-generated-uid")
	result.SetCreationTimestamp(metav1.NewTime(now.Truncate(time.Second)))
	if result.GetKind() != "PersistentVolumeClaim" {
		result.SetGeneration(1)
	} else {
		result.SetFinalizers([]string{"kubernetes.io/pvc-protection"})
	}
	fields, err := json.Marshal(admissionProbeFieldset(expected))
	if err != nil {
		t.Fatal(err)
	}
	ts := metav1.NewTime(now.Truncate(time.Second))
	result.SetManagedFields([]metav1.ManagedFieldsEntry{{Manager: "arcadectl-installer", Operation: metav1.ManagedFieldsOperationUpdate, APIVersion: result.GetAPIVersion(), FieldsType: "FieldsV1", FieldsV1: &metav1.FieldsV1{Raw: fields}, Time: &ts}})
	switch result.GetKind() {
	case "Pod":
		result.Object["status"] = map[string]any{"phase": "Pending", "qosClass": "BestEffort", "conditions": []any{map[string]any{"type": "PodScheduled", "status": "False", "reason": "SchedulingGated", "message": "Scheduling is blocked due to non-empty scheduling gates", "lastProbeTime": nil, "lastTransitionTime": now.Truncate(time.Second).Format(time.RFC3339)}}}
	case "PersistentVolumeClaim":
		result.Object["status"] = map[string]any{"phase": "Pending"}
	}
	return result
}

func probePolicyName(t *testing.T, plan *installrender.Plan, stem string) string {
	t.Helper()
	for _, resource := range plan.Resources() {
		if resource.Object.GetKind() == "ValidatingAdmissionPolicy" && strings.HasPrefix(resource.Object.GetName(), stem) {
			return resource.Object.GetName()
		}
	}
	t.Fatal("signed policy missing")
	return ""
}

func TestAdmissionProbeAcceptedShapeRejectsMutationsAndMalformedMetadata(t *testing.T) {
	plan := fixturePlan(t)
	now := time.Now().UTC()
	name := "arcadectl-probe-0123456789abcdef0123456789abcdef"
	for _, stem := range []string{"arcadectl-backup-worker-gate", "arcadectl-restore-worker-gate", "arcadectl-destroy-worker-gate", "arcadectl-restore-candidate-pvc-create", "arcadectl-retained-world-pvc-delete", "arcadectl-destroy-unsafe-admin"} {
		positive, negative, index, err := admissionCreateProbe(plan, probePolicyName(t, plan, stem), "arcadectl-controller", name)
		if err != nil || negative == nil || index < 0 || index > 1 {
			t.Fatal("closed factory failed")
		}
		valid := probeResultFixture(t, positive, now)
		if !validAdmissionProbeResult(positive, valid, now, now.Add(time.Second)) {
			t.Fatalf("native-shape fixture rejected for %s", stem)
		}
		for _, test := range []struct {
			name   string
			change func(*unstructured.Unstructured)
		}{
			{"foreign-name", func(o *unstructured.Unstructured) { o.SetName("foreign") }},
			{"namespace", func(o *unstructured.Unstructured) { o.SetNamespace("foreign") }},
			{"owner", func(o *unstructured.Unstructured) {
				o.SetOwnerReferences([]metav1.OwnerReference{{APIVersion: "v1", Kind: "Secret", Name: "foreign", UID: "foreign"}})
			}},
			{"annotation", func(o *unstructured.Unstructured) { o.SetAnnotations(map[string]string{"PRIVATE-CANARY": "injected"}) }},
			{"annotation-null", func(o *unstructured.Unstructured) {
				_ = unstructured.SetNestedField(o.Object, nil, "metadata", "annotations")
			}},
			{"owner-null", func(o *unstructured.Unstructured) {
				_ = unstructured.SetNestedField(o.Object, nil, "metadata", "ownerReferences")
			}},
			{"status-null", func(o *unstructured.Unstructured) { o.Object["status"] = nil }},
			{"unknown", func(o *unstructured.Unstructured) { o.Object["unknown"] = "PRIVATE-CANARY" }},
			{"resourceversion", func(o *unstructured.Unstructured) { o.SetResourceVersion("persisted") }},
			{"resourceversion-null", func(o *unstructured.Unstructured) {
				_ = unstructured.SetNestedField(o.Object, nil, "metadata", "resourceVersion")
			}},
			{"time-past", func(o *unstructured.Unstructured) { o.SetCreationTimestamp(metav1.NewTime(now.Add(-time.Minute))) }},
			{"time-future", func(o *unstructured.Unstructured) { o.SetCreationTimestamp(metav1.NewTime(now.Add(time.Minute))) }},
			{"generation", func(o *unstructured.Unstructured) { o.SetGeneration(7) }},
			{"fieldset", func(o *unstructured.Unstructured) {
				fields := o.GetManagedFields()
				fields[0].FieldsV1 = &metav1.FieldsV1{Raw: []byte(`{}`)}
				o.SetManagedFields(fields)
			}},
			{"manager", func(o *unstructured.Unstructured) {
				fields := o.GetManagedFields()
				fields[0].Manager = "foreign"
				o.SetManagedFields(fields)
			}},
			{"managed-time", func(o *unstructured.Unstructured) {
				fields := o.GetManagedFields()
				fields[0].Time = nil
				o.SetManagedFields(fields)
			}},
			{"finalizer", func(o *unstructured.Unstructured) { o.SetFinalizers([]string{"foreign"}) }},
			{"spec-null", func(o *unstructured.Unstructured) { o.Object["spec"] = nil }},
		} {
			t.Run(stem+"/"+test.name, func(t *testing.T) {
				result := valid.DeepCopy()
				test.change(result)
				if validAdmissionProbeResult(positive, result, now, now.Add(time.Second)) {
					t.Fatal("altered accepted object became evidence")
				}
			})
		}
		if positive.GetKind() == "Pod" {
			for _, field := range []string{"volumes", "nodeName", "initContainers", "ephemeralContainers"} {
				result := valid.DeepCopy()
				_ = unstructured.SetNestedField(result.Object, "injected", "spec", field)
				if validAdmissionProbeResult(positive, result, now, now.Add(time.Second)) {
					t.Fatal("injected executable field accepted")
				}
			}
			result := valid.DeepCopy()
			containers, _, _ := unstructured.NestedSlice(result.Object, "spec", "containers")
			_ = unstructured.SetNestedSlice(result.Object, append(containers, containers[0]), "spec", "containers")
			if validAdmissionProbeResult(positive, result, now, now.Add(time.Second)) {
				t.Fatal("injected sidecar accepted")
			}
			result = valid.DeepCopy()
			_ = unstructured.SetNestedField(result.Object, nil, "status", "containerStatuses")
			if validAdmissionProbeResult(positive, result, now, now.Add(time.Second)) {
				t.Fatal("null unknown-to-native status accepted")
			}
		}
	}
	for _, bad := range []string{"arcadectl-probe-", "arcadectl-probe-ABCDEF0123456789abcdef0123456789ab", "foreign-0123456789abcdef0123456789abcdef"} {
		if _, _, _, err := admissionCreateProbe(plan, probePolicyName(t, plan, "arcadectl-backup-worker-gate"), "arcadectl-controller", bad); err != ErrInvalid {
			t.Fatal("noncanonical probe name accepted")
		}
	}
	if _, _, _, err := admissionCreateProbe(plan, "foreign-policy", "arcadectl-controller", name); err != ErrInvalid {
		t.Fatal("unsigned policy name accepted")
	}
}
