// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestBaselineDeploymentDiagnosticClosedRawDetail(t *testing.T) {
	key := deploymentKey("PRIVATE-CANARY", "arcadectl-controller")
	original := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "apps/v1", "kind": "Deployment",
		"metadata": map[string]any{"namespace": key.Namespace, "name": key.Name, "resourceVersion": "1"},
		"status":   map[string]any{},
	}}
	rows := []struct{ field, key, want string }{
		{"metadata", "annotations", "annotations"}, {"metadata", "labels", "labels"}, {"metadata", "generation", "generation"},
		{"metadata", "ownerReferences", "lifecycle"}, {"metadata", "finalizers", "lifecycle"}, {"metadata", "deletionTimestamp", "lifecycle"},
		{"metadata", "deletionGracePeriodSeconds", "lifecycle"}, {"metadata", "creationTimestamp", "lifecycle"},
		{"metadata", "managedFields", "managed-fields"}, {"metadata", "PRIVATE-CANARY", "other"}, {"metadata", "", "other"},
		{"metadata", "resourceVersion", "resource-version-only"},
		{"status", "observedGeneration", "observed-generation"}, {"status", "replicas", "replicas"}, {"status", "updatedReplicas", "updated"},
		{"status", "readyReplicas", "ready"}, {"status", "availableReplicas", "available"}, {"status", "unavailableReplicas", "unavailable"},
		{"status", "terminatingReplicas", "terminating"}, {"status", "conditions", "conditions"}, {"status", "collisionCount", "collision"},
		{"status", "PRIVATE-CANARY", "other"}, {"status", "", "other"},
	}
	for _, row := range rows {
		t.Run(row.field+"/"+row.key, func(t *testing.T) {
			for _, value := range []any{nil, int64(0), "PRIVATE-CANARY"} {
				changed := original.DeepCopy()
				changed.Object[row.field].(map[string]any)[row.key] = value
				ctx, diagnostic := WithLifecycleDiagnostic(t.Context())
				traceBaselineObjectFailure(ctx, baselineFailureDenialBefore, key, original, changed)
				metadata, status := "none", "none"
				if row.field == "metadata" {
					metadata = row.want
				} else {
					status = row.want
				}
				want := "role=controller metadata-first=" + metadata + " status-first=" + status
				if got := diagnostic.DeploymentSnapshot(); got != want || strings.Contains(got, "PRIVATE") {
					t.Fatalf("fixed detail: %q want %q", got, want)
				}
				low := diagnostic.FailureSnapshot()
				traceBaselineFailure(ctx, baselineFailureDenialBefore, "Deployment", baselineObjectDifference(original, changed))
				if diagnostic.FailureSnapshot() != low || diagnostic.DeploymentSnapshot() != "" {
					t.Fatal("detail changed low record or generic refusal retained detail")
				}
			}
		})
	}
	ctx, diagnostic := WithLifecycleDiagnostic(t.Context())
	for _, field := range []string{"metadata", "status"} {
		for _, value := range []any{nil, "PRIVATE-CANARY", []any{"PRIVATE-CANARY"}} {
			changed := original.DeepCopy()
			changed.Object[field] = value
			traceBaselineObjectFailure(ctx, baselineFailureDenialAfter, key, original, changed)
			if got := diagnostic.DeploymentSnapshot(); !strings.Contains(got, field+"-first=other") || strings.Contains(got, "PRIVATE") {
				t.Fatal("malformed raw map escaped fixed detail", got)
			}
		}
	}
	changed := original.DeepCopy()
	changed.Object["metadata"].(map[string]any)["annotations"] = nil
	changed.Object["metadata"].(map[string]any)["labels"] = nil
	changed.SetResourceVersion("2")
	changed.Object["status"].(map[string]any)["replicas"] = int64(0)
	changed.Object["status"].(map[string]any)["observedGeneration"] = int64(0)
	for i := 0; i < 20; i++ {
		traceBaselineObjectFailure(ctx, baselineFailureDenialBefore, key, original, changed)
		if diagnostic.DeploymentSnapshot() != "role=controller metadata-first=annotations status-first=observed-generation" {
			t.Fatal("priority depended on map order")
		}
	}
	for _, reset := range []func(){func() { traceBaselineBoundary(ctx, baselineBoundaryScope) }, func() { traceOperationBoundary(ctx, boundaryRecoveryOpening) }, func() { traceLifecycleCheckpoint(ctx, AdmissionEffective, lifecycleDiagnosticEntered) }} {
		traceBaselineObjectFailure(ctx, baselineFailureDenialBefore, key, original, changed)
		reset()
		if diagnostic.DeploymentSnapshot() != "" {
			t.Fatal("next boundary retained detail")
		}
	}
	for name, role := range map[string]string{"arcadectl-controller": "controller", "arcadectl-api": "api", "arcadectl-destroy-controller": "destroy-controller", "PRIVATE-CANARY": "unknown"} {
		before, after := original.DeepCopy(), changed.DeepCopy()
		before.SetName(name)
		after.SetName(name)
		traceBaselineObjectFailure(ctx, baselineFailureDenialAfter, deploymentKey(key.Namespace, name), before, after)
		if !strings.HasPrefix(diagnostic.DeploymentSnapshot(), "role="+role+" ") {
			t.Fatal("role used raw output")
		}
	}
	foreign := changed.DeepCopy()
	foreign.SetName("PRIVATE-CANARY")
	traceBaselineObjectFailure(ctx, baselineFailureDenialBefore, key, original, foreign)
	if !strings.HasPrefix(diagnostic.DeploymentSnapshot(), "role=unknown ") {
		t.Fatal("role classified a mismatched identity")
	}
	for _, edit := range []func(*unstructured.Unstructured){func(o *unstructured.Unstructured) { o.SetNamespace("PRIVATE-CANARY-OTHER") }, func(o *unstructured.Unstructured) { o.SetAPIVersion("PRIVATE-CANARY") }, func(o *unstructured.Unstructured) { o.SetKind("PRIVATE-CANARY") }} {
		foreign := changed.DeepCopy()
		edit(foreign)
		traceBaselineObjectFailure(ctx, baselineFailureDenialBefore, key, original, foreign)
		if !strings.HasPrefix(diagnostic.DeploymentSnapshot(), "role=unknown ") {
			t.Fatal("role classified foreign scope/family")
		}
	}
	for _, field := range []string{"metadata", "status"} {
		before, after := original.DeepCopy(), original.DeepCopy()
		before.Object[field].(map[string]any)["PRIVATE-CANARY"] = nil
		after.Object[field].(map[string]any)["PRIVATE-CANARY"] = int64(0)
		for _, remove := range []bool{false, true} {
			if remove {
				delete(after.Object[field].(map[string]any), "PRIVATE-CANARY")
			}
			after.SetResourceVersion("2")
			traceBaselineObjectFailure(ctx, baselineFailureDenialBefore, key, before, after)
			if !strings.Contains(diagnostic.DeploymentSnapshot(), field+"-first=other") {
				t.Fatal("raw removal/null-to-zero lost substantive difference")
			}
		}
	}
	traceBaselineObjectFailure(ctx, baselineFailureExecutables, key, original, changed)
	if diagnostic.DeploymentSnapshot() != "" {
		t.Fatal("aggregate check acquired per-object output")
	}
	for status := uint32(11); status < 16; status++ {
		diagnostic.baselineFailure.Store(uint32(baselineFailureDenialBefore) | 3<<8 | 1<<23 | status<<28)
		if diagnostic.DeploymentSnapshot() != "" {
			t.Fatal("invalid packed status emitted detail")
		}
	}
	for _, packed := range []uint32{255 | 3<<8 | 1<<23, uint32(baselineFailureDenialBefore) | 255<<8 | 1<<23, uint32(baselineFailureDenialProbe) | 3<<8 | 1<<23} {
		diagnostic.baselineFailure.Store(packed)
		if diagnostic.DeploymentSnapshot() != "" {
			t.Fatal("invalid check/family emitted detail")
		}
	}
	var absent *LifecycleDiagnostic
	if absent.DeploymentSnapshot() != "" {
		t.Fatal("nil diagnostic fabricated detail")
	}
}
