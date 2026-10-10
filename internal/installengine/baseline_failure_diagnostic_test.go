// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"strings"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installstate"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestBaselineFailureDiagnosticClosedDifferencesAndReset(t *testing.T) {
	original := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "apps/v1", "kind": "Deployment",
		"metadata": map[string]any{"namespace": "PRIVATE-CANARY", "name": "PRIVATE-CANARY", "uid": "PRIVATE-CANARY", "resourceVersion": "1"},
		"spec":     map[string]any{"private": "PRIVATE-CANARY"},
	}}
	for _, row := range []struct {
		name string
		edit func(*unstructured.Unstructured)
		want string
	}{
		{"rv", func(o *unstructured.Unstructured) { o.SetResourceVersion("PRIVATE-CANARY") }, "resource-version,metadata"},
		{"status", func(o *unstructured.Unstructured) { o.Object["status"] = map[string]any{"private": "PRIVATE-CANARY"} }, "status"},
		{"spec", func(o *unstructured.Unstructured) { o.Object["spec"] = map[string]any{"different": "PRIVATE-CANARY"} }, "spec"},
		{"identity", func(o *unstructured.Unstructured) { o.SetUID("OTHER-PRIVATE-CANARY") }, "identity,metadata"},
		{"other", func(o *unstructured.Unstructured) { o.Object["PRIVATE-CANARY"] = "PRIVATE-CANARY" }, "other"},
		{"null", func(o *unstructured.Unstructured) { o.Object["status"] = nil }, "status"},
	} {
		t.Run(row.name, func(t *testing.T) {
			changed := original.DeepCopy()
			row.edit(changed)
			ctx, diagnostic := WithLifecycleDiagnostic(t.Context())
			traceBaselineFailure(ctx, baselineFailureDenialBefore, changed.GetKind(), baselineObjectDifference(original, changed))
			want := "check=denial-read-before family=Deployment changes=" + row.want
			if got := diagnostic.FailureSnapshot(); got != want || strings.Contains(got, "PRIVATE") {
				t.Fatalf("difference leaked values or lost fixed fields: %s", got)
			}
			if original.GetResourceVersion() != "1" || original.Object["status"] != nil {
				t.Fatal("diagnostic comparison mutated original")
			}
			traceBaselineBoundary(ctx, baselineBoundaryScope)
			if diagnostic.FailureSnapshot() != "" {
				t.Fatal("next provider retained prior refusal")
			}
		})
	}
	ctx, diagnostic := WithLifecycleDiagnostic(t.Context())
	key := installstate.Key{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "PRIVATE-CANARY", Name: "PRIVATE-CANARY"}
	before := &baselineExecutables{whole: map[installstate.Key]*unstructured.Unstructured{key: original}}
	after := &baselineExecutables{whole: map[installstate.Key]*unstructured.Unstructured{}}
	traceBaselineExecutableDifference(ctx, before, after)
	if diagnostic.FailureSnapshot() != "check=executables-stable family=Deployment changes=membership" {
		t.Fatal("membership diagnostic lost fixed original family")
	}
	// The first native family is fixed, while every changed member in that
	// family contributes its categories; neither map order nor names escape.
	for _, name := range []string{"PRIVATE-FIRST", "PRIVATE-SECOND"} {
		podKey := installstate.Key{APIVersion: "v1", Kind: "Pod", Namespace: key.Namespace, Name: name}
		pod := original.DeepCopy()
		pod.SetAPIVersion("v1")
		pod.SetKind("Pod")
		pod.SetName(name)
		before.whole[podKey], after.whole[podKey] = pod, pod.DeepCopy()
		if name == "PRIVATE-FIRST" {
			after.whole[podKey].Object["status"] = map[string]any{"PRIVATE": "PRIVATE"}
		} else {
			after.whole[podKey].Object["spec"] = map[string]any{"PRIVATE": "PRIVATE"}
		}
	}
	traceBaselineExecutableDifference(ctx, before, after)
	if diagnostic.FailureSnapshot() != "check=executables-stable family=Pod changes=spec,status" {
		t.Fatal("paired differences used map order or omitted a changed family member", diagnostic.FailureSnapshot())
	}
	traceOperationBoundary(ctx, boundaryRecoveryOpening)
	if diagnostic.FailureSnapshot() != "" {
		t.Fatal("next operation retained prior refusal")
	}
	traceBaselineFailure(ctx, baselineFailureDenialProbe, "PRIVATE-CANARY", 0)
	if diagnostic.FailureSnapshot() != "check=denial-probe family=unknown changes=unknown" {
		t.Fatal("unknown provider reply invented difference or printed a kind")
	}
	traceLifecycleCheckpoint(ctx, AdmissionEffective, lifecycleDiagnosticEntered)
	if diagnostic.FailureSnapshot() != "" {
		t.Fatal("next checkpoint retained prior refusal")
	}
	var absent *LifecycleDiagnostic
	if absent.FailureSnapshot() != "" {
		t.Fatal("nil diagnostic fabricated observed refusal")
	}
	diagnostic.baselineFailure.Store(^uint32(0))
	if got := diagnostic.FailureSnapshot(); !strings.HasPrefix(got, "check=unknown family=unknown changes=") || strings.Contains(got, "PRIVATE") {
		t.Fatal("invalid packed value escaped the closed label set")
	}
}
