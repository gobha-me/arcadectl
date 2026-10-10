// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"fmt"
	"reflect"

	"github.com/gobha-me/arcadectl/internal/installstate"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

var baselineMetadataLabels = [...]string{"none", "annotations", "labels", "generation", "lifecycle", "managed-fields", "other", "resource-version-only"}
var baselineStatusLabels = [...]string{"none", "observed-generation", "replicas", "updated", "ready", "available", "unavailable", "terminating", "conditions", "collision", "other"}

// Only called after whole-object equality refused. The extra nine bits share
// the SAME atomic record as the refusal; no object values or keys are retained.
func traceBaselineObjectFailure(ctx context.Context, check baselineFailureCheck, key installstate.Key, before, after *unstructured.Unstructured) {
	var detail uint32
	if key.APIVersion == "apps/v1" && key.Kind == "Deployment" && before != nil && after != nil {
		role := uint32(0)
		if baselineObjectKey(before) == key && baselineObjectKey(after) == key {
			switch key.Name {
			case "arcadectl-controller":
				role = 1
			case "arcadectl-api":
				role = 2
			case "arcadectl-destroy-controller":
				role = 3
			}
		}
		metadata := baselineFirstRawDifference(before.Object, after.Object, "metadata", [][]string{
			{"annotations"}, {"labels"}, {"generation"},
			{"ownerReferences", "finalizers", "deletionTimestamp", "deletionGracePeriodSeconds", "creationTimestamp"}, {"managedFields"},
		}, 6, "resourceVersion", 7)
		status := baselineFirstRawDifference(before.Object, after.Object, "status", [][]string{
			{"observedGeneration"}, {"replicas"}, {"updatedReplicas"}, {"readyReplicas"}, {"availableReplicas"},
			{"unavailableReplicas"}, {"terminatingReplicas"}, {"conditions"}, {"collisionCount"},
		}, 10, "", 0)
		detail = role<<23 | metadata<<25 | status<<28
	}
	storeBaselineFailure(ctx, check, key.Kind, baselineObjectDifference(before, after), detail)
}

// Raw presence is significant: absent, null and zero are never conflated.
// Unknown/malformed maps use a fixed label; priority never follows map order.
func baselineFirstRawDifference(before, after map[string]any, field string, groups [][]string, other uint32, last string, lastCode uint32) uint32 {
	a, hasA := before[field]
	b, hasB := after[field]
	if hasA == hasB && reflect.DeepEqual(a, b) {
		return 0
	}
	ma, okA := a.(map[string]any)
	mb, okB := b.(map[string]any)
	if !okA || !okB {
		return other
	}
	different := func(key string) bool {
		av, ap := ma[key]
		bv, bp := mb[key]
		return ap != bp || !reflect.DeepEqual(av, bv)
	}
	known := map[string]bool{}
	if last != "" {
		known[last] = true
	}
	for i, group := range groups {
		for _, key := range group {
			known[key] = true
			if different(key) {
				return uint32(i + 1)
			}
		}
	}
	for _, m := range []map[string]any{ma, mb} {
		for key := range m {
			if !known[key] && different(key) {
				return other
			}
		}
	}
	if last != "" && different(last) {
		return lastCode
	}
	return other
}

// DeploymentSnapshot supplements (never changes) FailureSnapshot. Aggregate
// executable refusals have no per-object detail, avoiding mixed-object records.
func (d *LifecycleDiagnostic) DeploymentSnapshot() string {
	if d == nil {
		return ""
	}
	packed := d.baselineFailure.Load()
	check := baselineFailureCheck(packed & 255)
	family := (packed >> 8) & 255
	metadata, status := (packed>>25)&7, (packed>>28)&15
	if packed>>23 == 0 || check != baselineFailureDenialBefore && check != baselineFailureDenialAfter || family != 3 || status >= uint32(len(baselineStatusLabels)) {
		return ""
	}
	role := [...]string{"unknown", "controller", "api", "destroy-controller"}[(packed>>23)&3]
	return fmt.Sprintf("role=%s metadata-first=%s status-first=%s", role, baselineMetadataLabels[metadata], baselineStatusLabels[status])
}
