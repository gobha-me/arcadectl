// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	"github.com/gobha-me/arcadectl/internal/installstate"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

type baselineFailureCheck uint8

const (
	baselineFailureExecutables baselineFailureCheck = iota + 1
	baselineFailureDenialBefore
	baselineFailureDenialProbe
	baselineFailureDenialAfter
)

func (c baselineFailureCheck) label() string {
	switch c {
	case baselineFailureExecutables:
		return "executables-stable"
	case baselineFailureDenialBefore:
		return "denial-read-before"
	case baselineFailureDenialProbe:
		return "denial-probe"
	case baselineFailureDenialAfter:
		return "denial-read-after"
	}
	return "unknown"
}

type baselineDifference uint8

const (
	baselineDifferenceMembership baselineDifference = 1 << iota
	baselineDifferenceIdentity
	baselineDifferenceRV
	baselineDifferenceMetadata
	baselineDifferenceSpec
	baselineDifferenceStatus
	baselineDifferenceOther
)

// Compare only after the existing whole equality has refused. These categories
// describe observed differences, not benign exceptions or root causes. No
// object, key, resource version, field value or error is retained in the trace.
func baselineObjectDifference(before, after *unstructured.Unstructured) baselineDifference {
	if before == nil || after == nil {
		if before != after {
			return baselineDifferenceMembership
		}
		return 0
	}
	var fields baselineDifference
	if before.GetAPIVersion() != after.GetAPIVersion() || before.GetKind() != after.GetKind() || before.GetNamespace() != after.GetNamespace() || before.GetName() != after.GetName() || before.GetUID() != after.GetUID() {
		fields |= baselineDifferenceIdentity
	}
	if before.GetResourceVersion() != after.GetResourceVersion() {
		fields |= baselineDifferenceRV
	}
	for _, row := range []struct {
		key string
		bit baselineDifference
	}{{"metadata", baselineDifferenceMetadata}, {"spec", baselineDifferenceSpec}, {"status", baselineDifferenceStatus}} {
		a, hasA := before.Object[row.key]
		b, hasB := after.Object[row.key]
		if hasA != hasB || !reflect.DeepEqual(a, b) {
			fields |= row.bit
		}
	}
	for _, objects := range [][2]*unstructured.Unstructured{{before, after}, {after, before}} {
		for key, value := range objects[0].Object {
			if key == "metadata" || key == "spec" || key == "status" {
				continue
			}
			other, exists := objects[1].Object[key]
			if !exists || !reflect.DeepEqual(value, other) {
				fields |= baselineDifferenceOther
			}
		}
	}
	return fields
}

// Native families are closed labels. Unknown kinds cannot become output text.
var baselineDiagnosticFamilies = [...]string{"Pod", "Job", "Deployment", "ReplicaSet", "StatefulSet", "DaemonSet", "ReplicationController", "CronJob", "ServiceAccount", "Secret", "Service"}

func traceBaselineFailure(ctx context.Context, check baselineFailureCheck, kind string, fields baselineDifference) {
	storeBaselineFailure(ctx, check, kind, fields, 0)
}

func storeBaselineFailure(ctx context.Context, check baselineFailureCheck, kind string, fields baselineDifference, detail uint32) {
	if ctx == nil || check.label() == "unknown" {
		return
	}
	d, ok := ctx.Value(lifecycleDiagnosticKey{}).(*LifecycleDiagnostic)
	if !ok || d == nil {
		return
	}
	family := uint32(0)
	for i, label := range baselineDiagnosticFamilies {
		if kind == label {
			family = uint32(i + 1)
			break
		}
	}
	// One scalar prevents mixed check/family/field records. This is not proof.
	d.baselineFailure.Store(uint32(check) | family<<8 | uint32(fields)<<16 | detail)
}

func traceBaselineExecutableDifference(ctx context.Context, before, after *baselineExecutables) {
	if before != nil && after != nil {
		// Fixed family order and aggregate all differences in the first changed
		// family; map iteration order never chooses an arbitrary object's label.
		for _, family := range baselineDiagnosticFamilies[:8] {
			var fields baselineDifference
			for _, pair := range [][2]map[installstate.Key]*unstructured.Unstructured{{before.whole, after.whole}, {before.guarded, after.guarded}} {
				for key, object := range pair[0] {
					if key.Kind == family {
						fields |= baselineObjectDifference(object, pair[1][key])
					}
				}
				for key, object := range pair[1] {
					if key.Kind == family {
						fields |= baselineObjectDifference(pair[0][key], object)
					}
				}
			}
			if fields != 0 {
				traceBaselineFailure(ctx, baselineFailureExecutables, family, fields)
				return
			}
		}
	}
	traceBaselineFailure(ctx, baselineFailureExecutables, "", 0)
}

// FailureSnapshot emits only closed observed-refusal labels. It cannot print
// provider text or serve as authority for retries, exemptions or mutations.
// Read after the SAME Step returns; empty means no classified failure was seen.
func (d *LifecycleDiagnostic) FailureSnapshot() string {
	if d == nil {
		return ""
	}
	packed := d.baselineFailure.Load()
	if packed == 0 {
		return ""
	}
	check := baselineFailureCheck(packed & 255).label()
	family := "unknown"
	if index := (packed >> 8) & 255; index > 0 && index <= uint32(len(baselineDiagnosticFamilies)) {
		family = baselineDiagnosticFamilies[index-1]
	}
	fields := []string{}
	for i, label := range []string{"membership", "identity", "resource-version", "metadata", "spec", "status", "other"} {
		if packed&(1<<uint(16+i)) != 0 {
			fields = append(fields, label)
		}
	}
	changes := "unknown"
	if len(fields) != 0 {
		changes = strings.Join(fields, ",")
	}
	return fmt.Sprintf("check=%s family=%s changes=%s", check, family, changes)
}
