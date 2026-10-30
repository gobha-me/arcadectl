// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"fmt"
	"reflect"
	"strconv"
	"sync/atomic"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Only numeric labels survive the already-refused comparison. This recorder
// retains no object, identity, metadata, context, callback or provider error.
type typedMetadataDiagnostic struct {
	value  atomic.Uint32
	detail atomic.Uint32
}

var typedMetadataKinds = [...]string{
	"unknown", "GameServer", "GameBackup", "GameRestore", "GameDestroy",
	"ArcadeOperation", "Job", "Pod", "Lease", "PersistentVolumeClaim", "Secret",
	"ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding", "Deployment",
	"ReplicaSet", "StatefulSet", "DaemonSet", "ReplicationController", "CronJob",
	"EndpointSlice", "ServiceAccount",
}

var typedMetadataFields = [...]string{
	"unknown", "name", "namespace", "uid", "resource-version", "generation",
	"owner-references", "deletion-timestamp", "other",
}

// Use the same exact comparison semantics as the existing public metadata
// guard. The first differing field is diagnostic only: RV disagreement does
// not establish which read is newer or authorize ignoring or retrying it.
func typedMetadataMismatchField(observed, wanted metav1.ObjectMeta) uint32 {
	switch {
	case observed.Name != wanted.Name:
		return 1
	case observed.Namespace != wanted.Namespace:
		return 2
	case observed.UID != wanted.UID:
		return 3
	case observed.ResourceVersion != wanted.ResourceVersion:
		return 4
	case observed.Generation != wanted.Generation:
		return 5
	case !reflect.DeepEqual(observed.OwnerReferences, wanted.OwnerReferences):
		return 6
	case !reflect.DeepEqual(observed.DeletionTimestamp, wanted.DeletionTimestamp):
		return 7
	case !reflect.DeepEqual(observed, wanted):
		return 8
	default:
		return 0
	}
}

// Every correlation invocation installs a new recorder. A late completion
// writes only its own recorder and cannot republish it after a reset.
func beginTypedMetadataDiagnostic(ctx context.Context) func(string, metav1.ObjectMeta, metav1.ObjectMeta) {
	record := beginTypedMetadataScopedDiagnostic(ctx)
	return func(kind string, observed, wanted metav1.ObjectMeta) { record(kind, observed, wanted, -2) }
}

// scope is -1 for a nonfixture row, or the fixed original fixture slot. -2
// leaves the optional detail absent. No object, ledger or address is retained.
func beginTypedMetadataScopedDiagnostic(ctx context.Context) func(string, metav1.ObjectMeta, metav1.ObjectMeta, int) {
	if ctx != nil {
		if trace, ok := ctx.Value(admissionTraceKey{}).(*admissionTrace); ok && trace != nil {
			recorder := &typedMetadataDiagnostic{}
			trace.typedMetadata.Store(recorder)
			return func(kind string, observed, wanted metav1.ObjectMeta, scope int) {
				field := typedMetadataMismatchField(observed, wanted)
				if field == 0 {
					return
				}
				var kindID uint32
				for id, label := range typedMetadataKinds {
					if kind == label {
						kindID = uint32(id)
						break
					}
				}
				recorder.detail.Store(0)
				recorder.value.Store(kindID<<8 | field)
				if scope >= -1 && scope < fixtureMaxSlots {
					order := uint32(0)
					gcRV, gcErr := strconv.ParseUint(observed.ResourceVersion, 10, 64)
					typedRV, typedErr := strconv.ParseUint(wanted.ResourceVersion, 10, 64)
					if gcErr == nil && typedErr == nil && fixtureRV(observed.ResourceVersion) && fixtureRV(wanted.ResourceVersion) {
						switch {
						case gcRV < typedRV:
							order = 1
						case gcRV == typedRV:
							order = 2
						default:
							order = 3
						}
					}
					metadata := uint32(2)
					copy := observed
					copy.ResourceVersion = wanted.ResourceVersion
					if reflect.DeepEqual(copy, wanted) {
						metadata = 1
					}
					recorder.detail.Store(uint32(scope+2) | order<<8 | metadata<<16)
				}
			}
		}
	}
	return func(string, metav1.ObjectMeta, metav1.ObjectMeta, int) {}
}

func (trace *admissionTrace) typedMetadataDetailSnapshot() string {
	if trace == nil || trace.typedMetadataSnapshot() == "" {
		return ""
	}
	recorder := trace.typedMetadata.Load()
	if recorder == nil {
		return ""
	}
	value := recorder.detail.Load()
	scope, order, metadata := value&255, value>>8&255, value>>16
	if scope < 1 || scope > fixtureMaxSlots+1 || order > 3 || metadata < 1 || metadata > 2 {
		return ""
	}
	label, slot := "nonfixture", -1
	if scope > 1 {
		label, slot = "fixture", int(scope)-2
	}
	return fmt.Sprintf("scope=%s slot=%d gc-rv-order=%s metadata=%s", label, slot,
		[...]string{"unknown", "less", "equal", "greater"}[order], [...]string{"", "rv-only", "beyond-rv"}[metadata])
}

// TypedMetadataDetailSnapshot classifies an already-refused comparison. RV
// ordering is a numeric comparison, not chronology, harmlessness or authority.
func (d *LifecycleDiagnostic) TypedMetadataDetailSnapshot() string {
	if d == nil {
		return ""
	}
	return d.admission.typedMetadataDetailSnapshot()
}

func (trace *admissionTrace) typedMetadataSnapshot() string {
	if trace == nil {
		return ""
	}
	recorder := trace.typedMetadata.Load()
	if recorder == nil {
		return ""
	}
	value := recorder.value.Load()
	kind, field := value>>8, value&255
	if kind >= uint32(len(typedMetadataKinds)) || field == 0 || field >= uint32(len(typedMetadataFields)) {
		return ""
	}
	return fmt.Sprintf("kind=%s field=%s", typedMetadataKinds[kind], typedMetadataFields[field])
}

// TypedMetadataSnapshot is optional same-attempt refused-comparison progress,
// not an underlying cause, successful observation, authority or retry route.
// Existing Snapshot remains unchanged and bounded separately.
func (d *LifecycleDiagnostic) TypedMetadataSnapshot() string {
	if d == nil {
		return ""
	}
	return d.admission.typedMetadataSnapshot()
}
