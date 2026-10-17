// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"fmt"
	"reflect"
	"sync/atomic"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Only numeric labels survive the already-refused comparison. This recorder
// retains no object, identity, metadata, context, callback or provider error.
type typedMetadataDiagnostic struct {
	value atomic.Uint32
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
	if ctx != nil {
		if trace, ok := ctx.Value(admissionTraceKey{}).(*admissionTrace); ok && trace != nil {
			recorder := &typedMetadataDiagnostic{}
			trace.typedMetadata.Store(recorder)
			return func(kind string, observed, wanted metav1.ObjectMeta) {
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
				recorder.value.Store(kindID<<8 | field)
			}
		}
	}
	return func(string, metav1.ObjectMeta, metav1.ObjectMeta) {}
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
