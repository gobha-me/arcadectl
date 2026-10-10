// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"reflect"

	"github.com/gobha-me/arcadectl/internal/installobserve"
	"github.com/gobha-me/arcadectl/internal/installstate"
	appsv1 "k8s.io/api/apps/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
)

// Called under wireMu AFTER the complete fresh GC observation. This is not a
// Lease-RV exemption: each refreshed whole object must equal that observation's
// public metadata and be a monotonic renewal of the already accepted typed read.
// The whole LIST and metadata pages were paired before the collector's final
// discovery/journal barriers. Renewal between those adjacent reads refuses.
// No permission, immutable field, holder chain, cold tail or unrelated Lease is
// inferred or relaxed, and the durable/session floor is not changed here.
func (w *fixtureWire) refreshPhaseLeaders(ctx context.Context, o *installobserve.Observation, before fixturePhaseBaseline, gc *installobserve.GCObservation) (fixturePhaseBaseline, map[installstate.Key]*coordinationv1.Lease, error) {
	return w.refreshPhaseLeadersRead(ctx, o, before, gc, nil)
}

func (w *fixtureWire) refreshPhaseLeadersRead(ctx context.Context, o *installobserve.Observation, before fixturePhaseBaseline, gc *installobserve.GCObservation, reads *fixturePhaseRead) (fixturePhaseBaseline, map[installstate.Key]*coordinationv1.Lease, error) {
	refreshed := map[installstate.Key]*coordinationv1.Lease{}
	if ctx == nil || w == nil || w.actors == nil || w.actors.request.Snapshot == nil || w.actors.admission == nil || w.actors.admission.prerequisites == nil || o == nil || gc == nil || before.validate(w.actors.request.Snapshot.Anchor().Namespace) != nil {
		return fixturePhaseBaseline{}, nil, ErrFixtures
	}
	after := before
	after.Leaders = append([]fixturePhaseLeader{}, before.Leaders...)
	if len(before.Leaders) == 0 {
		return after, refreshed, nil
	}
	if w.gcReadCurrent(ctx, reads) != nil {
		return fixturePhaseBaseline{}, nil, ErrFixtures
	}
	leases, readAt := gc.PairedLeases()
	if leases == nil || readAt.IsZero() {
		return fixturePhaseBaseline{}, nil, ErrFixtures
	}
	for index, original := range before.Leaders {
		key := original.Row.Key // closed validated sealed original leader names
		var lease *coordinationv1.Lease
		for i := range leases.Items {
			candidate := &leases.Items[i]
			if candidate.Name == key.Name && candidate.Namespace == key.Namespace {
				if lease != nil {
					return fixturePhaseBaseline{}, nil, ErrFixtures
				}
				lease = candidate
			}
		}
		if lease == nil || lease.APIVersion != key.APIVersion || lease.Kind != key.Kind || lease.UID != original.Row.UID {
			return fixturePhaseBaseline{}, nil, ErrFixtures
		}
		matches := 0
		for _, row := range gc.Objects() {
			if row.Metadata.UID == original.Row.UID || row.Source.GVR.GroupResource() == (schema.GroupResource{Group: "coordination.k8s.io", Resource: "leases"}) && row.Metadata.Namespace == key.Namespace && row.Metadata.Name == key.Name {
				if row.Source.Kind != "Lease" || row.Source.GVR.GroupResource() != (schema.GroupResource{Group: "coordination.k8s.io", Resource: "leases"}) || !reflect.DeepEqual(row.Metadata, fixtureGCMetadata(lease)) {
					return fixturePhaseBaseline{}, nil, ErrFixtures
				}
				matches++
			}
		}
		state, err := phaseLeaderState(o, original)
		if matches != 1 || err != nil {
			return fixturePhaseBaseline{}, nil, ErrFixtures
		}
		leader, err := capturePhaseLeader(key.Namespace, lease, state, readAt)
		if err != nil {
			return fixturePhaseBaseline{}, nil, ErrFixtures
		}
		after.Leaders[index], refreshed[key] = leader, lease
	}
	if after.validate(w.actors.request.Snapshot.Anchor().Namespace) != nil || !samePhaseBaseline(before, after) || w.gcReadCurrent(ctx, reads) != nil {
		return fixturePhaseBaseline{}, nil, ErrFixtures
	}
	return after, refreshed, nil
}

// Reconstruct ONLY the original sealed UID chain from the same complete typed
// observation. No pre-fixture classifier is applied to post-fixture objects.
func phaseLeaderState(o *installobserve.Observation, original fixturePhaseLeader) (admissionControllerState, error) {
	zero := admissionControllerState{}
	if o == nil || o.Snapshot() == nil || o.Runtime() == nil {
		return zero, ErrFixtures
	}
	byUID := map[types.UID]runtime.Object{}
	for _, collection := range phaseCollections(o) {
		items, err := meta.ExtractList(collection.list)
		if err != nil {
			return zero, ErrFixtures
		}
		for _, object := range items {
			m, err := meta.Accessor(object)
			if err != nil || byUID[m.GetUID()] != nil {
				return zero, ErrFixtures
			}
			byUID[m.GetUID()] = object
		}
	}
	parent, parentOK := byUID[original.ParentUID].(*appsv1.Deployment)
	set, setOK := byUID[original.SetUID].(*appsv1.ReplicaSet)
	pod, podOK := byUID[original.PodUID].(*corev1.Pod)
	if !parentOK || !setOK || !podOK || len(set.OwnerReferences) != 1 || set.OwnerReferences[0].UID != parent.UID {
		return zero, ErrFixtures
	}
	return admissionControllerState{Name: parent.Name, Executing: true, Deployment: parent, Sets: []*appsv1.ReplicaSet{set}, Pods: []*corev1.Pod{pod}}, nil
}
