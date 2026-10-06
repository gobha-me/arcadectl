// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"

	"github.com/gobha-me/arcadectl/internal/installobserve"
	"github.com/gobha-me/arcadectl/internal/installsafety"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

// observe binds the sealed safety read to the very same original journal,
// cluster and frozen static identity used for effects. A complete observation
// is not coldness, detached storage, runtime absence or admission behavior.
// Those obligations must be checked separately by the closed checkpoint.
func (p *ClusterPrerequisites) observe(ctx context.Context, request LifecycleCheck) (*installobserve.Observation, error) {
	if p == nil || p.engine == nil || p.access == nil || p.engine.access != p.access || p.access.frozen == nil || ctx == nil || request.Snapshot == nil {
		return nil, ErrInvalid
	}
	if _, err := p.permissions(request); err != nil || p.original(ctx, request.Snapshot) != nil {
		return nil, ErrPrerequisites
	}
	observer, err := installobserve.New(p.access.readConfig(), p.engine.journal, request.Target)
	if err != nil {
		return nil, ErrPrerequisites
	}
	observation, err := observer.Collect(ctx, request.Snapshot.Anchor())
	if err != nil || observation == nil || observation.Journal() == nil {
		return nil, ErrPrerequisites
	}
	journal := observation.Journal()
	if journal.Anchor() != request.Snapshot.Anchor() || journal.ResourceVersion() != request.Snapshot.ResourceVersion() || !bytes.Equal(journal.Bytes(), request.Snapshot.Bytes()) || p.original(ctx, request.Snapshot) != nil {
		return nil, ErrPrerequisites
	}
	return observation, nil
}

// closeDescendantUIDs is order-independent and linear in the sealed, bounded
// observation's ownership edges. Every reference counts, including malformed
// controller flags/kinds: classification is conservative; authorization still
// requires the exact original owner chain at the checkpoint. Unknown metadata
// encountered through the observer's recursive graph participates too.
func closeDescendantUIDs(s *installsafety.Snapshot, r *installsafety.RuntimeSnapshot, selected map[types.UID]bool) error {
	children := map[types.UID][]types.UID{}
	add := func(m metav1.Object) {
		for _, owner := range m.GetOwnerReferences() {
			children[owner.UID] = append(children[owner.UID], m.GetUID())
		}
	}
	for _, list := range []runtime.Object{
		s.GameServers, s.Backups, s.Restores, s.Destroys, s.Operations,
		s.Jobs, s.Pods, s.Leases, s.Claims, s.Secrets, s.Policies, s.Bindings,
		r.Deployments, r.ReplicaSets, r.StatefulSets, r.DaemonSets,
		r.ReplicationControllers, r.CronJobs, r.Attachments, r.EndpointSlices,
	} {
		items, err := meta.ExtractList(list)
		if err != nil {
			return ErrInvalid
		}
		for _, item := range items {
			m, err := meta.Accessor(item)
			if err != nil {
				return ErrInvalid
			}
			add(m)
		}
	}
	for i := range s.Owners {
		add(&s.Owners[i].Metadata)
	}
	queue := make([]types.UID, 0, len(selected))
	for uid := range selected {
		queue = append(queue, uid)
	}
	for i := 0; i < len(queue); i++ {
		for _, uid := range children[queue[i]] {
			if !selected[uid] {
				selected[uid] = true
				queue = append(queue, uid)
			}
		}
	}
	return nil
}
