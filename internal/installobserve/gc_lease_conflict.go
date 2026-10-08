// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installobserve

import (
	"context"
	"time"

	"github.com/gobha-me/arcadectl/internal/installstate"
	coordinationv1 "k8s.io/api/coordination/v1"
	"k8s.io/apimachinery/pkg/types"
)

// GCReadBudget bounds the total collection bytes and attempts across a single
// read-only renewal acquisition. It never authorizes a read or increases the
// original collection byte budget. Discovery retains its own original limits.
type GCReadBudget struct {
	remaining int
	attempts  uint8
}

func NewGCReadBudget() *GCReadBudget { return &GCReadBudget{remaining: 32 * 1024 * 1024} }

// LeaseRVConflict is an UNSEALED refusal, not a GCObservation or permission to
// retry. All collections and final discovery/journal checks completed, but one
// or more whole Leases had forward RV-only metadata differences. The engine
// must prove original leader identity, whole immutable shape, monotonic renewal,
// complete inventory/owner closure and actor/world/WAL guards independently.
// There is deliberately no conversion or promotion to successful evidence.
type LeaseRVConflict struct {
	journal *installstate.Snapshot
	objects []GCObject
	leases  *coordinationv1.LeaseList
	readAt  time.Time
}

func (c *LeaseRVConflict) Journal() *installstate.Snapshot {
	if c == nil {
		return nil
	}
	return c.journal
}

func (c *LeaseRVConflict) Objects() []GCObject {
	if c == nil {
		return nil
	}
	rows := make([]GCObject, len(c.objects))
	for i, row := range c.objects {
		rows[i] = GCObject{Source: row.Source, Metadata: *row.Metadata.DeepCopy()}
	}
	return rows
}

func (c *LeaseRVConflict) WholeLeases() (*coordinationv1.LeaseList, time.Time) {
	if c == nil || c.leases == nil {
		return nil, time.Time{}
	}
	return c.leases.DeepCopy(), c.readAt
}

func (c *LeaseRVConflict) Descendants(roots []types.UID) ([]GCObject, error) {
	if c == nil {
		return nil, ErrInvalid
	}
	return gcDescendants(c.journal, c.objects, roots)
}

// CollectWithLeaseRefusal performs ONE complete attempt. It neither retries nor
// returns a successful observation on mismatch. The existing strict entry
// points remain unchanged. An exhausted/shared invalid budget fails closed.
func (g *GCReader) CollectWithLeaseRefusal(ctx context.Context, discovery *GCDiscovery, budget *GCReadBudget) (*GCObservation, *LeaseRVConflict, error) {
	if budget == nil || budget.remaining <= 0 || budget.remaining > 32*1024*1024 || budget.attempts >= 3 {
		return nil, nil, ErrRead
	}
	budget.attempts++
	var refusal *LeaseRVConflict
	observation, err := g.collect(ctx, discovery, true, &refusal, &budget.remaining)
	return observation, refusal, err
}
