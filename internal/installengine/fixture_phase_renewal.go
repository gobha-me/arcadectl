// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"reflect"
	"strconv"

	"github.com/gobha-me/arcadectl/internal/installobserve"
	"github.com/gobha-me/arcadectl/internal/installstate"
	coordinationv1 "k8s.io/api/coordination/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Only this serialized GET/LIST-only phase can classify a complete refusal.
// No driver, setup, probe or effect is retried. A successful collection still
// requires exact metadata/whole agreement; a refusal cannot become evidence.
func (w *fixtureWire) phaseGCWithRenewals(ctx context.Context, o *installobserve.Observation, phase fixturePhaseBaseline, objects [fixtureMaxSlots]*unstructured.Unstructured, reads *fixturePhaseRead) (*installobserve.GCObservation, fixturePhaseBaseline, error) {
	return w.phaseGCWithAccountRenewals(ctx, o, phase, objects, reads, nil)
}

func (w *fixtureWire) phaseGCWithAccountRenewals(ctx context.Context, o *installobserve.Observation, phase fixturePhaseBaseline, objects [fixtureMaxSlots]*unstructured.Unstructured, reads *fixturePhaseRead, accounts *phaseServiceAccounts) (*installobserve.GCObservation, fixturePhaseBaseline, error) {
	if len(phase.Leaders) == 0 {
		gc, err := w.gcMetadataReadLocked(ctx, false, reads)
		return gc, phase, err
	}
	budget := installobserve.NewGCReadBudget()
	highWater := phase
	for attempt := 0; attempt < 3; attempt++ {
		if reads == nil || reads.current(ctx) != nil {
			return nil, phase, ErrFixtures
		}
		gc, refusal, err := w.gcMetadataAttempt(ctx, true, reads, budget)
		if err == nil {
			if reads.current(ctx) != nil {
				return nil, phase, ErrFixtures
			}
			return gc, highWater, nil
		}
		if refusal == nil {
			return nil, phase, ErrFixtures
		}
		next, err := w.classifyLeaseRVConflictAccounts(ctx, o, highWater, objects, refusal, reads, accounts)
		if err != nil || reads.current(ctx) != nil {
			return nil, phase, ErrFixtures
		}
		// Private invocation-local floor, NOT an accepted/durable phaseFloor.
		highWater = next
	}
	return nil, phase, ErrFixtures
}

// A projection used ONLY by pure refusal checks. Changing its Lease RVs cannot
// produce a successful GCObservation or bypass successful exact correlation.
type fixtureRenewalRows struct {
	*installobserve.LeaseRVConflict
	rows []installobserve.GCObject
}

func (r *fixtureRenewalRows) Objects() []installobserve.GCObject { return r.rows }

func (w *fixtureWire) classifyLeaseRVConflict(ctx context.Context, o *installobserve.Observation, before fixturePhaseBaseline, objects [fixtureMaxSlots]*unstructured.Unstructured, refusal *installobserve.LeaseRVConflict, reads *fixturePhaseRead) (fixturePhaseBaseline, error) {
	return w.classifyLeaseRVConflictAccounts(ctx, o, before, objects, refusal, reads, nil)
}

func (w *fixtureWire) classifyLeaseRVConflictAccounts(ctx context.Context, o *installobserve.Observation, before fixturePhaseBaseline, objects [fixtureMaxSlots]*unstructured.Unstructured, refusal *installobserve.LeaseRVConflict, reads *fixturePhaseRead, accounts *phaseServiceAccounts) (fixturePhaseBaseline, error) {
	zero := fixturePhaseBaseline{}
	if refusal == nil || o == nil || o.Snapshot() == nil || reads == nil || reads.local(ctx, w) != nil || before.validate(w.actors.request.Snapshot.Anchor().Namespace) != nil {
		return zero, ErrFixtures
	}
	leases, at := refusal.WholeLeases()
	if leases == nil || at.IsZero() || len(leases.Items) != len(o.Snapshot().Leases.Items) {
		return zero, ErrFixtures
	}
	after := before
	after.Leaders = append([]fixturePhaseLeader{}, before.Leaders...)
	refreshed := map[installstate.Key]*coordinationv1.Lease{}
	for index, original := range before.Leaders {
		var lease *coordinationv1.Lease
		for i := range leases.Items {
			candidate := &leases.Items[i]
			if candidate.Namespace == original.Row.Key.Namespace && candidate.Name == original.Row.Key.Name {
				if lease != nil {
					return zero, ErrFixtures
				}
				lease = candidate
			}
		}
		if lease == nil || lease.UID != original.Row.UID || lease.APIVersion != original.Row.Key.APIVersion || lease.Kind != original.Row.Key.Kind {
			return zero, ErrFixtures
		}
		state, err := phaseLeaderState(o, original)
		if err != nil {
			return zero, ErrFixtures
		}
		leader, err := capturePhaseLeader(original.Row.Key.Namespace, lease, state, at)
		if err != nil {
			return zero, ErrFixtures
		}
		after.Leaders[index], refreshed[original.Row.Key] = leader, lease
	}
	if !samePhaseBaseline(before, after) {
		return zero, ErrFixtures
	}
	// Unrelated/cold Leases remain exact WHOLE objects, not merely metadata.
	for _, lease := range leases.Items {
		key := installstate.Key{APIVersion: lease.APIVersion, Kind: lease.Kind, Namespace: lease.Namespace, Name: lease.Name}
		if refreshed[key] != nil {
			continue
		}
		found := false
		for _, original := range o.Snapshot().Leases.Items {
			if reflect.DeepEqual(lease, original) {
				found = true
				break
			}
		}
		if !found {
			return zero, ErrFixtures
		}
	}
	rows := refusal.Objects()
	for index, row := range rows {
		key := installstate.Key{APIVersion: row.Source.GVR.GroupVersion().String(), Kind: row.Source.Kind, Namespace: row.Metadata.Namespace, Name: row.Metadata.Name}
		lease := refreshed[key]
		if lease == nil {
			continue
		}
		m := fixtureGCMetadata(lease)
		oldRV, oldErr := strconv.ParseUint(row.Metadata.ResourceVersion, 10, 64)
		newRV, newErr := strconv.ParseUint(m.ResourceVersion, 10, 64)
		var floorRV uint64
		for _, original := range before.Leaders {
			if original.Row.Key == key {
				floorRV, _ = strconv.ParseUint(original.Row.ResourceVersion, 10, 64)
			}
		}
		m.ResourceVersion = row.Metadata.ResourceVersion
		if oldErr != nil || newErr != nil || oldRV < floorRV || newRV < oldRV || !reflect.DeepEqual(row.Metadata, m) {
			return zero, ErrFixtures
		}
		rows[index].Metadata.ResourceVersion = lease.ResourceVersion
	}
	if w.ledger.phaseGCRowsWithAccounts(o, objects, &fixtureRenewalRows{refusal, rows}, refreshed, accounts) != nil || reads.local(ctx, w) != nil {
		return zero, ErrFixtures
	}
	// Do not discard a signed Service/ConfigMap/RBAC change observed in a
	// refused attempt. Re-read their WHOLE original shapes and correlate the
	// candidate's raw namespace metadata before any fresh attempt is allowed.
	public, err := w.actors.admission.phasePublicInventoryAgainstGC(ctx, w.actors.request, refusal.Objects())
	if err != nil || !reflect.DeepEqual(before.Public, public) || reads.local(ctx, w) != nil {
		return zero, ErrFixtures
	}
	return after, nil
}
