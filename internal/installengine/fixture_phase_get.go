// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Only observePhaseLocked uses this GET-only helper while holding wireMu and
// bracketing the complete fixed scan with full remote witnesses. No flag,
// request enum, callback, send capability, WAL transition or public read proof
// is supplied. Each exact named GET still has live discovery and SSAR, private
// frozen original authentication, single native capture and local durable
// evidence at the same per-request boundaries as the ordinary GET route.
func (w *fixtureWire) getPhaseLocked(ctx context.Context, slot int) (*unstructured.Unstructured, bool, error) {
	if ctx == nil || !w.phaseReadable() || w.localCurrent() != nil || slot < 0 || slot >= len(w.ledger.document.Entries) || w.actors.admission == nil || w.actors.admission.prerequisites == nil || w.actors.admission.prerequisites.access == nil {
		return nil, false, ErrFixtures
	}
	key := w.ledger.document.Entries[slot].Key
	permission, err := fixturePermission(key, "get")
	if err != nil || fixtureActor(slot, "get") != 0 {
		return nil, false, ErrFixtures
	}
	parent := w.actors.admission.prerequisites.access
	discovery, err := parent.discover(ctx, key.APIVersion)
	if err != nil || !discoveredPermission(discovery, permission) || parent.authorize(ctx, permission.spec) != nil || !w.phaseReadable() || w.localCurrent() != nil {
		return nil, false, ErrFixtures
	}
	capture, err := w.request(ctx, slot, fixtureGetRequest)
	if err != nil || capture == nil || !w.phaseReadable() || w.localCurrent() != nil {
		return nil, false, ErrFixtures
	}
	if capture.notFound {
		return nil, true, nil
	}
	if capture.result == nil {
		return nil, false, ErrFixtures
	}
	uid := w.ledger.document.Entries[slot].OriginalUID
	if uid != "" && capture.result.GetUID() != uid {
		return nil, false, ErrFixtures
	}
	return capture.result.DeepCopy(), false, nil
}
