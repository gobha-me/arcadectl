// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// The finite provider must own one witness interval, not release wireMu around
// each transport. These are fake-wire composition regressions, NOT native
// admission, full-matrix completion or permission to expose mutation commands.
func TestFixtureAdmissionDriverLockedTransportComposition(t *testing.T) {
	for _, route := range []string{"preview", "create", "cold-seed", "warm-seed", "marker"} {
		t.Run(route, func(t *testing.T) {
			var w *fixtureWire
			var send func() (*unstructured.Unstructured, error)
			switch route {
			case "preview":
				w = newFixtureWireTest(t).wire
				send = func() (*unstructured.Unstructured, error) { return w.dryRunLocked(t.Context(), 0) }
			case "create":
				w = newFixtureWireTest(t).wire
				fixtureWireAdvance(t, w.ledger, 0, fixtureCreateAttempted, "")
				send = func() (*unstructured.Unstructured, error) { return w.createLocked(t.Context(), 0) }
			case "cold-seed":
				w = fixtureSeedWireFactory(t)(t).wire
				send = func() (*unstructured.Unstructured, error) { return w.seedDestroyStatusLocked(t.Context()) }
			case "warm-seed":
				w = fixtureWarmSeedWireFactory(t)(t).wire
				send = func() (*unstructured.Unstructured, error) { return w.seedWarmDestroyStatusLocked(t.Context()) }
			case "marker":
				h := retainedMarkerLearningFactory(t)(t)
				fixtureMarkerWireNativeReply(t, h)
				w = h.f.wire
				send = func() (*unstructured.Unstructured, error) { return w.markRetainedPVCLocked(t.Context()) }
			}
			w.ledger.wireMu.Lock()
			defer w.ledger.wireMu.Unlock()
			result, err := send()
			if err != nil || result == nil {
				t.Fatal("closed driver could not compose transport while holding wireMu", err)
			}
			if w.ledger.seedAck || w.ledger.seedEffect || w.ledger.markerAck || w.ledger.markerEffect || w.ledger.ackSlot != -1 || w.ledger.effectSlot != -1 {
				t.Fatal("transport returned before revoking spent effect/ACK capability")
			}
		})
	}
}
