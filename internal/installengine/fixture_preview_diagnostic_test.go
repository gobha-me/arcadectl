// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import "testing"

func TestFixturePreviewDiagnosticIsClosedAndNeverAuthority(t *testing.T) {
	allowed := map[string]bool{
		"unavailable": true, "readiness": true, "prepare": true,
		"prepared-readiness": true, "request": true, "reply": true,
		"post-witness": true, "post-readiness": true, "whole-shape": true,
		"accepted": true,
	}
	for i := 0; i < 256; i++ {
		if !allowed[fixturePreviewStage(i).String()] {
			t.Fatal("diagnostic generated an unbounded label")
		}
	}
	var absent *fixtureWire
	if absent.previewDiagnostic() != fixturePreviewUnavailable || (&fixtureWire{}).previewDiagnostic() != fixturePreviewUnavailable {
		t.Fatal("unavailable wire reported current proof")
	}
	f := &fixtureLedger{ackSlot: -1, effectSlot: -1}
	w := &fixtureWire{ledger: f, previewStage: fixturePreviewAccepted}
	if w.previewDiagnostic() != fixturePreviewAccepted || f.ackSlot != -1 || f.effectSlot != -1 || f.seedAck || f.seedEffect || f.markerAck || f.markerEffect || f.behaviorCompletion != nil {
		t.Fatal("reading a historical stage changed effect capabilities")
	}
}
