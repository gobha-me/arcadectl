// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

// Fixed private stage labels only. No raw error, response, header, object,
// identity or credential is retained, and this is never an effect capability
// or a reason to retry/waive a failed preview. Public errors remain ErrFixtures.
type fixturePreviewStage uint8

const (
	fixturePreviewUnavailable fixturePreviewStage = iota
	fixturePreviewReadiness
	fixturePreviewPrepare
	fixturePreviewPreparedReadiness
	fixturePreviewRequest
	fixturePreviewReply
	fixturePreviewPostWitness
	fixturePreviewPostReadiness
	fixturePreviewWholeShape
	fixturePreviewAccepted
)

func (s fixturePreviewStage) String() string {
	switch s {
	case fixturePreviewReadiness:
		return "readiness"
	case fixturePreviewPrepare:
		return "prepare"
	case fixturePreviewPreparedReadiness:
		return "prepared-readiness"
	case fixturePreviewRequest:
		return "request"
	case fixturePreviewReply:
		return "reply"
	case fixturePreviewPostWitness:
		return "post-witness"
	case fixturePreviewPostReadiness:
		return "post-readiness"
	case fixturePreviewWholeShape:
		return "whole-shape"
	case fixturePreviewAccepted:
		return "accepted"
	}
	return "unavailable"
}

// Read a diagnostic snapshot, never permission or proof of current readiness.
func (w *fixtureWire) previewDiagnostic() fixturePreviewStage {
	if w == nil || w.ledger == nil {
		return fixturePreviewUnavailable
	}
	w.ledger.wireMu.Lock()
	defer w.ledger.wireMu.Unlock()
	return w.previewStage
}
