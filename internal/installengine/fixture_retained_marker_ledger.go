// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

type fixtureRetainedMarkerState string

const (
	fixtureRetainedMarkerAttempted    fixtureRetainedMarkerState = "attempted"
	fixtureRetainedMarkerAcknowledged fixtureRetainedMarkerState = "acknowledged"
)

// Optional to retain exact canonical legacy bytes. The sole original PVC UID
// and address come from slot7; marker bytes come from the protected RunID, never
// caller input or a live matching name. This records durability ONLY, not a
// marker effect, whole-shape/GC/cold proof or permission to clean up. An unknown
// outcome stays attempted after GET/reload, with no replay/ACK capability.
type fixtureRetainedMarkerReceipt struct {
	State                       fixtureRetainedMarkerState `json:"state"`
	BeforeResourceVersion       string                     `json:"beforeResourceVersion"`
	AcknowledgedResourceVersion string                     `json:"acknowledgedResourceVersion"`
}

func validFixtureRetainedMarkerDocument(d fixtureLedgerDocument) bool {
	if d.RetainedMarker == nil {
		return true
	}
	r := d.RetainedMarker
	if !validFixtureRecipe(d) || !fixtureRV(r.BeforeResourceVersion) {
		return false
	}
	for _, entry := range d.Entries {
		if !nativeFixtureUID(string(entry.OriginalUID)) || entry.State != fixtureOriginal && entry.State != fixtureDeleteAttempted && entry.State != fixtureAbsent {
			return false
		}
		if r.State == fixtureRetainedMarkerAttempted && entry.State != fixtureOriginal {
			return false // an unknown marker effect freezes every cleanup entry
		}
	}
	switch r.State {
	case fixtureRetainedMarkerAttempted:
		return r.AcknowledgedResourceVersion == "" && (d.DestroySeed == nil || d.DestroySeed.State == fixtureDestroySeedAcknowledged)
	case fixtureRetainedMarkerAcknowledged:
		return fixtureRV(r.AcknowledgedResourceVersion) && r.AcknowledgedResourceVersion != r.BeforeResourceVersion
	}
	return false
}

func validFixtureRetainedMarkerTransition(before, after fixtureLedgerDocument) bool {
	if !validFixtureRetainedMarkerDocument(before) || !validFixtureRetainedMarkerDocument(after) || after.RetainedMarker == nil {
		return false
	}
	if before.RetainedMarker == nil {
		return after.RetainedMarker.State == fixtureRetainedMarkerAttempted
	}
	return before.RetainedMarker.State == fixtureRetainedMarkerAttempted && after.RetainedMarker.State == fixtureRetainedMarkerAcknowledged && before.RetainedMarker.BeforeResourceVersion == after.RetainedMarker.BeforeResourceVersion
}

// Until marked whole-object/wire validation exists, old routes may not infer
// permission from either a marker receipt or an instance-local marker flag.
func (f *fixtureLedger) markerUnresolved() bool {
	return f == nil || f.document.RetainedMarker != nil || f.markerAck || f.markerEffect
}
