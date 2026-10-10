// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

type fixtureDestroySeedState string

type fixtureDestroySeedMode string

const (
	fixtureDestroySeedCold          fixtureDestroySeedMode = ""
	fixtureDestroySeedWarmCancelled fixtureDestroySeedMode = "warm-cancelled-v1"
)

const (
	fixtureDestroySeedAttempted    fixtureDestroySeedState = "attempted"
	fixtureDestroySeedAcknowledged fixtureDestroySeedState = "acknowledged"
)

// Optional to preserve exact canonical legacy v1 bytes. Original UID and fixed
// address derive ONLY from slot9, not this receipt or an observed matching name.
// This is durability bookkeeping, not status transport/shape/cold/cleanup proof.
// A lost status result must remain attempted; a later GET cannot become an ACK.
// Mode is chosen by the closed workflow BEFORE intent, never from a GET shape.
// Omitted cold preserves legacy bytes; the distinct warm intent cannot use cold
// routes. Neither mode nor its durable receipt grants an effect by itself.
type fixtureDestroySeedReceipt struct {
	Mode                        fixtureDestroySeedMode  `json:"mode,omitempty"`
	State                       fixtureDestroySeedState `json:"state"`
	BeforeResourceVersion       string                  `json:"beforeResourceVersion"`
	AcknowledgedResourceVersion string                  `json:"acknowledgedResourceVersion"`
}

func validFixtureDestroySeedDocument(d fixtureLedgerDocument) bool {
	if d.DestroySeed == nil {
		return true
	}
	r := d.DestroySeed
	if r.Mode != fixtureDestroySeedCold && r.Mode != fixtureDestroySeedWarmCancelled {
		return false
	}
	if !validFixtureRecipe(d) || !fixtureRV(r.BeforeResourceVersion) {
		return false
	}
	for _, entry := range d.Entries {
		if !nativeFixtureUID(string(entry.OriginalUID)) || entry.State != fixtureOriginal && entry.State != fixtureDeleteAttempted && entry.State != fixtureAbsent {
			return false // seed starts only after ALL original CREATE acknowledgements
		}
		if r.State == fixtureDestroySeedAttempted && entry.State != fixtureOriginal {
			return false // unknown seed blocks cleanup even after protected reload
		}
	}
	switch r.State {
	case fixtureDestroySeedAttempted:
		return r.AcknowledgedResourceVersion == ""
	case fixtureDestroySeedAcknowledged:
		return fixtureRV(r.AcknowledgedResourceVersion) && r.AcknowledgedResourceVersion != r.BeforeResourceVersion
	}
	return false
}

func validFixtureDestroySeedTransition(before, after fixtureLedgerDocument) bool {
	if !validFixtureDestroySeedDocument(before) || !validFixtureDestroySeedDocument(after) || after.DestroySeed == nil {
		return false
	}
	if before.DestroySeed == nil {
		return after.DestroySeed.State == fixtureDestroySeedAttempted
	}
	return before.DestroySeed.State == fixtureDestroySeedAttempted && after.DestroySeed.State == fixtureDestroySeedAcknowledged && before.DestroySeed.Mode == after.DestroySeed.Mode && before.DestroySeed.BeforeResourceVersion == after.DestroySeed.BeforeResourceVersion
}
