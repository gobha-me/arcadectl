// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"reflect"

	"github.com/gobha-me/arcadectl/internal/privatefs"
)

const fixtureBehaviorVersion = "admission-behavior-v1"

const fixtureBehaviorVersionV2 = "admission-behavior-v2"

const fixtureBehaviorVersionV3 = "admission-behavior-v3"

func fixtureBehaviorRecipeVersion(d fixtureLedgerDocument) string {
	if !validFixtureRecipe(d) {
		return ""
	}
	switch d.Recipe {
	case fixtureRecipeV1:
		return fixtureBehaviorVersion
	case fixtureRecipeV2:
		return fixtureBehaviorVersionV2
	case fixtureRecipeV3:
		return fixtureBehaviorVersionV3
	default:
		return ""
	}
}

// Historical completion of the entire fixed matrix in THIS original run,
// before cleanup. The enclosing WAL binds the package/profile, journal, run,
// original UIDs, seed/marker ACKs and original-world digest. This is never a
// current AdmissionEffective result, permission, replay or resume capability.
type fixtureBehaviorReceipt struct {
	Version  string `json:"version"`
	Revision uint64 `json:"revision"`
}

func validFixtureBehaviorDocument(d fixtureLedgerDocument) bool {
	if d.Behavior == nil {
		return true // exact legacy encoding and aborted-run cleanup remain valid
	}
	r := d.Behavior
	version := fixtureBehaviorRecipeVersion(d)
	if !validFixtureRecipe(d) || r.Version != version || r.Revision == 0 || r.Revision > d.Revision || r.Revision > 9007199254740991 || !fixtureWorldsDigest.MatchString(d.OriginalWorldsSHA256) || !validFixtureDestroySeedDocument(d) || d.DestroySeed == nil || d.DestroySeed.State != fixtureDestroySeedAcknowledged || !validFixtureRetainedMarkerDocument(d) || d.RetainedMarker == nil || d.RetainedMarker.State != fixtureRetainedMarkerAcknowledged {
		return false
	}
	seen := make(map[string]bool, len(d.Entries))
	cleanupRevisions := uint64(0)
	for _, entry := range d.Entries {
		uid := string(entry.OriginalUID)
		if !receiptUID.MatchString(uid) || seen[uid] {
			return false
		}
		seen[uid] = true
		switch entry.State {
		case fixtureOriginal:
		case fixtureDeleteAttempted:
			cleanupRevisions++
		case fixtureAbsent:
			cleanupRevisions += 2
		default:
			return false // no receipt can settle an unknown CREATE/effect
		}
	}
	// Publication is a standalone all-original revision. In either immutable
	// recipe every later revision is exactly one intent or absence transition;
	// a recomputed archive hash cannot invent completion during/after cleanup.
	return r.Revision+cleanupRevisions == d.Revision
}

func validFixtureBehaviorTransition(before, after fixtureLedgerDocument) bool {
	if before.Behavior != nil || after.Behavior == nil || !validFixtureBehaviorDocument(after) || after.Behavior.Revision != after.Revision || before.OriginalWorldsSHA256 != after.OriginalWorldsSHA256 || !reflect.DeepEqual(before.Entries, after.Entries) || !reflect.DeepEqual(before.DestroySeed, after.DestroySeed) || !reflect.DeepEqual(before.RetainedMarker, after.RetainedMarker) {
		return false
	}
	for _, entry := range before.Entries {
		if entry.State != fixtureOriginal {
			return false // must precede the first original DELETE, not late recovery
		}
	}
	return true
}

// Only the closed finite matrix driver constructs this after all case validators and
// a final complete phase observation, under wireMu. A phase observation alone
// cannot grant it. No caller flags, callbacks or durable receipt can do so.
// Tests may instrument this state primitive, never claim native effectiveness.
type fixtureBehaviorCompletion struct {
	ledger   *fixtureLedger
	revision uint64
	bodySHA  string
	identity privatefs.FileIdentity
}

func (c *fixtureBehaviorCompletion) matches(f *fixtureLedger) bool {
	return c != nil && f != nil && c.ledger == f && c.revision == f.document.Revision && c.bodySHA == fixtureWorldDigest(f.body) && c.identity == f.identity
}
