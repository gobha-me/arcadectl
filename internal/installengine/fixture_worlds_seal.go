// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"reflect"
	"regexp"
)

var fixtureWorldsDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Optional only for exact legacy decoding. The complete provider must require
// a sealed original baseline before effects; an old active WAL stays fenced.
func validFixtureWorldsSeal(d fixtureLedgerDocument) bool {
	return d.OriginalWorldsSHA256 == "" || fixtureWorldsDigest.MatchString(d.OriginalWorldsSHA256)
}

func validFixtureWorldsSealTransition(before, after fixtureLedgerDocument) bool {
	if before.OriginalWorldsSHA256 != "" || !fixtureWorldsDigest.MatchString(after.OriginalWorldsSHA256) || before.DestroySeed != nil || after.DestroySeed != nil || before.RetainedMarker != nil || after.RetainedMarker != nil || !reflect.DeepEqual(before.Entries, after.Entries) {
		return false
	}
	for _, entry := range before.Entries {
		if entry.State != fixturePlanned || entry.OriginalUID != "" || entry.DeleteResourceVersion != "" {
			return false
		}
	}
	return validFixtureRecipe(before) && validFixtureRecipe(after) && before.Recipe == after.Recipe
}
