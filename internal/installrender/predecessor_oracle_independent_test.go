// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installrender

import "slices"

// predecessorManifestOracle independently computes whether plan declares
// previous as a predecessor using the pre-#129 defensive Manifest() copy path
// rather than Plan.DeclaresPredecessor.
func predecessorManifestOracle(plan, previous *Plan) bool {
	if plan == nil || previous == nil {
		return false
	}
	oldManifest := previous.Manifest()
	for _, candidate := range plan.Manifest().Predecessors {
		if candidate.PackageSHA256 == previous.Digest() &&
			candidate.SourceSHA == oldManifest.SourceSHA &&
			candidate.Images == oldManifest.Images &&
			candidate.Namespace == previous.Namespace() &&
			slices.Contains(candidate.ProfileIDs, previous.Profile().ID) {
			return true
		}
	}
	return false
}
