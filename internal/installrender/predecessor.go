// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installrender

import "slices"

// DeclaresPredecessor compares only immutable signed package metadata. It
// confers no live admission, ownership or transition authority. Keeping the
// comparison inside Plan avoids copying both complete manifests at every
// permission/eligibility boundary; callers still perform those boundaries.
func (p *Plan) DeclaresPredecessor(previous *Plan) bool {
	if p == nil || previous == nil {
		return false
	}
	for _, candidate := range p.manifest.Predecessors {
		if candidate.PackageSHA256 == previous.digest && candidate.SourceSHA == previous.manifest.SourceSHA &&
			candidate.Images == previous.manifest.Images && candidate.Namespace == previous.namespace &&
			slices.Contains(candidate.ProfileIDs, previous.profile.ID) {
			return true
		}
	}
	return false
}
