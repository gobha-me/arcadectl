// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package controller

import arcadev1alpha1 "github.com/gobha-me/arcadectl/api/v1alpha1"

// sameDataSelection compares whole exact data sets independent of the order
// of the map-list claims. No name-only or generation-only match is sufficient.
func sameDataSelection(left, right *arcadev1alpha1.RetainedDataReference) bool {
	if left == nil || right == nil || left.Identity == "" || left.Identity != right.Identity || len(left.Claims) == 0 || len(left.Claims) != len(right.Claims) {
		return false
	}
	paths := make(map[string]arcadev1alpha1.ExactLocalReference, len(left.Claims))
	for _, claim := range left.Claims {
		if claim.Path == "" || claim.ClaimRef.Name == "" || claim.ClaimRef.UID == "" || claim.ClaimRef.Namespace != nil {
			return false
		}
		if _, duplicate := paths[claim.Path]; duplicate {
			return false
		}
		paths[claim.Path] = claim.ClaimRef
	}
	for _, claim := range right.Claims {
		wanted, exists := paths[claim.Path]
		if !exists || claim.ClaimRef.Namespace != nil || claim.ClaimRef.Name != wanted.Name || claim.ClaimRef.UID != wanted.UID {
			return false
		}
		delete(paths, claim.Path)
	}
	return len(paths) == 0
}
