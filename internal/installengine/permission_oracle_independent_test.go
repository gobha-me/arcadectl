// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"encoding/json"
	"slices"
)

// jsonProofPermissionOracle independently deduplicates proofPermission entries
// via the pre-#129 JSON-marshaled SelfSubjectAccessReviewSpec map route, where
// the last entry with an identical JSON spec supplies the discovery kind.
func jsonProofPermissionOracle(permissions []proofPermission) []proofPermission {
	unique := make(map[string]proofPermission, len(permissions))
	for _, permission := range permissions {
		encoded, err := json.Marshal(permission.spec)
		if err != nil {
			panic(err)
		}
		unique[string(encoded)] = permission
	}
	keys := make([]string, 0, len(unique))
	for key := range unique {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	result := make([]proofPermission, 0, len(keys))
	for _, key := range keys {
		result = append(result, unique[key])
	}
	return result
}
