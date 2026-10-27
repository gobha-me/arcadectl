// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"slices"
	"strings"
)

// Value keys represent only the finite selector-free permission recipe, never
// an authorization result. The set is rebuilt at every existing derivation
// boundary and cannot outlive its caller. Keep kind outside the key, as in the
// previous JSON-spec deduplication: the last identical spec supplies its kind.
type proofPermissionKey struct {
	resource        bool
	namespaceOrPath string
	verb            string
	group           string
	version         string
	plural          string
	subresource     string
	name            string
}

func uniqueProofPermissions(permissions []proofPermission) ([]proofPermission, error) {
	for _, permission := range permissions {
		a, n := permission.spec.ResourceAttributes, permission.spec.NonResourceAttributes
		if !((a != nil && n == nil && a.FieldSelector == nil && a.LabelSelector == nil) || (a == nil && n != nil)) {
			return nil, ErrInvalid
		}
	}
	// A stable field order replaces sorting JSON encodings. No observer or
	// authorizer is skipped: consumers still visit every distinct descriptor.
	// Sort one detached slice rather than allocating keys and a hash table.
	// Stability preserves the old last-identical-spec discovery-kind behavior.
	result := slices.Clone(permissions)
	slices.SortStableFunc(result, func(a, b proofPermission) int {
		return compareProofPermissionKeys(permissionDescriptorKey(a), permissionDescriptorKey(b))
	})
	var previous proofPermissionKey
	count := 0
	for _, permission := range result {
		key := permissionDescriptorKey(permission)
		if count == 0 || key != previous {
			count++
			if count > 256 {
				return nil, ErrInvalid
			}
		}
		result[count-1], previous = permission, key
	}
	clear(result[count:])
	return result[:count], nil
}

// Called only for this invocation's validated selector-free descriptors.
func permissionDescriptorKey(permission proofPermission) proofPermissionKey {
	if a := permission.spec.ResourceAttributes; a != nil {
		return proofPermissionKey{true, a.Namespace, a.Verb, a.Group, a.Version, a.Resource, a.Subresource, a.Name}
	}
	n := permission.spec.NonResourceAttributes
	return proofPermissionKey{namespaceOrPath: n.Path, verb: n.Verb}
}

func compareProofPermissionKeys(a, b proofPermissionKey) int {
	if a.resource != b.resource {
		if a.resource {
			return 1
		}
		return -1
	}
	left := [...]string{a.namespaceOrPath, a.verb, a.group, a.version, a.plural, a.subresource, a.name}
	right := [...]string{b.namespaceOrPath, b.verb, b.group, b.version, b.plural, b.subresource, b.name}
	for i := range left {
		if order := strings.Compare(left[i], right[i]); order != 0 {
			return order
		}
	}
	return 0
}
