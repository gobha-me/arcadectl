// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installrender

import "slices"

// ResourcesByKind returns defensive copies of the exact kind union, in the
// original resource order. Filtering precedes copying so callers needing only
// Services or admission resources do not copy unrelated nested CRD schemas.
// This is desired signed-template data, not live identity or effect authority.
// Empty/unknown kinds select nothing; duplicate kinds never duplicate objects.
func (p *Plan) ResourcesByKind(kinds ...string) []Resource {
	if p == nil {
		return nil
	}
	var result []Resource
	for _, r := range p.resources {
		if slices.Contains(kinds, r.Object.GetKind()) {
			result = append(result, Resource{Object: r.Object.DeepCopy(), Retained: r.Retained, Phase: r.Phase})
		}
	}
	return result
}
