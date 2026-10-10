// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installrender

// ResourceMetadata is only a desired signed-template address and contract
// flags, NOT a live object, original UID or ownership/deletion authorization.
// It contains no object pointers, nested schemas, maps or mutable slices.
type ResourceMetadata struct {
	APIVersion string
	Kind       string
	Namespace  string
	Name       string
	Retained   bool
	Phase      Phase
}

// ResourceMetadata returns fresh value-only metadata from the private, already
// parameterized resources. Journal validation needs these addresses/flags, not
// a copy of all CRD schemas on every encode/read barrier. Whole-object consumers
// still use Resources(), with its original defensive-copy contract unchanged.
func (p *Plan) ResourceMetadata() []ResourceMetadata {
	if p == nil {
		return nil
	}
	result := make([]ResourceMetadata, len(p.resources))
	for i, r := range p.resources {
		result[i] = ResourceMetadata{APIVersion: r.Object.GetAPIVersion(), Kind: r.Object.GetKind(), Namespace: r.Object.GetNamespace(),
			Name: r.Object.GetName(), Retained: r.Retained, Phase: r.Phase}
	}
	return result
}
