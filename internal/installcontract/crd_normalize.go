// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installcontract

import (
	"encoding/json"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// normalizedCRDSpecShallow borrows only a freshly checked, bounded built-in JSON
// graph for the duration of this call. A private top-level copy holds the same
// two normalizations as normalizedCRDSpec. No nested field is omitted; every
// comparison still marshals the whole fresh spec. Ineligible graphs retain the
// unchanged deep-copy fallback, including its unsupported-type behavior.
func normalizedCRDSpecShallow(o *unstructured.Unstructured) []byte {
	if o == nil {
		return nil
	}
	value, exists, err := unstructured.NestedFieldNoCopy(o.Object, "spec")
	spec, ok := value.(map[string]any)
	if err != nil || !exists || !ok || spec == nil {
		return nil
	}
	if !sameObservedJSON(spec, spec) {
		return normalizedCRDSpec(o)
	}
	local := make(map[string]any, len(spec)+1)
	for key, value := range spec {
		local[key] = value
	}
	if _, exists := local["conversion"]; !exists {
		local["conversion"] = map[string]any{"strategy": "None"}
	}
	if value, exists := local["preserveUnknownFields"]; exists && value == false {
		delete(local, "preserveUnknownFields")
	}
	body, err := json.Marshal(local)
	if err != nil {
		return nil
	}
	return body
}
