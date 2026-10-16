// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installcontract

import (
	"math"
	"strings"
)

// Opportunistic retention/work limits, NOT input validity limits. Anything
// ineligible still takes the existing complete marshal/strict-decode path.
// String payload is not total heap: containers and interfaces also cost memory.
const (
	observedJSONNodes   = 2048
	observedJSONStrings = 64 * 1024
	observedJSONDepth   = 64
)

type observedJSONBudget struct{ nodes, strings int }

func (b *observedJSONBudget) node(depth int) bool {
	if depth > observedJSONDepth || b.nodes == observedJSONNodes {
		return false
	}
	b.nodes++
	return true
}

func (b *observedJSONBudget) text(s string) bool {
	if len(s) > observedJSONStrings-b.strings {
		return false
	}
	b.strings += len(s)
	return true
}

// Only built-in Kubernetes JSON tree types are eligible. Named types, other
// integers, json.Number and custom marshalers retain the original byte path.
// There is no pointer-identity shortcut, numeric coercion or selected-field key.
func sameObservedJSON(input, operand any) bool {
	var budget observedJSONBudget
	return budget.same(input, operand, 0)
}

func (b *observedJSONBudget) same(input, operand any, depth int) bool {
	if !b.node(depth) {
		return false
	}
	switch wanted := operand.(type) {
	case nil:
		return input == nil
	case bool:
		got, ok := input.(bool)
		return ok && got == wanted
	case string:
		got, ok := input.(string)
		return ok && b.text(wanted) && got == wanted
	case int64:
		got, ok := input.(int64)
		return ok && got == wanted
	case float64:
		got, ok := input.(float64)
		return ok && math.Float64bits(got) == math.Float64bits(wanted)
	case map[string]any:
		got, ok := input.(map[string]any)
		if !ok || (got == nil) != (wanted == nil) || len(got) != len(wanted) {
			return false
		}
		// Iterate the bounded, owned operand, not untrusted long input keys.
		for key, value := range wanted {
			if !b.node(depth+1) || !b.text(key) {
				return false
			}
			actual, exists := got[key]
			if !exists || !b.same(actual, value, depth+1) {
				return false
			}
		}
		return true
	case []any:
		got, ok := input.([]any)
		if !ok || (got == nil) != (wanted == nil) || len(got) != len(wanted) {
			return false
		}
		for i, value := range wanted {
			if !b.same(got[i], value, depth+1) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func cloneObservedJSON(input any) (any, bool) {
	var budget observedJSONBudget
	return budget.clone(input, 0)
}

func (b *observedJSONBudget) clone(input any, depth int) (any, bool) {
	if !b.node(depth) {
		return nil, false
	}
	switch value := input.(type) {
	case nil, bool, int64, float64:
		return value, true
	case string:
		if !b.text(value) {
			return nil, false
		}
		return strings.Clone(value), true
	case map[string]any:
		if value == nil {
			return map[string]any(nil), true
		}
		// Charge entries before container allocation, then all nested values.
		if len(value) > (observedJSONNodes-b.nodes)/2 {
			return nil, false
		}
		out := make(map[string]any, len(value))
		for key, child := range value {
			if !b.node(depth+1) || !b.text(key) {
				return nil, false
			}
			owned, ok := b.clone(child, depth+1)
			if !ok {
				return nil, false
			}
			out[strings.Clone(key)] = owned
		}
		return out, true
	case []any:
		if value == nil {
			return []any(nil), true
		}
		if len(value) > observedJSONNodes-b.nodes {
			return nil, false
		}
		out := make([]any, len(value))
		for i, child := range value {
			owned, ok := b.clone(child, depth+1)
			if !ok {
				return nil, false
			}
			out[i] = owned
		}
		return out, true
	default:
		return nil, false
	}
}
