// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installobserve

import (
	"encoding/json"
	"unicode/utf8"
)

// TEST-ONLY: the standard library validates ALL syntax first. The second pass
// enforces the unchanged depth/node/decoded-key bounds without materializing
// scalar values. This is not a new JSON syntax implementation or a metadata
// sanitizer. Production boundedJSON and transport remain untouched.
func boundedJSONScanCandidate(body []byte) error {
	if !utf8.Valid(body) || !json.Valid(body) {
		return ErrRead
	}
	w := jsonBudgetCandidate{body: body}
	if !w.value(0) {
		return ErrRead
	}
	w.space()
	if w.at != len(body) {
		return ErrRead
	}
	return nil
}

type jsonBudgetCandidate struct {
	body      []byte
	at, nodes int
}

func (w *jsonBudgetCandidate) space() {
	for w.at < len(w.body) {
		switch w.body[w.at] {
		case ' ', '\t', '\n', '\r':
			w.at++
		default:
			return
		}
	}
}

func (w *jsonBudgetCandidate) take(c byte) bool {
	if w.at >= len(w.body) || w.body[w.at] != c {
		return false
	}
	w.at++
	return true
}

// Returns the physical quoted span, not decoded contents. Even after
// json.Valid, all accesses/slices stay bounded and unmatched quotes refuse.
func (w *jsonBudgetCandidate) quoted() (start, end int, escaped, ok bool) {
	start = w.at
	if !w.take('"') {
		return 0, 0, false, false
	}
	for w.at < len(w.body) {
		c := w.body[w.at]
		w.at++
		if c == '"' {
			return start, w.at, escaped, true
		}
		if c == '\\' {
			escaped = true
			if w.at >= len(w.body) {
				return 0, 0, false, false
			}
			// Escaped quotes/backslashes are not physical terminators. For
			// Unicode escapes the already-validated hex digits need no decode.
			w.at++
		}
	}
	return 0, 0, false, false
}

func (w *jsonBudgetCandidate) value(depth int) bool {
	w.nodes++
	if depth > 64 || w.nodes > 200000 {
		return false
	}
	w.space()
	if w.at >= len(w.body) {
		return false
	}
	switch w.body[w.at] {
	case '{':
		w.at++
		w.space()
		if w.take('}') {
			return true
		}
		keys := map[string]struct{}{}
		for {
			start, end, escaped, ok := w.quoted()
			if !ok || end < start+2 {
				return false
			}
			var key string
			if escaped {
				// Match Decoder.Token's surrogate/replacement behavior exactly.
				if json.Unmarshal(w.body[start:end], &key) != nil {
					return false
				}
			} else {
				key = string(w.body[start+1 : end-1])
			}
			if _, duplicate := keys[key]; duplicate {
				return false
			}
			w.space()
			if !w.take(':') || !w.value(depth+1) {
				return false
			}
			keys[key] = struct{}{}
			w.space()
			if w.take('}') {
				return true
			}
			if !w.take(',') {
				return false
			}
			w.space()
		}
	case '[':
		w.at++
		w.space()
		if w.take(']') {
			return true
		}
		for {
			if !w.value(depth + 1) {
				return false
			}
			w.space()
			if w.take(']') {
				return true
			}
			if !w.take(',') {
				return false
			}
		}
	case '"':
		_, _, _, ok := w.quoted()
		return ok
	case 'n', 't', 'f', '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		// ALL scalar spelling/number constraints are enforced by json.Valid,
		// including huge exponents without a float conversion. Here only find
		// the end of this already-valid scalar, without allocating its value.
		start := w.at
		for w.at < len(w.body) {
			switch w.body[w.at] {
			case ' ', '\t', '\n', '\r', ',', ']', '}', ':':
				return w.at > start
			default:
				w.at++
			}
		}
		return w.at > start
	default:
		return false
	}
}
