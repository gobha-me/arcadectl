// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

// Package canonicaljson provides bounded exact JSON canonicalization without clients.
package canonicaljson

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

var ErrInvalid = errors.New("invalid bounded JSON")

const MaxBytes = 65536

// Only immutable public-identity evidence uses this larger, explicit bound.
// Settings, credentials and ordinary CanonicalJSON callers keep MaxBytes.
const MaxEvidenceBytes = 32 * 1024 * 1024

// CanonicalJSON rejects duplicate keys recursively and preserves exact numeric
// values without float64 rounding. Equivalent number spellings canonicalize to
// the same bounded exact representation. Integers retain integer JSON syntax
// so adapter decoders with typed integer fields can consume them. Depth is bounded.
func CanonicalJSON(input []byte) ([]byte, error) {
	return canonicalBounded(input, MaxBytes)
}

func CanonicalEvidenceJSON(input []byte) ([]byte, error) {
	return canonicalBounded(input, MaxEvidenceBytes)
}

func canonicalBounded(input []byte, limit int) ([]byte, error) {
	if len(input) == 0 || len(input) > limit || !utf8.Valid(input) {
		return nil, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.UseNumber()
	budget := limit
	value, err := decodeValue(decoder, 0, &budget)
	if err != nil {
		return nil, ErrInvalid
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, ErrInvalid
	}
	output, err := json.Marshal(value)
	if err != nil || len(output) > limit {
		return nil, ErrInvalid
	}
	return output, nil
}

// Charge canonical output while decoding, not after allocating an expanded
// value graph. Short exponent spellings can otherwise amplify a bounded input
// by orders of magnitude before Marshal's final output check.
func spend(budget *int, size int) bool {
	if budget == nil || size < 0 || *budget < size {
		return false
	}
	*budget -= size
	return true
}

func spendString(budget *int, value string) bool {
	encoded, err := json.Marshal(value)
	return err == nil && spend(budget, len(encoded))
}

func decodeValue(decoder *json.Decoder, depth int, budget *int) (any, error) {
	if depth > 32 {
		return nil, ErrInvalid
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, ErrInvalid
	}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			if !spend(budget, 2) {
				return nil, ErrInvalid
			}
			object := make(map[string]any)
			for decoder.More() {
				key, err := decoder.Token()
				name, ok := key.(string)
				if err != nil || !ok {
					return nil, ErrInvalid
				}
				if _, exists := object[name]; exists {
					return nil, ErrInvalid
				}
				if !spendString(budget, name) || !spend(budget, 1) || len(object) != 0 && !spend(budget, 1) {
					return nil, ErrInvalid
				}
				child, err := decodeValue(decoder, depth+1, budget)
				if err != nil {
					return nil, err
				}
				object[name] = child
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return nil, ErrInvalid
			}
			return object, nil
		case '[':
			if !spend(budget, 2) {
				return nil, ErrInvalid
			}
			array := make([]any, 0)
			for decoder.More() {
				if len(array) != 0 && !spend(budget, 1) {
					return nil, ErrInvalid
				}
				child, err := decodeValue(decoder, depth+1, budget)
				if err != nil {
					return nil, err
				}
				array = append(array, child)
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return nil, ErrInvalid
			}
			return array, nil
		}
		return nil, ErrInvalid
	case json.Number:
		number, err := canonicalNumber(string(value))
		if err != nil || !spend(budget, len(number)) {
			return nil, ErrInvalid
		}
		return number, nil
	case string:
		if !spendString(budget, value) {
			return nil, ErrInvalid
		}
		return value, nil
	case bool:
		size := 5
		if value {
			size = 4
		}
		if !spend(budget, size) {
			return nil, ErrInvalid
		}
		return value, nil
	case nil:
		if !spend(budget, 4) {
			return nil, ErrInvalid
		}
		return nil, nil
	default:
		return nil, ErrInvalid
	}
}

func canonicalNumber(number string) (json.Number, error) {
	if len(number) > 128 {
		return "", ErrInvalid
	}
	negative := strings.HasPrefix(number, "-")
	if negative {
		number = number[1:]
	}
	mantissa, exponentText, hasExponent := strings.Cut(strings.ToLower(number), "e")
	exponent := 0
	if hasExponent {
		parsed, err := strconv.Atoi(exponentText)
		if err != nil || parsed < -4096 || parsed > 4096 {
			return "", ErrInvalid
		}
		exponent = parsed
	}
	whole, fraction, _ := strings.Cut(mantissa, ".")
	coefficient := strings.TrimLeft(whole+fraction, "0")
	if coefficient == "" {
		return json.Number("0"), nil
	}
	exponent -= len(fraction)
	trimmed := strings.TrimRight(coefficient, "0")
	exponent += len(coefficient) - len(trimmed)
	coefficient = trimmed
	if negative {
		coefficient = "-" + coefficient
	}
	if exponent > 0 {
		coefficient += strings.Repeat("0", exponent)
	} else if exponent < 0 {
		coefficient += "e" + strconv.Itoa(exponent)
	}
	return json.Number(coefficient), nil
}
