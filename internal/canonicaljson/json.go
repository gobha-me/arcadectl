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

// CanonicalJSON rejects duplicate keys recursively and preserves exact numeric
// values without float64 rounding. Equivalent number spellings canonicalize to
// the same bounded exact representation. Integers retain integer JSON syntax
// so adapter decoders with typed integer fields can consume them. Depth is bounded.
func CanonicalJSON(input []byte) ([]byte, error) {
	if len(input) == 0 || len(input) > MaxBytes || !utf8.Valid(input) {
		return nil, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.UseNumber()
	value, err := decodeValue(decoder, 0)
	if err != nil {
		return nil, ErrInvalid
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, ErrInvalid
	}
	output, err := json.Marshal(value)
	if err != nil || len(output) > MaxBytes {
		return nil, ErrInvalid
	}
	return output, nil
}

func decodeValue(decoder *json.Decoder, depth int) (any, error) {
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
				child, err := decodeValue(decoder, depth+1)
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
			array := make([]any, 0)
			for decoder.More() {
				child, err := decodeValue(decoder, depth+1)
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
		return canonicalNumber(string(value))
	case string, bool, nil:
		return value, nil
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
