// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"

	strictjson "sigs.k8s.io/json"
)

// Independent oracle: the original production Decoder.Token implementation.
func originalBoundedJSON(raw []byte) bool {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	depth, nodes := 0, 0
	for {
		token, err := d.Token()
		if err == io.EOF {
			return depth == 0
		}
		if err != nil {
			return false
		}
		nodes++
		if nodes > 200000 {
			return false
		}
		if delimiter, ok := token.(json.Delim); ok {
			switch delimiter {
			case '{', '[':
				depth++
			case '}', ']':
				depth--
			}
			if depth > 64 || depth < 0 {
				return false
			}
		}
	}
}

func boundedJSONArray(elements int) []byte {
	return []byte("[" + strings.Repeat("0,", elements-1) + "0]")
}

func TestBoundedJSONSingleValueTokenOracleAndWireBounds(t *testing.T) {
	cases := [][]byte{
		[]byte(`{}`), []byte(`[]`), []byte(`null`), []byte(`true`), []byte(`false`),
		[]byte(`-123.456e+789`), []byte(`1e999999999`), []byte(`""`),
		[]byte(`{"a":[1,true,false,null,{},[]],"b":"[]{}:,"}`),
		[]byte(`{"a":"\\\"[]{}","b":"\u0022\u005b\uD800","c":"é😀"}`),
		[]byte(`{"duplicate":0,"duplicate":1}`),
		[]byte{'"', 0xff, '"'},
		[]byte(" \t\r\n{} \t\r\n"), nil, []byte(" \t\r\n"),
		[]byte(`{} {}`), []byte(`0 1`), []byte(`null[]`),
		[]byte(`{"a":`), []byte(`{"a" 1}`), []byte(`{"a":01}`),
		[]byte(`{"a":"\x"}`), []byte("\"unterminated\\"),
		[]byte(`[}`), []byte(`][`), []byte(`[0,]`), []byte(`NaN`),
	}
	for _, raw := range cases {
		want := json.Valid(raw) && originalBoundedJSON(raw)
		if boundedJSON(raw) != want {
			t.Fatal("token/depth prevalidation differs from the original single-value oracle")
		}
	}
	for _, depth := range []int{63, 64, 65} {
		raw := []byte(strings.Repeat("[", depth) + "0" + strings.Repeat("]", depth))
		if boundedJSON(raw) != (depth <= 64) || boundedJSON(raw) != originalBoundedJSON(raw) {
			t.Fatal("inclusive depth boundary changed")
		}
		var opening, closing strings.Builder
		for i := range depth {
			if i%2 == 0 {
				opening.WriteString(`{"key":`)
			} else {
				opening.WriteByte('[')
			}
		}
		for i := depth - 1; i >= 0; i-- {
			if i%2 == 0 {
				closing.WriteByte('}')
			} else {
				closing.WriteByte(']')
			}
		}
		raw = []byte(opening.String() + "0" + closing.String())
		if boundedJSON(raw) != (depth <= 64) || boundedJSON(raw) != originalBoundedJSON(raw) {
			t.Fatal("mixed object/array depth boundary changed")
		}
	}
	for _, count := range []int{1, 2, 3, 4, 63, 64, 65, 4095, 4096} {
		raw, err := json.Marshal(strings.Repeat("\\", count) + `"[]{}:,`)
		if err != nil || !boundedJSON(raw) || !originalBoundedJSON(raw) {
			t.Fatal("odd/even backslash or escaped quote changed token counts")
		}
	}
	for _, tokens := range []int{199999, 200000, 200001} {
		raw := boundedJSONArray(tokens - 2) // Both array delimiters count.
		if boundedJSON(raw) != (tokens <= 200000) || boundedJSON(raw) != originalBoundedJSON(raw) {
			t.Fatal("inclusive token boundary changed")
		}
	}
	// An object key is a token too: this object has exactly 200000 tokens.
	raw := []byte(`{"key":` + string(boundedJSONArray(199995)) + `}`)
	if !boundedJSON(raw) || !originalBoundedJSON(raw) {
		t.Fatal("object key/delimiter counting changed")
	}
	raw = []byte(`{"key":` + string(boundedJSONArray(199996)) + `}`)
	if boundedJSON(raw) || originalBoundedJSON(raw) {
		t.Fatal("object key escaped the token bound")
	}
	// The old prevalidator accepted streams/empty input, but every actual
	// caller's strict single-value decode refused them. Preserve wire refusal.
	for _, raw := range [][]byte{nil, []byte(" "), []byte(`{} {}`), []byte(`0 1`)} {
		var out any
		if _, err := strictjson.UnmarshalStrict(raw, &out); err == nil || boundedJSON(raw) {
			t.Fatal("empty or multiple JSON values accepted")
		}
	}
	// Grammar validation is not duplicate validation; the SAME strict decode
	// remains mandatory and independently rejects duplicate keys afterward.
	raw = []byte(`{"duplicate":0,"duplicate":1}`)
	var out map[string]any
	strictErrors, err := strictjson.UnmarshalStrict(raw, &out)
	if !boundedJSON(raw) || err != nil || len(strictErrors) == 0 {
		t.Fatal("strict duplicate-field refusal changed")
	}
}

func FuzzBoundedJSONSingleValueTokenOracle(f *testing.F) {
	for _, raw := range [][]byte{[]byte(`{}`), []byte(`{"key":[true,0,"\\\"[]"]}`), []byte(`[]{} `), []byte("\"unterminated\\"), []byte(strings.Repeat("[", 65) + "0" + strings.Repeat("]", 65))} {
		f.Add(raw)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 1024*1024 {
			t.Skip() // Same production response byte bound; not an input truncation.
		}
		if boundedJSON(raw) != (json.Valid(raw) && originalBoundedJSON(raw)) {
			t.Fatal("bounded scan differs from standard grammar/original token oracle")
		}
	})
}

func BenchmarkBoundedJSONTokenScan(b *testing.B) {
	for _, test := range []struct {
		name string
		raw  []byte
	}{
		{"policy-like", []byte(`{"spec":{"validations":[{"expression":"` + strings.Repeat("x[]{}:,\\\"", 4096) + `"}]}}`)},
		{"limit-array", boundedJSONArray(199998)},
	} {
		for _, scan := range []struct {
			name string
			fn   func([]byte) bool
		}{
			{"original", originalBoundedJSON}, {"bounded", boundedJSON},
		} {
			b.Run(test.name+"/"+scan.name, func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					if !scan.fn(test.raw) {
						b.Fatal("representative JSON refused")
					}
				}
			})
		}
	}
}
