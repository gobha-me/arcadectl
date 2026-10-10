// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package canonicaljson

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestExactEquivalentNumbers(t *testing.T) {
	for _, input := range []string{`{"z":-0.0,"a":9007199254740993,"n":20}`, `{"n":2e1,"a":9007199254740993,"z":0}`} {
		value, err := CanonicalJSON([]byte(input))
		if err != nil || string(value) != `{"a":9007199254740993,"n":20,"z":0}` {
			t.Fatal("exact canonical value changed")
		}
	}
}

func TestBoundedStrictJSON(t *testing.T) {
	for _, input := range []string{`{"a":1,"a":2}`, `{"a":1,"\u0061":2}`, `{}` + `{}`, `1e4097`, strings.Repeat("[", 34) + "0" + strings.Repeat("]", 34), strings.Repeat(" ", MaxBytes+1), string([]byte{'"', 255, '"'})} {
		if _, err := CanonicalJSON([]byte(input)); err != ErrInvalid {
			t.Fatal("unsafe JSON accepted or unsafe error returned")
		}
	}
}

func TestEvidenceCanonicalJSONKeepsOrdinaryBoundsAndStrictness(t *testing.T) {
	input := []byte(`{"publicIdentity":"` + strings.Repeat("x", MaxBytes) + `"}`)
	if _, err := CanonicalJSON(input); err != ErrInvalid {
		t.Fatal("ordinary JSON limit expanded")
	}
	if got, err := CanonicalEvidenceJSON(input); err != nil || string(got) != string(input) {
		t.Fatal("bounded public evidence rejected")
	}
	for _, input := range []string{`{"a":1,"a":2}`, `{"a":1,"\u0061":2}`, `{}` + `{}`, `1e4097`, strings.Repeat("[", 34) + "0" + strings.Repeat("]", 34), string([]byte{'"', 255, '"'})} {
		if _, err := CanonicalEvidenceJSON([]byte(input)); err != ErrInvalid {
			t.Fatal("evidence codec relaxed ambiguity/depth/number/UTF8 protection")
		}
	}
	large := []byte(`"` + strings.Repeat("x", MaxEvidenceBytes-2) + `"`)
	if got, err := CanonicalEvidenceJSON(large); err != nil || len(got) != MaxEvidenceBytes {
		t.Fatal("exact evidence hard limit refused")
	}
	if _, err := CanonicalEvidenceJSON(append(large, ' ')); err != ErrInvalid {
		t.Fatal("oversized evidence accepted")
	}
}

func TestEvidenceCanonicalOutputBudgetRejectsExpansionBeforeWholeDecode(t *testing.T) {
	// About 140KiB input would produce over 80MiB canonical numbers. Larger
	// valid input must not allocate a multi-GiB value graph before refusing.
	input := []byte("[" + strings.Repeat("1e4096,", 19999) + "1e4096]")
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.UseNumber()
	budget := MaxEvidenceBytes
	if _, err := decodeValue(decoder, 0, &budget); err != ErrInvalid || decoder.InputOffset() >= int64(len(input)) {
		t.Fatal("canonical expansion not refused during bounded decoding")
	}
	if _, err := CanonicalEvidenceJSON(input); err != ErrInvalid {
		t.Fatal("expanded evidence exceeded canonical-output budget")
	}
	// Escaping, punctuation, booleans and null are charged exactly too.
	for _, input := range []string{`{"z":[true,false,null,"<>&\n"],"a":1e3}`, `[]`, `{}`, `"\u0000"`} {
		body, err := CanonicalJSON([]byte(input))
		if err != nil {
			t.Fatal("ordinary canonical control unavailable")
		}
		if exact, err := canonicalBounded([]byte(input), len(body)); err != nil || !bytes.Equal(exact, body) {
			t.Fatal("exact canonical output budget refused")
		}
		if _, err := canonicalBounded([]byte(input), len(body)-1); err != ErrInvalid {
			t.Fatal("canonical output escaped exact budget")
		}
	}
}
