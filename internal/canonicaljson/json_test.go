// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package canonicaljson

import (
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
