// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installerprofile

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func assertCPURefusal(t *testing.T, body []byte, want CPURefusal) {
	t.Helper()
	summary, reason, err := SummarizeCPUWithDiagnostic(body, "/owned/installer")
	old, oldErr := SummarizeCPU(body, "/owned/installer")
	if err != errIncomplete || oldErr != errIncomplete || !reflect.DeepEqual(summary, CPUSummary{}) || !reflect.DeepEqual(old, summary) || reason != want || !reason.Valid() {
		t.Fatal("CPU refusal changed public error, exposed partial summary or lost exact fixed reason")
	}
	encoded, marshalErr := json.Marshal(reason)
	if marshalErr != nil || bytes.Contains(encoded, []byte("CANARY")) || bytes.Contains(encoded, []byte("/")) || len(encoded) > 24 {
		t.Fatal("CPU refusal escaped fixed numeric privacy boundary")
	}
}

func TestCPURefusalCategoriesAndFirstEncounteredCheck(t *testing.T) {
	valid := cpuGzip(t, newCPUFixture(true).wire(), nil)
	for name, body := range map[string][]byte{
		"empty":                    nil,
		"envelope-before-trailing": append(cpuGzip(t, newCPUFixture(true).wire(), func(w *gzip.Writer) { w.Name = "PRIVATE-CANARY" }), 0),
	} {
		t.Run(name, func(t *testing.T) { assertCPURefusal(t, body, CPURefusal{Stage: CPURefusalEnvelope}) })
	}
	t.Run("expansion-trailing", func(t *testing.T) {
		assertCPURefusal(t, append(bytes.Clone(valid), 0), CPURefusal{Stage: CPURefusalExpansion})
	})
	cases := []struct {
		name   string
		stage  uint8
		mutate func(*cpuFixture)
	}{
		{"protobuf", CPURefusalProtobuf, func(f *cpuFixture) { f.extra = []byte{0x80} }},
		{"nested-protobuf", CPURefusalProtobuf, func(f *cpuFixture) { f.functions[0] = []byte{0x80} }},
		{"reference", CPURefusalReference, func(f *cpuFixture) { f.functions[0] = cpuRecord(1, 999, 999, 7, 10) }},
		{"sample-reference", CPURefusalReference, func(f *cpuFixture) {
			f.samples[0] = append(cpuIntegers(1, true, 999), cpuIntegers(2, true, 1, cpuPeriod)...)
		}},
		{"schema-private-label", CPURefusalSchema, func(f *cpuFixture) { f.samples[0] = append(f.samples[0], cpuBytes(3, []byte("PRIVATE-CANARY"))...) }},
		{"schema-mapping", CPURefusalSchema, func(f *cpuFixture) { f.strings[5] = "/private/MAPPING-CANARY" }},
		{"accounting", CPURefusalAccounting, func(f *cpuFixture) { f.samples[0] = cpuIntegers(2, true, 2, cpuPeriod) }},
		{"empty-accounting", CPURefusalAccounting, func(f *cpuFixture) { f.samples = [][]byte{cpuIntegers(2, true, 0, 0)} }},
	}
	for _, scenario := range cases {
		t.Run(scenario.name, func(t *testing.T) {
			fixture := newCPUFixture(true)
			scenario.mutate(&fixture)
			assertCPURefusal(t, cpuGzip(t, fixture.wire(), nil), CPURefusal{Stage: scenario.stage})
		})
	}
	for _, packed := range []bool{false, true} {
		body := cpuGzip(t, newCPUFixture(packed).wire(), nil)
		summary, reason, err := SummarizeCPUWithDiagnostic(body, "/owned/installer")
		old, oldErr := SummarizeCPU(body, "/owned/installer")
		if err != nil || oldErr != nil || reason != (CPURefusal{}) || !reflect.DeepEqual(old, summary) {
			t.Fatal("successful CPU parser changed summary or invented a refusal")
		}
	}
}

func TestCPURefusalEveryWorkBoundPropagatesThroughParser(t *testing.T) {
	for _, bound := range []uint8{CPUBoundFields, CPUBoundRecords, CPUBoundStackDepth, CPUBoundStackReferences, CPUBoundInlineLines, CPUBoundExpandedWork, CPUBoundStringBytes} {
		t.Run(string(rune('0'+bound)), func(t *testing.T) {
			fixture := newCPUFixture(true)
			switch bound {
			case CPUBoundFields:
				// Unpacked fields exhaust the global budget inside a nested
				// sample before record or stack-reference bounds are reached.
				refs := make([]uint64, 16)
				for i := range refs {
					refs[i] = 1
				}
				sample := append(cpuIntegers(1, false, refs...), cpuIntegers(2, false, 1, cpuPeriod)...)
				fixture.samples = make([][]byte, 30000)
				for i := range fixture.samples {
					fixture.samples[i] = sample
				}
			case CPUBoundRecords:
				fixture.samples = make([][]byte, maxRecords+1)
				for i := range fixture.samples {
					fixture.samples[i] = cpuIntegers(2, true, 1, cpuPeriod)
				}
			case CPUBoundStackDepth, CPUBoundStackReferences, CPUBoundExpandedWork:
				depth := maxStackDepth
				if bound == CPUBoundStackDepth {
					depth++
				}
				refs := make([]uint64, depth)
				for i := range refs {
					refs[i] = 1
				}
				sample := append(cpuIntegers(1, true, refs...), cpuIntegers(2, true, 1, cpuPeriod)...)
				count := 1
				if bound == CPUBoundStackReferences {
					count = maxStackRefs/maxStackDepth + 1
				}
				if bound == CPUBoundExpandedWork {
					count = 8
					fixture.locations[0] = cpuRecord(1, 1, 4097)
					for i := 0; i < 128; i++ {
						fixture.locations[0] = append(fixture.locations[0], cpuBytes(4, cpuRecord(1, 10))...)
					}
				}
				fixture.samples = make([][]byte, count)
				for i := range fixture.samples {
					fixture.samples[i] = sample
				}
			case CPUBoundInlineLines:
				fixture.locations[0] = cpuRecord(1, 1, 4097)
				for i := 0; i < 129; i++ {
					fixture.locations[0] = append(fixture.locations[0], cpuBytes(4, cpuRecord(1, 10))...)
				}
			case CPUBoundStringBytes:
				fixture.strings[8] = strings.Repeat("x", 4097)
			}
			assertCPURefusal(t, cpuGzip(t, fixture.wire(), nil), CPURefusal{Stage: CPURefusalWork, Bound: bound})
		})
	}
}

func TestCPURefusalClosedNumericDomain(t *testing.T) {
	for stage := 0; stage < 256; stage++ {
		for bound := 0; bound < 256; bound++ {
			reason := CPURefusal{Stage: uint8(stage), Bound: uint8(bound)}
			want := stage <= 7 && bound == 0 && stage != 6 || stage == 6 && bound >= 1 && bound <= 7
			if reason.Valid() != want {
				t.Fatal("CPU refusal admitted an unreviewed numeric code")
			}
		}
	}
	for _, reason := range []CPURefusal{{Stage: 8}, {Bound: 1}, {Stage: CPURefusalWork}, {Stage: CPURefusalWork, Bound: 8}, {Stage: CPURefusalSchema, Bound: 1}} {
		if body, err := json.Marshal(reason); err == nil || len(body) != 0 {
			t.Fatal("caller-constructed unreviewed refusal serialized")
		}
	}
}
