// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installerprofile

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Independent test encoder: do not reuse protowire or production decoders.
func cpuVarint(number int, value uint64) []byte {
	result := binary.AppendUvarint(nil, uint64(number<<3))
	return binary.AppendUvarint(result, value)
}
func cpuBytes(number int, data []byte) []byte {
	result := binary.AppendUvarint(nil, uint64(number<<3|2))
	result = binary.AppendUvarint(result, uint64(len(data)))
	return append(result, data...)
}
func cpuRecord(values ...uint64) []byte {
	var result []byte
	for i, value := range values {
		if value != 0 {
			result = append(result, cpuVarint(i+1, value)...)
		}
	}
	return result
}
func cpuIntegers(number int, packed bool, values ...uint64) []byte {
	var result []byte
	for _, value := range values {
		if packed {
			result = binary.AppendUvarint(result, value)
		} else {
			result = append(result, cpuVarint(number, value)...)
		}
	}
	if packed {
		return cpuBytes(number, result)
	}
	return result
}

type cpuFixture struct {
	types, samples, mappings, locations, functions [][]byte
	strings                                        []string
	extra                                          []byte
	period, duration                               uint64
}

func newCPUFixture(packed bool) cpuFixture {
	location := func(id, function uint64) []byte {
		result := cpuRecord(id, 1, 4096+id)
		return append(result, cpuBytes(4, cpuRecord(function, 10))...)
	}
	sample := append(cpuIntegers(1, packed, 1, 2, 1), cpuIntegers(2, packed, 2, 2*cpuPeriod)...)
	return cpuFixture{
		types:     [][]byte{cpuRecord(1, 2), cpuRecord(3, 4)},
		samples:   [][]byte{sample, cpuIntegers(2, packed, 1, cpuPeriod)},
		mappings:  [][]byte{cpuRecord(1, 4096, 8192, 0, 5, 0, 1)},
		locations: [][]byte{location(1, 1), location(2, 2)},
		functions: [][]byte{cpuRecord(1, 6, 6, 7, 10), cpuRecord(2, 8, 8, 9, 20)},
		strings:   []string{"", "samples", "count", "cpu", "nanoseconds", "/owned/installer", "runtime.gcBgMarkWorker", "runtime/mgc.go", "PRIVATE-SYMBOL-CANARY", "/private/SOURCE-CANARY.go"},
		period:    cpuPeriod, duration: 1, // CPU may exceed wall time on several threads.
	}
}
func (f cpuFixture) wire() []byte {
	var result []byte
	for tag, group := range [][][]byte{f.types, f.samples, f.mappings, f.locations, f.functions} {
		for _, record := range group {
			result = append(result, cpuBytes(tag+1, record)...)
		}
	}
	for _, value := range f.strings {
		result = append(result, cpuBytes(6, []byte(value))...)
	}
	result = append(result, cpuVarint(9, 1)...)
	result = append(result, cpuVarint(10, f.duration)...)
	result = append(result, cpuBytes(11, cpuRecord(3, 4))...)
	result = append(result, cpuVarint(12, f.period)...)
	return append(result, f.extra...)
}
func cpuGzip(t *testing.T, wire []byte, edit func(*gzip.Writer)) []byte {
	t.Helper()
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if edit != nil {
		edit(writer)
	}
	if _, err := writer.Write(wire); err != nil || writer.Close() != nil {
		t.Fatal("owned CPU fixture compression failed")
	}
	return compressed.Bytes()
}

func TestCPUFixedSummaryPackedUnpackedAndPrivacy(t *testing.T) {
	want := CPUSummary{Samples: 3, CPUNanoseconds: 3 * cpuPeriod, DurationNanoseconds: 1, Buckets: []CPUBucket{
		{Category: "other", CumulativeNanoseconds: 2 * cpuPeriod},
		{Category: "runtime-gc", FlatNanoseconds: 2 * cpuPeriod, CumulativeNanoseconds: 2 * cpuPeriod},
		{Category: "unresolved", FlatNanoseconds: cpuPeriod, CumulativeNanoseconds: cpuPeriod},
	}}
	for _, packed := range []bool{false, true} {
		fixture := newCPUFixture(packed)
		for repeat := 0; repeat < 3; repeat++ {
			got, err := SummarizeCPU(cpuGzip(t, fixture.wire(), nil), "/owned/installer")
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatal("independent CPU fixture did not produce exact deterministic numeric summary")
			}
			encoded, err := json.Marshal(got)
			if err != nil || bytes.Contains(encoded, []byte("CANARY")) || bytes.Contains(encoded, []byte("/")) || bytes.Contains(encoded, []byte("gcBgMarkWorker")) {
				t.Fatal("profile strings escaped closed summary")
			}
		}
	}
}

func TestCPUSchemaReferencesAndArithmeticRefuse(t *testing.T) {
	cases := map[string]func(*cpuFixture){
		"labels-even-empty":     func(f *cpuFixture) { f.samples[0] = append(f.samples[0], cpuBytes(3, nil)...) },
		"comments":              func(f *cpuFixture) { f.extra = cpuVarint(13, 0) },
		"drop-frames":           func(f *cpuFixture) { f.extra = cpuVarint(7, 0) },
		"keep-frames":           func(f *cpuFixture) { f.extra = cpuVarint(8, 0) },
		"default-type":          func(f *cpuFixture) { f.extra = cpuVarint(14, 0) },
		"unknown":               func(f *cpuFixture) { f.extra = cpuBytes(15, nil) },
		"duplicate-period":      func(f *cpuFixture) { f.extra = cpuVarint(12, cpuPeriod) },
		"duplicate-period-type": func(f *cpuFixture) { f.extra = cpuBytes(11, cpuRecord(3, 4)) },
		"duplicate-time":        func(f *cpuFixture) { f.extra = cpuVarint(9, 1) },
		"wrong-scalar-wire":     func(f *cpuFixture) { f.extra = cpuBytes(9, nil) },
		"nonminimal-tag":        func(f *cpuFixture) { f.extra = []byte{0xe0, 0x80, 0x00, 0x01} },
		"nonminimal-value":      func(f *cpuFixture) { f.extra = []byte{0x78, 0x80, 0x00} },
		"truncated-varint":      func(f *cpuFixture) { f.extra = []byte{0x80} },
		"varint-overflow":       func(f *cpuFixture) { f.extra = bytes.Repeat([]byte{0xff}, 11) },
		"bad-length":            func(f *cpuFixture) { f.extra = []byte{0x7a, 0x05, 0x01} },
		"negative-duration":     func(f *cpuFixture) { f.duration = math.MaxUint64 },
		"zero-duration":         func(f *cpuFixture) { f.duration = 0 },
		"wrong-period":          func(f *cpuFixture) { f.period++ },
		"wrong-unit":            func(f *cpuFixture) { f.strings[4] = "bytes" },
		"wrong-sample-order":    func(f *cpuFixture) { f.types[0], f.types[1] = f.types[1], f.types[0] },
		"third-sample-type":     func(f *cpuFixture) { f.types = append(f.types, cpuRecord(3, 4)) },
		"wrong-cpu-product":     func(f *cpuFixture) { f.samples[0] = cpuIntegers(2, true, 2, cpuPeriod) },
		"multiply-overflow":     func(f *cpuFixture) { f.samples[0] = cpuIntegers(2, true, math.MaxInt64, 1) },
		"no-usable-samples":     func(f *cpuFixture) { f.samples = [][]byte{cpuIntegers(2, false, 0, 0)} },
		"three-values":          func(f *cpuFixture) { f.samples[0] = cpuIntegers(2, true, 1, cpuPeriod, 0) },
		"one-value":             func(f *cpuFixture) { f.samples[0] = cpuIntegers(2, false, 1) },
		"missing-location": func(f *cpuFixture) {
			f.samples[0] = append(cpuIntegers(1, true, 999), cpuIntegers(2, false, 1, cpuPeriod)...)
		},
		"missing-function": func(f *cpuFixture) {
			f.locations[0] = append(cpuRecord(1, 1, 4097), cpuBytes(4, cpuRecord(999, 10))...)
		},
		"missing-mapping": func(f *cpuFixture) {
			f.locations[0] = append(cpuRecord(1, 999, 4097), cpuBytes(4, cpuRecord(1, 10))...)
		},
		"address-outside-mapping": func(f *cpuFixture) { f.locations[0] = append(cpuRecord(1, 1, 8192), cpuBytes(4, cpuRecord(1, 10))...) },
		"duplicate-location":      func(f *cpuFixture) { f.locations = append(f.locations, f.locations[0]) },
		"duplicate-function":      func(f *cpuFixture) { f.functions = append(f.functions, f.functions[0]) },
		"duplicate-mapping":       func(f *cpuFixture) { f.mappings = append(f.mappings, f.mappings[0]) },
		"duplicate-singular":      func(f *cpuFixture) { f.functions[0] = append(f.functions[0], cpuVarint(1, 1)...) },
		"unexpected-mapping":      func(f *cpuFixture) { f.strings[5] = "/private/MAPPING-CANARY" },
		"mapping-bool":            func(f *cpuFixture) { f.mappings[0] = cpuRecord(1, 4096, 8192, 0, 5, 0, 2) },
		"mapping-future-field":    func(f *cpuFixture) { f.mappings[0] = append(f.mappings[0], cpuVarint(8, 1)...) },
		"function-system-name":    func(f *cpuFixture) { f.functions[0] = cpuRecord(1, 6, 8, 7, 10) },
		"out-of-range-string":     func(f *cpuFixture) { f.functions[0] = cpuRecord(1, 999, 999, 7, 10) },
		"nonempty-zero-string":    func(f *cpuFixture) { f.strings[0] = "CANARY" },
		"unreferenced-string":     func(f *cpuFixture) { f.strings = append(f.strings, "CANARY") },
		"string-control":          func(f *cpuFixture) { f.strings[8] = "CANARY\x00" },
		"invalid-utf8":            func(f *cpuFixture) { f.strings[8] = "\xff" },
		"overlong-string":         func(f *cpuFixture) { f.strings[8] = strings.Repeat("x", 4097) },
		"overlong-stack": func(f *cpuFixture) {
			f.samples[0] = append(cpuIntegers(1, true, make([]uint64, maxStackDepth+1)...), cpuIntegers(2, false, 1, cpuPeriod)...)
		},
		"too-many-strings": func(f *cpuFixture) { f.strings = append(f.strings, make([]string, maxRecords)...) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			fixture := newCPUFixture(true)
			mutate(&fixture)
			got, err := SummarizeCPU(cpuGzip(t, fixture.wire(), nil), "/owned/installer")
			if err == nil || !reflect.DeepEqual(got, CPUSummary{}) {
				t.Fatal("malformed/private CPU input produced a summary")
			}
		})
	}
}

func TestCPUCompressionAndBoundsRefuse(t *testing.T) {
	valid := cpuGzip(t, newCPUFixture(false).wire(), nil)
	cases := map[string][]byte{
		"empty": nil, "oversize-compressed": make([]byte, MaxProfileBytes+1),
		"truncated": valid[:len(valid)-1], "trailing": append(bytes.Clone(valid), 0),
		"second-member": append(bytes.Clone(valid), valid...),
		"name":          cpuGzip(t, newCPUFixture(false).wire(), func(w *gzip.Writer) { w.Name = "CANARY" }),
		"comment":       cpuGzip(t, newCPUFixture(false).wire(), func(w *gzip.Writer) { w.Comment = "CANARY" }),
		"extra":         cpuGzip(t, newCPUFixture(false).wire(), func(w *gzip.Writer) { w.Extra = []byte("CANARY") }),
		"time":          cpuGzip(t, newCPUFixture(false).wire(), func(w *gzip.Writer) { w.ModTime = time.Unix(1, 0) }),
		"expansion":     cpuGzip(t, make([]byte, maxDecodedBytes+1), nil),
	}
	checksum := bytes.Clone(valid)
	checksum[len(checksum)-8] ^= 1
	cases["checksum"] = checksum
	for name, compressed := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := SummarizeCPU(compressed, "/owned/installer"); err == nil {
				t.Fatal("incomplete/unbounded CPU gzip accepted")
			}
		})
	}
	if _, err := SummarizeCPU(valid, "/different/installer"); err == nil {
		t.Fatal("wrong executable mapping accepted")
	}
	fields := maxFields
	cursor := wireCursor{data: cpuVarint(1, 1), fields: &fields}
	if _, err := cursor.next(); err == nil {
		t.Fatal("global field allowance exceeded")
	}
}

func TestCPUAttributionUsesActualReviewedCopiersAndLiteralLabels(t *testing.T) {
	for _, symbol := range []string{
		"github.com/gobha-me/arcadectl/internal/installrender.(*Plan).Resources",
		"github.com/gobha-me/arcadectl/internal/installrender.(*Plan).ResourcesByKind",
	} {
		fixture := newCPUFixture(false)
		fixture.strings[6] = symbol
		got, err := SummarizeCPU(cpuGzip(t, fixture.wire(), nil), "/owned/installer")
		if err != nil {
			t.Fatal("reviewed copier profile refused")
		}
		found := false
		for _, bucket := range got.Buckets {
			if bucket.Category == "template-copy" && bucket.FlatNanoseconds == 2*cpuPeriod {
				found = true
			}
		}
		if !found {
			t.Fatal("actual defensive copier omitted from literal attribution")
		}
	}
}

func TestCPUExpandedInlineAttributionWorkBoundIsReached(t *testing.T) {
	for _, samples := range []int{7, 8} {
		fixture := newCPUFixture(true)
		location := cpuRecord(1, 1, 4097)
		for lines := 0; lines < 128; lines++ {
			location = append(location, cpuBytes(4, cpuRecord(1, 10))...)
		}
		fixture.locations[0] = location
		refs := make([]uint64, maxStackDepth)
		for i := range refs {
			refs[i] = 1
		}
		sample := append(cpuIntegers(1, true, refs...), cpuIntegers(2, true, 1, cpuPeriod)...)
		fixture.samples = nil
		for i := 0; i < samples; i++ {
			fixture.samples = append(fixture.samples, sample)
		}
		got, err := SummarizeCPU(cpuGzip(t, fixture.wire(), nil), "/owned/installer")
		if samples == 7 {
			if err != nil || got.Samples != 7 || got.CPUNanoseconds != 7*cpuPeriod || len(got.Buckets) != 1 || got.Buckets[0].Category != "runtime-gc" {
				t.Fatal("below-cap expanded inline fixture refused or misattributed")
			}
		} else if err == nil || !reflect.DeepEqual(got, CPUSummary{}) {
			t.Fatal("over-cap expanded inline work was not refused")
		}
	}
}

func TestCPUJSONCannotPublishCallerConstructedPrivateCategories(t *testing.T) {
	valid := CPUSummary{Samples: 1, CPUNanoseconds: cpuPeriod, DurationNanoseconds: 1, Buckets: []CPUBucket{{Category: "other", FlatNanoseconds: cpuPeriod, CumulativeNanoseconds: cpuPeriod}}}
	for _, mutate := range []func(*CPUSummary){
		func(s *CPUSummary) { s.Buckets[0].Category = "PRIVATE-CANARY" },
		func(s *CPUSummary) { s.Buckets[0].FlatNanoseconds++ },
		func(s *CPUSummary) { s.Buckets[0].CumulativeNanoseconds-- },
		func(s *CPUSummary) { s.Samples++ },
		func(s *CPUSummary) { s.Buckets = append(s.Buckets, s.Buckets[0]) },
	} {
		summary := valid
		summary.Buckets = append([]CPUBucket(nil), valid.Buckets...)
		mutate(&summary)
		if body, err := json.Marshal(summary); err == nil || len(body) != 0 {
			t.Fatal("caller-constructed private/malformed summary published")
		}
	}
}
