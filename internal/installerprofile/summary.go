// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installerprofile

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"math"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"google.golang.org/protobuf/encoding/protowire"
)

const (
	maxDecodedBytes = 32 * 1024 * 1024
	maxRecords      = 32768
	maxFields       = 524288
	maxStackDepth   = 512
	maxStackRefs    = 524288
	cpuPeriod       = 10000000 // The pinned Go CPU producer samples at 100Hz.
)

// CPUSummary contains only numeric data and literal reviewed attribution labels.
// It never copies symbols, paths, addresses, build IDs, labels or other profile
// strings. Cumulative buckets overlap: they must not be added together.
// CPU samples do not attribute limiter/network/filesystem sleep or prove a cure.
type CPUSummary struct {
	Samples             uint64      `json:"samples"`
	CPUNanoseconds      uint64      `json:"cpuNanoseconds"`
	DurationNanoseconds uint64      `json:"durationNanoseconds"`
	Buckets             []CPUBucket `json:"buckets"`
}

type CPUBucket struct {
	Category              string `json:"category"`
	FlatNanoseconds       uint64 `json:"flatNanoseconds"`
	CumulativeNanoseconds uint64 `json:"cumulativeNanoseconds"`
}

// MarshalJSON maintains the summary-only non-disclosure boundary even if a
// future caller constructs the exported value rather than using SummarizeCPU.
func (s CPUSummary) MarshalJSON() ([]byte, error) {
	if s.Samples == 0 || s.Samples > math.MaxInt64/cpuPeriod || s.CPUNanoseconds != s.Samples*cpuPeriod || s.DurationNanoseconds == 0 || s.DurationNanoseconds > math.MaxInt64 || len(s.Buckets) == 0 || len(s.Buckets) > 16 {
		return nil, errIncomplete
	}
	var flat uint64
	last := ""
	for _, bucket := range s.Buckets {
		switch bucket.Category {
		case "state-decode", "template-copy", "runtime-gc", "runtime", "json", "tls", "http", "client-go", "apimachinery", "installengine", "installbaseline", "installrender", "installstate", "other", "unresolved":
		default:
			return nil, errIncomplete
		}
		if bucket.Category <= last || bucket.FlatNanoseconds > bucket.CumulativeNanoseconds || bucket.CumulativeNanoseconds > s.CPUNanoseconds || flat > s.CPUNanoseconds-bucket.FlatNanoseconds {
			return nil, errIncomplete
		}
		flat += bucket.FlatNanoseconds
		last = bucket.Category
	}
	if flat != s.CPUNanoseconds {
		return nil, errIncomplete
	}
	type numericSummary CPUSummary
	return json.Marshal(numericSummary(s))
}

type wireField struct {
	number int
	kind   protowire.Type
	scalar uint64
	data   []byte
}
type wireCursor struct {
	data   []byte
	fields *int
}

func (c *wireCursor) next() (wireField, error) {
	var field wireField
	if len(c.data) == 0 {
		return field, refuseCPU(CPURefusalProtobuf)
	}
	if *c.fields >= maxFields {
		return field, refuseCPUWork(CPUBoundFields)
	}
	*c.fields++
	tag, n := protowire.ConsumeVarint(c.data)
	if n < 1 || n != protowire.SizeVarint(tag) || tag>>3 == 0 || tag>>3 > 536870911 {
		return field, refuseCPU(CPURefusalProtobuf)
	}
	c.data = c.data[n:]
	field.number, field.kind = int(tag>>3), protowire.Type(tag&7)
	switch field.kind {
	case protowire.VarintType:
		value, n := protowire.ConsumeVarint(c.data)
		if n < 1 || n != protowire.SizeVarint(value) {
			return field, refuseCPU(CPURefusalProtobuf)
		}
		field.scalar, c.data = value, c.data[n:]
	case protowire.BytesType:
		length, n := protowire.ConsumeVarint(c.data)
		if n < 1 || n != protowire.SizeVarint(length) || length > uint64(len(c.data)-n) {
			return field, refuseCPU(CPURefusalProtobuf)
		}
		field.data, c.data = c.data[n:n+int(length)], c.data[n+int(length):]
	default:
		return field, refuseCPU(CPURefusalProtobuf)
	}
	return field, nil
}

type record [8]uint64
type cpuLocation struct {
	values record
	lines  []record
}
type cpuSample struct {
	locations []uint64
	values    []uint64
}
type cpuProfile struct {
	types               []record
	periodType          record
	period, duration    uint64
	strings             []string
	mappings, functions map[uint64]record
	locations           map[uint64]cpuLocation
	samples             []cpuSample
	fields, refs        int
}

func parseRecord(data []byte, allowed uint16, fields *int) (record, error) {
	var values record
	var seen uint16
	c := wireCursor{data, fields}
	for len(c.data) != 0 {
		field, err := c.next()
		if err != nil {
			return record{}, err
		}
		if field.number >= len(values) || allowed&(1<<field.number) == 0 || seen&(1<<field.number) != 0 || field.kind != protowire.VarintType {
			return record{}, refuseCPU(CPURefusalProtobuf)
		}
		seen |= 1 << field.number
		values[field.number] = field.scalar
	}
	return values, nil
}

func repeatedInts(field wireField, values []uint64, limit int) ([]uint64, error) {
	if field.kind == protowire.VarintType {
		if len(values) == limit {
			if limit == maxStackDepth {
				return nil, refuseCPUWork(CPUBoundStackDepth)
			}
			return nil, refuseCPU(CPURefusalSchema)
		}
		return append(values, field.scalar), nil
	}
	if field.kind != protowire.BytesType || len(field.data) == 0 {
		return nil, refuseCPU(CPURefusalProtobuf)
	}
	for len(field.data) != 0 {
		value, n := protowire.ConsumeVarint(field.data)
		if n < 1 || n != protowire.SizeVarint(value) {
			return nil, refuseCPU(CPURefusalProtobuf)
		}
		if len(values) == limit {
			if limit == maxStackDepth {
				return nil, refuseCPUWork(CPUBoundStackDepth)
			}
			return nil, refuseCPU(CPURefusalSchema)
		}
		values, field.data = append(values, value), field.data[n:]
	}
	return values, nil
}

func (p *cpuProfile) sample(data []byte) error {
	var sample cpuSample
	c := wireCursor{data, &p.fields}
	for len(c.data) != 0 {
		field, err := c.next()
		if err != nil {
			return err
		}
		switch field.number {
		case 1:
			sample.locations, err = repeatedInts(field, sample.locations, maxStackDepth)
		case 2:
			sample.values, err = repeatedInts(field, sample.values, 2)
		default:
			return refuseCPU(CPURefusalSchema) // Labels, even empty, are always refused.
		}
		if err != nil {
			return err
		}
	}
	p.refs += len(sample.locations)
	if len(sample.values) != 2 {
		return refuseCPU(CPURefusalSchema)
	}
	if p.refs > maxStackRefs {
		return refuseCPUWork(CPUBoundStackReferences)
	}
	if len(p.samples) >= maxRecords {
		return refuseCPUWork(CPUBoundRecords)
	}
	p.samples = append(p.samples, sample)
	return nil
}

func (p *cpuProfile) location(data []byte) error {
	var location cpuLocation
	var seen uint16
	c := wireCursor{data, &p.fields}
	for len(c.data) != 0 {
		field, err := c.next()
		if err != nil {
			return err
		}
		if field.number == 4 {
			if field.kind != protowire.BytesType {
				return refuseCPU(CPURefusalProtobuf)
			}
			if len(location.lines) >= 128 {
				return refuseCPUWork(CPUBoundInlineLines)
			}
			line, err := parseRecord(field.data, 0x6, &p.fields)
			if err != nil {
				return err
			}
			if line[1] == 0 || line[2] > math.MaxInt64 {
				return refuseCPU(CPURefusalSchema)
			}
			location.lines = append(location.lines, line)
		} else {
			if field.number < 1 || field.number > 3 || field.kind != protowire.VarintType || seen&(1<<field.number) != 0 {
				return refuseCPU(CPURefusalProtobuf)
			}
			seen |= 1 << field.number
			location.values[field.number] = field.scalar
		}
	}
	id := location.values[1]
	if id == 0 {
		return refuseCPU(CPURefusalSchema)
	}
	if len(p.locations) >= maxRecords {
		return refuseCPUWork(CPUBoundRecords)
	}
	if _, exists := p.locations[id]; exists {
		return refuseCPU(CPURefusalProtobuf)
	}
	p.locations[id] = location
	return nil
}

func decodeCPU(data []byte) (*cpuProfile, error) {
	p := &cpuProfile{mappings: map[uint64]record{}, functions: map[uint64]record{}, locations: map[uint64]cpuLocation{}}
	c := wireCursor{data, &p.fields}
	var seen uint16
	for len(c.data) != 0 {
		field, err := c.next()
		if err != nil {
			return nil, err
		}
		if field.number == 9 || field.number == 10 || field.number == 12 {
			if field.kind != protowire.VarintType || seen&(1<<field.number) != 0 || field.scalar == 0 || field.scalar > math.MaxInt64 {
				return nil, refuseCPU(CPURefusalSchema)
			}
			seen |= 1 << field.number
			if field.number == 10 {
				p.duration = field.scalar
			}
			if field.number == 12 {
				p.period = field.scalar
			}
			continue
		}
		if field.kind != protowire.BytesType {
			return nil, refuseCPU(CPURefusalProtobuf)
		}
		switch field.number {
		case 1:
			value, err := parseRecord(field.data, 0x6, &p.fields)
			if err != nil {
				return nil, err
			}
			if len(p.types) >= 2 {
				return nil, refuseCPU(CPURefusalSchema)
			}
			p.types = append(p.types, value)
		case 2:
			if err := p.sample(field.data); err != nil {
				return nil, err
			}
		case 3, 5:
			mask := uint16(0xfe)
			if field.number == 5 {
				mask = 0x3e
			}
			value, err := parseRecord(field.data, mask, &p.fields)
			if err != nil {
				return nil, err
			}
			if value[1] == 0 {
				return nil, refuseCPU(CPURefusalSchema)
			}
			target := p.mappings
			if field.number == 5 {
				target = p.functions
			}
			if _, exists := target[value[1]]; exists {
				return nil, refuseCPU(CPURefusalProtobuf)
			}
			if len(target) >= maxRecords {
				return nil, refuseCPUWork(CPUBoundRecords)
			}
			target[value[1]] = value
		case 4:
			if err := p.location(field.data); err != nil {
				return nil, err
			}
		case 6:
			if len(field.data) > 4096 {
				return nil, refuseCPUWork(CPUBoundStringBytes)
			}
			if len(p.strings) >= maxRecords {
				return nil, refuseCPUWork(CPUBoundRecords)
			}
			if !utf8.Valid(field.data) {
				return nil, refuseCPU(CPURefusalSchema)
			}
			value := string(field.data)
			for _, r := range value {
				if unicode.IsControl(r) {
					return nil, refuseCPU(CPURefusalSchema)
				}
			}
			p.strings = append(p.strings, value)
		case 11:
			if seen&(1<<11) != 0 {
				return nil, refuseCPU(CPURefusalProtobuf)
			}
			seen |= 1 << 11
			p.periodType, err = parseRecord(field.data, 0x6, &p.fields)
			if err != nil {
				return nil, err
			}
		default:
			return nil, refuseCPU(CPURefusalSchema) // Comments/drop/keep/default/future fields.
		}
	}
	if seen != (1<<9|1<<10|1<<11|1<<12) || p.period != cpuPeriod || len(p.types) != 2 || len(p.strings) == 0 || p.strings[0] != "" {
		return nil, refuseCPU(CPURefusalSchema)
	}
	return p, nil
}

// SummarizeCPU accepts only the pinned Go CPU schema. executable is the exact
// harness-owned executable mapping, not caller-selected profile metadata. Raw
// bytes and all decoded strings remain in memory only. Nothing is emitted on a
// refusal; callers must not log parser errors or retain the input as a fallback.
// Success proves bounded CPU-format custody, NOT a timely flush/command success,
// cryptographic binary identity, or completeness under a forced process kill.
func SummarizeCPU(compressed []byte, executable string) (CPUSummary, error) {
	summary, _, err := SummarizeCPUWithDiagnostic(compressed, executable)
	return summary, err
}

func summarizeCPU(compressed []byte, executable string) (CPUSummary, error) {
	if len(compressed) == 0 || len(compressed) > MaxProfileBytes || executable == "" {
		return CPUSummary{}, refuseCPU(CPURefusalEnvelope)
	}
	reader := bytes.NewReader(compressed)
	gz, err := gzip.NewReader(reader)
	if err != nil {
		return CPUSummary{}, refuseCPU(CPURefusalEnvelope)
	}
	gz.Multistream(false)
	if gz.Name != "" || gz.Comment != "" || len(gz.Extra) != 0 || !gz.ModTime.IsZero() {
		_ = gz.Close()
		return CPUSummary{}, refuseCPU(CPURefusalEnvelope)
	}
	decoded, err := io.ReadAll(io.LimitReader(gz, maxDecodedBytes+1))
	closeErr := gz.Close()
	if err != nil || closeErr != nil || len(decoded) == 0 || len(decoded) > maxDecodedBytes || reader.Len() != 0 {
		return CPUSummary{}, refuseCPU(CPURefusalExpansion)
	}
	p, err := decodeCPU(decoded)
	if err != nil {
		return CPUSummary{}, err
	}
	return p.summarize(executable)
}

func reviewedMapping(path, executable string) bool {
	if path == executable {
		return true
	}
	switch path {
	case "[vdso]", "[vsyscall]",
		"/usr/lib/x86_64-linux-gnu/libc.so.6", "/lib/x86_64-linux-gnu/libc.so.6",
		"/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
		"/usr/lib/x86_64-linux-gnu/libpthread.so.0", "/lib/x86_64-linux-gnu/libpthread.so.0":
		return true
	}
	return false
}

func cpuCategory(symbol string) string {
	switch symbol {
	case "github.com/gobha-me/arcadectl/internal/installstate.Decode", "github.com/gobha-me/arcadectl/internal/installstate.DecodeWithBaseline":
		return "state-decode"
	case "github.com/gobha-me/arcadectl/internal/installrender.(*Plan).Resources", "github.com/gobha-me/arcadectl/internal/installrender.(*Plan).ResourcesByKind":
		return "template-copy"
	}
	for _, item := range []struct{ prefix, category string }{
		{"runtime.gc", "runtime-gc"}, {"runtime.scan", "runtime-gc"}, {"runtime.malloc", "runtime-gc"},
		{"runtime.", "runtime"}, {"encoding/json.", "json"}, {"sigs.k8s.io/json", "json"},
		{"crypto/tls.", "tls"}, {"net/http.", "http"}, {"k8s.io/client-go/", "client-go"},
		{"k8s.io/apimachinery/", "apimachinery"}, {"github.com/gobha-me/arcadectl/internal/installengine.", "installengine"},
		{"github.com/gobha-me/arcadectl/internal/installbaseline.", "installbaseline"},
		{"github.com/gobha-me/arcadectl/internal/installrender.", "installrender"},
		{"github.com/gobha-me/arcadectl/internal/installstate.", "installstate"},
	} {
		if strings.HasPrefix(symbol, item.prefix) {
			return item.category
		}
	}
	return "other" // Never copy even a syntactically plausible unknown symbol.
}

func (p *cpuProfile) summarize(executable string) (CPUSummary, error) {
	used := make([]bool, len(p.strings))
	used[0] = true
	invalidStringReference := false
	text := func(index uint64) (string, bool) {
		if index >= uint64(len(p.strings)) {
			invalidStringReference = true
			return "", false
		}
		used[index] = true
		return p.strings[index], true
	}
	valueType := func(value record, typ, unit string) bool {
		a, ok := text(value[1])
		b, good := text(value[2])
		return ok && good && a == typ && b == unit
	}
	if !valueType(p.types[0], "samples", "count") || !valueType(p.types[1], "cpu", "nanoseconds") || !valueType(p.periodType, "cpu", "nanoseconds") {
		if invalidStringReference {
			return CPUSummary{}, refuseCPU(CPURefusalReference)
		}
		return CPUSummary{}, refuseCPU(CPURefusalSchema)
	}
	haveExecutable := false
	for _, mapping := range p.mappings {
		path, ok := text(mapping[5])
		_, good := text(mapping[6])
		if !ok || !good {
			return CPUSummary{}, refuseCPU(CPURefusalReference)
		}
		if !reviewedMapping(path, executable) || mapping[2] >= mapping[3] || mapping[7] > 1 {
			return CPUSummary{}, refuseCPU(CPURefusalSchema)
		}
		haveExecutable = haveExecutable || path == executable
	}
	if !haveExecutable {
		return CPUSummary{}, refuseCPU(CPURefusalSchema)
	}
	for _, function := range p.functions {
		name, a := text(function[2])
		system, b := text(function[3])
		_, c := text(function[4])
		if !a || !b || !c {
			return CPUSummary{}, refuseCPU(CPURefusalReference)
		}
		if name != system || function[5] > math.MaxInt64 {
			return CPUSummary{}, refuseCPU(CPURefusalSchema)
		}
	}
	for _, location := range p.locations {
		if location.values[2] != 0 {
			mapping, ok := p.mappings[location.values[2]]
			if !ok || location.values[3] < mapping[2] || location.values[3] >= mapping[3] {
				return CPUSummary{}, refuseCPU(CPURefusalReference)
			}
		}
		for _, line := range location.lines {
			if _, ok := p.functions[line[1]]; !ok {
				return CPUSummary{}, refuseCPU(CPURefusalReference)
			}
		}
	}
	for _, present := range used {
		if !present {
			return CPUSummary{}, refuseCPU(CPURefusalSchema)
		}
	}
	summary := CPUSummary{DurationNanoseconds: p.duration}
	buckets := map[string]*CPUBucket{}
	work := 0
	for _, sample := range p.samples {
		count, cpu := sample.values[0], sample.values[1]
		if count > math.MaxInt64/cpuPeriod || cpu != count*cpuPeriod || summary.CPUNanoseconds > math.MaxInt64-cpu || summary.Samples > math.MaxInt64-count {
			return CPUSummary{}, refuseCPU(CPURefusalAccounting)
		}
		summary.Samples += count
		summary.CPUNanoseconds += cpu
		flat := "unresolved"
		categories := map[string]bool{}
		first := true
		for _, id := range sample.locations {
			location, ok := p.locations[id]
			if !ok {
				return CPUSummary{}, refuseCPU(CPURefusalReference)
			}
			work += 1 + len(location.lines)
			if work > maxStackRefs {
				return CPUSummary{}, refuseCPUWork(CPUBoundExpandedWork)
			}
			if len(location.lines) == 0 {
				categories["unresolved"] = true
				if first {
					flat, first = "unresolved", false
				}
			}
			for _, line := range location.lines {
				function := p.functions[line[1]]
				category := cpuCategory(p.strings[function[2]])
				categories[category] = true
				if first {
					flat, first = category, false
				}
			}
		}
		if len(categories) == 0 {
			categories["unresolved"] = true
		}
		for category := range categories {
			bucket := buckets[category]
			if bucket == nil {
				bucket = &CPUBucket{Category: category}
				buckets[category] = bucket
			}
			bucket.CumulativeNanoseconds += cpu
			if category == flat {
				bucket.FlatNanoseconds += cpu
			}
		}
	}
	if summary.Samples == 0 {
		return CPUSummary{}, refuseCPU(CPURefusalAccounting)
	} // Too short is unavailable, not installer failure.
	for _, bucket := range buckets {
		summary.Buckets = append(summary.Buckets, *bucket)
	}
	sort.Slice(summary.Buckets, func(i, j int) bool { return summary.Buckets[i].Category < summary.Buckets[j].Category })
	return summary, nil
}
