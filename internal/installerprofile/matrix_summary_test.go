// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installerprofile

import (
	"bytes"
	"encoding/json"
	"math"
	"reflect"
	"testing"
)

func matrixSummaryFixture(symbols []string, unresolved bool) cpuFixture {
	f := cpuFixture{
		types:    [][]byte{cpuRecord(1, 2), cpuRecord(3, 4)},
		mappings: [][]byte{cpuRecord(1, 4096, 8192, 0, 5, 0, 1)},
		strings:  []string{"", "samples", "count", "cpu", "nanoseconds", "/owned/installer", "/private/FILE-CANARY.go"},
		period:   cpuPeriod, duration: 1,
	}
	for i, symbol := range symbols {
		id, index := uint64(i+1), uint64(len(f.strings))
		f.strings = append(f.strings, symbol)
		f.functions = append(f.functions, cpuRecord(id, index, index, 6, 10))
		f.locations = append(f.locations, append(cpuRecord(id, 1, 4096+id), cpuBytes(4, cpuRecord(id, 10))...))
		f.samples = append(f.samples, append(cpuIntegers(1, true, id), cpuIntegers(2, true, 1, cpuPeriod)...))
	}
	if unresolved {
		f.samples = append(f.samples, cpuIntegers(2, true, 1, cpuPeriod))
	}
	return f
}

func TestMatrixCPUAllSixteenGroupsAndLegacyGolden(t *testing.T) {
	symbols := []string{
		"runtime.gcBgMarkWorker", "runtime.schedule", "encoding/json.Marshal", "reflect.deepValueEqual",
		"crypto/internal/fips140/sha256.blockAVX2", "crypto/tls.(*Conn).Read", "net/http.(*Transport).RoundTrip",
		"k8s.io/client-go/rest.(*Request).Do", "k8s.io/apimachinery/pkg/runtime.(*Scheme).Convert",
		"github.com/gobha-me/arcadectl/internal/installobserve.(*Observation).Snapshot",
		"github.com/gobha-me/arcadectl/internal/installcontract.(*Template).MatchLive",
		"github.com/gobha-me/arcadectl/internal/privatefs.(*Store).MatchOriginal",
		"github.com/gobha-me/arcadectl/internal/installengine.(*Engine).Apply",
		"github.com/gobha-me/arcadectl/internal/installstate.Decode", "PRIVATE-SYMBOL-CANARY",
	}
	body := cpuGzip(t, matrixSummaryFixture(symbols, true).wire(), nil)
	got, reason, err := SummarizeCPUMatrixWithDiagnostic(body, "/owned/installer")
	plain, plainErr := SummarizeCPUMatrix(body, "/owned/installer")
	wantNames := []string{"apimachinery", "client-go", "hash", "http", "installengine", "io-syscall", "json", "other", "package-state", "proof-contract", "proof-observe", "reflect", "runtime", "runtime-gc", "tls", "unresolved"}
	if err != nil || plainErr != nil || reason != (CPURefusal{}) || !reflect.DeepEqual(got, plain) || got.Samples != 16 || got.CPUNanoseconds != 16*cpuPeriod || len(got.Buckets) != 16 {
		t.Fatal("matrix parser lost exact bounded accounting")
	}
	for i, bucket := range got.Buckets {
		if bucket != (CPUBucket{Category: wantNames[i], FlatNanoseconds: cpuPeriod, CumulativeNanoseconds: cpuPeriod}) {
			t.Fatal("matrix category partition changed")
		}
	}
	encoded, err := json.Marshal(got)
	if err != nil || bytes.Contains(encoded, []byte("CANARY")) || bytes.Contains(encoded, []byte("/")) {
		t.Fatal("matrix summary exposed raw profile strings")
	}
	if _, err := json.Marshal(CPUSummary(got)); err == nil {
		t.Fatal("new vocabulary passed legacy serializer")
	}
	legacy, err := SummarizeCPU(body, "/owned/installer")
	if err != nil || len(legacy.Buckets) != 11 {
		t.Fatal("legacy vocabulary changed")
	}
	for _, bucket := range legacy.Buckets {
		count := uint64(1)
		if bucket.Category == "other" {
			count = 6
		}
		if bucket.FlatNanoseconds != count*cpuPeriod || bucket.CumulativeNanoseconds != count*cpuPeriod {
			t.Fatal("legacy classification was reinterpreted")
		}
	}
	legacy, err = SummarizeCPU(cpuGzip(t, newCPUFixture(true).wire(), nil), "/owned/installer")
	if err != nil {
		t.Fatal("legacy independent fixture refused")
	}
	encoded, err = json.Marshal(legacy)
	const golden = `{"samples":3,"cpuNanoseconds":30000000,"durationNanoseconds":1,"buckets":[{"category":"other","flatNanoseconds":0,"cumulativeNanoseconds":20000000},{"category":"runtime-gc","flatNanoseconds":20000000,"cumulativeNanoseconds":20000000},{"category":"unresolved","flatNanoseconds":10000000,"cumulativeNanoseconds":10000000}]}`
	if err != nil || string(encoded) != golden {
		t.Fatal("legacy summary wire bytes changed")
	}
}

func TestMatrixCPUClosedPrefixBoundaries(t *testing.T) {
	for symbol, want := range map[string]string{
		"runtime.mallocgc": "runtime-gc", "runtime.scanobject": "runtime-gc", "runtime.gcWork": "runtime-gc",
		"internal/reflectlite.ValueOf": "reflect", "crypto/sha256.Sum256": "hash",
		"crypto/internal/fips140/sha256.blockSHANI": "hash", "sigs.k8s.io/json.UnmarshalStrict": "json",
		"sigs.k8s.io/json/internal/golang/encoding/json.decode":                  "json",
		"github.com/gobha-me/arcadectl/internal/canonicaljson.CanonicalJSON":     "json",
		"github.com/gobha-me/arcadectl/internal/installsafety.ValidateCold":      "proof-observe",
		"github.com/gobha-me/arcadectl/internal/installbaseline.New":             "package-state",
		"github.com/gobha-me/arcadectl/internal/installrender.(*Plan).Resources": "package-state",
		"os.Open": "io-syscall", "io.Copy": "io-syscall", "io/fs.ValidPath": "io-syscall",
		"syscall.Syscall": "io-syscall", "golang.org/x/sys/unix.Openat": "io-syscall",
		"internal/syscall/unix.Fcntl": "io-syscall",
		"crypto/sha256evil.Sum256":    "other", "crypto/internal/fips140/sha256evil.block": "other",
		"crypto/sha512.Sum512": "other", "reflective.DeepEqual": "other", "reflect/PRIVATE-CANARY": "other",
		"sigs.k8s.io/jsonish.Decode": "other", "github.com/gobha-me/arcadectl/internal/installcontractevil.Match": "other",
		"github.com/gobha-me/arcadectl/internal/privatefs_extra.Read": "other", "os/PRIVATE-CANARY": "other",
		"PRIVATE-SYMBOL-CANARY": "other", "": "other",
	} {
		if matrixCPUCategory(symbol) != want {
			t.Fatal("matrix category boundary changed")
		}
	}
	if cpuCategory("sigs.k8s.io/jsonish.Decode") != "json" {
		t.Fatal("legacy broad classifier changed")
	}
}

func TestMatrixCPUFlatPartitionAndOverlappingCumulativeDedup(t *testing.T) {
	f := matrixSummaryFixture([]string{"reflect.deepValueEqual", "crypto/sha256.Sum256"}, false)
	f.samples = [][]byte{append(cpuIntegers(1, true, 1, 1, 2, 1), cpuIntegers(2, true, 2, 2*cpuPeriod)...)}
	got, err := SummarizeCPUMatrix(cpuGzip(t, f.wire(), nil), "/owned/installer")
	want := MatrixCPUSummary{Samples: 2, CPUNanoseconds: 2 * cpuPeriod, DurationNanoseconds: 1, Buckets: []CPUBucket{
		{Category: "hash", CumulativeNanoseconds: 2 * cpuPeriod},
		{Category: "reflect", FlatNanoseconds: 2 * cpuPeriod, CumulativeNanoseconds: 2 * cpuPeriod},
	}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("repeated stack category changed accounting")
	}
	if _, err := json.Marshal(got); err != nil {
		t.Fatal("valid overlapping cumulative buckets refused")
	}
	got.Buckets[0].Category = "PRIVATE-CANARY"
	again, err := SummarizeCPUMatrix(cpuGzip(t, f.wire(), nil), "/owned/installer")
	if err != nil || !reflect.DeepEqual(again, want) {
		t.Fatal("returned summary aliases parser state")
	}
}

func TestMatrixCPUCallerConstructedSummaryCannotBroadenWire(t *testing.T) {
	valid := MatrixCPUSummary{Samples: 1, CPUNanoseconds: cpuPeriod, DurationNanoseconds: 1,
		Buckets: []CPUBucket{{Category: "hash", FlatNanoseconds: cpuPeriod, CumulativeNanoseconds: cpuPeriod}}}
	for _, edit := range []func(*MatrixCPUSummary){
		func(s *MatrixCPUSummary) { s.Samples = 0 },
		func(s *MatrixCPUSummary) { s.Samples = math.MaxInt64/cpuPeriod + 1 },
		func(s *MatrixCPUSummary) { s.CPUNanoseconds++ },
		func(s *MatrixCPUSummary) { s.DurationNanoseconds = 0 },
		func(s *MatrixCPUSummary) { s.DurationNanoseconds = math.MaxInt64 + 1 },
		func(s *MatrixCPUSummary) { s.Buckets = nil },
		func(s *MatrixCPUSummary) { s.Buckets = make([]CPUBucket, 17) },
		func(s *MatrixCPUSummary) { s.Buckets[0].Category = "PRIVATE-CANARY" },
		func(s *MatrixCPUSummary) { s.Buckets[0].Category = "state-decode" },
		func(s *MatrixCPUSummary) { s.Buckets[0].Category = "template-copy" },
		func(s *MatrixCPUSummary) { s.Buckets[0].CumulativeNanoseconds = 0 },
		func(s *MatrixCPUSummary) { s.Buckets[0].CumulativeNanoseconds++ },
		func(s *MatrixCPUSummary) { s.Buckets[0].FlatNanoseconds-- },
		func(s *MatrixCPUSummary) { s.Buckets = append(s.Buckets, s.Buckets[0]) },
		func(s *MatrixCPUSummary) {
			s.Buckets = []CPUBucket{{"runtime", cpuPeriod, cpuPeriod}, {"hash", 0, cpuPeriod}}
		},
	} {
		bad := valid
		bad.Buckets = append([]CPUBucket{}, valid.Buckets...)
		edit(&bad)
		if body, err := json.Marshal(bad); err == nil || len(body) != 0 {
			t.Fatal("unreviewed matrix summary serialized")
		}
	}
	if _, err := json.Marshal(valid); err != nil {
		t.Fatal("valid independent matrix summary refused")
	}
	if _, err := json.Marshal(CPUSummary(valid)); err == nil {
		t.Fatal("legacy serializer widened")
	}
	profile := cpuGzip(t, newCPUFixture(true).wire(), nil)
	if _, err := summarizeCPUFor(profile, "/owned/installer", cpuVocabularyLegacy); err != nil {
		t.Fatal("invalid-vocabulary control profile was not accepted")
	}
	got, err := summarizeCPUFor(profile, "/owned/installer", cpuVocabulary(99))
	refusal, ok := err.(cpuParseRefusal)
	if !reflect.DeepEqual(got, cpuAccounting{}) || !ok || refusal.reason != (CPURefusal{Stage: CPURefusalSchema}) {
		t.Fatal("unknown classifier did not return zero output and schema refusal")
	}
	if MatrixCPUClassification != "matrix-cpu-categories-v1" {
		t.Fatal("classification is not literal")
	}
}
