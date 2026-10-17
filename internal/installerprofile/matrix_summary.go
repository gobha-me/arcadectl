// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installerprofile

import (
	"encoding/json"
	"math"
	"strings"
)

// MatrixCPUClassification identifies the closed vocabulary of matrix v5 rows.
// It is not a profile-controlled selector or a public diagnostic option.
const MatrixCPUClassification = "matrix-cpu-categories-v1"

type cpuVocabulary uint8

const (
	cpuVocabularyLegacy cpuVocabulary = iota
	cpuVocabularyMatrix
)

// Shared bounded decoding/accounting does not acquire either wire serializer.
// Only the source-selected entry point converts this private numeric result.
type cpuAccounting CPUSummary

// MatrixCPUSummary is deliberately distinct from CPUSummary. The legacy wire
// vocabulary remains frozen, including for callers constructing either value.
// Flat buckets partition CPU; cumulative buckets overlap and are not additive.
type MatrixCPUSummary CPUSummary

func (s MatrixCPUSummary) MarshalJSON() ([]byte, error) {
	if s.Samples == 0 || s.Samples > math.MaxInt64/cpuPeriod || s.CPUNanoseconds != s.Samples*cpuPeriod || s.DurationNanoseconds == 0 || s.DurationNanoseconds > math.MaxInt64 || len(s.Buckets) == 0 || len(s.Buckets) > 16 {
		return nil, errIncomplete
	}
	var flat uint64
	last := ""
	for _, bucket := range s.Buckets {
		switch bucket.Category {
		case "runtime-gc", "runtime", "json", "reflect", "hash", "tls", "http", "client-go", "apimachinery", "proof-observe", "proof-contract", "io-syscall", "installengine", "package-state", "other", "unresolved":
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
	type numericSummary MatrixCPUSummary
	return json.Marshal(numericSummary(s))
}

// SummarizeCPUMatrix uses the same bounded Go schema, validation order and work
// accounting as SummarizeCPU, with a separately reviewed numeric vocabulary.
// No original strings, paths, labels, addresses or partial summaries escape.
func SummarizeCPUMatrix(compressed []byte, executable string) (MatrixCPUSummary, error) {
	summary, _, err := SummarizeCPUMatrixWithDiagnostic(compressed, executable)
	return summary, err
}

func SummarizeCPUMatrixWithDiagnostic(compressed []byte, executable string) (MatrixCPUSummary, CPURefusal, error) {
	summary, err := summarizeCPUFor(compressed, executable, cpuVocabularyMatrix)
	if err != nil {
		if refusal, ok := err.(cpuParseRefusal); ok && refusal.reason.Valid() && refusal.reason.Stage != CPURefusalNone {
			return MatrixCPUSummary{}, refusal.reason, errIncomplete
		}
		return MatrixCPUSummary{}, CPURefusal{}, errIncomplete
	}
	return MatrixCPUSummary(summary), CPURefusal{}, nil
}

func matrixCPUCategory(symbol string) string {
	// These are exact package-qualified prefixes, not arbitrary profile data
	// copied into labels. Specific runtime allocation/GC precedes runtime.
	for _, item := range []struct{ prefix, category string }{
		{"runtime.gc", "runtime-gc"}, {"runtime.scan", "runtime-gc"}, {"runtime.malloc", "runtime-gc"},
		{"runtime.", "runtime"},
		{"encoding/json.", "json"}, {"sigs.k8s.io/json.", "json"}, {"sigs.k8s.io/json/", "json"},
		{"github.com/gobha-me/arcadectl/internal/canonicaljson.", "json"},
		{"reflect.", "reflect"}, {"internal/reflectlite.", "reflect"},
		{"crypto/sha256.", "hash"}, {"crypto/internal/fips140/sha256.", "hash"},
		{"crypto/tls.", "tls"}, {"net/http.", "http"},
		{"k8s.io/client-go/", "client-go"}, {"k8s.io/apimachinery/", "apimachinery"},
		{"github.com/gobha-me/arcadectl/internal/installobserve.", "proof-observe"},
		{"github.com/gobha-me/arcadectl/internal/installsafety.", "proof-observe"},
		{"github.com/gobha-me/arcadectl/internal/installcontract.", "proof-contract"},
		{"github.com/gobha-me/arcadectl/internal/privatefs.", "io-syscall"},
		{"os.", "io-syscall"}, {"io.", "io-syscall"}, {"io/fs.", "io-syscall"},
		{"syscall.", "io-syscall"}, {"golang.org/x/sys/unix.", "io-syscall"}, {"internal/syscall/unix.", "io-syscall"},
		{"github.com/gobha-me/arcadectl/internal/installengine.", "installengine"},
		{"github.com/gobha-me/arcadectl/internal/installstate.", "package-state"},
		{"github.com/gobha-me/arcadectl/internal/installbaseline.", "package-state"},
		{"github.com/gobha-me/arcadectl/internal/installrender.", "package-state"},
	} {
		if strings.HasPrefix(symbol, item.prefix) {
			return item.category
		}
	}
	// io-syscall includes networking and other uses, not just proof-file IO.
	// runtime-gc includes allocation helpers, not exclusively collection.
	return "other"
}
