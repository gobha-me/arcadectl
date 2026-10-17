// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installerprofile

import "encoding/json"

// CPURefusal reports only a closed parser category and, for work refusals, a
// fixed bound identifier. It never contains an observed field, string or path.
// The first encountered check is not a unique root cause for multifault input.
type CPURefusal struct {
	Stage uint8 `json:"stage"`
	Bound uint8 `json:"bound"`
}

const (
	CPURefusalNone uint8 = iota
	CPURefusalEnvelope
	CPURefusalExpansion
	CPURefusalProtobuf
	CPURefusalReference
	CPURefusalSchema
	CPURefusalWork
	CPURefusalAccounting
)

const (
	CPUBoundNone uint8 = iota
	CPUBoundFields
	CPUBoundRecords
	CPUBoundStackDepth
	CPUBoundStackReferences
	CPUBoundInlineLines
	CPUBoundExpandedWork
	CPUBoundStringBytes
)

func (r CPURefusal) Valid() bool {
	if r.Stage == CPURefusalWork {
		return r.Bound >= CPUBoundFields && r.Bound <= CPUBoundStringBytes
	}
	return r.Stage <= CPURefusalAccounting && r.Bound == CPUBoundNone
}

func (r CPURefusal) MarshalJSON() ([]byte, error) {
	if !r.Valid() {
		return nil, errIncomplete
	}
	type numericRefusal CPURefusal
	return json.Marshal(numericRefusal(r))
}

type cpuParseRefusal struct{ reason CPURefusal }

func (cpuParseRefusal) Error() string { return "CPU profile unavailable" }

func refuseCPU(stage uint8) error {
	return cpuParseRefusal{CPURefusal{Stage: stage}}
}

func refuseCPUWork(bound uint8) error {
	return cpuParseRefusal{CPURefusal{Stage: CPURefusalWork, Bound: bound}}
}

// SummarizeCPUWithDiagnostic has the same acceptance, summary and public error
// as SummarizeCPU. A refused parse adds only fixed numeric metadata. It does not
// relax bounds or retain raw input/partial attribution as a fallback.
func SummarizeCPUWithDiagnostic(compressed []byte, executable string) (CPUSummary, CPURefusal, error) {
	summary, err := summarizeCPU(compressed, executable)
	if err != nil {
		if refusal, ok := err.(cpuParseRefusal); ok && refusal.reason.Valid() && refusal.reason.Stage != CPURefusalNone {
			return CPUSummary{}, refusal.reason, errIncomplete
		}
		// No unreviewed/internal error text may cross the diagnostic boundary.
		return CPUSummary{}, CPURefusal{}, errIncomplete
	}
	return summary, CPURefusal{}, nil
}
