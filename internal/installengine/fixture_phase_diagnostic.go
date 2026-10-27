// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import "context"

// Opt-in attribution from the actual refused predicate. Only closed numeric
// labels are retained; no error, object, identity or credential is recorded.
// The substage in admissionTrace locates the gate within the complete pass.
type fixturePhaseGate uint32

const (
	phaseGateUnknown fixturePhaseGate = iota
	phaseGateReadable
	phaseGateCurrent
	phaseGateWorlds
	phaseGateLocalBarrier
	phaseGateRemote
	phaseGateBaseline
	phaseGateLeaders
)

func (gate fixturePhaseGate) String() string {
	switch gate {
	case phaseGateReadable:
		return "phaseReadable"
	case phaseGateCurrent:
		return "current"
	case phaseGateWorlds:
		return "worlds"
	case phaseGateLocalBarrier:
		return "localBarrier"
	case phaseGateRemote:
		return "remote"
	case phaseGateBaseline:
		return "baseline"
	case phaseGateLeaders:
		return "leaders"
	default:
		return "unknown"
	}
}

// Return the original predicate unchanged. Short-circuit evaluation remains at
// each call site. First refusal wins if a helper already identified its gate.
func phaseGateFailed(ctx context.Context, gate fixturePhaseGate, failed bool) bool {
	if failed && ctx != nil && gate > phaseGateUnknown && gate <= phaseGateLeaders {
		if trace, ok := ctx.Value(admissionTraceKey{}).(*admissionTrace); ok && trace != nil {
			trace.phaseGate.CompareAndSwap(0, uint32(gate))
		}
	}
	return failed
}

// Read only after the serialized observation has returned.
func (trace *admissionTrace) phaseGateSnapshot() fixturePhaseGate {
	if trace != nil {
		if gate := fixturePhaseGate(trace.phaseGate.Load()); gate <= phaseGateLeaders {
			return gate
		}
	}
	return phaseGateUnknown
}
