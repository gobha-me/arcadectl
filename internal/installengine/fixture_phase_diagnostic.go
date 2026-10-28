// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"fmt"
)

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

// warmPhaseReadDiagnostic accumulates one serialized warm phase-read poll.
// Counters saturate at 2^32-1. Only closed trace labels and a bounded slot are
// retained; no trace, error, object, identity, credential or evidence is retained.
// The caller serializes all access, including String.
//
//nolint:unused // The separate test author wires the Kind phaseRead consumer.
type warmPhaseReadDiagnostic struct {
	attempts uint32
	refusals [phaseGateLeaders + 1]uint32
	lastGate fixturePhaseGate
	substage string
	slot     int
}

// record counts one refused observation, independently of the attempt count.
// Invalid gates join unknown; phaseSnapshot supplies only closed labels/slots.
//
//nolint:unused // Used by the wrapper awaiting the separate Kind test author.
func (d *warmPhaseReadDiagnostic) record(gate fixturePhaseGate, trace *admissionTrace) {
	if d == nil {
		return
	}
	if gate > phaseGateLeaders {
		gate = phaseGateUnknown
	}
	if d.refusals[gate] < ^uint32(0) {
		d.refusals[gate]++
	}
	d.lastGate = gate
	d.substage, d.slot = trace.phaseSnapshot()
}

// String has the stable format:
//
//	attempts=N last_gate=G substage=S slot=I; refusals: phaseReadable=N current=N worlds=N localBarrier=N remote=N baseline=N leaders=N unknown=N
//
// Counts are decimal; all gates always appear in this order. Nil and zero values
// report zero counts, unknown gate/substage and slot=-1. Successes count as
// attempts but leave the last refusal and its position unchanged.
//
//nolint:unused // The separate test author wires the Kind phaseRead consumer.
func (d *warmPhaseReadDiagnostic) String() string {
	if d == nil {
		d = &warmPhaseReadDiagnostic{}
	}
	substage, slot := d.substage, d.slot
	if substage == "" {
		substage, slot = "unknown", -1
	}
	return fmt.Sprintf("attempts=%d last_gate=%s substage=%s slot=%d; refusals: phaseReadable=%d current=%d worlds=%d localBarrier=%d remote=%d baseline=%d leaders=%d unknown=%d",
		d.attempts, d.lastGate, substage, slot,
		d.refusals[phaseGateReadable], d.refusals[phaseGateCurrent], d.refusals[phaseGateWorlds],
		d.refusals[phaseGateLocalBarrier], d.refusals[phaseGateRemote], d.refusals[phaseGateBaseline],
		d.refusals[phaseGateLeaders], d.refusals[phaseGateUnknown])
}

// observePhaseAttributed adds opt-in diagnostics to the same observation. It
// never retries or changes deadlines, predicates, observations or error values.
//
//nolint:unused // The separate test author wires the Kind phaseRead consumer.
func (w *fixtureWire) observePhaseAttributed(ctx context.Context, d *warmPhaseReadDiagnostic) (*fixturePhaseObservation, error) {
	if d != nil && d.attempts < ^uint32(0) {
		d.attempts++
	}
	trace := &admissionTrace{}
	if ctx != nil {
		ctx = context.WithValue(ctx, admissionTraceKey{}, trace)
	}
	observation, err := w.observePhase(ctx)
	if err != nil {
		d.record(trace.phaseGateSnapshot(), trace)
	}
	return observation, err
}

//nolint:unused // The separate test author wires the Kind phaseRead fatal site.
func warmPhaseReadFailureMessage(d *warmPhaseReadDiagnostic) string {
	return "complete original phase did not converge with both renewing native leaders (" + d.String() + ")"
}
