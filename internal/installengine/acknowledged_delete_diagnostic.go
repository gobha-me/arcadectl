// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"errors"
	"fmt"
)

type acknowledgedDeleteStep uint8

const (
	ackOriginalOpening acknowledgedDeleteStep = iota + 1
	ackTargetRead
	ackOriginalClosing
	ackTargetOriginalCheck
	ackDraining
	ackExecutableCollection
	ackExecutableClosing
	ackTargetAbsentCheck
	ackQuietness
	ackFullGuardOpening
	ackRetiredAdmissionCheck
	ackPostGuardTargetRead
)

func (s acknowledgedDeleteStep) label() string {
	switch s {
	case ackOriginalOpening:
		return "original-opening"
	case ackTargetRead:
		return "target-read"
	case ackOriginalClosing:
		return "original-closing"
	case ackTargetOriginalCheck:
		return "target-original-check"
	case ackDraining:
		return "draining"
	case ackExecutableCollection:
		return "executable-collection"
	case ackExecutableClosing:
		return "executable-closing"
	case ackTargetAbsentCheck:
		return "target-absent-check"
	case ackQuietness:
		return "quietness"
	case ackFullGuardOpening:
		return "full-guard-opening"
	case ackRetiredAdmissionCheck:
		return "retired-admission-check"
	case ackPostGuardTargetRead:
		return "post-guard-target-read"
	}
	return "unknown"
}

type acknowledgedDeleteStatus uint8

type acknowledgedDeleteObservation uint8

const (
	ackObservedDraining acknowledgedDeleteObservation = iota + 1
	ackObservedQuietness
)

func (o acknowledgedDeleteObservation) label() string {
	switch o {
	case ackObservedDraining:
		return "draining"
	case ackObservedQuietness:
		return "quietness"
	}
	return "unknown"
}

// Record only a completed preparation observation. A later callback's opening
// fence must not erase it. This is not proof of native GC progress or authority.
func traceAcknowledgedDeleteObservation(ctx context.Context, observation acknowledgedDeleteObservation) {
	if ctx == nil || observation.label() == "unknown" {
		return
	}
	if d, ok := ctx.Value(lifecycleDiagnosticKey{}).(*LifecycleDiagnostic); ok && d != nil {
		d.ackObservation.Store(uint32(observation))
	}
}

const (
	ackActive acknowledgedDeleteStatus = iota + 1
	ackRefused
	ackCancelled
	ackDeadline
)

func (s acknowledgedDeleteStatus) label() string {
	switch s {
	case ackActive:
		return "active"
	case ackRefused:
		return "refused"
	case ackCancelled:
		return "cancelled"
	case ackDeadline:
		return "deadline"
	}
	return "unknown"
}

func traceAcknowledgedDeleteStep(ctx context.Context, step acknowledgedDeleteStep) {
	if ctx == nil || step.label() == "unknown" {
		return
	}
	if d, ok := ctx.Value(lifecycleDiagnosticKey{}).(*LifecycleDiagnostic); ok && d != nil {
		d.ackPreparation.Store(uint32(step)<<8 | uint32(ackActive))
	}
}

// Preserve only the last closed stage and an observed context outcome. Neither
// arbitrary error text nor cancellation causes enter the recorder. A refusal
// is not a provider cause, proof, permission to retry, or deadline override.
func traceAcknowledgedDeleteRefusal(ctx context.Context, err error) {
	if ctx == nil {
		return
	}
	d, ok := ctx.Value(lifecycleDiagnosticKey{}).(*LifecycleDiagnostic)
	if !ok || d == nil {
		return
	}
	status := ackRefused
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		status = ackDeadline
	} else if errors.Is(ctx.Err(), context.Canceled) || errors.Is(err, context.Canceled) {
		status = ackCancelled
	}
	for {
		before := d.ackPreparation.Load()
		if before>>8 > 255 || acknowledgedDeleteStep(before>>8).label() == "unknown" {
			return
		}
		// A collector child deadline is already observed by its deferred
		// diagnostic. The caller's still-active parent must not erase it.
		if before&255 == uint32(ackDeadline) || before&255 == uint32(ackCancelled) {
			return
		}
		if d.ackPreparation.CompareAndSwap(before, before&^255|uint32(status)) {
			return
		}
	}
}

// Read after the SAME Step returns. This separate diagnostic does not alter
// existing full-proof boundaries or retain a provider, object, identity, path,
// context or error. Empty means this Step never entered ACK preparation.
func (d *LifecycleDiagnostic) AcknowledgedDeleteSnapshot() string {
	if d == nil {
		return ""
	}
	packed := d.ackPreparation.Load()
	if packed == 0 {
		return ""
	}
	step, status := "unknown", "unknown"
	if packed>>8 <= 255 {
		step = acknowledgedDeleteStep(packed >> 8).label()
	}
	status = acknowledgedDeleteStatus(packed & 255).label()
	return fmt.Sprintf("step=%s status=%s", step, status)
}

// Read after the SAME Step returns, separately from the current-stage record.
// Preserve the last completed observation across later opening/refusal stages;
// unknown means no completed preparation observation was recorded. Neither
// objects, raw errors, identities nor timing values enter this closed record.
func (d *LifecycleDiagnostic) AcknowledgedDeleteObservationSnapshot() string {
	if d == nil || d.ackPreparation.Load() == 0 {
		return ""
	}
	label := "unknown"
	if value := d.ackObservation.Load(); value <= 255 {
		label = acknowledgedDeleteObservation(value).label()
	}
	return "last-completed=" + label
}
