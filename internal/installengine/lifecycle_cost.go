// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type lifecycleCostKey struct{}
type admissionCostKey struct{}
type lifecycleCostKind uint8

const (
	costAdmission lifecycleCostKind = iota
	costPhase
	costBaseline
	costAdmissionConstruction
	costAdmissionSetup
	costAdmissionMatrix
	costAdmissionDrain
	costAdmissionRetirement
	costAdmissionFinal
	costSDKWait
	costKinds
)

var lifecycleCostLabels = [costKinds]string{
	"admission", "phase", "baseline", "admission-construction", "admission-setup",
	"admission-matrix", "admission-drain", "admission-retirement", "admission-final",
	"sdk-wait",
}

type lifecycleCostMetric struct {
	calls    atomic.Uint64
	returned atomic.Uint64
	wallNS   atomic.Uint64
}

// LifecycleCosts contains only fixed counters and inclusive wall durations from
// ONE command. It retains no context, callback, errors, identities or objects.
// Returned means a function returned or a stage span closed, not success,
// proof or retry authority.
// Nested and overlapping durations must NOT be summed or called CPU time.
type LifecycleCosts struct {
	metrics [costKinds]lifecycleCostMetric
}

// WithLifecycleCosts starts a fresh command-wide recorder. Step-local progress
// resets do not clear it. An explicit new recorder never inherits old costs.
func WithLifecycleCosts(ctx context.Context) (context.Context, *LifecycleCosts) {
	if ctx == nil {
		return nil, nil
	}
	costs := &LifecycleCosts{}
	ctx = context.WithValue(ctx, lifecycleCostKey{}, costs)
	// A new command cannot continue an inherited old invocation's stage span.
	ctx = context.WithValue(ctx, admissionCostKey{}, (*admissionCostScope)(nil))
	return ctx, costs
}

// Snapshot is bounded numeric diagnostic data. Read only after the command's
// joined operations return; this is not an atomic concurrent proof snapshot.
func (c *LifecycleCosts) Snapshot() string {
	var b strings.Builder
	for kind, label := range lifecycleCostLabels {
		var calls, returned, wall uint64
		if c != nil {
			m := &c.metrics[kind]
			calls, returned, wall = m.calls.Load(), m.returned.Load(), m.wallNS.Load()
		}
		if kind != 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "%s-calls=%d %s-returned=%d %s-inclusive-wall-ns=%d", label, calls, label, returned, label, wall)
	}
	return b.String()
}

func lifecycleCosts(ctx context.Context) *LifecycleCosts {
	if ctx == nil {
		return nil
	}
	costs, _ := ctx.Value(lifecycleCostKey{}).(*LifecycleCosts)
	return costs
}

func beginLifecycleCost(ctx context.Context, kind lifecycleCostKind) func() {
	costs := lifecycleCosts(ctx)
	if costs == nil || kind >= costKinds {
		return func() {}
	}
	m := &costs.metrics[kind]
	m.calls.Add(1)
	started := time.Now()
	return func() {
		m.wallNS.Add(uint64(time.Since(started)))
		m.returned.Add(1)
	}
}

// Private to one VerifyEffective invocation. Stage spans never follow another
// invocation's progress, and the final partial stage is closed even on refusal.
type admissionCostScope struct {
	mu      sync.Mutex
	costs   *LifecycleCosts
	kind    lifecycleCostKind
	started time.Time
	closed  bool
}

func beginAdmissionCost(ctx context.Context) (context.Context, func()) {
	costs := lifecycleCosts(ctx)
	if costs == nil {
		return ctx, func() {}
	}
	finish := beginLifecycleCost(ctx, costAdmission)
	scope := &admissionCostScope{costs: costs, kind: costAdmissionConstruction, started: time.Now()}
	costs.metrics[scope.kind].calls.Add(1)
	return context.WithValue(ctx, admissionCostKey{}, scope), func() {
		scope.mu.Lock()
		defer scope.mu.Unlock()
		if scope.closed {
			return
		}
		scope.closeSpan(time.Now())
		scope.closed = true
		finish()
	}
}

func (s *admissionCostScope) closeSpan(now time.Time) {
	m := &s.costs.metrics[s.kind]
	m.wallNS.Add(uint64(now.Sub(s.started)))
	m.returned.Add(1)
}

func traceAdmissionCost(ctx context.Context, step admissionStep) {
	if ctx == nil {
		return
	}
	scope, _ := ctx.Value(admissionCostKey{}).(*admissionCostScope)
	if scope == nil {
		return
	}
	kind := costAdmissionConstruction
	switch {
	case step >= admissionSetupObservation && step <= admissionSetupSettle:
		kind = costAdmissionSetup
	case step >= admissionCaseObservation && step <= admissionFinish:
		kind = costAdmissionMatrix
	case step == admissionCleanup:
		kind = costAdmissionDrain
	case step == admissionRetire:
		kind = costAdmissionRetirement
	case step == admissionFinalWitness || step == admissionComplete:
		kind = costAdmissionFinal
	case step < admissionInitialPhase || step > admissionWire:
		return
	}
	scope.mu.Lock()
	defer scope.mu.Unlock()
	if scope.closed || scope.kind == kind {
		return
	}
	now := time.Now()
	scope.closeSpan(now)
	scope.kind, scope.started = kind, now
	scope.costs.metrics[kind].calls.Add(1)
}
