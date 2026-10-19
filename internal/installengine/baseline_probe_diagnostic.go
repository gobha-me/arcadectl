// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"time"
)

type baselineProbeDiagnosticKey struct{}
type baselineProbePhase uint8

const (
	baselineProbeDiscovery baselineProbePhase = iota + 1
	baselineProbeOpening
	baselineProbeDryRun
	baselineProbeClosing
	baselineProbeComplete
)

func (p baselineProbePhase) label() string {
	switch p {
	case baselineProbeDiscovery:
		return "discovery"
	case baselineProbeOpening:
		return "opening-authority"
	case baselineProbeDryRun:
		return "dry-run"
	case baselineProbeClosing:
		return "closing-authority"
	case baselineProbeComplete:
		return "complete"
	}
	return "unknown"
}

func baselineProbeOperationLabel(operation admissionProbeOperation) string {
	switch operation {
	case probeCreateOperation:
		return "create"
	case probeUpdateOperation:
		return "update"
	case probeDeleteAccountOperation:
		return "delete-account"
	case probeDeleteExecutableOperation:
		return "delete-executable"
	case probeDeleteIdentityOperation:
		return "delete-identity"
	case probePatchMetadataOperation:
		return "patch-metadata"
	}
	return "unknown"
}

// Only the latest private probe is retained. No objects, identity, callback,
// request, response, error or execution context can become diagnostic output.
type baselineProbeDiagnostic struct {
	position atomic.Uint32 // operation+1 in high byte; CREATE is zero
	metrics  [4]baselineProbeMetrics
}

type baselineProbeMetrics struct {
	wallNS      atomic.Uint64
	attempts    atomic.Uint64
	roundTripNS atomic.Uint64
	authority   atomic.Uint32
}

type baselineProbeAuthorityStage uint32

const (
	probeAuthorityScope baselineProbeAuthorityStage = iota + 1
	probeAuthorityVersion
	probeAuthorityAccessOpening
	probeAuthorityPoliciesOpening
	probeAuthorityOperation
	probeAuthorityContainment
	probeAuthorityAccessClosing
	probeAuthorityPoliciesClosing
	probeAuthorityAccessFinal
	probeAuthorityComplete
)

func (s baselineProbeAuthorityStage) label() string {
	switch s {
	case probeAuthorityScope:
		return "scope"
	case probeAuthorityVersion:
		return "version"
	case probeAuthorityAccessOpening:
		return "access-opening"
	case probeAuthorityPoliciesOpening:
		return "policies-opening"
	case probeAuthorityOperation:
		return "exact-operation"
	case probeAuthorityContainment:
		return "containment"
	case probeAuthorityAccessClosing:
		return "access-closing"
	case probeAuthorityPoliciesClosing:
		return "policies-closing"
	case probeAuthorityAccessFinal:
		return "access-final"
	case probeAuthorityComplete:
		return "complete"
	}
	return "unknown"
}

// A phase belongs to one probe, even across its joined actor lanes. Never use
// mutable global progress to attribute a concurrently finishing request.
type baselineProbePhaseScope struct {
	probe *baselineProbeDiagnostic
	phase baselineProbePhase
}

// Fixed pre-check progress only, never a failed operand, identity or result.
// Each phase owns its scalar; a late opening callback cannot overwrite closing
// progress, and an old probe cannot update the currently reported probe.
func traceBaselineProbeAuthority(ctx context.Context, stage baselineProbeAuthorityStage) {
	if ctx == nil {
		return
	}
	scope, ok := ctx.Value(baselineProbePhaseScope{}).(*baselineProbePhaseScope)
	if !ok || scope == nil || scope.probe == nil || scope.phase != baselineProbeOpening && scope.phase != baselineProbeClosing {
		return
	}
	scope.probe.metrics[scope.phase-1].authority.Store(uint32(stage))
}

func beginBaselineProbeDiagnostic(ctx context.Context, operation admissionProbeOperation) context.Context {
	if ctx == nil || baselineProbeOperationLabel(operation) == "unknown" {
		return ctx
	}
	d, ok := ctx.Value(lifecycleDiagnosticKey{}).(*LifecycleDiagnostic)
	if !ok || d == nil {
		return ctx
	}
	probe := &baselineProbeDiagnostic{}
	probe.position.Store(uint32(operation+1) << 8)
	d.baselineProbe.Store(probe)
	return context.WithValue(ctx, baselineProbeDiagnosticKey{}, probe)
}

func baselineProbePhaseContext(ctx context.Context, phase baselineProbePhase) (context.Context, func()) {
	if ctx == nil || phase < baselineProbeDiscovery || phase > baselineProbeClosing {
		return ctx, func() {}
	}
	ctx = withRequestPipelineScope(ctx, requestPipelineScope(phase-baselineProbeDiscovery))
	probe, ok := ctx.Value(baselineProbeDiagnosticKey{}).(*baselineProbeDiagnostic)
	if !ok || probe == nil {
		return ctx, func() {}
	}
	probe.position.Store(probe.position.Load()&0xffffff00 | uint32(phase))
	probe.metrics[phase-1].authority.Store(0)
	started := time.Now()
	scope := &baselineProbePhaseScope{probe: probe, phase: phase}
	return context.WithValue(ctx, baselineProbePhaseScope{}, scope), func() {
		probe.metrics[phase-1].wallNS.Add(uint64(time.Since(started)))
	}
}

func completeBaselineProbeDiagnostic(ctx context.Context) {
	if ctx == nil {
		return
	}
	if probe, ok := ctx.Value(baselineProbeDiagnosticKey{}).(*baselineProbeDiagnostic); ok && probe != nil {
		probe.position.Store(probe.position.Load()&0xffffff00 | uint32(baselineProbeComplete))
	}
}

// Called only after the actual one-attempt and purpose guards accept. This
// measures delegation to the guarded direct HTTP transport, not confirmed
// server handling. RoundTrip ends at headers: response-body work and SDK
// observer traffic are excluded. Concurrent lanes may overlap, so its sum is
// not subtracted from wall time or represented as local/CPU time.
func beginBaselineProbeRoundTrip(ctx context.Context) func() {
	if ctx == nil {
		return func() {}
	}
	scope, ok := ctx.Value(baselineProbePhaseScope{}).(*baselineProbePhaseScope)
	if !ok || scope == nil || scope.probe == nil || scope.phase < baselineProbeDiscovery || scope.phase > baselineProbeClosing {
		return func() {}
	}
	metrics := &scope.probe.metrics[scope.phase-1]
	metrics.attempts.Add(1)
	started := time.Now()
	return func() { metrics.roundTripNS.Add(uint64(time.Since(started))) }
}

// BaselineProbeSnapshot is bounded latest-probe progress/timing only. Read
// AFTER the same Step returns and joined actor lanes finish. Complete means
// only the probe primitive returned, never whole baseline/provider acceptance.
func (d *LifecycleDiagnostic) BaselineProbeSnapshot() string {
	if d == nil {
		return ""
	}
	probe := d.baselineProbe.Load()
	if probe == nil {
		return ""
	}
	position := probe.position.Load()
	operation, phase := "unknown", "unknown"
	if position>>8 >= 1 && position>>8 <= 256 {
		operation = baselineProbeOperationLabel(admissionProbeOperation((position >> 8) - 1))
	}
	phase = baselineProbePhase(position & 255).label()
	authority := "unknown"
	if p := baselineProbePhase(position & 255); p == baselineProbeOpening || p == baselineProbeClosing {
		authority = baselineProbeAuthorityStage(probe.metrics[p-1].authority.Load()).label()
	}
	var b strings.Builder
	fmt.Fprintf(&b, "phase=%s operation=%s authority=%s", phase, operation, authority)
	for i := range probe.metrics {
		metrics := &probe.metrics[i]
		fmt.Fprintf(&b, " %s-wall-ns=%d %s-direct-attempts=%d %s-direct-roundtrip-sum-ns=%d", baselineProbePhase(i+1).label(), metrics.wallNS.Load(), baselineProbePhase(i+1).label(), metrics.attempts.Load(), baselineProbePhase(i+1).label(), metrics.roundTripNS.Load())
	}
	return b.String()
}
