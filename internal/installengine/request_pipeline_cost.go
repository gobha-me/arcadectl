// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"time"
)

type requestPipelineKey struct{}
type requestPipelineScopeKey struct{}
type requestPipelineScope uint8
type requestPipelineKind uint8

const (
	pipelineBaselineDiscovery requestPipelineScope = iota
	pipelineBaselineOpening
	pipelineBaselineDryRun
	pipelineBaselineClosing
	pipelinePublicInventory
	pipelineOther
	pipelineScopes
)

const (
	pipelineClientDo requestPipelineKind = iota
	pipelineHeaders
	pipelinePostHeaders
	pipelineBodyRead
	pipelineValidation
	pipelineInventory
	pipelineContract
	pipelineRow
	pipelineKinds
)

var requestPipelineScopeLabels = [pipelineScopes]string{
	"baseline-discovery", "baseline-opening", "baseline-dry-run", "baseline-closing", "public-inventory", "other",
}

var requestPipelineKindLabels = [pipelineKinds]string{
	"client-do", "roundtrip-to-headers", "guarded-post-headers", "outer-body-read", "post-body-validation", "public-inventory", "contract-check", "phase-row",
}

type requestPipelineMetric struct {
	calls    atomic.Uint64
	returned atomic.Uint64
	wallNS   atomic.Uint64
}

// Only fixed scalar counters from ONE command. No identity, object, callback,
// request, response, error, context or previous invocation is retained here.
// Inclusive spans overlap; returned means returned, never proof or success.
type requestPipelineCosts struct {
	metrics [pipelineScopes][pipelineKinds]requestPipelineMetric
}

func withRequestPipelineCosts(ctx context.Context) (context.Context, *requestPipelineCosts) {
	if ctx == nil {
		return nil, nil
	}
	costs := &requestPipelineCosts{}
	ctx = context.WithValue(ctx, requestPipelineKey{}, costs)
	// A new command cannot inherit an old invocation's phase attribution.
	return context.WithValue(ctx, requestPipelineScopeKey{}, pipelineOther), costs
}

func requestPipelineRecorder(ctx context.Context) *requestPipelineCosts {
	if ctx == nil {
		return nil
	}
	costs, _ := ctx.Value(requestPipelineKey{}).(*requestPipelineCosts)
	return costs
}

func requestPipelineContextScope(ctx context.Context) requestPipelineScope {
	if ctx != nil {
		if scope, ok := ctx.Value(requestPipelineScopeKey{}).(requestPipelineScope); ok && scope < pipelineScopes {
			return scope
		}
	}
	return pipelineOther
}

// Attribution belongs to the immutable per-call context, never a shared mutable
// "current phase". Disabled observation cannot allocate a new context.
func withRequestPipelineScope(ctx context.Context, scope requestPipelineScope) context.Context {
	if scope >= pipelineScopes || requestPipelineRecorder(ctx) == nil {
		return ctx
	}
	return context.WithValue(ctx, requestPipelineScopeKey{}, scope)
}

// Inventory reached inside a baseline keeps that more specific attribution.
func withRequestPipelineInventory(ctx context.Context) context.Context {
	if requestPipelineRecorder(ctx) == nil || requestPipelineContextScope(ctx) < pipelinePublicInventory {
		return ctx
	}
	return withRequestPipelineScope(ctx, pipelinePublicInventory)
}

type requestPipelineSpan struct {
	metric  *requestPipelineMetric
	started time.Time
	now     func() time.Time
}

func beginRequestPipelineCost(ctx context.Context, kind requestPipelineKind) requestPipelineSpan {
	return beginRequestPipelineCostWithClock(ctx, kind, time.Now)
}

// The clock seam tests the disabled fast path, not production time attribution.
// Disabled or invalid observations return BEFORE a clock call or allocation.
func beginRequestPipelineCostWithClock(ctx context.Context, kind requestPipelineKind, now func() time.Time) requestPipelineSpan {
	costs := requestPipelineRecorder(ctx)
	if costs == nil || kind >= pipelineKinds || now == nil {
		return requestPipelineSpan{}
	}
	metric := &costs.metrics[requestPipelineContextScope(ctx)][kind]
	metric.calls.Add(1)
	return requestPipelineSpan{metric: metric, started: now(), now: now}
}

func (s requestPipelineSpan) finish() {
	if s.metric == nil {
		return
	}
	if elapsed := s.now().Sub(s.started); elapsed > 0 {
		s.metric.wallNS.Add(uint64(elapsed))
	}
	s.metric.returned.Add(1)
}

type requestPipelineRow struct {
	Scope                    string `json:"scope"`
	Kind                     string `json:"kind"`
	Calls                    uint64 `json:"calls"`
	Returned                 uint64 `json:"returned"`
	InclusiveWallNanoseconds uint64 `json:"inclusiveWallNanoseconds"`
}

// Snapshot is a bounded, separately versioned schema. Take it AFTER joined
// operations, not as an atomic concurrent snapshot. Do includes native capture
// inside the guarded transport; body reads can wait on the network. Neither
// Do-minus-headers nor summed overlapping spans is local CPU or exclusive time.
// SDK observers are deliberately outside this direct HTTP measurement.
func (c *requestPipelineCosts) snapshot() string {
	record := struct {
		Format     string                                                       `json:"format"`
		Accounting string                                                       `json:"accounting"`
		Rows       [int(pipelineScopes) * int(pipelineKinds)]requestPipelineRow `json:"rows"`
	}{Format: "installer-request-pipeline-v1", Accounting: "direct-http-inclusive-overlapping-not-sdk-or-cpu"}
	for scope, scopeLabel := range requestPipelineScopeLabels {
		for kind, kindLabel := range requestPipelineKindLabels {
			row := &record.Rows[scope*int(pipelineKinds)+kind]
			row.Scope, row.Kind = scopeLabel, kindLabel
			if c != nil {
				metric := &c.metrics[scope][kind]
				row.Calls, row.Returned, row.InclusiveWallNanoseconds = metric.calls.Load(), metric.returned.Load(), metric.wallNS.Load()
			}
		}
	}
	encoded, _ := json.Marshal(record) // Closed scalar fields cannot fail.
	return string(encoded)
}
