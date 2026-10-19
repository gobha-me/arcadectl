// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRequestPipelineDisabledHasNoClockOrAllocation(t *testing.T) {
	clock := func() time.Time { t.Fatal("disabled observation called its clock"); return time.Time{} }
	for _, ctx := range []context.Context{nil, context.Background(), context.WithValue(context.Background(), requestPipelineKey{}, (*requestPipelineCosts)(nil))} {
		if withRequestPipelineScope(ctx, pipelineBaselineOpening) != ctx || withRequestPipelineInventory(ctx) != ctx {
			t.Fatal("disabled observation changed its context")
		}
		if allocs := testing.AllocsPerRun(100, func() {
			beginRequestPipelineCostWithClock(ctx, pipelineClientDo, clock).finish()
			beginRequestPipelineCost(ctx, pipelineClientDo).finish()
			withRequestPipelineScope(ctx, pipelineBaselineOpening)
			withRequestPipelineInventory(ctx)
		}); allocs != 0 {
			t.Fatal("disabled observation allocated")
		}
	}
	if ctx, costs := withRequestPipelineCosts(nil); ctx != nil || costs != nil {
		t.Fatal("nil input acquired a recorder")
	}
}

func requestPipelineTestRows(t *testing.T, costs *requestPipelineCosts) []requestPipelineRow {
	t.Helper()
	text := costs.snapshot()
	var fields map[string]json.RawMessage
	var record struct {
		Format     string               `json:"format"`
		Accounting string               `json:"accounting"`
		Rows       []requestPipelineRow `json:"rows"`
	}
	decoder := json.NewDecoder(strings.NewReader(text))
	decoder.DisallowUnknownFields()
	if len(text) > 16384 || strings.Contains(text, "PRIVATE-CANARY") || json.Unmarshal([]byte(text), &fields) != nil || len(fields) != 3 || decoder.Decode(&record) != nil || record.Format != "installer-request-pipeline-v1" || record.Accounting != "direct-http-inclusive-overlapping-not-sdk-or-cpu" || len(record.Rows) != 48 {
		t.Fatal("pipeline snapshot lost its bounded independent closed schema")
	}
	// Literal v1 schema expectations are independent of the producer tables.
	for scope, label := range []string{"baseline-discovery", "baseline-opening", "baseline-dry-run", "baseline-closing", "public-inventory", "other"} {
		for kind, name := range []string{"client-do", "roundtrip-to-headers", "guarded-post-headers", "outer-body-read", "post-body-validation", "public-inventory", "contract-check", "phase-row"} {
			row := record.Rows[scope*8+kind]
			if row.Scope != label || row.Kind != name || row.Returned > row.Calls {
				t.Fatal("pipeline rows lost fixed order, labels or call accounting")
			}
		}
	}
	return record.Rows
}

func TestRequestPipelinePartialAccountingPrivacyAndCommandReset(t *testing.T) {
	ctx, costs := withRequestPipelineCosts(context.WithValue(context.Background(), struct{ private bool }{true}, "PRIVATE-CANARY"))
	opening := withRequestPipelineScope(ctx, pipelineBaselineOpening)
	tick := 0
	clock := func() time.Time { tick++; return time.Unix(0, int64(tick)) }
	beginRequestPipelineCostWithClock(opening, pipelineClientDo, clock).finish()
	partial := beginRequestPipelineCostWithClock(opening, pipelineClientDo, clock)
	row := requestPipelineTestRows(t, costs)[int(pipelineBaselineOpening)*int(pipelineKinds)+int(pipelineClientDo)]
	if tick != 3 || row.Calls != 2 || row.Returned != 1 || row.InclusiveWallNanoseconds != 1 {
		t.Fatal("partial calls were relabeled returned or duration became exclusive")
	}
	partial.finish()
	if tick != 4 {
		t.Fatal("enabled span did not use exactly one opening and closing clock call")
	}
	before := costs.snapshot()
	beginRequestPipelineCostWithClock(opening, pipelineKinds, clock).finish()
	beginRequestPipelineCostWithClock(opening, pipelineClientDo, nil).finish()
	if tick != 4 || before != costs.snapshot() || withRequestPipelineScope(opening, pipelineScopes) != opening {
		t.Fatal("invalid observation changed counters, context or clock")
	}
	oldPending := beginRequestPipelineCostWithClock(opening, pipelineClientDo, clock)
	fresh, newCosts := withRequestPipelineCosts(opening)
	if requestPipelineContextScope(fresh) != pipelineOther || requestPipelineContextScope(opening) != pipelineBaselineOpening {
		t.Fatal("new command inherited or mutated old phase attribution")
	}
	var empty *requestPipelineCosts
	if newCosts.snapshot() != empty.snapshot() {
		t.Fatal("new command inherited old counters")
	}
	oldPending.finish()
	if newCosts.snapshot() != empty.snapshot() {
		t.Fatal("outstanding old span followed the new command's recorder")
	}
	row = requestPipelineTestRows(t, costs)[int(pipelineBaselineOpening)*int(pipelineKinds)+int(pipelineClientDo)]
	if tick != 6 || row.Calls != 3 || row.Returned != 3 || row.InclusiveWallNanoseconds != 3 {
		t.Fatal("outstanding old span did not finish against its original recorder")
	}
	before = costs.snapshot()
	beginRequestPipelineCost(fresh, pipelineClientDo).finish()
	if costs.snapshot() != before {
		t.Fatal("new command changed old invocation counters")
	}
	requestPipelineTestRows(t, newCosts)
}

func TestRequestPipelineMaximumSnapshotRemainsBounded(t *testing.T) {
	_, costs := withRequestPipelineCosts(context.Background())
	for scope := range costs.metrics {
		for kind := range costs.metrics[scope] {
			metric := &costs.metrics[scope][kind]
			metric.calls.Store(math.MaxUint64)
			metric.returned.Store(math.MaxUint64)
			metric.wallNS.Store(math.MaxUint64)
		}
	}
	for _, row := range requestPipelineTestRows(t, costs) {
		if row.Calls != math.MaxUint64 || row.Returned != math.MaxUint64 || row.InclusiveWallNanoseconds != math.MaxUint64 {
			t.Fatal("maximum numeric snapshot lost precision")
		}
	}
}

func TestRequestPipelineScopeIsolationCancellationAndNegativeClock(t *testing.T) {
	ctx, costs := withRequestPipelineCosts(context.Background())
	inventory := withRequestPipelineInventory(ctx)
	opening := withRequestPipelineScope(ctx, pipelineBaselineOpening)
	closing := withRequestPipelineScope(opening, pipelineBaselineClosing)
	if requestPipelineContextScope(ctx) != pipelineOther || requestPipelineContextScope(inventory) != pipelinePublicInventory || withRequestPipelineInventory(opening) != opening || requestPipelineContextScope(opening) != pipelineBaselineOpening || requestPipelineContextScope(closing) != pipelineBaselineClosing {
		t.Fatal("nested contexts overwrote independent baseline or inventory attribution")
	}
	cancelled, cancel := context.WithCancelCause(closing)
	cause := errors.New("PRIVATE-CANARY")
	cancel(cause)
	ticks := 0
	clock := func() time.Time { ticks++; return time.Unix(0, int64(10-ticks)) }
	beginRequestPipelineCostWithClock(cancelled, pipelineValidation, clock).finish()
	row := requestPipelineTestRows(t, costs)[int(pipelineBaselineClosing)*int(pipelineKinds)+int(pipelineValidation)]
	if row.Calls != 1 || row.Returned != 1 || row.InclusiveWallNanoseconds != 0 || cancelled.Err() != context.Canceled || context.Cause(cancelled) != cause {
		t.Fatal("refused observation changed cancellation or underflowed duration")
	}
}

func TestRequestPipelineConcurrentImmutablePhases(t *testing.T) {
	ctx, costs := withRequestPipelineCosts(context.Background())
	var joined sync.WaitGroup
	for scope := pipelineBaselineDiscovery; scope <= pipelineBaselineClosing; scope++ {
		phase := withRequestPipelineScope(ctx, scope)
		for lane := 0; lane < 8; lane++ {
			joined.Add(1)
			go func() {
				defer joined.Done()
				for call := 0; call < 64; call++ {
					beginRequestPipelineCost(phase, pipelineClientDo).finish()
				}
			}()
		}
	}
	joined.Wait()
	for _, row := range requestPipelineTestRows(t, costs) {
		want := uint64(0)
		if row.Kind == "client-do" && row.Scope != "public-inventory" && row.Scope != "other" {
			want = 512
		}
		if row.Calls != want || row.Returned != want {
			t.Fatal("concurrent phases followed another lane or lost joined accounting")
		}
	}
}
