// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installstate"
)

func TestBaselineRuntimeDispatchRefusesIncompleteContextsBeforeWire(t *testing.T) {
	f := newBaselineFixture(t) // Pinned only, explicitly not verified enforcement.
	var requests atomic.Int32
	var waitForDeadline atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if waitForDeadline.Load() {
			<-r.Context().Done()
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()
	access, err := NewDirectHTTPAccess(serverConfig(server))
	if err != nil {
		t.Fatal("closed runtime refusal transport unavailable")
	}
	store, err := installstate.NewWithBaseline(access.Namespaces(), f.engine.baselinePlan(), f.plan)
	if err != nil {
		t.Fatal("runtime refusal journal unavailable")
	}
	engine, err := NewWithBaselineAccess(access, store, f.engine.files, f.engine.baselinePlan(), f.plan)
	if err != nil {
		t.Fatal("runtime refusal engine unavailable")
	}
	provider, err := NewClusterSecurityBaseline(engine, access)
	if err != nil {
		t.Fatal("runtime refusal provider unavailable")
	}
	if provider.Verify(t.Context(), f.snapshot) != ErrSecurityBaseline {
		t.Fatal("pinned baseline was treated as verified runtime security")
	}
	if provider.Verify(nil, f.snapshot) != ErrSecurityBaseline || provider.Verify(t.Context(), nil) != ErrSecurityBaseline {
		t.Fatal("missing runtime proof context entered dispatch")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if provider.Verify(ctx, f.snapshot) != ErrSecurityBaseline {
		t.Fatal("cancelled runtime proof context entered dispatch")
	}
	var absent *ClusterSecurityBaseline
	if absent.Verify(t.Context(), f.snapshot) != ErrSecurityBaseline {
		t.Fatal("nil runtime provider entered dispatch")
	}
	for _, mutate := range []func(*ClusterSecurityBaseline, *Engine){
		func(c *ClusterSecurityBaseline, e *Engine) { c.engine = nil },
		func(c *ClusterSecurityBaseline, e *Engine) { c.access = nil },
		func(c *ClusterSecurityBaseline, e *Engine) { e.baseline = nil },
		func(c *ClusterSecurityBaseline, e *Engine) { e.journal = nil },
		func(c *ClusterSecurityBaseline, e *Engine) { e.access = f.access },
		func(c *ClusterSecurityBaseline, e *Engine) {
			copy := *e.baseline
			copy.plan = baselineFixturePlan(t, f.plan.Namespace(), f.plan.Profile().ID, 'e')
			e.baseline = &copy // Authenticated but not the journal's original pin.
		},
	} {
		copy, engineCopy := *provider, *engine
		copy.engine = &engineCopy
		mutate(&copy, &engineCopy)
		if copy.Verify(t.Context(), f.snapshot) != ErrSecurityBaseline {
			t.Fatal("incomplete original runtime binding entered dispatch")
		}
	}
	if requests.Load() != 0 || engine.baseline.runtimeGuard != nil || f.access.writes != 0 {
		t.Fatal("runtime refusal performed wire/effects or installed itself as authority")
	}
	// A real caller deadline reached during the actual provider's first remote
	// witness is distinct from an inferred transport or structural cause.
	completeBaselineFixture(t, f)
	writes, updates := f.access.writes, f.nsUpdates
	waitForDeadline.Store(true)
	deadlineCtx, deadlineCancel := context.WithTimeout(t.Context(), time.Second)
	defer deadlineCancel()
	deadlineCtx, diagnostic := WithLifecycleDiagnostic(deadlineCtx)
	if provider.Verify(deadlineCtx, f.snapshot) != ErrSecurityBaseline || requests.Load() != 1 || diagnostic.BoundarySnapshot() != "operation=unknown baseline=runtime-deadline" || engine.baseline.runtimeGuard != nil || f.access.writes != writes || f.nsUpdates != updates {
		t.Fatal("actual runtime deadline changed refusal/effect behavior or lost its bounded diagnostic", diagnostic.BoundarySnapshot())
	}
}

func TestClusterLifecycleInstallsClosedBaselineRuntimeGuard(t *testing.T) {
	f := newBaselineFixture(t)
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()
	access, err := NewDirectHTTPAccess(serverConfig(server))
	if err != nil {
		t.Fatal("closed constructor transport unavailable")
	}
	store, err := installstate.NewWithBaseline(access.Namespaces(), f.engine.baselinePlan(), f.plan)
	if err != nil {
		t.Fatal("closed constructor journal unavailable")
	}
	engine, err := NewWithBaselineAccess(access, store, f.engine.files, f.engine.baselinePlan(), f.plan)
	if err != nil {
		t.Fatal("closed constructor engine unavailable")
	}
	if _, err := NewClusterLifecycle(engine, nil); err != ErrInvalid || engine.baseline.prerequisites != nil || engine.baseline.runtimeGuard != nil {
		t.Fatal("invalid constructor populated partial authority")
	}
	lifecycle, err := NewClusterLifecycle(engine, access)
	guard, ok := engine.baseline.runtimeGuard.(*ClusterSecurityBaseline)
	if err != nil || lifecycle == nil || lifecycle.engine != engine || !ok || guard == nil || guard != engine.baseline.prerequisites || guard.engine != engine || guard.access != access {
		t.Fatal("production lifecycle failed to install same closed original runtime/prerequisite proof")
	}
	if engine.baseline.verifyRuntime(t.Context(), f.snapshot) != ErrSecurityBaseline {
		t.Fatal("constructor made incomplete baseline ownership runtime authority")
	}
	if requests.Load() != 0 {
		t.Fatal("constructor or incomplete-baseline refusal contacted network")
	}
	completeBaselineFixture(t, f) // Synthetic ownership, not effective enforcement.
	if engine.baseline.verifyRuntime(t.Context(), f.snapshot) != ErrSecurityBaseline || requests.Load() == 0 {
		t.Fatal("constructor bypassed full live proof after baseline ownership completion")
	}
	if _, err := NewClusterLifecycle(engine, nil); err != ErrInvalid || engine.baseline.runtimeGuard != guard || engine.baseline.prerequisites != guard {
		t.Fatal("invalid reconstruction changed closed authority")
	}
}
