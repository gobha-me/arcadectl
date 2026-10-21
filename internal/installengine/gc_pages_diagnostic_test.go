// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"strings"
	"sync"
	"testing"
)

func TestLifecycleGCPagesDiagnosticClosedAndFreshAttempts(t *testing.T) {
	var absent *LifecycleDiagnostic
	if absent.GCPagesSnapshot() != "" {
		t.Fatal("nil recorder invented progress")
	}
	for _, ctx := range []context.Context{nil, t.Context(), context.WithValue(t.Context(), lifecycleDiagnosticKey{}, "PRIVATE-CANARY")} {
		beginGCPagesDiagnostic(ctx)("reason=fetch-unclassified inner=active caller=active")
	}
	ctx, diagnostic := WithLifecycleDiagnostic(t.Context())
	first := beginGCPagesDiagnostic(ctx)
	if diagnostic.GCPagesSnapshot() != "" {
		t.Fatal("unfinished attempt invented refusal")
	}
	want := "reason=fetch-unclassified inner=deadline caller=active"
	first(want)
	if diagnostic.GCPagesSnapshot() != want {
		t.Fatal("fixed refusal not recorded")
	}
	second := beginGCPagesDiagnostic(ctx)
	if diagnostic.GCPagesSnapshot() != "" {
		t.Fatal("new attempt retained old refusal")
	}
	first(want)
	if diagnostic.GCPagesSnapshot() != "" {
		t.Fatal("late old completion republished pointer")
	}
	second("reason=bytes inner=active caller=active")
	if diagnostic.GCPagesSnapshot() != "reason=bytes inner=active caller=active" {
		t.Fatal("current attempt missing")
	}
	traceLifecycleCheckpoint(ctx, ColdSafety, lifecycleDiagnosticEntered)
	second(want)
	if diagnostic.GCPagesSnapshot() != "" {
		t.Fatal("late completion survived checkpoint reset")
	}
	_, fresh := WithLifecycleDiagnostic(ctx)
	if fresh.GCPagesSnapshot() != "" {
		t.Fatal("new step inherited old diagnostic")
	}
	for _, reason := range []string{"unknown", "context", "fetch-unclassified", "shape", "bytes", "identity", "objects", "continuation", "pages"} {
		for _, inner := range []string{"unknown", "active", "cancelled", "deadline"} {
			for _, caller := range []string{"unknown", "active", "cancelled", "deadline"} {
				value := "reason=" + reason + " inner=" + inner + " caller=" + caller
				beginGCPagesDiagnostic(ctx)(value)
				if diagnostic.GCPagesSnapshot() != value {
					t.Fatal("valid finite value refused")
				}
			}
		}
	}
	for _, value := range []string{"", "PRIVATE-CANARY", strings.Repeat("x", 97), want + "\n", want + " extra=PRIVATE-CANARY", "reason=fetch-unclassified inner=PRIVATE-CANARY caller=active", "reason=unknown  inner=active caller=active", "reason=unknown inner=active caller=active\x00"} {
		beginGCPagesDiagnostic(ctx)(value)
		if diagnostic.GCPagesSnapshot() != "" {
			t.Fatal("untrusted diagnostic exposed")
		}
		// Getter independently refuses corrupted internal storage.
		recorder := &gcPagesDiagnostic{}
		recorder.value.Store(&value)
		diagnostic.gcPages.Store(recorder)
		if diagnostic.GCPagesSnapshot() != "" {
			t.Fatal("corrupt storage exposed")
		}
	}
}

func TestLifecycleGCPagesDiagnosticConcurrentLateCompletion(t *testing.T) {
	ctx, diagnostic := WithLifecycleDiagnostic(t.Context())
	old := beginGCPagesDiagnostic(ctx)
	current := beginGCPagesDiagnostic(ctx)
	want := "reason=bytes inner=active caller=active"
	current(want)
	var joined sync.WaitGroup
	for range 4 {
		joined.Add(1)
		go func() {
			defer joined.Done()
			for range 100 {
				old("reason=fetch-unclassified inner=deadline caller=active")
				if diagnostic.GCPagesSnapshot() != want {
					t.Error("late old attempt replaced current")
				}
			}
		}()
	}
	joined.Wait()
}
