// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installobserve

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestGCPagesDiagnosticClosedStatesAndRefusalTimeSnapshot(t *testing.T) {
	g := &GCReader{}
	unknown := "reason=unknown inner=unknown caller=unknown"
	if g.DiagnosticPagesRefusal() != unknown || (*GCReader)(nil).DiagnosticPagesRefusal() != unknown {
		t.Fatal("absent diagnostics invented a refusal")
	}
	for reason := pagesRefusalContext; reason <= pagesRefusalPages; reason++ {
		for inner := uint32(0); inner <= 3; inner++ {
			for caller := uint32(0); caller <= 3; caller++ {
				g.pagesDiagnostic.Store(uint32(reason) | inner<<8 | caller<<16)
				want := "reason=" + pagesReasonLabel(reason) + " inner=" + pagesContextLabel(inner) + " caller=" + pagesContextLabel(caller)
				if g.DiagnosticPagesRefusal() != want {
					t.Fatal("finite state changed")
				}
			}
		}
	}
	for _, value := range []uint32{0, 9, 255, 1 << 24, uint32(pagesRefusalFetch) | 4<<8, uint32(pagesRefusalFetch) | 4<<16} {
		g.pagesDiagnostic.Store(value)
		if g.DiagnosticPagesRefusal() != unknown {
			t.Fatal("corrupt state exposed")
		}
	}
	active := t.Context()
	cancelled, cancel := context.WithCancel(active)
	cancel()
	expired, expire := context.WithTimeout(active, 0)
	defer expire()
	for _, tc := range []struct {
		inner, caller context.Context
		want          string
	}{
		{active, active, "inner=active caller=active"},
		{cancelled, active, "inner=cancelled caller=active"},
		{expired, active, "inner=deadline caller=active"},
		{expired, expired, "inner=deadline caller=deadline"},
		{cancelled, cancelled, "inner=cancelled caller=cancelled"},
		{nil, nil, "inner=unknown caller=unknown"},
	} {
		g.recordPagesRefusal(pagesRefusalFetch, tc.inner, tc.caller)
		if g.DiagnosticPagesRefusal() != "reason=fetch-unclassified "+tc.want {
			t.Fatal("context state lost")
		}
	}
	inner, finish := context.WithCancel(active)
	g.recordPagesRefusal(pagesRefusalFetch, inner, active)
	finish()
	if g.DiagnosticPagesRefusal() != "reason=fetch-unclassified inner=active caller=active" {
		t.Fatal("getter substituted deferred cancellation")
	}
	g.Collect(nil, nil)
	if g.DiagnosticPagesRefusal() != unknown {
		t.Fatal("invalid attempt retained previous refusal")
	}
}

func TestGCPagesDiagnosticActualFetchRefusalAndSuccessReset(t *testing.T) {
	h := newGCHTTPFixture(t, "denied")
	discovery, err := h.g.Discover(t.Context(), h.f.anchor)
	if err != nil {
		t.Fatal(err)
	}
	observation, err := h.g.Collect(t.Context(), discovery)
	if observation != nil || err != ErrRead || h.g.DiagnosticStage() != "metadata-pages" || h.lists != 1 {
		t.Fatal("actual fetch refusal changed requests/results", err, h.lists)
	}
	if got := h.g.DiagnosticPagesRefusal(); got != "reason=fetch-unclassified inner=active caller=active" || strings.Contains(got, "PRIVATE-GC-CANARY") {
		t.Fatal("post-return diagnostic exposed error or deferred cancellation", got)
	}
	h.fault = ""
	if observation, err = h.g.Collect(t.Context(), discovery); err != nil || observation == nil {
		t.Fatal("successful complete collection changed", err)
	}
	if h.g.DiagnosticPagesRefusal() != "reason=unknown inner=unknown caller=unknown" {
		t.Fatal("success retained old refusal")
	}
}

func TestPagesDiagnosticBudgetChargingAndCancellationUnchanged(t *testing.T) {
	page := &metav1.PartialObjectMetadataList{ListMeta: metav1.ListMeta{ResourceVersion: "rv"}}
	body, err := json.Marshal(page)
	if err != nil {
		t.Fatal(err)
	}
	for _, size := range []int{-1, 0, len(body) - 1, len(body), len(body) + 1} {
		budget, calls := size, 0
		items, rv, err, reason := boundedPagesDiagnostic(t.Context(), func(_ context.Context, opts metav1.ListOptions) (runtime.Object, error) {
			calls++
			if opts != (metav1.ListOptions{Limit: pageLimit}) {
				t.Fatal("request options changed")
			}
			return page, nil
		}, &budget)
		if calls != 1 {
			t.Fatal("extra fetch")
		}
		if size < len(body) {
			if items != nil || rv != "" || err != ErrRead || reason != pagesRefusalBytes || budget != size {
				t.Fatal("failed bytes charged or evidence retained")
			}
		} else if err != nil || rv != "rv" || len(items) != 0 || reason != pagesRefusalUnknown || budget != size-len(body) {
			t.Fatal("successful budget/result changed")
		}
	}
	// Identity refusal still charges marshalled bytes before validating RV.
	page.ResourceVersion = ""
	body, _ = json.Marshal(page)
	budget := maxCollectionBytes
	_, _, err, reason := boundedPagesDiagnostic(t.Context(), func(context.Context, metav1.ListOptions) (runtime.Object, error) { return page, nil }, &budget)
	if err != ErrRead || reason != pagesRefusalIdentity || budget != maxCollectionBytes-len(body) {
		t.Fatal("validation moved before charging")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, _, err, reason = boundedPagesDiagnostic(ctx, func(context.Context, metav1.ListOptions) (runtime.Object, error) {
		t.Fatal("cancelled request issued")
		return nil, nil
	}, &budget)
	if err != ErrRead || reason != pagesRefusalContext {
		t.Fatal("cancellation diagnostic changed refusal")
	}
}
