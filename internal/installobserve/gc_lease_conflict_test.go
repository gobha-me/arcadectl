// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installobserve

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestGCLeaseRefusalRequiresCompleteForwardRVOnlyAndClosingBarrier(t *testing.T) {
	for _, fault := range []string{"rv", "rv-back", "generation", "missing", "uid", "name", "owner", "late-denial", "page-rv", "unknown-field", "rv-post-discovery", "rv-post-journal"} {
		t.Run(fault, func(t *testing.T) {
			h := newGCHTTPFixture(t, "lease-last")
			h.wholeFault = fault
			if fault == "rv-post-journal" {
				h.afterRead = func(path string) {
					if path != "/api" || h.wholeReads == 0 {
						return
					}
					ns, err := h.f.core.CoreV1().Namespaces().Get(t.Context(), h.f.anchor.Namespace, metav1.GetOptions{})
					if err != nil {
						t.Fatal(err)
					}
					ns.ResourceVersion = "2"
					if _, err := h.f.core.CoreV1().Namespaces().Update(t.Context(), ns, metav1.UpdateOptions{}); err != nil {
						t.Fatal(err)
					}
				}
			}
			discovery, err := h.g.Discover(t.Context(), h.f.anchor)
			if err != nil {
				t.Fatal(err)
			}
			observation, refusal, err := h.g.CollectWithLeaseRefusal(t.Context(), discovery, NewGCReadBudget())
			if err == nil || observation != nil || (refusal != nil) != (fault == "rv") {
				t.Fatal("unsafe/incomplete mismatch became refusal evidence or successful observation", fault, err)
			}
			if refusal == nil {
				return
			}
			if err != ErrConcurrent || refusal.Journal() == nil || !sameGCJournal(discovery.journal, refusal.Journal()) {
				t.Fatal("refusal lost original journal/sentinel")
			}
			leases, at := refusal.WholeLeases()
			if leases == nil || len(leases.Items) != 129 || at.IsZero() || h.wholeReads != 2 || h.reads["/apis"] != 3 {
				t.Fatal("refusal skipped complete pages or closing discovery")
			}
			leases.Items[128].ResourceVersion = "forged"
			rows := refusal.Objects()
			rows[0].Metadata.ResourceVersion = "forged"
			again, _ := refusal.WholeLeases()
			if again.Items[128].ResourceVersion != "22" || refusal.Objects()[0].Metadata.ResourceVersion == "forged" {
				t.Fatal("mutable refusal accessor changed internal evidence")
			}
			// The fourth collection must fail before issuing another request.
			budget := NewGCReadBudget()
			for range 3 {
				if o, c, e := h.g.CollectWithLeaseRefusal(t.Context(), discovery, budget); o != nil || c == nil || e != ErrConcurrent {
					t.Fatal("closed refusal attempt unavailable", e)
				}
			}
			before := h.lists
			if o, c, e := h.g.CollectWithLeaseRefusal(t.Context(), discovery, budget); o != nil || c != nil || e != ErrRead || h.lists != before {
				t.Fatal("attempt budget allowed another read")
			}
		})
	}
}

func TestGCLeaseRefusalBudgetNeverResetsAndCancellationNeverYieldsCandidate(t *testing.T) {
	h := newGCHTTPFixture(t, "lease-last")
	discovery, err := h.g.Discover(t.Context(), h.f.anchor)
	if err != nil {
		t.Fatal(err)
	}
	budget := NewGCReadBudget()
	budget.remaining = 1
	if o, c, e := h.g.CollectWithLeaseRefusal(t.Context(), discovery, budget); o != nil || c != nil || e != ErrRead || budget.remaining != 1 {
		t.Fatal("shared byte budget was reset", e)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if o, c, e := h.g.CollectWithLeaseRefusal(ctx, discovery, NewGCReadBudget()); o != nil || c != nil || e == nil {
		t.Fatal("cancelled read supplied partial candidate")
	}
}
