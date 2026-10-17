// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installobserve

import (
	"context"
	"sync"

	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
)

// NewWithPairedCollectionReads is a trusted scheduling seam for the installer's
// closed native static identity and shared default limiter. Its caller must
// establish that provenance; New/NewWithClients retain serial scheduling for
// arbitrary instrumentation and caller-supplied rate/transport configurations.
// It changes neither evidence authority nor the rate/deadline/page budgets.
func NewWithPairedCollectionReads(config *rest.Config, journal *installstate.Store, plan *installrender.Plan) (*Observer, error) {
	if config == nil || config.RateLimiter == nil {
		return nil, ErrInvalid
	}
	o, err := New(config, journal, plan)
	if err != nil {
		return nil, err
	}
	o.pairedCollections = true
	return o, nil
}

// Only the second collection's first page is prefetched. The caller consumes
// the first collection (including every continuation) before consuming that
// page exactly once through the unchanged page/byte/shape checks. All graph,
// aggregate budget and typed target writes stay on the caller. Secrets remain
// serial metadata-only reads and are never paired by Collect.
//
// One pending native response adds at most the existing 4MiB wire page bound
// plus its decoded representation; 32MiB remains an accepted-evidence budget,
// NOT a total-heap limit. No whole collection, third request or continuation is
// prefetched. Closing owner/journal work cannot outrun the joined worker.
func (o *Observer) collectPair(ctx context.Context, first, second collection, graph *ownerGraph, budget *int) error {
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		page runtime.Object
		err  error
	}
	done := make(chan result, 1)
	var joined sync.WaitGroup
	joined.Add(1)
	go func() {
		defer joined.Done()
		page, err := o.collectionPage(child, second, metav1.ListOptions{Limit: pageLimit})
		done <- result{page: page, err: err}
	}()
	if err := o.collectList(child, first, graph, budget); err != nil {
		cancel()
		<-done // Even refused/cancelled reads join before returning.
		joined.Wait()
		return err
	}
	// A failed second page never cancels the earlier canonical collection.
	// Its error is consumed only at its original collection boundary.
	prefetched := <-done
	joined.Wait()
	if ctx.Err() != nil {
		return ErrRead
	}
	used := false
	return o.collectListWithFetch(child, second, graph, budget, nil, func(ctx context.Context, opts metav1.ListOptions) (runtime.Object, error) {
		if !used {
			used = true
			if opts.Limit != pageLimit || opts.Continue != "" || opts.ResourceVersion != "" || opts.ResourceVersionMatch != "" || opts.LabelSelector != "" || opts.FieldSelector != "" || opts.Watch {
				return nil, ErrRead
			}
			page, err := prefetched.page, prefetched.err
			prefetched = result{}
			return page, err
		}
		return o.collectionPage(ctx, second, opts)
	})
}
