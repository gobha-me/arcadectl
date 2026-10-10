// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installobserve

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestPagesCompleteEmptyIntermediateAndNoSelectors(t *testing.T) {
	calls := 0
	items, rv, err := allPages(context.Background(), func(_ context.Context, opts metav1.ListOptions) (runtime.Object, error) {
		calls++
		if opts.Limit != pageLimit || opts.LabelSelector != "" || opts.FieldSelector != "" || opts.ResourceVersion != "" || opts.ResourceVersionMatch != "" || opts.Watch || opts.AllowWatchBookmarks {
			t.Fatal("list is filtered or cache-consistent only")
		}
		page := &metav1.PartialObjectMetadataList{ListMeta: metav1.ListMeta{ResourceVersion: "same-rv"}, Items: []metav1.PartialObjectMetadata{}}
		switch calls {
		case 1:
			if opts.Continue != "" {
				t.Fatal("first request resumes unknown page")
			}
			page.Continue = "page-two"
			page.Items = append(page.Items, metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{Name: "a"}})
		case 2:
			if opts.Continue != "page-two" {
				t.Fatal("missing second page")
			}
			page.Continue = "page-three"
		case 3:
			if opts.Continue != "page-three" {
				t.Fatal("missing final page")
			}
			page.Items = append(page.Items, metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{Name: "b"}})
		default:
			t.Fatal("list replayed after completion")
		}
		return page, nil
	})
	if err != nil || rv != "same-rv" || len(items) != 2 || calls != 3 {
		t.Fatal("complete pagination not established")
	}
}

func TestPagesDiscardIncompleteEvidenceWithoutRestart(t *testing.T) {
	for _, tc := range []string{"read-error", "nil", "typed-nil", "rv-change", "rv-empty", "rv-large", "repeat", "cycle", "endless-empty", "continue-large", "remaining-negative", "final-remaining", "object-bound", "byte-bound"} {
		t.Run(tc, func(t *testing.T) {
			calls := 0
			items, rv, err := allPages(context.Background(), func(_ context.Context, opts metav1.ListOptions) (runtime.Object, error) {
				calls++
				if calls > 1 && opts.Continue == "" {
					t.Fatal("failed list restarted")
				}
				page := &metav1.PartialObjectMetadataList{ListMeta: metav1.ListMeta{ResourceVersion: "rv", Continue: fmt.Sprint(calls)}}
				if calls == 1 {
					return page, nil
				}
				switch tc {
				case "read-error":
					return nil, errors.New("raw-canary")
				case "nil":
					return nil, nil
				case "typed-nil":
					return (*metav1.PartialObjectMetadataList)(nil), nil
				case "rv-change":
					page.ResourceVersion = "new-rv"
				case "rv-empty":
					page.ResourceVersion = ""
				case "rv-large":
					page.ResourceVersion = strings.Repeat("v", 129)
				case "repeat":
					page.Continue = "1"
				case "cycle":
					if calls == 3 {
						page.Continue = "1"
					}
				case "endless-empty": // The independent page bound handles empty pages.
				case "continue-large":
					page.Continue = strings.Repeat("t", maxContinueBytes+1)
				case "remaining-negative":
					n := int64(-1)
					page.RemainingItemCount = &n
				case "final-remaining":
					n := int64(1)
					page.RemainingItemCount, page.Continue = &n, ""
				case "object-bound":
					page.Items = make([]metav1.PartialObjectMetadata, 10001)
				case "byte-bound":
					page.Items = []metav1.PartialObjectMetadata{{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{"large": strings.Repeat("x", maxResponseBytes)}}}}
				}
				return page, nil
			})
			if !errors.Is(err, ErrRead) || items != nil || rv != "" || calls > maxPages || strings.Contains(err.Error(), "raw-canary") {
				t.Fatal("incomplete pages used as evidence")
			}
		})
	}
}

func TestPagesAggregateBudgetAndCancellation(t *testing.T) {
	calls := 0
	items, _, err := allPages(context.Background(), func(_ context.Context, _ metav1.ListOptions) (runtime.Object, error) {
		calls++
		return &metav1.PartialObjectMetadataList{ListMeta: metav1.ListMeta{ResourceVersion: "rv", Continue: fmt.Sprint(calls)}, Items: []metav1.PartialObjectMetadata{{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{"large": strings.Repeat("x", maxResponseBytes/2)}}}}}, nil
	})
	if !errors.Is(err, ErrRead) || items != nil || calls > 5 {
		t.Fatal("aggregate budget did not bound pages")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := allPages(ctx, func(context.Context, metav1.ListOptions) (runtime.Object, error) {
		t.Fatal("canceled observation issued a request")
		return nil, nil
	}); !errors.Is(err, ErrRead) {
		t.Fatal("cancellation accepted")
	}
}
