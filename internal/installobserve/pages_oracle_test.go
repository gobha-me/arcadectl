// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installobserve

import (
	"context"
	"encoding/json"
	"github.com/gobha-me/arcadectl/internal/installsafety"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// Frozen exact4a2 implementation: independent oracle for diagnostic-only changes.
func originalBoundedPagesWithoutDiagnostics(ctx context.Context, fetch func(context.Context, metav1.ListOptions) (runtime.Object, error), budget *int) ([]runtime.Object, string, error) {
	items := []runtime.Object{}
	rv, token := "", ""
	bytesRead := 0
	seen := map[string]bool{}
	for range maxPages {
		if ctx.Err() != nil {
			return nil, "", ErrRead
		}
		page, err := fetch(ctx, metav1.ListOptions{Limit: pageLimit, Continue: token})
		if err != nil || nilClient(page) {
			return nil, "", ErrRead
		}
		body, err := json.Marshal(page)
		if err != nil || len(body) > maxResponseBytes || bytesRead+len(body) > maxCollectionBytes || budget == nil || len(body) > *budget {
			return nil, "", ErrRead
		}
		bytesRead += len(body)
		*budget -= len(body)
		m, err := meta.ListAccessor(page)
		if err != nil || !validIdentity(m.GetResourceVersion()) || rv != "" && rv != m.GetResourceVersion() || len(m.GetContinue()) > maxContinueBytes {
			return nil, "", ErrRead
		}
		rv = m.GetResourceVersion()
		pageItems, err := meta.ExtractList(page)
		if err != nil || len(items)+len(pageItems) > installsafety.MaxObjectsPerList {
			return nil, "", ErrRead
		}
		items = append(items, pageItems...)
		token = m.GetContinue()
		if token == "" {
			if count := m.GetRemainingItemCount(); count != nil && *count != 0 {
				return nil, "", ErrRead
			}
			return items, rv, nil
		}
		if seen[token] || m.GetRemainingItemCount() != nil && *m.GetRemainingItemCount() < 0 {
			return nil, "", ErrRead
		}
		seen[token] = true
	}
	return nil, "", ErrRead
}
