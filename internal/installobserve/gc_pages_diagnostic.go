// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installobserve

import "context"

type pagesRefusalReason uint8

const (
	pagesRefusalUnknown pagesRefusalReason = iota
	pagesRefusalContext
	pagesRefusalFetch
	pagesRefusalShape
	pagesRefusalBytes
	pagesRefusalIdentity
	pagesRefusalObjects
	pagesRefusalContinuation
	pagesRefusalPages
)

func pagesReasonLabel(reason pagesRefusalReason) string {
	switch reason {
	case pagesRefusalContext:
		return "context"
	case pagesRefusalFetch:
		return "fetch-unclassified"
	case pagesRefusalShape:
		return "shape"
	case pagesRefusalBytes:
		return "bytes"
	case pagesRefusalIdentity:
		return "identity"
	case pagesRefusalObjects:
		return "objects"
	case pagesRefusalContinuation:
		return "continuation"
	case pagesRefusalPages:
		return "pages"
	}
	return "unknown"
}

func pagesContextState(ctx context.Context) uint32 {
	if ctx == nil {
		return 0
	}
	switch ctx.Err() {
	case nil:
		return 1
	case context.Canceled:
		return 2
	case context.DeadlineExceeded:
		return 3
	}
	return 0
}

func pagesContextLabel(state uint32) string {
	switch state {
	case 1:
		return "active"
	case 2:
		return "cancelled"
	case 3:
		return "deadline"
	}
	return "unknown"
}

func (g *GCReader) resetDiagnostics() {
	if g != nil {
		g.diagnostic.Store(0)
		g.pagesDiagnostic.Store(0)
	}
}

func (g *GCReader) recordPagesRefusal(reason pagesRefusalReason, inner, caller context.Context) {
	if g != nil {
		// Snapshot before the inner deferred cancel. Never retain the contexts
		// or inspect a fetch error, response, object or request identity.
		g.pagesDiagnostic.Store(uint32(reason) | pagesContextState(inner)<<8 | pagesContextState(caller)<<16)
	}
}

// DiagnosticPagesRefusal reports only the rejecting branch and context states
// observed at that refusal. Read it after Collect returns. It is not evidence,
// retry authority or causal attribution; fetch failures remain unclassified.
func (g *GCReader) DiagnosticPagesRefusal() string {
	unknown := "reason=unknown inner=unknown caller=unknown"
	if g == nil {
		return unknown
	}
	value := g.pagesDiagnostic.Load()
	reason, inner, caller := value&255, value>>8&255, value>>16&255
	if value>>24 != 0 || reason == 0 || reason > uint32(pagesRefusalPages) || inner > 3 || caller > 3 {
		return unknown
	}
	return "reason=" + pagesReasonLabel(pagesRefusalReason(reason)) + " inner=" + pagesContextLabel(inner) + " caller=" + pagesContextLabel(caller)
}
