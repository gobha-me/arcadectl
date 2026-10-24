// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installobserve

import (
	"context"
	"fmt"
	"sync/atomic"
)

type collectionDiagnosticKey struct{}
type collectionAttemptKey struct{}

// CollectionDiagnostic records only fixed branches from one complete typed
// observation. It retains no context, object, error, identity or request. It is
// not evidence, a retry classification or permission to accept partial reads.
type CollectionDiagnostic struct {
	latest atomic.Pointer[collectionAttempt]
}
type collectionAttempt struct {
	position atomic.Uint32
	contexts atomic.Uint32
}

// WithCollectionDiagnostic installs a fresh optional recorder. Every Collect
// invocation publishes its own attempt before reading. A late completion can
// update only its original attempt, never a later invocation's recorder.
func WithCollectionDiagnostic(ctx context.Context) (context.Context, *CollectionDiagnostic) {
	if ctx == nil {
		return nil, nil
	}
	d := &CollectionDiagnostic{}
	return context.WithValue(ctx, collectionDiagnosticKey{}, d), d
}

type collectionStage uint8

const (
	collectionEligibility collectionStage = iota + 1
	collectionJournalOpening
	collectionPlan
	collectionPages
	collectionIdentity
	collectionOwnerSeed
	collectionShape
	collectionDecode
	collectionEnvelope
	collectionOwners
	collectionJournalClosing
	collectionComplete
)

var collectionStages = [...]string{"unknown", "eligibility", "journal-opening", "plan", "list-pages", "list-identity", "list-owner-seed", "list-shape", "list-decode", "list-envelope", "owners", "journal-closing", "complete"}
var collectionKinds = [...]string{"unknown", "GameServer", "GameBackup", "GameRestore", "GameDestroy", "ArcadeOperation", "Job", "Pod", "Lease", "PersistentVolumeClaim", "Secret", "ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding", "Deployment", "ReplicaSet", "StatefulSet", "DaemonSet", "ReplicationController", "CronJob", "VolumeAttachment", "EndpointSlice"}
var collectionReasons = [...]string{"unknown", "invalid", "read", "ownership", "concurrent", "complete"}

func beginCollectionDiagnostic(ctx context.Context) (context.Context, *collectionAttempt) {
	if ctx == nil {
		return ctx, nil
	}
	d, _ := ctx.Value(collectionDiagnosticKey{}).(*CollectionDiagnostic)
	if d == nil {
		return ctx, nil
	}
	a := &collectionAttempt{}
	d.latest.Store(a)
	return context.WithValue(ctx, collectionAttemptKey{}, a), a
}

func traceCollection(ctx context.Context, stage collectionStage, kind string) {
	if ctx == nil {
		return
	}
	a, _ := ctx.Value(collectionAttemptKey{}).(*collectionAttempt)
	if a == nil {
		return
	}
	code := uint32(0)
	for i, label := range collectionKinds {
		if kind == label {
			code = uint32(i)
			break
		}
	}
	a.position.Store(uint32(stage) | code<<8)
}

func traceCollectionPages(ctx context.Context, reason pagesRefusalReason) {
	if ctx == nil {
		return
	}
	if a, _ := ctx.Value(collectionAttemptKey{}).(*collectionAttempt); a != nil {
		a.position.Or(uint32(reason) << 24)
	}
}

func (a *collectionAttempt) finish(inner, caller context.Context, err error) {
	if a == nil {
		return
	}
	reason := uint32(0)
	switch err {
	case nil:
		if a.position.Load()&255 == uint32(collectionComplete) {
			reason = 5
		}
	case ErrInvalid:
		reason = 1
	case ErrRead:
		reason = 2
	case ErrOwnership:
		reason = 3
	case ErrConcurrent:
		reason = 4
	}
	a.position.Or(reason << 16)
	// Called before the Collect child is cancelled. No context is retained.
	a.contexts.Store(pagesContextState(inner) | pagesContextState(caller)<<8)
}

// Snapshot is read after the same Collect returns. All strings come from
// closed local tables; unknown errors remain unknown without formatting them.
func (d *CollectionDiagnostic) Snapshot() string {
	stage, kind, reason, pages, inner, caller := "unknown", "unknown", "unknown", "unknown", "unknown", "unknown"
	if d != nil {
		if a := d.latest.Load(); a != nil {
			p, c := a.position.Load(), a.contexts.Load()
			if i := p & 255; i < uint32(len(collectionStages)) {
				stage = collectionStages[i]
			}
			if i := p >> 8 & 255; i < uint32(len(collectionKinds)) {
				kind = collectionKinds[i]
			}
			if i := p >> 16 & 255; i < uint32(len(collectionReasons)) {
				reason = collectionReasons[i]
			}
			pages = pagesReasonLabel(pagesRefusalReason(p >> 24))
			inner, caller = pagesContextLabel(c&255), pagesContextLabel(c>>8&255)
		}
	}
	return fmt.Sprintf("stage=%s collection=%s reason=%s pages=%s inner=%s caller=%s", stage, kind, reason, pages, inner, caller)
}
