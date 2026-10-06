// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installobserve

import (
	"bytes"
	"context"
	"slices"

	"github.com/go-logr/logr"
	"github.com/gobha-me/arcadectl/internal/installstate"
	corev1 "k8s.io/api/core/v1"
)

// ClaimsObservation contains only a complete current PVC list and its sealed
// original-identity journal. It is read-only recovery reporting evidence, NOT
// an owner/GC closure, coldness, detach, admission or deletion authorization.
type ClaimsObservation struct {
	journal *installstate.Snapshot
	claims  *corev1.PersistentVolumeClaimList
}

func (o *ClaimsObservation) Journal() *installstate.Snapshot {
	if o == nil {
		return nil
	}
	return o.journal
}

func (o *ClaimsObservation) Claims() *corev1.PersistentVolumeClaimList {
	if o == nil || o.claims == nil {
		return nil
	}
	return o.claims.DeepCopy()
}

// CollectClaims enumerates ALL current namespace PVCs, including unlabeled
// retained worlds. It does not require controllers or admission identities to
// survive uninstall, resolve owners, contact Secrets or inspect domain history.
// The caller separately proves original Namespace shape and repeats temporal
// observations; collection membership is not an atomic lock or ownership grant.
func (o *Observer) CollectClaims(ctx context.Context, anchor installstate.Anchor) (*ClaimsObservation, error) {
	if o == nil || o.journal == nil || ctx == nil || !o.plan.IsTrusted() || anchor.Namespace != o.plan.Namespace() {
		return nil, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, observationTimeout)
	defer cancel()
	ctx = logr.NewContext(ctx, logr.Discard())
	before, err := o.journal.Load(ctx, anchor)
	if err != nil || before.Anchor() != anchor {
		return nil, ErrOwnership
	}
	doc := before.Document()
	if doc.ProfileID != o.plan.Profile().ID || !slices.Contains([]string{doc.ActivePackage, doc.TargetPackage, doc.PreviousPackage}, o.plan.Digest()) {
		return nil, ErrOwnership
	}
	claims := &corev1.PersistentVolumeClaimList{}
	c := collection{"v1", "PersistentVolumeClaim", "persistentvolumeclaims", true, claims}
	// Reuse the existing closed item-identity/type/duplicate validation, but
	// deliberately do not resolve ownership or collect any other resource.
	graph := newOwnerGraph(o, doc.Resources, []collection{c})
	budget := maxCollectionBytes
	if err := o.collectList(ctx, c, graph, &budget); err != nil {
		return nil, err
	}
	after, err := o.journal.Load(ctx, anchor)
	if err != nil || after.Anchor() != anchor || after.ResourceVersion() != before.ResourceVersion() || !bytes.Equal(before.Bytes(), after.Bytes()) {
		return nil, ErrConcurrent
	}
	if ctx.Err() != nil {
		return nil, ErrRead
	}
	return &ClaimsObservation{journal: after, claims: claims}, nil
}
