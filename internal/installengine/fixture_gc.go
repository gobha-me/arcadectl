// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"

	"github.com/gobha-me/arcadectl/internal/installobserve"
	authv1 "k8s.io/api/authorization/v1"
)

// Read-only GC-domain metadata, bound to this original actor/WAL/journal and
// frozen administrator. This is NOT inertness, world safety, fixture adoption,
// permission to delete or recovery/retirement. Whole original fixture and world
// witnesses must independently justify every effect and every allowed child.
func (w *fixtureWire) gcMetadata(ctx context.Context) (*installobserve.GCObservation, error) {
	if ctx == nil || w == nil || w.ledger == nil {
		return nil, ErrFixtures
	}
	w.ledger.wireMu.Lock()
	defer w.ledger.wireMu.Unlock()
	if w.current(ctx) != nil {
		return nil, ErrFixtures
	}
	p := w.actors.admission.prerequisites
	s := w.actors.request.Snapshot
	reader, err := installobserve.NewGCReader(p.access.readConfig(), p.engine.journal, w.actors.request.Target)
	if err != nil {
		return nil, ErrFixtures
	}
	discovery, err := reader.Discover(ctx, s.Anchor())
	if err != nil || w.current(ctx) != nil {
		return nil, ErrFixtures
	}
	for _, source := range discovery.Resources() {
		permission := gcMetadataPermission(source, s.Anchor().Namespace)
		// Only the original administrator's current exact LIST right. No new
		// grant, TokenRequest, impersonation or full-object fallback is used.
		if p.access.authorize(ctx, permission.spec) != nil {
			return nil, ErrFixtures
		}
	}
	if w.current(ctx) != nil {
		return nil, ErrFixtures
	}
	observation, err := reader.Collect(ctx, discovery)
	if err != nil || observation == nil {
		return nil, ErrFixtures
	}
	journal := observation.Journal()
	if journal == nil || journal.Anchor() != s.Anchor() || journal.ResourceVersion() != s.ResourceVersion() || !bytes.Equal(journal.Bytes(), s.Bytes()) || w.current(ctx) != nil {
		return nil, ErrFixtures
	}
	return observation, nil
}

func gcMetadataPermission(source installobserve.GCResource, namespace string) proofPermission {
	return proofPermission{spec: authv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authv1.ResourceAttributes{
		Group: source.GVR.Group, Version: source.GVR.Version, Resource: source.GVR.Resource, Namespace: namespace, Verb: "list",
	}}, kind: source.Kind}
}
