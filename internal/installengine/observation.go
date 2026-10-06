// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"

	"github.com/gobha-me/arcadectl/internal/installobserve"
)

// observe binds the sealed safety read to the very same original journal,
// cluster and frozen static identity used for effects. A complete observation
// is not coldness, detached storage, runtime absence or admission behavior.
// Those obligations must be checked separately by the closed checkpoint.
func (p *ClusterPrerequisites) observe(ctx context.Context, request LifecycleCheck) (*installobserve.Observation, error) {
	if p == nil || p.engine == nil || p.access == nil || p.engine.access != p.access || p.access.frozen == nil || ctx == nil || request.Snapshot == nil {
		return nil, ErrInvalid
	}
	if _, err := p.permissions(request); err != nil || p.original(ctx, request.Snapshot) != nil {
		return nil, ErrPrerequisites
	}
	observer, err := installobserve.New(p.access.frozen, p.engine.journal, request.Target)
	if err != nil {
		return nil, ErrPrerequisites
	}
	observation, err := observer.Collect(ctx, request.Snapshot.Anchor())
	if err != nil || observation == nil || observation.Journal() == nil {
		return nil, ErrPrerequisites
	}
	journal := observation.Journal()
	if journal.Anchor() != request.Snapshot.Anchor() || journal.ResourceVersion() != request.Snapshot.ResourceVersion() || !bytes.Equal(journal.Bytes(), request.Snapshot.Bytes()) || p.original(ctx, request.Snapshot) != nil {
		return nil, ErrPrerequisites
	}
	return observation, nil
}
