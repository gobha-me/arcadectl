// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"time"

	"github.com/gobha-me/arcadectl/internal/installstate"
)

// ClusterTargetAuthenticated implements only the TargetAuthenticated portion
// of the lifecycle proof. It is bound to the original engine and its frozen
// HTTPS access, not caller-selected serving/Secret/dial providers. Success is
// authenticated identity evidence, never an effect or a completed installer.
type ClusterTargetAuthenticated struct {
	prerequisites *ClusterPrerequisites
	activation    *Activation
}

func NewClusterTargetAuthenticated(p *ClusterPrerequisites) (*ClusterTargetAuthenticated, error) {
	if p == nil || p.engine == nil || p.access == nil || p.engine.access != p.access || p.access.frozen == nil || p.access.native == nil {
		return nil, ErrInvalid
	}
	a, err := NewActivation(p.engine, p.access.Serving(), p.access.PrivateSecrets())
	if err != nil {
		return nil, ErrInvalid
	}
	return &ClusterTargetAuthenticated{p, a}, nil
}

func (c *ClusterTargetAuthenticated) Verify(ctx context.Context, request LifecycleCheck) error {
	if c == nil || c.prerequisites == nil || c.activation == nil || ctx == nil || request.Snapshot == nil || request.Options.Now.IsZero() || request.Checkpoint != TargetAuthenticated {
		return ErrInvalid
	}
	p := c.prerequisites
	d := request.Snapshot.Document()
	if p.engine.access != p.access || p.access.native == nil || d.Pending != nil || d.Stage != installstate.Verifying || request.Mode != d.Mode || request.Mode == installstate.Uninstall || request.Target == nil || request.Target.Digest() != d.TargetPackage {
		return ErrInvalid
	}
	if _, err := p.permissions(request); err != nil {
		return ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if p.original(ctx, request.Snapshot) != nil {
		return ErrActivation
	}
	// Current retained Secret/file bindings are authoritative. Do not reload
	// the original bootstrap candidate here: target package changes and valid
	// same-Secret-UID administrator rotation must remain supported.
	if c.activation.VerifyForwarded(ctx, request.Snapshot, request.Options.Activation, p.access) != nil || p.original(ctx, request.Snapshot) != nil {
		return ErrActivation
	}
	return nil
}
