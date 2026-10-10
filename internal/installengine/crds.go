// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"errors"
	"time"

	"github.com/gobha-me/arcadectl/internal/installstate"
)

var ErrCRDs = errors.New("original installation CRDs and served resources are unproved")

// VerifyCRDs combines every original recorded CRD's signed establishment and
// storage/conversion compatibility contract with actual exact-version served
// discovery. It neither installs missing CRDs nor substitutes target-only
// shape/status checks during a mixed active/target transition.
func (p *ClusterPrerequisites) VerifyCRDs(ctx context.Context, request LifecycleCheck) error {
	if p == nil || p.engine == nil || p.access == nil || ctx == nil || request.Checkpoint != CRDsAvailable || request.Snapshot == nil || !request.Target.IsTrusted() || request.Options.Now.IsZero() {
		return ErrInvalid
	}
	permissions, err := p.permissions(request)
	if err != nil {
		return ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if p.original(ctx, request.Snapshot) != nil || p.access.checkVersion(ctx, request.Target.Profile()) != nil {
		return ErrCRDs
	}
	d := request.Snapshot.Document()
	identities := map[installstate.Key]admissionIdentity{}
	for _, resource := range request.Target.Resources() {
		key := resourceKey(resource)
		if key.Kind != "CustomResourceDefinition" {
			continue
		}
		entry, original := p.engine.inventory(d, key)
		target, err := p.engine.contracts[request.Target.Digest()].Template(key, false)
		if entry == nil || original == nil || !entry.Retained || err != nil {
			return ErrCRDs
		}
		live, err := p.access.Get(ctx, key)
		if err != nil || original.CheckCRD(live, entry.UID, target) != nil {
			return ErrCRDs
		}
		identities[key] = admissionIdentity{UID: entry.UID, ResourceVersion: live.GetResourceVersion(), TemplateSHA256: original.Hash()}
	}
	if len(identities) != 5 {
		return ErrCRDs
	}
	discovery, err := p.access.discover(ctx, "arcade.gobha.me/v1alpha1")
	if err != nil {
		return ErrCRDs
	}
	for _, permission := range permissions {
		attrs := permission.spec.ResourceAttributes
		if attrs == nil || attrs.Group != "arcade.gobha.me" {
			continue
		}
		if !discoveredPermission(discovery, permission) {
			return ErrCRDs
		}
	}
	// Detect replacement, mutation or status/version changes across discovery.
	// This is repeated evidence, not an atomic API-server snapshot or lock.
	for key, identity := range identities {
		entry, original := p.engine.inventory(d, key)
		target, err := p.engine.contracts[request.Target.Digest()].Template(key, false)
		live, readErr := p.access.Get(ctx, key)
		if entry == nil || original == nil || err != nil || readErr != nil || original.Hash() != identity.TemplateSHA256 || entry.UID != identity.UID || live.GetResourceVersion() != identity.ResourceVersion || original.CheckCRD(live, identity.UID, target) != nil {
			return ErrCRDs
		}
	}
	if p.original(ctx, request.Snapshot) != nil {
		return ErrCRDs
	}
	return nil
}
