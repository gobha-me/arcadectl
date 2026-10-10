// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"

	"github.com/gobha-me/arcadectl/internal/installcontract"
	"github.com/gobha-me/arcadectl/internal/installstate"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// A read-only original signed access witness for the continuous guard. It does
// not call current(), normalize Pending away in the snapshot, require runtime
// policy health, create accounts or adopt matching names. Fresh prerequisite
// CREATE and post-retirement uninstall have distinct closed proof protocols.
func (b *baselineWorkflow) runtimeAccessWitness(ctx context.Context, snapshot *installstate.Snapshot) (map[installstate.Key]admissionIdentity, error) {
	if b == nil || b.engine == nil || ctx == nil || snapshot == nil {
		return nil, ErrSecurityBaseline
	}
	e := b.engine
	fresh, err := (&Lifecycle{engine: e}).original(ctx, snapshot)
	if err != nil {
		return nil, ErrSecurityBaseline
	}
	d := fresh.Document()
	if d.SecurityBaseline == nil || d.SecurityBaseline.Stage != installstate.BaselineVerified || d.SecurityBaseline.Pending != nil ||
		d.SecurityBaseline.ArtifactDigest != b.plan.Digest() || d.AdmissionRetirementRevision != 0 || !e.baselineObservable(d) {
		return nil, ErrSecurityBaseline
	}
	return b.readOriginalRuntimeAccess(ctx, fresh)
}

// Shared READ-only signed catalog, not a verified-baseline selection or an
// effect permit. Both callers supply their own closed opening eligibility and
// original Namespace observation; this leaf retains the same complete original
// UID/template catalog and trailing Namespace/journal fence. Historical
// enrollment must separately close its input/source, actor and cold evidence.
func (b *baselineWorkflow) readOriginalRuntimeAccess(ctx context.Context, fresh *installstate.Snapshot) (map[installstate.Key]admissionIdentity, error) {
	if b == nil || b.engine == nil || ctx == nil || ctx.Err() != nil || fresh == nil || !b.engine.baselineObservable(fresh.Document()) {
		return nil, ErrSecurityBaseline
	}
	e := b.engine
	d := fresh.Document()
	witness := map[installstate.Key]admissionIdentity{}
	// Mixed upgrades use the recorded active/target inventory, not prospective
	// access objects which have not been created yet. Every accepted template
	// still comes from one of this engine's authenticated sealed contracts.
	for _, resource := range d.Resources {
		key := resource.Key
		if !accessRetirementKey(key) {
			continue
		}
		entry, template := e.inventory(d, key)
		if entry == nil || template == nil || witness[key].UID != "" {
			return nil, ErrSecurityBaseline
		}
		live, err := e.access.Get(ctx, key)
		if err != nil || live == nil {
			return nil, ErrSecurityBaseline
		}
		accepted, err := e.baselineAccessTemplate(d, entry, template, live)
		if err != nil {
			return nil, ErrSecurityBaseline
		}
		witness[key] = admissionIdentity{entry.UID, live.GetResourceVersion(), accepted.Hash()}
	}
	for _, name := range []string{"arcadectl-controller", "arcadectl-api", "arcadectl-destroy-controller", "arcadectl-destroy-admin"} {
		key := installstate.Key{APIVersion: "v1", Kind: "ServiceAccount", Namespace: d.Namespace, Name: name}
		if witness[key].UID == "" {
			return nil, ErrSecurityBaseline
		}
	}
	// Original authority includes the complete sealed access catalog, not
	// merely accounts whose names survive. Otherwise lost journal/RBAC entries
	// could be masked by unrelated ambient grants making actor SSARs pass.
	catalog := e.plans[d.TargetPackage]
	if d.ActivePackage != "" {
		catalog = e.plans[d.ActivePackage]
	}
	if catalog == nil {
		return nil, ErrSecurityBaseline
	}
	for _, resource := range catalog.ResourceMetadata() {
		key := installstate.Key{APIVersion: resource.APIVersion, Kind: resource.Kind, Namespace: resource.Namespace, Name: resource.Name}
		if accessRetirementKey(key) && witness[key].UID == "" {
			return nil, ErrSecurityBaseline
		}
	}
	if _, err := (&Lifecycle{engine: e}).original(ctx, fresh); err != nil || ctx.Err() != nil {
		return nil, ErrSecurityBaseline
	}
	return witness, nil
}

func (e *Engine) baselineAccessTemplate(d installstate.Document, entry *installstate.Resource, before *installcontract.Template, live *unstructured.Unstructured) (*installcontract.Template, error) {
	if entry == nil || before == nil || live == nil || live.GetUID() != entry.UID {
		return nil, ErrSecurityBaseline
	}
	pending := d.Pending
	if pending == nil || pending.Key != entry.Key {
		if before.MatchLive(live, entry.UID) != nil {
			return nil, ErrSecurityBaseline
		}
		return before, nil
	}
	// Only an existing original signed access UPDATE can straddle its effect
	// boundary here. Missing/new/deleted access cannot mint actor authority.
	if pending.Action != installstate.Update || pending.BeforeUID != entry.UID || pending.BeforeSHA256 != before.Hash() || pending.BeforeResourceVersion == "" || !nonceID.MatchString(pending.CreateNonce) {
		return nil, ErrSecurityBaseline
	}
	contextDoc := d
	contextDoc.Pending = nil // private action derivation, NOT a changed snapshot
	digest, paused := d.TargetPackage, false
	if d.Stage == installstate.Quiescing {
		digest, paused = d.ActivePackage, true
	}
	after, err := e.desired(contextDoc, entry.Key, digest, paused)
	if err != nil || after.Hash() != pending.AfterSHA256 {
		return nil, ErrSecurityBaseline
	}
	if live.GetResourceVersion() == pending.BeforeResourceVersion && live.GetAnnotations()[installstate.MutationAnnotation] != pending.CreateNonce && before.MatchLive(live, entry.UID) == nil {
		return before, nil
	}
	if effectMatches(after, pending, live) {
		return after, nil
	}
	return nil, ErrSecurityBaseline
}
