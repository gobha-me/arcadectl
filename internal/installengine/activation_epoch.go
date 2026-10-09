// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/gobha-me/arcadectl/internal/adminauth"
	"github.com/gobha-me/arcadectl/internal/installbaseline"
	"github.com/gobha-me/arcadectl/internal/installstate"
	"github.com/gobha-me/arcadectl/internal/privatefs"
)

const (
	activationEpochOpening uint32 = iota
	activationEpochOpen
	activationEpochReleased
)

// One private, non-transferable verification owner. Holding its descriptors
// preserves the opening identities; it neither locks cluster objects nor
// supplies persistent mutation authority. An eventual lifecycle composition
// must retain this SAME owner through its trailing original-journal read.
type activationEpoch struct {
	self      *activationEpoch
	phase     atomic.Uint32
	authPhase atomic.Uint32
	target    *ClusterTargetAuthenticated
	request   LifecycleCheck
	baseline  *ClusterSecurityBaseline
	behavior  *baselineBehavior
	source    *reinstallSourceWitness
	clientPin *privatefs.FilePin
	caPin     *privatefs.FilePin
	clientID  privatefs.FileIdentity
	caID      privatefs.FileIdentity
}

// Scope is checked before file acquisition or a cluster request. Fresh Install
// legitimately has Installed=false; it still owes the SAME complete proof.
func (c *ClusterTargetAuthenticated) activationEpochScope(request LifecycleCheck) (*ClusterSecurityBaseline, error) {
	if c == nil || c.prerequisites == nil || c.activation == nil || request.Snapshot == nil || request.Checkpoint != TargetAuthenticated || request.Options.Now.IsZero() {
		return nil, ErrActivation
	}
	p := c.prerequisites
	if p.engine == nil || p.access == nil || p.engine.access != p.access || p.access.native == nil || !p.access.actorCompatible() || c.activation.engine != p.engine || p.engine.baseline == nil {
		return nil, ErrActivation
	}
	baseline, ok := p.engine.baseline.runtimeGuard.(*ClusterSecurityBaseline)
	if !ok || baseline == nil || baseline != p.engine.baseline.prerequisites || baseline.engine != p.engine || baseline.access != p.access {
		return nil, ErrActivation
	}
	d := request.Snapshot.Document()
	if d.Stage != installstate.Verifying || d.Pending != nil || d.AdmissionRetirementRevision != 0 || d.Mode == installstate.Uninstall || request.Mode != d.Mode ||
		request.Target == nil || !request.Target.IsTrusted() || request.Target.Digest() != d.TargetPackage || p.engine.plans[d.TargetPackage] != request.Target ||
		!p.engine.baselineObservable(d) || d.SecurityBaseline == nil || d.SecurityBaseline.Version != installbaseline.Version || d.SecurityBaseline.Stage != installstate.BaselineVerified || d.SecurityBaseline.Pending != nil ||
		d.SecurityBaseline.ArtifactDigest != p.engine.baselinePlan().Digest() || p.engine.fixtureFence(request.Snapshot) != nil {
		return nil, ErrActivation
	}
	if _, err := p.permissions(request); err != nil {
		return nil, ErrActivation
	}
	return baseline, nil
}

// The finite opening budget covers construction and the complete behavioral
// proof. File descriptors are acquired BEFORE any credential material can be
// read for authentication. Construction never opens a forwarding channel,
// transmits an administrator token, changes a Secret or changes the journal.
func (c *ClusterTargetAuthenticated) openActivationEpoch(ctx context.Context, request LifecycleCheck) (*activationEpoch, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, ErrActivation
	}
	baseline, err := c.activationEpochScope(request)
	if err != nil {
		return nil, ErrActivation
	}
	ctx, cancel := context.WithTimeout(ctx, baselineRuntimeTimeout)
	defer cancel()
	owner := &activationEpoch{target: c, request: request, baseline: baseline}
	owner.self = owner
	transferred := false
	defer func() {
		if !transferred {
			owner.release()
		}
	}()
	options := request.Options.Activation
	_, owner.caID, owner.caPin, err = privatefs.PinAbsolute(options.CAFile, 65536, privatefs.TrustedPublic)
	if err != nil {
		return nil, ErrActivation
	}
	_, owner.clientID, owner.clientPin, err = privatefs.PinAbsolute(options.CredentialFile, adminauth.MaxClientCredentialBytes, privatefs.Private)
	if err != nil {
		return nil, ErrActivation
	}
	if request.Snapshot.Document().AdmissionReinstall != nil {
		owner.source, err = baseline.engine.openReinstallSource(request.Snapshot)
		if err != nil {
			return nil, ErrActivation
		}
	}
	owner.behavior, err = baseline.newBaselineBehavior(ctx, request.Snapshot)
	if err != nil || owner.behavior.prove(ctx) != nil || ctx.Err() != nil {
		return nil, ErrActivation
	}
	owner.phase.Store(activationEpochOpen)
	if owner.confirmLocal(ctx) != nil {
		return nil, ErrActivation
	}
	transferred = true
	return owner, nil
}

// Fields remain immutable after acquisition, including after release; remote
// callbacks cannot race with pointer/map clearing. Opaque pins synchronize
// their shared close state. A copied owner cannot confirm or release originals.
func (o *activationEpoch) release() {
	if o == nil || o.self != o || o.phase.Swap(activationEpochReleased) == activationEpochReleased {
		return
	}
	_ = o.clientPin.Close()
	_ = o.caPin.Close()
	o.source.release()
	o.behavior.release()
}

func (o *activationEpoch) confirmLocal(ctx context.Context) error {
	if o == nil || o.self != o || ctx == nil || ctx.Err() != nil || o.phase.Load() != activationEpochOpen || o.behavior == nil || o.clientPin == nil || o.caPin == nil {
		return ErrActivation
	}
	baseline, err := o.target.activationEpochScope(o.request)
	if err != nil || baseline != o.baseline || o.behavior.actors == nil || o.behavior.actors.baseline != baseline || o.behavior.actors.snapshot != o.request.Snapshot ||
		baseline.engine.confirmBaselineParentReceipts(o.request.Snapshot.Document(), o.behavior.parents) != nil || baseline.engine.confirmBaselineMetadataReceipts(o.behavior.metadata) != nil {
		return ErrActivation
	}
	if o.request.Snapshot.Document().AdmissionReinstall != nil && o.source == nil || o.source != nil && baseline.engine.closeReinstallSource(o.source) != nil || o.clientPin.Confirm() != nil || o.caPin.Confirm() != nil || ctx.Err() != nil || o.phase.Load() != activationEpochOpen {
		return ErrActivation
	}
	return nil
}

// This is the complete non-probe closing fence, NOT a cached Verify result.
// Original access/configuration, denied executable catalog, whole metadata,
// whole parents/family and effective rules are all re-read against the SAME
// opening behavior. No witness is recaptured as a new floor after drift.
func (o *activationEpoch) fence(ctx context.Context) error {
	if o.confirmLocal(ctx) != nil {
		return ErrActivation
	}
	ctx, cancel := context.WithTimeout(ctx, baselineRuntimeTimeout)
	defer cancel()
	engine, snapshot := o.baseline.engine, o.request.Snapshot
	if _, err := engine.currentOriginal(ctx, snapshot); err != nil {
		return ErrActivation
	}
	if o.behavior.close(ctx) != nil {
		return ErrActivation
	}
	if _, err := engine.currentOriginal(ctx, snapshot); err != nil || o.confirmLocal(ctx) != nil {
		return ErrActivation
	}
	return nil
}

// Serving and private Secret material are one bracketed observation. Neither
// escapes until the closing complete fence and original file identities agree.
// This reader itself supplies no dial, authentication or mutation authority.
func (o *activationEpoch) readEvidence(ctx context.Context) (*Serving, credentialBinding, error) {
	if o.fence(ctx) != nil {
		return nil, credentialBinding{}, ErrActivation
	}
	a := o.target.activation
	serving, err := o.baseline.engine.readOriginalServing(ctx, o.request.Snapshot, a.serving, false)
	if err != nil {
		return nil, credentialBinding{}, ErrActivation
	}
	workflow, err := NewSecretWorkflow(a.engine, a.secrets)
	if err != nil {
		return nil, credentialBinding{}, ErrActivation
	}
	retained, caID, err := workflow.readRetainedObjects(ctx, o.request.Snapshot, o.request.Options.Activation.CAFile, time.Now())
	if err != nil || caID != o.caID {
		return nil, credentialBinding{}, ErrActivation
	}
	binding, err := a.bindOriginalCredentials(retained, caID, o.request.Options.Activation)
	if err != nil || binding.client != o.clientID || binding.ca != o.caID || o.fence(ctx) != nil {
		return nil, credentialBinding{}, ErrActivation
	}
	return serving, binding, nil
}
