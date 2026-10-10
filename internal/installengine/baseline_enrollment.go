// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"slices"

	"github.com/gobha-me/arcadectl/internal/installbaseline"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	"github.com/gobha-me/arcadectl/internal/privatefs"
)

// Explicit historical enrollment inputs, never a fresh-bootstrap fallback.
// The original authenticated bootstrap package/receipt and CA remain unchanged.
// Enrollment does not accept runtime retargeting, account repair or raw claims.
type BaselineEnrollmentOptions struct {
	OriginalBootstrap *installrender.Plan
	BootstrapReceipt  string
	Lifecycle         LifecycleOptions
}

// StepBaselineEnrollment advances the separately pinned baseline, never the
// completed historical runtime. One invocation may CREATE at most one signed
// baseline object. Pending recovery is observation-only, including after an
// uncertain CREATE. Ownership completion still requires full native proof.
func (l *Lifecycle) StepBaselineEnrollment(ctx context.Context, snapshot *installstate.Snapshot, options BaselineEnrollmentOptions) (*installstate.Snapshot, error) {
	if l == nil || l.engine == nil || ctx == nil || ctx.Err() != nil || snapshot == nil || !options.OriginalBootstrap.IsTrusted() || options.Lifecycle.Now.IsZero() {
		return snapshot, ErrSecurityBaseline
	}
	ctx, cancel := context.WithTimeout(ctx, baselineRuntimeTimeout)
	defer cancel()
	e := l.engine
	fresh, err := l.original(ctx, snapshot)
	if err != nil {
		return snapshot, err
	}
	source, err := e.openBaselineEnrollmentSource(ctx, fresh, options.OriginalBootstrap, options.BootstrapReceipt, options.Lifecycle.Activation.CAFile)
	if err != nil {
		return fresh, ErrSecurityBaseline
	}
	defer source.release()
	// Existing ACK identity is held BEFORE the opening remote safety bundle.
	// An empty/lost receipt cannot authorize explicit resume or recapture UID.
	var pendingReceipt *privatefs.FilePin
	if fresh.Document().SecurityBaseline.Pending != nil {
		uid, uidErr := e.baseline.loadReceiptUID(fresh.Document())
		if uidErr != nil {
			return fresh, ErrOutcomeUnknown
		}
		pendingReceipt, err = e.baseline.pinEnrollmentReceipt(fresh.Document(), uid)
		if err != nil {
			return fresh, ErrOutcomeUnknown
		}
		defer pendingReceipt.Close()
	}
	safety, err := l.openBaselineEnrollmentSafety(ctx, fresh, source.inputs, source, options.Lifecycle)
	if err != nil {
		return fresh, ErrSecurityBaseline
	}
	w := &baselineEnrollmentEffect{safety: safety, source: source, receipt: pendingReceipt}
	w.self = w
	defer w.release()
	document := fresh.Document()
	baseline := document.SecurityBaseline
	if baseline.Stage == installstate.BaselineApplying && baseline.Pending == nil {
		for _, resource := range e.baselinePlan().Resources() {
			object := resource.Object
			key := installstate.Key{APIVersion: object.GetAPIVersion(), Kind: object.GetKind(), Namespace: object.GetNamespace(), Name: object.GetName()}
			if !slices.ContainsFunc(baseline.Resources, func(row installstate.BaselineResource) bool { return row.Key == key }) {
				w.key = key
				break
			}
		}
	}
	permissions, err := w.permissions()
	checks := l.checks.(*clusterLifecycleChecks) // closed safety constructor checked this
	if err != nil || checks.prerequisites.verifyAccess(ctx, e.plans[document.TargetPackage], permissions) != nil || w.close(ctx, e.baseline, fresh) != nil {
		return fresh, ErrSecurityBaseline
	}
	if baseline.Stage == installstate.BaselineVerified {
		if safety.baseline.Verify(ctx, fresh) != nil || w.close(ctx, e.baseline, fresh) != nil {
			return fresh, ErrSecurityBaseline
		}
		return fresh, nil // no journal/effect replay on explicit verification retry
	}
	if baseline.Stage == installstate.BaselinePreparing || baseline.Stage == installstate.BaselineRecovery {
		baseline.Stage = installstate.BaselineApplying
	} else if baseline.Stage == installstate.BaselineApplying {
		if baseline.Pending != nil {
			return e.baseline.recoverEnrollment(ctx, fresh, nil, false, false, w)
		}
		if len(baseline.Resources) != installbaseline.ResourceCount {
			if w.key == (installstate.Key{}) {
				return fresh, ErrSecurityBaseline
			}
			return e.baseline.createEnrollment(ctx, fresh, w.key, w)
		}
		baseline.Stage = installstate.BaselineVerified
	} else {
		return fresh, ErrSecurityBaseline
	}
	document.Revision++
	next, err := e.journal.Commit(ctx, fresh, document)
	if err != nil {
		return fresh, err
	}
	if w.follow(ctx, next) != nil {
		return next, ErrOutcomeUnknown
	}
	if baseline.Stage == installstate.BaselineVerified && (w.safety.baseline.Verify(ctx, next) != nil || w.close(ctx, e.baseline, next) != nil) {
		return next, ErrOutcomeUnknown
	}
	return next, nil
}

// Concrete private single-operation owner, not a public permit, injected
// checker or a historical fallback in the fresh workflow. It only follows
// actual successful Store.Commit results from this operation's callsites.
type baselineEnrollmentEffect struct {
	self    *baselineEnrollmentEffect
	safety  *baselineEnrollmentSafety
	source  *baselineEnrollmentSourceWitness
	key     installstate.Key
	nonce   string
	used    bool
	receipt *privatefs.FilePin
}

func (w *baselineEnrollmentEffect) release() {
	if w != nil && w.self == w {
		w.safety.release()
	}
}

func (w *baselineEnrollmentEffect) matches(b *baselineWorkflow, snapshot *installstate.Snapshot) bool {
	return w != nil && w.self == w && w.safety != nil && w.safety.self == w.safety && w.safety.lifecycle != nil && w.safety.lifecycle.engine != nil && w.safety.snapshot != nil && w.source != nil && w.source.self == w.source && w.safety.source == w.source && b != nil &&
		w.safety.lifecycle.engine == b.engine && snapshot != nil && snapshot.Anchor() == w.safety.snapshot.Anchor() && snapshot.ResourceVersion() == w.safety.snapshot.ResourceVersion() && bytes.Equal(snapshot.Bytes(), w.safety.snapshot.Bytes())
}

func (w *baselineEnrollmentEffect) close(ctx context.Context, b *baselineWorkflow, snapshot *installstate.Snapshot) error {
	if !w.matches(b, snapshot) || b.verifyOwned(ctx, snapshot) != nil || w.safety.verifyActorContainment(ctx) != nil || b.verifyOwned(ctx, snapshot) != nil || w.safety.close(ctx) != nil || b.engine.confirmBaselineEnrollmentSource(ctx, w.source, snapshot) != nil || w.receipt != nil && w.receipt.Confirm() != nil {
		return ErrSecurityBaseline
	}
	return nil
}

func (w *baselineEnrollmentEffect) follow(ctx context.Context, next *installstate.Snapshot) error {
	if w == nil || w.self != w || w.safety == nil || w.receipt != nil && w.receipt.Confirm() != nil {
		return ErrSecurityBaseline
	}
	closing, err := w.safety.follow(ctx, next, w.source)
	if err != nil {
		return ErrSecurityBaseline
	}
	w.safety = closing
	if w.receipt != nil && w.receipt.Confirm() != nil {
		return ErrSecurityBaseline
	}
	return nil
}

// Exact namespace UPDATE and signed named GETs. Only the selected next key
// adds collection CREATE; a new invocation with Pending never asks for CREATE.
func (w *baselineEnrollmentEffect) permissions() ([]proofPermission, error) {
	if w == nil || w.self != w || w.safety == nil || w.safety.lifecycle == nil || w.safety.lifecycle.engine == nil || w.source == nil || !w.matches(w.safety.lifecycle.engine.baseline, w.safety.snapshot) {
		return nil, ErrSecurityBaseline
	}
	update, err := publicPermission(namespaceKey(w.safety.snapshot.Anchor().Namespace), "update")
	if err != nil {
		return nil, ErrSecurityBaseline
	}
	permissions := []proofPermission{update}
	selected := false
	for _, resource := range w.safety.lifecycle.engine.baselinePlan().Resources() {
		object := resource.Object
		key := installstate.Key{APIVersion: object.GetAPIVersion(), Kind: object.GetKind(), Namespace: object.GetNamespace(), Name: object.GetName()}
		read, err := publicPermission(key, "get")
		if err != nil {
			return nil, ErrSecurityBaseline
		}
		permissions = append(permissions, read)
		if key == w.key {
			baseline := w.safety.snapshot.Document().SecurityBaseline
			if baseline.Stage != installstate.BaselineApplying || baseline.Pending != nil || slices.ContainsFunc(baseline.Resources, func(row installstate.BaselineResource) bool { return row.Key == key }) {
				return nil, ErrSecurityBaseline
			}
			create, err := publicPermission(key, "create")
			if err != nil {
				return nil, ErrSecurityBaseline
			}
			permissions = append(permissions, create)
			selected = true
		}
	}
	if w.key != (installstate.Key{}) && !selected {
		return nil, ErrSecurityBaseline
	}
	return permissions, nil
}

// BeginBaselineEnrollment publishes protected original source evidence and
// introduces its immutable public seal via one baseline-only Namespace CAS.
// It never CREATEs a baseline/runtime object or regenerates a private Secret.
// Any later ownership/effect work uses the distinct explicit enrollment Step.
func (l *Lifecycle) BeginBaselineEnrollment(ctx context.Context, snapshot *installstate.Snapshot, options BaselineEnrollmentOptions) (*installstate.Snapshot, error) {
	if l == nil || l.engine == nil || ctx == nil || ctx.Err() != nil || snapshot == nil || !options.OriginalBootstrap.IsTrusted() || options.Lifecycle.Now.IsZero() {
		return snapshot, ErrSecurityBaseline
	}
	ctx, cancel := context.WithTimeout(ctx, baselineRuntimeTimeout)
	defer cancel()
	e := l.engine
	fresh, err := l.original(ctx, snapshot)
	if err != nil || !e.historicalEnrollmentSource(fresh.Document()) {
		return snapshot, ErrSecurityBaseline
	}
	inputs, err := e.openBaselineEnrollmentInputs(ctx, fresh, options.OriginalBootstrap, options.BootstrapReceipt, options.Lifecycle.Activation.CAFile)
	if err != nil {
		return fresh, ErrSecurityBaseline
	}
	defer inputs.release()
	safety, err := l.openBaselineEnrollmentSafety(ctx, fresh, inputs, nil, options.Lifecycle)
	if err != nil {
		return fresh, ErrSecurityBaseline
	}
	defer safety.release()
	// Authorize only the existing installation Namespace UPDATE. No ordinary
	// operation catalog, namespace creation or new baseline CREATE permission.
	permission, err := publicPermission(namespaceKey(fresh.Anchor().Namespace), "update")
	if err != nil || safety.baseline.access.authorize(ctx, permission.spec) != nil || safety.close(ctx) != nil {
		return fresh, ErrSecurityBaseline
	}
	source, err := e.saveBaselineEnrollmentSource(ctx, fresh, inputs, safety.opening.worlds)
	if err != nil {
		return fresh, err
	}
	defer source.release()
	// Protected publication is an interval too. Reprove actor containment and
	// the complete world/original bundle before the Namespace introduction.
	if source.matchesWorlds(safety.opening.worlds) != nil || safety.verifyActorContainment(ctx) != nil || e.confirmBaselineEnrollmentSource(ctx, source, fresh) != nil {
		return fresh, ErrSecurityBaseline
	}
	document := fresh.Document()
	document.SecurityBaseline, err = installstate.PinnedSecurityBaseline(e.baselinePlan())
	if err != nil {
		return fresh, ErrSecurityBaseline
	}
	provenance := source.provenance
	document.SecurityBaseline.Enrollment = &provenance
	document.Revision++
	introduced, err := e.journal.Commit(ctx, fresh, document)
	if err != nil {
		// The protected source remains durable. Unknown Namespace outcomes need
		// an explicit reload/resume; never repeat introduction or recapture data.
		return fresh, err
	}
	// A successful write ACK is not a final safety proof. Reconstruct from the
	// real returned Snapshot, retaining prior originals through its last reads.
	closing, err := safety.follow(ctx, introduced, source)
	if err != nil {
		return introduced, ErrOutcomeUnknown
	}
	defer closing.release()
	return introduced, nil
}
