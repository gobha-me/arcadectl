// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"errors"
	"slices"

	"github.com/gobha-me/arcadectl/internal/installbaseline"
	"github.com/gobha-me/arcadectl/internal/installcontract"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
)

var ErrSecurityBaseline = errors.New("installation security baseline is absent, incomplete or unproved; preserve original evidence before resume")

// This private provider is installed by closed production composition, never
// by command-line callbacks or public caller claims. Tests may instrument it.
type baselineRuntimeGuard interface {
	Verify(context.Context, *installstate.Snapshot) error
}

type baselineWorkflow struct {
	engine        *Engine
	plan          *installbaseline.Plan
	contract      *installcontract.Contract
	runtimeGuard  baselineRuntimeGuard
	prerequisites *ClusterSecurityBaseline // installed only by closed lifecycle composition
}

// Selection only, never effect authority. A signed baseline may be established
// through the ordinary fresh path only before any runtime inventory exists.
// Existing installations require their separate explicit enrollment protocol.
func freshBaselineEnrollment(d installstate.Document) bool {
	return d.Mode == installstate.Install && d.ActivePackage == "" && !d.Installed && d.Pending == nil && d.AdmissionReinstall == nil && d.AdmissionRetirementRevision == 0 &&
		(d.Stage == installstate.Preparing || d.Stage == installstate.Applying || d.Stage == installstate.RecoveryRequired) &&
		len(d.Resources) == 1 && d.Resources[0].Key == namespaceKey(d.Namespace) && d.Resources[0].UID == d.NamespaceUID && d.Resources[0].Retained
}

// NewWithBaselineAccess is the trusted instrumentation seam corresponding to
// NewWithAccess. Without a closed runtime guard, ordinary runtime effects stay
// refused even after original baseline resource ownership is established.
func NewWithBaselineAccess(access Access, journal *installstate.Store, files *privatefs.Store, baseline *installbaseline.Plan, plans ...*installrender.Plan) (*Engine, error) {
	if !baseline.IsTrusted() || journal == nil || journal.BaselineDigest() != baseline.Digest() {
		return nil, ErrInvalid
	}
	engine, err := newWithAccess(access, journal, files, plans...)
	if err != nil || baseline.Namespace() != plans[0].Namespace() || baseline.Profile() != plans[0].Profile().ID {
		return nil, ErrInvalid
	}
	contract, err := installcontract.NewBaseline(baseline)
	if err != nil {
		return nil, ErrInvalid
	}
	engine.baseline = &baselineWorkflow{engine: engine, plan: baseline, contract: contract}
	return engine, nil
}

func (e *Engine) baselinePlan() *installbaseline.Plan {
	if e == nil || e.baseline == nil {
		return nil
	}
	return e.baseline.plan
}

func (b *baselineWorkflow) verifyRuntime(ctx context.Context, snapshot *installstate.Snapshot) error {
	if b == nil || b.runtimeGuard == nil || snapshot == nil {
		return ErrSecurityBaseline
	}
	document := snapshot.Document()
	if document.SecurityBaseline == nil || document.SecurityBaseline.Stage != installstate.BaselineVerified || document.SecurityBaseline.Pending != nil {
		return ErrSecurityBaseline
	}
	return b.runtimeGuard.Verify(ctx, snapshot)
}

func (b *baselineWorkflow) original(ctx context.Context, snapshot *installstate.Snapshot) (*installstate.Snapshot, error) {
	if b == nil || b.engine == nil || !b.plan.IsTrusted() || b.contract == nil || ctx == nil || snapshot == nil {
		return nil, ErrInvalid
	}
	// Same uncached original Namespace/journal and unresolved-fixture fence as
	// lifecycle original observation; works for completed legacy operations too.
	fresh, err := (&Lifecycle{engine: b.engine}).original(ctx, snapshot)
	if err != nil {
		return nil, err
	}
	document := fresh.Document()
	baseline := document.SecurityBaseline
	if document.Pending != nil || baseline == nil || baseline.ArtifactDigest != b.plan.Digest() || baseline.Version != installbaseline.Version {
		return nil, ErrSecurityBaseline
	}
	return fresh, nil
}

func (b *baselineWorkflow) verifyOwned(ctx context.Context, snapshot *installstate.Snapshot) error {
	document := snapshot.Document()
	for _, resource := range document.SecurityBaseline.Resources {
		template, err := b.contract.Template(resource.Key, false)
		if err != nil || template.Hash() != resource.TemplateSHA256 {
			return ErrSecurityBaseline
		}
		live, err := b.engine.access.Get(ctx, resource.Key)
		if err != nil || template.MatchLive(live, resource.UID) != nil {
			return ErrSecurityBaseline
		}
	}
	_, err := b.original(ctx, snapshot)
	return err
}

// EstablishBaselineOwnership advances at most ONE CREATE effect. Verified
// means completed original-identity ownership, NOT serving/type-checking/native
// behavior health. Runtime remains fenced until the closed guard independently
// proves those obligations. This method never addresses runtime inventory.
func (e *Engine) EstablishBaselineOwnership(ctx context.Context, snapshot *installstate.Snapshot) (*installstate.Snapshot, error) {
	if e == nil || e.baseline == nil {
		return snapshot, ErrInvalid
	}
	b := e.baseline
	fresh, err := b.original(ctx, snapshot)
	if err != nil {
		return snapshot, err
	}
	if b.verifyOwned(ctx, fresh) != nil {
		return fresh, ErrSecurityBaseline
	}
	document := fresh.Document()
	baseline := document.SecurityBaseline
	if baseline.Stage == installstate.BaselineVerified {
		return fresh, nil
	}
	// Existing legacy runtime needs explicit producer/descendant enrollment
	// proof. It cannot use this fresh-bootstrap path or be silently adopted.
	if document.ActivePackage != "" || document.Mode != installstate.Install || len(document.Resources) != 1 || document.Resources[0].Key.Kind != "Namespace" {
		return fresh, ErrSecurityBaseline
	}
	if baseline.Stage == installstate.BaselinePreparing || baseline.Stage == installstate.BaselineRecovery {
		baseline.Stage = installstate.BaselineApplying
		document.Revision++
		return e.journal.Commit(ctx, fresh, document)
	}
	if baseline.Stage != installstate.BaselineApplying {
		return fresh, ErrSecurityBaseline
	}
	if baseline.Pending != nil {
		return b.recover(ctx, fresh, nil, false, false)
	}
	if len(baseline.Resources) == installbaseline.ResourceCount {
		if b.verifyOwned(ctx, fresh) != nil {
			return fresh, ErrSecurityBaseline
		}
		baseline.Stage = installstate.BaselineVerified
		document.Revision++
		return e.journal.Commit(ctx, fresh, document)
	}
	for _, resource := range b.plan.Resources() {
		object := resource.Object
		key := installstate.Key{APIVersion: object.GetAPIVersion(), Kind: object.GetKind(), Name: object.GetName()}
		if !slices.ContainsFunc(baseline.Resources, func(entry installstate.BaselineResource) bool { return entry.Key == key }) {
			return b.create(ctx, fresh, key)
		}
	}
	return fresh, ErrSecurityBaseline
}

func (b *baselineWorkflow) create(ctx context.Context, snapshot *installstate.Snapshot, key installstate.Key) (*installstate.Snapshot, error) {
	return b.createEnrollment(ctx, snapshot, key, nil)
}

func (b *baselineWorkflow) createEnrollment(ctx context.Context, snapshot *installstate.Snapshot, key installstate.Key, enrollment *baselineEnrollmentEffect) (*installstate.Snapshot, error) {
	fresh, err := b.original(ctx, snapshot)
	if err != nil {
		return snapshot, err
	}
	document := fresh.Document()
	baseline := document.SecurityBaseline
	if baseline.Stage != installstate.BaselineApplying || baseline.Pending != nil {
		return fresh, ErrInvalid
	}
	if enrollment == nil && !freshBaselineEnrollment(document) || enrollment != nil && (!enrollment.matches(b, fresh) || enrollment.key != key || enrollment.used || enrollment.nonce != "") {
		return fresh, ErrSecurityBaseline
	}
	template, err := b.contract.Template(key, false)
	if err != nil || slices.ContainsFunc(baseline.Resources, func(entry installstate.BaselineResource) bool { return entry.Key == key }) {
		return fresh, ErrInvalid
	}
	if _, err := b.engine.access.Get(ctx, key); !apierrors.IsNotFound(err) {
		return fresh, ErrOwnership
	}
	nonce, err := installstate.NewID()
	if err != nil {
		return fresh, ErrInvalid
	}
	candidate, err := template.Candidate(nonce)
	if err != nil {
		return fresh, ErrInvalid
	}
	if enrollment != nil && enrollment.close(ctx, b, fresh) != nil {
		return fresh, ErrSecurityBaseline
	}
	admitted, err := b.engine.access.Create(ctx, key, candidate, true)
	if err != nil || template.MatchAdmitted(admitted) != nil || admitted.GetAnnotations()[installstate.MutationAnnotation] != nonce {
		return fresh, ErrRead
	}
	if b.verifyOwned(ctx, fresh) != nil {
		return fresh, ErrSecurityBaseline
	}
	fresh, err = b.original(ctx, fresh)
	if err != nil {
		return snapshot, err
	}
	if enrollment != nil && enrollment.close(ctx, b, fresh) != nil {
		return fresh, ErrSecurityBaseline
	}
	baseline.Pending = &installstate.Pending{Action: installstate.Create, Key: key, CreateNonce: nonce, AfterSHA256: template.Hash()}
	document.Revision++
	intent, err := b.engine.journal.Commit(ctx, fresh, document)
	if err != nil {
		return fresh, err
	} // No target effect before confirmed intent.
	if err := b.prepareReceipt(intent); err != nil {
		return intent, ErrOutcomeUnknown
	}
	// Keep the exact empty original receipt through all new remote proof reads.
	// It is replaced with the known ACK identity only after the one actual call.
	var originalReceipt *privatefs.FilePin
	if enrollment != nil {
		originalReceipt, err = b.pinEnrollmentReceipt(intent.Document(), "")
		defer originalReceipt.Close()
		enrollment.receipt = originalReceipt
		if err != nil || enrollment.follow(ctx, intent) != nil {
			return intent, ErrOutcomeUnknown
		}
	}
	if _, err := b.original(ctx, intent); err != nil {
		return intent, ErrOutcomeUnknown
	}
	if b.verifyOwned(ctx, intent) != nil {
		return intent, ErrOutcomeUnknown
	}
	if enrollment != nil {
		if enrollment.close(ctx, b, intent) != nil || originalReceipt.Confirm() != nil || enrollment.used {
			return intent, ErrOutcomeUnknown
		}
		enrollment.nonce, enrollment.used = nonce, true // consumed BEFORE transport
	}
	ack, effectErr := b.engine.access.Create(ctx, key, candidate, false)
	if enrollment != nil && originalReceipt.Confirm() != nil {
		return intent, ErrOutcomeUnknown
	}
	if effectErr == nil && ack != nil {
		// Persist any known ACK identity BEFORE accepting its shape. A malformed
		// ACK cannot leave an empty receipt that later adopts a replacement.
		if err := b.pinReceiptUID(intent.Document(), ack.GetUID()); err != nil {
			return intent, ErrOutcomeUnknown
		}
		if enrollment != nil {
			ackReceipt, err := b.pinEnrollmentReceipt(intent.Document(), ack.GetUID())
			if err != nil {
				return intent, ErrOutcomeUnknown
			}
			defer ackReceipt.Close()
			enrollment.receipt = ackReceipt // only this known ACK rollover is allowed
		}
	}
	if effectErr == nil && (ack == nil || !effectMatches(template, baseline.Pending, ack)) {
		return intent, ErrOutcomeUnknown
	}
	return b.recoverEnrollment(ctx, intent, ack, effectErr == nil, ambiguousCreateResponse(effectErr), enrollment)
}

// Recovery never retries any CREATE or dry-run. Only the original ambiguous
// call may bind first identity from its immediate checked readback. Explicit
// resume requires the protected already-pinned UID, not matching public labels.
func (b *baselineWorkflow) recover(ctx context.Context, snapshot *installstate.Snapshot, ack *unstructured.Unstructured, hasAck, initialObservation bool) (*installstate.Snapshot, error) {
	return b.recoverEnrollment(ctx, snapshot, ack, hasAck, initialObservation, nil)
}

func (b *baselineWorkflow) recoverEnrollment(ctx context.Context, snapshot *installstate.Snapshot, ack *unstructured.Unstructured, hasAck, initialObservation bool, enrollment *baselineEnrollmentEffect) (*installstate.Snapshot, error) {
	fresh, err := b.original(ctx, snapshot)
	if err != nil {
		return snapshot, ErrOutcomeUnknown
	}
	document := fresh.Document()
	baseline := document.SecurityBaseline
	pending := baseline.Pending
	if baseline.Stage != installstate.BaselineApplying || pending == nil || pending.Action != installstate.Create {
		return fresh, ErrInvalid
	}
	if enrollment == nil && !freshBaselineEnrollment(document) || enrollment != nil && (!enrollment.matches(b, fresh) || (hasAck || initialObservation) && (!enrollment.used || enrollment.key != pending.Key || enrollment.nonce != pending.CreateNonce)) {
		return fresh, ErrSecurityBaseline
	}
	template, err := b.contract.Template(pending.Key, false)
	if err != nil || template.Hash() != pending.AfterSHA256 || slices.ContainsFunc(baseline.Resources, func(entry installstate.BaselineResource) bool { return entry.Key == pending.Key }) {
		return fresh, ErrInvalid
	}
	if b.verifyOwned(ctx, fresh) != nil {
		return fresh, ErrOutcomeUnknown
	}
	live, err := b.engine.access.Get(ctx, pending.Key)
	if err != nil || !effectMatches(template, pending, live) || hasAck && (ack == nil || ack.GetUID() != live.GetUID()) {
		return fresh, ErrOutcomeUnknown
	}
	if initialObservation {
		if enrollment != nil && (enrollment.receipt == nil || enrollment.receipt.Confirm() != nil) {
			return fresh, ErrOutcomeUnknown
		}
		if b.pinReceiptUID(document, live.GetUID()) != nil {
			return fresh, ErrOutcomeUnknown
		}
		if enrollment != nil {
			observedReceipt, err := b.pinEnrollmentReceipt(document, live.GetUID())
			if err != nil {
				return fresh, ErrOutcomeUnknown
			}
			defer observedReceipt.Close()
			enrollment.receipt = observedReceipt
		}
	}
	original, err := b.loadReceiptUID(document)
	if err != nil || original != live.GetUID() {
		return fresh, ErrOutcomeUnknown
	}
	var originalReceipt *privatefs.FilePin
	if enrollment != nil {
		originalReceipt = enrollment.receipt
		if originalReceipt == nil || originalReceipt.Confirm() != nil {
			return fresh, ErrOutcomeUnknown
		}
	}
	if _, err := b.original(ctx, fresh); err != nil {
		return fresh, ErrOutcomeUnknown
	}
	if enrollment != nil && (enrollment.close(ctx, b, fresh) != nil || originalReceipt.Confirm() != nil) {
		return fresh, ErrOutcomeUnknown
	}
	baseline.Resources = append(baseline.Resources, installstate.BaselineResource{Key: pending.Key, UID: original, TemplateSHA256: template.Hash()})
	installstate.SortBaselineResources(baseline.Resources)
	baseline.Pending = nil
	document.Revision++
	settled, err := b.engine.journal.Commit(ctx, fresh, document)
	if err != nil {
		return fresh, ErrOutcomeUnknown
	}
	if enrollment != nil && (enrollment.follow(ctx, settled) != nil || enrollment.close(ctx, b, settled) != nil || originalReceipt.Confirm() != nil) {
		return settled, ErrOutcomeUnknown
	}
	return settled, nil
}

func (b *baselineWorkflow) pinEnrollmentReceipt(document installstate.Document, uid types.UID) (*privatefs.FilePin, error) {
	name, err := b.receiptName(document)
	if err != nil {
		return nil, ErrOutcomeUnknown
	}
	body, _, pin, err := b.engine.files.Pin(name, 4096)
	want, bodyErr := b.receiptBody(document, uid)
	if err != nil || bodyErr != nil || !bytes.Equal(body, want) || pin.Confirm() != nil {
		_ = pin.Close()
		return nil, ErrOutcomeUnknown
	}
	return pin, nil
}
