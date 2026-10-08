// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"reflect"
	"time"

	"github.com/gobha-me/arcadectl/internal/privatefs"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/wait"
)

// Only a new v2 WAL plus the independently sealed initial phase can create a
// driver. Loading receipts/recovery/archives never restores this capability.
type fixtureAdmissionDriver struct {
	wire      *fixtureWire
	initial   *initialAdmissionPhase
	previous  *fixturePhaseObservation
	next      fixtureAdmissionCase
	completed uint64
	failed    bool
}

type fixtureDriverSeal struct {
	body     []byte
	identity privatefs.FileIdentity
	revision uint64
	worldID  privatefs.FileIdentity
}

func (a *ClusterAdmission) newAdmissionDriver(ctx context.Context, request LifecycleCheck) (*fixtureAdmissionDriver, error) {
	initial, err := a.waitInitialPhase(ctx, request)
	if err != nil {
		return nil, ErrFixtures
	}
	actors, err := a.newActors(ctx, request, existingScopedImpersonation)
	if err != nil {
		return nil, ErrFixtures
	}
	f, err := a.prerequisites.engine.prepareFixtureLedgerV2(ctx, request.Snapshot)
	if err != nil {
		return nil, err
	}
	if initial.seal(f) != nil {
		_ = f.close()
		return nil, ErrFixtures // uncertain preparation remains durably fenced
	}
	w, err := actors.fixtures(ctx, f)
	if err != nil {
		_ = f.close()
		return nil, ErrFixtures
	}
	f.wireMu.Lock()
	defer f.wireMu.Unlock()
	if !f.driverFresh || f.document.Recipe != fixtureRecipeV2 || f.document.DestroySeed != nil || f.document.RetainedMarker != nil || f.document.Behavior != nil {
		_ = f.close()
		return nil, ErrFixtures
	}
	f.driverFresh = false // a second wire/new driver cannot repeat this run
	return &fixtureAdmissionDriver{wire: w, initial: initial}, nil
}

func (d *fixtureAdmissionDriver) sealLocked() (fixtureDriverSeal, error) {
	if d == nil || d.wire == nil || d.wire.ledger == nil || d.wire.ledger.worldIdentity == nil {
		return fixtureDriverSeal{}, ErrFixtures
	}
	f := d.wire.ledger
	return fixtureDriverSeal{bytes.Clone(f.body), f.identity, f.document.Revision, *f.worldIdentity}, nil
}

func (d *fixtureAdmissionDriver) unchangedLocked(ctx context.Context, seal fixtureDriverSeal) error {
	w, f := d.wire, d.wire.ledger
	if !w.phaseReadable() || f.identity != seal.identity || f.document.Revision != seal.revision || !bytes.Equal(f.body, seal.body) || f.worldIdentity == nil || *f.worldIdentity != seal.worldID || w.current(ctx) != nil {
		return ErrFixtures
	}
	s := w.actors.request.Snapshot
	fresh, err := f.engine.journal.Load(ctx, s.Anchor())
	if err != nil || !bytes.Equal(fresh.Bytes(), s.Bytes()) || fresh.ResourceVersion() != s.ResourceVersion() {
		return ErrFixtures
	}
	// Close local-file checks AFTER the remote actor/policy/journal reads.
	body, identity, err := f.engine.files.Read(f.name, fixtureLedgerMaxBytes)
	if err != nil || identity != seal.identity || !bytes.Equal(body, seal.body) || f.engine.files.ConfirmDurable(f.name, identity) != nil || f.originalWorldsCurrent() != nil || f.worldIdentity == nil || *f.worldIdentity != seal.worldID {
		return ErrFixtures
	}
	decoded, err := f.decodeCurrentWAL(body)
	if err != nil || !reflect.DeepEqual(decoded, f.document) || f.identity != seal.identity || !bytes.Equal(f.body, seal.body) || f.document.Revision != seal.revision {
		return ErrFixtures
	}
	return nil
}

func fixtureSameObservation(before, after *fixturePhaseObservation) bool {
	return before != nil && after != nil && samePhaseBaseline(before.phase, after.phase) && reflect.DeepEqual(before.objects, after.objects)
}

// All persistent setup and the 55 one-send cases share one wireMu interval.
// Every error permanently latches failure; no prefix is current effectiveness.
func (d *fixtureAdmissionDriver) run(ctx context.Context) (err error) {
	if d == nil || d.wire == nil || d.wire.ledger == nil || ctx == nil {
		return ErrFixtures
	}
	f := d.wire.ledger
	f.wireMu.Lock()
	defer f.wireMu.Unlock()
	defer func() {
		if err != nil {
			d.failed = true
			f.behaviorCompletion = nil
		}
	}()
	if d.failed || d.initial == nil || d.previous != nil || d.next != 0 || d.completed != 0 || f.document.Recipe != fixtureRecipeV2 || f.document.Behavior != nil {
		return ErrFixtures
	}
	if err = d.createOriginalsLocked(ctx); err != nil {
		return err
	}
	for d.next < fixtureAdmissionCaseCount {
		if d.next == 39 {
			if err = d.seedLocked(ctx); err != nil {
				return err
			}
		}
		if d.next == 45 {
			if err = d.markerLocked(ctx); err != nil {
				return err
			}
		}
		if err = d.runCaseLocked(ctx, d.next); err != nil {
			return err
		}
	}
	return d.finishLocked(ctx)
}

func (d *fixtureAdmissionDriver) createOriginalsLocked(ctx context.Context) error {
	w, f := d.wire, d.wire.ledger
	before, err := w.observePhaseLocked(ctx)
	if err != nil || before == nil || !samePhaseBaseline(d.initial.baseline, before.phase) {
		return ErrFixtures
	}
	for slot := range f.document.Entries {
		if f.document.Entries[slot].State != fixturePlanned || before.objects[slot] != nil {
			return ErrFixtures
		}
		seal, err := d.sealLocked()
		if err != nil || d.unchangedLocked(ctx, seal) != nil {
			return ErrFixtures
		}
		_, previewErr := w.dryRunLocked(ctx, slot)
		afterPreview, phaseErr := w.observePhaseLocked(ctx) // mandatory even refusal
		if previewErr != nil || phaseErr != nil || !fixtureSameObservation(before, afterPreview) || d.unchangedLocked(ctx, seal) != nil {
			return ErrFixtures
		}
		next, err := f.nextDocument()
		if err != nil {
			return ErrFixtures
		}
		next.Entries[slot].State = fixtureCreateAttempted
		if f.advance(next) != nil {
			return ErrFixtures
		}
		created, createErr := w.createLocked(ctx, slot)
		// A reliable ACK is already durable before any refusal. Never use a
		// later GET to repair an unknown CREATE or re-send a pending intent.
		if createErr != nil || f.validateResult(slot, fixtureAcknowledgedResult, created, time.Now().UTC()) != nil {
			_, _ = w.observePhaseLocked(ctx)
			return ErrFixtures
		}
		seal, err = d.sealLocked()
		if err != nil {
			return ErrFixtures
		}
		var accepted *fixturePhaseObservation
		// Observation-only convergence is bounded; no send is retried. The
		// original sealed domain and all earlier fixtures remain byte-exact.
		if wait.PollUntilContextTimeout(ctx, 200*time.Millisecond, 90*time.Second, true, func(ctx context.Context) (bool, error) {
			fresh, err := w.observePhaseLocked(ctx)
			if err != nil {
				return false, nil
			}
			if !samePhaseBaseline(before.phase, fresh.phase) || fresh.objects[slot] == nil || d.unchangedLocked(ctx, seal) != nil {
				return false, ErrFixtures
			}
			if !fixtureAdmissionOriginalSettled(f, slot, fresh, time.Now().UTC()) {
				return false, nil // ACK shape is not a settled controller baseline
			}
			for index := range before.objects {
				if index != slot && !reflect.DeepEqual(before.objects[index], fresh.objects[index]) {
					return false, ErrFixtures
				}
			}
			accepted = fresh
			return true, nil
		}) != nil || accepted == nil {
			return ErrFixtures
		}
		before = accepted
	}
	d.previous = before
	return nil
}

func fixtureAdmissionOriginalSettled(f *fixtureLedger, slot int, observation *fixturePhaseObservation, observed time.Time) bool {
	if f == nil || observation == nil || slot < 0 || slot >= len(fixtureCatalogFor(f.document)) || observation.objects[slot] == nil {
		return false
	}
	if slot == fixtureCancelledDestroy || slot == fixtureVerifiedCancelledDestroy {
		for _, leader := range observation.phase.Leaders {
			if leader.Row.Key.Name == "destroy-controller.arcade.gobha.me" {
				return f.validateWarmCancelledDestroySlotResult(slot, observation.objects[slot], observed) == nil
			}
		}
	}
	return f.validateResult(slot, fixtureStableResult, observation.objects[slot], observed) == nil
}

func (d *fixtureAdmissionDriver) runCaseLocked(ctx context.Context, number fixtureAdmissionCase) (err error) {
	defer func() {
		if err != nil {
			d.failed = true
		}
	}()
	w, f := d.wire, d.wire.ledger
	if d.failed || number != d.next || number >= fixtureAdmissionCaseCount || d.completed != (uint64(1)<<number)-1 || f.document.Recipe != fixtureRecipeV2 || f.document.Behavior != nil || (number < 39) != (f.document.DestroySeed == nil) || (number < 45) != (f.document.RetainedMarker == nil) {
		return ErrFixtures
	}
	for _, entry := range f.document.Entries {
		if entry.State != fixtureOriginal || !nativeFixtureUID(string(entry.OriginalUID)) {
			return ErrFixtures
		}
	}
	seal, err := d.sealLocked()
	if err != nil {
		return err
	}
	before, err := w.observePhaseLocked(ctx)
	if err != nil || !fixtureSameObservation(d.previous, before) || d.unchangedLocked(ctx, seal) != nil {
		return ErrFixtures
	}
	r, err := w.admissionRequest(number, before)
	if err != nil {
		return err
	}
	if r.slot == -1 && w.counterpartAbsentLocked(ctx, number, before) != nil {
		return ErrFixtures
	}
	key := fixtureObjectKey(r.object)
	operation := r.operation
	if operation == probeEphemeralOperation || operation == probeResizeOperation {
		operation = probeUpdateOperation
	}
	permission, err := actorPermission(key, operation)
	if err != nil {
		return ErrFixtures
	}
	if r.operation == probeEphemeralOperation {
		permission.spec.ResourceAttributes.Subresource = "ephemeralcontainers"
	} else if r.operation == probeResizeOperation {
		permission.spec.ResourceAttributes.Subresource = "resize"
	}
	parent := w.actors.admission.prerequisites.access
	discovery, discoveryErr := parent.discover(ctx, key.APIVersion)
	authorizer := parent
	if r.actor != 0 {
		authorizer = w.actors.clients[r.actor]
	}
	if discoveryErr != nil || !discoveredPermission(discovery, permission) || authorizer == nil || authorizer.authorize(ctx, permission.spec) != nil || d.unchangedLocked(ctx, seal) != nil {
		return ErrFixtures
	}
	binding, message := "", ""
	if r.policy != "" {
		policy := w.actors.policies.policies[r.policy]
		if policy == nil || r.index < 0 || r.index >= len(policy.Spec.Validations) {
			return ErrFixtures
		}
		message = policy.Spec.Validations[r.index].Message
		for _, candidate := range w.actors.policies.bindings {
			if candidate.Spec.PolicyName == r.policy {
				if binding != "" {
					return ErrFixtures
				}
				binding = candidate.Name
			}
		}
		if binding == "" {
			return ErrFixtures
		}
	}
	started := time.Now().UTC()
	var reply *unstructured.Unstructured
	var replyErr error
	if r.actor == 0 {
		reply, replyErr = parent.probeOperation(ctx, r.operation, r.object, r.policy, binding, message)
	} else {
		reply, replyErr = w.actors.probe(ctx, r.actor, r.operation, r.object, r.policy, binding, message)
	}
	// Do not short-circuit this observation or named absence read on send
	// errors. Neither a partial proof nor transport success grants a case bit.
	after, phaseErr := w.observePhaseLocked(ctx)
	counterpartErr := error(nil)
	if r.slot == -1 {
		counterpartErr = w.counterpartAbsentLocked(ctx, number, before)
	}
	observed := time.Now().UTC()
	if phaseErr != nil || !fixtureSameObservation(before, after) || counterpartErr != nil || d.unchangedLocked(ctx, seal) != nil || replyErr != nil {
		return ErrFixtures
	}
	if r.policy != "" {
		if reply != nil { // exact native denial capture returns nil, nil
			return ErrFixtures
		}
	} else if d.validatePositive(number, r, reply, before, started, observed) != nil {
		return ErrFixtures
	}
	d.previous = after
	d.completed |= uint64(1) << number
	d.next++
	return nil
}

func (d *fixtureAdmissionDriver) validatePositive(number fixtureAdmissionCase, r fixtureAdmissionRequest, reply *unstructured.Unstructured, before *fixturePhaseObservation, started, observed time.Time) error {
	f := d.wire.ledger
	if r.slot == -1 {
		if validAdmissionProbeResult(r.object, reply, started, observed) {
			return nil
		}
		return ErrFixtures
	}
	original := before.objects[r.slot]
	if number == 16 || number == 24 || number == 32 {
		return f.validateWorkerGateAuthorization(r.slot, original, reply, &before.phase, observed)
	}
	switch number {
	case 36, 37:
		return f.validatePlainPodUnchangedSubresource(r.operation, original, reply, &before.phase, observed)
	case 42:
		return f.validateRetainedMarkerDryRunAdd(original, reply, &before.phase, observed)
	case 44, 47:
		return f.validateFixturePVCDeleteReply(r.slot, original, reply, &before.phase, started, observed)
	case 46:
		return f.validateRetainedMarkerDryRunRemove(original, reply, &before.phase, observed)
	case 48:
		return f.validateVerifiedCancelledUnchangedUpdate(original, reply, &before.phase, observed)
	case 53:
		return f.validateAdmissionConfirmationDelta(original, reply, &before.phase, observed)
	default:
		return f.validateFixtureUnchangedUpdate(r.slot, original, reply, &before.phase, observed)
	}
}

func (d *fixtureAdmissionDriver) finishLocked(ctx context.Context) error {
	w, f := d.wire, d.wire.ledger
	if d.failed || d.next != fixtureAdmissionCaseCount || d.completed != fixtureAdmissionAllCases || f.document.Recipe != fixtureRecipeV2 || f.document.Behavior != nil || f.document.DestroySeed == nil || f.document.DestroySeed.State != fixtureDestroySeedAcknowledged || f.document.RetainedMarker == nil || f.document.RetainedMarker.State != fixtureRetainedMarkerAcknowledged {
		return ErrFixtures
	}
	seal, err := d.sealLocked()
	if err != nil {
		return err
	}
	final, err := w.observePhaseLocked(ctx)
	if err != nil || !fixtureSameObservation(d.previous, final) || d.unchangedLocked(ctx, seal) != nil {
		return ErrFixtures
	}
	f.behaviorCompletion = &fixtureBehaviorCompletion{ledger: f, revision: seal.revision, bodySHA: fixtureWorldDigest(seal.body), identity: seal.identity}
	defer func() { f.behaviorCompletion = nil }()
	next, err := f.nextDocument()
	if err != nil {
		return err
	}
	next.Behavior = &fixtureBehaviorReceipt{Version: fixtureBehaviorVersionV2, Revision: next.Revision}
	return f.advance(next) // consumes capability BEFORE uncertain publication
}
