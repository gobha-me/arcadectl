// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"errors"
	"time"

	"github.com/gobha-me/arcadectl/internal/installstate"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	"k8s.io/apimachinery/pkg/util/wait"
)

// ResumeFixtures disposes of an interrupted probe run before ordinary Step.
// Only the closed cluster provider may do so. This NEVER proves current
// AdmissionEffective, restores a driver, adopts a CREATE, or replays DELETE.
// Untouched originals need newly justified single-attempt cleanup; previously
// attempted originals may only be observed until actual complete absence.
func (l *Lifecycle) ResumeFixtures(ctx context.Context, s *installstate.Snapshot, opts LifecycleOptions) error {
	if l == nil || l.engine == nil || ctx == nil || s == nil || opts.Now.IsZero() {
		return ErrInvalid
	}
	checks, ok := l.checks.(*clusterLifecycleChecks)
	if !ok || checks == nil || checks.admission == nil || checks.prerequisites == nil || checks.prerequisites.engine != l.engine {
		return ErrInvalid
	}
	d := s.Document()
	plan := l.engine.plans[d.TargetPackage]
	if plan == nil || !l.engine.compatible(d) {
		return ErrInvalid
	}
	return checks.admission.resumeFixtures(ctx, LifecycleCheck{Checkpoint: AdmissionEffective, Snapshot: s, Mode: d.Mode, Target: plan, Options: opts})
}

// Eligibility is stricter than phaseReadable: no Planned tail, unknown CREATE,
// unknown setup or never-created UID can be converted into a cleanup receipt.
func fixtureRecoveryEligible(f *fixtureLedger) bool {
	if f == nil || f.driverFresh || f.ackSlot != -1 || f.effectSlot != -1 || f.seedAck || f.seedEffect || f.markerAck || f.markerEffect || f.worldPublication || f.behaviorCompletion != nil || f.retirementPublicationUnknown || !validFixtureRecipe(f.document) || !validFixtureDestroySeedDocument(f.document) || !validFixtureRetainedMarkerDocument(f.document) || f.document.DestroySeed != nil && f.document.DestroySeed.State != fixtureDestroySeedAcknowledged || f.document.RetainedMarker != nil && f.document.RetainedMarker.State != fixtureRetainedMarkerAcknowledged {
		return false
	}
	for _, entry := range f.document.Entries {
		if !nativeFixtureUID(string(entry.OriginalUID)) {
			return false
		}
		switch entry.State {
		case fixtureOriginal, fixtureDeleteAttempted, fixtureAbsent:
		default:
			return false
		}
	}
	return true
}

func (a *ClusterAdmission) resumeFixtures(ctx context.Context, request LifecycleCheck) error {
	if a == nil || a.prerequisites == nil || a.prerequisites.engine == nil || ctx == nil || request.Snapshot == nil || request.Checkpoint != AdmissionEffective {
		return ErrInvalid
	}
	e, s := a.prerequisites.engine, request.Snapshot
	if e.fixtureFence(s) == nil {
		return nil // no active run; ordinary Step still performs fresh proofs
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Minute)
	defer cancel()
	retirement, retirementErr := e.readFixtureRetirement(s.Anchor())
	if retirementErr != nil && !errors.Is(retirementErr, privatefs.ErrNotFound) {
		return ErrFixtures
	}
	var f *fixtureLedger
	var err error
	if retirementErr == nil && retirement.record.State == fixtureRetiring {
		f, err = e.loadFixtureRetirement(ctx, s)
	} else {
		f, err = e.loadFixtureLedger(ctx, s)
	}
	if err != nil {
		return ErrFixtures
	}
	defer f.close()
	if !fixtureRecoveryEligible(f) {
		return ErrFixtures
	}
	if _, err := f.loadOriginalWorlds(); err != nil {
		return ErrFixtures
	}
	actors, err := a.newActors(ctx, request, existingScopedImpersonation)
	if err != nil {
		return ErrFixtures
	}
	w, err := actors.fixtures(ctx, f)
	if err != nil {
		return ErrFixtures
	}
	// A DeleteAttempted original still present is deliberately rejected by
	// complete phase accounting. The first reverse cleanup call may only wait
	// for its disappearance; never normalize presence or refresh its RV.
	for _, slot := range fixtureDeletionOrder(f.document) {
		if f.document.Entries[slot].State == fixtureAbsent {
			continue
		}
		remove := w.removeUnmarkedOriginal
		if f.document.RetainedMarker != nil {
			remove = w.removeAcknowledgedMarkerOriginal
		}
		if err := remove(ctx, slot); err != nil {
			if f.document.Entries[slot].State != fixtureDeleteAttempted || wait.PollUntilContextTimeout(ctx, 200*time.Millisecond, 90*time.Second, true, func(ctx context.Context) (bool, error) {
				return remove(ctx, slot) == nil, nil
			}) != nil {
				return ErrFixtures
			}
		}
	}
	if w.retireDrained(ctx) != nil || a.prerequisites.original(ctx, s) != nil || e.fixtureFence(s) != nil {
		return ErrFixtures
	}
	return nil
}
