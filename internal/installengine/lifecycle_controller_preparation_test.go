// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"strings"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installstate"
)

func TestLifecycleControllerPreparationWaitsForReadyThenWholeQuietness(t *testing.T) {
	testAcknowledgedDeploymentEffectMode(t, "", false, true)
}

func TestLifecycleControllerPreparationUpdateWaitsForReadyThenWholeQuietness(t *testing.T) {
	testAcknowledgedDeploymentEffectMode(t, "", true, true)
}

func TestLifecycleControllerPreparationRejectsLateProducerStatusDrift(t *testing.T) {
	testAcknowledgedDeploymentEffectMode(t, "late-producer-status", false, true)
}

func TestLifecycleControllerPreparationRejectsForeignUID(t *testing.T) {
	testAcknowledgedDeploymentEffectMode(t, "wrong-live-uid", false, true)
}

func TestLifecycleControllerPreparationRejectsUnsignedTemplate(t *testing.T) {
	testAcknowledgedDeploymentEffectMode(t, "changed-live-template", false, true)
}

func TestLifecycleControllerPreparationRejectsStaleJournal(t *testing.T) {
	testAcknowledgedDeploymentEffectMode(t, "journal-in-wait", false, true)
}

func TestLifecycleControllerPreparationRejectsReceiptReplacementDuringWait(t *testing.T) {
	testAcknowledgedDeploymentEffectMode(t, "receipt-in-wait", false, true)
}

func TestLifecycleControllerPreparationRejectsReceiptReplacementDuringProof(t *testing.T) {
	testAcknowledgedDeploymentEffectMode(t, "receipt-after-wait", false, true)
}

func TestLifecycleControllerPreparationRejectsReceiptReplacementDuringSettlement(t *testing.T) {
	testAcknowledgedDeploymentEffectMode(t, "receipt-at-settlement", false, true)
}

func TestLifecycleControllerPreparationDoesNotWaitForLostCreateResponse(t *testing.T) {
	testAcknowledgedDeploymentEffectMode(t, "ambiguous-response", false, true)
}

func TestLifecycleControllerPreparationDoesNotWaitForLostUpdateResponse(t *testing.T) {
	testAcknowledgedDeploymentEffectMode(t, "ambiguous-response", true, true)
}

func TestLifecycleControllerPreparationStableUnreadyCannotOpenProof(t *testing.T) {
	testAcknowledgedDeploymentEffectMode(t, "stable-unready", false, true)
}

// Pure private-purpose binding controls; these do not stand in for cluster
// authentication, native readiness, or the actual Apply/ACK tests above.
func TestLifecycleControllerPreparationCannotTransferOriginalOrIntent(t *testing.T) {
	f := newBaselineFixture(t)
	completeBaselineFixture(t, f)
	access := &HTTPAccess{}
	f.engine.access = access
	checks := &clusterLifecycleChecks{prerequisites: &ClusterPrerequisites{engine: f.engine, access: access}}
	lifecycle := &Lifecycle{engine: f.engine, checks: checks}
	d := f.snapshot.Document()
	key := deploymentKey(d.Namespace, "arcadectl-controller")
	target, err := f.engine.desired(d, key, d.TargetPackage, false)
	if err != nil {
		t.Fatal("signed controller target unavailable")
	}
	purpose := &lifecycleControllerPreparation{lifecycle: lifecycle, checks: checks, original: f.snapshot, key: key, digest: d.TargetPackage, hash: target.Hash()}
	if !purpose.validOriginal(f.engine, f.snapshot, key, d.TargetPackage, false) {
		t.Fatal("exact private original purpose refused")
	}
	equivalent, err := f.store.Load(t.Context(), f.snapshot.Anchor())
	if err != nil || equivalent == f.snapshot {
		t.Fatal("independent original snapshot unavailable")
	}
	for _, mutate := range []func(*lifecycleControllerPreparation){
		func(p *lifecycleControllerPreparation) {
			copy := *lifecycle
			p.lifecycle = &copy
			copy.engine = &Engine{}
		},
		func(p *lifecycleControllerPreparation) { p.checks = &clusterLifecycleChecks{} },
		func(p *lifecycleControllerPreparation) { p.original = equivalent },
		func(p *lifecycleControllerPreparation) { p.key.Name = "arcadectl-api" },
		func(p *lifecycleControllerPreparation) { p.digest = strings.Repeat("f", 64) },
		func(p *lifecycleControllerPreparation) { p.hash = strings.Repeat("f", 64) },
	} {
		copy := *purpose
		mutate(&copy)
		if copy.validOriginal(f.engine, f.snapshot, key, d.TargetPackage, false) {
			t.Fatal("private preparation transferred to another original identity, key or template")
		}
	}
	if purpose.validOriginal(f.engine, f.snapshot, key, d.TargetPackage, true) || purpose.validOriginal(&Engine{}, f.snapshot, key, d.TargetPackage, false) {
		t.Fatal("private preparation transferred to paused target or another engine")
	}
	pending := &installstate.Pending{Action: installstate.Create, Key: key, CreateNonce: strings.Repeat("c", 32), AfterSHA256: target.Hash()}
	d.Revision++
	d.Pending = pending
	intent, err := f.store.Commit(t.Context(), f.snapshot, d)
	if err != nil {
		t.Fatal("actual private test intent CAS unavailable")
	}
	bound, err := purpose.bindIntent(f.engine, intent, pending)
	if err != nil || !bound.validIntent(f.engine, intent) || bound.validOriginal(f.engine, f.snapshot, key, d.TargetPackage, false) {
		t.Fatal("purpose lost exact single intent binding")
	}
	loaded, err := f.store.Load(t.Context(), intent.Anchor())
	if err != nil || bound.validIntent(f.engine, loaded) || bound.validIntent(&Engine{}, intent) {
		t.Fatal("purpose transferred across restart or engine")
	}
	for _, mutate := range []func(*installstate.Pending){
		func(p *installstate.Pending) { p.CreateNonce = strings.Repeat("d", 32) },
		func(p *installstate.Pending) { p.Action = installstate.Update },
		func(p *installstate.Pending) { p.BeforeUID = "foreign" },
		func(p *installstate.Pending) { p.BeforeResourceVersion = "foreign" },
		func(p *installstate.Pending) { p.BeforeSHA256 = strings.Repeat("f", 64) },
		func(p *installstate.Pending) { p.AfterSHA256 = strings.Repeat("f", 64) },
		func(p *installstate.Pending) { p.Key.Name = "arcadectl-api" },
	} {
		changed := *pending
		mutate(&changed)
		if _, err := purpose.bindIntent(f.engine, intent, &changed); err == nil {
			t.Fatal("purpose accepted different locally constructed Pending fields")
		}
		copy := *bound
		copy.pending = changed
		if copy.validIntent(f.engine, intent) {
			t.Fatal("purpose accepted changed bound Pending fields")
		}
	}
	d.Revision++
	d.Pending = nil
	d.Resources = append(d.Resources, installstate.Resource{Key: key, UID: "unit-controller", TemplateSHA256: target.Hash(), Retained: target.Retained(), Phase: target.Phase()})
	installstate.SortResources(d.Resources)
	other, err := f.store.Commit(t.Context(), intent, d)
	if err != nil {
		t.Fatal("private test settlement CAS unavailable")
	}
	if bound.validIntent(f.engine, other) {
		t.Fatal("purpose transferred across later settlement CAS")
	}
	d.Stage = installstate.Verifying
	d.Revision++
	stage, err := f.store.Commit(t.Context(), other, d)
	if err != nil {
		t.Fatal("private test stage CAS unavailable")
	}
	copy := *purpose
	copy.original = stage
	if bound.validIntent(f.engine, stage) || copy.validOriginal(f.engine, stage, key, d.TargetPackage, false) {
		t.Fatal("purpose transferred across lifecycle stage")
	}
}
