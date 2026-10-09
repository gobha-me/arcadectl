// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"maps"
	"reflect"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
)

// Real lifecycle Step/Begin/CAS completion under explicitly synthetic proof
// providers. This validates the context boundary, not native runtime security.
func TestBaselineObservationContextGenuineLifecycleCompletion(t *testing.T) {
	previous, target := lifecycleTransitionPlans(t)
	v := newLifecycleFixturePlans(t, previous, target)
	snapshot := v.finish(t, v.f.snapshot)
	for _, mode := range []installstate.Mode{installstate.Install, installstate.Upgrade, installstate.Rollback} {
		if mode != installstate.Install {
			digest := target.Digest()
			if mode == installstate.Rollback {
				digest = previous.Digest()
			}
			var err error
			snapshot, err = v.l.Begin(t.Context(), snapshot, mode, digest, v.opts)
			if err != nil {
				t.Fatal("signed lifecycle transition refused")
			}
			snapshot = v.finish(t, snapshot)
		}
		before, rv, writes := snapshot.Bytes(), snapshot.ResourceVersion(), v.f.access.writes+v.private.writes
		d := snapshot.Document()
		copy := d
		if d.Mode != mode || d.Stage != installstate.Complete || !v.f.engine.baselineObservable(d) {
			t.Fatal("genuine completed installed state is not observable")
		}
		if mode != installstate.Install && v.f.engine.compatible(d) {
			t.Fatal("completed observation changed mutation compatibility")
		}
		if !bytes.Equal(before, snapshot.Bytes()) || rv != snapshot.ResourceVersion() || writes != v.f.access.writes+v.private.writes || !reflect.DeepEqual(copy, d) {
			t.Fatal("read-only context changed original evidence")
		}
	}
	// A reinstall can retain the history left by a prior rollback.
	d := snapshot.Document()
	d.Mode = installstate.Install
	if d.PreviousPackage != target.Digest() || !v.f.engine.baselineObservable(d) {
		t.Fatal("completed install lost legitimate retained package history")
	}
	retired, err := v.l.Begin(t.Context(), snapshot, installstate.Uninstall, previous.Digest(), v.opts)
	if err != nil {
		t.Fatal("signed retaining uninstall refused")
	}
	retired = v.finish(t, retired)
	if v.f.engine.baselineObservable(retired.Document()) {
		t.Fatal("completed retirement became active runtime authority")
	}
}

func TestBaselineObservationContextCompleteRefusesInvalidEvidence(t *testing.T) {
	previous, target := lifecycleTransitionPlans(t)
	v := newLifecycleFixturePlans(t, previous, target)
	complete := v.finish(t, v.f.snapshot).Document()
	for _, row := range []struct {
		name   string
		change func(*installstate.Document)
	}{
		{"not-installed", func(d *installstate.Document) { d.Installed = false }},
		{"pending", func(d *installstate.Document) { d.Pending = &installstate.Pending{} }},
		{"retirement", func(d *installstate.Document) { d.AdmissionRetirementRevision = 1 }},
		{"active-mismatch", func(d *installstate.Document) { d.ActivePackage = target.Digest() }},
		{"missing-target", func(d *installstate.Document) { d.TargetPackage, d.ActivePackage = "missing", "missing" }},
		{"missing-previous", func(d *installstate.Document) { d.PreviousPackage = "missing" }},
		{"same-previous", func(d *installstate.Document) { d.PreviousPackage = d.TargetPackage }},
		{"namespace", func(d *installstate.Document) { d.Namespace = "wrong-original-scope" }},
		{"profile", func(d *installstate.Document) {
			if d.ProfileID == installrender.Profile137 {
				d.ProfileID = installrender.Profile135
			} else {
				d.ProfileID = installrender.Profile137
			}
		}},
		{"unknown-mode", func(d *installstate.Document) { d.Mode = "unknown" }},
		{"uninstall", func(d *installstate.Document) { d.Mode = installstate.Uninstall }},
		{"upgrade-no-previous", func(d *installstate.Document) { d.Mode = installstate.Upgrade }},
		{"upgrade-reversed", func(d *installstate.Document) { d.Mode, d.PreviousPackage = installstate.Upgrade, target.Digest() }},
		{"rollback-no-previous", func(d *installstate.Document) { d.Mode = installstate.Rollback }},
		{"rollback-reversed", func(d *installstate.Document) {
			d.Mode, d.TargetPackage, d.ActivePackage, d.PreviousPackage = installstate.Rollback, target.Digest(), target.Digest(), previous.Digest()
		}},
	} {
		t.Run(row.name, func(t *testing.T) {
			d := complete
			row.change(&d)
			if v.f.engine.baselineObservable(d) {
				t.Fatal("invalid completed state entered read-only active baseline context")
			}
		})
	}
	for _, digest := range []string{complete.TargetPackage, target.Digest()} {
		copy := *v.f.engine
		copy.plans = maps.Clone(copy.plans)
		copy.plans[digest] = &installrender.Plan{} // not authenticated
		d := complete
		if digest != complete.TargetPackage {
			d.PreviousPackage = digest
		}
		if copy.baselineObservable(d) {
			t.Fatal("untrusted registered plan entered observation context")
		}
	}
	var absent *Engine
	if absent.baselineObservable(complete) {
		t.Fatal("nil engine entered observation context")
	}
}

func TestBaselineObservationContextPreservesEveryNoncompleteModeStage(t *testing.T) {
	previous, target := lifecycleTransitionPlans(t)
	f := newFixtureWithPlans(t, false, previous, target)
	for _, mode := range []installstate.Mode{installstate.Install, installstate.Upgrade, installstate.Rollback, installstate.Uninstall, "unknown"} {
		for _, stage := range []installstate.Stage{installstate.Preparing, installstate.Quiescing, installstate.Applying, installstate.Verifying, installstate.RecoveryRequired, "unknown"} {
			for _, installed := range []bool{false, true} {
				for _, active := range []string{"", previous.Digest(), target.Digest(), "missing"} {
					d := f.snapshot.Document()
					d.Mode, d.Stage, d.Installed, d.ActivePackage, d.TargetPackage, d.PreviousPackage = mode, stage, installed, active, target.Digest(), previous.Digest()
					if f.engine.baselineObservable(d) != f.engine.compatible(d) {
						t.Fatal("noncomplete context changed existing eligibility")
					}
				}
			}
		}
	}
}
