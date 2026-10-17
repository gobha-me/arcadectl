// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"reflect"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installbaseline"
	"github.com/gobha-me/arcadectl/internal/installstate"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Actual Step/journal/private intent/ACK machinery with synthetic native access
// and a trusted instrumented prerequisites check. These tests do NOT certify
// production TLS/discovery/authorization, effective behavior or native enrollment.
func baselineStepFixture(t *testing.T, f *fixture) *lifecycleFixture {
	t.Helper()
	v := &lifecycleFixture{f: f, private: &fakePrivateSecrets{f: f, objects: map[string]*corev1.Secret{}}, opts: LifecycleOptions{Now: time.Now().UTC()}}
	secrets, err := NewSecretWorkflow(f.engine, v.private)
	if err != nil {
		t.Fatal("baseline step Secret workflow unavailable")
	}
	v.l, err = NewLifecycleWithChecks(f.engine, secrets, v)
	if err != nil {
		t.Fatal("baseline step lifecycle unavailable")
	}
	return v
}

func TestBaselineLifecycleStepsOnlyOwnershipAndRestarts(t *testing.T) {
	f := newPreparingBaselineFixture(t)
	before := f.snapshot.Document()
	before.SecurityBaseline = nil
	before.Revision = 0
	for step := 0; step <= installbaseline.ResourceCount+1; step++ {
		v := baselineStepFixture(t, f)
		writes, previews := f.access.writes, f.access.dryRuns
		next, err := v.l.Step(t.Context(), f.snapshot, v.opts)
		if err != nil || next == nil || f.access.writes-writes > 1 || f.access.dryRuns-previews > 1 || next.Document().Pending != nil || !reflect.DeepEqual(v.checks, []Checkpoint{Prerequisites}) {
			t.Fatal("fresh baseline step bypassed prerequisites, changed runtime or emitted multiple effects", step, err)
		}
		d := next.Document()
		d.SecurityBaseline = nil
		d.Revision = 0
		if !reflect.DeepEqual(before, d) {
			t.Fatal("baseline ownership step advanced runtime lifecycle or inventory")
		}
		f.snapshot = next
		f.snapshot = reloadBaselineFixture(t, f) // No in-memory ACK survives.
	}
	if f.access.writes != installbaseline.ResourceCount || f.access.dryRuns != installbaseline.ResourceCount || f.snapshot.Document().SecurityBaseline.Stage != installstate.BaselineVerified {
		t.Fatal("finite fresh Step loop did not establish exactly twelve original baseline resources")
	}
	// Advancing the ordinary journal to Applying is nonexecuting. Ownership
	// alone still must not authorize even the first prerequisite/runtime effect.
	v := baselineStepFixture(t, f)
	updates := f.nsUpdates
	next, err := v.l.Step(t.Context(), f.snapshot, v.opts)
	if err != nil || next == nil || next.Document().Stage != installstate.Applying || f.nsUpdates != updates+1 || f.access.writes != installbaseline.ResourceCount || f.access.dryRuns != installbaseline.ResourceCount || !reflect.DeepEqual(next.Document().Resources, f.snapshot.Document().Resources) || !reflect.DeepEqual(next.Document().SecurityBaseline, f.snapshot.Document().SecurityBaseline) {
		t.Fatal("ownership completion advanced more than the ordinary nonexecuting stage")
	}
	f.snapshot = next
	f.snapshot = reloadBaselineFixture(t, f)
	v = baselineStepFixture(t, f)
	original := f.snapshot.Bytes()
	updates = f.nsUpdates
	_, err = v.l.Step(t.Context(), f.snapshot, v.opts)
	closed, readErr := f.store.Load(t.Context(), f.snapshot.Anchor())
	if err == nil || readErr != nil || f.nsUpdates != updates || closed == nil || closed.ResourceVersion() != f.snapshot.ResourceVersion() || !bytes.Equal(original, closed.Bytes()) || f.access.writes != installbaseline.ResourceCount || f.access.dryRuns != installbaseline.ResourceCount || f.engine.baseline.runtimeGuard != nil {
		t.Fatal("ownership-only fixture acquired ordinary runtime authority")
	}
}

func TestBaselineLifecycleFreshOwnershipExcludesHistoricalAndRuntimeContexts(t *testing.T) {
	for _, scenario := range []string{"absent-baseline", "non-namespace-root", "uninstall"} {
		t.Run(scenario, func(t *testing.T) {
			f := newPreparingBaselineFixture(t)
			d := f.snapshot.Document()
			switch scenario {
			case "absent-baseline":
				d.SecurityBaseline = nil
			case "non-namespace-root":
				for _, metadata := range f.plan.ResourceMetadata() {
					if metadata.Kind == "CustomResourceDefinition" {
						key := installstate.Key{APIVersion: metadata.APIVersion, Kind: metadata.Kind, Name: metadata.Name}
						template, err := f.engine.contracts[f.plan.Digest()].Template(key, false)
						if err != nil {
							t.Fatal("signed excluded root fixture unavailable")
						}
						d.Resources = append(d.Resources, installstate.Resource{Key: key, UID: "preexisting-root", TemplateSHA256: template.Hash(), Phase: template.Phase(), Retained: template.Retained()})
						break
					}
				}
			case "uninstall":
				d.Mode, d.ActivePackage, d.Installed = installstate.Uninstall, f.plan.Digest(), true
			}
			// Deliberately synthetic schema-valid initial state, never enrollment
			// evidence. Refusal must happen before a proof/check/effect is attempted.
			f.snapshot = prerequisiteSnapshotFixture(t, f, d)
			v := baselineStepFixture(t, f)
			writes, updates := f.access.writes, f.nsUpdates
			next, err := v.l.Step(t.Context(), f.snapshot, v.opts)
			if err != ErrSecurityBaseline || next == nil || !bytes.Equal(next.Bytes(), f.snapshot.Bytes()) || f.access.writes != writes || f.nsUpdates != updates || f.access.dryRuns != 0 || len(v.checks) != 0 {
				t.Fatal("fresh ownership admitted historical or nonempty runtime context", scenario, err)
			}
		})
	}
}

func TestBaselineLifecyclePrerequisitesRefuseBeforeOwnershipEffect(t *testing.T) {
	f := newBaselineFixture(t)
	v := baselineStepFixture(t, f)
	v.fail = Prerequisites
	writes, updates := f.access.writes, f.nsUpdates
	next, err := v.l.Step(t.Context(), f.snapshot, v.opts)
	if err == nil || next == nil || !bytes.Equal(next.Bytes(), f.snapshot.Bytes()) || f.access.writes != writes || f.nsUpdates != updates || f.access.dryRuns != 0 {
		t.Fatal("denied baseline prerequisites emitted preview/effect/intent")
	}
}

func TestBaselineLifecyclePendingRecoveryNeverReplaysCreate(t *testing.T) {
	for _, scenario := range []string{"acknowledged", "empty-ack", "copied-nonce"} {
		t.Run(scenario, func(t *testing.T) {
			f := newBaselineFixture(t)
			f.access.write = func(_ installstate.Action, key installstate.Key, candidate *unstructured.Unstructured) (*unstructured.Unstructured, error) {
				live := candidate.DeepCopy()
				live.SetUID("original-baseline-ack")
				live.SetResourceVersion("101")
				f.access.objects[key] = live.DeepCopy()
				if scenario == "empty-ack" {
					return nil, nil
				}
				ack := live.DeepCopy()
				ack.SetName("malformed-ack") // UID becomes durable before shape acceptance.
				return ack, nil
			}
			v := baselineStepFixture(t, f)
			next, err := v.l.Step(t.Context(), f.snapshot, v.opts)
			if err != ErrOutcomeUnknown || next == nil || next.Document().SecurityBaseline.Pending == nil || next.Document().Pending != nil || f.access.writes != 1 || f.access.dryRuns != 1 {
				t.Fatal("baseline CREATE uncertainty lost its separate intent", err)
			}
			f.snapshot = next
			f.snapshot = reloadBaselineFixture(t, f)
			pending := f.snapshot.Document().SecurityBaseline.Pending
			if scenario == "copied-nonce" {
				f.access.objects[pending.Key].SetUID("foreign-copied-nonce")
			}
			f.access.write = nil
			v = baselineStepFixture(t, f)
			updates := f.nsUpdates
			next, err = v.l.Step(t.Context(), f.snapshot, v.opts)
			if f.access.writes != 1 || f.access.dryRuns != 1 || next == nil || next.Document().Pending != nil || !reflect.DeepEqual(v.checks, []Checkpoint{Prerequisites}) {
				t.Fatal("baseline recovery replayed preview/CREATE or entered ordinary pending recovery")
			}
			if scenario == "acknowledged" {
				if err != nil || next.Document().SecurityBaseline.Pending != nil || len(next.Document().SecurityBaseline.Resources) != 1 || next.Document().SecurityBaseline.Resources[0].UID != "original-baseline-ack" || f.nsUpdates != updates+1 {
					t.Fatal("baseline Step did not settle its durable original ACK exactly once", err)
				}
			} else if err != ErrOutcomeUnknown || next.Document().SecurityBaseline.Pending == nil || f.nsUpdates != updates || !bytes.Equal(next.Bytes(), f.snapshot.Bytes()) {
				t.Fatal("baseline recovery adopted an empty ACK or copied public nonce", err)
			}
		})
	}
}
