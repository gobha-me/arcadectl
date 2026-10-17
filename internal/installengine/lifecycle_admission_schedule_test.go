// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// Independent original ordered-loop oracle: no scheduling helper under test.
func originalNextApplyKey(t *testing.T, v *lifecycleFixture, d installstate.Document) (installstate.Key, bool) {
	t.Helper()
	for _, key := range v.l.ordered(d) {
		want, err := v.f.engine.contracts[d.TargetPackage].Template(key, false)
		if err != nil {
			t.Fatal("signed target unavailable")
		}
		entry, _ := v.f.engine.inventory(d, key)
		if entry == nil || entry.TemplateSHA256 != want.Hash() {
			return key, true
		}
	}
	return installstate.Key{}, false
}

func admissionScheduleTransition(t *testing.T, mode installstate.Mode) (*lifecycleFixture, *installstate.Snapshot) {
	t.Helper()
	previous, target := lifecycleTransitionPlans(t)
	v := newLifecycleFixturePlans(t, previous, target)
	s := v.finish(t, v.f.snapshot)
	requested := target
	if mode == installstate.Rollback {
		upgrading, err := v.l.Begin(context.Background(), s, installstate.Upgrade, target.Digest(), v.opts)
		if err != nil {
			t.Fatal("genuine source could not begin preceding upgrade")
		}
		s = v.finish(t, upgrading)
		requested = previous
	}
	s, err := v.l.Begin(context.Background(), s, mode, requested.Digest(), v.opts)
	if err != nil {
		t.Fatal("genuine completed source did not begin transition")
	}
	return v, s
}

func TestLifecycleApplyingOneFreshAdmissionMatrixPerStep(t *testing.T) {
	for _, mode := range []installstate.Mode{installstate.Upgrade, installstate.Rollback} {
		t.Run(string(mode), func(t *testing.T) {
			v, s := admissionScheduleTransition(t, mode)
			applying, fullForStep := false, false
			v.probe = func(request LifecycleCheck) error {
				if request.Checkpoint == AdmissionEffective {
					fullForStep = true
				}
				return nil
			}
			v.f.nsUpdate = func(*corev1.Namespace) error {
				if applying && !fullForStep {
					t.Fatal("application journal intent/stage changed before its new full matrix")
				}
				return nil
			}
			qualified, noAction := 0, false
			for step := 0; step < 100 && s.Document().Stage != installstate.Complete; step++ {
				before := s.Document()
				applying, fullForStep = before.Stage == installstate.Applying && before.Pending == nil, false
				key, selected := originalNextApplyKey(t, v, before)
				// A new coordinator on EVERY Step must still owe a new matrix.
				l, err := NewLifecycleWithChecks(v.f.engine, v.l.secrets, v)
				if err != nil {
					t.Fatal(err)
				}
				v.l, v.checks = l, nil
				s = v.step(t, s)
				if before.Stage != installstate.Applying || before.Pending != nil {
					continue
				}
				full, fullIndex := 0, -1
				for index, checkpoint := range v.checks {
					if checkpoint == AdmissionEffective {
						full++
						fullIndex = index
					}
				}
				if full != 1 {
					t.Fatalf("application Step ran %d full matrices, want exactly one", full)
				}
				if selected && installRank(key) >= 3 {
					qualified++
					for _, checkpoint := range []Checkpoint{ColdSafety, CRDsAvailable} {
						index := slices.Index(v.checks, checkpoint)
						if index < 0 || index >= fullIndex {
							t.Fatal("fresh full matrix did not follow observational safety gates")
						}
					}
					if index := slices.Index(v.checks, APIStopped); index >= fullIndex {
						t.Fatal("API absence was checked after the final full matrix")
					}
				} else {
					if fullIndex >= slices.Index(v.checks, ColdSafety) {
						t.Fatal("lower-rank/no-action path lost its entry matrix")
					}
					noAction = noAction || !selected
				}
			}
			if s.Document().Stage != installstate.Complete || qualified < 2 || !noAction {
				t.Fatal("did not exercise successive qualified Steps and the no-action transition")
			}
		})
	}
}

func TestLifecycleApplySelectionMatchesOriginalAndDoesNotMutate(t *testing.T) {
	previous, target := lifecycleTransitionPlans(t)
	v := newLifecycleFixturePlans(t, previous, target)
	s := v.finish(t, v.f.snapshot)
	d := s.Document()
	d.TargetPackage = target.Digest()
	// Pure selection fixture, not ownership evidence: make all other signed
	// targets current so removing each individual row exercises every rank.
	for _, key := range v.l.ordered(d) {
		want, err := v.f.engine.contracts[d.TargetPackage].Template(key, false)
		if err != nil {
			t.Fatal(err)
		}
		index := slices.IndexFunc(d.Resources, func(r installstate.Resource) bool { return r.Key == key })
		if index >= 0 {
			d.Resources[index].TemplateSHA256 = want.Hash()
		} else {
			d.Resources = append(d.Resources, installstate.Resource{Key: key, TemplateSHA256: want.Hash()})
		}
	}
	journalBefore := s.Bytes()
	ranks := map[int]bool{}
	for _, key := range v.l.ordered(d) {
		candidate := d
		candidate.Resources = slices.DeleteFunc(slices.Clone(d.Resources), func(r installstate.Resource) bool { return r.Key == key })
		wantKey, wantFound := originalNextApplyKey(t, v, candidate)
		if !wantFound || wantKey != key {
			t.Fatal("selection fixture did not isolate the chosen target")
		}
		resourcesBefore := slices.Clone(candidate.Resources)
		writes, dryRuns, journalWrites := v.f.access.writes+v.private.writes, v.f.access.dryRuns, v.f.nsUpdates
		got, found, err := v.l.nextApplySelection(candidate)
		if err != nil || found != wantFound || found && (got.key != wantKey || got.rank != installRank(wantKey)) {
			t.Fatal("pure selection differs from original ordered/hash predicate")
		}
		if v.f.access.writes+v.private.writes != writes || v.f.access.dryRuns != dryRuns || v.f.nsUpdates != journalWrites || !bytes.Equal(s.Bytes(), journalBefore) || !slices.Equal(candidate.Resources, resourcesBefore) {
			t.Fatal("selection performed an effect")
		}
		ranks[got.rank] = true
	}
	if len(ranks) != 6 {
		t.Fatal("pure selection did not exercise every dependency rank")
	}
}

func admissionScheduleHighRank(t *testing.T) (*lifecycleFixture, *installstate.Snapshot) {
	t.Helper()
	v, s := admissionScheduleTransition(t, installstate.Upgrade)
	for step := 0; step < 100 && s.Document().Stage != installstate.Complete; step++ {
		if s.Document().Stage == installstate.Applying && s.Document().Pending == nil {
			key, selected := originalNextApplyKey(t, v, s.Document())
			if selected && installRank(key) >= 3 {
				return v, s
			}
		}
		s = v.step(t, s)
	}
	t.Fatal("no high-rank application Step available")
	return nil, nil
}

func TestLifecycleDeferredAdmissionRefusalsHaveNoEffect(t *testing.T) {
	for _, gate := range []Checkpoint{ColdSafety, APIStopped, CRDsAvailable, AdmissionEffective} {
		t.Run(fmt.Sprint(gate), func(t *testing.T) {
			v, s := admissionScheduleHighRank(t)
			v.fail, v.checks = gate, nil
			writes, dryRuns, journalWrites := v.f.access.writes+v.private.writes, v.f.access.dryRuns, v.f.nsUpdates
			next, err := v.l.Step(context.Background(), s, v.opts)
			if !errors.Is(err, ErrLifecycle) || !slices.Contains(v.checks, gate) || !next.SameJournalBytes(s) ||
				v.f.access.writes+v.private.writes != writes || v.f.access.dryRuns != dryRuns || v.f.nsUpdates != journalWrites {
				t.Fatal("deferred/final gate refusal changed target intent, journal, Secret or resource")
			}
			if gate != AdmissionEffective && slices.Contains(v.checks, AdmissionEffective) {
				t.Fatal("refused observational gate unnecessarily ran the full matrix")
			}
		})
	}
}

func TestLifecycleDeferredAdmissionSeesLateRefusal(t *testing.T) {
	for _, earlier := range []Checkpoint{ColdSafety, APIStopped, CRDsAvailable} {
		t.Run(fmt.Sprint(earlier), func(t *testing.T) {
			v, s := admissionScheduleHighRank(t)
			changed, checked := false, false
			v.probe = func(request LifecycleCheck) error {
				if request.Checkpoint == earlier {
					changed = true // Strict trusted provider observes subsequent drift.
				}
				if request.Checkpoint == AdmissionEffective {
					checked = true
					if changed {
						return ErrAdmission
					}
				}
				return nil
			}
			writes, dryRuns, journalWrites := v.f.access.writes+v.private.writes, v.f.access.dryRuns, v.f.nsUpdates
			next, err := v.l.Step(context.Background(), s, v.opts)
			if !changed || !checked || !errors.Is(err, ErrLifecycle) || !next.SameJournalBytes(s) ||
				v.f.access.writes+v.private.writes != writes || v.f.access.dryRuns != dryRuns || v.f.nsUpdates != journalWrites {
				t.Fatal("late full provider refusal was bypassed before a target effect")
			}
		})
	}
}

func TestLifecycleApplyingKeepsEntryAdmissionForLowerRanksAndInvalidSelection(t *testing.T) {
	for _, rank := range []int{0, 1, 2, -1, -2} {
		t.Run(fmt.Sprint(rank), func(t *testing.T) {
			v, s := admissionScheduleHighRank(t)
			d := s.Document()
			var missing installstate.Key
			// Explicit scheduling-only fixture: all signed target hashes are
			// current except one lower-rank row. This is NOT live ownership
			// evidence, and the trusted provider must refuse at its first gate.
			for _, key := range v.l.ordered(d) {
				template, err := v.f.engine.contracts[d.TargetPackage].Template(key, false)
				if err != nil {
					t.Fatal(err)
				}
				index := slices.IndexFunc(d.Resources, func(r installstate.Resource) bool { return r.Key == key })
				if index >= 0 {
					d.Resources[index].TemplateSHA256 = template.Hash()
				} else {
					d.Resources = append(d.Resources, installstate.Resource{Key: key, UID: "selection-only", TemplateSHA256: template.Hash(), Phase: template.Phase(), Retained: template.Retained()})
				}
				if rank >= 0 && installRank(key) == rank && missing.Kind == "" {
					missing = key
				}
			}
			if rank >= 0 {
				if missing.Kind == "" {
					t.Fatal("required lower rank absent")
				}
				d.Resources = slices.DeleteFunc(d.Resources, func(r installstate.Resource) bool { return r.Key == missing })
			}
			installstate.SortResources(d.Resources)
			plans := []*installrender.Plan{v.f.plan, v.f.engine.plans[d.TargetPackage]}
			body, err := installstate.Encode(d, plans...)
			if err != nil {
				t.Fatal(err)
			}
			ns, err := v.f.access.client.CoreV1().Namespaces().Get(context.Background(), d.Namespace, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			ns.Annotations[installstate.Annotation] = string(body)
			if err := v.f.access.client.Tracker().Update(schema.GroupVersionResource{Version: "v1", Resource: "namespaces"}, ns, ""); err != nil {
				t.Fatal(err)
			}
			s, err = v.f.store.Load(context.Background(), s.Anchor())
			if err != nil {
				t.Fatal(err)
			}
			if rank == -2 {
				v.f.engine.contracts[d.TargetPackage] = nil // Pure selection error.
			}
			v.fail, v.checks = AdmissionEffective, nil
			writes, dryRuns, journalWrites := v.f.access.writes+v.private.writes, v.f.access.dryRuns, v.f.nsUpdates
			next, err := v.l.applyOwned(context.Background(), s, v.opts, nil)
			if !errors.Is(err, ErrLifecycle) || len(v.checks) != 1 || v.checks[0] != AdmissionEffective || !next.SameJournalBytes(s) ||
				v.f.access.writes+v.private.writes != writes || v.f.access.dryRuns != dryRuns || v.f.nsUpdates != journalWrites {
				t.Fatal("lower-rank/absent/invalid selection deferred its entry matrix or mutated")
			}
		})
	}
}

func TestLifecycleDeferredAdmissionCancellationHasNoEffect(t *testing.T) {
	v, s := admissionScheduleHighRank(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reached := false
	v.checks = nil
	v.probe = func(request LifecycleCheck) error {
		if request.Checkpoint == ColdSafety {
			reached = true
			cancel()
		}
		return nil
	}
	writes, dryRuns, journalWrites := v.f.access.writes+v.private.writes, v.f.access.dryRuns, v.f.nsUpdates
	next, err := v.l.Step(ctx, s, v.opts)
	if !reached || err == nil || slices.Contains(v.checks, AdmissionEffective) || !next.SameJournalBytes(s) ||
		v.f.access.writes+v.private.writes != writes || v.f.access.dryRuns != dryRuns || v.f.nsUpdates != journalWrites {
		t.Fatal("cancelled observational gate proceeded to proof, intent or effect")
	}
}

func TestLifecycleDeferredAdmissionJournalChangeRejectsSelection(t *testing.T) {
	v, s := admissionScheduleHighRank(t)
	changed := false
	v.checks = nil
	v.probe = func(request LifecycleCheck) error {
		if request.Checkpoint == CRDsAvailable {
			ns, err := v.f.access.client.CoreV1().Namespaces().Get(context.Background(), s.Anchor().Namespace, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			rv, err := strconv.Atoi(ns.ResourceVersion)
			if err != nil {
				t.Fatal(err)
			}
			ns.ResourceVersion = strconv.Itoa(rv + 1)
			if err := v.f.access.client.Tracker().Update(schema.GroupVersionResource{Version: "v1", Resource: "namespaces"}, ns, ""); err != nil {
				t.Fatal(err)
			}
			changed = true // External namespace CAS, not a coordinator effect.
		}
		return nil
	}
	writes, dryRuns, journalWrites := v.f.access.writes+v.private.writes, v.f.access.dryRuns, v.f.nsUpdates
	_, err := v.l.Step(context.Background(), s, v.opts)
	if !changed || !errors.Is(err, ErrConcurrent) || slices.Contains(v.checks, AdmissionEffective) ||
		v.f.access.writes+v.private.writes != writes || v.f.access.dryRuns != dryRuns || v.f.nsUpdates != journalWrites {
		t.Fatal("late original-journal change authorized the locally selected target")
	}
}
