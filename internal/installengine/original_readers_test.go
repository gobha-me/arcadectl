// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"sync/atomic"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installstate"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Trusted instrumentation of a refusing guard, NOT native admission or an
// owned activation session. Extracted readers must never become effect gates.
func TestOriginalJournalReaderDoesNotSupplyRuntimeAuthority(t *testing.T) {
	f := newBaselineFixture(t)
	completeBaselineFixture(t, f)
	guard := &baselineParentRefusingRuntimeGuard{}
	f.engine.baseline.runtimeGuard = guard
	writes, dryRuns, updates := f.access.writes, f.access.dryRuns, f.nsUpdates
	fresh, err := f.engine.currentOriginal(t.Context(), f.snapshot)
	if err != nil || fresh == nil || fresh.Anchor() != f.snapshot.Anchor() || fresh.ResourceVersion() != f.snapshot.ResourceVersion() || !bytes.Equal(fresh.Bytes(), f.snapshot.Bytes()) || guard.calls.Load() != 0 {
		t.Fatal("exact original journal reader changed identity or acquired runtime authority")
	}
	if current, err := f.engine.current(t.Context(), f.snapshot); current != nil || err != ErrSecurityBaseline || guard.calls.Load() != 1 {
		t.Fatal("ordinary current lost its independent complete runtime guard")
	}
	if _, err := f.engine.Apply(t.Context(), f.snapshot, f.key, f.plan.Digest(), false); err != ErrSecurityBaseline || guard.calls.Load() != 2 {
		t.Fatal("original reader supplied ordinary runtime effect authority")
	}
	if f.access.writes != writes || f.access.dryRuns != dryRuns || f.nsUpdates != updates {
		t.Fatal("refused runtime authority changed cluster or journal")
	}
}

func TestOriginalServingReaderMatchesGuardedWholeFingerprint(t *testing.T) {
	x := newServingFixture(t)
	before, err := x.f.engine.ObserveServing(t.Context(), x.f.snapshot, x.access)
	if err != nil {
		t.Fatal("original guarded serving control unavailable")
	}
	read, err := x.f.engine.readOriginalServing(t.Context(), x.f.snapshot, x.access, false)
	if err != nil || read == nil || *read != *before {
		t.Fatal("extracted whole serving reader changed exact original fingerprint")
	}
	// Deliberately incomplete baseline: raw reader data is not permission to
	// consume an independently guarded public observer or authentication path.
	x.f.engine.baseline = &baselineWorkflow{engine: x.f.engine}
	if serving, err := x.f.engine.ObserveServing(t.Context(), x.f.snapshot, x.access); serving != nil || err != ErrServing {
		t.Fatal("raw serving data bypassed absent complete baseline authority")
	}
	if read, err := x.f.engine.readOriginalServing(nil, x.f.snapshot, x.access, false); read != nil || err != ErrServing {
		t.Fatal("raw serving reader accepted missing observation context")
	}
}

type servingClosingRuntimeGuard struct{ calls atomic.Int32 }

func (g *servingClosingRuntimeGuard) Verify(context.Context, *installstate.Snapshot) error {
	if g.calls.Add(1) == 1 {
		return nil // Trusted counting instrumentation only, not effective health.
	}
	return ErrSecurityBaseline
}

func TestOriginalServingExtractionPreservesClosingRuntimeGuard(t *testing.T) {
	x := newServingFixture(t)
	baseline := newBaselineFixtureWithPlans(t, x.f.plan)
	completeBaselineFixture(t, baseline)
	// Explicitly synthetic Verifying inventory. Original baseline ownership is
	// copied only to exercise wrapper guard ordering, never to claim enrollment,
	// policy enforcement or a native serving/activation proof.
	d := x.f.snapshot.Document()
	d.SecurityBaseline = baseline.snapshot.Document().SecurityBaseline
	d.Revision++
	plan := baseline.engine.baselinePlan()
	body, err := installstate.EncodeWithBaseline(d, plan, x.f.plan)
	if err != nil {
		t.Fatal("synthetic baseline-aware serving journal unavailable")
	}
	namespace, err := x.f.access.client.CoreV1().Namespaces().Get(t.Context(), d.Namespace, metav1.GetOptions{})
	if err != nil {
		t.Fatal("original serving namespace unavailable")
	}
	namespace.Annotations[installstate.Annotation] = string(body)
	if x.f.access.client.Tracker().Update(corev1.SchemeGroupVersion.WithResource("namespaces"), namespace, "") != nil {
		t.Fatal("synthetic serving journal seed refused")
	}
	store, err := installstate.NewWithBaseline(x.f.access.client.CoreV1().Namespaces(), plan, x.f.plan)
	if err != nil {
		t.Fatal("baseline-aware serving store unavailable")
	}
	engine, err := NewWithBaselineAccess(x.f.access, store, x.f.engine.files, plan, x.f.plan)
	if err != nil {
		t.Fatal("baseline-aware serving engine unavailable")
	}
	snapshot, err := store.Load(t.Context(), x.f.snapshot.Anchor())
	if err != nil {
		t.Fatal("original sealed serving journal unavailable")
	}
	guard := &servingClosingRuntimeGuard{}
	engine.baseline.runtimeGuard = guard
	writes, dryRuns, updates := x.f.access.writes, x.f.access.dryRuns, x.f.nsUpdates
	serving, err := engine.ObserveServing(t.Context(), snapshot, x.access)
	if serving != nil || err != ErrServing || guard.calls.Load() != 2 {
		t.Fatal("serving escaped after opening success and closing runtime refusal")
	}
	if x.f.access.writes != writes || x.f.access.dryRuns != dryRuns || x.f.nsUpdates != updates {
		t.Fatal("closing serving refusal changed cluster or journal")
	}
}

func TestOriginalCredentialBindingReaderDoesNotAuthorizeAuthentication(t *testing.T) {
	x := newServingFixture(t)
	guarded, err := x.activation.binding(t.Context(), x.f.snapshot, x.options)
	if err != nil {
		t.Fatal("original guarded credential binding unavailable")
	}
	_, caID, err := privatefs.ReadAbsolute(x.options.CAFile, 65536, privatefs.TrustedPublic)
	if err != nil {
		t.Fatal("original public CA identity unavailable")
	}
	read, err := x.activation.bindOriginalCredentials(x.secrets.objects, caID, x.options)
	if err != nil || read != guarded {
		t.Fatal("extracted original credential validation changed exact binding")
	}
	requests := activationServer(t, x, x.f.plan.Namespace(), nil)
	x.f.engine.baseline = &baselineWorkflow{engine: x.f.engine}
	if _, err := x.activation.binding(t.Context(), x.f.snapshot, x.options); err != ErrActivation {
		t.Fatal("unguarded original byte validation bypassed retained-read authority")
	}
	if x.activation.VerifyDirect(t.Context(), x.f.snapshot, x.options) != ErrActivation || requests.Load() != 0 {
		t.Fatal("raw credential binding authorized token transmission")
	}
	if _, err := x.activation.bindOriginalCredentials(nil, caID, x.options); err != ErrActivation {
		t.Fatal("original credential validator accepted absent retained Secret evidence")
	}
}
