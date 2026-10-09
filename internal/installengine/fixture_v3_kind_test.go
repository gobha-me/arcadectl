//go:build kindinstall

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installbaseline"
	"github.com/gobha-me/arcadectl/internal/installcontract"
	"github.com/gobha-me/arcadectl/internal/installstate"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
)

type kindFixtureBaseline struct {
	plan     *installbaseline.Plan
	contract *installcontract.Contract
	uids     map[installstate.Key]types.UID
}

// Exact-owned isolated Kind only. No runtime-journal enrollment or installation
// authority is invented. Cluster teardown removes these exact test resources.
func installKindFixtureBaseline(t *testing.T, ctx context.Context, access *HTTPAccess, namespace, profile string) *kindFixtureBaseline {
	t.Helper()
	plan := baselineFixturePlan(t, namespace, profile, 'd')
	contract, err := installcontract.NewBaseline(plan)
	if err != nil {
		t.Fatal("standalone baseline contract unavailable")
	}
	fixture := &kindFixtureBaseline{plan: plan, contract: contract, uids: map[installstate.Key]types.UID{}}
	for _, resource := range plan.Resources() {
		object := resource.Object
		key := installstate.Key{APIVersion: object.GetAPIVersion(), Kind: object.GetKind(), Name: object.GetName()}
		template, err := contract.Template(key, false)
		if err != nil || template.Hash() != resource.TemplateSHA256 {
			t.Fatal("standalone baseline template identity changed")
		}
		candidate, err := template.Candidate(strings.Repeat("b", 32))
		if err != nil {
			t.Fatal("standalone baseline candidate unavailable")
		}
		preview, err := access.Create(ctx, key, candidate, true)
		if err != nil || template.MatchAdmitted(preview) != nil {
			t.Fatal("standalone baseline preview differs from reviewed shape")
		}
		ack, err := access.Create(ctx, key, candidate, false)
		if err != nil || ack == nil || !nativeFixtureUID(string(ack.GetUID())) || template.MatchLive(ack, ack.GetUID()) != nil {
			t.Fatal("standalone baseline original ACK unavailable")
		}
		fixture.uids[key] = ack.GetUID()
	}
	if wait.PollUntilContextTimeout(ctx, 200*time.Millisecond, 2*time.Minute, true, func(ctx context.Context) (bool, error) { return fixture.current(ctx, access) == nil, nil }) != nil {
		t.Fatal("actual baseline controller-manager typechecking did not converge")
	}
	return fixture
}

func (f *kindFixtureBaseline) current(ctx context.Context, access *HTTPAccess) error {
	if f == nil || f.plan == nil || f.contract == nil || len(f.uids) != installbaseline.ResourceCount {
		return ErrFixtures
	}
	for key, uid := range f.uids {
		template, err := f.contract.Template(key, false)
		live, readErr := access.Get(ctx, key)
		if err != nil || readErr != nil || live == nil || template.MatchLive(live, uid) != nil {
			return ErrFixtures
		}
		if key.Kind == "ValidatingAdmissionPolicy" {
			var typed admissionv1.ValidatingAdmissionPolicy
			if decodeServing(live, &typed) != nil || typed.Generation < 1 || typed.Status.ObservedGeneration != typed.Generation || typed.Status.TypeChecking == nil || len(typed.Status.TypeChecking.ExpressionWarnings) != 0 {
				return ErrFixtures
			}
		}
	}
	return nil
}

func newKindV3AdmissionDriver(t *testing.T, ctx context.Context, a *ClusterAdmission, request LifecycleCheck) *fixtureAdmissionDriver {
	t.Helper()
	initial, err := a.waitInitialPhase(ctx, request)
	if err != nil {
		t.Fatal("actual original initial phase unavailable")
	}
	first, err := a.collectPhaseServiceAccounts(ctx, request)
	if err != nil {
		t.Fatal("native complete initial account collection unavailable")
	}
	second, err := a.collectPhaseServiceAccounts(ctx, request)
	if err != nil || !samePhaseServiceAccounts(first, second) {
		t.Fatal("native initial account collection changed")
	}
	initial.baseline.Accounts, err = second.baseline(initial.baseline.Public, nil)
	if err != nil {
		t.Fatal("native original account floor unavailable")
	}
	actors, err := a.newActors(ctx, request, existingScopedImpersonation)
	if err != nil {
		t.Fatal("native original actor witnesses unavailable")
	}
	f, err := a.prerequisites.engine.prepareFixtureLedgerV3(ctx, request.Snapshot)
	if err != nil {
		t.Fatal("native fresh v3 ledger unavailable")
	}
	t.Cleanup(func() {
		if f.lock != nil {
			_ = f.close()
		}
	})
	if initial.seal(f) != nil {
		t.Fatal("native v3 phase seal unavailable")
	}
	w, err := actors.fixtures(ctx, f)
	if err != nil {
		t.Fatal("native original v3 wire unavailable")
	}
	f.wireMu.Lock()
	defer f.wireMu.Unlock()
	if !f.driverFresh || f.document.Recipe != fixtureRecipeV3 || !fixtureMatrixRecipe(f.document) || f.document.DestroySeed != nil || f.document.RetainedMarker != nil || f.document.Behavior != nil {
		t.Fatal("native fresh v3 run corrupted")
	}
	f.driverFresh = false
	return &fixtureAdmissionDriver{wire: w, initial: initial}
}
