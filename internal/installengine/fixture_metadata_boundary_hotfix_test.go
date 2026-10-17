// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installrender"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
)

// Regression for the pre-baseline installer hotfix. These are deterministic
// shape checks, not a reproduction or attribution of any historical CI refusal.
func TestPrebaselineHotfixIndependentMetadataTimes(t *testing.T) {
	created := time.Date(2026, 10, 17, 22, 0, 0, 0, time.UTC)
	observed := created.Add(time.Minute)
	for _, profile := range []string{installrender.Profile135, installrender.Profile137} {
		for _, recipe := range []string{fixtureRecipeV1, fixtureRecipeV2} {
			t.Run(profile+"/"+recipe, func(t *testing.T) {
				f := newFixtureWithPlans(t, false, fixturePlanProfile(t, "isolated-install", profile))
				ledger, err := f.engine.prepareFixtureLedger(t.Context(), f.snapshot)
				if err != nil {
					t.Fatal("original ledger unavailable")
				}
				defer ledger.close()
				if recipe == fixtureRecipeV2 {
					instrumentFreshFixtureRecipeV2(t, ledger)
				}
				for slot := range fixtureCatalogFor(ledger.document) {
					for _, phase := range []fixtureResultPhase{fixtureDryRunResult, fixtureAcknowledgedResult, fixtureStableResult} {
						if phase == fixtureAcknowledgedResult {
							acknowledgeRecipeFixture(t, ledger, slot, types.UID(fmt.Sprintf("a0000000-0000-4000-8000-%012x", slot+1)))
						}
						original := fixtureResultExample(t, ledger, slot, phase, created)
						before := bytes.Clone(ledger.body)
						for _, stamp := range []time.Time{created.Add(-time.Second), created, created.Add(time.Second)} {
							candidate := original.DeepCopy()
							candidate.Object["metadata"].(map[string]any)["managedFields"].([]any)[0].(map[string]any)["time"] = stamp.Format(time.RFC3339)
							if ledger.validateResult(slot, phase, candidate, observed) != nil {
								t.Fatalf("independent finite metadata times refused slot%d phase%d", slot, phase)
							}
						}
						for _, stamp := range []any{nil, "0001-01-01T00:00:00Z", "0000-01-01T00:00:00Z", "10000-01-01T00:00:00Z", "not-a-time", created.Format(time.RFC3339) + ".bad", observed.Add(2 * time.Second).Format(time.RFC3339)} {
							candidate := original.DeepCopy()
							candidate.Object["metadata"].(map[string]any)["managedFields"].([]any)[0].(map[string]any)["time"] = stamp
							if ledger.validateResult(slot, phase, candidate, observed) != ErrFixtures {
								t.Fatal("invalid managed-field timestamp accepted")
							}
						}
						if !bytes.Equal(before, ledger.body) || f.access.writes != 0 || f.nsUpdates != 0 {
							t.Fatal("metadata validation mutated ownership or cluster state")
						}
					}
				}
			})
		}
	}
}

func TestPrebaselineHotfixMarkerOriginalCreationBoundary(t *testing.T) {
	created := time.Date(2026, 10, 17, 22, 0, 0, 0, time.UTC)
	observed := created.Add(time.Minute)
	for _, profile := range []string{installrender.Profile135, installrender.Profile137} {
		for _, recipe := range []string{fixtureRecipeV1, fixtureRecipeV2} {
			t.Run(profile+"/"+recipe, func(t *testing.T) {
				f := newFixtureWithPlans(t, false, fixturePlanProfile(t, "isolated-install", profile))
				ledger, err := f.engine.prepareFixtureLedger(t.Context(), f.snapshot)
				if err != nil {
					t.Fatal("original ledger unavailable")
				}
				defer ledger.close()
				if recipe == fixtureRecipeV2 {
					instrumentFreshFixtureRecipeV2(t, ledger)
				}
				acknowledgeAllRecipeFixtures(t, ledger)
				phase := &fixturePhaseBaseline{}
				before := fixtureResultExample(t, ledger, fixtureRetainedPVC, fixtureStableResult, created)
				role := func(o *unstructured.Unstructured, status bool) map[string]any {
					t.Helper()
					for _, raw := range o.Object["metadata"].(map[string]any)["managedFields"].([]any) {
						field := raw.(map[string]any)
						if (field["subresource"] == "status") == status {
							return field
						}
					}
					t.Fatal("fixed managed-field role unavailable")
					return nil
				}
				old := created.Add(-time.Second)
				role(before, false)["time"] = old.Format(time.RFC3339)
				if ledger.validateResult(fixtureRetainedPVC, fixtureStableResult, before, observed) != nil || ledger.validatePhaseFixture(fixtureRetainedPVC, before, phase, observed) != nil {
					t.Fatal("creation-boundary original failed independent whole validation")
				}
				body, savedBefore := bytes.Clone(ledger.body), before.DeepCopy()
				candidate := func(stamp time.Time) *unstructured.Unstructured {
					after := fixtureMarkedRetainedExample(t, ledger, created)
					after.SetResourceVersion(before.GetResourceVersion())
					main, status := role(after, false), role(after, true)
					main["time"] = stamp.Format(time.RFC3339)
					fields := []any{main, status}
					if stamp.After(created.Add(10 * time.Second)) {
						fields = []any{status, main}
					}
					after.Object["metadata"].(map[string]any)["managedFields"] = fields
					return after
				}
				for _, stamp := range []time.Time{old, created, created.Add(20 * time.Second)} {
					after := candidate(stamp)
					savedAfter := after.DeepCopy()
					if ledger.validateRetainedMarkerDryRunAdd(before, after, phase, observed) != nil || !reflect.DeepEqual(savedAfter, after) {
						t.Fatal("valid marker delta refused or changed its input")
					}
				}
				if ledger.validateRetainedMarkerDryRunAdd(before, candidate(old.Add(-time.Second)), phase, observed) != ErrFixtures {
					t.Fatal("marker main-record timestamp regression admitted")
				}
				badBefore, badAfter := before.DeepCopy(), candidate(created)
				for _, o := range []*unstructured.Unstructured{badBefore, badAfter} {
					main, status := role(o, false), role(o, true)
					main["time"], status["time"] = old.Add(-time.Second).Format(time.RFC3339), old.Format(time.RFC3339)
					o.Object["metadata"].(map[string]any)["managedFields"] = []any{main, status}
				}
				// Both replies keep equal status, legal ordering and nonregressing
				// main time. Only the marker's status creation floor rejects them.
				if ledger.validateResult(fixtureRetainedPVC, fixtureStableResult, badBefore, observed) != nil || ledger.validateRetainedMarkerDryRunAdd(badBefore, badAfter, phase, observed) != ErrFixtures {
					t.Fatal("marker status creation floor weakened")
				}
				if !bytes.Equal(body, ledger.body) || !reflect.DeepEqual(savedBefore, before) || f.access.writes != 0 || f.nsUpdates != 0 {
					t.Fatal("marker validation mutated ownership, inputs or cluster state")
				}
				// Removal still needs an acknowledged persistent marker. Do not
				// broaden its independent creation floor to match a dry-run shape.
				if ledger.advance(fixtureMarkerIntent(t, ledger)) != nil {
					t.Fatal("abstract marker intent unavailable")
				}
				ledger.markerEffect = false // Abstract fixture, never a native ACK.
				if ledger.advance(fixtureMarkerAcknowledgement(t, ledger)) != nil {
					t.Fatal("abstract marker acknowledgement unavailable")
				}
				marked := fixtureMarkedRetainedExample(t, ledger, created)
				unmarked := fixtureResultExample(t, ledger, fixtureRetainedPVC, fixtureStableResult, created)
				unmarked.SetResourceVersion(marked.GetResourceVersion())
				for _, o := range []*unstructured.Unstructured{marked, unmarked} {
					main, status := role(o, false), role(o, true)
					main["time"] = created.Format(time.RFC3339)
					o.Object["metadata"].(map[string]any)["managedFields"] = []any{main, status}
				}
				body, identity, revision := bytes.Clone(ledger.body), ledger.identity, ledger.document.Revision
				ack, effect := ledger.markerAck, ledger.markerEffect
				savedMarked, savedUnmarked := marked.DeepCopy(), unmarked.DeepCopy()
				if ledger.validateRetainedMarkerDryRunRemove(marked, unmarked, phase, observed) != nil {
					t.Fatal("acknowledged marker removal at creation boundary refused")
				}
				if !reflect.DeepEqual(savedMarked, marked) || !reflect.DeepEqual(savedUnmarked, unmarked) {
					t.Fatal("marker removal changed its inputs")
				}
				role(marked, false)["time"], role(unmarked, false)["time"] = old.Format(time.RFC3339), old.Format(time.RFC3339)
				if ledger.validateRetainedMarkerDryRunRemove(marked, unmarked, phase, observed) != ErrFixtures {
					t.Fatal("persistent marked-before creation floor weakened")
				}
				if !bytes.Equal(body, ledger.body) || ledger.identity != identity || ledger.document.Revision != revision || ledger.markerAck != ack || ledger.markerEffect != effect || f.access.writes != 0 || f.nsUpdates != 0 {
					t.Fatal("marker removal changed ownership, receipt capability or cluster state")
				}
			})
		}
	}
}
