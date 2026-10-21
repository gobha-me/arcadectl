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

func TestFixtureV3AccountFirstBodyAndLastCleanup(t *testing.T) {
	for _, profile := range []string{installrender.Profile135, installrender.Profile137} {
		t.Run(profile, func(t *testing.T) {
			f := newFixtureWithPlans(t, false, fixturePlanProfile(t, "isolated-install", profile))
			ledger, err := f.engine.prepareFixtureLedgerV3(t.Context(), f.snapshot)
			if err != nil {
				t.Fatal(err)
			}
			defer ledger.close()
			if !reflect.DeepEqual(fixtureCreationOrder(ledger.document), []int{11, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}) || !reflect.DeepEqual(fixtureDeletionOrder(ledger.document), []int{10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 11}) {
				t.Fatal("v3 order changed")
			}
			before := bytes.Clone(ledger.body)
			for _, slot := range []int{0, 1, 2, 3, 4, 5, 6} {
				if _, err := ledger.object(slot); err != ErrFixtures {
					t.Fatal("workload constructed before original account ACK")
				}
			}
			next := cloneFixtureLedgerDocument(ledger.document)
			next.Revision++
			next.Entries[0].State = fixtureCreateAttempted
			if validFixtureTransition(ledger.document, next) {
				t.Fatal("workload intent preceded original account")
			}
			created := time.Date(2026, 10, 6, 10, 0, 0, 0, time.UTC)
			fixtureResultRefusals(t, ledger, fixtureTokenlessAccount, fixtureDryRunResult, fixtureResultExample(t, ledger, fixtureTokenlessAccount, fixtureDryRunResult, created), created.Add(time.Minute))
			if !bytes.Equal(before, ledger.body) || ledger.document.Entries[11].OriginalUID != "" {
				t.Fatal("dry-run gained ownership")
			}
			acknowledgeRecipeFixture(t, ledger, fixtureTokenlessAccount, "a0000000-0000-4000-8000-00000000000c")
			for _, phase := range []fixtureResultPhase{fixtureAcknowledgedResult, fixtureStableResult} {
				fixtureResultRefusals(t, ledger, fixtureTokenlessAccount, phase, fixtureResultExample(t, ledger, fixtureTokenlessAccount, phase, created), created.Add(time.Minute))
			}
			for _, slot := range fixtureCreationOrder(ledger.document)[1:] {
				o, err := ledger.object(slot)
				if err != nil {
					t.Fatal("ordered constructor refused", slot)
				}
				if o.GetKind() == "Job" || o.GetKind() == "Pod" {
					path := []string{"spec"}
					if o.GetKind() == "Job" {
						path = []string{"spec", "template", "spec"}
					}
					for _, alias := range []string{"serviceAccount", "serviceAccountName"} {
						name, present, err := unstructured.NestedString(o.Object, append(path, alias)...)
						if err != nil || !present || name != ledger.document.Entries[11].Key.Name {
							t.Fatal("workload account alias not original")
						}
					}
				}
				acknowledgeRecipeFixture(t, ledger, slot, types.UID(fmt.Sprintf("a0000000-0000-4000-8000-%012x", slot+1)))
			}
			next = cloneFixtureLedgerDocument(ledger.document)
			next.Revision++
			next.Entries[11].State, next.Entries[11].DeleteResourceVersion = fixtureDeleteAttempted, "101"
			if validFixtureTransition(ledger.document, next) || f.engine.validateFixtureLedger(next) != ErrFixtures {
				t.Fatal("account deleted before dependencies")
			}
			for _, slot := range fixtureDeletionOrder(ledger.document) {
				next = cloneFixtureLedgerDocument(ledger.document)
				next.Revision++
				next.Entries[slot].State, next.Entries[slot].DeleteResourceVersion = fixtureDeleteAttempted, "101"
				if ledger.advance(next) != nil {
					t.Fatal("ordered delete intent refused", slot)
				}
				next = cloneFixtureLedgerDocument(ledger.document)
				next.Revision++
				next.Entries[slot].State = fixtureAbsent
				if ledger.advance(next) != nil {
					t.Fatal("ordered absence refused", slot)
				}
			}
			if f.engine.validateFixtureLedger(ledger.document) != nil {
				t.Fatal("historical absent workloads require a live account")
			}
			if fixtureBehaviorRecipeVersion(ledger.document) != fixtureBehaviorVersionV3 {
				t.Fatal("v3 inherits historical receipt")
			}
		})
	}
}

func TestFixtureV3UnknownAccountAndPlannedCleanupRemainFenced(t *testing.T) {
	f := newFixture(t, false)
	ledger, err := f.engine.prepareFixtureLedgerV3(t.Context(), f.snapshot)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.close()
	next := cloneFixtureLedgerDocument(ledger.document)
	next.Revision++
	next.Entries[11].State = fixtureAbsent
	if validFixtureTransition(ledger.document, next) {
		t.Fatal("planned account retired ahead of other slots")
	}
	next.Entries[11].State = fixtureCreateAttempted
	if ledger.advance(next) != nil {
		t.Fatal("account intent refused")
	}
	if _, err := ledger.fixtureAccount("default"); err != ErrFixtures {
		t.Fatal("unknown account acquired workload authority")
	}
	for _, slot := range []int{0, 1, 2, 3, 4, 5, 6} {
		if _, err := ledger.object(slot); err != ErrFixtures {
			t.Fatal("unknown account permits workload")
		}
	}
}
