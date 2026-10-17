// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/canonicaljson"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
)

// Test-only fresh-document instrumentation. Production cannot rewrite a run's
// recipe; the default producer remains v1. This performs no Kubernetes effect
// and proves neither native shapes nor full behavior completion.
func instrumentFreshFixtureRecipeV2(t *testing.T, f *fixtureLedger) {
	t.Helper()
	if f.document.Recipe != fixtureRecipeV1 || f.document.Revision != 1 || f.document.OriginalWorldsSHA256 != "" {
		t.Fatal("recipe instrumentation requires an untouched fresh document")
	}
	d := f.document
	d.Recipe = fixtureRecipeV2
	d.Entries = append(append([]fixtureEntry{}, d.Entries...), fixtureEntry{
		Key:   installstate.Key{APIVersion: "arcade.gobha.me/v1alpha1", Kind: "GameDestroy", Namespace: d.Entries[0].Key.Namespace, Name: "arcadectl-probe-" + d.RunID + "-verified-cancelled-destroy"},
		State: fixturePlanned,
	})
	body, err := f.engine.fixtureLedgerBody(d)
	if err != nil {
		t.Fatal("closed v2 schema unavailable", err)
	}
	id, err := f.engine.files.AtomicWrite(f.name, body, &f.identity)
	if err != nil {
		t.Fatal("test-only fresh v2 publication unavailable", err)
	}
	f.document, f.body, f.identity = d, body, id
}

func instrumentFreshFixtureRecipeV3(t *testing.T, f *fixtureLedger) {
	t.Helper()
	instrumentFreshFixtureRecipeV2(t, f)
	d := cloneFixtureLedgerDocument(f.document)
	d.Recipe = fixtureRecipeV3
	d.Entries = append(d.Entries, fixtureEntry{Key: installstate.Key{APIVersion: "v1", Kind: "ServiceAccount", Namespace: d.Entries[0].Key.Namespace, Name: "arcadectl-probe-" + d.RunID + "-tokenless-account"}, State: fixturePlanned})
	body, err := f.engine.fixtureLedgerBody(d)
	if err != nil {
		t.Fatal("v3 schema unavailable", err)
	}
	id, err := f.engine.files.AtomicWrite(f.name, body, &f.identity)
	if err != nil {
		t.Fatal("test-only fresh v3 publication unavailable", err)
	}
	f.document, f.body, f.identity = d, body, id
}

func TestFixtureRecipeVersionsAreClosedAndImmutable(t *testing.T) {
	f := newFixture(t, false)
	ledger, err := f.engine.prepareFixtureLedger(t.Context(), f.snapshot)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.close()
	legacy, body := ledger.document, bytes.Clone(ledger.body)
	wantCatalog := []fixtureRecipe{
		{"batch/v1", "Job", "backup-job", -1}, {"v1", "Pod", "backup-pod", 0},
		{"batch/v1", "Job", "restore-job", -1}, {"v1", "Pod", "restore-pod", 2},
		{"batch/v1", "Job", "destroy-job", -1}, {"v1", "Pod", "destroy-pod", 4},
		{"v1", "Pod", "plain-pod", -1}, {"v1", "PersistentVolumeClaim", "retained-pvc", -1},
		{"v1", "PersistentVolumeClaim", "plain-pvc", -1},
		{"arcade.gobha.me/v1alpha1", "GameDestroy", "cancelled-destroy", -1},
	}
	if legacy.Recipe != fixtureRecipeV1 || len(legacy.Entries) != len(wantCatalog) || !reflect.DeepEqual(fixtureCatalog[:], wantCatalog) || len(fixtureCatalogV2) != 11 || len(fixtureCatalogV3) != fixtureMaxSlots || !reflect.DeepEqual(fixtureCatalogV2[:len(fixtureCatalog)], wantCatalog) || !reflect.DeepEqual(fixtureCatalogV3[:len(fixtureCatalogV2)], fixtureCatalogV2[:]) {
		t.Fatal("default producer or original v1 prefix changed")
	}
	for slot, recipe := range wantCatalog {
		want := installstate.Key{APIVersion: recipe.version, Kind: recipe.kind, Namespace: legacy.Entries[slot].Key.Namespace, Name: "arcadectl-probe-" + legacy.RunID + "-" + recipe.suffix}
		if legacy.Entries[slot].Key != want {
			t.Fatal("legacy fixed address changed")
		}
	}
	// Independently pinned pre-receipt v1 wire schema, not a serialization of
	// the current document type. Optional old receipt fields are omitted here.
	type oldKey struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Namespace  string `json:"namespace"`
		Name       string `json:"name"`
	}
	type oldEntry struct {
		Key                   oldKey `json:"key"`
		State                 string `json:"state"`
		OriginalUID           string `json:"originalUid"`
		DeleteResourceVersion string `json:"deleteResourceVersion"`
	}
	oldEntries := make([]oldEntry, len(wantCatalog))
	for slot, recipe := range wantCatalog {
		oldEntries[slot] = oldEntry{Key: oldKey{recipe.version, recipe.kind, legacy.Entries[slot].Key.Namespace, "arcadectl-probe-" + legacy.RunID + "-" + recipe.suffix}, State: "planned"}
	}
	oldWire := struct {
		Version                string          `json:"version"`
		Recipe                 string          `json:"recipe"`
		Revision               uint64          `json:"revision"`
		RunID                  string          `json:"runId"`
		Journal                json.RawMessage `json:"journal"`
		JournalResourceVersion string          `json:"journalResourceVersion"`
		Entries                []oldEntry      `json:"entries"`
	}{"v1", "inert-admission-v1", 1, legacy.RunID, bytes.Clone(legacy.Journal), legacy.JournalResourceVersion, oldEntries}
	oldBody, err := json.Marshal(oldWire)
	if err != nil {
		t.Fatal(err)
	}
	oldBody, err = canonicaljson.CanonicalJSON(oldBody)
	if err != nil || !bytes.Equal(oldBody, body) {
		t.Fatal("v1 canonical bytes changed")
	}
	if decoded, err := f.engine.decodeFixtureLedger(oldBody); err != nil || !reflect.DeepEqual(decoded, legacy) {
		t.Fatal("old v1 wire document no longer decodes")
	}
	if _, err := ledger.object(fixtureVerifiedCancelledDestroy); err != ErrFixtures {
		t.Fatal("v1 addressed v2 slot")
	}
	instrumentFreshFixtureRecipeV2(t, ledger)
	v2 := ledger.document
	for _, invalid := range []struct {
		recipe string
		count  int
	}{
		{"", 0}, {"future", 11}, {fixtureRecipeV1, 11}, {fixtureRecipeV2, 10}, {fixtureRecipeV2, 0}, {fixtureRecipeV2, 12}, {fixtureRecipeV3, 11}, {fixtureRecipeV3, 13},
	} {
		d := v2
		d.Recipe = invalid.recipe
		d.Entries = make([]fixtureEntry, invalid.count)
		if validFixtureRecipe(d) || fixtureCatalogFor(d) != nil || f.engine.validateFixtureLedger(d) != ErrFixtures {
			t.Fatal("unknown or mismatched recipe gained slots")
		}
	}
	next := v2
	next.Revision = legacy.Revision + 1
	if validFixtureTransition(legacy, next) {
		t.Fatal("v1 run upgraded in place")
	}
	next = legacy
	next.Revision = v2.Revision + 1
	if validFixtureTransition(v2, next) {
		t.Fatal("v2 run downgraded in place")
	}
	next = v2
	next.Entries = append([]fixtureEntry{}, v2.Entries...)
	next.Revision++
	next.Entries[fixtureVerifiedCancelledDestroy].State = fixtureCreateAttempted
	if validFixtureTransition(v2, next) {
		t.Fatal("v2 skipped ordered original acknowledgements")
	}
}

func TestFixtureRecipeV2ClosedVerifiedOriginalAndWholeShapes(t *testing.T) {
	created := time.Date(2026, 10, 6, 10, 0, 0, 0, time.UTC)
	for _, profile := range []string{installrender.Profile135, installrender.Profile137} {
		t.Run(profile, func(t *testing.T) {
			f := newFixtureWithPlans(t, false, fixturePlanProfile(t, "isolated-install", profile))
			ledger, err := f.engine.prepareFixtureLedger(t.Context(), f.snapshot)
			if err != nil {
				t.Fatal(err)
			}
			defer ledger.close()
			instrumentFreshFixtureRecipeV2(t, ledger)
			for slot := range fixtureCatalog {
				acknowledgeRecipeFixture(t, ledger, slot, types.UID(fmt.Sprintf("a0000000-0000-4000-8000-%012x", slot+1)))
			}
			if validFixtureDestroySeedDocument(fixtureSeedIntent(t, ledger)) {
				t.Fatal("seed accepted before eleventh original ACK")
			}
			if validFixtureRetainedMarkerDocument(fixtureMarkerIntent(t, ledger)) {
				t.Fatal("marker accepted before eleventh original ACK")
			}
			before := bytes.Clone(ledger.body)
			dry := fixtureResultExample(t, ledger, fixtureVerifiedCancelledDestroy, fixtureDryRunResult, created)
			fixtureResultRefusals(t, ledger, fixtureVerifiedCancelledDestroy, fixtureDryRunResult, dry, created.Add(time.Minute))
			o, err := ledger.object(fixtureVerifiedCancelledDestroy)
			if err != nil || o.GetAnnotations() != nil || o.GetUID() != "" || o.GetResourceVersion() != "" || len(o.GetOwnerReferences()) != 0 || len(o.GetFinalizers()) != 0 {
				t.Fatal("verified constructor gained live/unsafe authority")
			}
			mode, _, _ := unstructured.NestedString(o.Object, "spec", "mode")
			cancelled, _, _ := unstructured.NestedBool(o.Object, "spec", "cancelRequested")
			if mode != "VerifiedBackup" || !cancelled {
				t.Fatal("verified fixture is executable or wrong mode")
			}
			if _, present := o.Object["status"]; present {
				t.Fatal("verified fixture acquired status")
			}
			if _, present, err := unstructured.NestedFieldNoCopy(o.Object, "spec", "confirmationChallenge"); err != nil || present {
				t.Fatal("verified fixture acquired confirmation")
			}
			if fixtureActor(fixtureVerifiedCancelledDestroy, "create") != 0 {
				t.Fatal("verified fixture acquired unsafe administrator route")
			}
			unsafe, _ := ledger.object(fixtureCancelledDestroy)
			uData, _, _ := unstructured.NestedMap(unsafe.Object, "spec", "target", "data")
			vData, _, _ := unstructured.NestedMap(o.Object, "spec", "target", "data")
			if reflect.DeepEqual(uData, vData) || !bytes.Equal(before, ledger.body) {
				t.Fatal("constructor reused unsafe data or changed WAL")
			}
			acknowledgeRecipeFixture(t, ledger, fixtureVerifiedCancelledDestroy, "a0000000-0000-4000-8000-00000000000b")
			for _, phase := range []fixtureResultPhase{fixtureAcknowledgedResult, fixtureStableResult} {
				fixtureResultRefusals(t, ledger, fixtureVerifiedCancelledDestroy, phase, fixtureResultExample(t, ledger, fixtureVerifiedCancelledDestroy, phase, created), created.Add(time.Minute))
			}
			warm := fixtureWarmCancelledSlotExample(t, ledger, fixtureVerifiedCancelledDestroy, created, [3]time.Duration{time.Second, 2 * time.Second, 3 * time.Second})
			if ledger.validateWarmCancelledDestroySlotResult(fixtureVerifiedCancelledDestroy, warm, created.Add(time.Minute)) != nil || ledger.validateWarmCancelledDestroyResult(warm, created.Add(time.Minute)) != ErrFixtures {
				t.Fatal("closed warm slots confused original identities")
			}
			for _, entry := range ledger.document.Entries {
				if entry.State != fixtureOriginal {
					t.Fatal("missing original ACK")
				}
			}
		})
	}
}

func TestFixtureRecipeV2CompletePhaseAndHistoricalRetirement(t *testing.T) {
	newPhase := fixturePhaseFactoryWithSetup(t, func(h *fixturePhaseTest) { instrumentFreshFixtureRecipeV2(t, h.f.wire.ledger) })
	h := newPhase(t)
	f := h.f.wire.ledger
	acknowledgeAllRecipeFixtures(t, f)
	created := time.Now().UTC().Truncate(time.Second).Add(-20 * time.Second)
	for slot := range f.document.Entries {
		h.f.objects[slot] = fixtureResultExample(t, f, slot, fixtureStableResult, created)
	}
	phase, err := h.f.wire.observePhase(t.Context())
	if err != nil || phase == nil || phase.objects[fixtureVerifiedCancelledDestroy] == nil {
		t.Fatal("eleventh original absent from complete phase", err)
	}
	settled, err := h.f.wire.settledFixtures(t.Context())
	if err != nil || settled == nil || settled.objects[fixtureVerifiedCancelledDestroy] == nil || settled.objects[fixtureVerifiedCancelledDestroy].GetUID() != f.document.Entries[fixtureVerifiedCancelledDestroy].OriginalUID {
		t.Fatal("settled GET/GC composition omitted eleventh original", err)
	}
	original := h.f.objects[fixtureVerifiedCancelledDestroy]
	delete(h.f.objects, fixtureVerifiedCancelledDestroy)
	if _, err := h.f.wire.observePhase(t.Context()); err != ErrFixtures {
		t.Fatal("complete phase accepted missing eleventh original")
	}
	h.f.objects[fixtureVerifiedCancelledDestroy] = original.DeepCopy()
	h.f.objects[fixtureVerifiedCancelledDestroy].SetUID("b0000000-0000-4000-8000-00000000000b")
	if _, err := h.f.wire.observePhase(t.Context()); err != ErrFixtures {
		t.Fatal("complete phase adopted replacement eleventh original")
	}
	h.f.objects[fixtureVerifiedCancelledDestroy] = original
	// Test-only reverse original cleanup instrumentation, never native deletion.
	for slot := len(f.document.Entries) - 1; slot >= 0; slot-- {
		next, _ := f.nextDocument()
		next.Entries[slot].State, next.Entries[slot].DeleteResourceVersion = fixtureDeleteAttempted, "101"
		if f.advance(next) != nil {
			t.Fatal("reverse v2 intent refused")
		}
		next, _ = f.nextDocument()
		next.Entries[slot].State = fixtureAbsent
		if f.advance(next) != nil {
			t.Fatal("reverse v2 absence refused")
		}
		delete(h.f.objects, slot)
	}
	fixtureRetirementIntent(t, h)
	// Historical reading must not depend on currently registered plans.
	oldPlans := f.engine.plans
	f.engine.plans = nil
	evidence, err := f.engine.readFixtureRetirement(h.f.actor.request.Snapshot.Anchor())
	f.engine.plans = oldPlans
	if err != nil || evidence == nil || !bytes.Equal(evidence.archive, f.body) {
		t.Fatal("v2 historical archive required current plans", err)
	}
	if h.f.wire.retireDrained(t.Context()) != nil || f.engine.fixtureFence(h.f.actor.request.Snapshot) != nil {
		t.Fatal("complete v2 retirement failed to retire fence")
	}
}
