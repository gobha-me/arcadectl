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

// Source-derived examples, not native status-subresource certification or
// reliable status-write ACKs. No real controller or world is involved.
func fixtureDestroySeedExample(t *testing.T, ledger *fixtureLedger, created time.Time) *unstructured.Unstructured {
	t.Helper()
	o := fixtureResultExample(t, ledger, fixtureCancelledDestroy, fixtureStableResult, created)
	status, err := ledger.destroySeedStatus()
	if err != nil {
		t.Fatal("closed seed unavailable")
	}
	o.Object["status"] = status
	m := o.Object["metadata"].(map[string]any)
	m["managedFields"] = append(m["managedFields"].([]any), map[string]any{
		"manager": "arcadectl-installer", "operation": "Update", "apiVersion": o.GetAPIVersion(),
		"fieldsType": "FieldsV1", "fieldsV1": fixtureDestroySeedFieldset(), "time": created.Add(10 * time.Second).Format(time.RFC3339), "subresource": "status",
	})
	return o
}

func acknowledgeAllRecipeFixtures(t *testing.T, ledger *fixtureLedger) {
	t.Helper()
	for slot := range fixtureCatalogFor(ledger.document) {
		acknowledgeRecipeFixture(t, ledger, slot, types.UID(fmt.Sprintf("a0000000-0000-4000-8000-%012x", slot+1)))
	}
}

func TestFixtureDestroySeedOriginalRecipeAndPureIsolation(t *testing.T) {
	created := time.Date(2026, time.October, 6, 10, 0, 0, 0, time.UTC)
	for _, profile := range []string{installrender.Profile135, installrender.Profile137} {
		t.Run(profile, func(t *testing.T) {
			f := newFixtureWithPlans(t, false, fixturePlanProfile(t, "isolated-install", profile))
			ledger, err := f.engine.prepareFixtureLedger(t.Context(), f.snapshot)
			if err != nil {
				t.Fatal(err)
			}
			defer ledger.close()
			if _, err := ledger.destroySeedStatus(); err != ErrFixtures {
				t.Fatal("planned GameDestroy acquired seed authority")
			}
			for slot := 0; slot < fixtureCancelledDestroy; slot++ {
				acknowledgeRecipeFixture(t, ledger, slot, types.UID(fmt.Sprintf("a0000000-0000-4000-8000-%012x", slot+1)))
			}
			next, _ := ledger.nextDocument()
			next.Entries[fixtureCancelledDestroy].State = fixtureCreateAttempted
			if ledger.advance(next) != nil {
				t.Fatal("test intent unavailable")
			}
			if _, err := ledger.destroySeedStatus(); err != ErrFixtures {
				t.Fatal("unknown CREATE acquired seed authority")
			}
			next, _ = ledger.nextDocument()
			next.Entries[fixtureCancelledDestroy].State = fixtureOriginal
			next.Entries[fixtureCancelledDestroy].OriginalUID = "a0000000-0000-4000-8000-00000000000a"
			if ledger.advance(next) != nil {
				t.Fatal("test ACK unavailable")
			}
			before, revision, identity := bytes.Clone(ledger.body), ledger.document.Revision, ledger.identity
			ack, effect := ledger.ackSlot, ledger.effectSlot
			want := map[string]any{"phase": "Cancelled", "preview": map[string]any{"challenge": ledger.document.RunID, "expiresAt": "2000-01-01T00:00:00Z", "restoreGuidance": "Isolated cancelled admission fixture; no world or restore artifact exists."}}
			status, err := ledger.destroySeedStatus()
			if err != nil || !reflect.DeepEqual(status, want) {
				t.Fatal("closed synthetic status recipe drifted")
			}
			status["preview"].(map[string]any)["challenge"] = "foreign"
			status["phase"] = "Deleting"
			again, err := ledger.destroySeedStatus()
			if err != nil || !reflect.DeepEqual(again, want) {
				t.Fatal("caller mutation corrupted future seed recipe")
			}
			fields := fixtureDestroySeedFieldset()
			fields["f:status"].(map[string]any)["f:spec"] = map[string]any{}
			if reflect.DeepEqual(fields, fixtureDestroySeedFieldset()) {
				t.Fatal("status fieldset shared mutable authority")
			}
			o := fixtureDestroySeedExample(t, ledger, created)
			original := o.DeepCopy()
			if ledger.validateDestroySeedResult(o, created.Add(time.Minute)) != nil || !reflect.DeepEqual(o, original) {
				t.Fatal("pure seeded validation refused or mutated its input")
			}
			for _, phase := range []fixtureResultPhase{fixtureDryRunResult, fixtureAcknowledgedResult, fixtureStableResult} {
				if ledger.validateResult(fixtureCancelledDestroy, phase, o, created.Add(time.Minute)) != ErrFixtures {
					t.Fatal("normal status-absent validator relaxed")
				}
			}
			if !bytes.Equal(ledger.body, before) || ledger.document.Revision != revision || ledger.identity != identity || ledger.ackSlot != ack || ledger.effectSlot != effect || f.engine.fixtureFence(f.snapshot) != ErrFixtures || f.access.writes != 0 || f.nsUpdates != 0 {
				t.Fatal("pure recipe/validation mutated WAL, capabilities, effects or fence")
			}
			body, storedIdentity, err := f.engine.files.Read(ledger.name, fixtureLedgerMaxBytes)
			if err != nil || !bytes.Equal(body, before) || storedIdentity != identity {
				t.Fatal("pure recipe/validation mutated actual protected file")
			}
			next, _ = ledger.nextDocument()
			next.Entries[fixtureCancelledDestroy].State = fixtureDeleteAttempted
			next.Entries[fixtureCancelledDestroy].DeleteResourceVersion = "101"
			if ledger.advance(next) != nil {
				t.Fatal("test delete intent unavailable")
			}
			for _, state := range []fixtureState{fixtureDeleteAttempted, fixtureAbsent} {
				if state == fixtureAbsent {
					next, _ = ledger.nextDocument()
					next.Entries[fixtureCancelledDestroy].State = state
					if ledger.advance(next) != nil {
						t.Fatal("test absence unavailable")
					}
				}
				if _, err := ledger.destroySeedStatus(); err != ErrFixtures || ledger.validateDestroySeedResult(o, created.Add(time.Minute)) != ErrFixtures {
					t.Fatal("pending/absent GameDestroy repaired by seed recipe or shape")
				}
			}
		})
	}
}

func TestFixtureDestroySeedWholeShapeRefusals(t *testing.T) {
	created := time.Date(2026, time.October, 6, 10, 0, 0, 0, time.UTC)
	observed := created.Add(time.Minute)
	for _, profile := range []string{installrender.Profile135, installrender.Profile137} {
		t.Run(profile, func(t *testing.T) {
			f := newFixtureWithPlans(t, false, fixturePlanProfile(t, "isolated-install", profile))
			ledger, err := f.engine.prepareFixtureLedger(t.Context(), f.snapshot)
			if err != nil {
				t.Fatal(err)
			}
			defer ledger.close()
			acknowledgeAllRecipeFixtures(t, ledger)
			o := fixtureDestroySeedExample(t, ledger, created)
			if ledger.validateDestroySeedResult(o, observed) != nil {
				t.Fatal("closed positive refused")
			}
			before := bytes.Clone(ledger.body)
			mutations := map[string]func(*unstructured.Unstructured){
				"status-absent":       func(x *unstructured.Unstructured) { delete(x.Object, "status") },
				"status-null":         func(x *unstructured.Unstructured) { x.Object["status"] = nil },
				"status-empty":        func(x *unstructured.Unstructured) { x.Object["status"] = map[string]any{} },
				"status-string":       func(x *unstructured.Unstructured) { x.Object["status"] = "PRIVATE-CANARY" },
				"status-preview-null": func(x *unstructured.Unstructured) { x.Object["status"].(map[string]any)["preview"] = nil },
				"top-level":           func(x *unstructured.Unstructured) { x.Object["private"] = "PRIVATE-CANARY" },
				"kind":                func(x *unstructured.Unstructured) { x.SetKind("GameServer") },
				"api-version":         func(x *unstructured.Unstructured) { x.SetAPIVersion("foreign/v1") },
				"uid":                 func(x *unstructured.Unstructured) { x.SetUID("c0000000-0000-4000-8000-000000000001") },
				"name":                func(x *unstructured.Unstructured) { x.SetName("foreign") },
				"namespace":           func(x *unstructured.Unstructured) { x.SetNamespace("foreign") },
				"generation":          func(x *unstructured.Unstructured) { x.SetGeneration(2) },
				"finalizer":           func(x *unstructured.Unstructured) { x.SetFinalizers([]string{"arcade.gobha.me/destroy"}) },
				"owners":              func(x *unstructured.Unstructured) { x.Object["metadata"].(map[string]any)["ownerReferences"] = []any{} },
				"audit": func(x *unstructured.Unstructured) {
					x.SetAnnotations(map[string]string{"arcade.gobha.me/unsafe-requested-by": "foreign"})
				},
				"creation-null": func(x *unstructured.Unstructured) { x.Object["metadata"].(map[string]any)["creationTimestamp"] = nil },
				"metadata-extra": func(x *unstructured.Unstructured) {
					x.Object["metadata"].(map[string]any)["private"] = "PRIVATE-CANARY"
				},
				"spec-cancel": func(x *unstructured.Unstructured) { x.Object["spec"].(map[string]any)["cancelRequested"] = false },
				"spec-confirmation": func(x *unstructured.Unstructured) {
					x.Object["spec"].(map[string]any)["confirmationChallenge"] = ledger.document.RunID
				},
				"target-world-uid": func(x *unstructured.Unstructured) {
					_ = unstructured.SetNestedField(x.Object, string(o.GetUID()), "spec", "target", "gameServer", "uid")
				},
				"target-data-identity": func(x *unstructured.Unstructured) {
					_ = unstructured.SetNestedField(x.Object, "synthetic-proof", "spec", "target", "data", "identity")
				},
				"target-claim-uid": func(x *unstructured.Unstructured) {
					x.Object["spec"].(map[string]any)["target"].(map[string]any)["data"].(map[string]any)["claims"].([]any)[0].(map[string]any)["claimRef"].(map[string]any)["uid"] = string(ledger.document.Entries[fixtureRetainedPVC].OriginalUID)
				},
				"fields-missing": func(x *unstructured.Unstructured) {
					x.Object["metadata"].(map[string]any)["managedFields"] = x.Object["metadata"].(map[string]any)["managedFields"].([]any)[:1]
				},
				"fields-extra": func(x *unstructured.Unstructured) {
					x.Object["metadata"].(map[string]any)["managedFields"] = append(x.Object["metadata"].(map[string]any)["managedFields"].([]any), map[string]any{})
				},
				"fields-order": func(x *unstructured.Unstructured) {
					m := x.Object["metadata"].(map[string]any)["managedFields"].([]any)
					m[0], m[1] = m[1], m[0]
				},
				"fields-status-null": func(x *unstructured.Unstructured) {
					x.Object["metadata"].(map[string]any)["managedFields"].([]any)[1] = nil
				},
			}
			for _, key := range []string{"phase", "preview"} {
				mutations["status-missing-"+key] = func(x *unstructured.Unstructured) { delete(x.Object["status"].(map[string]any), key) }
			}
			for _, key := range []string{"observedGeneration", "startedAt", "completedAt", "conditions", "verification", "deletionJournal", "private"} {
				mutations["status-extra-"+key] = func(x *unstructured.Unstructured) { x.Object["status"].(map[string]any)[key] = nil }
			}
			for _, phase := range []string{"Pending", "Preview", "Verifying", "Deleting", "Succeeded", "Failed", ""} {
				mutations["status-phase-"+phase] = func(x *unstructured.Unstructured) { x.Object["status"].(map[string]any)["phase"] = phase }
			}
			for _, key := range []string{"challenge", "expiresAt", "restoreGuidance"} {
				for _, mode := range []string{"missing", "null", "altered"} {
					mutations["preview-"+key+"-"+mode] = func(x *unstructured.Unstructured) {
						p := x.Object["status"].(map[string]any)["preview"].(map[string]any)
						switch mode {
						case "missing":
							delete(p, key)
						case "null":
							p[key] = nil
						default:
							p[key] = "PRIVATE-CANARY"
						}
					}
				}
			}
			mutations["preview-extra"] = func(x *unstructured.Unstructured) {
				x.Object["status"].(map[string]any)["preview"].(map[string]any)["private"] = "PRIVATE-CANARY"
			}
			for _, index := range []int{0, 1} {
				for _, key := range []string{"manager", "operation", "apiVersion", "fieldsType", "fieldsV1", "subresource", "time", "private"} {
					mutations[fmt.Sprintf("fields-%d-%s", index, key)] = func(x *unstructured.Unstructured) {
						x.Object["metadata"].(map[string]any)["managedFields"].([]any)[index].(map[string]any)[key] = "PRIVATE-CANARY"
					}
				}
			}
			for label, fields := range map[string]map[string]any{
				"atomic-status": {"f:status": map[string]any{}},
				"hidden-spec":   {"f:status": map[string]any{}, "f:spec": map[string]any{}},
				"missing-dots":  {"f:status": map[string]any{"f:phase": map[string]any{}, "f:preview": fixtureFieldLeaves("challenge", "expiresAt", "restoreGuidance")}},
			} {
				mutations["status-fieldset-"+label] = func(x *unstructured.Unstructured) {
					x.Object["metadata"].(map[string]any)["managedFields"].([]any)[1].(map[string]any)["fieldsV1"] = fields
				}
			}
			for _, rv := range []string{"", "0", "01", "18446744073709551616", "foreign"} {
				mutations["rv-"+rv] = func(x *unstructured.Unstructured) { x.SetResourceVersion(rv) }
			}
			for _, timestamp := range []string{"2026-10-06T09:59:59Z", "2026-10-06T10:01:02Z", "2026-10-06T10:00:10.000Z", "2026-10-06T11:00:10+01:00", "0000-01-01T00:00:00Z", ""} {
				mutations["status-time-"+timestamp] = func(x *unstructured.Unstructured) {
					x.Object["metadata"].(map[string]any)["managedFields"].([]any)[1].(map[string]any)["time"] = timestamp
				}
			}
			for name, mutate := range mutations {
				t.Run(name, func(t *testing.T) {
					x := o.DeepCopy()
					mutate(x)
					input := x.DeepCopy()
					if ledger.validateDestroySeedResult(x, observed) != ErrFixtures || !reflect.DeepEqual(x, input) || !bytes.Equal(ledger.body, before) {
						t.Fatal("foreign seeded shape accepted or pure validation mutated input/WAL")
					}
				})
			}
			for slot := 0; slot < fixtureCancelledDestroy; slot++ {
				if ledger.validateDestroySeedResult(fixtureResultExample(t, ledger, slot, fixtureStableResult, created), observed) != ErrFixtures {
					t.Fatal("seed shape accepted another fixture slot")
				}
			}
			if ledger.validateDestroySeedResult(nil, observed) != ErrFixtures || (*fixtureLedger)(nil).validateDestroySeedResult(o, observed) != ErrFixtures {
				t.Fatal("nil input accepted")
			}
		})
	}
}

func TestFixtureDestroySeedExpiryAndProtectedReloadWithoutAuthority(t *testing.T) {
	f := newFixture(t, false)
	ledger, err := f.engine.prepareFixtureLedger(t.Context(), f.snapshot)
	if err != nil {
		t.Fatal(err)
	}
	acknowledgeAllRecipeFixtures(t, ledger)
	created := time.Date(1999, time.December, 31, 23, 0, 0, 0, time.UTC)
	o := fixtureDestroySeedExample(t, ledger, created)
	expiry := time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)
	for _, observed := range []time.Time{time.Time{}, expiry.Add(-time.Second), expiry, time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)} {
		if ledger.validateDestroySeedResult(o, observed) != ErrFixtures {
			t.Fatal("nonexpired preview or invalid observation accepted")
		}
	}
	if ledger.validateDestroySeedResult(o, expiry.Add(time.Nanosecond)) != nil {
		t.Fatal("strictly expired preview refused")
	}
	before := bytes.Clone(ledger.body)
	if ledger.close() != nil {
		t.Fatal("test ledger close failed")
	}
	if _, err := ledger.destroySeedStatus(); err != ErrFixtures || ledger.validateDestroySeedResult(o, expiry.Add(time.Second)) != ErrFixtures {
		t.Fatal("closed ledger supplied seed recipe or accepted seeded shape")
	}
	loaded, err := f.engine.loadFixtureLedger(t.Context(), f.snapshot)
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.close()
	if loaded.validateDestroySeedResult(o, time.Date(2026, time.October, 6, 10, 0, 0, 0, time.UTC)) != nil || !bytes.Equal(loaded.body, before) || loaded.ackSlot != -1 || loaded.effectSlot != -1 || f.engine.fixtureFence(f.snapshot) != ErrFixtures {
		t.Fatal("old original shape refused or reload restored authority/retired fence")
	}
	// No synthetic shape is a same-attempt ACK. In-memory document corruption
	// must not retarget the recipe even if a live body looks compatible.
	loaded.document.Entries[fixtureCancelledDestroy].OriginalUID = types.UID("synthetic-server-" + loaded.document.RunID)
	if _, err := loaded.destroySeedStatus(); err != ErrFixtures || loaded.validateDestroySeedResult(o, expiry.Add(time.Second)) != ErrFixtures {
		t.Fatal("non-native or unprotected original UID accepted")
	}
}

func TestFixtureDestroySeedRefusesProtectedNonNativeOriginal(t *testing.T) {
	f := newFixture(t, false)
	ledger, err := f.engine.prepareFixtureLedger(t.Context(), f.snapshot)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.close()
	for slot := range fixtureCatalog {
		acknowledgeRecipeFixture(t, ledger, slot, types.UID(fmt.Sprintf("durable-receipt-but-not-native-%d", slot)))
	}
	if _, err := f.engine.decodeFixtureLedger(ledger.body); err != nil {
		t.Fatal("test ledger is not genuinely protected/canonical")
	}
	if _, err := ledger.destroySeedStatus(); err != ErrFixtures {
		t.Fatal("protected non-native original UID admitted synthetic seed")
	}
}
