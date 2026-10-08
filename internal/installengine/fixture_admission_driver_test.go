// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installstate"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestFixtureAdmissionCounterpartExactNativeNotFound(t *testing.T) {
	for _, key := range []installstate.Key{
		{APIVersion: "v1", Kind: "Pod", Namespace: "isolated-install", Name: "fixed-pod"},
		{APIVersion: "v1", Kind: "PersistentVolumeClaim", Namespace: "isolated-install", Name: "fixed-claim"},
		{APIVersion: "arcade.gobha.me/v1alpha1", Kind: "GameDestroy", Namespace: "isolated-install", Name: "fixed-destroy"},
	} {
		t.Run(key.Kind, func(t *testing.T) {
			_, plural, _ := fixturePath(key, false)
			gv, _ := schema.ParseGroupVersion(key.APIVersion)
			status := apierrors.NewNotFound(schema.GroupResource{Group: gv.Group, Resource: plural}, key.Name).ErrStatus
			status.APIVersion, status.Kind = "v1", "Status"
			body, err := json.Marshal(status)
			if err != nil {
				t.Fatal(err)
			}
			check := func(body []byte) bool {
				response := &http.Response{StatusCode: http.StatusNotFound, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader(body))}
				defer response.Body.Close()
				return fixtureCounterpartNotFound(response, key)
			}
			if !check(body) {
				t.Fatalf("exact native named NotFound refused: %s", body)
			}
			for name, bad := range map[string][]byte{
				"bare": []byte("not found"), "empty": nil,
				"foreign-name": bytes.ReplaceAll(body, []byte(key.Name), []byte("foreign-name")),
				"foreign-kind": bytes.ReplaceAll(body, []byte(plural), []byte("foreigns")),
				"extra":        append(bytes.TrimSuffix(body, []byte("}")), []byte(`,"extra":true}`)...),
				"duplicate":    append(bytes.TrimSuffix(body, []byte("}")), []byte(`,"code":404}`)...),
			} {
				if check(bad) {
					t.Error("invalid named absence accepted", name)
				}
			}
		})
	}
}

func TestFixtureAdmissionAll55ClosedRequests(t *testing.T) {
	f := newFixture(t, false)
	ledger, err := f.engine.prepareFixtureLedgerV2(t.Context(), f.snapshot)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.close()
	if !ledger.driverFresh || ledger.document.Recipe != fixtureRecipeV2 || len(ledger.document.Entries) != 11 || ledger.document.Version != "v1" {
		t.Fatal("fresh v2 producer did not preserve envelope and exact recipe")
	}
	acknowledgeAllRecipeFixtures(t, ledger)
	plan := f.engine.plans[f.snapshot.Document().TargetPackage]
	policies := &admissionConfiguration{policies: map[string]*admissionv1.ValidatingAdmissionPolicy{}}
	for _, resource := range plan.Resources() {
		if resource.Object.GetKind() == "ValidatingAdmissionPolicy" {
			var policy admissionv1.ValidatingAdmissionPolicy
			if runtime.DefaultUnstructuredConverter.FromUnstructured(resource.Object.Object, &policy) != nil {
				t.Fatal("signed policy unavailable")
			}
			policies.policies[policy.Name] = &policy
		}
	}
	w := &fixtureWire{ledger: ledger, actors: &admissionActors{request: LifecycleCheck{Target: plan}, policies: policies}}
	phase := &fixturePhaseObservation{}
	created := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	for slot := range ledger.document.Entries {
		phase.objects[slot] = fixtureResultExample(t, ledger, slot, fixtureStableResult, created)
	}
	original := *phase
	for slot, object := range original.objects {
		original.objects[slot] = object.DeepCopy()
	}
	// Independent expected schedule: twelve CREATE pairs, three eight-case
	// workers, two plain subresources, then fixed PVC/unsafe controls.
	negative := map[int]int{1: 1, 3: 1, 5: 0, 7: 0, 9: 1, 11: 0, 13: 2, 14: 3, 15: 3, 17: 3, 18: 0, 19: 0, 21: 2, 22: 3, 23: 3, 25: 3, 26: 0, 27: 0, 29: 2, 30: 3, 31: 3, 33: 3, 34: 0, 35: 0, 40: 3, 41: 1, 43: 2, 45: 1, 50: 1, 52: 0, 54: 1}
	actors := map[int]admissionActor{16: ordinaryControllerActor, 17: destroyControllerActor, 24: ordinaryControllerActor, 25: destroyControllerActor, 32: destroyControllerActor, 33: ordinaryControllerActor, 38: ordinaryControllerActor, 42: ordinaryControllerActor, 44: destroyControllerActor, 46: ordinaryControllerActor, 49: destroyAdministratorActor, 50: destroyAdministratorActor, 51: destroyControllerActor, 52: destroyControllerActor, 53: destroyAdministratorActor, 54: destroyAdministratorActor}
	addresses := map[installstate.Key]bool{}
	for number := fixtureAdmissionCase(0); number < fixtureAdmissionCaseCount; number++ {
		t.Run(fmt.Sprintf("case-%02d", number), func(t *testing.T) {
			r, err := w.admissionRequest(number, phase)
			index, denied := negative[int(number)]
			if err != nil || r.object == nil || (r.policy != "") != denied || denied && r.index != index || r.actor != actors[int(number)] {
				t.Fatal("closed case differs from independent actor/denial schedule", number, err)
			}
			if number < 12 || number == 38 || number == 49 || number == 50 {
				key := fixtureObjectKey(r.object)
				if r.slot != -1 || r.operation != probeCreateOperation || r.object.GetUID() != "" || r.object.GetResourceVersion() != "" || len(r.object.GetManagedFields()) != 0 || addresses[key] {
					t.Fatal("CREATE counterpart acquired generated identity or reused address")
				}
				addresses[key] = true
			} else if r.slot < 0 || r.object.GetUID() != phase.objects[r.slot].GetUID() || r.object.GetResourceVersion() != phase.objects[r.slot].GetResourceVersion() {
				t.Fatal("named case lost original identity")
			}
			if !reflect.DeepEqual(original, *phase) {
				t.Fatal("closed constructor mutated an observed original")
			}
		})
	}
	if _, err := w.admissionRequest(fixtureAdmissionCaseCount, phase); err != ErrFixtures {
		t.Fatal("unlisted case accepted")
	}
	if len(addresses) != 15 || fixtureAdmissionAllCases != (uint64(1)<<55)-1 {
		t.Fatal("matrix/address cardinality differs")
	}
	if ledger.close() != nil {
		t.Fatal("close failed")
	}
	loaded, err := f.engine.loadFixtureLedger(t.Context(), f.snapshot)
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.close()
	if loaded.driverFresh || loaded.document.Recipe != fixtureRecipeV2 || len(loaded.document.Entries) != 11 {
		t.Fatal("reload regranted driver or changed original recipe")
	}
}

func TestFixtureAdmissionPairedSeedDeltas(t *testing.T) {
	created := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	observed := created.Add(time.Minute)
	for _, warm := range []bool{false, true} {
		t.Run(fmt.Sprintf("warm-%t", warm), func(t *testing.T) {
			f := newFixture(t, false)
			ledger, err := f.engine.prepareFixtureLedgerV2(t.Context(), f.snapshot)
			if err != nil {
				t.Fatal(err)
			}
			defer ledger.close()
			acknowledgeAllRecipeFixtures(t, ledger)
			intent := fixtureSeedIntent(t, ledger)
			if warm {
				intent.DestroySeed.Mode = fixtureDestroySeedWarmCancelled
			}
			if ledger.advance(intent) != nil {
				t.Fatal("test intent unavailable")
			}
			ledger.seedEffect = false // pure test instrumentation, not a send/ACK
			if ledger.advance(fixtureSeedAcknowledgement(t, ledger)) != nil {
				t.Fatal("test receipt unavailable")
			}
			ledger.seedAck = false
			before := fixtureResultExample(t, ledger, fixtureCancelledDestroy, fixtureStableResult, created)
			var after *unstructured.Unstructured
			check := ledger.validateDestroySeedDelta
			if warm {
				before = fixtureWarmCancelledExample(t, ledger, created, [3]time.Duration{time.Second, time.Second, time.Second})
				after = fixtureWarmSeededExample(t, ledger, created, [4]time.Duration{time.Second, time.Second, time.Second, 2 * time.Second})
				check = ledger.validateWarmDestroySeedDelta
			} else {
				after = fixtureDestroySeedExample(t, ledger, created)
			}
			after.SetResourceVersion("102")
			beforeCopy, afterCopy := before.DeepCopy(), after.DeepCopy()
			if check(before, after, observed) != nil || !reflect.DeepEqual(beforeCopy, before) || !reflect.DeepEqual(afterCopy, after) {
				t.Fatal("exact paired setup refused or mutated its inputs")
			}
			bad := after.DeepCopy()
			fields := bad.Object["metadata"].(map[string]any)["managedFields"].([]any)
			for _, value := range fields {
				field := value.(map[string]any)
				if field["manager"] == "arcadectl-installer" && field["subresource"] == nil {
					field["time"] = created.Add(3 * time.Second).Format(time.RFC3339)
				}
			}
			if check(before, bad, observed) != ErrFixtures {
				t.Fatal("otherwise-valid setup changed original installer-main time")
			}
			if warm {
				bad = after.DeepCopy()
				fields = bad.Object["metadata"].(map[string]any)["managedFields"].([]any)
				for _, value := range fields {
					field := value.(map[string]any)
					if field["manager"] == "arcadectl-controller" && field["subresource"] == "status" {
						field["time"] = created.Add(2 * time.Second).Format(time.RFC3339)
					}
				}
				if check(before, bad, observed) != ErrFixtures {
					t.Fatal("setup changed historic controller-status time")
				}
				phase := &fixturePhaseBaseline{Leaders: []fixturePhaseLeader{{Row: fixtureWorldRow{Key: installstate.Key{Name: "destroy-controller.arcade.gobha.me"}}}}}
				confirmation := fixtureWarmConfirmationExample(t, ledger, created, false)
				if ledger.validateAdmissionConfirmationDelta(after, confirmation, phase, observed) != nil {
					t.Fatal("paired exact warm confirmation refused")
				}
				bad = confirmation.DeepCopy()
				fields = bad.Object["metadata"].(map[string]any)["managedFields"].([]any)
				for _, value := range fields {
					field := value.(map[string]any)
					if field["manager"] == "arcadectl-controller" && field["subresource"] == "status" {
						field["time"] = created.Add(2 * time.Second).Format(time.RFC3339)
					}
				}
				if ledger.validateAdmissionConfirmationDelta(after, bad, phase, observed) != ErrFixtures {
					t.Fatal("confirmation changed historic controller-status time")
				}
			}
		})
	}
}

func TestFixtureAdmissionOriginalSettledRequiresStableBookkeeping(t *testing.T) {
	f := newFixture(t, false)
	ledger, err := f.engine.prepareFixtureLedgerV2(t.Context(), f.snapshot)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.close()
	acknowledgeAllRecipeFixtures(t, ledger)
	created := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	for _, slot := range []int{fixtureBackupJob, fixtureRestoreJob, fixtureDestroyJob, fixtureRetainedPVC, fixturePlainPVC} {
		observation := &fixturePhaseObservation{}
		observation.objects[slot] = fixtureResultExample(t, ledger, slot, fixtureAcknowledgedResult, created)
		if fixtureAdmissionOriginalSettled(ledger, slot, observation, created.Add(time.Minute)) {
			t.Fatal("acknowledged original froze an intermediate baseline", slot)
		}
		observation.objects[slot] = fixtureResultExample(t, ledger, slot, fixtureStableResult, created)
		if !fixtureAdmissionOriginalSettled(ledger, slot, observation, created.Add(time.Minute)) {
			t.Fatal("settled original refused", slot)
		}
	}
}
