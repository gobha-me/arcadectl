// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installstate"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
)

func phaseLeaderFixture(pod *corev1.Pod, index int, now time.Time) coordinationv1.Lease {
	name, uid := "controller.arcade.gobha.me", types.UID("10000000-0000-4000-8000-000000000011")
	if index == 1 {
		name, uid = "destroy-controller.arcade.gobha.me", "10000000-0000-4000-8000-000000000012"
	}
	created := metav1.NewTime(now.Add(-time.Minute).Truncate(time.Second))
	acquire, renew := metav1.NewMicroTime(now.Add(-20*time.Second)), metav1.NewMicroTime(now.Add(-2*time.Second))
	managed := metav1.NewTime(now.Add(-2 * time.Second).Truncate(time.Second))
	return coordinationv1.Lease{TypeMeta: metav1.TypeMeta{APIVersion: "coordination.k8s.io/v1", Kind: "Lease"}, ObjectMeta: metav1.ObjectMeta{
		Name: name, Namespace: pod.Namespace, UID: uid, ResourceVersion: "101", CreationTimestamp: created,
		ManagedFields: []metav1.ManagedFieldsEntry{{Manager: "manager", Operation: metav1.ManagedFieldsOperationUpdate, APIVersion: "coordination.k8s.io/v1", Time: &managed, FieldsType: "FieldsV1", FieldsV1: &metav1.FieldsV1{Raw: []byte(`{"f:spec":{"f:acquireTime":{},"f:holderIdentity":{},"f:leaseDurationSeconds":{},"f:leaseTransitions":{},"f:renewTime":{}}}`)}}},
	}, Spec: coordinationv1.LeaseSpec{HolderIdentity: ptr.To(pod.Name + "_10000000-0000-4000-8000-000000000099"), LeaseDurationSeconds: ptr.To[int32](15), LeaseTransitions: ptr.To[int32](0), AcquireTime: &acquire, RenewTime: &renew}}
}

// These test the internal initial baseline from an actual sealed HTTP observer;
// they are NOT standalone ordinary cold safety or full admission evidence.
func TestAdmissionInitialPhaseIndependentLeaderBasis(t *testing.T) {
	plan := fixturePlan(t)
	for _, warm := range [][2]bool{{false, false}, {true, false}, {false, true}, {true, true}} {
		name := "cold"
		if warm[0] {
			name += "-controller"
		}
		if warm[1] {
			name += "-destroy"
		}
		t.Run(name, func(t *testing.T) {
			v, ns, lists := readyControllerFixture(t, plan)
			originalPods := lists["Pod"].(*corev1.PodList).DeepCopy()
			d := admissionPauseFamilies(t, v, lists, warm)
			now := time.Now().UTC().Truncate(time.Microsecond)
			leases := &coordinationv1.LeaseList{}
			for index := range originalPods.Items {
				leases.Items = append(leases.Items, phaseLeaderFixture(&originalPods.Items[index], index, now))
			}
			lists["Lease"] = leases
			states, o, err := admissionClassifyObservationTest(t, v, ns, lists, d, plan, "")
			if err != nil {
				t.Fatal(err)
			}
			baseline, err := capturePhaseBaseline(o, states, now)
			expected := 0
			for _, active := range warm {
				if active {
					expected++
				}
			}
			if err != nil || len(baseline.Leaders) != expected || baseline.validate(ns.Name) != nil {
				t.Fatalf("per-family leader basis incorrect: %v", err)
			}
			// Both complete native Leases remain accounted: warm ones normalized,
			// cold tails exact and not incorrectly bound to a surviving Pod.
			coldLeases := 0
			for _, row := range baseline.Rows {
				if row.Key.Kind == "Lease" {
					coldLeases++
				}
			}
			if coldLeases+len(baseline.Leaders) != 2 {
				t.Fatal("lease collection was omitted")
			}
			for index := range leases.Items {
				leases.Items[index].ResourceVersion = "102"
				renew := metav1.NewMicroTime(now.Add(-time.Second))
				leases.Items[index].Spec.RenewTime = &renew
				managed := metav1.NewTime(now.Add(-time.Second).Truncate(time.Second))
				leases.Items[index].ManagedFields[0].Time = &managed
			}
			states, fresh, err := admissionClassifyObservationTest(t, v, ns, lists, d, plan, "")
			if err != nil {
				t.Fatal(err)
			}
			after, err := capturePhaseBaseline(fresh, states, now)
			if err != nil || samePhaseBaseline(baseline, after) != (expected == 2) {
				t.Fatalf("renewal waiver escaped original running family: %v", err)
			}
		})
	}
}

func TestAdmissionInitialPhaseLeaderMutationRefused(t *testing.T) {
	plan := fixturePlan(t)
	for _, scenario := range []string{"missing", "wrong-holder", "stale", "uid", "rv-regression", "renew-regression", "managed-regression", "fieldset", "transition", "data-label", "extra-public-row"} {
		t.Run(scenario, func(t *testing.T) {
			v, ns, lists := readyControllerFixture(t, plan)
			d, err := installstate.Decode([]byte(ns.Annotations[installstate.Annotation]), plan)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC().Truncate(time.Microsecond)
			pods := lists["Pod"].(*corev1.PodList)
			leases := &coordinationv1.LeaseList{}
			for index := range pods.Items {
				leases.Items = append(leases.Items, phaseLeaderFixture(&pods.Items[index], index, now))
			}
			lists["Lease"] = leases
			states, o, err := admissionClassifyObservationTest(t, v, ns, lists, d, plan, "")
			if err != nil {
				t.Fatal(err)
			}
			before, err := capturePhaseBaseline(o, states, now)
			if err != nil {
				t.Fatal(err)
			}
			lease := &leases.Items[0]
			switch scenario {
			case "missing":
				leases.Items = leases.Items[1:]
			case "wrong-holder":
				lease.Spec.HolderIdentity = ptr.To("foreign-pod_10000000-0000-4000-8000-000000000099")
			case "stale":
				renew := metav1.NewMicroTime(now.Add(-16 * time.Second))
				lease.Spec.RenewTime = &renew
			case "uid":
				lease.UID = "10000000-0000-4000-8000-000000000013"
			case "rv-regression":
				lease.ResourceVersion = "100"
			case "renew-regression":
				renew := metav1.NewMicroTime(now.Add(-3 * time.Second))
				lease.Spec.RenewTime = &renew
			case "managed-regression":
				fieldTime := metav1.NewTime(now.Add(-3 * time.Second).Truncate(time.Second))
				lease.ManagedFields[0].Time = &fieldTime
			case "fieldset":
				lease.ManagedFields[0].FieldsV1.Raw = []byte(`{"f:spec":{"f:holderIdentity":{}}}`)
			case "transition":
				lease.Spec.LeaseTransitions = ptr.To[int32](1)
			case "data-label":
				lease.Labels = map[string]string{"arcade.gobha.me/destroy-uid": "intent"}
			case "extra-public-row":
				copy := pods.Items[0].DeepCopy()
				copy.Name, copy.UID, copy.OwnerReferences, copy.Labels = "unrelated", "unrelated", nil, map[string]string{"other": "other"}
				copy.GenerateName = ""
				copy.Spec.ServiceAccountName, copy.Spec.DeprecatedServiceAccount = "unrelated", ""
				pods.Items = append(pods.Items, *copy)
			}
			states, o, err = admissionClassifyObservationTest(t, v, ns, lists, d, plan, "")
			if err != nil {
				t.Fatal(err)
			}
			after, err := capturePhaseBaseline(o, states, now)
			if err == nil && samePhaseBaseline(before, after) {
				t.Fatalf("accepted changed leader/baseline %s", scenario)
			}
			body, _ := json.Marshal(before)
			if bytes.Contains(body, []byte("holderIdentity")) || bytes.Contains(body, []byte("fieldsV1")) {
				t.Fatal("baseline persisted raw runtime content")
			}
		})
	}
}

// Intrinsic time/identity refusals are independent of the client/server clock
// ordering regression exercised through the complete HTTPS initializer above.
func TestAdmissionInitialPhaseLeaderClockDomainsRemainBounded(t *testing.T) {
	plan := fixturePlan(t)
	v, ns, lists := readyControllerFixture(t, plan)
	d, err := installstate.Decode([]byte(ns.Annotations[installstate.Annotation]), plan)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	states, _, err := admissionClassifyObservationTest(t, v, ns, lists, d, plan, "")
	if err != nil || !states[0].Executing || len(states[0].Pods) != 1 {
		t.Fatal("original leader chain unavailable")
	}
	lease := phaseLeaderFixture(states[0].Pods[0], 0, now)
	lease.CreationTimestamp = metav1.NewTime(now.Add(-10 * time.Second).Truncate(time.Second))
	acquire := metav1.NewMicroTime(lease.CreationTimestamp.Add(-time.Second))
	lease.Spec.AcquireTime = &acquire
	original, err := capturePhaseLeader(ns.Name, &lease, states[0], now)
	if err != nil {
		t.Fatal("original client-acquired-before-server-created leader refused")
	}
	for _, scenario := range []string{"nil-acquire", "zero-acquire", "non-utc-acquire", "submicro-acquire", "acquire-after-renew", "future-creation", "future-renew", "stale-renew", "foreign-holder", "changed-acquisition", "changed-creation"} {
		t.Run(scenario, func(t *testing.T) {
			changed := lease.DeepCopy()
			wantValid := false
			switch scenario {
			case "nil-acquire":
				changed.Spec.AcquireTime = nil
			case "zero-acquire":
				changed.Spec.AcquireTime = &metav1.MicroTime{}
			case "non-utc-acquire":
				changed.Spec.AcquireTime.Time = changed.Spec.AcquireTime.In(time.FixedZone("foreign", 3600))
			case "submicro-acquire":
				changed.Spec.AcquireTime.Time = changed.Spec.AcquireTime.Add(time.Nanosecond)
			case "acquire-after-renew":
				changed.Spec.AcquireTime.Time = changed.Spec.RenewTime.Add(time.Microsecond)
			case "future-creation":
				changed.CreationTimestamp.Time = now.Add(2 * time.Second)
			case "future-renew":
				changed.Spec.RenewTime.Time = now.Add(2 * time.Second)
			case "stale-renew":
				// Isolate freshness, not the independent acquire <= renew rule.
				changed.Spec.AcquireTime.Time = now.Add(-20 * time.Second)
				changed.Spec.RenewTime.Time = now.Add(-16 * time.Second)
			case "foreign-holder":
				changed.Spec.HolderIdentity = ptr.To("foreign-pod_10000000-0000-4000-8000-000000000099")
			case "changed-acquisition":
				changed.Spec.AcquireTime.Time = changed.Spec.AcquireTime.Add(time.Microsecond)
				wantValid = true
			case "changed-creation":
				changed.CreationTimestamp.Time = changed.CreationTimestamp.Add(-time.Second)
				wantValid = true
			}
			observed, err := capturePhaseLeader(ns.Name, changed, states[0], now)
			if (err == nil) != wantValid {
				t.Fatal("leader clock/identity intrinsic refusal changed")
			}
			if wantValid {
				before := fixturePhaseBaseline{Version: "admission-phase-v1", Leaders: []fixturePhaseLeader{original}}
				after := fixturePhaseBaseline{Version: "admission-phase-v1", Leaders: []fixturePhaseLeader{observed}}
				if samePhaseBaseline(before, after) {
					t.Fatal("immutable acquisition/server creation changed between original reads")
				}
			}
		})
	}
}

func TestAdmissionInitialPhaseImmutableCompanionAndClosedShape(t *testing.T) {
	f := newFixture(t, false)
	ledger, err := f.engine.prepareFixtureLedger(t.Context(), f.snapshot)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.close()
	baseline := fixturePhaseBaseline{Version: "admission-phase-v1", Rows: []fixtureWorldRow{}, Leaders: []fixturePhaseLeader{}}
	initial := &initialAdmissionPhase{journal: f.snapshot, worlds: &coldWorldTuple{Servers: nil, Claims: nil, Volumes: nil}, baseline: baseline}
	if initial.seal(ledger) != nil {
		t.Fatal("phase publication failed")
	}
	d, err := ledger.loadOriginalWorlds()
	if err != nil || d.Phase == nil || !reflect.DeepEqual(*d.Phase, baseline) {
		t.Fatal("phase was not durably pinned")
	}
	if initial.seal(ledger) != ErrFixtures || f.engine.fixtureFence(f.snapshot) != ErrFixtures || f.access.writes != 0 {
		t.Fatal("phase replay granted effect or retired fence")
	}
	body, err := ledger.worldsBody(d)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{`null`, `{}`, `{"version":"admission-phase-v1","rows":[],"leaders":[],"foreign":true}`} {
		var fields map[string]json.RawMessage
		if json.Unmarshal(body, &fields) != nil {
			t.Fatal("shape setup")
		}
		fields["phase"] = json.RawMessage(raw)
		modified, _ := json.Marshal(fields)
		if _, err := ledger.decodeWorlds(modified); err != ErrFixtures {
			t.Fatal("accepted malformed/null/open phase")
		}
	}
	for _, mutate := range []func(*fixturePhaseBaseline){
		func(b *fixturePhaseBaseline) { b.Version = "v2" },
		func(b *fixturePhaseBaseline) { b.Rows = nil },
		func(b *fixturePhaseBaseline) { b.Leaders = nil },
		func(b *fixturePhaseBaseline) {
			b.Rows = []fixtureWorldRow{{Key: installstate.Key{APIVersion: "v1", Kind: "PersistentVolume", Name: "world"}, UID: "pv", ResourceVersion: "1", SHA256: strings.Repeat("a", 64)}}
		},
		func(b *fixturePhaseBaseline) {
			b.Rows = []fixtureWorldRow{{Key: installstate.Key{APIVersion: "v1", Kind: "Pod", Namespace: "foreign", Name: "pod"}, UID: "pod", ResourceVersion: "1", SHA256: strings.Repeat("a", 64)}}
		},
	} {
		copy := baseline
		mutate(&copy)
		modified := d
		modified.Phase = &copy
		if _, err := ledger.worldsBody(modified); err != ErrFixtures {
			t.Fatal("accepted malformed phase baseline")
		}
	}
	// World and phase rows cannot disagree even if each is independently valid.
	d.Rows = originalWorldRowsExample(t, ledger)
	if _, err := ledger.worldsBody(d); err != ErrFixtures {
		t.Fatal("phase omitted sealed original worlds")
	}
}

func TestAdmissionInitialPhaseRenewalFloorsAndAddressUniqueness(t *testing.T) {
	ns := "isolated-install"
	row := func(gv, kind, name, uid string) fixtureWorldRow {
		return fixtureWorldRow{installstate.Key{APIVersion: gv, Kind: kind, Namespace: ns, Name: name}, types.UID(uid), "101", strings.Repeat("a", 64)}
	}
	baseline := fixturePhaseBaseline{Version: "admission-phase-v1", Rows: []fixtureWorldRow{
		row("apps/v1", "Deployment", "arcadectl-controller", "parent"),
		row("apps/v1", "ReplicaSet", "arcadectl-controller-bcdfg", "set"),
		row("v1", "Pod", "arcadectl-controller-bcdfg-bcdfg", "pod"),
	}, Leaders: []fixturePhaseLeader{{Row: row("coordination.k8s.io/v1", "Lease", "controller.arcade.gobha.me", "10000000-0000-4000-8000-000000000011"), ParentUID: "parent", SetUID: "set", PodUID: "pod", RenewTime: "2026-10-07T12:00:00Z", ManagedTimes: []string{"2026-10-07T12:00:00Z"}}}}
	if baseline.validate(ns) != nil {
		t.Fatal("valid structural leader evidence refused")
	}
	clone := func() fixturePhaseBaseline {
		body, _ := json.Marshal(baseline)
		var copy fixturePhaseBaseline
		if json.Unmarshal(body, &copy) != nil {
			t.Fatal("copy failed")
		}
		return copy
	}
	for _, scenario := range []string{"same-rv-renewal", "same-rv-managed", "new-rv", "new-rv-renewal", "new-rv-managed"} {
		after := clone()
		if strings.HasPrefix(scenario, "new-rv") {
			after.Leaders[0].Row.ResourceVersion = "102"
		}
		if strings.HasSuffix(scenario, "renewal") {
			after.Leaders[0].RenewTime = "2026-10-07T12:00:01Z"
		}
		if strings.HasSuffix(scenario, "managed") {
			after.Leaders[0].ManagedTimes[0] = "2026-10-07T12:00:01Z"
		}
		if samePhaseBaseline(baseline, after) != strings.HasPrefix(scenario, "new-rv") {
			t.Fatalf("RV/body advancement rule violated: %s", scenario)
		}
		if strings.HasPrefix(scenario, "new-rv") && samePhaseBaseline(after, baseline) {
			t.Fatalf("newest accepted floor regressed: %s", scenario)
		}
	}
	duplicate := clone()
	duplicate.Rows = append(duplicate.Rows, row("coordination.k8s.io/v1", "Lease", "controller.arcade.gobha.me", "10000000-0000-4000-8000-000000000012"))
	sortFixtureWorlds(duplicate.Rows)
	if duplicate.validate(ns) != ErrFixtures {
		t.Fatal("duplicate address split across ordinary and leader rows accepted")
	}
	for _, kind := range []string{"Pod", "Lease", "Secret"} {
		public := clone()
		name := "arcadectl-controller-bcdfg-bcdfg"
		if kind == "Lease" {
			name = "controller.arcade.gobha.me"
		}
		public.Public = []fixtureWorldRow{row("v1", kind, name, "different-original")}
		if kind == "Lease" {
			public.Public[0].Key.APIVersion = "coordination.k8s.io/v1"
		}
		if public.validate(ns) != ErrFixtures {
			t.Fatal("typed/leader/Secret kind admitted in public inventory", kind)
		}
	}
}
