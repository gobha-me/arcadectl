//go:build kindinstall

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"reflect"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installstate"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Exercise the actual native-test validator without starting a cluster. Client
// acquisition and server creation use independent clocks; live renewal freshness
// and the original signed-role Pod holder binding remain mandatory.
func TestWarmNativeLeaderClockDomainsRemainBounded(t *testing.T) {
	_, ns, lists := readyControllerFixture(t, fixturePlan(t))
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	created := now.Add(-10 * time.Second)
	roles := []struct {
		name, account, election string
		podKey, leaseKey        installstate.Key
	}{
		{name: "controller", account: "arcadectl-controller", election: "controller.arcade.gobha.me"},
		{name: "destroy-controller", account: "arcadectl-destroy-controller", election: "destroy-controller.arcade.gobha.me"},
	}
	template := map[installstate.Key]*unstructured.Unstructured{}
	pods := lists["Pod"].(*corev1.PodList)
	for index := range roles {
		role := &roles[index]
		for i := range pods.Items {
			pod := &pods.Items[i]
			if pod.Spec.ServiceAccountName != role.account {
				continue
			}
			if role.podKey.Name != "" {
				t.Fatal("ambiguous original signed-role Pod")
			}
			role.podKey = installstate.Key{APIVersion: "v1", Kind: "Pod", Namespace: ns.Name, Name: pod.Name}
			role.leaseKey = installstate.Key{APIVersion: "coordination.k8s.io/v1", Kind: "Lease", Namespace: ns.Name, Name: role.election}
			template[role.podKey] = servingObject(t, pod)
			lease := phaseLeaderFixture(pod, index, now)
			lease.CreationTimestamp = metav1.NewTime(created)
			acquire := metav1.NewMicroTime(created.Add(time.Second))
			lease.Spec.AcquireTime = &acquire
			template[role.leaseKey] = servingObject(t, &lease)
		}
		if role.podKey.Name == "" {
			t.Fatal("original signed-role Pod unavailable")
		}
	}
	clone := func(objects map[installstate.Key]*unstructured.Unstructured) map[installstate.Key]*unstructured.Unstructured {
		result := make(map[installstate.Key]*unstructured.Unstructured, len(objects))
		for key, object := range objects {
			result[key] = object.DeepCopy()
		}
		return result
	}
	set := func(object *unstructured.Unstructured, value any, fields ...string) {
		t.Helper()
		if unstructured.SetNestedField(object.Object, value, fields...) != nil {
			t.Fatal("clock regression fixture field unavailable")
		}
	}
	canonical := func(instant time.Time) string { return instant.UTC().Format("2006-01-02T15:04:05.000000Z") }
	check := func(t *testing.T, baseline, current map[installstate.Key]*unstructured.Unstructured, wantValid bool) {
		t.Helper()
		before, after := clone(baseline), clone(current)
		err := warmNativeLeaders(baseline, current, now)
		if wantValid && err != nil {
			t.Error("legitimate client-before-server leader clocks refused")
		}
		if !wantValid && err != ErrFixtures {
			t.Error("invalid leader evidence accepted or refusal changed")
		}
		if !reflect.DeepEqual(before, baseline) || !reflect.DeepEqual(after, current) {
			t.Error("leader clock validation mutated original or current evidence")
		}
	}
	for _, selection := range []struct {
		name    string
		indices []int
	}{
		{"controller", []int{0}},
		{"destroy-controller", []int{1}},
		{"both", []int{0, 1}},
	} {
		for _, offset := range []struct {
			name     string
			duration time.Duration
		}{{"microsecond", time.Microsecond}, {"second", time.Second}} {
			t.Run(selection.name+"/"+offset.name, func(t *testing.T) {
				baseline := clone(template)
				for _, index := range selection.indices {
					set(baseline[roles[index].leaseKey], canonical(created.Add(-offset.duration)), "spec", "acquireTime")
				}
				current := clone(baseline)
				check(t, baseline, current, true)
				for _, role := range roles {
					lease := current[role.leaseKey]
					lease.SetResourceVersion("102")
					set(lease, canonical(now.Add(-time.Second)), "spec", "renewTime")
					fields := lease.GetManagedFields()
					for i := range fields {
						updated := metav1.NewTime(now.Add(-time.Second))
						fields[i].Time = &updated
					}
					lease.SetManagedFields(fields)
				}
				check(t, baseline, current, true)
			})
		}
	}
	// Each fault is isolated to each original role; the other leader stays valid.
	// The holder suffix is an independent controller-runtime UUID, not a Pod UID.
	faults := []string{
		"missing-acquire", "null-acquire", "zero-acquire", "year-zero-acquire", "non-utc-acquire", "submicro-acquire", "noncanonical-acquire", "acquire-after-renew",
		"future-creation", "future-renew", "stale-renew", "missing-holder", "foreign-pod-holder", "invalid-holder-suffix", "wrong-service-account",
		"invalid-original-uid", "changed-current-uid", "invalid-original-rv", "rv-regression", "missing-current", "missing-original", "unknown-election",
		"renew-regression", "managed-regression", "changed-acquisition", "changed-creation", "changed-duration", "changed-metadata", "added-status",
	}
	for _, role := range roles {
		for _, fault := range faults {
			t.Run(role.name+"/refuse-"+fault, func(t *testing.T) {
				baseline := clone(template)
				original := baseline[role.leaseKey]
				switch fault {
				case "missing-acquire":
					unstructured.RemoveNestedField(original.Object, "spec", "acquireTime")
				case "null-acquire":
					set(original, nil, "spec", "acquireTime")
				case "zero-acquire":
					set(original, "0001-01-01T00:00:00.000000Z", "spec", "acquireTime")
				case "year-zero-acquire":
					set(original, "0000-01-01T00:00:00.000000Z", "spec", "acquireTime")
				case "non-utc-acquire":
					set(original, created.Add(time.Second).In(time.FixedZone("synthetic", 3600)).Format("2006-01-02T15:04:05.000000Z07:00"), "spec", "acquireTime")
				case "submicro-acquire":
					set(original, created.Add(time.Second+time.Nanosecond).Format(time.RFC3339Nano), "spec", "acquireTime")
				case "noncanonical-acquire":
					set(original, created.Add(time.Second).Format(time.RFC3339), "spec", "acquireTime")
				case "acquire-after-renew":
					set(original, canonical(now.Add(-time.Second)), "spec", "acquireTime")
				case "future-creation":
					original.SetCreationTimestamp(metav1.NewTime(now.Add(2 * time.Second)))
				case "future-renew":
					set(original, canonical(now.Add(2*time.Second)), "spec", "renewTime")
				case "stale-renew":
					set(original, canonical(now.Add(-20*time.Second)), "spec", "acquireTime")
					set(original, canonical(now.Add(-16*time.Second)), "spec", "renewTime")
				case "missing-holder":
					unstructured.RemoveNestedField(original.Object, "spec", "holderIdentity")
				case "foreign-pod-holder":
					set(original, "foreign-pod_10000000-0000-4000-8000-000000000099", "spec", "holderIdentity")
				case "invalid-holder-suffix":
					set(original, role.podKey.Name+"_not-a-native-uuid", "spec", "holderIdentity")
				case "wrong-service-account":
					set(baseline[role.podKey], "foreign-account", "spec", "serviceAccountName")
				case "invalid-original-uid":
					original.SetUID("not-a-native-uuid")
				case "invalid-original-rv":
					original.SetResourceVersion("not-a-resource-version")
				case "missing-original":
					delete(baseline, role.leaseKey)
				case "unknown-election":
					delete(baseline, role.leaseKey)
					key := role.leaseKey
					key.Name = "unrelated-election"
					original.SetName(key.Name)
					baseline[key] = original
				}
				current := clone(baseline)
				switch fault {
				case "changed-current-uid":
					current[role.leaseKey].SetUID("10000000-0000-4000-8000-000000000088")
				case "rv-regression":
					current[role.leaseKey].SetResourceVersion("100")
				case "missing-current":
					delete(current, role.leaseKey)
				case "renew-regression":
					set(current[role.leaseKey], canonical(now.Add(-3*time.Second)), "spec", "renewTime")
				case "managed-regression":
					fields := current[role.leaseKey].GetManagedFields()
					for i := range fields {
						regressed := metav1.NewTime(now.Add(-3 * time.Second))
						fields[i].Time = &regressed
					}
					current[role.leaseKey].SetManagedFields(fields)
				case "changed-acquisition":
					set(current[role.leaseKey], canonical(created.Add(time.Second+time.Microsecond)), "spec", "acquireTime")
				case "changed-creation":
					current[role.leaseKey].SetCreationTimestamp(metav1.NewTime(created.Add(-time.Second)))
				case "changed-duration":
					set(current[role.leaseKey], int64(16), "spec", "leaseDurationSeconds")
				case "changed-metadata":
					current[role.leaseKey].SetLabels(map[string]string{"untrusted": "value"})
				case "added-status":
					set(current[role.leaseKey], map[string]any{}, "status")
				}
				check(t, baseline, current, false)
			})
		}
	}
}
