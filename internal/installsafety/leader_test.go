// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installsafety

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	arcade "github.com/gobha-me/arcadectl/api/v1alpha1"
	platformkube "github.com/gobha-me/arcadectl/internal/platform/kube"
	batchv1 "k8s.io/api/batch/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
)

func nativeLeaderLease(name string) coordinationv1.Lease {
	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	acquired := metav1.NewMicroTime(created.Add(123456 * time.Microsecond))
	renewed := metav1.NewMicroTime(acquired.Add(2 * time.Second))
	return coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{
		Name: name, Namespace: "isolated-install", UID: "fbef956f-ea1e-4767-a68d-5d6c09dce0e1",
		ResourceVersion: "123", CreationTimestamp: metav1.NewTime(created),
	}, Spec: coordinationv1.LeaseSpec{
		HolderIdentity:       ptr.To("arcadectl-controller-768ddf9876-abcde_f574737a-d643-4f5a-9cf6-8af21889c181"),
		LeaseDurationSeconds: ptr.To[int32](15), AcquireTime: &acquired, RenewTime: &renewed,
		LeaseTransitions: ptr.To[int32](0),
	}}
}

func TestNativeControllerElectionLeaseNotDataOperation(t *testing.T) {
	plan, s, inventory := safetyFixture(t)
	// No controller Pod is present. An expired, ownerless native election Lease
	// remains after shutdown; it cannot execute a data operation or prove runtime
	// readiness. Stale renewals must not obstruct retaining uninstall.
	for _, name := range []string{"controller.arcade.gobha.me", "destroy-controller.arcade.gobha.me"} {
		s.Leases.Items = []coordinationv1.Lease{nativeLeaderLease(name)}
		before := cloneSnapshot(s)
		if err := Validate(plan, s, inventory); err != nil {
			t.Fatalf("native %s: %v", name, err)
		}
		if !reflect.DeepEqual(before, s) {
			t.Fatal("election classification mutated the observation")
		}
	}
	f := newColdFixture(t, false)
	f.s.Leases.Items = []coordinationv1.Lease{nativeLeaderLease("controller.arcade.gobha.me"), nativeLeaderLease("destroy-controller.arcade.gobha.me")}
	f.s.Leases.Items[1].UID = "bf249b0a-671c-4d04-ad76-889473f80914"
	if err := f.validate(); err != nil {
		t.Fatalf("ordinary cold-world validation with shutdown election tails: %v", err)
	}
}

func TestNativeControllerElectionLeaseNeverMasksWorkerSignals(t *testing.T) {
	plan, base, inventory := safetyFixture(t)
	for _, change := range []struct {
		name  string
		apply func(*coordinationv1.Lease)
	}{
		{"data-label", func(l *coordinationv1.Lease) { l.Labels = map[string]string{platformkube.LabelDataIdentity: "world"} }},
		{"operation-label", func(l *coordinationv1.Lease) {
			l.Labels = map[string]string{platformkube.LabelDataOperation: "destroy"}
		}},
		{"backup-label", func(l *coordinationv1.Lease) { l.Labels = map[string]string{platformkube.LabelBackupUID: "backup"} }},
		{"restore-label", func(l *coordinationv1.Lease) { l.Labels = map[string]string{platformkube.LabelRestoreUID: "restore"} }},
		{"destroy-label", func(l *coordinationv1.Lease) { l.Labels = map[string]string{platformkube.LabelDestroyUID: "destroy"} }},
		{"worker-label", func(l *coordinationv1.Lease) { l.Labels = map[string]string{platformkube.LabelName: "destroy-worker"} }},
		{"receipt-label", func(l *coordinationv1.Lease) {
			l.Labels = map[string]string{"arcade.gobha.me/operation-uid": "receipt"}
		}},
		{"unknown-label", func(l *coordinationv1.Lease) { l.Labels = map[string]string{"other": ""} }},
		{"worker-annotation", func(l *coordinationv1.Lease) {
			l.Annotations = map[string]string{platformkube.AnnotationWorkerPodUID: "pod"}
		}},
		{"backup-annotation", func(l *coordinationv1.Lease) {
			l.Annotations = map[string]string{"arcade.gobha.me/backup-name": "backup"}
		}},
		{"restore-annotation", func(l *coordinationv1.Lease) {
			l.Annotations = map[string]string{"arcade.gobha.me/restore-name": "restore"}
		}},
		{"destroy-annotation", func(l *coordinationv1.Lease) {
			l.Annotations = map[string]string{"arcade.gobha.me/destroy-name": "destroy"}
		}},
		{"unknown-annotation", func(l *coordinationv1.Lease) { l.Annotations = map[string]string{"other": ""} }},
		{"operation-owner", func(l *coordinationv1.Lease) {
			l.OwnerReferences = []metav1.OwnerReference{{APIVersion: arcade.GroupVersion.String(), Kind: "GameDestroy", Name: "destroy", UID: "destroy"}}
		}},
		{"foreign-owner", func(l *coordinationv1.Lease) {
			l.OwnerReferences = []metav1.OwnerReference{{APIVersion: "v1", Kind: "Pod", Name: "other", UID: "other"}}
		}},
		{"generate-name", func(l *coordinationv1.Lease) { l.GenerateName = "destroy-" }},
		{"finalizer", func(l *coordinationv1.Lease) { l.Finalizers = []string{"other/hold"} }},
		{"deletion", func(l *coordinationv1.Lease) { l.DeletionTimestamp = ptr.To(metav1.Now()) }},
		{"deletion-grace", func(l *coordinationv1.Lease) { l.DeletionGracePeriodSeconds = ptr.To[int64](0) }},
		{"duration-absent", func(l *coordinationv1.Lease) { l.Spec.LeaseDurationSeconds = nil }},
		{"duration-other", func(l *coordinationv1.Lease) { l.Spec.LeaseDurationSeconds = ptr.To[int32](30) }},
		{"holder-absent", func(l *coordinationv1.Lease) { l.Spec.HolderIdentity = nil }},
		{"holder-empty", func(l *coordinationv1.Lease) { l.Spec.HolderIdentity = ptr.To("") }},
		{"holder-bare-uuid", func(l *coordinationv1.Lease) { l.Spec.HolderIdentity = ptr.To("f574737a-d643-4f5a-9cf6-8af21889c181") }},
		{"holder-bad-host", func(l *coordinationv1.Lease) {
			l.Spec.HolderIdentity = ptr.To("Not-A-Pod_f574737a-d643-4f5a-9cf6-8af21889c181")
		}},
		{"holder-bad-uuid", func(l *coordinationv1.Lease) { l.Spec.HolderIdentity = ptr.To("pod_not-a-uuid") }},
		{"holder-nil-uuid", func(l *coordinationv1.Lease) {
			l.Spec.HolderIdentity = ptr.To("pod_00000000-0000-0000-0000-000000000000")
		}},
		{"holder-upper-uuid", func(l *coordinationv1.Lease) {
			l.Spec.HolderIdentity = ptr.To("pod_F574737A-D643-4F5A-9CF6-8AF21889C181")
		}},
		{"holder-extra-part", func(l *coordinationv1.Lease) {
			l.Spec.HolderIdentity = ptr.To("pod_other_f574737a-d643-4f5a-9cf6-8af21889c181")
		}},
		{"acquire-absent", func(l *coordinationv1.Lease) { l.Spec.AcquireTime = nil }},
		{"acquire-zero", func(l *coordinationv1.Lease) { l.Spec.AcquireTime = &metav1.MicroTime{} }},
		{"renew-absent", func(l *coordinationv1.Lease) { l.Spec.RenewTime = nil }},
		{"renew-zero", func(l *coordinationv1.Lease) { l.Spec.RenewTime = &metav1.MicroTime{} }},
		{"renew-before-acquire", func(l *coordinationv1.Lease) { l.Spec.RenewTime.Time = l.Spec.AcquireTime.Add(-time.Second) }},
		{"nanosecond-renewal", func(l *coordinationv1.Lease) { l.Spec.RenewTime.Time = l.Spec.RenewTime.Add(time.Nanosecond) }},
		{"transitions-absent", func(l *coordinationv1.Lease) { l.Spec.LeaseTransitions = nil }},
		{"transitions-negative", func(l *coordinationv1.Lease) { l.Spec.LeaseTransitions = ptr.To[int32](-1) }},
		{"preferred-holder", func(l *coordinationv1.Lease) { l.Spec.PreferredHolder = ptr.To("other") }},
		{"strategy", func(l *coordinationv1.Lease) { l.Spec.Strategy = ptr.To(coordinationv1.OldestEmulationVersion) }},
		{"creation-absent", func(l *coordinationv1.Lease) { l.CreationTimestamp = metav1.Time{} }},
	} {
		for _, name := range []string{"controller.arcade.gobha.me", "destroy-controller.arcade.gobha.me"} {
			t.Run(name+"/"+change.name, func(t *testing.T) {
				s := cloneSnapshot(base)
				l := nativeLeaderLease(name)
				change.apply(&l)
				s.Leases.Items = []coordinationv1.Lease{l}
				if err := Validate(plan, s, inventory); !errors.Is(err, ErrWorker) {
					t.Fatalf("reserved name masked malformed/worker lease: %v", err)
				}
			})
		}
	}
	for _, kind := range []string{"GameBackup", "GameRestore", "GameDestroy", "ArcadeOperation"} {
		s := cloneSnapshot(base)
		l := nativeLeaderLease("destroy-controller.arcade.gobha.me")
		m := objectMeta("operation")
		// Even a syntactically perfect election holder must not erase the
		// independent exact operation-UID match (UIDs are opaque to this check).
		m.UID = types.UID(*l.Spec.HolderIdentity)
		switch kind {
		case "GameBackup":
			s.Backups.Items = []arcade.GameBackup{{ObjectMeta: m, Status: arcade.GameBackupStatus{DataOperationStatus: arcade.DataOperationStatus{ObservedGeneration: 1, Phase: arcade.DataPhaseSucceeded}}}}
		case "GameRestore":
			s.Restores.Items = []arcade.GameRestore{{ObjectMeta: m, Status: arcade.GameRestoreStatus{DataOperationStatus: arcade.DataOperationStatus{ObservedGeneration: 1, Phase: arcade.DataPhaseSucceeded}}}}
		case "GameDestroy":
			s.Destroys.Items = []arcade.GameDestroy{{ObjectMeta: m, Status: arcade.GameDestroyStatus{ObservedGeneration: 1, Phase: arcade.DestroyPhaseCancelled}}}
		case "ArcadeOperation":
			s.Operations.Items = []arcade.ArcadeOperation{{ObjectMeta: m, Status: arcade.ArcadeOperationStatus{ObservedGeneration: 1, Phase: arcade.OperationPhaseSucceeded}}}
		}
		s.Leases.Items = []coordinationv1.Lease{l}
		if err := Validate(plan, s, inventory); !errors.Is(err, ErrWorker) {
			t.Fatalf("%s holder was masked: %v", kind, err)
		}
	}
}

func TestControllerElectionNameNeverExemptsPodJobOrDerivedFence(t *testing.T) {
	plan, base, inventory := safetyFixture(t)
	for _, name := range []string{"destroy-controller.arcade.gobha.me", "destroy-controller.arcade.gobha.me-extra", "destroy-worker-" + strings.Repeat("a", 32), "destroy-controller.arcade.gobha.me.evil"} {
		for _, kind := range []string{"Pod", "Job", "Lease"} {
			if name == "destroy-controller.arcade.gobha.me" && kind == "Lease" {
				continue
			}
			s := cloneSnapshot(base)
			switch kind {
			case "Pod":
				s.Pods.Items = []corev1.Pod{{ObjectMeta: objectMeta(name)}}
			case "Job":
				s.Jobs.Items = []batchv1.Job{{ObjectMeta: objectMeta(name)}}
			case "Lease":
				l := nativeLeaderLease(name)
				s.Leases.Items = []coordinationv1.Lease{l}
			}
			if err := Validate(plan, s, inventory); !errors.Is(err, ErrWorker) {
				t.Fatalf("%s %s: %v", kind, name, err)
			}
		}
	}
	for _, name := range []string{platformkube.DataOperationLeaseName("world"), platformkube.DestroyWorkerLeaseName("destroy")} {
		s := cloneSnapshot(base)
		s.Leases.Items = []coordinationv1.Lease{nativeLeaderLease(name)}
		if err := Validate(plan, s, inventory); !errors.Is(err, ErrWorker) {
			t.Fatalf("derived fence %s: %v", name, err)
		}
	}
}
