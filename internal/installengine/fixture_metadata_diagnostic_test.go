// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestTypedMetadataDiagnosticExactProjectionAndClosedLabels(t *testing.T) {
	wanted := metav1.ObjectMeta{Name: "original", Namespace: "isolated", UID: "original-uid", ResourceVersion: "91", Generation: 1}
	for _, test := range []struct {
		field string
		edit  func(*metav1.ObjectMeta)
	}{
		{"name", func(o *metav1.ObjectMeta) { o.Name = "PRIVATE-CANARY" }},
		{"namespace", func(o *metav1.ObjectMeta) { o.Namespace = "PRIVATE-CANARY" }},
		{"uid", func(o *metav1.ObjectMeta) { o.UID = "PRIVATE-CANARY" }},
		{"resource-version", func(o *metav1.ObjectMeta) { o.ResourceVersion = "PRIVATE-CANARY" }},
		{"generation", func(o *metav1.ObjectMeta) { o.Generation++ }},
		{"owner-references", func(o *metav1.ObjectMeta) { o.OwnerReferences = []metav1.OwnerReference{{Name: "PRIVATE-CANARY"}} }},
		{"deletion-timestamp", func(o *metav1.ObjectMeta) { now := metav1.NewTime(time.Unix(1, 0)); o.DeletionTimestamp = &now }},
		{"other", func(o *metav1.ObjectMeta) { o.Labels = map[string]string{"PRIVATE-CANARY": "PRIVATE-CANARY"} }},
	} {
		t.Run(test.field, func(t *testing.T) {
			observed := *wanted.DeepCopy()
			test.edit(&observed)
			ctx, d := WithLifecycleDiagnostic(t.Context())
			beginTypedMetadataDiagnostic(ctx)("Pod", observed, wanted)
			if reflect.DeepEqual(observed, wanted) || d.TypedMetadataSnapshot() != "kind=Pod field="+test.field || strings.Contains(d.TypedMetadataSnapshot(), "CANARY") {
				t.Fatal("exact mismatch missing or values escaped", d.TypedMetadataSnapshot())
			}
		})
	}
	// First-different-field precedence cannot turn a multi-field mismatch into
	// a diagnosis of the newest observation, a retry or successful comparison.
	observed := wanted
	observed.Name, observed.ResourceVersion = "changed", "92"
	if typedMetadataMismatchField(observed, wanted) != 1 {
		t.Fatal("first mismatch precedence changed")
	}
	if typedMetadataMismatchField(wanted, wanted) != 0 {
		t.Fatal("equal metadata invented mismatch")
	}
	for _, owners := range []struct{ observed, wanted []metav1.OwnerReference }{
		{nil, []metav1.OwnerReference{}},
		{[]metav1.OwnerReference{{Name: "a"}, {Name: "b"}}, []metav1.OwnerReference{{Name: "b"}, {Name: "a"}}},
		{[]metav1.OwnerReference{{Controller: new(bool)}}, []metav1.OwnerReference{{}}},
		{[]metav1.OwnerReference{{BlockOwnerDeletion: new(bool)}}, []metav1.OwnerReference{{}}},
	} {
		a, b := wanted, wanted
		a.OwnerReferences, b.OwnerReferences = owners.observed, owners.wanted
		if reflect.DeepEqual(a, b) || typedMetadataMismatchField(a, b) != 6 {
			t.Fatal("owner order, flags or nil/empty semantics normalized")
		}
	}
	a, b := wanted, wanted
	utc := metav1.NewTime(time.Unix(1, 0).UTC())
	zone := metav1.NewTime(time.Unix(1, 0).In(time.FixedZone("PRIVATE-CANARY", 0)))
	a.DeletionTimestamp, b.DeletionTimestamp = &utc, &zone
	if !utc.Equal(&zone) || reflect.DeepEqual(a, b) || typedMetadataMismatchField(a, b) != 7 {
		t.Fatal("exact timestamp representation mismatch normalized")
	}
	// Every admitted kind is finite and known; arbitrary canaries never become
	// output. VolumeAttachment is not a phase correlation collection.
	wantKinds := []string{"unknown", "GameServer", "GameBackup", "GameRestore", "GameDestroy", "ArcadeOperation", "Job", "Pod", "Lease", "PersistentVolumeClaim", "Secret", "ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding", "Deployment", "ReplicaSet", "StatefulSet", "DaemonSet", "ReplicationController", "CronJob", "EndpointSlice", "ServiceAccount"}
	if !reflect.DeepEqual(typedMetadataKinds[:], wantKinds) {
		t.Fatal("reviewed phase-kind whitelist changed")
	}
	for _, kind := range append(append([]string{}, wantKinds...), "PRIVATE-CANARY", "Pod\nPRIVATE-CANARY", "VolumeAttachment") {
		ctx, d := WithLifecycleDiagnostic(t.Context())
		observed = wanted
		observed.ResourceVersion = "PRIVATE-CANARY"
		beginTypedMetadataDiagnostic(ctx)(kind, observed, wanted)
		label := "unknown"
		for _, known := range wantKinds {
			if kind == known {
				label = known
			}
		}
		if got := d.TypedMetadataSnapshot(); got != "kind="+label+" field=resource-version" || len(got) > 80 || strings.Contains(got, "CANARY") {
			t.Fatal("kind escaped fixed output", got)
		}
	}
	for _, corrupt := range []uint32{0, 255, 1 << 16, 0xffffffff, uint32(len(typedMetadataKinds))<<8 | 1, 1<<8 | uint32(len(typedMetadataFields))} {
		trace := &admissionTrace{}
		recorder := &typedMetadataDiagnostic{}
		recorder.value.Store(corrupt)
		trace.typedMetadata.Store(recorder)
		if trace.typedMetadataSnapshot() != "" {
			t.Fatal("corrupt numeric label exposed")
		}
	}
	if (*LifecycleDiagnostic)(nil).TypedMetadataSnapshot() != "" || (*admissionTrace)(nil).typedMetadataSnapshot() != "" {
		t.Fatal("nil diagnostic invented mismatch")
	}
}

func TestTypedMetadataDiagnosticInvocationAndResetIsolation(t *testing.T) {
	wanted := metav1.ObjectMeta{ResourceVersion: "91"}
	observed := metav1.ObjectMeta{ResourceVersion: "92"}
	for _, ctx := range []context.Context{nil, t.Context(), context.WithValue(t.Context(), admissionTraceKey{}, "PRIVATE-CANARY"), context.WithValue(t.Context(), admissionTraceKey{}, (*admissionTrace)(nil))} {
		beginTypedMetadataDiagnostic(ctx)("PRIVATE-CANARY", observed, wanted)
	}
	for _, reset := range []string{"invocation", "phase", "outer", "checkpoint", "fresh-step"} {
		t.Run(reset, func(t *testing.T) {
			ctx, d := WithLifecycleDiagnostic(t.Context())
			old := beginTypedMetadataDiagnostic(ctx)
			old("Pod", observed, wanted)
			if d.TypedMetadataSnapshot() != "kind=Pod field=resource-version" {
				t.Fatal("initial refusal missing")
			}
			switch reset {
			case "invocation":
				beginTypedMetadataDiagnostic(ctx)
			case "phase":
				traceAdmissionPhase(ctx, admissionPhaseOriginal, -1)
			case "outer":
				traceAdmission(ctx, admissionSetupPreview, 9)
			case "checkpoint":
				traceLifecycleCheckpoint(ctx, AdmissionEffective, lifecycleDiagnosticEntered)
			case "fresh-step":
				ctx, d = WithLifecycleDiagnostic(ctx)
			}
			old("Secret", observed, wanted)
			if d.TypedMetadataSnapshot() != "" {
				t.Fatal("late old completion survived reset")
			}
			current := beginTypedMetadataDiagnostic(ctx)
			current("ServiceAccount", wanted, wanted)
			if d.TypedMetadataSnapshot() != "" {
				t.Fatal("unfinished/equal observation invented refusal")
			}
			current("ServiceAccount", observed, wanted)
			var joined sync.WaitGroup
			for range 4 {
				joined.Go(func() {
					for range 100 {
						old("Secret", observed, wanted)
						if d.TypedMetadataSnapshot() != "kind=ServiceAccount field=resource-version" {
							t.Error("concurrent earlier completion replaced current diagnostic")
						}
					}
				})
			}
			joined.Wait()
			before := d.TypedMetadataSnapshot()
			traceAdmission(ctx, admissionStep(255), 99999)
			traceAdmissionPhase(ctx, admissionPhaseStep(255), 99999)
			if d.TypedMetadataSnapshot() != before || len(d.Snapshot()) > 256 {
				t.Fatal("invalid reset or enlarged existing snapshot")
			}
		})
	}
	ctx, cancel := context.WithCancelCause(t.Context())
	cancel(context.Canceled)
	ctx, d := WithLifecycleDiagnostic(ctx)
	beginTypedMetadataDiagnostic(ctx)("Pod", observed, wanted)
	if ctx.Err() != context.Canceled || context.Cause(ctx) != context.Canceled || d.TypedMetadataSnapshot() != "kind=Pod field=resource-version" {
		t.Fatal("diagnostic changed cancellation")
	}
}
