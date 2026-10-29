// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installobserve"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestTypedMetadataDetailRemainsClosedAndDoesNotChangeInputs(t *testing.T) {
	wanted := metav1.ObjectMeta{Name: "PRIVATE-METADATA-CANARY", Namespace: "PRIVATE-METADATA-CANARY", UID: "PRIVATE-METADATA-CANARY", ResourceVersion: "91"}
	for _, test := range []struct {
		name, rv, order, metadata string
		scope                     int
		labels                    bool
	}{
		{"nonfixture-greater", "92", "greater", "rv-only", -1, false},
		{"fixture-less", "90", "less", "rv-only", fixturePlainPod, false},
		{"metadata-beyond-rv", "92", "greater", "beyond-rv", fixturePlainPod, true},
		{"same-rv-other-metadata", "91", "equal", "beyond-rv", -1, true},
		{"invalid-rv", "PRIVATE-METADATA-CANARY", "unknown", "rv-only", -1, false},
		{"noncanonical-rv", "092", "unknown", "rv-only", -1, false},
		{"overflow-rv", strings.Repeat("9", 100), "unknown", "rv-only", -1, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			observed := *wanted.DeepCopy()
			observed.ResourceVersion = test.rv
			if test.labels {
				observed.Labels = map[string]string{"PRIVATE-METADATA-CANARY": "PRIVATE-METADATA-CANARY"}
			}
			beforeObserved, beforeWanted := observed.DeepCopy(), wanted.DeepCopy()
			ctx, diagnostic := WithLifecycleDiagnostic(t.Context())
			beginTypedMetadataScopedDiagnostic(ctx)("Pod", observed, wanted, test.scope)
			label := "nonfixture"
			if test.scope >= 0 {
				label = "fixture"
			}
			want := "scope=" + label + " slot=" + strconv.Itoa(test.scope) + " gc-rv-order=" + test.order + " metadata=" + test.metadata
			if got := diagnostic.TypedMetadataDetailSnapshot(); got != want || strings.Contains(got, "CANARY") || len(got) > 120 {
				t.Fatalf("closed refusal detail mismatch: %q", got)
			}
			if !reflect.DeepEqual(observed, *beforeObserved) || !reflect.DeepEqual(wanted, *beforeWanted) || reflect.DeepEqual(observed, wanted) {
				t.Fatal("diagnostic mutated input metadata or rescued the refused comparison")
			}
		})
	}
}

func TestTypedMetadataDetailResetAndLateWriterIsolation(t *testing.T) {
	observed, wanted := metav1.ObjectMeta{ResourceVersion: "92"}, metav1.ObjectMeta{ResourceVersion: "91"}
	ctx, diagnostic := WithLifecycleDiagnostic(t.Context())
	old := beginTypedMetadataScopedDiagnostic(ctx)
	old("Pod", observed, wanted, -1)
	if diagnostic.TypedMetadataDetailSnapshot() == "" {
		t.Fatal("initial detail absent")
	}
	old("Pod", observed, wanted, -2)
	if diagnostic.TypedMetadataDetailSnapshot() != "" {
		t.Fatal("unclassified comparison retained previous detail")
	}
	old("Pod", observed, wanted, fixturePlainPod)
	traceAdmissionPhase(ctx, admissionPhaseOriginal, -1)
	current := beginTypedMetadataScopedDiagnostic(ctx)
	current("Pod", observed, wanted, -1)
	want := diagnostic.TypedMetadataDetailSnapshot()
	var writers sync.WaitGroup
	for range 4 {
		writers.Go(func() {
			for range 100 {
				old("Pod", observed, wanted, fixturePlainPod)
				if diagnostic.TypedMetadataDetailSnapshot() != want {
					t.Error("late detached recorder republished old detail")
				}
			}
		})
	}
	writers.Wait()
	beginTypedMetadataDiagnostic(ctx)("Pod", observed, wanted)
	if diagnostic.TypedMetadataDetailSnapshot() != "" || diagnostic.TypedMetadataSnapshot() != "kind=Pod field=resource-version" {
		t.Fatal("legacy metadata diagnostic changed its output or invented detail")
	}
	if (*LifecycleDiagnostic)(nil).TypedMetadataDetailSnapshot() != "" || (*admissionTrace)(nil).typedMetadataDetailSnapshot() != "" {
		t.Fatal("nil diagnostic invented detail")
	}
	for _, corrupt := range []uint32{0, 255, 1 | 4<<8 | 1<<16, 1 | 3<<16, 0xffffffff} {
		current = beginTypedMetadataScopedDiagnostic(ctx)
		current("Pod", observed, wanted, -1)
		diagnostic.admission.typedMetadata.Load().detail.Store(corrupt)
		if diagnostic.TypedMetadataDetailSnapshot() != "" {
			t.Fatal("unreviewed numeric labels escaped")
		}
	}
	for _, scope := range []int{-2, -99, fixtureMaxSlots, 999999} {
		current = beginTypedMetadataScopedDiagnostic(ctx)
		current("Pod", observed, wanted, scope)
		if diagnostic.TypedMetadataDetailSnapshot() != "" {
			t.Fatal("unbounded fixture slot escaped")
		}
	}
}

func TestTypedMetadataDetailActualHTTPSRefusalKeepsWALAndNoEffects(t *testing.T) {
	h := fixturePhaseFactory(t)(t)
	f, ledger := h.f, h.f.wire.ledger
	acknowledgeAllRecipeFixtures(t, ledger)
	created := time.Now().UTC().Truncate(time.Second).Add(-20 * time.Second)
	for slot := range fixtureCatalog {
		f.objects[slot] = fixtureResultExample(t, ledger, slot, fixtureStableResult, created)
	}
	h.gcRows = func(source installobserve.GCResource, rows []metav1.PartialObjectMetadata) []metav1.PartialObjectMetadata {
		if source.Kind == "Pod" {
			for i := range rows {
				if rows[i].UID == ledger.document.Entries[fixturePlainPod].OriginalUID {
					rows[i].ResourceVersion = "999"
				}
			}
		}
		return rows
	}
	body, identity := bytes.Clone(ledger.body), ledger.identity
	ctx, diagnostic := WithLifecycleDiagnostic(context.Background())
	observation, err := f.wire.observePhase(ctx)
	if err != ErrFixtures || observation != nil || diagnostic.TypedMetadataSnapshot() != "kind=Pod field=resource-version" || diagnostic.TypedMetadataDetailSnapshot() != "scope=fixture slot="+strconv.Itoa(fixturePlainPod)+" gc-rv-order=greater metadata=rv-only" {
		t.Fatal("actual refused predicate did not publish bounded fixture context", diagnostic.TypedMetadataDetailSnapshot())
	}
	if !bytes.Equal(body, ledger.body) || identity != ledger.identity || ledger.phaseFloor != nil || f.creates != 0 || f.deletes != 0 || f.seeds != 0 {
		t.Fatal("diagnostic changed evidence, advanced a floor or performed an effect")
	}
}
