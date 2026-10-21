// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	platformkube "github.com/gobha-me/arcadectl/internal/platform/kube"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestVerifiedWarmCaptureUsesOnlyFixedV2CancelledSlot(t *testing.T) {
	f := newFixture(t, false)
	ledger, err := f.engine.prepareFixtureLedger(t.Context(), f.snapshot)
	if err != nil {
		t.Fatal("original ledger unavailable")
	}
	defer ledger.close()
	instrumentFreshFixtureRecipeV2(t, ledger)
	acknowledgeAllRecipeFixtures(t, ledger)
	created := time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
	original := fixtureWarmCancelledSlotExample(t, ledger, fixtureVerifiedCancelledDestroy, created, [3]time.Duration{time.Second, 2 * time.Second, 3 * time.Second})
	dir := t.TempDir()
	if os.Chmod(dir, 0700) != nil {
		t.Fatal("private capture directory unavailable")
	}
	t.Setenv("ARCADECTL_TEST_NATIVE_FIXTURE_SHAPES", dir)
	body, identity, revision := bytes.Clone(ledger.body), ledger.identity, ledger.document.Revision
	for _, stage := range []string{"seed", "warm-seed-learning", "warm-seeded", "warm-confirmation", "retained-marker-learning", "PRIVATE-CANARY"} {
		if captureNativeFixtureShape(ledger, fixtureVerifiedCancelledDestroy, stage, original) != ErrFixtures {
			t.Fatal("verified leaf acquired another slot's capture stage")
		}
	}
	corrupt := original.DeepCopy()
	_ = unstructured.SetNestedField(corrupt.Object, "PRIVATE-CANARY", "status", "preview", "restoreGuidance")
	if captureNativeFixtureShape(ledger, fixtureVerifiedCancelledDestroy, "warm-cancelled", corrupt) != ErrFixtures {
		t.Fatal("verified cancellation capture accepted private/foreign status")
	}
	files, err := os.ReadDir(dir)
	if err != nil || len(files) != 0 {
		t.Fatal("refused capture persisted data")
	}
	if captureNativeFixtureShape(ledger, fixtureVerifiedCancelledDestroy, "warm-cancelled", original) != nil {
		t.Fatal("fixed verified cancellation capture refused")
	}
	name := filepath.Join(dir, "kubernetes-1.35.8-fixture-10-warm-cancelled.json")
	info, err := os.Stat(name)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("verified cancellation capture is not private")
	}
	stored, err := os.ReadFile(name)
	if err != nil || bytes.Contains(stored, []byte("PRIVATE-CANARY")) || bytes.Contains(stored, []byte(`"spec"`)) || !bytes.Equal(body, ledger.body) || identity != ledger.identity || revision != ledger.document.Revision || ledger.behaviorCompletion != nil {
		t.Fatal("verified diagnostic leaked data or changed authority/evidence")
	}
}

func TestWarmSeededCaptureRequiresExactAcknowledgedPublicShape(t *testing.T) {
	f := newFixture(t, false)
	ledger, err := f.engine.prepareFixtureLedger(t.Context(), f.snapshot)
	if err != nil {
		t.Fatal("original ledger unavailable")
	}
	defer ledger.close()
	acknowledgeAllRecipeFixtures(t, ledger)
	intent := fixtureSeedIntent(t, ledger)
	intent.DestroySeed.Mode = fixtureDestroySeedWarmCancelled
	if ledger.advance(intent) != nil {
		t.Fatal("abstract warm intent unavailable")
	}
	created := time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
	original := fixtureWarmSeededExample(t, ledger, created, [4]time.Duration{time.Second, time.Second, time.Second, 2 * time.Second})
	dir := t.TempDir()
	if os.Chmod(dir, 0700) != nil {
		t.Fatal("private capture directory unavailable")
	}
	t.Setenv("ARCADECTL_TEST_NATIVE_FIXTURE_SHAPES", dir)
	if captureNativeFixtureShape(ledger, fixtureCancelledDestroy, "warm-seeded", original) != ErrFixtures {
		t.Fatal("unacknowledged shape acquired capture authority")
	}
	ledger.seedEffect = false // Abstract test receipt, never a native wire ACK.
	if ledger.advance(fixtureSeedAcknowledgement(t, ledger)) != nil {
		t.Fatal("abstract acknowledged receipt unavailable")
	}
	before, identity, revision := bytes.Clone(ledger.body), ledger.identity, ledger.document.Revision
	for _, change := range []string{"uid", "rv", "status", "manager", "field-tree", "metadata", "generation", "finalizer", "slot", "stage"} {
		t.Run(change, func(t *testing.T) {
			o := original.DeepCopy()
			slot, stage := fixtureCancelledDestroy, "warm-seeded"
			switch change {
			case "uid":
				o.SetUID("20000000-0000-4000-8000-000000000001")
			case "rv":
				o.SetResourceVersion("999")
			case "status":
				_ = unstructured.SetNestedField(o.Object, "PRIVATE-WARM-CANARY", "status", "preview", "restoreGuidance")
			case "manager", "field-tree":
				fields, _, _ := unstructured.NestedSlice(o.Object, "metadata", "managedFields")
				field := fields[0].(map[string]any)
				if change == "manager" {
					field["manager"] = "PRIVATE-WARM-CANARY"
				} else {
					field["fieldsV1"] = map[string]any{"PRIVATE-WARM-CANARY": map[string]any{}}
				}
				_ = unstructured.SetNestedSlice(o.Object, fields, "metadata", "managedFields")
			case "metadata":
				_ = unstructured.SetNestedField(o.Object, "PRIVATE-WARM-CANARY", "metadata", "privateCredential")
			case "generation":
				o.SetGeneration(2)
			case "finalizer":
				o.SetFinalizers(nil)
			case "slot":
				slot = fixturePlainPod
			case "stage":
				stage = "warm-private"
			}
			if captureNativeFixtureShape(ledger, slot, stage, o) != ErrFixtures {
				t.Fatal("foreign/private warm seeded diagnostic accepted")
			}
			files, err := os.ReadDir(dir)
			if err != nil || len(files) != 0 {
				t.Fatal("refused diagnostic wrote private data")
			}
		})
	}
	name := filepath.Join(dir, "kubernetes-1.35.8-fixture-9-warm-seeded.json")
	if captureNativeFixtureShape(ledger, fixtureCancelledDestroy, "warm-seeded", original) != nil {
		t.Fatal("exact acknowledged public shape refused")
	}
	info, err := os.Stat(name)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("warm seeded capture is not private")
	}
	stored, err := os.ReadFile(name)
	if err != nil || bytes.Contains(stored, []byte("PRIVATE-WARM-CANARY")) || bytes.Contains(stored, []byte(`"spec"`)) {
		t.Fatal("warm seeded capture contains private or executable fields")
	}
	if captureNativeFixtureShape(ledger, fixtureCancelledDestroy, "warm-seeded", original) != ErrFixtures {
		t.Fatal("duplicate capture replaced original evidence")
	}
	unchanged, err := os.ReadFile(name)
	if err != nil || !bytes.Equal(stored, unchanged) || !bytes.Equal(before, ledger.body) || identity != ledger.identity || revision != ledger.document.Revision {
		t.Fatal("capture changed evidence or effect ledger")
	}
}

func TestWarmConfirmationCaptureRequiresExactAcknowledgedPublicDelta(t *testing.T) {
	f := newFixture(t, false)
	ledger, err := f.engine.prepareFixtureLedger(t.Context(), f.snapshot)
	if err != nil {
		t.Fatal("original ledger unavailable")
	}
	defer ledger.close()
	acknowledgeAllRecipeFixtures(t, ledger)
	intent := fixtureSeedIntent(t, ledger)
	intent.DestroySeed.Mode = fixtureDestroySeedWarmCancelled
	if ledger.advance(intent) != nil {
		t.Fatal("abstract warm intent unavailable")
	}
	dir := t.TempDir()
	if os.Chmod(dir, 0700) != nil {
		t.Fatal("private capture directory unavailable")
	}
	t.Setenv("ARCADECTL_TEST_NATIVE_FIXTURE_SHAPES", dir)
	created := time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
	original := fixtureWarmConfirmationExample(t, ledger, created, false)
	if captureNativeFixtureShape(ledger, fixtureCancelledDestroy, "warm-confirmation", original) != ErrFixtures {
		t.Fatal("unknown warm seed acquired diagnostic confirmation authority")
	}
	ledger.seedEffect = false // Abstract receipt, never a native wire ACK.
	if ledger.advance(fixtureSeedAcknowledgement(t, ledger)) != nil {
		t.Fatal("abstract acknowledged warm seed unavailable")
	}
	before, identity, revision := bytes.Clone(ledger.body), ledger.identity, ledger.document.Revision
	for _, change := range []string{"challenge", "status", "missing-owned-leaf", "extra-owned-leaf", "generation", "rv", "uid", "slot", "stage"} {
		t.Run(change, func(t *testing.T) {
			o := original.DeepCopy()
			slot, stage := fixtureCancelledDestroy, "warm-confirmation"
			switch change {
			case "challenge":
				_ = unstructured.SetNestedField(o.Object, "PRIVATE-WARM-CANARY", "spec", "confirmationChallenge")
			case "status":
				_ = unstructured.SetNestedField(o.Object, "PRIVATE-WARM-CANARY", "status", "preview", "restoreGuidance")
			case "missing-owned-leaf", "extra-owned-leaf":
				fields, _, _ := unstructured.NestedSlice(o.Object, "metadata", "managedFields")
				spec := fields[3].(map[string]any)["fieldsV1"].(map[string]any)["f:spec"].(map[string]any)
				if change == "missing-owned-leaf" {
					delete(spec, "f:confirmationChallenge")
				} else {
					spec["f:PRIVATE-WARM-CANARY"] = map[string]any{}
				}
				_ = unstructured.SetNestedSlice(o.Object, fields, "metadata", "managedFields")
			case "generation":
				o.SetGeneration(1)
			case "rv":
				o.SetResourceVersion("999")
			case "uid":
				o.SetUID("20000000-0000-4000-8000-000000000001")
			case "slot":
				slot = fixturePlainPod
			case "stage":
				stage = "warm-private"
			}
			if captureNativeFixtureShape(ledger, slot, stage, o) != ErrFixtures {
				t.Fatal("foreign/private warm confirmation capture accepted")
			}
			files, err := os.ReadDir(dir)
			if err != nil || len(files) != 0 {
				t.Fatal("refused confirmation capture wrote private data")
			}
		})
	}
	if captureNativeFixtureShape(ledger, fixtureCancelledDestroy, "warm-confirmation", original) != nil {
		t.Fatal("exact acknowledged public confirmation diagnostic refused")
	}
	name := filepath.Join(dir, "kubernetes-1.35.8-fixture-9-warm-confirmation.json")
	info, err := os.Stat(name)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("confirmation capture is not private")
	}
	stored, err := os.ReadFile(name)
	if err != nil || bytes.Contains(stored, []byte("PRIVATE-WARM-CANARY")) || bytes.Contains(stored, []byte(`"spec"`)) || !bytes.Contains(stored, []byte(`"f:confirmationChallenge"`)) {
		t.Fatal("confirmation capture leaked executable/private fields or omitted bookkeeping")
	}
	if captureNativeFixtureShape(ledger, fixtureCancelledDestroy, "warm-confirmation", original) != ErrFixtures {
		t.Fatal("duplicate confirmation capture replaced original evidence")
	}
	unchanged, err := os.ReadFile(name)
	if err != nil || !bytes.Equal(stored, unchanged) || !bytes.Equal(before, ledger.body) || identity != ledger.identity || revision != ledger.document.Revision || ledger.seedAck || ledger.seedEffect {
		t.Fatal("confirmation capture changed original evidence/WAL/capabilities")
	}
}

func TestWarmCancellationCaptureClosedStatusAndNoPrivateWrites(t *testing.T) {
	f := newFixture(t, false)
	ledger, err := f.engine.prepareFixtureLedger(t.Context(), f.snapshot)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.close()
	acknowledgeAllRecipeFixtures(t, ledger)
	created := time.Now().UTC().Truncate(time.Second).Add(-20 * time.Second)
	original := fixtureWarmCancelledExample(t, ledger, created, [3]time.Duration{time.Second, time.Second, time.Second})
	if nativeWarmCancellationStatus(original, time.Now().UTC()) != nil {
		t.Fatal("fixed public test cancellation shape refused")
	}
	cases := []struct {
		name   string
		change func(*unstructured.Unstructured)
	}{
		{"journal", func(o *unstructured.Unstructured) {
			_ = unstructured.SetNestedSlice(o.Object, []any{}, "status", "deletionJournal")
		}},
		{"preview", func(o *unstructured.Unstructured) {
			_ = unstructured.SetNestedMap(o.Object, map[string]any{"challenge": "PRIVATE-WARM-CANARY"}, "status", "preview")
		}},
		{"private-message", func(o *unstructured.Unstructured) {
			conditions, _, _ := unstructured.NestedSlice(o.Object, "status", "conditions")
			conditions[0].(map[string]any)["message"] = "PRIVATE-WARM-CANARY"
			_ = unstructured.SetNestedSlice(o.Object, conditions, "status", "conditions")
		}},
		{"private-manager", func(o *unstructured.Unstructured) {
			fields, _, _ := unstructured.NestedSlice(o.Object, "metadata", "managedFields")
			fields[0].(map[string]any)["manager"] = "PRIVATE-WARM-CANARY"
			_ = unstructured.SetNestedSlice(o.Object, fields, "metadata", "managedFields")
		}},
		{"private-field-tree", func(o *unstructured.Unstructured) {
			fields, _, _ := unstructured.NestedSlice(o.Object, "metadata", "managedFields")
			fields[0].(map[string]any)["fieldsV1"] = map[string]any{"PRIVATE-WARM-CANARY": map[string]any{}}
			_ = unstructured.SetNestedSlice(o.Object, fields, "metadata", "managedFields")
		}},
		{"reason", func(o *unstructured.Unstructured) {
			conditions, _, _ := unstructured.NestedSlice(o.Object, "status", "conditions")
			conditions[0].(map[string]any)["reason"] = "Unexpected"
			_ = unstructured.SetNestedSlice(o.Object, conditions, "status", "conditions")
		}},
		{"observed-generation", func(o *unstructured.Unstructured) {
			_ = unstructured.SetNestedField(o.Object, int64(2), "status", "observedGeneration")
		}},
		{"unknown-status", func(o *unstructured.Unstructured) {
			_ = unstructured.SetNestedField(o.Object, "PRIVATE-WARM-CANARY", "status", "unknown")
		}},
		{"time-inversion", func(o *unstructured.Unstructured) {
			_ = unstructured.SetNestedField(o.Object, created.Add(2*time.Second).Format(time.RFC3339), "status", "startedAt")
		}},
		{"future", func(o *unstructured.Unstructured) {
			_ = unstructured.SetNestedField(o.Object, time.Now().UTC().Add(time.Hour).Format(time.RFC3339), "status", "completedAt")
		}},
		{"no-finalizer", func(o *unstructured.Unstructured) { o.SetFinalizers(nil) }},
		{"extra-finalizer", func(o *unstructured.Unstructured) {
			o.SetFinalizers([]string{platformkube.DestroyFinalizer, "example.test/foreign"})
		}},
		{"deleting", func(o *unstructured.Unstructured) {
			stamp := metav1.NewTime(created.Add(time.Second))
			o.SetDeletionTimestamp(&stamp)
		}},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			dir := t.TempDir()
			if os.Chmod(dir, 0700) != nil {
				t.Fatal("private capture directory unavailable")
			}
			t.Setenv("ARCADECTL_TEST_NATIVE_FIXTURE_SHAPES", dir)
			o := original.DeepCopy()
			item.change(o)
			if captureNativeFixtureShape(ledger, fixtureCancelledDestroy, "warm-cancelled", o) != ErrFixtures {
				t.Fatal("unsafe warm diagnostic shape accepted")
			}
			files, err := os.ReadDir(dir)
			if err != nil || len(files) != 0 {
				t.Fatal("refused diagnostic wrote private data")
			}
		})
	}
	t.Run("closed-stage-and-slot", func(t *testing.T) {
		dir := t.TempDir()
		if os.Chmod(dir, 0700) != nil {
			t.Fatal("private capture directory unavailable")
		}
		t.Setenv("ARCADECTL_TEST_NATIVE_FIXTURE_SHAPES", dir)
		if captureNativeFixtureShape(ledger, fixturePlainPod, "warm-cancelled", original) != ErrFixtures || captureNativeFixtureShape(ledger, fixtureCancelledDestroy, "warm-private", original) != ErrFixtures {
			t.Fatal("foreign warm diagnostic route accepted")
		}
		files, err := os.ReadDir(dir)
		if err != nil || len(files) != 0 {
			t.Fatal("foreign route wrote data")
		}
	})
	t.Run("public-capture-only", func(t *testing.T) {
		dir := t.TempDir()
		if os.Chmod(dir, 0700) != nil {
			t.Fatal("private capture directory unavailable")
		}
		t.Setenv("ARCADECTL_TEST_NATIVE_FIXTURE_SHAPES", dir)
		if captureNativeFixtureShape(ledger, fixtureCancelledDestroy, "warm-cancelled", original) != nil {
			t.Fatal("closed public cancellation capture refused")
		}
		info, err := os.Stat(filepath.Join(dir, "kubernetes-1.35.8-fixture-9-warm-cancelled.json"))
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("warm bookkeeping capture not private")
		}
	})
}

// Diagnostic only: return fixed public constants, never context error text or
// identities. This cannot authorize an effect, retry or cleanup progression.
func warmCleanupContextStage(ctx context.Context) string {
	if ctx == nil {
		return "unavailable"
	}
	switch ctx.Err() {
	case nil:
		return "active"
	case context.DeadlineExceeded:
		return "deadline-exceeded"
	case context.Canceled:
		return "cancelled"
	default:
		return "unclassified"
	}
}

type warmDiagnosticContext struct {
	context.Context
	fault error
}

func (c warmDiagnosticContext) Err() error { return c.fault }

func TestWarmCleanupContextDiagnosticIsClosed(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, closeExpired := context.WithDeadline(context.Background(), time.Now().Add(-time.Minute))
	defer closeExpired()
	for _, tc := range []struct {
		ctx  context.Context
		want string
	}{
		{nil, "unavailable"}, {context.Background(), "active"}, {cancelled, "cancelled"}, {expired, "deadline-exceeded"},
		{warmDiagnosticContext{context.Background(), errors.New("PRIVATE-CONTEXT-CANARY")}, "unclassified"},
		{warmDiagnosticContext{context.Background(), fmt.Errorf("PRIVATE-CONTEXT-CANARY: %w", context.DeadlineExceeded)}, "unclassified"},
	} {
		if warmCleanupContextStage(tc.ctx) != tc.want {
			t.Fatal("context diagnostic escaped its closed constants")
		}
	}
}
