// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	arcadev1 "github.com/gobha-me/arcadectl/api/v1alpha1"
	"github.com/gobha-me/arcadectl/internal/canonicaljson"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Optional PRIVATE diagnostic capture, only called for fixed synthetic objects
// in the exclusively owned native Kind test, after constructor equality and UID
// acknowledgement. It never captures Secrets, real worlds, general observations,
// request credentials, transport errors, or Pod specs. No CI artifact is uploaded.
// Capture is off by default. This is not a production validator or UID authority.
func captureNativeFixtureShape(f *fixtureLedger, slot int, stage string, o *unstructured.Unstructured) error {
	dir := os.Getenv("ARCADECTL_TEST_NATIVE_FIXTURE_SHAPES")
	if dir == "" {
		return nil
	}
	if f == nil || o == nil || slot < 0 || slot >= len(fixtureCatalog) || stage != "ack" && stage != "live" && (stage != "seed" || slot != fixtureCancelledDestroy) {
		return ErrFixtures
	}
	want, err := f.object(slot)
	if err != nil || !reflect.DeepEqual(o.Object["spec"], want.Object["spec"]) || !reflect.DeepEqual(o.GetLabels(), want.GetLabels()) || !reflect.DeepEqual(o.GetAnnotations(), want.GetAnnotations()) || !reflect.DeepEqual(o.GetOwnerReferences(), want.GetOwnerReferences()) || o.GetAPIVersion() != want.GetAPIVersion() || o.GetKind() != want.GetKind() || o.GetName() != want.GetName() || o.GetNamespace() != want.GetNamespace() || o.GetUID() != f.document.Entries[slot].OriginalUID || !nativeFixtureUID(string(o.GetUID())) {
		return ErrFixtures
	}
	// Reject unknown raw/typed fields before recording public native bookkeeping.
	switch o.GetKind() {
	case "Pod":
		var typed corev1.Pod
		err = decodeServing(o, &typed)
	case "PersistentVolumeClaim":
		var typed corev1.PersistentVolumeClaim
		err = decodeServing(o, &typed)
	case "Job":
		var typed batchv1.Job
		err = decodeServing(o, &typed)
	case "GameDestroy":
		var typed arcadev1.GameDestroy
		err = decodeServing(o, &typed)
	default:
		return ErrFixtures
	}
	if err != nil {
		return ErrFixtures
	}
	if stage == "seed" {
		status, err := f.destroySeedStatus()
		if err != nil || !reflect.DeepEqual(o.Object["status"], status) {
			return ErrFixtures
		}
	}
	shape := map[string]any{"apiVersion": o.Object["apiVersion"], "kind": o.Object["kind"], "metadata": o.Object["metadata"]}
	if status, present := o.Object["status"]; present {
		shape["status"] = status
	}
	body, err := json.Marshal(shape)
	if err != nil || len(body) > 65536 {
		return ErrFixtures
	}
	body, err = canonicaljson.CanonicalJSON(body)
	if err != nil {
		return ErrFixtures
	}
	files, err := privatefs.Open(dir, false)
	if err != nil {
		return ErrFixtures
	}
	defer files.Close()
	plans := []*installrender.Plan{}
	for _, plan := range f.engine.plans {
		plans = append(plans, plan)
	}
	journal, err := installstate.Decode(f.document.Journal, plans...)
	if err != nil {
		return ErrFixtures
	}
	plan := f.engine.plans[journal.TargetPackage]
	if !plan.IsTrusted() {
		return ErrFixtures
	}
	profile := plan.Profile().ID
	name := fmt.Sprintf("%s-fixture-%d-%s.json", profile, slot, stage)
	if _, err := files.AtomicWrite(name, body, nil); err != nil {
		return ErrFixtures
	}
	return nil
}

func TestNativeFixtureShapeCaptureIsPrivateClosedAndOffByDefault(t *testing.T) {
	t.Setenv("ARCADECTL_TEST_NATIVE_FIXTURE_SHAPES", "")
	if captureNativeFixtureShape(nil, -1, "foreign", nil) != nil {
		t.Fatal("disabled diagnostic touched evidence")
	}
	dir := t.TempDir()
	if os.Chmod(dir, 0700) != nil {
		t.Fatal("private capture directory unavailable")
	}
	t.Setenv("ARCADECTL_TEST_NATIVE_FIXTURE_SHAPES", dir)
	f := newFixture(t, false)
	ledger, err := f.engine.prepareFixtureLedger(t.Context(), f.snapshot)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.close()
	fixtureWireAdvance(t, ledger, 0, fixtureCreateAttempted, "")
	next, _ := ledger.nextDocument()
	next.Entries[0].State, next.Entries[0].OriginalUID = fixtureOriginal, "10000000-0000-4000-8000-000000000001"
	if ledger.advance(next) != nil {
		t.Fatal("original fixture ACK unavailable")
	}
	o, err := ledger.object(0)
	if err != nil {
		t.Fatal(err)
	}
	o.SetUID(next.Entries[0].OriginalUID)
	o.SetResourceVersion("101")
	if err := captureNativeFixtureShape(ledger, 0, "ack", o); err != nil {
		t.Fatal("private capture refused", err)
	}
	files, err := privatefs.Open(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer files.Close()
	body, _, err := files.Read("kubernetes-1.35.8-fixture-0-ack.json", 65536)
	if err != nil {
		t.Fatal(err)
	}
	var shape map[string]any
	if json.Unmarshal(body, &shape) != nil || shape["kind"] != "Job" || shape["spec"] != nil {
		t.Fatal("diagnostic selected another object or stored executable spec")
	}
	filename := filepath.Join(dir, "kubernetes-1.35.8-fixture-0-ack.json")
	info, err := os.Stat(filename)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("diagnostic file is not private")
	}
	if captureNativeFixtureShape(ledger, 0, "ack", o) != ErrFixtures {
		t.Fatal("duplicate capture replaced original evidence")
	}
	recorded, _, err := files.Read("kubernetes-1.35.8-fixture-0-ack.json", 65536)
	if err != nil || string(recorded) != string(body) {
		t.Fatal("duplicate capture changed original evidence")
	}
	unsafe := t.TempDir()
	if os.Chmod(unsafe, 0755) != nil {
		t.Fatal("unsafe directory fixture unavailable")
	}
	link := filepath.Join(t.TempDir(), "capture-link")
	if os.Symlink(dir, link) != nil {
		t.Fatal("symlink fixture unavailable")
	}
	for _, path := range []string{unsafe, link, filepath.Join(dir, "absent")} {
		t.Setenv("ARCADECTL_TEST_NATIVE_FIXTURE_SHAPES", path)
		if captureNativeFixtureShape(ledger, 0, "live", o) != ErrFixtures {
			t.Fatal("unsafe capture destination accepted")
		}
	}
	t.Setenv("ARCADECTL_TEST_NATIVE_FIXTURE_SHAPES", dir)
	for _, change := range []string{"uid", "kind", "spec", "annotations", "metadata", "stage"} {
		mutated := o.DeepCopy()
		stage := "live"
		switch change {
		case "uid":
			mutated.SetUID("20000000-0000-4000-8000-000000000001")
		case "kind":
			mutated.SetKind("Secret")
		case "spec":
			mutated.Object["spec"] = map[string]any{}
		case "annotations":
			mutated.SetAnnotations(map[string]string{"private": "PRIVATE-CANARY"})
		case "metadata":
			mutated.Object["metadata"].(map[string]any)["privateCredential"] = "PRIVATE-CANARY"
		case "stage":
			stage = "foreign"
		}
		if captureNativeFixtureShape(ledger, 0, stage, mutated) != ErrFixtures {
			t.Fatal("foreign/private observation admitted", change)
		}
	}
}

func TestNativeFixtureSeedShapeCaptureRequiresExactSyntheticOriginal(t *testing.T) {
	dir := t.TempDir()
	if os.Chmod(dir, 0700) != nil {
		t.Fatal("private seed capture directory unavailable")
	}
	t.Setenv("ARCADECTL_TEST_NATIVE_FIXTURE_SHAPES", dir)
	f := newFixture(t, false)
	ledger, err := f.engine.prepareFixtureLedger(t.Context(), f.snapshot)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.close()
	acknowledgeAllRecipeFixtures(t, ledger)
	seeded := fixtureDestroySeedExample(t, ledger, time.Now().UTC().Add(-time.Minute))
	if captureNativeFixtureShape(ledger, fixtureCancelledDestroy, "seed", seeded) != nil {
		t.Fatal("fixed synthetic seed capture refused")
	}
	files, err := privatefs.Open(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer files.Close()
	name := "kubernetes-1.35.8-fixture-9-seed.json"
	body, _, err := files.Read(name, 65536)
	if err != nil {
		t.Fatal("seed shape not privately recorded")
	}
	var shape map[string]any
	if json.Unmarshal(body, &shape) != nil || shape["spec"] != nil || shape["kind"] != "GameDestroy" || !reflect.DeepEqual(shape["status"], seeded.Object["status"]) {
		t.Fatal("seed capture stored executable spec or changed fixed synthetic status")
	}
	if captureNativeFixtureShape(ledger, 0, "seed", seeded) != ErrFixtures || captureNativeFixtureShape(ledger, fixtureCancelledDestroy, "seed", seeded) != ErrFixtures {
		t.Fatal("seed capture accepted another slot or overwrote original evidence")
	}
	for label, change := range map[string]func(*unstructured.Unstructured){
		"phase": func(o *unstructured.Unstructured) { o.Object["status"].(map[string]any)["phase"] = "Deleting" },
		"guidance": func(o *unstructured.Unstructured) {
			o.Object["status"].(map[string]any)["preview"].(map[string]any)["restoreGuidance"] = "PRIVATE-CANARY"
		},
		"status-extra": func(o *unstructured.Unstructured) { o.Object["status"].(map[string]any)["private"] = "PRIVATE-CANARY" },
		"confirmation": func(o *unstructured.Unstructured) {
			_ = unstructured.SetNestedField(o.Object, ledger.document.RunID, "spec", "confirmationChallenge")
		},
		"foreign-uid": func(o *unstructured.Unstructured) { o.SetUID("c0000000-0000-4000-8000-000000000001") },
		"metadata": func(o *unstructured.Unstructured) {
			o.Object["metadata"].(map[string]any)["private"] = "PRIVATE-CANARY"
		},
	} {
		t.Run(label, func(t *testing.T) {
			negativeDir := t.TempDir()
			if os.Chmod(negativeDir, 0700) != nil {
				t.Fatal("private negative capture directory unavailable")
			}
			t.Setenv("ARCADECTL_TEST_NATIVE_FIXTURE_SHAPES", negativeDir)
			o := seeded.DeepCopy()
			change(o)
			if captureNativeFixtureShape(ledger, fixtureCancelledDestroy, "seed", o) != ErrFixtures {
				t.Fatal("foreign/nonfixed seed diagnostic accepted")
			}
			entries, err := os.ReadDir(negativeDir)
			if err != nil || len(entries) != 0 {
				t.Fatal("refused synthetic seed created a private diagnostic artifact")
			}
		})
	}
	recorded, _, err := files.Read(name, 65536)
	if err != nil || string(recorded) != string(body) {
		t.Fatal("refused seed diagnostics changed original private capture")
	}
}
