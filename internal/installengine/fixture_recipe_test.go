// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
)

func acknowledgeRecipeFixture(t *testing.T, ledger *fixtureLedger, slot int, uid types.UID) {
	t.Helper()
	next, err := ledger.nextDocument()
	if err != nil {
		t.Fatal(err)
	}
	next.Entries[slot].State = fixtureCreateAttempted
	if ledger.advance(next) != nil {
		t.Fatal("recipe fixture intent unavailable")
	}
	next, err = ledger.nextDocument()
	if err != nil {
		t.Fatal(err)
	}
	next.Entries[slot].State, next.Entries[slot].OriginalUID = fixtureOriginal, uid
	if ledger.advance(next) != nil {
		t.Fatal("recipe fixture acknowledgement unavailable")
	}
}

// Pure construction and WAL instrumentation, not CREATE, native defaults,
// policy evaluation, original live shape, recovery or cleanup certification.
func TestFixtureRecipeClosedInertObjectsAndOriginalOwner(t *testing.T) {
	for _, namespace := range []string{installrender.DefaultNamespace, "isolated-install"} {
		for _, profile := range []string{installrender.Profile135, installrender.Profile137} {
			t.Run(namespace+"/"+profile, func(t *testing.T) {
				plan := fixturePlanProfile(t, namespace, profile)
				f := newFixtureWithPlans(t, false, plan)
				ledger, err := f.engine.prepareFixtureLedger(context.Background(), f.snapshot)
				if err != nil {
					t.Fatal(err)
				}
				defer ledger.close()
				for slot := range fixtureCatalog {
					if owner := fixtureCatalog[slot].owner; owner >= 0 {
						// The preceding original was durably acknowledged below.
						if ledger.document.Entries[owner].OriginalUID == "" {
							t.Fatal("missing preceding owner acknowledgement")
						}
					}
					o, err := ledger.object(slot)
					if err != nil {
						t.Fatalf("closed slot%d unavailable: %v", slot, err)
					}
					key := resourceKeyFromObject(o)
					created := o.GetCreationTimestamp()
					if key != ledger.document.Entries[slot].Key || o.GetUID() != "" || o.GetResourceVersion() != "" || o.GetGeneration() != 0 || !created.IsZero() || len(o.GetFinalizers()) != 0 {
						t.Fatal("constructor supplied live identity or escaped fixed slot")
					}
					if _, present := o.Object["status"]; present {
						t.Fatal("constructor supplied status authority")
					}
					switch o.GetKind() {
					case "Pod", "Job":
						podSpec, _, _ := unstructured.NestedMap(o.Object, "spec")
						if o.GetKind() == "Job" {
							podSpec, _, _ = unstructured.NestedMap(o.Object, "spec", "template", "spec")
							suspended, _, _ := unstructured.NestedBool(o.Object, "spec", "suspend")
							parallelism, _, _ := unstructured.NestedInt64(o.Object, "spec", "parallelism")
							manual, _, _ := unstructured.NestedBool(o.Object, "spec", "manualSelector")
							if !suspended || parallelism != 0 || !manual || len(o.GetOwnerReferences()) != 0 {
								t.Fatal("Job recipe became executable or adopted an owner")
							}
						} else if slot == fixturePlainPod {
							if len(o.GetLabels()) != 0 || len(o.GetOwnerReferences()) != 0 {
								t.Fatal("plain Pod accidentally classified as worker")
							}
						} else {
							owner := ledger.document.Entries[fixtureCatalog[slot].owner]
							refs := o.GetOwnerReferences()
							if len(refs) != 1 || !reflect.DeepEqual(refs[0], metav1.OwnerReference{APIVersion: "batch/v1", Kind: "Job", Name: owner.Key.Name, UID: owner.OriginalUID, Controller: boolPointer(false), BlockOwnerDeletion: boolPointer(true)}) {
								t.Fatal("worker adopted a name or fabricated/controlling owner")
							}
							job, err := ledger.object(fixtureCatalog[slot].owner)
							if err != nil {
								t.Fatal(err)
							}
							selector, _, _ := unstructured.NestedStringMap(job.Object, "spec", "selector", "matchLabels")
							if len(selector) != 1 || labels.SelectorFromSet(selector).Matches(labels.Set(o.GetLabels())) {
								t.Fatal("Job controller could adopt/delete the manual probe")
							}
						}
						for _, forbidden := range []string{"volumes", "initContainers", "ephemeralContainers", "nodeName", "nodeSelector", "hostNetwork", "hostPID", "hostIPC", "imagePullSecrets"} {
							if _, found := podSpec[forbidden]; found {
								t.Fatal("inert recipe acquired executable/data/host authority")
							}
						}
						if podSpec["automountServiceAccountToken"] != false || podSpec["enableServiceLinks"] != false || len(podSpec["schedulingGates"].([]any)) != 1 {
							t.Fatal("inert recipe lost gate/tokenless isolation")
						}
						containers := podSpec["containers"].([]any)
						if len(containers) != 1 || containers[0].(map[string]any)["image"] != plan.Manifest().Images.Controller || !reflect.DeepEqual(containers[0].(map[string]any)["command"], []any{"arcadectl-admission-probe"}) {
							t.Fatal("unsigned executable admitted into recipe")
						}
					case "PersistentVolumeClaim":
						wantSpec := map[string]any{"accessModes": []any{"ReadWriteOnce"}, "resources": map[string]any{"requests": map[string]any{"storage": "1Mi"}}, "storageClassName": "", "volumeMode": "Filesystem"}
						if !reflect.DeepEqual(o.Object["spec"], wantSpec) || !reflect.DeepEqual(o.GetAnnotations(), map[string]string{"pv.kubernetes.io/bind-completed": "yes"}) {
							t.Fatal("PVC recipe could bind/provision/import data")
						}
						if slot == fixtureRetainedPVC {
							if o.GetLabels()["arcade.gobha.me/data-policy"] != "retain" || o.GetLabels()["app.kubernetes.io/instance"] != key.Name || len(key.Name) > 63 {
								t.Fatal("retained fixture lost original role or valid label")
							}
						} else if len(o.GetLabels()) != 0 {
							t.Fatal("plain fixture mislabeled retained")
						}
					case "GameDestroy":
						cancel, _, _ := unstructured.NestedBool(o.Object, "spec", "cancelRequested")
						mode, _, _ := unstructured.NestedString(o.Object, "spec", "mode")
						if !cancel || mode != "UnsafeNoBackup" || o.GetAnnotations()["arcade.gobha.me/unsafe-requested-by"] != "system:serviceaccount:"+plan.Namespace()+":arcadectl-destroy-admin" {
							t.Fatal("destroy fixture was not born safely cancelled/audited")
						}
						for _, forbidden := range []string{"confirmationChallenge", "backupRef", "repositorySecretRef"} {
							if _, found, _ := unstructured.NestedFieldNoCopy(o.Object, "spec", forbidden); found {
								t.Fatal("destroy fixture acquired confirmation or credentials")
							}
						}
						claimName, _, _ := unstructured.NestedString(o.Object, "spec", "target", "gameServer", "name")
						identity, _, _ := unstructured.NestedString(o.Object, "spec", "target", "data", "identity")
						retained, err := ledger.object(fixtureRetainedPVC)
						if err != nil || !strings.HasSuffix(claimName, ledger.document.RunID) || identity != "synthetic-"+ledger.document.RunID || identity == retained.GetLabels()["arcade.gobha.me/data-identity"] {
							t.Fatal("destroy target escaped synthetic namespace/run")
						}
					}
					// Every returned value is a defensive construction, not stored
					// caller configuration for a later CREATE/cleanup operation.
					original := o.DeepCopy()
					o.SetName("foreign")
					o.Object["spec"] = map[string]any{"PRIVATE-CANARY": true}
					again, err := ledger.object(slot)
					if err != nil || !reflect.DeepEqual(again, original) {
						t.Fatal("returned recipe mutation contaminated future authority")
					}
					acknowledgeRecipeFixture(t, ledger, slot, types.UID(fmt.Sprintf("acknowledged-slot-%d", slot)))
				}
				if f.access.writes != 0 || f.nsUpdates != 0 {
					t.Fatal("pure constructors performed cluster/journal effects")
				}
			})
		}
	}
}

func boolPointer(value bool) *bool { return &value }

func TestFixtureRecipeRefusesUnknownOwnersClosedLedgerAndAlteredEvidence(t *testing.T) {
	f := newFixture(t, false)
	ledger, err := f.engine.prepareFixtureLedger(context.Background(), f.snapshot)
	if err != nil {
		t.Fatal(err)
	}
	for _, slot := range []int{-1, len(fixtureCatalog), fixtureBackupPod, fixtureRestorePod, fixtureDestroyPod} {
		if _, err := ledger.object(slot); err != ErrFixtures {
			t.Fatal("invalid slot or unknown owner admitted")
		}
	}
	next, _ := ledger.nextDocument()
	next.Entries[fixtureBackupJob].State = fixtureCreateAttempted
	if ledger.advance(next) != nil {
		t.Fatal("attempt setup failed")
	}
	if _, err := ledger.object(fixtureBackupPod); err != ErrFixtures {
		t.Fatal("unknown CREATE outcome became Job ownership")
	}
	old := ledger.document.Entries[0].Key
	ledger.document.Entries[0].Key = installstate.Key{APIVersion: "v1", Kind: "Secret", Namespace: "foreign", Name: "PRIVATE-CANARY"}
	if _, err := ledger.object(0); err != ErrFixtures {
		t.Fatal("changed in-memory recipe admitted")
	}
	ledger.document.Entries[0].Key = old
	// The constructor resolves only the journal's originally registered target
	// package. A different trusted namespace/profile is not a fallback recipe.
	target := f.snapshot.Document().TargetPackage
	originalPlan := f.engine.plans[target]
	for _, replacement := range []*installrender.Plan{
		fixturePlanProfile(t, "foreign", installrender.Profile135),
		fixturePlanProfile(t, originalPlan.Namespace(), installrender.Profile137),
		nil,
	} {
		f.engine.plans[target] = replacement
		if _, err := ledger.object(fixtureBackupJob); err != ErrFixtures {
			t.Fatal("foreign/missing registered target became recipe authority")
		}
	}
	f.engine.plans[target] = originalPlan
	if ledger.close() != nil {
		t.Fatal("ledger close failed")
	}
	if _, err := ledger.object(0); err != ErrFixtures {
		t.Fatal("closed ledger retained recipe authority")
	}
	var missing *fixtureLedger
	if _, err := missing.object(0); err != ErrFixtures || f.access.writes != 0 {
		t.Fatal("nil constructor or refused recipe performed effect")
	}
}
