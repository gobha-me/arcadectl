//go:build kindinstall

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/dynamic"
)

// Called only in targetKindFixture's fresh, exclusively owned cluster. All
// synthetic CRs are data-free. The temporary CRD is NOT installer inventory,
// product discovery authority or permission to modify an external cluster.
func proveKindFixtureGCMetadata(t *testing.T, ctx context.Context, wire *fixtureWire, admin dynamic.Interface) (completed bool) {
	t.Helper()
	ledger := wire.ledger
	anchor := wire.actors.request.Snapshot.Anchor()
	group := "gc-" + ledger.document.RunID + ".arcade-test.example"
	gvr := schema.GroupVersionResource{Group: group, Version: "v1", Resource: "gcprobes"}
	crdGVR := schema.GroupVersionResource{Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions"}
	crds := admin.Resource(crdGVR)
	objects := admin.Resource(gvr).Namespace(anchor.Namespace)
	crdName := "gcprobes." + group
	crd := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "apiextensions.k8s.io/v1", "kind": "CustomResourceDefinition",
		"metadata": map[string]any{"name": crdName, "labels": map[string]any{"arcadectl-test-run": ledger.document.RunID}},
		"spec": map[string]any{"group": group, "scope": "Namespaced", "names": map[string]any{"plural": "gcprobes", "singular": "gcprobe", "kind": "GCProbe", "listKind": "GCProbeList"},
			"versions": []any{map[string]any{"name": "v1", "served": true, "storage": true, "schema": map[string]any{"openAPIV3Schema": map[string]any{"type": "object", "properties": map[string]any{"spec": map[string]any{"type": "object", "x-kubernetes-preserve-unknown-fields": true}}}}}}},
	}}
	var originals []*unstructured.Unstructured
	var originalCRD *unstructured.Unstructured
	unknown := false
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		if unknown || originalCRD == nil {
			t.Error("unknown custom proof CREATE remains unadopted; requiring exact owned Kind teardown")
			return
		}
		deleteOriginal := func(client dynamic.ResourceInterface, original *unstructured.Unstructured) bool {
			live, err := client.Get(cleanupCtx, original.GetName(), metav1.GetOptions{})
			if err != nil || live.GetUID() != original.GetUID() || !fixtureRV(live.GetResourceVersion()) || live.GetDeletionTimestamp() != nil || len(live.GetFinalizers()) != 0 || !reflect.DeepEqual(live.Object["spec"], original.Object["spec"]) || !reflect.DeepEqual(live.GetOwnerReferences(), original.GetOwnerReferences()) || !reflect.DeepEqual(live.GetLabels(), original.GetLabels()) {
				t.Error("custom proof original identity/shape changed; refusing cleanup")
				return false
			}
			uid, rv := live.GetUID(), live.GetResourceVersion()
			policy := metav1.DeletePropagationBackground
			if client.Delete(cleanupCtx, live.GetName(), metav1.DeleteOptions{PropagationPolicy: &policy, Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &rv}}) != nil {
				t.Error("custom proof original UID/RV deletion refused")
				return false
			}
			if wait.PollUntilContextTimeout(cleanupCtx, 100*time.Millisecond, 20*time.Second, true, func(ctx context.Context) (bool, error) {
				live, err := client.Get(ctx, original.GetName(), metav1.GetOptions{})
				if apierrors.IsNotFound(err) {
					return true, nil
				}
				if err != nil || live.GetUID() != original.GetUID() {
					return false, ErrOwnership
				}
				return false, nil
			}) != nil {
				t.Error("custom proof actual absence unproved")
				return false
			}
			return true
		}
		// Reverse CREATE order puts the custom leaf before its custom parent.
		for i := len(originals) - 1; i >= 0; i-- {
			if !deleteOriginal(objects, originals[i]) {
				return
			}
		}
		// Before deleting this cluster-scoped CRD, prove no custom objects remain
		// anywhere. Never allow CRD deletion to sweep an unacknowledged object.
		remaining, err := admin.Resource(gvr).List(cleanupCtx, metav1.ListOptions{Limit: 128})
		if err != nil || len(remaining.Items) != 0 || remaining.GetContinue() != "" || remaining.GetResourceVersion() == "" {
			t.Error("temporary CRD domain not empty; refusing cluster-scoped cleanup")
			return
		}
		live, err := crds.Get(cleanupCtx, crdName, metav1.GetOptions{})
		// Both pinned native registries add the cleanup finalizer atomically on
		// DELETE, not CREATE. Before our first DELETE require NO finalizer; no
		// foreign protection may be cleared or treated as native bookkeeping.
		// https://github.com/kubernetes/apiextensions-apiserver/blob/v0.35.8/pkg/registry/customresourcedefinition/etcd.go#L75-L156
		// https://github.com/kubernetes/apiextensions-apiserver/blob/v0.37.0/pkg/registry/customresourcedefinition/etcd.go#L75-L158
		if err != nil || live.GetUID() != originalCRD.GetUID() || !reflect.DeepEqual(live.Object["spec"], originalCRD.Object["spec"]) || !reflect.DeepEqual(live.GetLabels(), originalCRD.GetLabels()) || live.GetDeletionTimestamp() != nil || len(live.GetOwnerReferences()) != 0 || len(live.GetFinalizers()) != 0 || !fixtureRV(live.GetResourceVersion()) {
			t.Error("temporary CRD original protection changed; refusing cleanup")
			return
		}
		uid, rv := live.GetUID(), live.GetResourceVersion()
		if crds.Delete(cleanupCtx, crdName, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &rv}}) != nil {
			t.Error("temporary CRD original UID/RV deletion refused")
			return
		}
		if wait.PollUntilContextTimeout(cleanupCtx, 100*time.Millisecond, 20*time.Second, true, func(ctx context.Context) (bool, error) {
			live, err := crds.Get(ctx, crdName, metav1.GetOptions{})
			if apierrors.IsNotFound(err) {
				return true, nil
			}
			if err != nil || live.GetUID() != originalCRD.GetUID() {
				return false, ErrOwnership
			}
			return false, nil
		}) != nil {
			t.Error("temporary CRD actual absence unproved")
			return
		}
		completed = true // Only all original custom/CRD actual absences unlock parents.
	}()
	var err error
	originalCRD, err = crds.Create(ctx, crd, metav1.CreateOptions{FieldManager: "arcadectl-test", FieldValidation: "Strict"})
	if err != nil || originalCRD == nil || !nativeFixtureUID(string(originalCRD.GetUID())) || !fixtureRV(originalCRD.GetResourceVersion()) {
		unknown = true
		t.Fatal("temporary owned CRD CREATE acknowledgement unavailable")
	}
	if wait.PollUntilContextTimeout(ctx, 100*time.Millisecond, 30*time.Second, true, func(ctx context.Context) (bool, error) {
		live, err := crds.Get(ctx, crdName, metav1.GetOptions{})
		if err != nil || live.GetUID() != originalCRD.GetUID() {
			return false, ErrOwnership
		}
		conditions, found, err := unstructured.NestedSlice(live.Object, "status", "conditions")
		if err != nil || !found {
			return false, nil
		}
		for _, condition := range conditions {
			c, ok := condition.(map[string]any)
			if ok && c["type"] == "Established" && c["status"] == "True" {
				return true, nil
			}
		}
		return false, nil
	}) != nil {
		t.Fatal("temporary owned CRD was not established")
	}
	create := func(name string, owners []metav1.OwnerReference) *unstructured.Unstructured {
		t.Helper()
		o := &unstructured.Unstructured{Object: map[string]any{"apiVersion": group + "/v1", "kind": "GCProbe", "metadata": map[string]any{"name": name, "namespace": anchor.Namespace}, "spec": map[string]any{"private": "PRIVATE-GC-NATIVE-CANARY"}}}
		o.SetLabels(map[string]string{"arcadectl-test-run": ledger.document.RunID, "private": "PRIVATE-GC-NATIVE-CANARY"})
		o.SetAnnotations(map[string]string{"private": "PRIVATE-GC-NATIVE-CANARY"})
		o.SetOwnerReferences(owners)
		live, err := objects.Create(ctx, o, metav1.CreateOptions{FieldManager: "arcadectl-test", FieldValidation: "Strict"})
		if err != nil || live == nil || !nativeFixtureUID(string(live.GetUID())) || !fixtureRV(live.GetResourceVersion()) {
			unknown = true
			t.Fatal("custom proof CREATE acknowledgement unavailable")
		}
		originals = append(originals, live.DeepCopy())
		return live
	}
	var parent fixtureEntry
	for _, entry := range ledger.document.Entries {
		if entry.Key.Kind == "Job" {
			parent = entry
			break
		}
	}
	if parent.State != fixtureOriginal || !nativeFixtureUID(string(parent.OriginalUID)) {
		t.Fatal("original suspended Job root unavailable")
	}
	bridge := create("bridge", []metav1.OwnerReference{{APIVersion: parent.Key.APIVersion, Kind: parent.Key.Kind, Name: parent.Key.Name, UID: parent.OriginalUID}})
	child := create("child", []metav1.OwnerReference{{APIVersion: group + "/v1", Kind: "GCProbe", Name: bridge.GetName(), UID: bridge.GetUID()}})
	for i := 0; i < 129; i++ {
		create(fmt.Sprintf("benign-%03d", i), nil)
	}
	wal, identity := bytes.Clone(ledger.body), ledger.identity
	revision, ack, effect := ledger.document.Revision, ledger.ackSlot, ledger.effectSlot
	observation, err := wire.gcMetadata(ctx)
	if err != nil || observation == nil {
		t.Fatal("native complete GC metadata observation refused", err)
	}
	custom, secrets := 0, 0
	for _, object := range observation.Objects() {
		m := object.Metadata
		if m.Annotations != nil || m.Labels != nil || len(m.ManagedFields) != 0 {
			t.Fatal("native private metadata escaped public observation")
		}
		if object.Source.GVR == gvr {
			custom++
		}
		if object.Source.GVR.Group == "" && object.Source.GVR.Resource == "secrets" {
			secrets++
		}
	}
	if custom != len(originals) || custom <= 128 || secrets == 0 {
		t.Fatal("native custom pagination or metadata-only Secret evidence missing")
	}
	children, err := observation.Descendants([]types.UID{parent.OriginalUID})
	if err != nil {
		t.Fatal("native custom descendant closure refused")
	}
	selected := map[types.UID]bool{}
	for _, object := range children {
		if object.Source.GVR == gvr {
			selected[object.Metadata.UID] = true
		}
	}
	if len(selected) != 2 || !selected[bridge.GetUID()] || !selected[child.GetUID()] {
		t.Fatal("native custom intermediary omitted or benign custom objects selected")
	}
	if settled, err := wire.settledFixtures(ctx); err != ErrFixtures || settled != nil {
		t.Fatal("native original fixture composition ignored the custom descendant chain")
	}
	durable, gotIdentity, err := ledger.engine.files.Read(ledger.name, fixtureLedgerMaxBytes)
	if err != nil || !bytes.Equal(wal, durable) || !bytes.Equal(wal, ledger.body) || gotIdentity != identity || ledger.identity != identity || ledger.document.Revision != revision || ledger.ackSlot != ack || ledger.effectSlot != effect || ledger.engine.fixtureFence(wire.actors.request.Snapshot) != ErrFixtures {
		t.Fatal("native GC reads changed protected WAL/capabilities/fence")
	}
	t.Log("native complete GC discovery and exact-admin LIST SSARs observed 131 private custom CRs across metadata pages, metadata-only Secrets and the two-level custom owner chain; WAL/capabilities unchanged; original custom objects and CRD require UID/RV cleanup and actual absence")
	return
}
