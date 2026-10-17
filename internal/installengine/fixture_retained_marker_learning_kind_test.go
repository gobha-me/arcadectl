//go:build kindinstall

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installstate"
	authv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

// Called ONLY in the exclusively owned, empty-world Kind runner. Learning a
// single annotation does not certify post-write whole ownership or authorize
// object cleanup. The existing marker fence leaves all originals for exact-
// owned Kind teardown; no real cluster/config/world can reach this helper.
func proveKindRetainedMarkerLearning(t *testing.T, ctx context.Context, p *ClusterPrerequisites, request LifecycleCheck, baseline map[installstate.Key]*unstructured.Unstructured, w *fixtureWire, admin dynamic.Interface) {
	t.Helper()
	f := w.ledger
	if f.document.RetainedMarker != nil || f.markerAck || f.markerEffect || f.seedAck || f.seedEffect || f.ackSlot != -1 || f.effectSlot != -1 {
		t.Fatal("original retained marker learning prerequisites unresolved")
	}
	var before *unstructured.Unstructured
	beforeCheck := func() {
		t.Helper()
		observation, err := p.observe(ctx, request)
		current, mapErr := warmNativeObjects(observation)
		live, absent, getErr := w.get(ctx, fixtureRetainedPVC)
		if err != nil || mapErr != nil || warmNativeBaseline(f, baseline, current) != nil || getErr != nil || absent || f.validateResult(fixtureRetainedPVC, fixtureStableResult, live, time.Now().UTC()) != nil || !reflect.DeepEqual(current[f.document.Entries[fixtureRetainedPVC].Key], live) || warmNativeIsolation(ctx, w, admin) != nil || retainedMarkerNativeStorageAbsent(ctx, p, current, f.document.Entries[fixtureRetainedPVC].Key, admin) != nil || w.current(ctx) != nil {
			t.Fatal("complete original nonbinding marker baseline unproved")
		}
		before = live
	}
	beforeCheck()
	// Capture pre-effect public bookkeeping separately, before marker intent.
	if captureNativeFixtureShape(f, fixtureRetainedPVC, "live", before) != nil {
		t.Fatal("private original retained-PVC diagnostic unavailable")
	}
	beforeCheck()
	next, err := f.nextDocument()
	if err != nil {
		t.Fatal("original retained marker intent unavailable")
	}
	next.RetainedMarker = &fixtureRetainedMarkerReceipt{State: fixtureRetainedMarkerAttempted, BeforeResourceVersion: before.GetResourceVersion()}
	if f.advance(next) != nil {
		t.Fatal("original retained marker intent durability refused")
	}
	// Failures still receive bounded read-only storage/domain/GC observations.
	// This never adopts an ACK, captures an untrusted body or allows cleanup.
	defer func() {
		if !t.Failed() {
			return
		}
		auditCtx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		observation, err := p.observe(auditCtx, request)
		current, mapErr := warmNativeObjects(observation)
		journal, journalErr := f.engine.journal.Load(auditCtx, request.Snapshot.Anchor())
		if err != nil || mapErr != nil || retainedMarkerNativeFailureBaseline(f, baseline, current) != nil || retainedMarkerNativeStorageAbsent(auditCtx, p, current, f.document.Entries[fixtureRetainedPVC].Key, admin) != nil || warmNativeIsolation(auditCtx, w, admin) != nil || journalErr != nil || !bytes.Equal(journal.Bytes(), request.Snapshot.Bytes()) || journal.ResourceVersion() != request.Snapshot.ResourceVersion() || w.current(auditCtx) != nil || f.markerAck || f.markerEffect {
			t.Log("failed marker attempt: read-only original storage/domain/GC/journal witness unresolved; no ACK adoption/replay/object cleanup; owned teardown required")
			return
		}
		t.Log("failed marker attempt: unrelated original full baseline/storage/GC/journal unchanged; slot7 outcome remains unaccepted; no ACK adoption/replay/object cleanup; owned teardown required")
	}()
	beforeCheck() // full independent storage/domain witnesses AFTER durable intent
	// No subsequent object DELETE is allowed, regardless of this result.
	marked, err := retainedMarkerLearningOnce(ctx, w)
	if err != nil || marked == nil || retainedMarkerLearningDelta(f, before, marked, time.Now().UTC()) != nil || f.markerAck || f.markerEffect {
		t.Fatal("fixed original ordinary-actor marker native ACK/privacy refused")
	}
	if captureNativeFixtureShape(f, fixtureRetainedPVC, "retained-marker-learning", marked) != nil {
		t.Fatal("private public-only retained marker diagnostic refused")
	}
	ackBody, ackIdentity := bytes.Clone(f.body), f.identity
	if _, err := retainedMarkerLearningOnce(ctx, w); err != ErrFixtures {
		t.Fatal("native retained marker write replayed")
	}
	for range 2 {
		live, absent, getErr := w.get(ctx, fixtureRetainedPVC)
		observation, err := p.observe(ctx, request)
		current, mapErr := warmNativeObjects(observation)
		journal, journalErr := f.engine.journal.Load(ctx, request.Snapshot.Anchor())
		if getErr != nil || absent || live == nil || !reflect.DeepEqual(live.Object, marked.Object) || retainedMarkerLearningPublic(f, live, time.Now().UTC()) != nil || err != nil || mapErr != nil || retainedMarkerNativeLearningBaseline(f, baseline, current, marked) != nil || warmNativeIsolation(ctx, w, admin) != nil || retainedMarkerNativeStorageAbsent(ctx, p, current, f.document.Entries[fixtureRetainedPVC].Key, admin) != nil || journalErr != nil || !bytes.Equal(journal.Bytes(), request.Snapshot.Bytes()) || journal.ResourceVersion() != request.Snapshot.ResourceVersion() || w.current(ctx) != nil || !bytes.Equal(f.body, ackBody) || f.identity != ackIdentity || f.markerAck || f.markerEffect || f.engine.fixtureFence(request.Snapshot) != ErrFixtures {
			t.Fatal("retained marker learning changed complete original baseline/storage/GC/WAL")
		}
		gc, err := w.gcMetadata(ctx)
		source, sourceErr := fixtureGCSource(f.document.Entries[fixtureRetainedPVC])
		if err != nil || sourceErr != nil {
			t.Fatal("marked original metadata closure unavailable")
		}
		matches := 0
		for _, row := range gc.Objects() {
			if row.Metadata.UID == marked.GetUID() {
				if row.Source != source || !reflect.DeepEqual(row.Metadata, fixtureGCMetadata(marked)) {
					t.Fatal("marked original full/metadata witnesses diverged")
				}
				matches++
			}
		}
		if matches != 1 {
			t.Fatal("marked original metadata row absent or duplicated")
		}
		fresh, absent, err := w.get(ctx, fixtureRetainedPVC)
		if err != nil || absent || fresh == nil || !reflect.DeepEqual(fresh.Object, marked.Object) || w.current(ctx) != nil {
			t.Fatal("marked original changed after storage/GC witnesses")
		}
	}
	if w.fixturesSettled() || f.validateResult(fixtureRetainedPVC, fixtureStableResult, marked, time.Now().UTC()) != ErrFixtures {
		t.Fatal("marker learning became ordinary whole/settled authority")
	}
	t.Log("fixed original ordinary-controller marker UPDATE reliably ACKed; public bookkeeping only; fresh original GET/full unfiltered baseline/GC/global PV and attachment absence/no consumers/journal/WAL unchanged; production whole shape and object cleanup remain forbidden; exact-owned empty Kind teardown required")
}

// This empty-test-only witness is deliberately stricter than a production
// world-preservation proof. It is NOT namespace GC pretending to cover global
// volumes, or a permit to require every real installation to have zero PVs.
func retainedMarkerNativeStorageAbsent(ctx context.Context, p *ClusterPrerequisites, current map[installstate.Key]*unstructured.Unstructured, claim installstate.Key, admin dynamic.Interface) error {
	if ctx == nil || p == nil || p.access == nil || admin == nil || claim.Kind != "PersistentVolumeClaim" || claim.Namespace == "" || !addressPart(claim.Name) {
		return ErrFixtures
	}
	for _, item := range []struct {
		gvr  schema.GroupVersionResource
		kind string
	}{
		{schema.GroupVersionResource{Version: "v1", Resource: "persistentvolumes"}, "PersistentVolume"},
		{schema.GroupVersionResource{Group: "storage.k8s.io", Version: "v1", Resource: "volumeattachments"}, "VolumeAttachment"},
	} {
		version := item.gvr.Version
		if item.gvr.Group != "" {
			version = item.gvr.Group + "/" + version
		}
		permission := proofPermission{kind: item.kind, spec: authv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authv1.ResourceAttributes{Group: item.gvr.Group, Version: item.gvr.Version, Resource: item.gvr.Resource, Verb: "list"}}}
		discovery, err := p.access.discover(ctx, version)
		if err != nil || !discoveredPermission(discovery, permission) || p.access.authorize(ctx, permission.spec) != nil {
			return ErrFixtures
		}
		list, err := admin.Resource(item.gvr).List(ctx, metav1.ListOptions{Limit: 128})
		if err != nil || list == nil || !fixtureRV(list.GetResourceVersion()) || list.GetContinue() != "" || list.GetRemainingItemCount() != nil && *list.GetRemainingItemCount() != 0 || len(list.Items) != 0 {
			return ErrFixtures
		}
	}
	for key, object := range current {
		if key.Namespace != claim.Namespace {
			continue
		}
		switch key.Kind {
		case "Pod", "Job", "Deployment", "ReplicaSet", "StatefulSet", "DaemonSet", "ReplicationController", "CronJob":
			if retainedMarkerClaimConsumer(object.Object, claim.Name) {
				return ErrFixtures
			}
		}
	}
	return nil
}

// Failure-only read witness: require every unrelated original body and known
// address/UID, but do NOT accept/adopt slot7's unknown whole shape or RV.
func retainedMarkerNativeFailureBaseline(f *fixtureLedger, baseline, current map[installstate.Key]*unstructured.Unstructured) error {
	if f == nil || len(f.document.Entries) != len(fixtureCatalog) || warmNativeLeaders(baseline, current, time.Now().UTC()) != nil || len(current) != len(baseline)+len(fixtureCatalog) {
		return ErrFixtures
	}
	for key, original := range baseline {
		fresh := current[key]
		if fresh == nil || key.Kind != "Lease" && !reflect.DeepEqual(original.Object, fresh.Object) {
			return ErrFixtures
		}
	}
	for slot, entry := range f.document.Entries {
		fresh := current[entry.Key]
		if entry.State != fixtureOriginal || fresh == nil || fresh.GetUID() != entry.OriginalUID || baseline[entry.Key] != nil {
			return ErrFixtures
		}
		if slot != fixtureRetainedPVC && !warmNativeWhole(f, slot, fresh) {
			return ErrFixtures
		}
	}
	return nil
}

func retainedMarkerClaimConsumer(raw any, claim string) bool {
	switch value := raw.(type) {
	case map[string]any:
		if pvc, ok := value["persistentVolumeClaim"].(map[string]any); ok && pvc["claimName"] == claim {
			return true
		}
		for _, child := range value {
			if retainedMarkerClaimConsumer(child, claim) {
				return true
			}
		}
	case []any:
		for _, child := range value {
			if retainedMarkerClaimConsumer(child, claim) {
				return true
			}
		}
	}
	return false
}

// Explicit TEST-only accounting over the COMPLETE observation. The marker's
// ACK-bound diagnostic object is compared without projecting/filtering rows;
// every other fixture still needs its unchanged exact native whole contract.
func retainedMarkerNativeLearningBaseline(f *fixtureLedger, baseline, current map[installstate.Key]*unstructured.Unstructured, marked *unstructured.Unstructured) error {
	if marked == nil || retainedMarkerLearningPublic(f, marked, time.Now().UTC()) != nil || warmNativeLeaders(baseline, current, time.Now().UTC()) != nil || len(current) != len(baseline)+len(fixtureCatalog) {
		return ErrFixtures
	}
	for key, original := range baseline {
		fresh := current[key]
		if fresh == nil || key.Kind != "Lease" && !reflect.DeepEqual(original.Object, fresh.Object) {
			return ErrFixtures
		}
	}
	for slot, entry := range f.document.Entries {
		fresh := current[entry.Key]
		if entry.State != fixtureOriginal || fresh == nil || fresh.GetUID() != entry.OriginalUID || baseline[entry.Key] != nil {
			return ErrFixtures
		}
		if slot == fixtureRetainedPVC {
			if !reflect.DeepEqual(fresh.Object, marked.Object) {
				return ErrFixtures
			}
		} else if !warmNativeWhole(f, slot, fresh) {
			return ErrFixtures
		}
	}
	return nil
}
