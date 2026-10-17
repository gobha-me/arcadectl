// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"reflect"
	"time"

	"github.com/gobha-me/arcadectl/internal/installobserve"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
)

// Private, read-only composition of original whole shapes and namespace GC
// metadata. It does NOT authorize cleanup, settle uncertain effects, retire a
// WAL, exempt fixtures from ordinary cold/runtime checks or lock cluster writers.
// World/storage/controller safety must be established independently by the full
// provider around every effect. No object or effect capability is exported.
type settledFixtureObservation struct {
	wire     *fixtureWire
	identity privatefs.FileIdentity
	body     []byte
	objects  [fixtureMaxSlots]*unstructured.Unstructured
	gc       *installobserve.GCObservation
}

func (w *fixtureWire) settledFixtures(ctx context.Context) (*settledFixtureObservation, error) {
	if w == nil || w.ledger == nil || ctx == nil {
		return nil, ErrFixtures
	}
	w.ledger.wireMu.Lock()
	defer w.ledger.wireMu.Unlock()
	if !w.fixturesSettled() || w.current(ctx) != nil {
		return nil, ErrFixtures
	}
	f := w.ledger
	observation := &settledFixtureObservation{wire: w, identity: f.identity, body: bytes.Clone(f.body)}
	stable := func() bool {
		return w.fixturesSettled() && f.identity == observation.identity && bytes.Equal(f.body, observation.body)
	}
	current := func() bool {
		if !stable() || w.current(ctx) != nil || !stable() {
			return false
		}
		// Close the local WAL/capability boundary AFTER actor verification as
		// well. An original actor read cannot hide a late local-file change.
		body, identity, err := f.engine.files.Read(f.name, fixtureLedgerMaxBytes)
		if err != nil || identity != observation.identity || !bytes.Equal(body, observation.body) || f.engine.files.ConfirmDurable(f.name, identity) != nil {
			return false
		}
		document, err := f.engine.decodeFixtureLedger(body)
		return err == nil && reflect.DeepEqual(document, f.document) && stable()
	}
	read := func(slot int) (*unstructured.Unstructured, error) {
		if !current() {
			return nil, ErrFixtures
		}
		object, absent, err := w.getLocked(ctx, slot)
		if err != nil || absent || object == nil || !current() {
			return nil, ErrFixtures
		}
		shape := f.validateResult(slot, fixtureStableResult, object, time.Now().UTC())
		if slot == fixtureCancelledDestroy && f.document.DestroySeed != nil {
			shape = f.validateDestroySeedResult(object, time.Now().UTC())
			if object.GetResourceVersion() != f.document.DestroySeed.AcknowledgedResourceVersion {
				shape = ErrFixtures
			}
		}
		if shape != nil {
			return nil, ErrFixtures
		}
		return object, nil
	}
	for slot := range fixtureCatalogFor(f.document) {
		object, err := read(slot)
		if err != nil {
			return nil, ErrFixtures
		}
		observation.objects[slot] = object
	}
	gc, err := w.gcMetadataLocked(ctx)
	if err != nil || gc == nil || !current() {
		return nil, ErrFixtures
	}
	rows := gc.Objects()
	for slot := range f.document.Entries {
		original := observation.objects[slot]
		source, err := fixtureGCSource(f.document.Entries[slot])
		if err != nil {
			return nil, ErrFixtures
		}
		metadata := fixtureGCMetadata(original)
		matches := 0
		for _, row := range rows {
			if row.Metadata.UID != original.GetUID() {
				continue
			}
			if row.Source != source || !reflect.DeepEqual(row.Metadata, metadata) {
				return nil, ErrFixtures
			}
			matches++
		}
		if matches != 1 {
			return nil, ErrFixtures
		}
		children, err := gc.Descendants([]types.UID{original.GetUID()})
		if err != nil {
			return nil, ErrFixtures
		}
		// Per-root closure is essential: putting every fixture UID in roots
		// would hide the original workers (Descendants excludes its roots).
		worker := -1
		for candidate, recipe := range fixtureCatalogFor(f.document) {
			if recipe.owner == slot {
				worker = candidate
			}
		}
		if worker == -1 {
			if len(children) != 0 {
				return nil, ErrFixtures
			}
		} else {
			workerSource, err := fixtureGCSource(f.document.Entries[worker])
			if err != nil || len(children) != 1 || children[0].Source != workerSource || !reflect.DeepEqual(children[0].Metadata, fixtureGCMetadata(observation.objects[worker])) {
				return nil, ErrFixtures
			}
		}
		fresh, err := read(slot)
		if err != nil || !reflect.DeepEqual(original.Object, fresh.Object) {
			return nil, ErrFixtures
		}
	}
	if !current() {
		return nil, ErrFixtures
	}
	observation.gc = gc
	return observation, nil
}

func (w *fixtureWire) fixturesSettled() bool {
	if w == nil || w.ledger == nil {
		return false
	}
	f := w.ledger
	if f.markerUnresolved() || !validFixtureRecipe(f.document) || f.ackSlot != -1 || f.effectSlot != -1 || f.seedAck || f.seedEffect || f.document.DestroySeed != nil && (f.document.DestroySeed.Mode != fixtureDestroySeedCold || f.document.DestroySeed.State != fixtureDestroySeedAcknowledged) {
		return false
	}
	for _, entry := range f.document.Entries {
		if entry.State != fixtureOriginal || !nativeFixtureUID(string(entry.OriginalUID)) || entry.DeleteResourceVersion != "" {
			return false
		}
	}
	return true
}

func fixtureGCSource(entry fixtureEntry) (installobserve.GCResource, error) {
	_, resource, err := fixturePath(entry.Key, true)
	gv, parseErr := schema.ParseGroupVersion(entry.Key.APIVersion)
	if err != nil || parseErr != nil {
		return installobserve.GCResource{}, ErrFixtures
	}
	return installobserve.GCResource{GVR: gv.WithResource(resource), Kind: entry.Key.Kind}, nil
}

// Same deliberately public projection as the below-wrapper metadata reader.
// Labels, annotations, managed fields, status and arbitrary payload never serve
// as GC identity. Whole GET validation independently accounts for those fields.
func fixtureGCMetadata(object metav1.Object) metav1.ObjectMeta {
	metadata := metav1.ObjectMeta{Name: object.GetName(), Namespace: object.GetNamespace(), UID: object.GetUID(), ResourceVersion: object.GetResourceVersion(), Generation: object.GetGeneration(), OwnerReferences: object.GetOwnerReferences()}
	if timestamp := object.GetDeletionTimestamp(); timestamp != nil {
		metadata.DeletionTimestamp = timestamp.DeepCopy()
	}
	return *metadata.DeepCopy()
}
