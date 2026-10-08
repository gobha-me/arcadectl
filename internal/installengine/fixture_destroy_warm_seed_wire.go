// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"time"

	platformkube "github.com/gobha-me/arcadectl/internal/platform/kube"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Separate closed warm route. Mode is chosen BEFORE intent, never inferred
// from a GET or retried as a different route. Existing named-status discovery/
// SSAR must authorize the original install-admin; no runtime rights are added.
func (w *fixtureWire) prepareWarmDestroySeed(ctx context.Context) error {
	if w == nil || w.ledger == nil || !w.ledger.destroyWarmSeedReady() || w.current(ctx) != nil {
		return ErrFixtures
	}
	key := w.ledger.document.Entries[fixtureCancelledDestroy].Key
	parent := w.actors.admission.prerequisites.access
	permission := fixtureDestroySeedPermission(key.Namespace, key.Name)
	discovery, err := parent.discover(ctx, key.APIVersion)
	if err != nil || !discoveredPermission(discovery, permission) || parent.authorize(ctx, permission.spec) != nil || w.current(ctx) != nil || !w.ledger.destroyWarmSeedReady() {
		return ErrFixtures
	}
	return nil
}

func (f *fixtureLedger) destroyWarmSeedReady() bool {
	if f.markerUnresolved() || !f.seedAck || !f.seedEffect || f.ackSlot != -1 || f.effectSlot != -1 || f.document.DestroySeed == nil || f.document.DestroySeed.Mode != fixtureDestroySeedWarmCancelled || f.document.DestroySeed.State != fixtureDestroySeedAttempted {
		return false
	}
	_, err := f.destroyWarmSeedStatus()
	return err == nil
}

// Caller holds wireMu. The strict original cancellation and exact intent RV
// are prerequisites ONLY: derive the entire payload from the protected recipe,
// original UID/RV, sole known finalizer and fixed expired preview. Never copy
// live status or arbitrary metadata. Full controller/world/storage/GC witnesses
// still belong to the complete provider, not this private transport primitive.
func (w *fixtureWire) warmDestroySeedPayload(ctx context.Context) (*unstructured.Unstructured, error) {
	if w == nil || w.ledger == nil || !w.ledger.destroyWarmSeedReady() || w.prepareWarmDestroySeed(ctx) != nil {
		return nil, ErrFixtures
	}
	if _, _, err := w.prepare(ctx, fixtureCancelledDestroy, "get"); err != nil {
		return nil, ErrFixtures
	}
	observation, err := w.request(ctx, fixtureCancelledDestroy, fixtureGetRequest)
	f := w.ledger
	if err != nil || observation == nil || observation.notFound || observation.result == nil || w.current(ctx) != nil || !f.destroyWarmSeedReady() || observation.result.GetResourceVersion() != f.document.DestroySeed.BeforeResourceVersion || f.validateWarmCancelledDestroyResult(observation.result, time.Now().UTC()) != nil {
		return nil, ErrFixtures
	}
	o, err := f.object(fixtureCancelledDestroy)
	if err != nil {
		return nil, ErrFixtures
	}
	o.SetUID(f.document.Entries[fixtureCancelledDestroy].OriginalUID)
	o.SetResourceVersion(f.document.DestroySeed.BeforeResourceVersion)
	o.SetFinalizers([]string{platformkube.DestroyFinalizer})
	o.Object["status"], err = f.destroyWarmSeedStatus()
	if err != nil {
		return nil, ErrFixtures
	}
	return o, nil
}

// Same-attempt one-send warm seeding. A reliable below-wrapper original UID/
// distinct RV ACK is durably recorded BEFORE later witness/whole-shape refusal.
// Unknown replies stay attempted across GET/rebuild/reload and never replay.
// Accepted shape is not confirmation, cleanup, coldness or WAL retirement.
func (w *fixtureWire) seedWarmDestroyStatus(ctx context.Context) (*unstructured.Unstructured, error) {
	if w == nil || w.ledger == nil {
		return nil, ErrFixtures
	}
	f := w.ledger
	f.wireMu.Lock()
	defer f.wireMu.Unlock()
	return w.seedWarmDestroyStatusLocked(ctx)
}

// Caller holds wireMu across the complete setup phase interval. Preserve
// reliable-ACK publication and capability revocation before post-observation.
func (w *fixtureWire) seedWarmDestroyStatusLocked(ctx context.Context) (*unstructured.Unstructured, error) {
	if w == nil || w.ledger == nil {
		return nil, ErrFixtures
	}
	f := w.ledger
	if !f.destroyWarmSeedReady() {
		return nil, ErrFixtures
	}
	defer func() { f.seedAck, f.seedEffect = false, false }()
	if w.prepareWarmDestroySeed(ctx) != nil {
		return nil, ErrFixtures
	}
	capture, requestErr := w.request(ctx, fixtureCancelledDestroy, fixtureWarmSeedStatusRequest)
	if capture == nil || capture.seedAcknowledgedRV == "" || capture.seedUID != f.document.Entries[fixtureCancelledDestroy].OriginalUID || capture.uid != "" {
		return nil, ErrOutcomeUnknown
	}
	next, err := f.nextDocument()
	if err != nil || next.DestroySeed == nil {
		return nil, ErrFixtures
	}
	next.DestroySeed.State, next.DestroySeed.AcknowledgedResourceVersion = fixtureDestroySeedAcknowledged, capture.seedAcknowledgedRV
	if f.advance(next) != nil || requestErr != nil || w.current(ctx) != nil || capture.result == nil || capture.result.GetResourceVersion() != f.document.DestroySeed.AcknowledgedResourceVersion || f.validateWarmDestroySeedResult(capture.result, time.Now().UTC()) != nil {
		return nil, ErrFixtures
	}
	return capture.result.DeepCopy(), nil
}
