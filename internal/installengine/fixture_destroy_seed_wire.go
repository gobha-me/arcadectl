// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"time"

	authv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// No generic update/subresource permission or runtime actor expansion. The
// frozen original install-admin must independently hold this exact named right;
// absent discovery/SSAR refuses, never grants access or changes identity.
func (w *fixtureWire) prepareDestroySeed(ctx context.Context) error {
	if w.current(ctx) != nil || !w.ledger.destroySeedReady() {
		return ErrFixtures
	}
	key := w.ledger.document.Entries[fixtureCancelledDestroy].Key
	permission := fixtureDestroySeedPermission(key.Namespace, key.Name)
	parent := w.actors.admission.prerequisites.access
	discovery, err := parent.discover(ctx, key.APIVersion)
	if err != nil || !discoveredPermission(discovery, permission) || parent.authorize(ctx, permission.spec) != nil || w.current(ctx) != nil || !w.ledger.destroySeedReady() {
		return ErrFixtures
	}
	return nil
}

func fixtureDestroySeedPermission(namespace, name string) proofPermission {
	return proofPermission{spec: authv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authv1.ResourceAttributes{
		Group: "arcade.gobha.me", Version: "v1alpha1", Resource: "gamedestroys", Subresource: "status", Namespace: namespace, Name: name, Verb: "update",
	}}, kind: "GameDestroy"}
}

func (f *fixtureLedger) destroySeedReady() bool {
	if f == nil || !f.seedAck || !f.seedEffect || f.ackSlot != -1 || f.effectSlot != -1 || f.document.DestroySeed == nil || f.document.DestroySeed.State != fixtureDestroySeedAttempted {
		return false
	}
	_, err := f.destroySeedStatus() // canonical protected document + original UUID
	return err == nil
}

// Called under wireMu, including from the closed enum request. Prove the actual
// original absent-status whole body and receipt RV immediately before deriving
// the deterministic constructor-only payload. The provider must additionally
// supply complete controller-cold/descendant/permission witnesses; this private
// transport alone is not that provider or a public installer entrypoint.
func (w *fixtureWire) destroySeedPayload(ctx context.Context) (*unstructured.Unstructured, error) {
	if w == nil || w.ledger == nil || !w.ledger.destroySeedReady() || w.prepareDestroySeed(ctx) != nil {
		return nil, ErrFixtures
	}
	if _, _, err := w.prepare(ctx, fixtureCancelledDestroy, "get"); err != nil {
		return nil, ErrFixtures
	}
	observation, err := w.request(ctx, fixtureCancelledDestroy, fixtureGetRequest)
	f := w.ledger
	if err != nil || observation == nil || observation.notFound || observation.result == nil || w.current(ctx) != nil || !f.destroySeedReady() || observation.result.GetResourceVersion() != f.document.DestroySeed.BeforeResourceVersion || f.validateResult(fixtureCancelledDestroy, fixtureStableResult, observation.result, time.Now().UTC()) != nil {
		return nil, ErrFixtures
	}
	o, err := f.object(fixtureCancelledDestroy)
	if err != nil {
		return nil, ErrFixtures
	}
	o.SetUID(f.document.Entries[fixtureCancelledDestroy].OriginalUID)
	o.SetResourceVersion(f.document.DestroySeed.BeforeResourceVersion)
	o.Object["status"], err = f.destroySeedStatus()
	if err != nil {
		return nil, ErrFixtures
	}
	return o, nil
}

// Same-attempt, single-send status seeding of ONE synthetic original. Reliable
// original UID/RV evidence is captured BELOW wrappers and durably acknowledged
// BEFORE post-request witnesses or whole-shape refusal. No later GET, new wire
// or reload can ACK/replay an unknown effect. ACK alone is not cleanup authority.
func (w *fixtureWire) seedDestroyStatus(ctx context.Context) (*unstructured.Unstructured, error) {
	if w == nil || w.ledger == nil {
		return nil, ErrFixtures
	}
	f := w.ledger
	f.wireMu.Lock()
	defer f.wireMu.Unlock()
	if !f.destroySeedReady() {
		return nil, ErrFixtures
	}
	defer func() { f.seedAck, f.seedEffect = false, false }()
	if w.prepareDestroySeed(ctx) != nil {
		return nil, ErrFixtures
	}
	capture, requestErr := w.request(ctx, fixtureCancelledDestroy, fixtureSeedStatusRequest)
	if capture == nil || capture.seedAcknowledgedRV == "" || capture.seedUID != f.document.Entries[fixtureCancelledDestroy].OriginalUID || capture.uid != "" {
		return nil, ErrOutcomeUnknown
	}
	next, err := f.nextDocument()
	if err != nil || next.DestroySeed == nil {
		return nil, ErrFixtures
	}
	next.DestroySeed.State, next.DestroySeed.AcknowledgedResourceVersion = fixtureDestroySeedAcknowledged, capture.seedAcknowledgedRV
	if f.advance(next) != nil || requestErr != nil || w.current(ctx) != nil || capture.result == nil || capture.result.GetResourceVersion() != f.document.DestroySeed.AcknowledgedResourceVersion || f.validateDestroySeedResult(capture.result, time.Now().UTC()) != nil {
		return nil, ErrFixtures
	}
	return capture.result.DeepCopy(), nil
}
