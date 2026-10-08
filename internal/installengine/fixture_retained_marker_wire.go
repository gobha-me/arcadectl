// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Private fixed original synthetic marker route. Reuses the existing ordinary
// software actor with both identity/request and fixture captures. No factory
// grant, generic UPDATE, retry, adoption, cleanup or public entrypoint is added.
func (w *fixtureWire) markRetainedPVC(ctx context.Context) (*unstructured.Unstructured, error) {
	if w == nil || w.ledger == nil {
		return nil, ErrFixtures
	}
	f := w.ledger
	f.wireMu.Lock()
	defer f.wireMu.Unlock()
	return w.markRetainedPVCLocked(ctx)
}

// Caller holds wireMu across the complete marker setup phase interval.
// Once-only capability consumption and ACK ordering remain in this body.
func (w *fixtureWire) markRetainedPVCLocked(ctx context.Context) (*unstructured.Unstructured, error) {
	if w == nil || w.ledger == nil {
		return nil, ErrFixtures
	}
	f := w.ledger
	if !retainedMarkerReady(f) {
		return nil, ErrFixtures
	}
	defer func() { f.markerAck, f.markerEffect = false, false }()
	if ctx == nil || w.current(ctx) != nil {
		return nil, ErrFixtures
	}
	entry := f.document.Entries[fixtureRetainedPVC]
	a := w.actors.clients[ordinaryControllerActor]
	permission, err := actorPermission(entry.Key, probeUpdateOperation)
	if err != nil || a == nil || a.actor == nil || a.actor.actor != ordinaryControllerActor || !a.actor.allows(entry.Key, probeUpdateOperation) || a.base == nil || a.client == nil {
		return nil, ErrFixtures
	}
	parent := w.actors.admission.prerequisites.access
	discovery, err := parent.discover(ctx, entry.Key.APIVersion)
	if err != nil || !discoveredPermission(discovery, permission) || a.authorize(ctx, permission.spec) != nil || w.current(ctx) != nil {
		return nil, ErrFixtures
	}
	live, absent, err := w.getLocked(ctx, fixtureRetainedPVC)
	if err != nil || absent || live == nil || live.GetResourceVersion() != f.document.RetainedMarker.BeforeResourceVersion || f.validateResult(fixtureRetainedPVC, fixtureStableResult, live, time.Now().UTC()) != nil || !retainedMarkerReady(f) || w.current(ctx) != nil {
		return nil, ErrFixtures
	}
	// Every byte is constructor-derived. In particular preserve the certified
	// synthetic binder annotation; never put it on a real/adopted world.
	payload, err := f.retainedMarkerObject()
	path, _, pathErr := fixturePath(entry.Key, false)
	if err != nil || pathErr != nil {
		return nil, ErrFixtures
	}
	payload.SetUID(entry.OriginalUID)
	payload.SetResourceVersion(f.document.RetainedMarker.BeforeResourceVersion)
	payload.SetFinalizers([]string{"kubernetes.io/pvc-protection"})
	body, err := json.Marshal(payload.Object)
	if err != nil || len(body) > 65536 {
		return nil, ErrFixtures
	}
	u := *a.base
	u.Path = strings.TrimRight(u.Path, "/") + path
	u.RawQuery = "fieldManager=arcadectl-installer&fieldValidation=Strict"
	identity := fixtureWireIdentity{actor: ordinaryControllerActor, namespace: a.actor.namespace, username: a.actor.username, authorization: a.actor.authorization}
	capture := &fixtureCapture{identity: identity, method: http.MethodPut, url: u.String(), body: body, key: entry.Key, seedUID: entry.OriginalUID, seedBeforeRV: f.document.RetainedMarker.BeforeResourceVersion}
	actor := &actorRequestCapture{identity: *a.actor, method: http.MethodPut, url: u.String(), body: body}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	ctx = logr.NewContext(ctx, logr.Discard())
	ctx = context.WithValue(ctx, attemptKey{}, &requestAttempt{method: http.MethodPut, actor: actor, fixture: capture})
	r, err := http.NewRequestWithContext(ctx, http.MethodPut, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, ErrFixtures
	}
	r.GetBody = nil
	r.Header.Set("Accept", "application/json")
	r.Header.Set("Content-Type", "application/json")
	if f.document.OriginalWorldsSHA256 != "" && f.originalWorldsCurrent() != nil {
		return nil, ErrFixtures
	}
	f.markerEffect = false // consume BEFORE Do, shared by all clients/rebuilds
	response, requestErr := a.client.Do(r)
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	if capture.seedAcknowledgedRV == "" || capture.seedUID != entry.OriginalUID || capture.uid != "" {
		return nil, ErrOutcomeUnknown
	}
	next, err := f.nextDocument()
	if err != nil || next.RetainedMarker == nil {
		return nil, ErrFixtures
	}
	next.RetainedMarker.State = fixtureRetainedMarkerAcknowledged
	next.RetainedMarker.AcknowledgedResourceVersion = capture.seedAcknowledgedRV
	// Reliable ACK is durable before ANY later wrapper/witness/privacy refusal.
	if f.advance(next) != nil || requestErr != nil || !capture.success || w.current(ctx) != nil || capture.result == nil || capture.result.GetResourceVersion() != f.document.RetainedMarker.AcknowledgedResourceVersion || f.validateRetainedMarkerDelta(live, capture.result, time.Now().UTC()) != nil {
		return nil, ErrFixtures
	}
	return capture.result.DeepCopy(), nil // whole shape only, NOT provider/cleanup authority
}

func retainedMarkerReady(f *fixtureLedger) bool {
	if f == nil || !f.markerAck || !f.markerEffect || f.seedAck || f.seedEffect || f.ackSlot != -1 || f.effectSlot != -1 || f.document.RetainedMarker == nil || f.document.RetainedMarker.State != fixtureRetainedMarkerAttempted {
		return false
	}
	_, err := f.object(fixtureRetainedPVC) // validates canonical protected evidence
	return err == nil && validFixtureRetainedMarkerDocument(f.document)
}
