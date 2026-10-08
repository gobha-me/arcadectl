// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/gobha-me/arcadectl/internal/privatefs"
)

// Closed cleanup of the next reverse-order original in an acknowledged-marker
// run. This never clears a marker receipt or relaxes ANY old effect route. The
// entire original phase, not an ACK receipt alone, justifies a durable intent.
// A lost response leaves an attempted original; later calls can only prove its
// actual absence, NEVER replay its DELETE. Safe aborted-run cleanup is allowed,
// but neither cleanup nor retirement supplies missing behavior completion.
func (w *fixtureWire) removeAcknowledgedMarkerOriginal(ctx context.Context, slot int) error {
	return w.removeKnownOriginal(ctx, slot, true)
}

// An unmarked aborted run has the same original-identity cleanup obligations;
// it must not acquire permission to send any marker/status/setup request.
func (w *fixtureWire) removeUnmarkedOriginal(ctx context.Context, slot int) error {
	return w.removeKnownOriginal(ctx, slot, false)
}

func (w *fixtureWire) removeKnownOriginal(ctx context.Context, slot int, marked bool) error {
	if ctx == nil || w == nil || w.ledger == nil || w.actors == nil || w.actors.admission == nil || w.actors.admission.prerequisites == nil || w.actors.admission.prerequisites.access == nil || w.actors.admission.prerequisites.access.frozen == nil {
		return ErrFixtures
	}
	f := w.ledger
	f.wireMu.Lock()
	defer f.wireMu.Unlock()
	if !w.phaseReadable() || f.retirementArchive || f.retirementPublicationUnknown || !validFixtureRetainedMarkerDocument(f.document) || marked && (f.document.RetainedMarker == nil || f.document.RetainedMarker.State != fixtureRetainedMarkerAcknowledged) || !marked && f.document.RetainedMarker != nil {
		return ErrFixtures
	}
	nextSlot := -1
	for index := len(f.document.Entries) - 1; index >= 0; index-- {
		if f.document.Entries[index].State != fixtureAbsent {
			nextSlot = index
			break
		}
	}
	if slot < 0 || slot != nextSlot {
		return ErrFixtures
	}
	entry := f.document.Entries[slot]
	if entry.State != fixtureOriginal && entry.State != fixtureDeleteAttempted {
		return ErrFixtures
	}
	var observed *fixturePhaseObservation
	if entry.State == fixtureOriginal {
		body, identity := bytes.Clone(f.body), f.identity
		permission, err := fixturePermission(entry.Key, "delete")
		actor := fixtureActor(slot, "delete")
		parent := w.actors.admission.prerequisites.access
		discovery, discoveryErr := parent.discover(ctx, entry.Key.APIVersion)
		authorizer := parent
		if actor != 0 {
			authorizer = w.actors.clients[actor]
		}
		if err != nil || discoveryErr != nil || !discoveredPermission(discovery, permission) || authorizer == nil || authorizer.authorize(ctx, permission.spec) != nil || w.markedCleanupCurrent(ctx, body, identity) != nil {
			return ErrFixtures
		}
		phase, err := w.observePhaseLocked(ctx)
		if err != nil || phase == nil || phase.objects[slot] == nil || w.markedCleanupCurrent(ctx, body, identity) != nil {
			return ErrFixtures
		}
		original := phase.objects[slot]
		if original.GetUID() != entry.OriginalUID || !fixtureRV(original.GetResourceVersion()) {
			return ErrFixtures
		}
		next, err := f.nextDocument()
		if err != nil {
			return ErrFixtures
		}
		next.Entries[slot].State = fixtureDeleteAttempted
		next.Entries[slot].DeleteResourceVersion = original.GetResourceVersion()
		if f.advance(next) != nil {
			return ErrFixtures
		}
		// This closure is the ONLY new effect path. No request enum/factory or
		// externally reusable send witness accepts acknowledged-marker effects.
		// Consume even a pre-send refusal: an intent is never a replay grant.
		defer func() {
			if f.effectSlot == slot {
				f.effectSlot = -1
			}
		}()
		body, identity = bytes.Clone(f.body), f.identity
		if f.effectSlot != slot || !reflect.DeepEqual(f.document, next) || w.markedCleanupCurrent(ctx, body, identity) != nil {
			return ErrFixtures
		}
		options, err := fixtureDeleteOptions(f.document.Entries[slot])
		payload, marshalErr := json.Marshal(options)
		path, _, pathErr := fixturePath(entry.Key, false)
		a := w.clients[actor]
		if err != nil || marshalErr != nil || pathErr != nil || len(payload) > 65536 || a == nil || a.base == nil || a.client == nil {
			return ErrFixtures
		}
		wireIdentity := fixtureWireIdentity{actor: actor, namespace: entry.Key.Namespace}
		if actor != 0 {
			wireIdentity.username = "system:serviceaccount:" + entry.Key.Namespace + ":" + actor.account()
		}
		config := parent.frozen
		if config.BearerToken != "" {
			wireIdentity.authorization = "Bearer " + config.BearerToken
		} else if config.Username != "" || config.Password != "" {
			wireIdentity.authorization = "Basic " + base64.StdEncoding.EncodeToString([]byte(config.Username+":"+config.Password))
		}
		u := *a.base
		u.Path, u.RawQuery = strings.TrimRight(u.Path, "/")+path, ""
		capture := &fixtureCapture{identity: wireIdentity, method: http.MethodDelete, url: u.String(), body: payload, key: entry.Key}
		requestCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		requestCtx = logr.NewContext(requestCtx, logr.Discard())
		requestCtx = context.WithValue(requestCtx, attemptKey{}, &requestAttempt{method: http.MethodDelete, fixture: capture})
		r, err := http.NewRequestWithContext(requestCtx, http.MethodDelete, u.String(), bytes.NewReader(payload))
		if err != nil || w.markedCleanupCurrent(ctx, body, identity) != nil || !reflect.DeepEqual(f.document, next) || f.effectSlot != slot {
			return ErrFixtures
		}
		r.GetBody = nil
		r.Header.Set("Accept", "application/json")
		r.Header.Set("Content-Type", "application/json")
		f.effectSlot = -1 // shared capability consumed BEFORE any possible send
		response, requestErr := a.client.Do(r)
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		// Mandatory post-attempt observation, including transport/capture errors.
		// It cannot acknowledge DELETE or repair uncertainty; the durable intent
		// remains the only disposition until a later complete absence read.
		post, postErr := w.observePhaseLocked(ctx)
		if requestErr != nil || !capture.success || w.markedCleanupCurrent(ctx, body, identity) != nil {
			return ErrOutcomeUnknown
		}
		if postErr != nil || post == nil || post.objects[slot] != nil {
			return ErrFixtures
		}
		observed = post
	}
	// DELETE acknowledgment is not absence. A present attempted object is
	// deliberately refused by complete phase accounting, never normalized.
	var observeErr error
	if observed == nil {
		observed, observeErr = w.observePhaseLocked(ctx)
	}
	if observeErr != nil || observed == nil || observed.objects[slot] != nil {
		return ErrFixtures
	}
	next, err := f.nextDocument()
	if err != nil || next.Entries[slot].State != fixtureDeleteAttempted {
		return ErrFixtures
	}
	next.Entries[slot].State = fixtureAbsent
	if f.advance(next) != nil {
		return ErrFixtures
	}
	if _, err := w.observePhaseLocked(ctx); err != nil {
		return ErrFixtures
	}
	return nil
}

// Close the protected-file boundary AFTER remote actor/journal reads. Captured
// body+file identity pin this same instance/phase or its one exact intent, not a
// matching name, marker, recreated file, legacy companion or caller-selected RV.
func (w *fixtureWire) markedCleanupCurrent(ctx context.Context, body []byte, identity privatefs.FileIdentity) error {
	f := w.ledger
	if f.ackSlot != -1 || f.seedAck || f.seedEffect || f.markerAck || f.markerEffect || f.worldPublication || f.behaviorCompletion != nil || f.retirementArchive || f.retirementPublicationUnknown || !bytes.Equal(f.body, body) || f.identity != identity || w.current(ctx) != nil {
		return ErrFixtures
	}
	live, fileID, err := f.engine.files.Read(f.name, fixtureLedgerMaxBytes)
	if err != nil || fileID != identity || f.identity != identity || !bytes.Equal(live, body) || !bytes.Equal(f.body, body) || f.engine.files.ConfirmDurable(f.name, identity) != nil || f.originalWorldsCurrent() != nil {
		return ErrFixtures
	}
	document, err := f.engine.decodeFixtureLedger(live)
	if err != nil || !reflect.DeepEqual(document, f.document) {
		return ErrFixtures
	}
	return nil
}
