// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
)

// Real closed original wire on fake TLS; no native or complete matrix claim.
func TestFixtureRecipeV2OriginalWirePreviewAckDeleteAndAbsence(t *testing.T) {
	newPhase := fixturePhaseFactoryWithSetup(t, func(h *fixturePhaseTest) { instrumentFreshFixtureRecipeV2(t, h.f.wire.ledger) })
	h := newPhase(t)
	f, w := h.f.wire.ledger, h.f.wire
	created := time.Now().UTC().Truncate(time.Second).Add(-20 * time.Second)
	for slot := range fixtureCatalog {
		acknowledgeRecipeFixture(t, f, slot, types.UID(fmt.Sprintf("a0000000-0000-4000-8000-%012x", slot+1)))
		h.f.objects[slot] = fixtureResultExample(t, f, slot, fixtureStableResult, created)
	}
	body, identity := bytes.Clone(f.body), f.identity
	preview, err := w.dryRun(t.Context(), fixtureVerifiedCancelledDestroy)
	if err != nil || preview == nil || preview.GetUID() == "" || f.document.Entries[fixtureVerifiedCancelledDestroy].OriginalUID != "" || !bytes.Equal(body, f.body) || identity != f.identity || h.f.previews != 1 || h.f.creates != 0 || h.f.deletes != 0 {
		t.Fatal("v2 preview adopted identity, changed WAL or sent an effect", err)
	}
	h.f.reply = func(reply http.ResponseWriter, o *unstructured.Unstructured) {
		ack := fixtureResultExample(t, f, fixtureVerifiedCancelledDestroy, fixtureAcknowledgedResult, created)
		ack.SetUID(o.GetUID())
		h.f.objects[fixtureVerifiedCancelledDestroy] = ack.DeepCopy()
		reply.WriteHeader(http.StatusCreated)
		if json.NewEncoder(reply).Encode(ack.Object) != nil {
			t.Error("synthetic ACK encoding failed")
		}
	}
	next, _ := f.nextDocument()
	next.Entries[fixtureVerifiedCancelledDestroy].State = fixtureCreateAttempted
	if f.advance(next) != nil {
		t.Fatal("v2 original intent unavailable")
	}
	ack, err := w.create(t.Context(), fixtureVerifiedCancelledDestroy)
	if err != nil || ack == nil || f.validateResult(fixtureVerifiedCancelledDestroy, fixtureAcknowledgedResult, ack, time.Now().UTC()) != nil || f.document.Entries[fixtureVerifiedCancelledDestroy].OriginalUID != ack.GetUID() || ack.GetUID() == preview.GetUID() || h.f.creates != 1 {
		t.Fatal("v2 CREATE lacked original whole ACK", err)
	}
	if _, err := w.create(t.Context(), fixtureVerifiedCancelledDestroy); err != ErrFixtures || h.f.creates != 1 {
		t.Fatal("v2 original CREATE replayed")
	}
	next, _ = f.nextDocument()
	next.Entries[fixtureVerifiedCancelledDestroy].State, next.Entries[fixtureVerifiedCancelledDestroy].DeleteResourceVersion = fixtureDeleteAttempted, ack.GetResourceVersion()
	if f.advance(next) != nil || w.delete(t.Context(), fixtureVerifiedCancelledDestroy) != nil || h.f.deletes != 1 {
		t.Fatal("v2 DELETE failed exact original intent")
	}
	if w.delete(t.Context(), fixtureVerifiedCancelledDestroy) != ErrFixtures || h.f.deletes != 1 {
		t.Fatal("v2 original DELETE replayed")
	}
	if o, absent, err := w.get(t.Context(), fixtureVerifiedCancelledDestroy); err != nil || !absent || o != nil {
		t.Fatal("v2 original absence unproved")
	}
	next, _ = f.nextDocument()
	next.Entries[fixtureVerifiedCancelledDestroy].State = fixtureAbsent
	if f.advance(next) != nil || h.f.previews != 1 || h.f.creates != 1 || h.f.deletes != 1 || h.f.seeds != 0 || f.behaviorCompletion != nil {
		t.Fatal("v2 absence altered seed or behavior authority")
	}
}

func TestFixtureRecipeV1UnusedCompositionTailRefused(t *testing.T) {
	h := fixturePhaseFactory(t)(t)
	f := h.f.wire.ledger
	phase, err := h.f.wire.observePhase(t.Context())
	if err != nil || phase == nil || phase.objects[fixtureVerifiedCancelledDestroy] != nil {
		t.Fatal("v1 composition acquired v2 tail", err)
	}
	observation, err := h.f.actor.admission.prerequisites.observe(t.Context(), h.f.actor.request)
	if err != nil || f.phaseGC(observation, phase.objects, phase.gc, nil) != nil {
		t.Fatal("unchanged v1 GC composition refused", err)
	}
	objects := phase.objects
	objects[fixtureVerifiedCancelledDestroy] = &unstructured.Unstructured{Object: map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": "foreign"}}}
	if f.phaseGC(observation, objects, phase.gc, nil) != ErrFixtures {
		t.Fatal("nonempty v1 tail became an unaccounted exemption")
	}
}
