// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func fixtureMarkerWireNativeReply(t *testing.T, h *retainedMarkerLearningFixture) {
	t.Helper()
	h.reply = func(r http.ResponseWriter, o *unstructured.Unstructured) {
		o.Object = fixtureMarkedRetainedExample(t, h.f.wire.ledger, o.GetCreationTimestamp().Time).Object
		h.f.objects[fixtureRetainedPVC] = o.DeepCopy()
		_ = json.NewEncoder(r).Encode(o.Object)
	}
}

func TestFixtureRetainedMarkerWireWholeAckNoReplayOrReloadAuthority(t *testing.T) {
	h := retainedMarkerLearningFactory(t)(t)
	fixtureMarkerWireNativeReply(t, h)
	w, f := h.f.wire, h.f.wire.ledger
	o, err := w.markRetainedPVC(t.Context())
	if err != nil || o == nil || h.updates != 1 || f.document.RetainedMarker.State != fixtureRetainedMarkerAcknowledged || f.markerAck || f.markerEffect || f.validateRetainedMarkerDelta(h.before, o, time.Now().UTC()) != nil {
		t.Fatal("original fixed marker failed reliable ACK/whole delta")
	}
	changed := o.DeepCopy()
	changed.SetCreationTimestamp(metav1.NewTime(o.GetCreationTimestamp().Add(-time.Second)))
	if f.validateRetainedMarkerResult(changed, time.Now().UTC()) != nil || f.validateRetainedMarkerDelta(h.before, changed, time.Now().UTC()) != ErrFixtures {
		t.Fatal("delta control failed to pin original creation independently of shape")
	}
	changedBefore := h.before.DeepCopy()
	changedBefore.SetResourceVersion("104")
	if f.validateResult(fixtureRetainedPVC, fixtureStableResult, changedBefore, time.Now().UTC()) != nil || f.validateRetainedMarkerDelta(changedBefore, o, time.Now().UTC()) != ErrFixtures {
		t.Fatal("delta accepted a whole-valid pre-image with a different original receipt RV")
	}
	changedStatus := o.DeepCopy()
	statusFields := changedStatus.Object["metadata"].(map[string]any)["managedFields"].([]any)
	statusTime, err := time.Parse(time.RFC3339, statusFields[0].(map[string]any)["time"].(string))
	if err != nil {
		t.Fatal("original status timestamp unavailable")
	}
	statusFields[0].(map[string]any)["time"] = statusTime.Add(time.Second).Format(time.RFC3339)
	if f.validateRetainedMarkerResult(changedStatus, time.Now().UTC()) != nil || f.validateRetainedMarkerDelta(h.before, changedStatus, time.Now().UTC()) != ErrFixtures {
		t.Fatal("delta accepted a whole-valid changed controller-status record")
	}
	regressedMain := o.DeepCopy()
	mainFields := regressedMain.Object["metadata"].(map[string]any)["managedFields"].([]any)
	mainFields[1].(map[string]any)["time"] = o.GetCreationTimestamp().UTC().Format(time.RFC3339)
	regressedMain.Object["metadata"].(map[string]any)["managedFields"] = []any{mainFields[1], mainFields[0]}
	if f.validateRetainedMarkerResult(regressedMain, time.Now().UTC()) != nil || f.validateRetainedMarkerDelta(h.before, regressedMain, time.Now().UTC()) != ErrFixtures {
		t.Fatal("delta accepted a whole-valid installer-main timestamp regression")
	}
	if w.fixturesSettled() || f.engine.fixtureFence(h.f.actor.request.Snapshot) != ErrFixtures || !f.markerUnresolved() {
		t.Fatal("marked acceptance supplied ordinary settled/cleanup/retirement authority")
	}
	before := bytes.Clone(f.body)
	if _, err := w.markRetainedPVC(t.Context()); err != ErrFixtures || h.updates != 1 || !bytes.Equal(before, f.body) {
		t.Fatal("same-instance marker replayed")
	}
	if f.close() != nil {
		t.Fatal("original marker close failed")
	}
	loaded, err := f.engine.loadFixtureLedger(t.Context(), h.f.actor.request.Snapshot)
	if err != nil {
		t.Fatal("original marker reload failed")
	}
	defer loaded.close()
	rebuilt, err := w.actors.fixtures(t.Context(), loaded)
	if err != nil {
		t.Fatal("original marker wire rebuild failed")
	}
	if _, err := rebuilt.markRetainedPVC(t.Context()); err != ErrFixtures || h.updates != 1 || loaded.markerAck || loaded.markerEffect || !bytes.Equal(before, loaded.body) || !loaded.markerUnresolved() {
		t.Fatal("reload replayed marker or retired its fence")
	}
}

func TestFixtureRetainedMarkerWireUnknownAndLateWholeRefusal(t *testing.T) {
	newMarker := retainedMarkerLearningFactory(t)
	for _, fault := range []string{"denied", "foreign-uid", "unchanged-rv", "partial", "duplicate", "http-error", "missing-owned-leaf", "changed-creation", "private-shape", "outer-error", "file-replacement"} {
		t.Run(fault, func(t *testing.T) {
			h := newMarker(t)
			w, f := h.f.wire, h.f.wire.ledger
			h.deny = fault == "denied"
			h.reply = func(r http.ResponseWriter, o *unstructured.Unstructured) {
				o.Object = fixtureMarkedRetainedExample(t, f, o.GetCreationTimestamp().Time).Object
				switch fault {
				case "foreign-uid":
					o.SetUID("b0000000-0000-4000-8000-000000000001")
				case "unchanged-rv":
					o.SetResourceVersion("101")
				case "partial":
					_, _ = r.Write([]byte(`{"metadata":`))
					return
				case "duplicate":
					_, _ = r.Write([]byte(`{"metadata":{"uid":"a","uid":"b"}}`))
					return
				case "http-error":
					r.WriteHeader(http.StatusInternalServerError)
					_, _ = r.Write([]byte(`{"private":"PRIVATE-CANARY"}`))
					return
				case "missing-owned-leaf":
					fields := o.Object["metadata"].(map[string]any)["managedFields"].([]any)
					delete(fields[1].(map[string]any)["fieldsV1"].(map[string]any)["f:metadata"].(map[string]any)["f:annotations"].(map[string]any), "f:arcade.gobha.me/cold-backup-uid")
				case "changed-creation":
					o.SetCreationTimestamp(metav1.NewTime(o.GetCreationTimestamp().Add(-time.Second)))
				case "private-shape":
					o.Object["metadata"].(map[string]any)["privateCredential"] = "PRIVATE-CANARY"
				case "file-replacement":
					if _, err := f.engine.files.AtomicWrite(f.name, bytes.Clone(f.body), &f.identity); err != nil {
						t.Fatal("protected replacement injection failed")
					}
				}
				h.f.objects[fixtureRetainedPVC] = o.DeepCopy()
				_ = json.NewEncoder(r).Encode(o.Object)
			}
			if fault == "outer-error" {
				a := w.actors.clients[ordinaryControllerActor]
				prior := a.client.Transport
				a.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
					response, err := prior.RoundTrip(r)
					if r.Method != http.MethodPut {
						return response, err
					}
					if response != nil && response.Body != nil {
						_ = response.Body.Close()
					}
					return nil, ErrFixtures
				})
			}
			_, err := w.markRetainedPVC(t.Context())
			unknown := fault == "foreign-uid" || fault == "unchanged-rv" || fault == "partial" || fault == "duplicate" || fault == "http-error"
			if unknown && err != ErrOutcomeUnknown || !unknown && err != ErrFixtures || f.markerAck || f.markerEffect {
				t.Fatal("marker failure classification/capabilities invalid")
			}
			wantSends := 1
			if fault == "denied" {
				wantSends = 0
			}
			if h.updates != wantSends {
				t.Fatal("preflight/send-once count invalid")
			}
			ack := !unknown && fault != "denied" && fault != "file-replacement"
			if (f.document.RetainedMarker.State == fixtureRetainedMarkerAcknowledged) != ack {
				t.Fatal("native ACK was adopted or lost before late refusal")
			}
			if _, err := w.markRetainedPVC(t.Context()); err != ErrFixtures || h.updates != wantSends {
				t.Fatal("refused/unknown marker replayed")
			}
			if fault == "file-replacement" {
				return
			}
			before := bytes.Clone(f.body)
			_, _, getErr := w.get(t.Context(), fixtureRetainedPVC)
			if fault == "foreign-uid" && getErr != ErrFixtures || fault != "foreign-uid" && getErr != nil || !bytes.Equal(before, f.body) {
				t.Fatal("observational GET repaired original outcome")
			}
			if f.close() != nil {
				t.Fatal("refused original close failed")
			}
			loaded, err := f.engine.loadFixtureLedger(t.Context(), h.f.actor.request.Snapshot)
			if err != nil {
				t.Fatal("refused original reload failed")
			}
			defer loaded.close()
			rebuilt, err := w.actors.fixtures(t.Context(), loaded)
			if err != nil {
				t.Fatal("refused original rebuild failed")
			}
			if _, err := rebuilt.markRetainedPVC(t.Context()); err != ErrFixtures || h.updates != wantSends || loaded.markerAck || loaded.markerEffect || !bytes.Equal(before, loaded.body) || loaded.engine.fixtureFence(h.f.actor.request.Snapshot) != ErrFixtures {
				t.Fatal("reload bypassed unknown/late-refusal fence")
			}
		})
	}
}
