// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installobserve"
	authv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Production phase/WAL/actor/marker-wire composition against a fake API; this
// is NOT native admission, storage deletion or behavior certification.
func markedCleanupPhaseFactory(t *testing.T, recipe string, unknown bool) func(*testing.T) *fixturePhaseTest {
	t.Helper()
	newPhase := fixturePhaseFactoryWithSetup(t, func(h *fixturePhaseTest) {
		if recipe == fixtureRecipeV2 {
			instrumentFreshFixtureRecipeV2(t, h.f.wire.ledger)
		}
	})
	return func(t *testing.T) *fixturePhaseTest {
		t.Helper()
		h := newPhase(t)
		f, ledger := h.f, h.f.wire.ledger
		acknowledgeAllRecipeFixtures(t, ledger)
		created := time.Now().UTC().Truncate(time.Second).Add(-40 * time.Second)
		for slot := range ledger.document.Entries {
			f.objects[slot] = fixtureResultExample(t, ledger, slot, fixtureStableResult, created)
		}
		entry := ledger.document.Entries[fixtureRetainedPVC]
		permission, _ := actorPermission(entry.Key, probeUpdateOperation)
		path, _, _ := fixturePath(entry.Key, false)
		prior := f.actor.fixtureHandler
		updates := 0
		f.actor.fixtureHandler = func(w http.ResponseWriter, r *http.Request) bool {
			if r.URL.Path == "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" {
				body, _ := io.ReadAll(r.Body)
				r.Body = io.NopCloser(bytes.NewReader(body))
				var review authv1.SelfSubjectAccessReview
				if json.Unmarshal(body, &review) == nil && reflect.DeepEqual(review.Spec, permission.spec) {
					if r.Method != http.MethodPost || r.Header.Get("Impersonate-User") != "system:serviceaccount:"+entry.Key.Namespace+":"+ordinaryControllerActor.account() {
						t.Error("marker review escaped original ordinary controller")
					}
					review.Status.Allowed = true
					_ = json.NewEncoder(w).Encode(review)
					return true
				}
			}
			if r.Method != http.MethodPut || r.URL.Path != path {
				return prior(w, r)
			}
			updates++
			want, err := ledger.retainedMarkerObject()
			if err != nil {
				t.Error("fixed marker payload unavailable")
				w.WriteHeader(500)
				return true
			}
			want.SetUID(entry.OriginalUID)
			want.SetResourceVersion(ledger.document.RetainedMarker.BeforeResourceVersion)
			want.SetFinalizers([]string{"kubernetes.io/pvc-protection"})
			var got map[string]any
			if updates != 1 || json.NewDecoder(r.Body).Decode(&got) != nil || !reflect.DeepEqual(got, want.Object) || r.Header.Get("Impersonate-User") != "system:serviceaccount:"+entry.Key.Namespace+":"+ordinaryControllerActor.account() || r.URL.RawQuery != "fieldManager=arcadectl-installer&fieldValidation=Strict" || ledger.markerEffect || !ledger.markerAck {
				t.Error("marker escaped original fixed actor/payload/single-send intent")
			}
			f.objects[fixtureRetainedPVC] = fixtureMarkedRetainedExample(t, ledger, created)
			if unknown {
				w.WriteHeader(500)
			} else {
				_ = json.NewEncoder(w).Encode(f.objects[fixtureRetainedPVC].Object)
			}
			return true
		}
		if ledger.advance(fixtureMarkerIntent(t, ledger)) != nil {
			t.Fatal("fixed marker intent unavailable")
		}
		_, err := f.wire.markRetainedPVC(t.Context())
		wantErr := error(nil)
		if unknown {
			wantErr = ErrOutcomeUnknown
		}
		if err != wantErr || updates != 1 {
			t.Fatal("production marker ACK/unknown control failed")
		}
		return h
	}
}

func TestFixtureMarkedCleanupCompleteReverseDrainAndRetirement(t *testing.T) {
	for _, recipe := range []string{fixtureRecipeV1, fixtureRecipeV2} {
		t.Run(recipe, func(t *testing.T) {
			h := markedCleanupPhaseFactory(t, recipe, false)(t)
			f, ledger := h.f, h.f.wire.ledger
			started := time.Now()
			for slot := len(ledger.document.Entries) - 1; slot >= 0; slot-- {
				t.Logf("checking marked original cleanup slot=%d elapsedSeconds=%d", slot, int(time.Since(started)/time.Second))
				if _, _, err := f.wire.prepare(t.Context(), slot, "delete"); err != ErrFixtures {
					t.Fatal("ACK marker reopened old effect preflight")
				}
				if f.wire.removeAcknowledgedMarkerOriginal(t.Context(), slot) != nil || ledger.document.Entries[slot].State != fixtureAbsent || ledger.effectSlot != -1 || ledger.document.Behavior != nil || !ledger.markerUnresolved() {
					t.Fatal("strict original marked cleanup failed or invented behavior")
				}
				t.Logf("marked original actually absent slot=%d elapsedSeconds=%d", slot, int(time.Since(started)/time.Second))
			}
			if f.deletes != len(ledger.document.Entries) || f.wire.retireDrained(t.Context()) != nil || ledger.engine.fixtureFence(f.actor.request.Snapshot) != nil {
				t.Fatal("complete actual absence did not retire original marked run")
			}
		})
	}
}

func TestFixtureMarkedCleanupPostIntentRefusalConsumesSend(t *testing.T) {
	newPhase := markedCleanupPhaseFactory(t, fixtureRecipeV2, false)
	for _, fault := range []string{"read", "file"} {
		t.Run(fault, func(t *testing.T) {
			h := newPhase(t)
			f, ledger := h.f, h.f.wire.ledger
			prior := f.actor.fixtureHandler
			injected := false
			f.actor.fixtureHandler = func(w http.ResponseWriter, r *http.Request) bool {
				if !injected && r.Method == http.MethodGet && ledger.document.Entries[10].State == fixtureDeleteAttempted {
					injected = true
					if fault == "read" {
						w.WriteHeader(500)
						return true
					}
					if _, err := ledger.engine.files.AtomicWrite(ledger.name, bytes.Clone(ledger.body), &ledger.identity); err != nil {
						t.Error("post-intent protected-file injection failed")
					}
				}
				return prior(w, r)
			}
			if f.wire.removeAcknowledgedMarkerOriginal(t.Context(), 10) != ErrFixtures || !injected || f.deletes != 0 || ledger.document.Entries[10].State != fixtureDeleteAttempted || ledger.effectSlot != -1 {
				t.Fatal("post-intent refusal sent DELETE or retained send authority")
			}
			body := bytes.Clone(ledger.body)
			// The transient read fault is now recovered. Even with a matching
			// original still present, a second call may observe but NEVER resend.
			if f.wire.removeAcknowledgedMarkerOriginal(t.Context(), 10) != ErrFixtures || f.deletes != 0 || ledger.effectSlot != -1 || !bytes.Equal(body, ledger.body) {
				t.Fatal("post-intent refusal replayed DELETE or adopted presence")
			}
		})
	}
}

func TestFixtureMarkedCleanupAcceptedDeleteWaitsForActualAbsence(t *testing.T) {
	h := markedCleanupPhaseFactory(t, fixtureRecipeV2, false)(t)
	f, ledger := h.f, h.f.wire.ledger
	original := f.objects[10].DeepCopy()
	f.afterEffect = func() { f.objects[10] = original.DeepCopy() }
	// The existing fake returns202: acceptance alone cannot settle a still
	// present original or normalize its deletion/finalizer shape.
	if f.wire.removeAcknowledgedMarkerOriginal(t.Context(), 10) != ErrFixtures || f.deletes != 1 || ledger.effectSlot != -1 || ledger.document.Entries[10].State != fixtureDeleteAttempted {
		t.Fatal("accepted response became actual absence or retained send authority")
	}
	body := bytes.Clone(ledger.body)
	if f.wire.removeAcknowledgedMarkerOriginal(t.Context(), 10) != ErrFixtures || f.deletes != 1 || !bytes.Equal(body, ledger.body) {
		t.Fatal("still-present accepted DELETE was replayed or settled")
	}
	delete(f.objects, 10) // Model later actual API/GC completion, not another send.
	if f.wire.removeAcknowledgedMarkerOriginal(t.Context(), 10) != nil || f.deletes != 1 || ledger.document.Entries[10].State != fixtureAbsent || ledger.document.Behavior != nil {
		t.Fatal("delayed actual absence failed observation-only settlement")
	}
}

func TestFixtureMarkedCleanupRejectsUnknownAndWholePhaseDrift(t *testing.T) {
	newPhase := markedCleanupPhaseFactory(t, fixtureRecipeV2, false)
	for _, fault := range []string{"order", "missing-context", "marker-flag", "seed-flag", "send-flag", "journal", "wal-file", "late-wal-file", "uid", "rv", "binder", "status", "spec", "finalizer", "managed-field", "descendant"} {
		t.Run(fault, func(t *testing.T) {
			h := newPhase(t)
			f, ledger := h.f, h.f.wire.ledger
			marked := f.objects[fixtureRetainedPVC]
			slot := len(ledger.document.Entries) - 1
			switch fault {
			case "order":
				slot = 0
			case "marker-flag":
				ledger.markerAck = true
			case "seed-flag":
				ledger.seedEffect = true
			case "send-flag":
				ledger.effectSlot = slot
			case "journal":
				f.wire.actors.request.Snapshot = nil
			case "wal-file", "late-wal-file":
				tamper := func() {
					if _, err := ledger.engine.files.AtomicWrite(ledger.name, bytes.Clone(ledger.body), &ledger.identity); err != nil {
						t.Error("protected replacement injection failed")
					}
				}
				if fault == "wal-file" {
					tamper()
				} else {
					h.afterGet = func(index int) {
						if index == slot {
							h.afterGet = nil
							tamper()
						}
					}
				}
			case "uid":
				marked.SetUID("b0000000-0000-4000-8000-000000000001")
			case "rv":
				marked.SetResourceVersion("999")
			case "binder":
				annotations := marked.GetAnnotations()
				delete(annotations, "pv.kubernetes.io/bind-completed")
				marked.SetAnnotations(annotations)
			case "status":
				marked.Object["status"] = map[string]any{"phase": "Pending"}
			case "spec":
				_ = unstructured.SetNestedField(marked.Object, "foreign", "spec", "storageClassName")
			case "finalizer":
				marked.SetFinalizers(nil)
			case "managed-field":
				marked.Object["metadata"].(map[string]any)["managedFields"].([]any)[0].(map[string]any)["manager"] = "foreign"
			case "descendant":
				h.gcRows = func(source installobserve.GCResource, rows []metav1.PartialObjectMetadata) []metav1.PartialObjectMetadata {
					if source.Kind == "Widget" {
						rows = append(rows, metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{Name: "child", Namespace: marked.GetNamespace(), UID: "b0000000-0000-4000-8000-000000000001", ResourceVersion: "101", OwnerReferences: []metav1.OwnerReference{{APIVersion: "v1", Kind: "PersistentVolumeClaim", Name: marked.GetName(), UID: marked.GetUID()}}}})
					}
					return rows
				}
			}
			body, identity := bytes.Clone(ledger.body), ledger.identity
			err := ErrFixtures
			if fault == "missing-context" {
				err = f.wire.removeAcknowledgedMarkerOriginal(nil, slot)
			} else {
				err = f.wire.removeAcknowledgedMarkerOriginal(t.Context(), slot)
			}
			if err != ErrFixtures || f.deletes != 0 || !bytes.Equal(body, ledger.body) || identity != ledger.identity {
				t.Fatal("unproved original acquired marked cleanup effect or WAL mutation")
			}
		})
	}
	t.Run("unknown-marker", func(t *testing.T) {
		h := markedCleanupPhaseFactory(t, fixtureRecipeV2, true)(t)
		ledger := h.f.wire.ledger
		body := bytes.Clone(ledger.body)
		if h.f.wire.removeAcknowledgedMarkerOriginal(t.Context(), 10) != ErrFixtures || h.f.deletes != 0 || !bytes.Equal(body, ledger.body) || ledger.document.RetainedMarker.State != fixtureRetainedMarkerAttempted {
			t.Fatal("unknown marker was adopted or bypassed cleanup fence")
		}
	})
}

func TestFixtureMarkedCleanupLostDeleteOnlyObservesAfterReload(t *testing.T) {
	for _, present := range []bool{false, true} {
		t.Run(map[bool]string{false: "absent", true: "present"}[present], func(t *testing.T) {
			h := markedCleanupPhaseFactory(t, fixtureRecipeV2, false)(t)
			f, old := h.f, h.f.wire.ledger
			original := f.objects[10].DeepCopy()
			f.deleteReply = func(w http.ResponseWriter) { w.WriteHeader(500) }
			if present {
				f.afterEffect = func() { f.objects[10] = original.DeepCopy() }
			}
			if f.wire.removeAcknowledgedMarkerOriginal(t.Context(), 10) != ErrOutcomeUnknown || f.deletes != 1 || old.effectSlot != -1 || old.document.Entries[10].State != fixtureDeleteAttempted {
				t.Fatal("lost marked DELETE failed to consume single-send authority")
			}
			actors := f.wire.actors
			if old.close() != nil {
				t.Fatal("original ledger close failed")
			}
			loaded, err := old.engine.loadFixtureLedger(t.Context(), f.actor.request.Snapshot)
			if err != nil {
				t.Fatal("original attempted ledger reload failed")
			}
			defer loaded.close()
			// Reload never grants a missing companion identity from current
			// survivors. Recover only the exact already sealed durable baseline
			// before rebuilding the observation-only attempted-delete path.
			if _, err := actors.fixtures(t.Context(), loaded); err != ErrFixtures || f.deletes != 1 {
				t.Fatal("reloaded cleanup admitted an unpinned original companion")
			}
			worlds, err := loaded.loadOriginalWorlds()
			if err != nil || worlds.Phase == nil || loaded.effectSlot != -1 || loaded.ackSlot != -1 {
				t.Fatal("exact original companion recovery failed or restored send authority")
			}
			f.wire, err = actors.fixtures(t.Context(), loaded)
			if err != nil {
				t.Fatal("original actor rebuild failed")
			}
			body := bytes.Clone(loaded.body)
			err = f.wire.removeAcknowledgedMarkerOriginal(t.Context(), 10)
			if f.deletes != 1 || loaded.effectSlot != -1 || present && (err != ErrFixtures || !bytes.Equal(body, loaded.body) || loaded.document.Entries[10].State != fixtureDeleteAttempted) || !present && (err != nil || loaded.document.Entries[10].State != fixtureAbsent) {
				t.Fatal("reloaded marked cleanup replayed/adopted an attempted original")
			}
		})
	}
}
