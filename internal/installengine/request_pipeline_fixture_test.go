// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	authv1 "k8s.io/api/authorization/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func pipelineFixtureContext(t *testing.T, enabled bool) (context.Context, *LifecycleCosts) {
	t.Helper()
	if enabled {
		return WithLifecycleCosts(t.Context())
	}
	return t.Context(), nil
}

func assertPipelineFixtureJoined(t *testing.T, costs *LifecycleCosts) {
	t.Helper()
	if costs == nil {
		return
	}
	if costs.pipeline.metrics[pipelineOther][pipelineClientDo].calls.Load() == 0 || strings.Contains(costs.RequestPipelineSnapshot(), "PRIVATE-CANARY") {
		t.Fatal("fixture path bypassed scalar observation or exposed provider data")
	}
	for _, row := range requestPipelineTestRows(t, costs.pipeline) {
		if row.Calls != row.Returned {
			t.Fatal("joined fixture left unfinished request observations")
		}
	}
}

// Observe the actual target send, not preflight discovery/review traffic. The
// handler is inside that request's Do, so precisely one other-scope Do must be
// pending. Recorder publication to the server goroutine uses atomic.Pointer.
func assertPipelineFixturePending(t *testing.T, enabled bool, costs *LifecycleCosts) {
	t.Helper()
	if !enabled {
		if costs != nil {
			t.Error("disabled fixture unexpectedly acquired a recorder")
		}
		return
	}
	if costs == nil || costs.pipeline == nil {
		t.Error("target request lost its command recorder")
		return
	}
	metric := &costs.pipeline.metrics[pipelineOther][pipelineClientDo]
	calls, returned := metric.calls.Load(), metric.returned.Load()
	if calls <= returned || calls-returned != 1 {
		t.Error("target request bypassed its own in-flight Do observation")
	}
}

// Each fresh fixture has its own protected nonce/timestamps. Existing fake
// handlers verify its constructor-derived exact actor/payload/once-only intent;
// compare effect counts and dispositions, not different fixtures' random bytes.
// These are fake-API equivalence controls, not native lifecycle certification.
func TestRequestPipelineRetainedMarkerKeepsAckAndNoReplay(t *testing.T) {
	newMarker := retainedMarkerLearningFactory(t)
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled", true: "enabled"}[enabled], func(t *testing.T) {
			h := newMarker(t)
			fixtureMarkerWireNativeReply(t, h)
			wire, ledger := h.f.wire, h.f.wire.ledger
			path, _, pathErr := fixturePath(ledger.document.Entries[fixtureRetainedPVC].Key, false)
			if pathErr != nil {
				t.Fatal("fixed marker route unavailable")
			}
			var recorder atomic.Pointer[LifecycleCosts]
			prior := h.f.actor.fixtureHandler
			h.f.actor.fixtureHandler = func(w http.ResponseWriter, r *http.Request) bool {
				if r.URL.Path == path && r.Method == http.MethodPut {
					assertPipelineFixturePending(t, enabled, recorder.Load())
				}
				return prior(w, r)
			}
			ctx, costs := pipelineFixtureContext(t, enabled)
			recorder.Store(costs)
			result, err := wire.markRetainedPVC(ctx)
			if err != nil || result == nil || h.updates != 1 || ledger.document.RetainedMarker.State != fixtureRetainedMarkerAcknowledged || ledger.markerAck || ledger.markerEffect || ledger.validateRetainedMarkerDelta(h.before, result, time.Now().UTC()) != nil || !ledger.markerUnresolved() || wire.fixturesSettled() {
				t.Fatal("observation changed reliable marker ACK, original delta or recovery fence")
			}
			before := bytes.Clone(ledger.body)
			if _, err := wire.markRetainedPVC(ctx); err != ErrFixtures || h.updates != 1 || !bytes.Equal(before, ledger.body) {
				t.Fatal("observation granted marker replay")
			}
			assertPipelineFixtureJoined(t, costs)
		})
	}
}

func TestRequestPipelineMarkedCleanupKeepsAcceptedPresenceAndNoReplay(t *testing.T) {
	newPhase := markedCleanupPhaseFactory(t, fixtureRecipeV2, false)
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled", true: "enabled"}[enabled], func(t *testing.T) {
			h := newPhase(t)
			f, ledger := h.f, h.f.wire.ledger
			original := f.objects[10].DeepCopy()
			f.afterEffect = func() { f.objects[10] = original.DeepCopy() }
			path, _, pathErr := fixturePath(ledger.document.Entries[10].Key, false)
			if pathErr != nil {
				t.Fatal("fixed cleanup route unavailable")
			}
			var recorder atomic.Pointer[LifecycleCosts]
			prior := f.actor.fixtureHandler
			f.actor.fixtureHandler = func(w http.ResponseWriter, r *http.Request) bool {
				if r.URL.Path == path && r.Method == http.MethodDelete {
					assertPipelineFixturePending(t, enabled, recorder.Load())
				}
				return prior(w, r)
			}
			ctx, costs := pipelineFixtureContext(t, enabled)
			recorder.Store(costs)
			if f.wire.removeAcknowledgedMarkerOriginal(ctx, 10) != ErrFixtures || f.deletes != 1 || ledger.effectSlot != -1 || ledger.document.Entries[10].State != fixtureDeleteAttempted {
				t.Fatal("observed DELETE acceptance became absence or a new send grant")
			}
			before := bytes.Clone(ledger.body)
			if f.wire.removeAcknowledgedMarkerOriginal(ctx, 10) != ErrFixtures || f.deletes != 1 || !bytes.Equal(before, ledger.body) {
				t.Fatal("observed still-present original was replayed or adopted")
			}
			delete(f.objects, 10) // Fake later API/GC completion, not a second send.
			if f.wire.removeAcknowledgedMarkerOriginal(ctx, 10) != nil || f.deletes != 1 || ledger.document.Entries[10].State != fixtureAbsent || ledger.document.Behavior != nil {
				t.Fatal("actual absence no longer settled observation-only")
			}
			assertPipelineFixtureJoined(t, costs)
		})
	}
}

func TestRequestPipelineCounterpartKeepsExactNativeAbsenceAndNoEffects(t *testing.T) {
	newPhase := fixturePhaseFactoryWithSetup(t, func(h *fixturePhaseTest) { instrumentFreshFixtureRecipeV2(t, h.f.wire.ledger) })
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled", true: "enabled"}[enabled], func(t *testing.T) {
			h := newPhase(t)
			f, ledger := h.f, h.f.wire.ledger
			acknowledgeAllRecipeFixtures(t, ledger)
			created := time.Now().UTC().Truncate(time.Second).Add(-40 * time.Second)
			for slot := range ledger.document.Entries {
				f.objects[slot] = fixtureResultExample(t, ledger, slot, fixtureStableResult, created)
			}
			phase, err := f.wire.observePhase(t.Context())
			if err != nil {
				t.Fatal("original fake phase unavailable")
			}
			request, err := f.wire.admissionRequest(0, phase)
			if err != nil {
				t.Fatal("closed counterpart request unavailable")
			}
			key := fixtureObjectKey(request.object)
			path, plural, err := fixturePath(key, false)
			permission, permissionErr := fixturePermission(key, "get")
			if err != nil || permissionErr != nil {
				t.Fatal("exact counterpart route/permission unavailable")
			}
			var namedGets atomic.Int32
			var reply atomic.Int32
			var recorder atomic.Pointer[LifecycleCosts]
			prior := f.actor.fixtureHandler
			f.actor.fixtureHandler = func(w http.ResponseWriter, r *http.Request) bool {
				if r.URL.Path == "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" {
					body, _ := io.ReadAll(r.Body)
					r.Body = io.NopCloser(bytes.NewReader(body))
					var review authv1.SelfSubjectAccessReview
					if json.Unmarshal(body, &review) == nil && reflect.DeepEqual(review.Spec, permission.spec) {
						if r.Method != http.MethodPost || r.Header.Get("Impersonate-User") != "" {
							t.Error("counterpart review changed its original administrator")
						}
						review.Status.Allowed = true
						w.Header().Set("Content-Type", "application/json")
						json.NewEncoder(w).Encode(review)
						return true
					}
				}
				if r.URL.Path != path || r.Method != http.MethodGet {
					return prior(w, r)
				}
				namedGets.Add(1)
				assertPipelineFixturePending(t, enabled, recorder.Load())
				body, _ := io.ReadAll(r.Body)
				if len(body) != 0 || r.URL.RawQuery != "" || r.Header.Get("Impersonate-User") != "" {
					t.Error("counterpart GET changed bytes, query or actor")
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusNotFound)
				if reply.Load() == 1 {
					io.WriteString(w, "PRIVATE-CANARY")
					return true
				}
				gv, _ := schema.ParseGroupVersion(key.APIVersion)
				status := apierrors.NewNotFound(schema.GroupResource{Group: gv.Group, Resource: plural}, key.Name).ErrStatus
				status.APIVersion, status.Kind = "v1", "Status"
				if reply.Load() == 2 {
					status.Details.Name = "foreign-name"
				}
				json.NewEncoder(w).Encode(status)
				return true
			}
			before, identity := bytes.Clone(ledger.body), ledger.identity
			creates, deletes := f.creates, f.deletes
			for fault := int32(0); fault < 3; fault++ {
				reply.Store(fault)
				ctx, costs := pipelineFixtureContext(t, enabled)
				recorder.Store(costs)
				ledger.wireMu.Lock()
				observedErr := f.wire.counterpartAbsentLocked(ctx, 0, phase)
				ledger.wireMu.Unlock()
				if fault == 0 && observedErr != nil || fault != 0 && observedErr != ErrFixtures || namedGets.Load() != fault+1 || f.creates != creates || f.deletes != deletes || !bytes.Equal(before, ledger.body) || !reflect.DeepEqual(identity, ledger.identity) {
					t.Fatal("counterpart observation changed native absence, original evidence or effect count")
				}
				assertPipelineFixtureJoined(t, costs)
			}
		})
	}
}

func TestRequestPipelinePublicInventoryKeepsFreshContractsRowsAndPhase(t *testing.T) {
	newPhase := fixturePhaseFactory(t)
	for _, mode := range []string{"inventory", "baseline-opening", "contract-refusal"} {
		t.Run(mode, func(t *testing.T) {
			h := newPhase(t)
			f, ledger := h.f, h.f.wire.ledger
			if mode == "contract-refusal" {
				mutated := false
				for key, object := range f.actor.v.f.access.objects {
					if key.Kind == "Service" {
						if unstructured.SetNestedField(object.Object, "ExternalName", "spec", "type") != nil {
							t.Fatal("same-identity contract drift unavailable")
						}
						mutated = true
						break
					}
				}
				if !mutated {
					t.Fatal("signed Service control missing")
				}
			}
			before := bytes.Clone(ledger.body)
			plain, plainErr := f.actor.admission.phasePublicInventory(t.Context(), f.actor.request)
			ctx, costs := WithLifecycleCosts(t.Context())
			scope := pipelinePublicInventory
			if mode == "baseline-opening" {
				var finish func()
				ctx, finish = baselineProbePhaseContext(ctx, baselineProbeOpening)
				defer finish()
				scope = pipelineBaselineOpening
			}
			observed, observedErr := f.actor.admission.phasePublicInventory(ctx, f.actor.request)
			if observedErr != plainErr || !reflect.DeepEqual(observed, plain) || !bytes.Equal(before, ledger.body) || f.creates != 0 || f.deletes != 0 {
				t.Fatal("inventory observation changed fresh rows, refusal, original evidence or effects")
			}
			metrics := &costs.pipeline.metrics[scope]
			if metrics[pipelineInventory].calls.Load() != 1 || metrics[pipelineContract].calls.Load() == 0 || metrics[pipelineClientDo].calls.Load() != metrics[pipelineContract].calls.Load() {
				t.Fatal("inventory, actual reads or contract hooks missing from their phase")
			}
			if mode == "contract-refusal" {
				if observedErr != ErrFixtures || observed != nil || metrics[pipelineRow].calls.Load()+1 != metrics[pipelineContract].calls.Load() {
					t.Fatal("failed whole contract was accepted or counted as a completed row")
				}
			} else if observedErr != nil || len(observed) == 0 || metrics[pipelineRow].calls.Load() != uint64(len(observed)) || metrics[pipelineContract].calls.Load() != uint64(len(observed)) {
				t.Fatal("whole validated public rows lost their individual observation")
			}
			for other := requestPipelineScope(0); other < pipelineScopes; other++ {
				if other == scope {
					continue
				}
				for kind := requestPipelineKind(0); kind < pipelineKinds; kind++ {
					if costs.pipeline.metrics[other][kind].calls.Load() != 0 {
						t.Fatal("inventory discarded a more specific baseline or invented another scope")
					}
				}
			}
			for _, row := range requestPipelineTestRows(t, costs.pipeline) {
				if row.Calls != row.Returned {
					t.Fatal("joined inventory refusal/success left unfinished spans")
				}
			}
		})
	}
}
