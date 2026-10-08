// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installobserve"
	"github.com/gobha-me/arcadectl/internal/installstate"
	authv1 "k8s.io/api/authorization/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/utils/ptr"
)

// Component proof through actual sealed typed and GC readers plus the original
// administrator/WAL transport. These independent fixtures deliberately do not
// claim a complete warm phase, native admission, or any effect authorization.
// The native warm test exercises the complete composed observer on both profiles.
func TestFixturePhaseLeaderRefreshWholeGCAndMonotonicTypedFloor(t *testing.T) {
	newPhase := fixturePhaseFactory(t)
	for _, scenario := range []string{"renewal", "gc-superseded", "gc-missing", "gc-wrong-rv", "uid", "holder", "acquire", "transition", "fieldset", "data-label", "rv-regression", "renew-regression", "managed-regression", "list-denied", "unknown-list-field", "original-chain-missing"} {
		t.Run(scenario, func(t *testing.T) {
			h := newPhase(t)
			v, ns, lists := readyControllerFixture(t, h.f.actor.v.f.plan)
			d, err := installstate.Decode([]byte(ns.Annotations[installstate.Annotation]), h.f.actor.v.f.plan)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC().Truncate(time.Microsecond)
			leases := &coordinationv1.LeaseList{}
			for index, pod := range lists["Pod"].(*corev1.PodList).Items {
				leases.Items = append(leases.Items, phaseLeaderFixture(&pod, index, now))
			}
			lists["Lease"] = leases
			states, observation, err := admissionClassifyObservationTest(t, v, ns, lists, d, h.f.actor.v.f.plan, "")
			if err != nil {
				t.Fatal(err)
			}
			before, err := capturePhaseBaseline(observation, states, now)
			if err != nil || len(before.Leaders) != 2 {
				t.Fatal("sealed typed original leader chains unavailable", err)
			}
			whole := map[string]*unstructured.Unstructured{}
			for index := range leases.Items {
				fresh := leases.Items[index].DeepCopy()
				fresh.ResourceVersion = "102"
				renew, managed := metav1.NewMicroTime(now.Add(-time.Second)), metav1.NewTime(now.Add(-time.Second).Truncate(time.Second))
				fresh.Spec.RenewTime, fresh.ManagedFields[0].Time = &renew, &managed
				if index == 0 {
					switch scenario {
					case "uid":
						fresh.UID = "10000000-0000-4000-8000-000000000019"
					case "holder":
						fresh.Spec.HolderIdentity = ptr.To("foreign-pod_10000000-0000-4000-8000-000000000099")
					case "acquire":
						acquire := metav1.NewMicroTime(fresh.Spec.AcquireTime.Add(time.Second))
						fresh.Spec.AcquireTime = &acquire
					case "transition":
						fresh.Spec.LeaseTransitions = ptr.To[int32](1)
					case "fieldset":
						fresh.ManagedFields[0].FieldsV1.Raw = []byte(`{"f:spec":{"f:holderIdentity":{}}}`)
					case "data-label":
						fresh.Labels = map[string]string{"arcade.gobha.me/destroy-uid": "intent"}
					case "rv-regression":
						fresh.ResourceVersion = "100"
					case "renew-regression":
						renew := metav1.NewMicroTime(now.Add(-3 * time.Second))
						fresh.Spec.RenewTime = &renew
					case "managed-regression":
						managed := metav1.NewTime(now.Add(-3 * time.Second).Truncate(time.Second))
						fresh.ManagedFields[0].Time = &managed
					}
				}
				object := servingObject(t, fresh)
				whole[fresh.Name] = object
				h.extra = append(h.extra, object.DeepCopy())
			}
			h.gcRows = func(source installobserve.GCResource, rows []metav1.PartialObjectMetadata) []metav1.PartialObjectMetadata {
				if source.GVR.Group == "coordination.k8s.io" && source.GVR.Resource == "leases" {
					for index := range rows {
						if rows[index].Name == "controller.arcade.gobha.me" {
							if scenario == "gc-missing" {
								return append(rows[:index], rows[index+1:]...)
							}
							if scenario == "gc-wrong-rv" {
								rows[index].ResourceVersion = "103"
							}
						}
					}
				}
				return rows
			}
			base := h.f.actor.fixtureHandler
			wholeReads := 0
			h.f.actor.fixtureHandler = func(w http.ResponseWriter, r *http.Request) bool {
				if r.URL.Path == "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" {
					body, _ := io.ReadAll(r.Body)
					r.Body = io.NopCloser(bytes.NewReader(body))
					var review authv1.SelfSubjectAccessReview
					if json.Unmarshal(body, &review) != nil {
						t.Error("named Lease review unavailable")
						return false
					}
					if a := review.Spec.ResourceAttributes; a != nil && a.Group == "coordination.k8s.io" && a.Resource == "leases" && a.Verb == "list" {
						if r.Method != http.MethodPost || r.Header.Get("Impersonate-User") != "" || a.Version != "v1" || a.Namespace != ns.Name || a.Name != "" || a.Subresource != "" || review.Spec.NonResourceAttributes != nil {
							t.Error("Lease LIST review escaped original administrator/closed route")
						}
						review.Status.Allowed = scenario != "list-denied"
						_ = json.NewEncoder(w).Encode(review)
						return true
					}
				}
				if r.URL.Path == "/apis/coordination.k8s.io/v1/namespaces/"+ns.Name+"/leases" && !strings.Contains(r.Header.Get("Accept"), "PartialObjectMetadataList") {
					if r.Method != http.MethodGet || r.Header.Get("Impersonate-User") != "" || r.URL.Query().Get("limit") != "128" {
						t.Error("whole leader LIST escaped original unfiltered route")
					}
					wholeReads++
					items := []any{}
					for _, object := range whole {
						copy := object.DeepCopy()
						if scenario == "gc-superseded" {
							copy.SetResourceVersion("103")
							_ = unstructured.SetNestedField(copy.Object, now.Format(time.RFC3339Nano), "spec", "renewTime")
						}
						if scenario == "unknown-list-field" {
							copy.Object["unexpected"] = "rejected"
						}
						items = append(items, copy.Object)
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"apiVersion": "coordination.k8s.io/v1", "kind": "LeaseList", "metadata": map[string]any{"resourceVersion": "100"}, "items": items})
					return true
				}
				return base(w, r)
			}
			gc, err := h.f.wire.gcMetadataModeLocked(t.Context(), true)
			if err != nil {
				if scenario == "gc-superseded" || scenario == "gc-missing" || scenario == "gc-wrong-rv" || scenario == "list-denied" || scenario == "unknown-list-field" {
					if h.f.creates != 0 || h.f.deletes != 0 || h.f.seeds != 0 || scenario == "list-denied" && wholeReads != 0 {
						t.Fatal("paired read refusal issued an effect or unauthorized LIST")
					}
					return
				}
				t.Fatal("real metadata reader failed before narrow refresh", err)
			}
			if scenario == "original-chain-missing" {
				before.Leaders[0].PodUID = before.Leaders[1].PodUID
			}
			unchanged := fixturePreviewUnchanged(t, h.f)
			body, _ := json.Marshal(before)
			after, refreshed, err := h.f.wire.refreshPhaseLeaders(t.Context(), observation, before, gc)
			if (err == nil) != (scenario == "renewal") {
				t.Fatalf("whole/GC/typed-floor refresh accepted %s: %v", scenario, err)
			}
			if err == nil && (len(refreshed) != 2 || wholeReads != 1 || !samePhaseBaseline(before, after) || after.Leaders[0].Row.ResourceVersion != "102" || after.Leaders[1].Row.ResourceVersion != "102") {
				t.Fatal("original complete renewal correlation unavailable")
			}
			afterBody, _ := json.Marshal(before)
			if !bytes.Equal(body, afterBody) || h.f.wire.ledger.phaseFloor != nil || h.f.creates != 0 || h.f.deletes != 0 || h.f.seeds != 0 {
				t.Fatal("narrow observation changed its floor/WAL or issued an effect")
			}
			unchanged()
		})
	}
}

func TestFixturePhaseColdLeaderTailMetadataRemainsExact(t *testing.T) {
	newPhase := fixturePhaseFactoryWithSetup(t, func(h *fixturePhaseTest) {
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "old-controller", Namespace: h.f.actor.request.Snapshot.Anchor().Namespace}}
		lease := phaseLeaderFixture(pod, 0, time.Now().UTC())
		h.extra = append(h.extra, servingObject(t, &lease))
	})
	for _, drift := range []bool{false, true} {
		t.Run(map[bool]string{false: "unchanged", true: "gc-renewed-cold-tail"}[drift], func(t *testing.T) {
			h := newPhase(t)
			if drift {
				h.gcRows = func(source installobserve.GCResource, rows []metav1.PartialObjectMetadata) []metav1.PartialObjectMetadata {
					if source.GVR.Group == "coordination.k8s.io" && source.GVR.Resource == "leases" {
						for index := range rows {
							rows[index].ResourceVersion = "102"
						}
					}
					return rows
				}
			}
			unchanged := fixturePreviewUnchanged(t, h.f)
			observation, err := h.f.wire.observePhase(t.Context())
			if (err == nil) == drift {
				t.Fatal("cold tail was treated as a renewing original leader", err)
			}
			if err == nil && (len(observation.phase.Leaders) != 0 || !reflect.DeepEqual(observation.phase.Rows, h.f.wire.ledger.phaseFloor.Rows)) {
				t.Fatal("cold tail escaped exact original rows")
			}
			unchanged()
		})
	}
}
