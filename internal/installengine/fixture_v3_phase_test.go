// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installobserve"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func fixtureV3PhaseFactory(t *testing.T) func(*testing.T) *fixturePhaseTest {
	t.Helper()
	return fixturePhaseFactoryWithSetup(t, func(h *fixturePhaseTest) {
		instrumentFreshFixtureRecipeV3(t, h.f.wire.ledger)
		h.extra = append(h.extra, &unstructured.Unstructured{Object: map[string]any{"apiVersion": "v1", "kind": "ServiceAccount", "metadata": map[string]any{"name": "default", "namespace": h.f.actor.request.Snapshot.Anchor().Namespace, "uid": "c0000000-0000-4000-8000-000000000001", "resourceVersion": "91"}, "automountServiceAccountToken": false}})
	})
}

func TestFixtureV3CompleteAccountsRefuseIncompleteAndChangingMembership(t *testing.T) {
	newPhase := fixtureV3PhaseFactory(t)
	for _, scenario := range []string{"planned", "original", "missing-list", "missing-get", "replacement", "list-get-rv", "default-missing", "default-change", "extra-account", "signed-missing", "signed-change", "late-account-change", "gc-only-account", "descendant"} {
		t.Run(scenario, func(t *testing.T) {
			h := newPhase(t)
			f := h.f.wire.ledger
			if scenario != "planned" {
				acknowledgeAllRecipeFixtures(t, f)
				created := time.Now().UTC().Truncate(time.Second).Add(-20 * time.Second)
				for slot := range f.document.Entries {
					h.f.objects[slot] = fixtureResultExample(t, f, slot, fixtureStableResult, created)
				}
			}
			before := bytes.Clone(f.body)
			switch scenario {
			case "missing-list":
				h.hide[11] = true
			case "missing-get":
				h.extra = append(h.extra, h.f.objects[11])
				delete(h.f.objects, 11)
			case "replacement":
				h.f.objects[11].SetUID("b0000000-0000-4000-8000-000000000001")
			case "list-get-rv":
				h.afterAccountList = func() { h.f.objects[11].SetResourceVersion("999") }
			case "default-missing":
				h.extra = nil
			case "default-change":
				h.extra[0].Object["automountServiceAccountToken"] = true
			case "extra-account":
				extra := h.extra[0].DeepCopy()
				extra.SetName("foreign")
				extra.SetUID("c0000000-0000-4000-8000-000000000002")
				h.extra = append(h.extra, extra)
			case "signed-missing", "signed-change":
				found := false
				for key, object := range h.f.actor.v.f.access.objects {
					if key.Kind == "ServiceAccount" {
						found = true
						if scenario == "signed-missing" {
							delete(h.f.actor.v.f.access.objects, key)
						} else {
							object.SetResourceVersion("999")
						}
						break
					}
				}
				if !found {
					t.Fatal("signed account control absent")
				}
			case "late-account-change":
				h.afterGet = func(slot int) {
					if slot == 11 {
						h.f.objects[11].SetResourceVersion("999")
					}
				}
			case "gc-only-account":
				h.gcRows = func(source installobserve.GCResource, rows []metav1.PartialObjectMetadata) []metav1.PartialObjectMetadata {
					if source.Kind == "ServiceAccount" {
						rows = append(rows, metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{Name: "gc-only", Namespace: f.document.Entries[11].Key.Namespace, UID: "c0000000-0000-4000-8000-000000000002", ResourceVersion: "101"}})
					}
					return rows
				}
			case "descendant":
				h.gcRows = func(source installobserve.GCResource, rows []metav1.PartialObjectMetadata) []metav1.PartialObjectMetadata {
					if source.Kind == "Widget" {
						rows = append(rows, metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{Name: "child", Namespace: f.document.Entries[11].Key.Namespace, UID: "custom-child", ResourceVersion: "101", OwnerReferences: []metav1.OwnerReference{{APIVersion: "v1", Kind: "ServiceAccount", Name: f.document.Entries[11].Key.Name, UID: f.document.Entries[11].OriginalUID}}}})
					}
					return rows
				}
			}
			observation, err := h.f.wire.observePhase(t.Context())
			if scenario == "planned" || scenario == "original" {
				if err != nil || observation == nil || observation.phase.Accounts == nil || len(observation.phase.Accounts.Rows) != 1 || (scenario == "original") != (observation.objects[11] != nil) {
					t.Fatal("complete v3 phase refused", err)
				}
			} else if err != ErrFixtures || observation != nil {
				t.Fatal("incomplete or changing accounts accepted")
			}
			if !bytes.Equal(before, f.body) || h.f.creates != 0 || h.f.deletes != 0 {
				t.Fatal("read-only refusal changed WAL or sent an effect")
			}
		})
	}
}

func TestFixtureV3LateFinalAccountMutationRefused(t *testing.T) {
	newPhase := fixtureV3PhaseFactory(t)
	for _, kind := range []string{"fixture", "default"} {
		for _, boundary := range []string{"final-configured", "final-public"} {
			t.Run(kind+"-"+boundary, func(t *testing.T) {
				h := newPhase(t)
				f := h.f.wire.ledger
				acknowledgeAllRecipeFixtures(t, f)
				created := time.Now().UTC().Truncate(time.Second).Add(-20 * time.Second)
				for slot := range f.document.Entries {
					h.f.objects[slot] = fixtureResultExample(t, f, slot, fixtureStableResult, created)
				}
				trace := &admissionTrace{}
				mutated := false
				h.afterPublicGet = func(_ int) {
					phase, _ := trace.phaseSnapshot()
					if mutated || phase != boundary {
						return
					}
					mutated = true
					if kind == "fixture" {
						h.f.objects[11].SetResourceVersion("999")
					} else {
						h.extra[0].SetResourceVersion("999")
					}
				}
				observation, err := h.f.wire.observePhase(context.WithValue(t.Context(), admissionTraceKey{}, trace))
				if !mutated {
					t.Fatal("late account control did not reach final boundary")
				}
				if err != ErrFixtures || observation != nil {
					t.Fatal("late final account mutation escaped complete observation")
				}
			})
		}
	}
}
