// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installstate"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	authv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// This is fake HTTPS refusal evidence for the closed read-only interval, not
// native admission or full provider/lifecycle certification.
func TestFixturePhaseNamedScanClosesEveryRemoteOriginalWitness(t *testing.T) {
	newPhase := unmarkedRecoveryPhaseFactory(t)
	seed := newPhase(t)
	keys := []installstate.Key{}
	for key := range seed.f.wire.actors.witness {
		keys = append(keys, key)
	}
	for key := range seed.f.actor.v.f.access.objects {
		if key.Kind == "ValidatingAdmissionPolicy" || key.Kind == "ValidatingAdmissionPolicyBinding" {
			keys = append(keys, key)
		}
	}
	sort.Slice(keys, func(i, j int) bool { return fixtureWorldOrder(keys[i]) < fixtureWorldOrder(keys[j]) })
	if len(keys) < 15 {
		t.Fatal("remote witness fault catalogue incomplete")
	}
	for _, key := range keys {
		t.Run(key.Kind+"/"+key.Name, func(t *testing.T) {
			h := newPhase(t)
			f := h.f.wire.ledger
			original := h.f.actor.v.f.access.objects[key].DeepCopy()
			changed, restored := false, false
			h.afterGet = func(slot int) {
				if slot == 0 && !changed {
					tampered := original.DeepCopy()
					labels := tampered.GetLabels()
					if labels == nil {
						labels = map[string]string{}
					}
					labels["foreign.example/changed"] = "true"
					tampered.SetLabels(labels)
					tampered.SetResourceVersion("998")
					h.f.actor.v.f.access.objects[key] = tampered
					changed = true
				} else if slot == 1 && changed && !restored {
					// Restore the WHOLE original shape, but never fabricate its
					// old Kubernetes RV. Closing original UID+RV must refuse.
					back := original.DeepCopy()
					back.SetResourceVersion("999")
					h.f.actor.v.f.access.objects[key] = back
					restored = true
					h.afterGet = nil
				}
			}
			before, identity := bytes.Clone(f.body), f.identity
			if result, err := h.f.wire.observePhase(t.Context()); result != nil || err != ErrFixtures || !changed || !restored || f.phaseFloor != nil || !bytes.Equal(before, f.body) || f.identity != identity || h.f.creates != 0 || h.f.deletes != 0 || h.f.seeds != 0 || f.behaviorCompletion != nil {
				t.Fatal("changed/restored remote witness escaped the closed named scan")
			}
		})
	}
}

func TestFixturePhaseNamedScanKeepsPerGETAuthorizationAndLocalEvidence(t *testing.T) {
	newPhase := unmarkedRecoveryPhaseFactory(t)
	for _, fault := range []string{"get-denied", "get-error", "get-forbidden", "wal-replaced", "world-replaced", "foreign-uid", "whole-shape", "journal-rv"} {
		t.Run(fault, func(t *testing.T) {
			h := newPhase(t)
			f, ledger := h.f, h.f.wire.ledger
			injected := false
			refused := false
			prior := f.actor.fixtureHandler
			f.actor.fixtureHandler = func(w http.ResponseWriter, r *http.Request) bool {
				if injected && fault == "get-denied" && r.URL.Path == "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" {
					body, _ := io.ReadAll(r.Body)
					r.Body = io.NopCloser(bytes.NewReader(body))
					var review authv1.SelfSubjectAccessReview
					if json.Unmarshal(body, &review) == nil && review.Spec.ResourceAttributes != nil && review.Spec.ResourceAttributes.Verb == "get" && review.Spec.ResourceAttributes.Name == ledger.document.Entries[1].Key.Name {
						review.Status.Allowed = false
						_ = json.NewEncoder(w).Encode(review)
						return true
					}
				}
				if injected && (fault == "get-error" || fault == "get-forbidden") && r.Method == http.MethodGet {
					path, _, _ := fixturePath(ledger.document.Entries[1].Key, false)
					if r.URL.Path == path {
						status := http.StatusInternalServerError
						if fault == "get-forbidden" {
							status = http.StatusForbidden // SSAR success is not actual GET permission
						}
						w.WriteHeader(status)
						refused = true
						return true
					}
				}
				return prior(w, r)
			}
			h.afterGet = func(slot int) {
				if slot != 0 || injected {
					return
				}
				injected = true
				switch fault {
				case "wal-replaced":
					if _, err := ledger.engine.files.AtomicWrite(ledger.name, bytes.Clone(ledger.body), &ledger.identity); err != nil {
						t.Error("WAL replacement injection unavailable")
					}
				case "world-replaced":
					name, _ := ledger.originalWorldsName()
					body, id, err := ledger.engine.files.ReadEvidence(name, privatefs.MaxEvidenceFileBytes)
					if err != nil {
						t.Error("original companion unavailable")
					} else if _, err := ledger.engine.files.AtomicWrite(name, body, &id); err != nil {
						t.Error("companion replacement injection unavailable")
					}
				case "foreign-uid":
					f.objects[1].SetUID("b0000000-0000-4000-8000-000000000001")
				case "whole-shape":
					_ = unstructured.SetNestedField(f.objects[1].Object, "foreign", "spec", "nodeName")
				case "journal-rv":
					s := f.actor.request.Snapshot
					ns, err := f.actor.v.f.access.client.CoreV1().Namespaces().Get(t.Context(), s.Anchor().Namespace, metav1.GetOptions{})
					if err != nil {
						t.Error("original namespace unavailable")
					} else {
						ns.ResourceVersion = "999"
						// Inject remote drift directly into the fake tracker. The
						// fixture's normal namespace UPDATE correctly rejects our
						// changed RV as stale CAS; that is not the fault under test.
						if err := f.actor.v.f.access.client.Tracker().Update(corev1.SchemeGroupVersion.WithResource("namespaces"), ns, ""); err != nil {
							t.Error("namespace RV injection unavailable")
						}
					}
				}
			}
			before, identity := bytes.Clone(ledger.body), ledger.identity
			if result, err := f.wire.observePhase(t.Context()); result != nil || err != ErrFixtures || !injected || ledger.phaseFloor != nil || !bytes.Equal(before, ledger.body) || ledger.identity != identity || f.creates != 0 || f.deletes != 0 || f.seeds != 0 || ledger.behaviorCompletion != nil {
				t.Fatal("read-only named scan bypassed exact permission/file/object/journal checks")
			}
			if fault == "get-forbidden" && !refused {
				t.Fatal("native GET refusal was not exercised")
			}
		})
	}
}
