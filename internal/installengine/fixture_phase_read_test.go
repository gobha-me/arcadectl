// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	authv1 "k8s.io/api/authorization/v1"
)

// Actual composed sealed observers over fake HTTPS. This is not native
// admission certification. It proves the phase-only batching retains every
// collection, named scan, source permission and GC rediscovery boundary.
func TestFixturePhaseReadPassKeepsCompleteCollectionsAndNativeRefusals(t *testing.T) {
	newPhase := unmarkedRecoveryPhaseFactory(t)
	for _, fault := range []string{"healthy", "metadata-forbidden", "list-review-denied", "final-discovery-refused", "late-policy-restored"} {
		t.Run(fault, func(t *testing.T) {
			h := newPhase(t)
			f, ledger := h.f, h.f.wire.ledger
			base := f.actor.fixtureHandler
			typed, metadata, listReviews := map[string]int{}, map[string]int{}, map[string]int{}
			catalogues := 0
			namedReviews := map[int]int{}
			injected := false
			f.actor.fixtureHandler = func(w http.ResponseWriter, r *http.Request) bool {
				if r.Method == http.MethodPost && r.URL.Path == "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" {
					body, _ := io.ReadAll(r.Body)
					r.Body = io.NopCloser(bytes.NewReader(body))
					var review authv1.SelfSubjectAccessReview
					if json.Unmarshal(body, &review) != nil {
						t.Error("exact review unavailable")
					}
					if a := review.Spec.ResourceAttributes; a != nil {
						for slot, entry := range ledger.document.Entries {
							permission, err := fixturePermission(entry.Key, "get")
							if err == nil && review.Spec.ResourceAttributes != nil && *a == *permission.spec.ResourceAttributes && review.Spec.NonResourceAttributes == nil {
								namedReviews[slot]++
							}
						}
						if a.Verb == "list" {
							listReviews[a.Group+"/"+a.Resource]++
							if fault == "list-review-denied" && h.gets != 0 {
								review.Status.Allowed = false
								_ = json.NewEncoder(w).Encode(review)
								injected = true
								return true
							}
						}
					}
				}
				if r.Method == http.MethodGet && r.URL.Path == "/apis" {
					catalogues++
					if fault == "final-discovery-refused" && catalogues == 3 {
						w.WriteHeader(http.StatusForbidden)
						injected = true
						return true
					}
				}
				if r.Method == http.MethodGet && r.URL.Query().Get("limit") == "128" {
					if strings.Contains(r.Header.Get("Accept"), "PartialObjectMetadataList") {
						metadata[r.URL.Path]++
						if fault == "metadata-forbidden" && h.gets != 0 {
							w.WriteHeader(http.StatusForbidden)
							injected = true
							return true // even after successful exact LIST SSAR
						}
					} else {
						typed[r.URL.Path]++
					}
				}
				return base(w, r)
			}
			if fault == "late-policy-restored" {
				// The final catalogue is after all GC pages. Restore original
				// policy shape with a newer native RV; remote pass closure must
				// refuse before publishing this pass or advancing its floor.
				prior := f.actor.fixtureHandler
				f.actor.fixtureHandler = func(w http.ResponseWriter, r *http.Request) bool {
					handled := prior(w, r)
					if r.Method == http.MethodGet && r.URL.Path == "/apis" && catalogues == 3 {
						for key, object := range f.actor.v.f.access.objects {
							if key.Kind == "ValidatingAdmissionPolicy" {
								object.SetResourceVersion("999")
								injected = true
								break
							}
						}
					}
					return handled
				}
			}
			body, identity := bytes.Clone(ledger.body), ledger.identity
			trace := &admissionTrace{}
			result, err := f.wire.observePhase(context.WithValue(t.Context(), admissionTraceKey{}, trace))
			stage, slot := trace.phaseSnapshot()
			if fault != "healthy" {
				if result != nil || err != ErrFixtures || !injected || ledger.phaseFloor != nil {
					t.Fatal("read pass accepted native refusal or late remote drift", fault, err)
				}
				expected := "gc-collections"
				if fault == "late-policy-restored" {
					expected = "public-after"
				}
				if stage != expected || slot != -1 {
					t.Fatal("fixed phase diagnostic did not identify the actual refusal boundary", stage, slot)
				}
			} else {
				if stage != "complete" || slot != -1 {
					t.Fatal("complete paired reads did not retain their fixed diagnostic")
				}
				if result == nil || err != nil || catalogues != 6 || h.gets != 2*len(ledger.document.Entries) {
					t.Fatalf("complete paired read passes unavailable: %v catalogues=%d gets=%d", err, catalogues, h.gets)
				}
				ns := ledger.document.Entries[0].Key.Namespace
				for _, collection := range proofCollections {
					path := "/apis/" + collection.gv
					group := strings.Split(collection.gv, "/")[0]
					if collection.gv == "v1" {
						path, group = "/api/v1", ""
					}
					if collection.namespaced {
						path += "/namespaces/" + ns
					}
					path += "/" + collection.plural
					if collection.kind == "Secret" {
						if metadata[path] != 4 { // two typed Secret reads plus two GC collections
							t.Fatal("metadata-only Secret passes omitted", metadata[path])
						}
					} else if typed[path] != 2 {
						t.Fatal("complete typed collection omitted", collection.kind, typed[path])
					}
					if collection.namespaced && (metadata[path] < 2 || listReviews[group+"/"+collection.plural] != 2) {
						t.Fatal("GC metadata or exact source review omitted", collection.kind)
					}
				}
				if metadata["/apis/gc.example.test/v1/namespaces/"+ns+"/widgets"] != 2 || listReviews["gc.example.test/widgets"] != 2 {
					t.Fatal("unknown custom GC source or its exact LIST permission omitted")
				}
				for slot := range ledger.document.Entries {
					if namedReviews[slot] != 2 {
						t.Fatal("exact per-GET permission omitted", slot, namedReviews[slot])
					}
				}
			}
			if !bytes.Equal(body, ledger.body) || identity != ledger.identity || f.creates != 0 || f.deletes != 0 || f.seeds != 0 || f.previews != 0 || ledger.behaviorCompletion != nil {
				t.Fatal("read-only interval changed WAL or effect capabilities")
			}
		})
	}
}
