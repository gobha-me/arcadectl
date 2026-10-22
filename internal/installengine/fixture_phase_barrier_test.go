// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/gobha-me/arcadectl/internal/privatefs"
)

// These composed sealed observers use fake TLS, not native admission or a
// lifecycle certificate. The existing named/GC/renewal tests retain their own
// complete permission, pagination, whole-object and warm-closure obligations.
func phaseBarrierFactory(t *testing.T, recipe string) func(*testing.T) *fixturePhaseTest {
	t.Helper()
	if recipe == fixtureRecipeV3 {
		return fixtureV3PhaseFactory(t)
	}
	if recipe != fixtureRecipeV2 {
		t.Fatal("unsupported barrier test recipe")
	}
	return fixturePhaseFactoryWithSetup(t, func(h *fixturePhaseTest) {
		instrumentFreshFixtureRecipeV2(t, h.f.wire.ledger)
	})
}

type phaseBarrierCounts struct {
	policies, bindings map[string]int
	requests           map[string]int
}

func phaseBarrierObserve(t *testing.T, h *fixturePhaseTest) phaseBarrierCounts {
	t.Helper()
	counts := phaseBarrierCounts{map[string]int{}, map[string]int{}, map[string]int{}}
	trace := &admissionTrace{}
	base := h.f.actor.fixtureHandler
	defer func() { h.f.actor.fixtureHandler = base }()
	h.f.actor.fixtureHandler = func(w http.ResponseWriter, r *http.Request) bool {
		stage, _ := trace.phaseSnapshot()
		counts.requests[stage]++ // actor fixture serializes handlers on its mutex
		if testRuntimeConfigurationRequest(r) {
			if strings.HasSuffix(r.URL.Path, "/validatingadmissionpolicies") {
				counts.policies[stage]++
			} else if strings.HasSuffix(r.URL.Path, "/validatingadmissionpolicybindings") {
				counts.bindings[stage]++
			}
		}
		return base(w, r)
	}
	if result, err := h.f.wire.observePhase(context.WithValue(t.Context(), admissionTraceKey{}, trace)); result == nil || err != nil || h.f.wire.ledger.phaseFloor == nil {
		t.Fatal("complete paired phase unavailable", err)
	}
	return counts
}

func phaseBarrierUnchanged(t *testing.T, h *fixturePhaseTest, body []byte, identity privatefs.FileIdentity) {
	t.Helper()
	f, ledger := h.f, h.f.wire.ledger
	if !bytes.Equal(body, ledger.body) || identity != ledger.identity || f.creates != 0 || f.deletes != 0 || f.previews != 0 || f.seeds != 0 || ledger.behaviorCompletion != nil || ledger.ackSlot != -1 || ledger.effectSlot != -1 {
		t.Fatal("read-only barrier changed WAL or published an effect capability")
	}
}

func TestFixturePhaseReadBarrierColdCensus(t *testing.T) {
	for _, recipe := range []string{fixtureRecipeV2, fixtureRecipeV3} {
		t.Run(recipe, func(t *testing.T) {
			newPhase := phaseBarrierFactory(t, recipe)
			h := newPhase(t)
			ledger := h.f.wire.ledger
			body, identity := bytes.Clone(ledger.body), ledger.identity
			counts := phaseBarrierObserve(t, h)
			// Six configuration observations = four FULL outer witnesses plus
			// the independent before/after configuration pair. Each observation
			// must still read BOTH complete runtime collections. Cold fixtures
			// have no warm-renewal guards to confuse this outer-only census.
			want := map[string]int{"original-witness": 1, "configured": 1, "public-after": 2, "final-configured": 1, "final-public": 1}
			if !reflect.DeepEqual(counts.policies, want) || !reflect.DeepEqual(counts.bindings, want) || h.gets != 2*len(ledger.document.Entries) || len(ledger.phaseFloor.Leaders) != 0 {
				t.Fatal("outer witness/configuration/named-read census changed", counts.policies, counts.bindings, h.gets)
			}
			phaseBarrierUnchanged(t, h, body, identity)
			// A new invocation must perform the SAME fresh remote witnesses,
			// never inherit a successful guard from the previous invocation.
			h.gets = 0
			if again := phaseBarrierObserve(t, h); !reflect.DeepEqual(again.policies, want) || !reflect.DeepEqual(again.bindings, want) || h.gets != 2*len(ledger.document.Entries) {
				t.Fatal("later phase reused a witness")
			}
			phaseBarrierUnchanged(t, h, body, identity)
		})
	}
}

func TestFixturePhaseReadBarrierClosuresBeforeFloor(t *testing.T) {
	for _, recipe := range []string{fixtureRecipeV2, fixtureRecipeV3} {
		newPhase := phaseBarrierFactory(t, recipe)
		for _, closure := range []int{3, 4, 6} {
			for _, fault := range []string{"forbidden", "resource-version", "uid"} {
				t.Run(recipe+"/"+string(rune('0'+closure))+"/"+fault, func(t *testing.T) {
					h := newPhase(t)
					ledger := h.f.wire.ledger
					before, identity := bytes.Clone(ledger.body), ledger.identity
					base := h.f.actor.fixtureHandler
					calls, injected := 0, false
					var floorBefore []byte
					h.f.actor.fixtureHandler = func(w http.ResponseWriter, r *http.Request) bool {
						if testRuntimeConfigurationRequest(r) && strings.HasSuffix(r.URL.Path, "/validatingadmissionpolicies") {
							calls++
							if calls == closure {
								floorBefore, _ = json.Marshal(ledger.phaseFloor)
								injected = true
								if fault == "forbidden" {
									w.WriteHeader(http.StatusForbidden)
									return true // successful earlier reads grant no permit
								}
								for key, object := range h.f.actor.v.f.access.objects {
									if key.Kind == "ValidatingAdmissionPolicy" {
										if fault == "uid" {
											object.SetUID("b0000000-0000-4000-8000-000000000001")
										} else {
											object.SetResourceVersion("999") // WHOLE original shape, newer native RV
										}
										break
									}
								}
							}
						}
						return base(w, r)
					}
					result, err := h.f.wire.observePhase(t.Context())
					floorAfter, _ := json.Marshal(ledger.phaseFloor)
					wantGets := 2 * len(ledger.document.Entries)
					if closure == 3 {
						wantGets = len(ledger.document.Entries)
					}
					if result != nil || err != ErrFixtures || !injected || calls != closure || h.gets != wantGets || !bytes.Equal(floorBefore, floorAfter) || (closure == 3) != (ledger.phaseFloor == nil) {
						t.Fatal("closure refused too early/late or advanced an unclosed floor", calls, h.gets, err)
					}
					phaseBarrierUnchanged(t, h, before, identity)
				})
			}
		}
	}
}

func TestFixturePhaseReadBarrierLocalReplacement(t *testing.T) {
	for _, recipe := range []string{fixtureRecipeV2, fixtureRecipeV3} {
		newPhase := phaseBarrierFactory(t, recipe)
		control := newPhase(t)
		counts := phaseBarrierObserve(t, control)
		publicPaths := map[string]bool{}
		for _, row := range control.f.wire.ledger.phaseFloor.Public {
			path, err := resourcePath(row.Key, false)
			if err != nil || publicPaths[path] {
				t.Fatal("exact public read catalogue unavailable")
			}
			publicPaths[path] = true
		}
		if len(publicPaths) == 0 {
			t.Fatal("public replacement boundary would be vacuous")
		}
		for _, stage := range []string{"configured", "public-after", "final-configured", "final-public"} {
			for _, file := range []string{"wal", "worlds"} {
				t.Run(recipe+"/"+stage+"/"+file, func(t *testing.T) {
					h := newPhase(t)
					ledger := h.f.wire.ledger
					before, identity := bytes.Clone(ledger.body), ledger.identity
					trace := &admissionTrace{}
					base := h.f.actor.fixtureHandler
					calls, replaced := 0, false
					var floorBefore []byte
					h.f.actor.fixtureHandler = func(w http.ResponseWriter, r *http.Request) bool {
						handled := base(w, r)
						actual, _ := trace.phaseSnapshot()
						if actual == stage {
							limit := counts.requests[stage]
							public := stage == "public-after" || stage == "final-public"
							if public {
								limit = len(publicPaths)
							}
							if !public || r.Method == http.MethodGet && publicPaths[r.URL.Path] {
								calls++
							}
							// After the complete public inventory, BEFORE any V3
							// account collection or retained full witness. Configured
							// targets its final response. All bytes stay identical.
							if !replaced && calls == limit {
								floorBefore, _ = json.Marshal(ledger.phaseFloor)
								name, body, id := ledger.name, bytes.Clone(ledger.body), ledger.identity
								if file == "worlds" {
									name, _ = ledger.originalWorldsName()
									var err error
									body, id, err = ledger.engine.files.ReadEvidence(name, privatefs.MaxEvidenceFileBytes)
									if err != nil {
										t.Error("companion fault setup unavailable")
										return handled
									}
								}
								if _, err := ledger.engine.files.AtomicWrite(name, body, &id); err != nil {
									t.Error("same-byte replacement unavailable")
								}
								replaced = true
							}
						}
						return handled
					}
					result, err := h.f.wire.observePhase(context.WithValue(t.Context(), admissionTraceKey{}, trace))
					floorAfter, _ := json.Marshal(ledger.phaseFloor)
					if result != nil || err != ErrFixtures || !replaced || !bytes.Equal(floorBefore, floorAfter) {
						t.Fatal("local boundary accepted replaced protected evidence", stage, file, err)
					}
					phaseBarrierUnchanged(t, h, before, identity)
				})
			}
		}
	}
}
