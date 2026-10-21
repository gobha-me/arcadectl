// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Genuine independent actor checkpoints and protected receipts, but FAKE
// native-derived replies. This is no native effect/cleanup/provider proof.
func fixtureWarmSeedWireFactory(t *testing.T) func(*testing.T) *fixtureWireTest {
	t.Helper()
	learning := warmSeedLearningFactory(t)
	return func(t *testing.T) *fixtureWireTest {
		t.Helper()
		f := learning(t, fixtureDestroySeedWarmCancelled)
		f.nativeWarmSeedReply = true
		return f
	}
}

func TestFixtureWarmSeedWireOriginalAckSharedSendAndReload(t *testing.T) {
	f := fixtureWarmSeedWireFactory(t)(t)
	ledger := f.wire.ledger
	for slot := 0; slot < fixtureCancelledDestroy; slot++ {
		if _, err := f.wire.request(t.Context(), slot, fixtureWarmSeedStatusRequest); err != ErrFixtures {
			t.Fatal("warm seed enum selected nonfixed slot")
		}
	}
	if f.seeds != 0 || !ledger.seedAck || !ledger.seedEffect {
		t.Fatal("wrong slot consumed/exercised warm capability")
	}
	rebuilt, err := f.wire.actors.fixtures(t.Context(), ledger)
	if err != nil {
		t.Fatal("original rebuilt wire unavailable")
	}
	type outcome struct {
		result *unstructured.Unstructured
		err    error
	}
	replies := make(chan outcome, 2)
	for _, w := range []*fixtureWire{f.wire, rebuilt} {
		go func(w *fixtureWire) {
			result, err := w.seedWarmDestroyStatus(t.Context())
			replies <- outcome{result, err}
		}(w)
	}
	a, b := <-replies, <-replies
	if a.err != nil {
		a, b = b, a
	}
	if a.err != nil || a.result == nil || b.err != ErrFixtures || b.result != nil || f.seeds != 1 || a.result.GetResourceVersion() != "102" || ledger.document.DestroySeed.Mode != fixtureDestroySeedWarmCancelled || ledger.document.DestroySeed.State != fixtureDestroySeedAcknowledged || ledger.document.DestroySeed.AcknowledgedResourceVersion != "102" || ledger.seedAck || ledger.seedEffect || ledger.validateWarmDestroySeedResult(a.result, time.Now().UTC()) != nil || ledger.validateDestroySeedResult(a.result, time.Now().UTC()) != ErrFixtures || f.wire.fixturesSettled() {
		t.Fatal("shared warm wire lost original ACK/shape or sent twice", a.err, b.err)
	}
	a.result.SetResourceVersion("999")
	if f.objects[fixtureCancelledDestroy].GetResourceVersion() != "102" {
		t.Fatal("warm returned object aliases persistent reply")
	}
	if ledger.close() != nil {
		t.Fatal("warm receipt close failed")
	}
	loaded, err := ledger.engine.loadFixtureLedger(t.Context(), f.actor.request.Snapshot)
	if err != nil {
		t.Fatal("warm acknowledged reload unavailable")
	}
	defer loaded.close()
	rebuilt, err = f.wire.actors.fixtures(t.Context(), loaded)
	if err != nil {
		t.Fatal("warm original reloaded wire unavailable")
	}
	if _, err := rebuilt.seedWarmDestroyStatus(t.Context()); err != ErrFixtures || loaded.seedAck || loaded.seedEffect || f.seeds != 1 || loaded.engine.fixtureFence(f.actor.request.Snapshot) != ErrFixtures {
		t.Fatal("warm reload restored effect or retired WAL fence")
	}
}

func TestFixtureWarmSeedWireReliableAckBeforeLateRefusal(t *testing.T) {
	newSeed := fixtureWarmSeedWireFactory(t)
	for _, fault := range []string{"post-witness", "outer-error", "outer-fake-rv", "whole-shape", "file-replacement"} {
		t.Run(fault, func(t *testing.T) {
			f := newSeed(t)
			ledger := f.wire.ledger
			switch fault {
			case "post-witness":
				f.afterSeed = func() {
					for key, o := range f.actor.v.f.access.objects {
						if key.Kind == "ServiceAccount" {
							o.SetResourceVersion("999")
							break
						}
					}
				}
			case "outer-error", "outer-fake-rv":
				original := f.wire.clients[0].client.Transport
				f.wire.clients[0].client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
					response, err := original.RoundTrip(r)
					if r.Method != http.MethodPut || response == nil {
						return response, err
					}
					body, _ := io.ReadAll(response.Body)
					if string(body) != "{}" || response.Header.Get("X-Private-Canary") != "" {
						t.Error("native warm reply escaped below-wrapper sanitizer")
					}
					if fault == "outer-error" {
						return nil, errors.New("PRIVATE-WARM-WIRE-CANARY")
					}
					response.Body = io.NopCloser(strings.NewReader(`{"metadata":{"resourceVersion":"999","uid":"foreign"}}`))
					return response, nil
				})
			case "whole-shape":
				f.seedReply = func(w http.ResponseWriter, o *unstructured.Unstructured) {
					_ = unstructured.SetNestedField(o.Object, "Deleting", "status", "phase")
					_ = json.NewEncoder(w).Encode(o.Object)
				}
			case "file-replacement":
				f.afterSeed = func() {
					if _, err := ledger.engine.files.AtomicWrite(ledger.name, bytes.Clone(ledger.body), &ledger.identity); err != nil {
						t.Error("test WAL replacement unavailable")
					}
				}
			}
			result, err := f.wire.seedWarmDestroyStatus(t.Context())
			if fault == "outer-fake-rv" {
				if err != nil || result == nil || result.GetResourceVersion() != "102" {
					t.Fatal("outer warm reply forged actual ACK", err)
				}
			} else if result != nil || err != ErrFixtures {
				t.Fatal("warm post-ACK refusal returned acceptance or unsafe error", err)
			}
			ack := fault != "file-replacement"
			if (ledger.document.DestroySeed.State == fixtureDestroySeedAcknowledged) != ack || ack && ledger.document.DestroySeed.AcknowledgedResourceVersion != "102" || ledger.seedAck || ledger.seedEffect || f.seeds != 1 {
				t.Fatal("warm reliable ACK lost or local persistence failure fabricated it")
			}
			if _, err := f.wire.seedWarmDestroyStatus(t.Context()); err != ErrFixtures || f.seeds != 1 {
				t.Fatal("late warm refusal replayed status")
			}
		})
	}
}

func TestFixtureWarmSeedWireUnknownCannotAdoptReplayOrClean(t *testing.T) {
	newSeed := fixtureWarmSeedWireFactory(t)
	for _, fault := range []string{"same-rv", "foreign-uid", "partial", "duplicate", "mime", "oversize", "status", "redirect"} {
		t.Run(fault, func(t *testing.T) {
			f := newSeed(t)
			ledger := f.wire.ledger
			f.seedReply = func(w http.ResponseWriter, o *unstructured.Unstructured) {
				switch fault {
				case "same-rv":
					o.SetResourceVersion("101")
				case "foreign-uid":
					o.SetUID("c0000000-0000-4000-8000-000000000001")
				case "partial":
					_, _ = io.WriteString(w, `{"metadata":`)
					return
				case "duplicate":
					body, _ := json.Marshal(o.Object)
					_, _ = w.Write(append([]byte(`{"kind":"foreign",`), body[1:]...))
					return
				case "mime":
					w.Header().Set("Content-Type", "text/plain")
				case "oversize":
					_, _ = io.WriteString(w, strings.Repeat("X", 1024*1024+1))
					return
				case "status":
					w.WriteHeader(http.StatusInternalServerError)
					_, _ = io.WriteString(w, "PRIVATE-WARM-WIRE-CANARY")
					return
				case "redirect":
					w.Header().Set("Location", "/PRIVATE-REDIRECT-CANARY")
					w.WriteHeader(http.StatusTemporaryRedirect)
					return
				}
				_ = json.NewEncoder(w).Encode(o.Object)
			}
			result, err := f.wire.seedWarmDestroyStatus(t.Context())
			if result != nil || err != ErrOutcomeUnknown || ledger.document.DestroySeed.State != fixtureDestroySeedAttempted || ledger.seedAck || ledger.seedEffect || f.seeds != 1 {
				t.Fatal("unknown warm reply acknowledged or retained capabilities", err)
			}
			f.seedReply = nil
			live, absent, err := f.wire.get(t.Context(), fixtureCancelledDestroy)
			if err != nil || absent || live.GetResourceVersion() != "102" || ledger.document.DestroySeed.State != fixtureDestroySeedAttempted {
				t.Fatal("later GET adopted unknown warm effect")
			}
			if ledger.close() != nil {
				t.Fatal("unknown warm close failed")
			}
			loaded, err := ledger.engine.loadFixtureLedger(t.Context(), f.actor.request.Snapshot)
			if err != nil {
				t.Fatal("unknown warm reload failed")
			}
			defer loaded.close()
			rebuilt, err := f.wire.actors.fixtures(t.Context(), loaded)
			if err != nil {
				t.Fatal("unknown original warm wire unavailable")
			}
			if _, err := rebuilt.seedWarmDestroyStatus(t.Context()); err != ErrFixtures || f.seeds != 1 || loaded.seedAck || loaded.seedEffect || loaded.advance(fixtureSeedAcknowledgement(t, loaded)) != ErrFixtures {
				t.Fatal("unknown warm reload regained replay or ACK")
			}
			next, _ := loaded.nextDocument()
			next.Entries[fixtureCancelledDestroy].State, next.Entries[fixtureCancelledDestroy].DeleteResourceVersion = fixtureDeleteAttempted, "102"
			if loaded.advance(next) != ErrFixtures || loaded.engine.fixtureFence(f.actor.request.Snapshot) != ErrFixtures {
				t.Fatal("unknown warm reload granted cleanup/ordinary progression")
			}
		})
	}
}

func TestFixtureWarmSeedWirePreflightAndTamperingNoWrite(t *testing.T) {
	newSeed := fixtureWarmSeedWireFactory(t)
	for _, fault := range []string{"missing-discovery", "deny", "rv", "uid", "status", "finalizer", "cancelled", "path", "query", "body", "identity", "context", "idempotency"} {
		t.Run(fault, func(t *testing.T) {
			f := newSeed(t)
			ctx := t.Context()
			switch fault {
			case "missing-discovery":
				f.missingSeedDiscovery = true
			case "deny":
				f.denySeed = true
			case "rv":
				f.objects[fixtureCancelledDestroy].SetResourceVersion("100")
			case "uid":
				f.objects[fixtureCancelledDestroy].SetUID("c0000000-0000-4000-8000-000000000001")
			case "status":
				_ = unstructured.SetNestedField(f.objects[fixtureCancelledDestroy].Object, "Deleting", "status", "phase")
			case "finalizer":
				f.objects[fixtureCancelledDestroy].SetFinalizers(nil)
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			default:
				original := f.wire.clients[0].client.Transport
				f.wire.clients[0].client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
					if r.Method == http.MethodPut {
						switch fault {
						case "path":
							r.URL.Path = strings.TrimSuffix(r.URL.Path, "/status")
						case "query":
							r.URL.RawQuery = "dryRun=All"
						case "body":
							r.Body = io.NopCloser(strings.NewReader(`{"status":{"phase":"Deleting"}}`))
						case "identity":
							r.Header.Set("Impersonate-User", "foreign")
						case "context":
							r = r.WithContext(context.Background())
						case "idempotency":
							r.Header.Set("Idempotency-Key", "")
						}
					}
					return original.RoundTrip(r)
				})
			}
			before := bytes.Clone(f.wire.ledger.body)
			result, err := f.wire.seedWarmDestroyStatus(ctx)
			if result != nil || err == nil || f.seeds != 0 || f.wire.ledger.seedAck || f.wire.ledger.seedEffect || !bytes.Equal(before, f.wire.ledger.body) {
				t.Fatal("warm preflight/request drift reached effect or retained capability", err)
			}
		})
	}
}

func TestFixtureSeedWireColdWarmCrossoverRefusesBeforeAnyHTTP(t *testing.T) {
	newCold, newWarm := fixtureSeedWireFactory(t), fixtureWarmSeedWireFactory(t)
	for _, warm := range []bool{false, true} {
		factory := newCold
		if warm {
			factory = newWarm
		}
		f := factory(t)
		var calls atomic.Int64
		original := f.actor.fixtureHandler
		f.actor.fixtureHandler = func(w http.ResponseWriter, r *http.Request) bool { calls.Add(1); return original(w, r) }
		before, identity, revision := bytes.Clone(f.wire.ledger.body), f.wire.ledger.identity, f.wire.ledger.document.Revision
		if warm {
			if f.wire.prepareDestroySeed(t.Context()) != ErrFixtures {
				t.Fatal("warm intent entered cold preparation")
			}
			if _, err := f.wire.destroySeedPayload(t.Context()); err != ErrFixtures {
				t.Fatal("warm intent entered cold payload")
			}
			if _, err := f.wire.seedDestroyStatus(t.Context()); err != ErrFixtures {
				t.Fatal("warm intent entered cold send")
			}
			if _, err := f.wire.request(t.Context(), fixtureCancelledDestroy, fixtureSeedStatusRequest); err != ErrFixtures {
				t.Fatal("warm intent entered direct cold enum")
			}
		} else {
			if f.wire.prepareWarmDestroySeed(t.Context()) != ErrFixtures {
				t.Fatal("cold intent entered warm preparation")
			}
			if _, err := f.wire.warmDestroySeedPayload(t.Context()); err != ErrFixtures {
				t.Fatal("cold intent entered warm payload")
			}
			if _, err := f.wire.seedWarmDestroyStatus(t.Context()); err != ErrFixtures {
				t.Fatal("cold intent entered warm send")
			}
			if _, err := f.wire.request(t.Context(), fixtureCancelledDestroy, fixtureWarmSeedStatusRequest); err != ErrFixtures {
				t.Fatal("cold intent entered direct warm enum")
			}
		}
		if calls.Load() != 0 || f.seeds != 0 || f.reads != 0 || !bytes.Equal(before, f.wire.ledger.body) || f.wire.ledger.identity != identity || f.wire.ledger.document.Revision != revision || !f.wire.ledger.seedAck || !f.wire.ledger.seedEffect {
			t.Fatal("route crossover reached ANY HTTP or changed original receipt/caps")
		}
	}
}

func TestFixtureSeedWireDirectEnumsRevokeUnknownCapabilities(t *testing.T) {
	for _, route := range []struct {
		name      string
		factory   func(*testing.T) *fixtureWireTest
		operation fixtureRequest
	}{
		{"cold", fixtureSeedWireFactory(t), fixtureSeedStatusRequest},
		{"warm", fixtureWarmSeedWireFactory(t), fixtureWarmSeedStatusRequest},
	} {
		t.Run(route.name, func(t *testing.T) {
			for _, fault := range []string{"foreign-uid", "partial"} {
				t.Run(fault, func(t *testing.T) {
					f := route.factory(t)
					ledger := f.wire.ledger
					f.seedReply = func(w http.ResponseWriter, o *unstructured.Unstructured) {
						if fault == "partial" {
							_, _ = io.WriteString(w, `{"metadata":`)
							return
						}
						o.SetUID("c0000000-0000-4000-8000-000000000001")
						_ = json.NewEncoder(w).Encode(o.Object)
					}
					before, identity, revision := bytes.Clone(ledger.body), ledger.identity, ledger.document.Revision
					// Intentionally bypass both seed entrypoints' deferred revocation.
					// The common enum MUST revoke unknown ACK authority itself.
					ledger.wireMu.Lock()
					capture, err := f.wire.request(t.Context(), fixtureCancelledDestroy, route.operation)
					ledger.wireMu.Unlock()
					if err != ErrFixtures || capture == nil || capture.seedAcknowledgedRV != "" || f.seeds != 1 || ledger.seedAck || ledger.seedEffect || ledger.document.DestroySeed.State != fixtureDestroySeedAttempted || !bytes.Equal(before, ledger.body) || ledger.identity != identity || ledger.document.Revision != revision {
						t.Fatal("direct unknown enum retained/fabricated ACK or replay authority")
					}
					if ledger.advance(fixtureSeedAcknowledgement(t, ledger)) != ErrFixtures {
						t.Fatal("direct unknown enum accepted a supplied ACK")
					}
					ledger.wireMu.Lock()
					_, err = f.wire.request(t.Context(), fixtureCancelledDestroy, route.operation)
					ledger.wireMu.Unlock()
					if err != ErrFixtures || f.seeds != 1 {
						t.Fatal("direct unknown enum replayed status")
					}
					f.seedReply = nil
					live, absent, err := f.wire.get(t.Context(), fixtureCancelledDestroy)
					if err != nil || absent || live.GetResourceVersion() != "102" || ledger.document.DestroySeed.State != fixtureDestroySeedAttempted {
						t.Fatal("later GET repaired direct unknown ACK")
					}
					next, _ := ledger.nextDocument()
					next.Entries[fixtureCancelledDestroy].State, next.Entries[fixtureCancelledDestroy].DeleteResourceVersion = fixtureDeleteAttempted, "102"
					if ledger.advance(next) != ErrFixtures || ledger.engine.fixtureFence(f.actor.request.Snapshot) != ErrFixtures || f.deletes != 0 || f.actor.v.f.access.writes != 0 || f.actor.v.f.nsUpdates != 0 {
						t.Fatal("direct unknown enum authorized cleanup/ordinary progress")
					}
				})
			}
		})
	}
}
