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
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installstate"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Independent genuine actor checkpoints, but synthetic original fixture ACKs
// and whole native-shaped fake objects. These are wire/WAL regressions, not
// native CREATE/status admission, coldness or cleanup certification.
func fixtureSeedWireFactory(t *testing.T) func(*testing.T) *fixtureWireTest {
	return fixtureSeedWireFactoryWithWorlds(t, false)
}

func fixtureSeedWireFactoryWithWorlds(t *testing.T, sealed bool) func(*testing.T) *fixtureWireTest {
	t.Helper()
	newPreview := fixturePreviewFactory(t)
	return func(t *testing.T) *fixtureWireTest {
		t.Helper()
		f := newPreview(t)
		if sealed && f.wire.ledger.sealOriginalWorlds([]fixtureWorldRow{}) != nil {
			t.Fatal("original empty-world seal unavailable")
		}
		acknowledgeAllRecipeFixtures(t, f.wire.ledger)
		created := time.Now().UTC().Truncate(time.Second).Add(-20 * time.Second)
		for slot := range fixtureCatalog {
			f.objects[slot] = fixtureResultExample(t, f.wire.ledger, slot, fixtureStableResult, created)
		}
		if f.wire.ledger.advance(fixtureSeedIntent(t, f.wire.ledger)) != nil {
			t.Fatal("fixture seed intent unavailable")
		}
		return f
	}
}

func TestFixtureSeedWireFixedStatusOriginalAckAndNoReplay(t *testing.T) {
	f := fixtureSeedWireFactory(t)(t)
	ledger, ctx := f.wire.ledger, t.Context()
	originalUID := ledger.document.Entries[fixtureCancelledDestroy].OriginalUID
	beforeRevision := ledger.document.Revision
	result, err := f.wire.seedDestroyStatus(ctx)
	if err != nil || result == nil || result.GetUID() != originalUID || result.GetResourceVersion() != "102" || f.seeds != 1 || ledger.document.DestroySeed.State != fixtureDestroySeedAcknowledged || ledger.document.DestroySeed.AcknowledgedResourceVersion != "102" || ledger.document.Revision != beforeRevision+1 || ledger.seedAck || ledger.seedEffect || ledger.ackSlot != -1 || ledger.effectSlot != -1 {
		t.Fatal("fixed original status write not reliably ACKed/accepted once", err)
	}
	if ledger.validateResult(fixtureCancelledDestroy, fixtureStableResult, result, time.Now().UTC()) != ErrFixtures || ledger.validateDestroySeedResult(result, time.Now().UTC()) != nil {
		t.Fatal("seeded validation relaxed normal absent-status contract")
	}
	result.Object["status"].(map[string]any)["phase"] = "Deleting"
	if f.objects[fixtureCancelledDestroy].Object["status"].(map[string]any)["phase"] != "Cancelled" {
		t.Fatal("returned seed object aliases captured persistent object")
	}
	if _, err := f.wire.seedDestroyStatus(ctx); err != ErrFixtures {
		t.Fatal("same-instance status write replayed")
	}
	rebuilt, err := f.wire.actors.fixtures(ctx, ledger)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rebuilt.seedDestroyStatus(ctx); err != ErrFixtures {
		t.Fatal("new client restored consumed status capability")
	}
	if ledger.close() != nil {
		t.Fatal("ledger close failed")
	}
	loaded, err := ledger.engine.loadFixtureLedger(ctx, f.actor.request.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.close()
	rebuilt, err = f.wire.actors.fixtures(ctx, loaded)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rebuilt.seedDestroyStatus(ctx); err != ErrFixtures || loaded.seedAck || loaded.seedEffect || f.seeds != 1 || ledger.engine.fixtureFence(f.actor.request.Snapshot) != ErrFixtures {
		t.Fatal("reload replayed status or retired active WAL fence")
	}
}

func TestFixtureSeedWireReliableAckPrecedesLaterRefusals(t *testing.T) {
	newSeed := fixtureSeedWireFactory(t)
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
					if r.Method != http.MethodPut {
						return response, err
					}
					if response == nil {
						t.Error("reliable inner reply unavailable")
						return response, err
					}
					body, _ := io.ReadAll(response.Body)
					if string(body) != "{}" || response.Header.Get("X-Private-Canary") != "" {
						t.Error("raw seed response escaped below-wrapper sanitization")
					}
					if fault == "outer-error" {
						return nil, errors.New("PRIVATE-OUTER-CANARY")
					}
					response.Body = io.NopCloser(strings.NewReader(`{"metadata":{"resourceVersion":"999","uid":"foreign"}}`))
					return response, nil
				})
			case "whole-shape":
				f.seedReply = func(w http.ResponseWriter, o *unstructured.Unstructured) {
					o.Object["status"].(map[string]any)["phase"] = "Deleting"
					_ = json.NewEncoder(w).Encode(o.Object)
				}
			case "file-replacement":
				f.afterSeed = func() {
					if _, err := ledger.engine.files.AtomicWrite(ledger.name, bytes.Clone(ledger.body), &ledger.identity); err != nil {
						t.Error(err)
					}
				}
			}
			result, err := f.wire.seedDestroyStatus(t.Context())
			if fault == "outer-fake-rv" {
				if err != nil || result == nil || result.GetResourceVersion() != "102" {
					t.Fatal("outer body replaced native ACK/result", err)
				}
			} else if err != ErrFixtures || result != nil || strings.Contains(err.Error(), "PRIVATE") {
				t.Fatal("post-ACK refusal lost fixed error boundary", err)
			}
			state := fixtureDestroySeedAcknowledged
			if fault == "file-replacement" {
				state = fixtureDestroySeedAttempted
			}
			if ledger.document.DestroySeed.State != state || state == fixtureDestroySeedAcknowledged && ledger.document.DestroySeed.AcknowledgedResourceVersion != "102" || ledger.seedAck || ledger.seedEffect || f.seeds != 1 {
				t.Fatal("reliable ACK not recorded before later refusal, or durability failure fabricated ACK")
			}
			if _, err := f.wire.seedDestroyStatus(t.Context()); err != ErrFixtures || f.seeds != 1 {
				t.Fatal("post-refusal status replayed")
			}
		})
	}
}

func TestFixtureSeedWireUnknownReplyCannotReplayAdoptOrClean(t *testing.T) {
	newSeed := fixtureSeedWireFactory(t)
	for _, fault := range []string{"unchanged-rv", "empty-rv", "zero-rv", "padded-rv", "overflow-rv", "foreign-uid", "foreign-name", "mime", "partial", "duplicate", "oversize", "status", "redirect"} {
		t.Run(fault, func(t *testing.T) {
			f := newSeed(t)
			ledger := f.wire.ledger
			f.seedReply = func(w http.ResponseWriter, o *unstructured.Unstructured) {
				switch fault {
				case "unchanged-rv":
					o.SetResourceVersion("101")
				case "empty-rv":
					o.SetResourceVersion("")
				case "zero-rv":
					o.SetResourceVersion("0")
				case "padded-rv":
					o.SetResourceVersion("0102")
				case "overflow-rv":
					o.SetResourceVersion("18446744073709551616")
				case "foreign-uid":
					o.SetUID("c0000000-0000-4000-8000-000000000001")
				case "foreign-name":
					o.SetName("foreign")
				case "mime":
					w.Header().Set("Content-Type", "text/plain")
				case "partial":
					_, _ = io.WriteString(w, `{"metadata":`)
					return
				case "duplicate":
					body, _ := json.Marshal(o.Object)
					_, _ = w.Write(append([]byte(`{"kind":"foreign",`), body[1:]...))
					return
				case "oversize":
					_, _ = io.WriteString(w, strings.Repeat("X", 1024*1024+1))
					return
				case "status":
					w.WriteHeader(500)
					_, _ = io.WriteString(w, "PRIVATE-STATUS-CANARY")
					return
				case "redirect":
					w.Header().Set("Location", "/PRIVATE-REDIRECT-CANARY")
					w.WriteHeader(307)
					return
				}
				_ = json.NewEncoder(w).Encode(o.Object)
			}
			if result, err := f.wire.seedDestroyStatus(t.Context()); result != nil || err != ErrOutcomeUnknown || ledger.document.DestroySeed.State != fixtureDestroySeedAttempted || ledger.seedAck || ledger.seedEffect || f.seeds != 1 {
				t.Fatal("unknown status became acknowledged or replayable", err)
			}
			f.seedReply = nil
			if _, err := f.wire.seedDestroyStatus(t.Context()); err != ErrFixtures {
				t.Fatal("unknown same-instance status replayed")
			}
			// Actual later original UID/new-RV/whole seeded observation does not
			// become reliable same-attempt ACK or settle this unknown intent.
			live, absent, err := f.wire.get(t.Context(), fixtureCancelledDestroy)
			if err != nil || absent || ledger.validateDestroySeedResult(live, time.Now().UTC()) != nil || ledger.document.DestroySeed.State != fixtureDestroySeedAttempted {
				t.Fatal("later observation failed or adopted unknown status")
			}
			if ledger.close() != nil {
				t.Fatal("ledger close unavailable")
			}
			loaded, err := ledger.engine.loadFixtureLedger(t.Context(), f.actor.request.Snapshot)
			if err != nil {
				t.Fatal(err)
			}
			defer loaded.close()
			rebuilt, err := f.wire.actors.fixtures(t.Context(), loaded)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := rebuilt.seedDestroyStatus(t.Context()); err != ErrFixtures || loaded.seedAck || loaded.seedEffect || f.seeds != 1 {
				t.Fatal("reload replayed unknown status")
			}
			next, _ := loaded.nextDocument()
			next.Entries[fixtureCancelledDestroy].State, next.Entries[fixtureCancelledDestroy].DeleteResourceVersion = fixtureDeleteAttempted, live.GetResourceVersion()
			if loaded.advance(next) != ErrFixtures || loaded.advance(fixtureSeedAcknowledgement(t, loaded)) != ErrFixtures || loaded.engine.fixtureFence(f.actor.request.Snapshot) != ErrFixtures {
				t.Fatal("later original shape/RV settled ACK or authorized cleanup")
			}
		})
	}
}

func TestFixtureSeedWirePreflightAndRequestTamperingRefuseBeforeWrite(t *testing.T) {
	newSeed := fixtureSeedWireFactory(t)
	for _, fault := range []string{"missing-discovery", "deny-status", "old-rv", "changed-uid", "status-present", "finalizer", "canceled", "path", "query", "uid", "rv", "spec", "status", "audit", "impersonation", "context", "idempotency"} {
		t.Run(fault, func(t *testing.T) {
			f := newSeed(t)
			ctx := t.Context()
			switch fault {
			case "missing-discovery":
				f.missingSeedDiscovery = true
			case "deny-status":
				f.denySeed = true
			case "old-rv":
				f.objects[fixtureCancelledDestroy].SetResourceVersion("100")
			case "changed-uid":
				f.objects[fixtureCancelledDestroy].SetUID("c0000000-0000-4000-8000-000000000001")
			case "status-present":
				f.objects[fixtureCancelledDestroy].Object["status"] = map[string]any{}
			case "finalizer":
				f.objects[fixtureCancelledDestroy].SetFinalizers([]string{"foreign"})
			case "canceled":
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
						case "impersonation":
							r.Header.Set("Impersonate-User", "foreign")
						case "context":
							r = r.WithContext(context.Background())
						case "idempotency":
							r.Header.Set("Idempotency-Key", "")
						default:
							var o unstructured.Unstructured
							body, _ := io.ReadAll(r.Body)
							if json.Unmarshal(body, &o.Object) != nil {
								t.Error("body unavailable")
							}
							switch fault {
							case "uid":
								o.SetUID("foreign")
							case "rv":
								o.SetResourceVersion("")
							case "spec":
								o.Object["spec"].(map[string]any)["cancelRequested"] = false
							case "status":
								o.Object["status"].(map[string]any)["phase"] = "Deleting"
							case "audit":
								o.SetAnnotations(nil)
							}
							body, _ = json.Marshal(o.Object)
							r.Body = io.NopCloser(bytes.NewReader(body))
							r.ContentLength = int64(len(body))
						}
					}
					return original.RoundTrip(r)
				})
			}
			before := bytes.Clone(f.wire.ledger.body)
			result, err := f.wire.seedDestroyStatus(ctx)
			if result != nil || err == nil || f.seeds != 0 || f.wire.ledger.seedAck || f.wire.ledger.seedEffect || !bytes.Equal(before, f.wire.ledger.body) {
				t.Fatal("preflight/request drift reached status effect or retained capabilities", err)
			}
			if _, err := f.wire.seedDestroyStatus(t.Context()); err != ErrFixtures || f.seeds != 0 {
				t.Fatal("preflight/request refusal replayed consumed attempt")
			}
		})
	}
}

func TestFixtureSeedWireClosedEnumAndSharedSingleSend(t *testing.T) {
	f := fixtureSeedWireFactory(t)(t)
	ledger := f.wire.ledger
	before := bytes.Clone(ledger.body)
	for slot := 0; slot < fixtureCancelledDestroy; slot++ {
		if _, err := f.wire.request(t.Context(), slot, fixtureSeedStatusRequest); err != ErrFixtures {
			t.Fatal("seed enum selected nonfixed slot")
		}
	}
	if _, err := fixturePermission(ledger.document.Entries[fixtureCancelledDestroy].Key, "update"); err != ErrFixtures {
		t.Fatal("seed broadened generic update permission")
	}
	if f.seeds != 0 || !bytes.Equal(before, ledger.body) || !ledger.seedAck || !ledger.seedEffect {
		t.Fatal("invalid seed enum performed effect/transition")
	}
	rebuilt, err := f.wire.actors.fixtures(t.Context(), ledger)
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 2)
	for _, wire := range []*fixtureWire{f.wire, rebuilt} {
		go func(w *fixtureWire) { _, err := w.seedDestroyStatus(t.Context()); results <- err }(wire)
	}
	a, b := <-results, <-results
	if (a == nil) == (b == nil) || a != nil && a != ErrFixtures || b != nil && b != ErrFixtures || f.seeds != 1 || ledger.seedAck || ledger.seedEffect || ledger.document.DestroySeed.State != fixtureDestroySeedAcknowledged {
		t.Fatal("shared clients sent more than one original status effect", a, b)
	}
	if !reflect.DeepEqual(ledger.document.Entries[fixtureCancelledDestroy].Key, installstate.Key{APIVersion: "arcade.gobha.me/v1alpha1", Kind: "GameDestroy", Namespace: f.actor.request.Snapshot.Anchor().Namespace, Name: "arcadectl-probe-" + ledger.document.RunID + "-cancelled-destroy"}) {
		t.Fatal("status changed original fixed address")
	}
}
