// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installstate"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Fake HTTPS replies exercise the closed preview seam, not native admission or
// cold/descendant authority. Both native profiles independently certify it.
// Replay the genuine lifecycle once per table, not once per fault. Children
// share only the immutable signed Plan and read-only public checkpoint values.
// Each has independent fake objects/Namespace/CAS, TLS, files, engine, server,
// clients, actor witnesses and WAL. No seed credential/file/capability is copied.
func fixturePreviewFactory(t *testing.T) func(*testing.T) *fixtureWireTest {
	t.Helper()
	seed := newActorFixture(t)
	plan, checkpoint := seed.v.f.plan, seed.request.Snapshot
	ns, err := seed.v.f.access.client.CoreV1().Namespaces().Get(t.Context(), checkpoint.Anchor().Namespace, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(seed.v.private.objects) != 0 {
		t.Fatal("preview checkpoint contains private Secrets")
	}
	if _, _, err := seed.v.f.engine.files.Read(credentialName(checkpoint.Anchor()), 1024*1024); !errors.Is(err, privatefs.ErrNotFound) {
		t.Fatal("preview checkpoint contains a credential candidate", err)
	}
	objects := map[installstate.Key]*unstructured.Unstructured{}
	for key, o := range seed.v.f.access.objects {
		if key.Kind == "Secret" {
			t.Fatal("preview checkpoint contains a retained Secret")
		}
		objects[key] = o.DeepCopy()
	}
	body, rv, anchor := bytes.Clone(checkpoint.Bytes()), checkpoint.ResourceVersion(), checkpoint.Anchor()
	return func(t *testing.T) *fixtureWireTest {
		t.Helper()
		v := newLifecycleFixturePlans(t, plan)
		if err := v.f.access.client.Tracker().Update(corev1.SchemeGroupVersion.WithResource("namespaces"), ns.DeepCopy(), ""); err != nil {
			t.Fatal(err)
		}
		v.f.access.objects = map[installstate.Key]*unstructured.Unstructured{}
		for key, o := range objects {
			v.f.access.objects[key] = o.DeepCopy()
		}
		s, err := v.f.store.Load(t.Context(), anchor)
		if err != nil || !bytes.Equal(body, s.Bytes()) || rv != s.ResourceVersion() {
			t.Fatal("independent preview checkpoint mismatch", err)
		}
		v.f.snapshot = s
		return newFixtureWireTestAtActor(t, newActorFixtureAtCheckpoint(t, v, s))
	}
}

func fixturePreviewUnchanged(t *testing.T, f *fixtureWireTest) func() {
	t.Helper()
	ledger := f.wire.ledger
	body := bytes.Clone(ledger.body)
	identity, revision, ack, effect := ledger.identity, ledger.document.Revision, ledger.ackSlot, ledger.effectSlot
	entries := append([]fixtureEntry(nil), ledger.document.Entries...)
	return func() {
		t.Helper()
		durable, gotIdentity, err := ledger.engine.files.Read(ledger.name, fixtureLedgerMaxBytes)
		if err != nil || !bytes.Equal(body, ledger.body) || !bytes.Equal(body, durable) || identity != ledger.identity || identity != gotIdentity || revision != ledger.document.Revision || ack != ledger.ackSlot || effect != ledger.effectSlot || !reflect.DeepEqual(entries, ledger.document.Entries) {
			t.Fatal("preview changed protected WAL, ownership or capability")
		}
	}
}

func TestFixtureDryRunCheckpointCopiesRemainIndependent(t *testing.T) {
	newPreview := fixturePreviewFactory(t)
	a, b := newPreview(t), newPreview(t)
	if a.wire.ledger.engine == b.wire.ledger.engine || a.wire.ledger.engine.files == b.wire.ledger.engine.files || a.actor.v.f.access.client == b.actor.v.f.access.client || a.actor.admission == b.actor.admission || a.wire.clients[0] == b.wire.clients[0] {
		t.Fatal("preview children share mutable resources")
	}
	unchanged := fixturePreviewUnchanged(t, b)
	var account installstate.Key
	var originalRV string
	for key, o := range a.actor.v.f.access.objects {
		if key.Kind == "ServiceAccount" {
			account, originalRV = key, o.GetResourceVersion()
			o.SetResourceVersion("999")
			o.Object["automountServiceAccountToken"] = true
			break
		}
	}
	if account.Name == "" || b.actor.v.f.access.objects[account].GetResourceVersion() != originalRV {
		t.Fatal("public checkpoint map is shared")
	}
	ns, err := a.actor.v.f.access.client.CoreV1().Namespaces().Get(t.Context(), a.actor.request.Snapshot.Anchor().Namespace, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ns.ResourceVersion = "999"
	if err := a.actor.v.f.access.client.Tracker().Update(corev1.SchemeGroupVersion.WithResource("namespaces"), ns, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := a.wire.ledger.engine.files.AtomicWrite(a.wire.ledger.name, []byte(`{}`), &a.wire.ledger.identity); err != nil {
		t.Fatal(err)
	}
	if _, err := a.wire.dryRun(t.Context(), 0); err != ErrFixtures {
		t.Fatal("corrupt child was accepted", err)
	}
	if _, err := b.wire.dryRun(t.Context(), 0); err != nil {
		t.Fatal("other child's corruption leaked", err)
	}
	unchanged()
	c := newPreview(t)
	if c.actor.v.f.access.objects[account].GetResourceVersion() != originalRV {
		t.Fatal("seed changed through child mutation")
	}
	if _, err := c.wire.dryRun(t.Context(), 0); err != nil {
		t.Fatal("seed checkpoint was mutated", err)
	}
}

func TestFixtureDryRunFixedSlotsNoOwnershipOrEffectGrant(t *testing.T) {
	f := newFixtureWireTest(t)
	ctx, ledger := t.Context(), f.wire.ledger
	for slot := range fixtureCatalog {
		unchanged := fixturePreviewUnchanged(t, f)
		preview, err := f.wire.dryRun(ctx, slot)
		if err != nil || preview == nil || preview.GetResourceVersion() != "" || !nativeFixtureUID(string(preview.GetUID())) {
			t.Fatal("closed preview refused", slot, err)
		}
		unchanged()
		if _, absent, err := f.wire.get(ctx, slot); err != nil || !absent || f.creates != slot {
			t.Fatal("preview persisted an object", slot, err)
		}
		if _, err := f.wire.create(ctx, slot); err != ErrFixtures {
			t.Fatal("preview granted persistent effect", err)
		}
		previewUID := preview.GetUID()
		preview.SetUID("caller-copy-only")
		fixtureWireAdvance(t, ledger, slot, fixtureCreateAttempted, "")
		if _, err := f.wire.dryRun(ctx, slot); err != ErrFixtures {
			t.Fatal("pending CREATE previewed", err)
		}
		live, err := f.wire.create(ctx, slot)
		if err != nil || live == nil || live.GetUID() == previewUID || ledger.document.Entries[slot].OriginalUID != live.GetUID() {
			t.Fatal("preview UID adopted instead of original ACK", slot, err)
		}
	}
	if f.previews != len(fixtureCatalog) || f.creates != len(fixtureCatalog) || f.deletes != 0 || ledger.engine.fixtureFence(f.actor.request.Snapshot) != ErrFixtures {
		t.Fatal("preview effect count or retirement fence changed")
	}
}

func TestFixtureDryRunRejectsNonOriginalStateBeforeHTTP(t *testing.T) {
	newPreview := fixturePreviewFactory(t)
	for _, scenario := range []string{"owner-unacknowledged", "later-slot", "create-attempted", "original", "delete-attempted", "absent", "other-pending", "other-cleanup", "ack-capability", "effect-capability", "bad-slot", "short-ledger"} {
		t.Run(scenario, func(t *testing.T) {
			f := newPreview(t)
			ledger, slot := f.wire.ledger, 0
			switch scenario {
			case "owner-unacknowledged":
				slot = fixtureBackupPod
			case "later-slot":
				slot = fixturePlainPVC
			case "create-attempted", "original", "delete-attempted", "absent":
				ledger.document.Entries[slot].State = fixtureState(scenario)
			case "other-pending":
				ledger.document.Entries[fixtureRestoreJob].State = fixtureCreateAttempted
			case "other-cleanup":
				ledger.document.Entries[fixturePlainPVC].State = fixtureAbsent
			case "ack-capability":
				ledger.ackSlot = slot
			case "effect-capability":
				ledger.effectSlot = slot
			case "bad-slot":
				slot = len(fixtureCatalog)
			case "short-ledger":
				ledger.document.Entries = nil
			}
			calls := 0
			parent := f.wire.actors.admission.prerequisites.access
			for _, access := range append([]*HTTPAccess{parent}, f.wire.clients[0], f.wire.clients[destroyAdministratorActor], f.wire.clients[destroyControllerActor]) {
				next := access.client.Transport
				access.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) { calls++; return next.RoundTrip(r) })
			}
			if _, err := f.wire.dryRun(t.Context(), slot); err != ErrFixtures || calls != 0 || f.previews != 0 {
				t.Fatal("unsafe preview reached any HTTP", err)
			}
			if _, err := f.wire.request(t.Context(), slot, fixtureDryRunRequest); err != ErrFixtures || calls != 0 {
				t.Fatal("inner preview bypassed state gate", err)
			}
		})
	}
}

func TestFixtureDryRunRefusesRequestTamperingWithoutPersistentFallback(t *testing.T) {
	newPreview := fixturePreviewFactory(t)
	for name, mutate := range map[string]func(*http.Request){
		"dry-run-absent": func(r *http.Request) { r.URL.RawQuery = "fieldManager=arcadectl-installer&fieldValidation=Strict" },
		"dry-run-empty": func(r *http.Request) {
			r.URL.RawQuery = "dryRun=&fieldManager=arcadectl-installer&fieldValidation=Strict"
		},
		"dry-run-other": func(r *http.Request) {
			r.URL.RawQuery = "dryRun=Other&fieldManager=arcadectl-installer&fieldValidation=Strict"
		},
		"dry-run-duplicate": func(r *http.Request) { r.URL.RawQuery += "&dryRun=All" },
		"manager":           func(r *http.Request) { r.URL.RawQuery = "dryRun=All&fieldManager=foreign&fieldValidation=Strict" },
		"validation": func(r *http.Request) {
			r.URL.RawQuery = "dryRun=All&fieldManager=arcadectl-installer&fieldValidation=Ignore"
		},
		"method":      func(r *http.Request) { r.Method = http.MethodGet },
		"route":       func(r *http.Request) { r.URL.Path += "/status" },
		"actor":       func(r *http.Request) { r.Header.Set("Impersonate-User", "system:masters") },
		"auth":        func(r *http.Request) { r.Header.Set("Authorization", "Bearer FOREIGN-CANARY") },
		"body":        func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader(`{}`)); r.ContentLength = 2 },
		"idempotency": func(r *http.Request) { r.Header["Idempotency-Key"] = []string{} },
		"get-body": func(r *http.Request) {
			r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(`{}`)), nil }
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newPreview(t)
			unchanged := fixturePreviewUnchanged(t, f)
			a := f.wire.clients[0]
			next := a.client.Transport
			a.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) { mutate(r); return next.RoundTrip(r) })
			if _, err := f.wire.dryRun(t.Context(), 0); err != ErrFixtures || f.previews != 0 || f.creates != 0 {
				t.Fatal("tampered preview reached wire or fell back", err)
			}
			unchanged()
		})
	}
}

func TestFixtureDryRunDurablePendingAndCleanupRemainFencedAfterReload(t *testing.T) {
	newPreview := fixturePreviewFactory(t)
	for _, scenario := range []string{"create-intent", "unknown-create", "delete-intent", "absent"} {
		t.Run(scenario, func(t *testing.T) {
			f := newPreview(t)
			ledger := f.wire.ledger
			fixtureWireAdvance(t, ledger, 0, fixtureCreateAttempted, "")
			if scenario == "unknown-create" {
				f.reply = func(w http.ResponseWriter, o *unstructured.Unstructured) {
					w.WriteHeader(201)
					_, _ = io.WriteString(w, `{"message":"PRIVATE-LOST-CANARY"}`)
				}
				if _, err := f.wire.create(t.Context(), 0); err != ErrOutcomeUnknown {
					t.Fatal("test unknown CREATE unavailable", err)
				}
			} else if scenario != "create-intent" {
				if _, err := f.wire.create(t.Context(), 0); err != nil {
					t.Fatal(err)
				}
				if _, absent, err := f.wire.get(t.Context(), 1); err != nil || !absent {
					t.Fatal("uncreated child absence unavailable", err)
				}
				fixtureWireAdvance(t, ledger, 1, fixtureAbsent, "")
				fixtureWireAdvance(t, ledger, 0, fixtureDeleteAttempted, "101")
				if scenario == "absent" {
					if err := f.wire.delete(t.Context(), 0); err != nil {
						t.Fatal(err)
					}
					if _, absent, err := f.wire.get(t.Context(), 0); err != nil || !absent {
						t.Fatal("original absence unavailable", err)
					}
					fixtureWireAdvance(t, ledger, 0, fixtureAbsent, "101")
				}
			}
			unchanged := fixturePreviewUnchanged(t, f)
			for _, slot := range []int{0, fixtureRestoreJob} {
				if _, err := f.wire.dryRun(t.Context(), slot); err != ErrFixtures || f.previews != 0 {
					t.Fatal("durable pending/cleanup previewed", err)
				}
			}
			unchanged()
			if err := ledger.close(); err != nil {
				t.Fatal(err)
			}
			loaded, err := ledger.engine.loadFixtureLedger(t.Context(), f.actor.request.Snapshot)
			if err != nil {
				t.Fatal(err)
			}
			defer loaded.close()
			wire, err := f.wire.actors.fixtures(t.Context(), loaded)
			if err != nil {
				t.Fatal(err)
			}
			f.wire = wire
			unchanged = fixturePreviewUnchanged(t, f)
			if loaded.ackSlot != -1 || loaded.effectSlot != -1 {
				t.Fatal("load restored effect capability")
			}
			for _, slot := range []int{0, fixtureRestoreJob} {
				if _, err := wire.dryRun(t.Context(), slot); err != ErrFixtures || f.previews != 0 {
					t.Fatal("reloaded uncertainty/cleanup previewed", err)
				}
			}
			unchanged()
		})
	}
}

func TestFixtureDryRunWholeReplyRefusalLeavesOriginalLedger(t *testing.T) {
	newPreview := fixturePreviewFactory(t)
	for _, scenario := range []string{"spec", "owner", "status", "rv", "uid", "duplicate", "trailing", "mime", "oversize", "lost", "wrong-status"} {
		t.Run(scenario, func(t *testing.T) {
			f := newPreview(t)
			unchanged := fixturePreviewUnchanged(t, f)
			f.reply = func(w http.ResponseWriter, o *unstructured.Unstructured) {
				status := 201
				switch scenario {
				case "spec":
					o.Object["spec"] = map[string]any{"foreign": "PRIVATE-SPEC-CANARY"}
				case "owner":
					o.Object["metadata"].(map[string]any)["ownerReferences"] = []any{}
				case "status":
					o.Object["status"] = map[string]any{"active": int64(1)}
				case "rv":
					o.SetResourceVersion("101")
				case "uid":
					o.SetUID("not-native")
				case "mime":
					w.Header().Set("Content-Type", "text/plain")
				case "wrong-status":
					status = 200
				}
				body, _ := json.Marshal(o.Object)
				switch scenario {
				case "duplicate":
					body = append([]byte(`{"metadata":{},`), body[1:]...)
				case "trailing":
					body = append(body, []byte(` {}`)...)
				case "oversize":
					body = bytes.Repeat([]byte(" "), 1024*1024+1)
				case "lost":
					body = []byte(`{"message":"PRIVATE-LOST-CANARY"}`)
				}
				w.WriteHeader(status)
				_, _ = w.Write(body)
			}
			if o, err := f.wire.dryRun(t.Context(), 0); err != ErrFixtures || o != nil || f.previews != 1 || f.creates != 0 {
				t.Fatal("unproved reply accepted or retried", err)
			}
			unchanged()
		})
	}
}

func TestFixtureDryRunRefusesPostWitnessAndAuthorizationDrift(t *testing.T) {
	newPreview := fixturePreviewFactory(t)
	for _, scenario := range []string{"post-account", "post-policy", "post-journal", "post-wal", "pre-review-account", "deny-admin", "deny-actor"} {
		t.Run(scenario, func(t *testing.T) {
			f := newPreview(t)
			unchanged := fixturePreviewUnchanged(t, f)
			mutateWitness := func(kind string) {
				for key, o := range f.actor.v.f.access.objects {
					if key.Kind == kind {
						o.SetResourceVersion("999")
						return
					}
				}
				t.Error("witness fixture unavailable")
			}
			slot, expected := 0, 1
			switch scenario {
			case "post-account":
				f.afterPreview = func() { mutateWitness("ServiceAccount") }
			case "post-policy":
				f.afterPreview = func() { mutateWitness("ValidatingAdmissionPolicy") }
			case "post-journal":
				originalHandler := f.actor.fixtureHandler
				f.actor.fixtureHandler = func(w http.ResponseWriter, r *http.Request) bool {
					if r.Method == http.MethodGet && r.URL.Path == "/api/v1/namespaces/"+f.actor.request.Snapshot.Anchor().Namespace {
						ns, err := f.actor.v.f.access.client.CoreV1().Namespaces().Get(r.Context(), f.actor.request.Snapshot.Anchor().Namespace, metav1.GetOptions{})
						if err != nil {
							t.Error(err)
							w.WriteHeader(500)
							return true
						}
						ns.APIVersion, ns.Kind = "v1", "Namespace"
						_ = json.NewEncoder(w).Encode(ns)
						return true
					}
					return originalHandler(w, r)
				}
				f.afterPreview = func() {
					ns, err := f.actor.v.f.access.client.CoreV1().Namespaces().Get(t.Context(), f.actor.request.Snapshot.Anchor().Namespace, metav1.GetOptions{})
					if err != nil {
						t.Error(err)
						return
					}
					ns.ResourceVersion = "999"
					if err := f.actor.v.f.access.client.Tracker().Update(corev1.SchemeGroupVersion.WithResource("namespaces"), ns, ""); err != nil {
						t.Error(err)
					}
				}
			case "post-wal":
				f.afterPreview = func() {
					ledger := f.wire.ledger
					if _, err := ledger.engine.files.CreateExclusive(ledger.name, []byte(`{}`)); !errors.Is(err, privatefs.ErrExists) {
						t.Error("protected WAL unexpectedly overwritten", err)
					}
					// The in-memory original identity cannot be replaced by a body.
					ledger.identity = privatefs.FileIdentity{}
				}
			case "pre-review-account":
				f.actor.afterReview = func() { mutateWitness("ServiceAccount") }
				expected = 0
			case "deny-admin":
				f.actor.denyAdmin = true
				expected = 0
			case "deny-actor":
				for i := 0; i < fixtureCancelledDestroy; i++ {
					fixtureWireAdvance(t, f.wire.ledger, i, fixtureCreateAttempted, "")
					if _, err := f.wire.create(t.Context(), i); err != nil {
						t.Fatal(err)
					}
				}
				slot = fixtureCancelledDestroy
				unchanged = fixturePreviewUnchanged(t, f)
				f.actor.denyActor = true
				expected = 0
			}
			originalIdentity := f.wire.ledger.identity
			if o, err := f.wire.dryRun(t.Context(), slot); err != ErrFixtures || o != nil || f.previews != expected {
				t.Fatal("drift or denial accepted", err)
			}
			if scenario == "post-wal" {
				f.wire.ledger.identity = originalIdentity
			}
			unchanged()
		})
	}
}

func TestFixtureDryRunRefusesProtectedFileReplacementWithoutRepair(t *testing.T) {
	newPreview := fixturePreviewFactory(t)
	for _, content := range []string{"same", "changed"} {
		t.Run(content, func(t *testing.T) {
			f := newPreview(t)
			ledger := f.wire.ledger
			body, identity, revision := bytes.Clone(ledger.body), ledger.identity, ledger.document.Revision
			replacement := body
			if content == "changed" {
				replacement = []byte(`{}`)
			}
			var replaced privatefs.FileIdentity
			f.afterPreview = func() {
				var err error
				replaced, err = ledger.engine.files.AtomicWrite(ledger.name, replacement, &identity)
				if err != nil {
					t.Error("test-owned protected replacement unavailable", err)
				}
			}
			if o, err := f.wire.dryRun(t.Context(), 0); err != ErrFixtures || o != nil || f.previews != 1 || f.creates != 0 {
				t.Fatal("changed protected file accepted", err)
			}
			durable, actual, err := ledger.engine.files.Read(ledger.name, fixtureLedgerMaxBytes)
			if err != nil || !bytes.Equal(durable, replacement) || actual != replaced || actual == identity || ledger.identity != identity || !bytes.Equal(ledger.body, body) || ledger.document.Revision != revision || ledger.ackSlot != -1 || ledger.effectSlot != -1 || ledger.document.Entries[0].OriginalUID != "" {
				t.Fatal("preview adopted/repaired/replaced external file evidence")
			}
		})
	}
}

func TestFixtureDryRunNoRedirectReplayOrWrapperReplacement(t *testing.T) {
	newPreview := fixturePreviewFactory(t)
	for _, scenario := range []string{"redirect", "429", "503", "outer-error", "outer-body", "replay"} {
		t.Run(scenario, func(t *testing.T) {
			f := newPreview(t)
			unchanged := fixturePreviewUnchanged(t, f)
			if scenario == "redirect" || scenario == "429" || scenario == "503" {
				f.reply = func(w http.ResponseWriter, o *unstructured.Unstructured) {
					status := 302
					if scenario == "429" {
						status = 429
					}
					if scenario == "503" {
						status = 503
					}
					w.Header().Set("Location", "/PRIVATE-REDIRECT-CANARY")
					w.Header().Set("Trailer", "X-Private-Trailer")
					w.WriteHeader(status)
					_, _ = io.WriteString(w, `{"message":"PRIVATE-REPLY-CANARY"}`)
					w.Header().Set("X-Private-Trailer", "PRIVATE-TRAILER-CANARY")
				}
			}
			a := f.wire.clients[0]
			next := a.client.Transport
			a.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				response, err := next.RoundTrip(r)
				if response != nil {
					body, _ := io.ReadAll(response.Body)
					_ = response.Body.Close()
					if string(body) != "{}" || strings.Contains(fmt.Sprint(response.Header, response.Trailer, response.Status), "PRIVATE-") {
						t.Error("native preview reply leaked below wrapper")
					}
					response.Body = io.NopCloser(bytes.NewReader(body))
				}
				switch scenario {
				case "outer-error":
					return nil, errors.New("PRIVATE-WRAPPER-CANARY")
				case "outer-body":
					if response != nil {
						response.Body = io.NopCloser(strings.NewReader(`{"metadata":{"uid":"not-native"}}`))
					}
				case "replay":
					second, retryErr := next.RoundTrip(r)
					if second != nil && second.Body != nil {
						_ = second.Body.Close()
					}
					if retryErr == nil {
						t.Error("same preview attempt replayed")
					}
				}
				return response, err
			})
			o, err := f.wire.dryRun(t.Context(), 0)
			if scenario == "outer-body" || scenario == "replay" {
				if err != nil || o == nil || !nativeFixtureUID(string(o.GetUID())) {
					t.Fatal("wrapper replaced native shape", err)
				}
			} else if err != ErrFixtures || o != nil {
				t.Fatal("ambiguous/failed preview accepted", err)
			}
			if f.previews != 1 || f.creates != 0 {
				t.Fatal("preview retried or persisted")
			}
			unchanged()
		})
	}
}

func TestFixtureDryRunInvalidReceiverAndContext(t *testing.T) {
	var missing *fixtureWire
	for _, w := range []*fixtureWire{missing, {}, {ledger: &fixtureLedger{}}} {
		if _, err := w.dryRun(context.Background(), 0); err != ErrFixtures {
			t.Fatal("invalid preview receiver accepted", err)
		}
	}
	f := newFixtureWireTest(t)
	if _, err := f.wire.dryRun(nil, 0); err != ErrFixtures || f.previews != 0 {
		t.Fatal("nil context previewed", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	unchanged := fixturePreviewUnchanged(t, f)
	if _, err := f.wire.dryRun(ctx, 0); err != ErrFixtures || f.previews != 0 {
		t.Fatal("cancelled context previewed", err)
	}
	unchanged()
}
