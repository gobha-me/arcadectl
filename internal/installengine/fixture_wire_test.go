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
	"time"

	authv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
)

// Fake transport observations exercise only the private, ledger-bound seam.
// They are NOT whole-shape certification, native admission or fixture permission.
type fixtureWireTest struct {
	actor                   *actorFixture
	wire                    *fixtureWire
	objects                 map[int]*unstructured.Unstructured
	creates, deletes, reads int
	previews                int
	reply                   func(http.ResponseWriter, *unstructured.Unstructured)
	deleteReply             func(http.ResponseWriter)
	afterEffect             func()
	afterPreview            func()
	seeds                   int
	seedReply               func(http.ResponseWriter, *unstructured.Unstructured)
	afterSeed               func()
	denySeed                bool
	missingSeedDiscovery    bool
}

func newFixtureWireTest(t *testing.T) *fixtureWireTest {
	t.Helper()
	return newFixtureWireTestAtActor(t, newActorFixture(t))
}

func newFixtureWireTestAtActor(t *testing.T, a *actorFixture) *fixtureWireTest {
	t.Helper()
	actors, err := a.admission.newActors(context.Background(), a.request, existingScopedImpersonation)
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := a.admission.prerequisites.engine.prepareFixtureLedger(context.Background(), a.request.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if ledger.lock != nil {
			_ = ledger.close()
		}
	})
	f := &fixtureWireTest{actor: a, objects: map[int]*unstructured.Unstructured{}}
	a.fixtureHandler = func(w http.ResponseWriter, r *http.Request) bool {
		if strings.Contains(r.URL.Path, "PRIVATE-REDIRECT-CANARY") {
			t.Error("redirect reached another address")
			w.WriteHeader(500)
			return true
		}
		for _, gv := range []string{"v1", "batch/v1", "arcade.gobha.me/v1alpha1"} {
			path := "/apis/" + gv
			if gv == "v1" {
				path = "/api/v1"
			}
			if r.Method == http.MethodGet && r.URL.Path == path {
				resources := []metav1.APIResource{}
				seen := map[string]bool{}
				for _, entry := range ledger.document.Entries {
					if entry.Key.APIVersion != gv {
						continue
					}
					_, plural, _ := fixturePath(entry.Key, true)
					if !seen[plural] {
						resources = append(resources, metav1.APIResource{Name: plural, Kind: entry.Key.Kind, Namespaced: true, Verbs: metav1.Verbs{"get", "list", "create", "delete"}})
						seen[plural] = true
					}
				}
				// Actor construction still uses the baseline discovery before this hook.
				if gv == "arcade.gobha.me/v1alpha1" && !f.missingSeedDiscovery {
					resources = append(resources, metav1.APIResource{Name: "gamedestroys/status", Kind: "GameDestroy", Namespaced: true, Verbs: metav1.Verbs{"update"}})
				}
				_ = json.NewEncoder(w).Encode(metav1.APIResourceList{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "APIResourceList"}, GroupVersion: gv, APIResources: resources})
				return true
			}
		}
		if r.URL.Path == "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" {
			var review authv1.SelfSubjectAccessReview
			if json.NewDecoder(r.Body).Decode(&review) != nil {
				t.Error("bad fixture review")
				w.WriteHeader(500)
				return true
			}
			valid := false
			for slot, entry := range ledger.document.Entries {
				for _, verb := range []string{"get", "create", "delete"} {
					permission, _ := fixturePermission(entry.Key, verb)
					username := ""
					if actor := fixtureActor(slot, verb); actor != 0 {
						username = "system:serviceaccount:" + entry.Key.Namespace + ":" + actor.account()
					}
					if reflect.DeepEqual(permission.spec, review.Spec) && r.Header.Get("Impersonate-User") == username {
						valid = true
					}
				}
			}
			seedPermission := fixtureDestroySeedPermission(ledger.document.Entries[fixtureCancelledDestroy].Key.Namespace, ledger.document.Entries[fixtureCancelledDestroy].Key.Name)
			isSeed := reflect.DeepEqual(seedPermission.spec, review.Spec) && r.Header.Get("Impersonate-User") == ""
			valid = valid || isSeed
			if r.Method != http.MethodPost || !valid || r.URL.RawQuery != "fieldManager=arcadectl-installer&fieldValidation=Strict" {
				t.Error("fixture review escaped fixed identity/route")
			}
			review.Status.Allowed = valid && !a.denyAdmin && !a.denyActor && !(isSeed && f.denySeed)
			_ = json.NewEncoder(w).Encode(review)
			if a.afterReview != nil {
				a.afterReview()
			}
			return true
		}
		seedKey := ledger.document.Entries[fixtureCancelledDestroy].Key
		seedPath, _, _ := fixturePath(seedKey, false)
		if r.URL.Path == seedPath+"/status" {
			if r.Method != http.MethodPut || r.Header.Get("Impersonate-User") != "" || r.URL.RawQuery != "fieldManager=arcadectl-installer&fieldValidation=Strict" {
				t.Error("seed escaped fixed admin/status route/query")
			}
			f.seeds++
			var got unstructured.Unstructured
			want, _ := ledger.object(fixtureCancelledDestroy)
			want.SetUID(ledger.document.Entries[fixtureCancelledDestroy].OriginalUID)
			want.SetResourceVersion(ledger.document.DestroySeed.BeforeResourceVersion)
			want.Object["status"], _ = ledger.destroySeedStatus()
			if json.NewDecoder(r.Body).Decode(&got.Object) != nil || !reflect.DeepEqual(got.Object, want.Object) || ledger.document.DestroySeed.State != fixtureDestroySeedAttempted || ledger.seedEffect || !ledger.seedAck {
				t.Error("seed lost original deterministic body/durable intent/send consumption")
			}
			object := f.objects[fixtureCancelledDestroy].DeepCopy()
			object.Object["status"], _ = ledger.destroySeedStatus()
			object.SetResourceVersion("102")
			fields := object.Object["metadata"].(map[string]any)["managedFields"].([]any)
			object.Object["metadata"].(map[string]any)["managedFields"] = append(fields, map[string]any{"manager": "arcadectl-installer", "operation": "Update", "apiVersion": object.GetAPIVersion(), "fieldsType": "FieldsV1", "fieldsV1": fixtureDestroySeedFieldset(), "time": time.Now().UTC().Truncate(time.Second).Format(time.RFC3339), "subresource": "status"})
			f.objects[fixtureCancelledDestroy] = object.DeepCopy()
			if f.afterSeed != nil {
				f.afterSeed()
			}
			w.Header().Set("X-Private-Canary", "PRIVATE-SEED-HEADER")
			if f.seedReply != nil {
				f.seedReply(w, object)
			} else {
				_ = json.NewEncoder(w).Encode(object.Object)
			}
			return true
		}
		for slot, entry := range ledger.document.Entries {
			path, _, _ := fixturePath(entry.Key, r.Method == http.MethodPost)
			if r.URL.Path != path {
				continue
			}
			// Collections repeat across slots; select CREATE by its fixed body name.
			var object unstructured.Unstructured
			if r.Method == http.MethodPost {
				body, _ := io.ReadAll(r.Body)
				r.Body = io.NopCloser(bytes.NewReader(body))
				if json.Unmarshal(body, &object.Object) != nil || object.GetName() != entry.Key.Name {
					continue
				}
			}
			verb := map[string]string{http.MethodGet: "get", http.MethodPost: "create", http.MethodDelete: "delete"}[r.Method]
			username := ""
			if actor := fixtureActor(slot, verb); actor != 0 {
				username = "system:serviceaccount:" + entry.Key.Namespace + ":" + actor.account()
			}
			if r.Header.Get("Impersonate-User") != username {
				t.Error("fixture used wrong software identity")
			}
			preview := r.Method == http.MethodPost && r.URL.RawQuery == "dryRun=All&fieldManager=arcadectl-installer&fieldValidation=Strict"
			if r.Method != http.MethodPost && r.URL.RawQuery != "" || r.Method == http.MethodPost && !preview && r.URL.RawQuery != "fieldManager=arcadectl-installer&fieldValidation=Strict" {
				t.Error("fixture query escaped fixed bounds")
			}
			switch r.Method {
			case http.MethodPost:
				w.Header().Set("X-Private-Canary", "PRIVATE-HEADER-CANARY")
				body, identity, err := ledger.engine.files.Read(ledger.name, fixtureLedgerMaxBytes)
				if err != nil || identity != ledger.identity || !bytes.Equal(body, ledger.body) {
					t.Error("wire used unproved original WAL")
				}
				want, err := ledger.object(slot)
				wantBody, _ := json.Marshal(want.Object)
				gotBody, _ := json.Marshal(object.Object)
				if err != nil || !bytes.Equal(wantBody, gotBody) {
					t.Error("caller recipe reached wire")
				}
				if preview {
					f.previews++
					if !ledger.dryRunReady(slot) {
						t.Error("preview escaped Planned/no-pending state")
					}
					object = *fixtureResultExample(t, ledger, slot, fixtureDryRunResult, time.Now().UTC().Truncate(time.Second).Add(-3*time.Second))
					if f.afterPreview != nil {
						f.afterPreview()
					}
					if f.reply != nil {
						f.reply(w, &object)
					} else {
						w.WriteHeader(201)
						_ = json.NewEncoder(w).Encode(object.Object)
					}
					return true // no persistent object, WAL or send capability
				}
				f.creates++
				if entry.State != fixtureCreateAttempted || ledger.effectSlot != -1 {
					t.Error("wire preceded durable CREATE intent/capability consumption")
				}
				object.SetUID(types.UID(fmt.Sprintf("10000000-0000-4000-8000-%012d", slot+1)))
				object.SetResourceVersion("101")
				f.objects[slot] = object.DeepCopy()
				if f.afterEffect != nil {
					f.afterEffect()
				}
				if f.reply != nil {
					f.reply(w, &object)
				} else {
					w.WriteHeader(201)
					_ = json.NewEncoder(w).Encode(object.Object)
				}
			case http.MethodGet:
				f.reads++
				if o := f.objects[slot]; o != nil {
					_ = json.NewEncoder(w).Encode(o.Object)
				} else {
					w.WriteHeader(404)
					_, _ = io.WriteString(w, `{"message":"PRIVATE-404-CANARY"}`)
				}
			case http.MethodDelete:
				f.deletes++
				var options metav1.DeleteOptions
				if json.NewDecoder(r.Body).Decode(&options) != nil || options.Preconditions == nil || options.Preconditions.UID == nil || options.Preconditions.ResourceVersion == nil || *options.Preconditions.UID != entry.OriginalUID || *options.Preconditions.ResourceVersion != entry.DeleteResourceVersion || len(options.DryRun) != 0 || entry.State != fixtureDeleteAttempted || ledger.effectSlot != -1 {
					t.Error("DELETE lost durable original UID/RV intent")
				}
				if options.PropagationPolicy == nil || entry.Key.Kind == "Job" && *options.PropagationPolicy != metav1.DeletePropagationForeground || entry.Key.Kind != "Job" && *options.PropagationPolicy != metav1.DeletePropagationBackground {
					t.Error("unexpected cleanup propagation")
				}
				delete(f.objects, slot)
				if f.afterEffect != nil {
					f.afterEffect()
				}
				if f.deleteReply != nil {
					f.deleteReply(w)
				} else {
					w.WriteHeader(202)
					_, _ = io.WriteString(w, `{"message":"PRIVATE-DELETE-CANARY"}`)
				}
			default:
				t.Error("unexpected fixture method")
				w.WriteHeader(500)
			}
			return true
		}
		return false
	}
	f.wire, err = actors.fixtures(context.Background(), ledger)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func fixtureWireAdvance(t *testing.T, ledger *fixtureLedger, slot int, state fixtureState, rv string) {
	t.Helper()
	next, err := ledger.nextDocument()
	if err != nil {
		t.Fatal(err)
	}
	next.Entries[slot].State, next.Entries[slot].DeleteResourceVersion = state, rv
	if err := ledger.advance(next); err != nil {
		t.Fatal(err)
	}
}

func TestFixtureWireDurableIdentityFixedActorsAndCleanup(t *testing.T) {
	f := newFixtureWireTest(t)
	ctx := context.Background()
	ledger := f.wire.ledger
	for slot := range fixtureCatalog {
		if _, missing, err := f.wire.get(ctx, slot); err != nil || !missing {
			t.Fatal("fixed-address absence", err)
		}
		fixtureWireAdvance(t, ledger, slot, fixtureCreateAttempted, "")
		o, err := f.wire.create(ctx, slot)
		if err != nil || o == nil || ledger.document.Entries[slot].OriginalUID != o.GetUID() || ledger.document.Entries[slot].State != fixtureOriginal {
			t.Fatal("reliable ACK not durably pinned", err)
		}
		if _, err := f.wire.create(ctx, slot); err != ErrFixtures {
			t.Fatal("CREATE replay", err)
		}
		live, absent, err := f.wire.get(ctx, slot)
		if err != nil || absent || live.GetUID() != o.GetUID() {
			t.Fatal("original GET", err)
		}
		live.SetUID("caller-mutated-copy")
		if f.objects[slot].GetUID() != o.GetUID() {
			t.Fatal("live reply alias")
		}
	}
	for _, slot := range []int{1, 0, 3, 2, 5, 4, 6, 7, 8, 9} {
		fixtureWireAdvance(t, ledger, slot, fixtureDeleteAttempted, "101")
		if err := f.wire.delete(ctx, slot); err != nil {
			t.Fatal("original DELETE", err)
		}
		if ledger.document.Entries[slot].State != fixtureDeleteAttempted {
			t.Fatal("DELETE ACK counted as absence")
		}
		rebuilt, err := f.wire.actors.fixtures(ctx, ledger)
		if err != nil || rebuilt.delete(ctx, slot) != ErrFixtures {
			t.Fatal("rebuilt client replayed DELETE", err)
		}
		if _, absent, err := f.wire.get(ctx, slot); err != nil || !absent {
			t.Fatal("actual absence", err)
		}
		fixtureWireAdvance(t, ledger, slot, fixtureAbsent, "101")
	}
	if f.creates != 10 || f.deletes != 10 || ledger.engine.fixtureFence(f.actor.request.Snapshot) != ErrFixtures {
		t.Fatal("effect count or unresolved retirement fence")
	}
}

func TestFixtureWireKnownAckPrecedesPostWitnessAndWrapperErrors(t *testing.T) {
	for _, scenario := range []string{"post-witness", "outer-error", "outer-fake-uid", "whole-shape-not-accepted"} {
		t.Run(scenario, func(t *testing.T) {
			f := newFixtureWireTest(t)
			ledger := f.wire.ledger
			fixtureWireAdvance(t, ledger, 0, fixtureCreateAttempted, "")
			switch scenario {
			case "post-witness":
				f.afterEffect = func() {
					for key, object := range f.actor.v.f.access.objects {
						if key.Kind == "ServiceAccount" {
							object.SetResourceVersion("999")
							break
						}
					}
				}
			case "outer-error", "outer-fake-uid":
				a := f.wire.clients[0]
				next := a.client.Transport
				a.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
					response, err := next.RoundTrip(r)
					if err != nil {
						return response, err
					}
					body, _ := io.ReadAll(response.Body)
					_ = response.Body.Close()
					if string(body) != "{}" {
						t.Error("native response escaped inner capture")
					}
					for _, value := range []string{response.Status, fmt.Sprint(response.Header), fmt.Sprint(response.Trailer)} {
						if strings.Contains(value, "PRIVATE-") {
							t.Error("native response metadata escaped inner capture")
						}
					}
					if scenario == "outer-error" {
						return nil, errors.New("PRIVATE-WRAPPER-CANARY")
					}
					response.Body = io.NopCloser(strings.NewReader(`{"metadata":{"uid":"20000000-0000-4000-8000-000000000001"}}`))
					return response, nil
				})
			case "whole-shape-not-accepted":
				f.reply = func(w http.ResponseWriter, o *unstructured.Unstructured) {
					o.Object["spec"] = map[string]any{"unexpected": "not-accepted"}
					w.WriteHeader(201)
					_ = json.NewEncoder(w).Encode(o.Object)
				}
			}
			o, err := f.wire.create(context.Background(), 0)
			want := types.UID("10000000-0000-4000-8000-000000000001")
			if f.creates != 1 || ledger.document.Entries[0].OriginalUID != want || ledger.document.Entries[0].State != fixtureOriginal {
				t.Fatal("reliable native ACK lost before later refusal", err)
			}
			if scenario == "post-witness" || scenario == "outer-error" {
				if err != ErrFixtures || o != nil {
					t.Fatal("post-ACK refusal not static", err)
				}
			} else if err != nil || o.GetUID() != want {
				t.Fatal("outer response replaced trusted ACK", err)
			}
		})
	}
}

func TestFixtureWireUnknownCreateNeverAdoptsOrReplays(t *testing.T) {
	for _, scenario := range []string{"lost", "status", "duplicate", "trailing", "uid", "namespace", "kind", "mime", "oversize"} {
		t.Run(scenario, func(t *testing.T) {
			f := newFixtureWireTest(t)
			ledger := f.wire.ledger
			f.reply = func(w http.ResponseWriter, o *unstructured.Unstructured) {
				body, _ := json.Marshal(o.Object)
				status := 201
				switch scenario {
				case "lost":
					body = []byte(`{"message":"PRIVATE-LOST-CANARY"}`)
				case "status":
					status = 200
				case "duplicate":
					body = append([]byte(`{"metadata":{},`), body[1:]...)
				case "trailing":
					body = append(body, []byte(` {}`)...)
				case "uid":
					o.SetUID("non-native-uid")
					body, _ = json.Marshal(o.Object)
				case "namespace":
					o.SetNamespace("foreign")
					body, _ = json.Marshal(o.Object)
				case "kind":
					o.SetKind("Secret")
					body, _ = json.Marshal(o.Object)
				case "mime":
					w.Header().Set("Content-Type", "text/plain")
				case "oversize":
					body = bytes.Repeat([]byte(" "), 1024*1024+1)
				}
				w.WriteHeader(status)
				_, _ = w.Write(body)
			}
			fixtureWireAdvance(t, ledger, 0, fixtureCreateAttempted, "")
			if _, err := f.wire.create(context.Background(), 0); err != ErrOutcomeUnknown {
				t.Fatal("unknown ACK accepted", err)
			}
			if _, missing, err := f.wire.get(context.Background(), 0); err != nil || missing {
				t.Fatal("later GET observation refused", err)
			}
			if ledger.document.Entries[0].OriginalUID != "" || ledger.ackSlot != -1 {
				t.Fatal("later GET adopted unknown UID")
			}
			next, _ := ledger.nextDocument()
			next.Entries[0].State, next.Entries[0].OriginalUID = fixtureOriginal, f.objects[0].GetUID()
			if ledger.advance(next) != ErrFixtures {
				t.Fatal("unknown ACK adopted in same instance")
			}
			rebuilt, err := f.wire.actors.fixtures(context.Background(), ledger)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := rebuilt.create(context.Background(), 0); err != ErrFixtures {
				t.Fatal("rebuilt client replayed", err)
			}
			for _, slot := range []int{0, fixtureRestoreJob} {
				if _, err := rebuilt.dryRun(t.Context(), slot); err != ErrFixtures || f.previews != 0 {
					t.Fatal("preview bypassed unknown CREATE", err)
				}
			}
			if err := ledger.close(); err != nil {
				t.Fatal(err)
			}
			loaded, err := ledger.engine.loadFixtureLedger(context.Background(), f.actor.request.Snapshot)
			if err != nil {
				t.Fatal(err)
			}
			defer loaded.close()
			restarted, err := f.wire.actors.fixtures(context.Background(), loaded)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := restarted.create(context.Background(), 0); err != ErrFixtures || f.creates != 1 {
				t.Fatal("restart replayed", err)
			}
			if _, err := restarted.dryRun(t.Context(), fixtureRestoreJob); err != ErrFixtures || f.previews != 0 {
				t.Fatal("reloaded unknown CREATE previewed", err)
			}
		})
	}
}

func TestFixtureWireRejectsRequestTamperingAndGenericAccess(t *testing.T) {
	for name, mutate := range map[string]func(*http.Request){
		"auth":              func(r *http.Request) { r.Header.Set("Authorization", "Bearer FOREIGN-CANARY") },
		"auth-alias":        func(r *http.Request) { r.Header["authorization"] = []string{"Bearer FAKE-ADMIN-CANARY"} },
		"groups":            func(r *http.Request) { r.Header["Impersonate-Group"] = nil },
		"user":              func(r *http.Request) { r.Header.Set("Impersonate-User", "system:masters") },
		"idempotency":       func(r *http.Request) { r.Header["Idempotency-Key"] = []string{} },
		"idempotency-alias": func(r *http.Request) { r.Header["x-idempotency-key"] = []string{"replay"} },
		"method":            func(r *http.Request) { r.Method = http.MethodGet },
		"route":             func(r *http.Request) { r.URL.Path += "/status" },
		"host":              func(r *http.Request) { r.Host = "foreign" },
		"query":             func(r *http.Request) { r.URL.RawQuery += "&dryRun=All" },
		"body":              func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader(`{}`)); r.ContentLength = 2 },
		"get-body": func(r *http.Request) {
			r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(`{}`)), nil }
		},
		"accept-alias":   func(r *http.Request) { r.Header["accept"] = []string{"text/plain"} },
		"mime-duplicate": func(r *http.Request) { r.Header["Content-Type"] = []string{"application/json", "text/plain"} },
		"context":        func(r *http.Request) { *r = *r.WithContext(context.Background()) },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixtureWireTest(t)
			fixtureWireAdvance(t, f.wire.ledger, 0, fixtureCreateAttempted, "")
			a := f.wire.clients[0]
			next := a.client.Transport
			a.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) { mutate(r); return next.RoundTrip(r) })
			if _, err := f.wire.create(context.Background(), 0); err != ErrOutcomeUnknown || f.creates != 0 || f.wire.ledger.document.Entries[0].OriginalUID != "" {
				t.Fatal("tampered request reached wire or was trusted", err)
			}
		})
	}
	f := newFixtureWireTest(t)
	key := f.wire.ledger.document.Entries[0].Key
	o, _ := f.wire.ledger.object(0)
	for _, a := range f.wire.clients {
		if _, err := a.Get(context.Background(), key); err == nil {
			t.Fatal("private fixture client used as general reader")
		}
		if _, err := a.Create(context.Background(), key, o, false); err == nil {
			t.Fatal("private fixture client used as arbitrary mutation access")
		}
	}
	if f.creates != 0 || f.reads != 0 {
		t.Fatal("generic Access reached fixture route")
	}
}

func TestFixtureWireUnknownDeleteCannotReplayAcrossClientsOrRestart(t *testing.T) {
	for _, scenario := range []string{"lost-response", "outer-error", "post-witness"} {
		t.Run(scenario, func(t *testing.T) {
			f := newFixtureWireTest(t)
			ctx, ledger := context.Background(), f.wire.ledger
			fixtureWireAdvance(t, ledger, 0, fixtureCreateAttempted, "")
			if _, err := f.wire.create(ctx, 0); err != nil {
				t.Fatal(err)
			}
			fixtureWireAdvance(t, ledger, 1, fixtureAbsent, "") // exact fake address is absent; no effect
			fixtureWireAdvance(t, ledger, 0, fixtureDeleteAttempted, "101")
			var restore func()
			switch scenario {
			case "lost-response":
				f.deleteReply = func(w http.ResponseWriter) {
					connection, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					_ = connection.Close()
				}
			case "outer-error":
				a := f.wire.clients[0]
				next := a.client.Transport
				a.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
					response, err := next.RoundTrip(r)
					if response != nil && response.Body != nil {
						_ = response.Body.Close()
					}
					if err != nil {
						return nil, err
					}
					return nil, errors.New("PRIVATE-DELETE-ERROR")
				})
			case "post-witness":
				for key, object := range f.actor.v.f.access.objects {
					if key.Kind != "ServiceAccount" {
						continue
					}
					original := object.DeepCopy()
					f.afterEffect = func() { object.SetResourceVersion("999") }
					restore = func() { f.actor.v.f.access.objects[key] = original }
					break
				}
			}
			if err := f.wire.delete(ctx, 0); err != ErrOutcomeUnknown {
				t.Fatal("uncertain DELETE was accepted", err)
			}
			if restore != nil {
				restore()
			}
			f.afterEffect = nil
			if ledger.document.Entries[0].State != fixtureDeleteAttempted || ledger.effectSlot != -1 || f.deletes != 1 {
				t.Fatal("unknown DELETE reset receipt/capability")
			}
			rebuilt, err := f.wire.actors.fixtures(ctx, ledger)
			if err != nil || rebuilt.delete(ctx, 0) != ErrFixtures {
				t.Fatal("rebuilt client replayed uncertain DELETE", err)
			}
			if err := ledger.close(); err != nil {
				t.Fatal(err)
			}
			loaded, err := ledger.engine.loadFixtureLedger(ctx, f.actor.request.Snapshot)
			if err != nil {
				t.Fatal(err)
			}
			defer loaded.close()
			restarted, err := f.wire.actors.fixtures(ctx, loaded)
			if err != nil || restarted.delete(ctx, 0) != ErrFixtures || f.deletes != 1 {
				t.Fatal("loaded client replayed uncertain DELETE", err)
			}
			if _, err := restarted.dryRun(ctx, fixtureRestoreJob); err != ErrFixtures || f.previews != 0 {
				t.Fatal("reloaded unknown DELETE previewed", err)
			}
			if _, missing, err := restarted.get(ctx, 0); err != nil || !missing {
				t.Fatal("absence read after unknown DELETE", err)
			}
			if loaded.document.Entries[0].State != fixtureDeleteAttempted {
				t.Fatal("GET silently retired uncertain DELETE")
			}
		})
	}
}

func TestFixtureWireSharedClientsSerializeOneEffectAndRejectReplacement(t *testing.T) {
	f := newFixtureWireTest(t)
	ctx, ledger := context.Background(), f.wire.ledger
	other, err := f.wire.actors.fixtures(ctx, ledger)
	if err != nil {
		t.Fatal(err)
	}
	fixtureWireAdvance(t, ledger, 0, fixtureCreateAttempted, "")
	results := make(chan error, 2)
	for _, wire := range []*fixtureWire{f.wire, other} {
		go func(wire *fixtureWire) { _, err := wire.create(ctx, 0); results <- err }(wire)
	}
	success, refusal := 0, 0
	for range 2 {
		switch err := <-results; err {
		case nil:
			success++
		case ErrFixtures:
			refusal++
		default:
			t.Fatal(err)
		}
	}
	if success != 1 || refusal != 1 || f.creates != 1 {
		t.Fatal("shared clients repeated the same durable intent")
	}
	uid := ledger.document.Entries[0].OriginalUID
	f.objects[0].SetUID("20000000-0000-4000-8000-000000000001")
	if _, _, err := f.wire.get(ctx, 0); err != ErrFixtures || ledger.document.Entries[0].OriginalUID != uid {
		t.Fatal("same-address replacement adopted", err)
	}
}

func TestFixtureWireRefusesRedirectAndRedactsErrorResponse(t *testing.T) {
	for _, status := range []int{302, 403, 422, 429, 500, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			f := newFixtureWireTest(t)
			f.reply = func(w http.ResponseWriter, o *unstructured.Unstructured) {
				w.Header().Set("Location", "/PRIVATE-REDIRECT-CANARY")
				w.Header().Set("X-Private-Canary", "PRIVATE-HEADER-CANARY")
				w.Header().Set("Trailer", "X-Private-Trailer")
				w.WriteHeader(status)
				_, _ = io.WriteString(w, `{"message":"PRIVATE-ERROR-CANARY"}`)
				w.Header().Set("X-Private-Trailer", "PRIVATE-TRAILER-CANARY")
			}
			a := f.wire.clients[0]
			next := a.client.Transport
			a.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				response, err := next.RoundTrip(r)
				if response != nil {
					body, _ := io.ReadAll(response.Body)
					_ = response.Body.Close()
					if string(body) != "{}" || strings.Contains(fmt.Sprint(response.Header, response.Trailer, response.Status), "PRIVATE-") {
						t.Error("native error/redirect metadata escaped capture")
					}
					response.Body = io.NopCloser(bytes.NewReader(body))
				}
				return response, err
			})
			fixtureWireAdvance(t, f.wire.ledger, 0, fixtureCreateAttempted, "")
			if _, err := f.wire.create(context.Background(), 0); err != ErrOutcomeUnknown || f.creates != 1 {
				t.Fatal("native failure retried or trusted", err)
			}
		})
	}
}

func TestFixtureWireClosedRequestRejectsMisuseBeforeAnyHTTP(t *testing.T) {
	f := newFixtureWireTest(t)
	ctx := context.Background()
	for _, operation := range []fixtureRequest{0, fixtureCreateRequest, fixtureDeleteRequest, 255} {
		if _, err := f.wire.request(ctx, 0, operation); err != ErrFixtures {
			t.Fatal("request without fixed method/intent accepted", err)
		}
	}
	for _, slot := range []int{-1, len(fixtureCatalog)} {
		if _, err := f.wire.request(ctx, slot, fixtureGetRequest); err != ErrFixtures {
			t.Fatal("foreign fixture address accepted", err)
		}
	}
	if _, err := f.wire.request(nil, 0, fixtureGetRequest); err != ErrFixtures {
		t.Fatal("nil context accepted", err)
	}
	var missing *fixtureWire
	if _, err := missing.request(ctx, 0, fixtureGetRequest); err != ErrFixtures {
		t.Fatal("nil wire accepted", err)
	}
	for _, invalid := range []*fixtureWire{{}, {ledger: f.wire.ledger}, {ledger: f.wire.ledger, actors: f.wire.actors}} {
		if _, err := invalid.request(ctx, 0, fixtureGetRequest); err != ErrFixtures {
			t.Fatal("incomplete wire accepted", err)
		}
	}
	if f.creates != 0 || f.deletes != 0 || f.reads != 0 {
		t.Fatal("misuse reached HTTP effect/read")
	}
}
