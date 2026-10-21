// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	platformkube "github.com/gobha-me/arcadectl/internal/platform/kube"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// TEST ONLY. This fixed learning effect is absent from production binaries.
// It returns an ACK-bound response for private bookkeeping, NOT a whole-result
// acceptance, AdmissionEffective, cleanup permission or a production provider.
// Production warm status transport must wait for separately native-proven whole
// result contracts. No arbitrary payload, address, actor or retry is selectable.
func warmSeedLearningOnce(ctx context.Context, w *fixtureWire) (*unstructured.Unstructured, error) {
	if w == nil || w.ledger == nil {
		return nil, ErrFixtures
	}
	f := w.ledger
	f.wireMu.Lock()
	defer f.wireMu.Unlock()
	if !warmSeedLearningReady(f) {
		return nil, ErrFixtures
	}
	defer func() { f.seedAck, f.seedEffect = false, false }()
	if ctx == nil || w.current(ctx) != nil {
		return nil, ErrFixtures
	}
	entry := f.document.Entries[fixtureCancelledDestroy]
	parent := w.actors.admission.prerequisites.access
	permission := fixtureDestroySeedPermission(entry.Key.Namespace, entry.Key.Name)
	discovery, err := parent.discover(ctx, entry.Key.APIVersion)
	if err != nil || !discoveredPermission(discovery, permission) || parent.authorize(ctx, permission.spec) != nil || w.current(ctx) != nil {
		return nil, ErrFixtures
	}
	live, absent, err := w.getLocked(ctx, fixtureCancelledDestroy)
	if err != nil || absent || live == nil || live.GetResourceVersion() != f.document.DestroySeed.BeforeResourceVersion || f.validateWarmCancelledDestroyResult(live, time.Now().UTC()) != nil || !warmSeedLearningReady(f) || w.current(ctx) != nil {
		return nil, ErrFixtures
	}
	// The observed body is only a strict precondition. Never copy its metadata
	// or status into the effect: derive all bytes from the protected constructor.
	payload, err := f.object(fixtureCancelledDestroy)
	if err != nil {
		return nil, ErrFixtures
	}
	payload.SetUID(entry.OriginalUID)
	payload.SetResourceVersion(f.document.DestroySeed.BeforeResourceVersion)
	payload.SetFinalizers([]string{platformkube.DestroyFinalizer})
	payload.Object["status"] = warmSeedLearningStatus(f)
	body, err := json.Marshal(payload.Object)
	path, _, pathErr := fixturePath(entry.Key, false)
	a := w.clients[0]
	if err != nil || len(body) > 65536 || pathErr != nil || a == nil || a.base == nil || a.client == nil {
		return nil, ErrFixtures
	}
	u := *a.base
	u.Path = strings.TrimRight(u.Path, "/") + path + "/status"
	u.RawQuery = "fieldManager=arcadectl-installer&fieldValidation=Strict"
	identity := fixtureWireIdentity{namespace: entry.Key.Namespace}
	config := parent.frozen
	if config.BearerToken != "" {
		identity.authorization = "Bearer " + config.BearerToken
	} else if config.Username != "" || config.Password != "" {
		identity.authorization = "Basic " + base64.StdEncoding.EncodeToString([]byte(config.Username+":"+config.Password))
	}
	capture := &fixtureCapture{identity: identity, method: http.MethodPut, url: u.String(), body: body, key: entry.Key, seedUID: entry.OriginalUID, seedBeforeRV: f.document.DestroySeed.BeforeResourceVersion}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	ctx = logr.NewContext(ctx, logr.Discard())
	ctx = context.WithValue(ctx, attemptKey{}, &requestAttempt{method: http.MethodPut, fixture: capture})
	r, err := http.NewRequestWithContext(ctx, http.MethodPut, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, ErrFixtures
	}
	r.GetBody = nil
	r.Header.Set("Accept", "application/json")
	r.Header.Set("Content-Type", "application/json")
	f.seedEffect = false // one send, consumed BEFORE Do and shared across wires
	response, requestErr := a.client.Do(r)
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	if capture.seedAcknowledgedRV == "" || capture.seedUID != entry.OriginalUID || capture.uid != "" {
		return nil, ErrOutcomeUnknown
	}
	next, err := f.nextDocument()
	if err != nil || next.DestroySeed == nil {
		return nil, ErrFixtures
	}
	next.DestroySeed.State, next.DestroySeed.AcknowledgedResourceVersion = fixtureDestroySeedAcknowledged, capture.seedAcknowledgedRV
	if f.advance(next) != nil || requestErr != nil || !capture.success || w.current(ctx) != nil || capture.result == nil || capture.result.GetResourceVersion() != f.document.DestroySeed.AcknowledgedResourceVersion {
		return nil, ErrFixtures
	}
	return capture.result.DeepCopy(), nil // DIAGNOSTIC ONLY: no whole-result gate
}

func warmSeedLearningReady(f *fixtureLedger) bool {
	return !f.markerUnresolved() && f.seedAck && f.seedEffect && f.ackSlot == -1 && f.effectSlot == -1 && f.document.DestroySeed != nil && f.document.DestroySeed.Mode == fixtureDestroySeedWarmCancelled && f.document.DestroySeed.State == fixtureDestroySeedAttempted
}

func warmSeedLearningStatus(f *fixtureLedger) map[string]any {
	return map[string]any{"phase": "Cancelled", "preview": map[string]any{
		"challenge": f.document.RunID, "expiresAt": fixtureDestroySeedExpiry, "restoreGuidance": fixtureDestroySeedGuidance,
	}}
}

// PRIVATE TEST capture/privacy boundary only. Known public role/path dictionaries
// bound diagnostic bytes, not the native count, ownership split or role order.
// Subsets of the controller's known cancellation tree are allowed for LEARNING
// only: the actual native record is subsequently inspected, never treated as an
// accepted production seeded shape. No observation gate/effect uses this result.
func warmSeedLearningPublic(f *fixtureLedger, o *unstructured.Unstructured, observed time.Time) error {
	if f == nil || o == nil || f.document.DestroySeed == nil || f.document.DestroySeed.Mode != fixtureDestroySeedWarmCancelled || f.document.DestroySeed.State != fixtureDestroySeedAcknowledged || o.GetResourceVersion() != f.document.DestroySeed.AcknowledgedResourceVersion || !reflect.DeepEqual(o.GetFinalizers(), []string{platformkube.DestroyFinalizer}) || !reflect.DeepEqual(o.Object["status"], warmSeedLearningStatus(f)) {
		return ErrFixtures
	}
	want, err := f.object(fixtureCancelledDestroy)
	fields, found, fieldsErr := unstructured.NestedSlice(o.Object, "metadata", "managedFields")
	if err != nil || fieldsErr != nil || !found || len(fields) == 0 {
		return ErrFixtures
	}
	seen := map[string]bool{}
	var installer any
	for _, raw := range fields {
		field, ok := raw.(map[string]any)
		if !ok || !fixtureResultTime(field["time"], o.GetCreationTimestamp().Time, observed.UTC().Add(time.Second)) {
			return ErrFixtures
		}
		manager, managerOK := field["manager"].(string)
		subresource, present := field["subresource"]
		role := manager + ":"
		if present {
			if subresource != "status" {
				return ErrFixtures
			}
			role += "status"
		}
		var allowed map[string]any
		switch role {
		case "arcadectl-installer:":
			allowed, installer = fixtureResultFieldset(want), raw
		case "arcadectl-controller:":
			allowed = fixtureWarmFinalizerFieldset()
		case "arcadectl-controller:status":
			allowed = fixtureWarmCancellationFieldset()
		case "arcadectl-installer:status":
			allowed = fixtureDestroySeedFieldset()
		default:
			return ErrFixtures
		}
		if !managerOK || seen[role] || !warmSeedLearningFieldSubset(field["fieldsV1"], allowed) {
			return ErrFixtures
		}
		seen[role] = true
		expected := map[string]any{"manager": manager, "operation": "Update", "apiVersion": want.GetAPIVersion(), "fieldsType": "FieldsV1", "fieldsV1": field["fieldsV1"], "time": field["time"]}
		if present {
			expected["subresource"] = "status"
		}
		if !reflect.DeepEqual(field, expected) {
			return ErrFixtures
		}
	}
	// The unmodified cold whole check proves every other raw metadata/spec field
	// is constructor-bound public data before storing a diagnostic. This private
	// copy does not filter an ordinary observation or authorize cleanup.
	base := o.DeepCopy()
	delete(base.Object, "status")
	unstructured.RemoveNestedField(base.Object, "metadata", "finalizers")
	if installer == nil || unstructured.SetNestedSlice(base.Object, []any{installer}, "metadata", "managedFields") != nil || f.validateResult(fixtureCancelledDestroy, fixtureStableResult, base, observed) != nil {
		return ErrFixtures
	}
	return nil
}

func warmSeedLearningFieldSubset(raw any, allowed map[string]any) bool {
	tree, ok := raw.(map[string]any)
	if !ok || allowed == nil {
		return false
	}
	for key, value := range tree {
		child, known := allowed[key].(map[string]any)
		if !known || !warmSeedLearningFieldSubset(value, child) {
			return false
		}
	}
	return true
}

// Independent fake replies exercise only the diagnostic transport/ACK boundary.
// Their managedFields are deliberately NOT a guessed successful native seed
// example; unchanged cancellation ownership is public but not seeded acceptance.
func warmSeedLearningFactory(t *testing.T) func(*testing.T, fixtureDestroySeedMode) *fixtureWireTest {
	t.Helper()
	preview := fixturePreviewFactory(t)
	return func(t *testing.T, mode fixtureDestroySeedMode) *fixtureWireTest {
		t.Helper()
		f := preview(t)
		ledger := f.wire.ledger
		acknowledgeAllRecipeFixtures(t, ledger)
		created := time.Now().UTC().Truncate(time.Second).Add(-20 * time.Second)
		for slot := range fixtureCatalog {
			f.objects[slot] = fixtureResultExample(t, ledger, slot, fixtureStableResult, created)
		}
		f.objects[fixtureCancelledDestroy] = fixtureWarmCancelledExample(t, ledger, created, [3]time.Duration{time.Second, time.Second, time.Second})
		intent := fixtureSeedIntent(t, ledger)
		intent.DestroySeed.Mode = mode
		if ledger.advance(intent) != nil {
			t.Fatal("original diagnostic learning intent unavailable")
		}
		prior := f.actor.fixtureHandler
		path, _, _ := fixturePath(ledger.document.Entries[fixtureCancelledDestroy].Key, false)
		f.actor.fixtureHandler = func(w http.ResponseWriter, r *http.Request) bool {
			if r.URL.Path != path+"/status" {
				return prior(w, r)
			}
			f.seeds++
			want, _ := ledger.object(fixtureCancelledDestroy)
			want.SetUID(ledger.document.Entries[fixtureCancelledDestroy].OriginalUID)
			want.SetResourceVersion(ledger.document.DestroySeed.BeforeResourceVersion)
			want.SetFinalizers([]string{platformkube.DestroyFinalizer})
			want.Object["status"] = warmSeedLearningStatus(ledger)
			var got map[string]any
			if r.Method != http.MethodPut || r.Header.Get("Impersonate-User") != "" || r.URL.RawQuery != "fieldManager=arcadectl-installer&fieldValidation=Strict" || json.NewDecoder(r.Body).Decode(&got) != nil || !reflect.DeepEqual(got, want.Object) || ledger.document.DestroySeed.Mode != fixtureDestroySeedWarmCancelled || ledger.document.DestroySeed.State != fixtureDestroySeedAttempted || ledger.seedEffect || !ledger.seedAck {
				t.Error("diagnostic effect escaped constructor/identity/intent/single-send bounds")
			}
			result := f.objects[fixtureCancelledDestroy].DeepCopy()
			result.SetResourceVersion("102")
			result.Object["status"] = warmSeedLearningStatus(ledger)
			if f.nativeWarmSeedReply {
				result = fixtureWarmSeededExample(t, ledger, result.GetCreationTimestamp().Time, [4]time.Duration{time.Second, time.Second, time.Second, 2 * time.Second})
			}
			f.objects[fixtureCancelledDestroy] = result.DeepCopy()
			if f.afterSeed != nil {
				f.afterSeed()
			}
			w.Header().Set("X-Private-Canary", "PRIVATE-WARM-SEED-HEADER")
			if f.seedReply != nil {
				f.seedReply(w, result)
			} else {
				_ = json.NewEncoder(w).Encode(result.Object)
			}
			return true
		}
		return f
	}
}

func TestWarmSeedLearningFixedEffectAckFenceAndNoReplay(t *testing.T) {
	f := warmSeedLearningFactory(t)(t, fixtureDestroySeedWarmCancelled)
	ledger := f.wire.ledger
	result, err := warmSeedLearningOnce(t.Context(), f.wire)
	if err != nil || result == nil || f.seeds != 1 || ledger.document.DestroySeed.State != fixtureDestroySeedAcknowledged || ledger.document.DestroySeed.Mode != fixtureDestroySeedWarmCancelled || ledger.document.DestroySeed.AcknowledgedResourceVersion != "102" || ledger.seedAck || ledger.seedEffect || ledger.engine.fixtureFence(f.actor.request.Snapshot) != ErrFixtures {
		t.Fatal("diagnostic original ACK lost durability/identity/fence", err)
	}
	if ledger.validateDestroySeedResult(result, time.Now().UTC()) != ErrFixtures || ledger.validateWarmCancelledDestroyResult(result, time.Now().UTC()) != ErrFixtures || (&fixtureWire{ledger: ledger}).fixturesSettled() {
		t.Fatal("diagnostic reply became cold/whole/settled authority")
	}
	result.SetResourceVersion("999")
	if f.objects[fixtureCancelledDestroy].GetResourceVersion() != "102" {
		t.Fatal("diagnostic return aliases live fake body")
	}
	if _, err := warmSeedLearningOnce(t.Context(), f.wire); err != ErrFixtures {
		t.Fatal("same wire replayed diagnostic seed")
	}
	rebuilt, err := f.wire.actors.fixtures(t.Context(), ledger)
	if err != nil {
		t.Fatal("original rebuilt wire unavailable")
	}
	if _, err := warmSeedLearningOnce(t.Context(), rebuilt); err != ErrFixtures {
		t.Fatal("rebuilt wire replayed diagnostic seed")
	}
	if ledger.close() != nil {
		t.Fatal("acknowledged diagnostic ledger close failed")
	}
	loaded, err := ledger.engine.loadFixtureLedger(t.Context(), f.actor.request.Snapshot)
	if err != nil {
		t.Fatal("acknowledged diagnostic reload failed")
	}
	defer loaded.close()
	rebuilt, err = f.wire.actors.fixtures(t.Context(), loaded)
	if err != nil {
		t.Fatal("reloaded original wire unavailable")
	}
	if _, err := warmSeedLearningOnce(t.Context(), rebuilt); err != ErrFixtures || loaded.seedAck || loaded.seedEffect || f.seeds != 1 {
		t.Fatal("reload restored diagnostic send capability")
	}
}

func TestWarmSeedLearningUnknownAndReliableAckBeforeRefusal(t *testing.T) {
	newSeed := warmSeedLearningFactory(t)
	for _, fault := range []string{"same-rv", "foreign-uid", "partial", "outer-error", "post-witness", "file-replacement"} {
		t.Run(fault, func(t *testing.T) {
			f := newSeed(t, fixtureDestroySeedWarmCancelled)
			ledger := f.wire.ledger
			switch fault {
			case "outer-error":
				original := f.wire.clients[0].client.Transport
				f.wire.clients[0].client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
					response, err := original.RoundTrip(r)
					if r.Method != http.MethodPut {
						return response, err
					}
					if response == nil {
						t.Error("reliable inner response unavailable")
						return response, err
					}
					body, _ := io.ReadAll(response.Body)
					if string(body) != "{}" || response.Header.Get("X-Private-Canary") != "" {
						t.Error("raw diagnostic seed response escaped sanitizer")
					}
					return nil, errors.New("PRIVATE-WARM-SEED-CANARY")
				})
			case "post-witness":
				f.afterSeed = func() {
					for key, o := range f.actor.v.f.access.objects {
						if key.Kind == "ServiceAccount" {
							o.SetResourceVersion("999")
							break
						}
					}
				}
			case "file-replacement":
				f.afterSeed = func() {
					if _, err := ledger.engine.files.AtomicWrite(ledger.name, bytes.Clone(ledger.body), &ledger.identity); err != nil {
						t.Error("test replacement failed")
					}
				}
			default:
				f.seedReply = func(w http.ResponseWriter, o *unstructured.Unstructured) {
					if fault == "partial" {
						_, _ = io.WriteString(w, `{"metadata":`)
						return
					}
					if fault == "same-rv" {
						o.SetResourceVersion("101")
					} else {
						o.SetUID("c0000000-0000-4000-8000-000000000001")
					}
					_ = json.NewEncoder(w).Encode(o.Object)
				}
			}
			result, err := warmSeedLearningOnce(t.Context(), f.wire)
			ack := fault == "outer-error" || fault == "post-witness"
			wantErr := ErrOutcomeUnknown
			if ack || fault == "file-replacement" {
				wantErr = ErrFixtures
			}
			if result != nil || err != wantErr || f.seeds != 1 || ledger.seedAck || ledger.seedEffect || (ledger.document.DestroySeed.State == fixtureDestroySeedAcknowledged) != ack {
				t.Fatal("diagnostic uncertainty adopted/replayed or reliable ACK lost", err)
			}
			if _, err := warmSeedLearningOnce(t.Context(), f.wire); err != ErrFixtures || f.seeds != 1 {
				t.Fatal("diagnostic refusal replayed")
			}
			if fault == "same-rv" || fault == "foreign-uid" || fault == "partial" {
				// A later exact original observation is not a same-attempt ACK.
				f.seedReply = nil
				live, absent, err := f.wire.get(t.Context(), fixtureCancelledDestroy)
				if err != nil || absent || live.GetResourceVersion() != "102" || ledger.document.DestroySeed.State != fixtureDestroySeedAttempted {
					t.Fatal("later GET adopted an unknown diagnostic effect")
				}
				if ledger.close() != nil {
					t.Fatal("unknown diagnostic close failed")
				}
				loaded, err := ledger.engine.loadFixtureLedger(t.Context(), f.actor.request.Snapshot)
				if err != nil {
					t.Fatal("unknown diagnostic reload failed")
				}
				defer loaded.close()
				rebuilt, err := f.wire.actors.fixtures(t.Context(), loaded)
				if err != nil {
					t.Fatal("unknown original rebuilt wire unavailable")
				}
				if _, err := warmSeedLearningOnce(t.Context(), rebuilt); err != ErrFixtures || loaded.seedAck || loaded.seedEffect || loaded.document.DestroySeed.State != fixtureDestroySeedAttempted || f.seeds != 1 || loaded.engine.fixtureFence(f.actor.request.Snapshot) != ErrFixtures {
					t.Fatal("unknown diagnostic reload restored ACK/replay/ordinary authority")
				}
				cleanup, _ := loaded.nextDocument()
				cleanup.Entries[fixtureCancelledDestroy].State, cleanup.Entries[fixtureCancelledDestroy].DeleteResourceVersion = fixtureDeleteAttempted, "102"
				if loaded.advance(cleanup) != ErrFixtures {
					t.Fatal("unknown diagnostic reload granted original cleanup")
				}
			}
		})
	}
}

func TestWarmSeedLearningPreflightAndPrivateCaptureRefuse(t *testing.T) {
	newSeed := warmSeedLearningFactory(t)
	for _, fault := range []string{"cold", "rv", "uid", "status", "finalizer", "deny", "discovery", "body-tamper"} {
		t.Run(fault, func(t *testing.T) {
			mode := fixtureDestroySeedWarmCancelled
			if fault == "cold" {
				mode = fixtureDestroySeedCold
			}
			f := newSeed(t, mode)
			live := f.objects[fixtureCancelledDestroy]
			switch fault {
			case "rv":
				live.SetResourceVersion("100")
			case "uid":
				live.SetUID("c0000000-0000-4000-8000-000000000001")
			case "status":
				unstructured.RemoveNestedField(live.Object, "status", "conditions")
			case "finalizer":
				live.SetFinalizers(nil)
			case "deny":
				f.denySeed = true
			case "discovery":
				f.missingSeedDiscovery = true
			case "body-tamper":
				original := f.wire.clients[0].client.Transport
				f.wire.clients[0].client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
					if r.Method == http.MethodPut {
						r.Body = io.NopCloser(strings.NewReader(`{"status":{"phase":"Deleting"}}`))
					}
					return original.RoundTrip(r)
				})
			}
			before := bytes.Clone(f.wire.ledger.body)
			result, err := warmSeedLearningOnce(t.Context(), f.wire)
			if result != nil || err == nil || f.seeds != 0 || !bytes.Equal(before, f.wire.ledger.body) {
				t.Fatal("diagnostic precondition drift reached status effect")
			}
		})
	}
	f := newSeed(t, fixtureDestroySeedWarmCancelled)
	result, err := warmSeedLearningOnce(t.Context(), f.wire)
	if err != nil || warmSeedLearningPublic(f.wire.ledger, result, time.Now().UTC()) != nil {
		t.Fatal("public diagnostic-only body refused")
	}
	dir := t.TempDir()
	if os.Chmod(dir, 0700) != nil {
		t.Fatal("private learning capture directory unavailable")
	}
	t.Setenv("ARCADECTL_TEST_NATIVE_FIXTURE_SHAPES", dir)
	for _, fault := range []string{"manager", "path", "status", "metadata", "rv"} {
		bad := result.DeepCopy()
		switch fault {
		case "manager", "path":
			fields, _, _ := unstructured.NestedSlice(bad.Object, "metadata", "managedFields")
			if fault == "manager" {
				fields[0].(map[string]any)["manager"] = "PRIVATE-WARM-SEED-CANARY"
			} else {
				fields[0].(map[string]any)["fieldsV1"] = map[string]any{"PRIVATE-WARM-SEED-CANARY": map[string]any{}}
			}
			_ = unstructured.SetNestedSlice(bad.Object, fields, "metadata", "managedFields")
		case "status":
			_ = unstructured.SetNestedField(bad.Object, "PRIVATE-WARM-SEED-CANARY", "status", "preview", "restoreGuidance")
		case "metadata":
			_ = unstructured.SetNestedField(bad.Object, "PRIVATE-WARM-SEED-CANARY", "metadata", "unknown")
		case "rv":
			bad.SetResourceVersion("999")
		}
		if captureNativeFixtureShape(f.wire.ledger, fixtureCancelledDestroy, "warm-seed-learning", bad) != ErrFixtures {
			t.Fatal("private/unbound diagnostic body captured", fault)
		}
	}
	files, err := os.ReadDir(dir)
	if err != nil || len(files) != 0 || f.seeds != 1 || f.wire.ledger.engine.fixtureFence(f.actor.request.Snapshot) != ErrFixtures {
		t.Fatal("refused diagnostic wrote data/performed another effect/retired fence")
	}
}
