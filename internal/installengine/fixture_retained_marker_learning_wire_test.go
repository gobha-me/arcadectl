// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	platformkube "github.com/gobha-me/arcadectl/internal/platform/kube"
	authv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

type retainedMarkerLearningFixture struct {
	f       *fixtureWireTest
	before  *unstructured.Unstructured
	updates int
	deny    bool
	reply   func(http.ResponseWriter, *unstructured.Unstructured)
	after   func()
}

// Genuine independent actor checkpoints; synthetic original fixture ACKs and
// native-shaped fake replies are NOT native marker/ownership certification.
func retainedMarkerLearningFactory(t *testing.T) func(*testing.T) *retainedMarkerLearningFixture {
	return retainedMarkerLearningFactoryWithWorlds(t, false)
}

func retainedMarkerLearningFactoryWithWorlds(t *testing.T, sealed bool) func(*testing.T) *retainedMarkerLearningFixture {
	t.Helper()
	newPreview := fixturePreviewFactory(t)
	return func(t *testing.T) *retainedMarkerLearningFixture {
		t.Helper()
		f := newPreview(t)
		ledger := f.wire.ledger
		if sealed && ledger.sealOriginalWorlds([]fixtureWorldRow{}) != nil {
			t.Fatal("original empty-world seal unavailable")
		}
		acknowledgeAllRecipeFixtures(t, ledger)
		created := time.Now().UTC().Truncate(time.Second).Add(-20 * time.Second)
		for slot := range fixtureCatalog {
			f.objects[slot] = fixtureResultExample(t, ledger, slot, fixtureStableResult, created)
		}
		if ledger.advance(fixtureMarkerIntent(t, ledger)) != nil {
			t.Fatal("marker learning intent unavailable")
		}
		h := &retainedMarkerLearningFixture{f: f, before: f.objects[fixtureRetainedPVC].DeepCopy()}
		prior := f.actor.fixtureHandler
		entry := ledger.document.Entries[fixtureRetainedPVC]
		permission, _ := actorPermission(entry.Key, probeUpdateOperation)
		path, _, _ := fixturePath(entry.Key, false)
		f.actor.fixtureHandler = func(w http.ResponseWriter, r *http.Request) bool {
			if r.URL.Path == "/api/v1" && r.Method == http.MethodGet {
				// Extend only this fake fixture discovery with the existing
				// native PVC UPDATE verb needed by the new named-right proof.
				_ = json.NewEncoder(w).Encode(metav1.APIResourceList{TypeMeta: metav1.TypeMeta{Kind: "APIResourceList", APIVersion: "v1"}, GroupVersion: "v1", APIResources: []metav1.APIResource{
					{Name: "pods", Kind: "Pod", Namespaced: true, Verbs: metav1.Verbs{"get", "list", "create", "delete"}},
					{Name: "persistentvolumeclaims", Kind: "PersistentVolumeClaim", Namespaced: true, Verbs: metav1.Verbs{"get", "list", "create", "delete", "update"}},
				}})
				return true
			}
			if r.URL.Path == "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" {
				body, _ := io.ReadAll(r.Body)
				r.Body = io.NopCloser(bytes.NewReader(body))
				var review authv1.SelfSubjectAccessReview
				if json.Unmarshal(body, &review) == nil && reflect.DeepEqual(review.Spec, permission.spec) {
					if r.Method != http.MethodPost || r.Header.Get("Impersonate-User") != "system:serviceaccount:"+entry.Key.Namespace+":"+ordinaryControllerActor.account() {
						t.Error("marker SSAR lost original named ordinary identity")
					}
					review.Status.Allowed = !h.deny
					_ = json.NewEncoder(w).Encode(review)
					return true
				}
			}
			if r.URL.Path != path || r.Method != http.MethodPut {
				return prior(w, r)
			}
			h.updates++
			want, _ := retainedMarkerLearningRecipe(ledger)
			want.SetUID(entry.OriginalUID)
			want.SetResourceVersion(ledger.document.RetainedMarker.BeforeResourceVersion)
			want.SetFinalizers([]string{"kubernetes.io/pvc-protection"})
			var got map[string]any
			if r.Header.Get("Impersonate-User") != "system:serviceaccount:"+entry.Key.Namespace+":"+ordinaryControllerActor.account() || r.URL.RawQuery != "fieldManager=arcadectl-installer&fieldValidation=Strict" || json.NewDecoder(r.Body).Decode(&got) != nil || !reflect.DeepEqual(got, want.Object) || ledger.markerEffect || !ledger.markerAck || ledger.document.RetainedMarker.State != fixtureRetainedMarkerAttempted {
				t.Error("marker effect escaped fixed original actor/body/once-only bounds")
			}
			result := f.objects[fixtureRetainedPVC].DeepCopy()
			annotations := result.GetAnnotations()
			annotations[platformkube.AnnotationColdBackupUID] = ledger.document.RunID
			result.SetAnnotations(annotations)
			result.SetResourceVersion("102")
			f.objects[fixtureRetainedPVC] = result.DeepCopy()
			if h.after != nil {
				h.after()
			}
			w.Header().Set("X-Private-Canary", "PRIVATE-MARKER-HEADER")
			if h.reply != nil {
				h.reply(w, result)
			} else {
				_ = json.NewEncoder(w).Encode(result.Object)
			}
			return true
		}
		return h
	}
}

func TestRetainedMarkerLearningOriginalAckPrivacyAndNoReplay(t *testing.T) {
	h := retainedMarkerLearningFactory(t)(t)
	w, ledger := h.f.wire, h.f.wire.ledger
	result, err := retainedMarkerLearningOnce(t.Context(), w)
	if err != nil || result == nil || h.updates != 1 || ledger.document.RetainedMarker.State != fixtureRetainedMarkerAcknowledged || ledger.markerAck || ledger.markerEffect || retainedMarkerLearningPublic(ledger, result, time.Now().UTC()) != nil {
		t.Fatal("fixed diagnostic marker write not ACKed once", err)
	}
	if retainedMarkerLearningDelta(ledger, h.before, result, time.Now().UTC()) != nil {
		t.Fatal("fixed diagnostic write changed more than marker/RV/bookkeeping")
	}
	changedCreation := result.DeepCopy()
	changedCreation.SetCreationTimestamp(metav1.NewTime(result.GetCreationTimestamp().Add(-time.Second)))
	if retainedMarkerLearningPublic(ledger, changedCreation, time.Now().UTC()) != nil {
		t.Fatal("changed creation privacy control was not independently public")
	}
	if retainedMarkerLearningDelta(ledger, h.before, changedCreation, time.Now().UTC()) != ErrFixtures {
		t.Fatal("marker delta adopted changed creation time")
	}
	if ledger.validateResult(fixtureRetainedPVC, fixtureStableResult, result, time.Now().UTC()) != ErrFixtures || w.fixturesSettled() {
		t.Fatal("learning reply became ordinary whole/settled permission")
	}
	if _, err := retainedMarkerLearningOnce(t.Context(), w); err != ErrFixtures || h.updates != 1 {
		t.Fatal("marker write replayed")
	}
	if ledger.close() != nil {
		t.Fatal("marker learning close unavailable")
	}
	loaded, err := ledger.engine.loadFixtureLedger(t.Context(), h.f.actor.request.Snapshot)
	if err != nil {
		t.Fatal("marker learning reload unavailable")
	}
	defer loaded.close()
	rebuilt, err := w.actors.fixtures(t.Context(), loaded)
	if err != nil {
		t.Fatal("marker learning wire rebuild unavailable")
	}
	if _, err := retainedMarkerLearningOnce(t.Context(), rebuilt); err != ErrFixtures || loaded.markerAck || loaded.markerEffect || h.updates != 1 || loaded.engine.fixtureFence(h.f.actor.request.Snapshot) != ErrFixtures {
		t.Fatal("marker reload restored effect or retired fence")
	}
}

func TestRetainedMarkerLearningUnknownAndLateRefusals(t *testing.T) {
	newMarker := retainedMarkerLearningFactory(t)
	for _, fault := range []string{"foreign-uid", "unchanged-rv", "partial", "duplicate", "mime", "oversize", "http-error", "post-witness", "outer-error", "private-shape", "file-replacement"} {
		t.Run(fault, func(t *testing.T) {
			h := newMarker(t)
			w, ledger := h.f.wire, h.f.wire.ledger
			unknown := fault == "foreign-uid" || fault == "unchanged-rv" || fault == "partial" || fault == "duplicate" || fault == "mime" || fault == "oversize" || fault == "http-error"
			h.reply = func(r http.ResponseWriter, o *unstructured.Unstructured) {
				switch fault {
				case "foreign-uid":
					o.SetUID("b0000000-0000-4000-8000-000000000001")
				case "unchanged-rv":
					o.SetResourceVersion("101")
				case "partial":
					_, _ = io.WriteString(r, `{"metadata":`)
					return
				case "duplicate":
					_, _ = io.WriteString(r, `{"metadata":{},"metadata":{}}`)
					return
				case "mime":
					r.Header().Set("Content-Type", "text/plain")
				case "oversize":
					_, _ = io.WriteString(r, strings.Repeat("x", 1024*1024+1))
					return
				case "http-error":
					r.WriteHeader(500)
				case "private-shape":
					o.SetAnnotations(map[string]string{"private": "PRIVATE-CANARY"})
				}
				_ = json.NewEncoder(r).Encode(o.Object)
			}
			switch fault {
			case "post-witness":
				h.after = func() {
					for key, o := range h.f.actor.v.f.access.objects {
						if key.Kind == "ServiceAccount" {
							o.SetResourceVersion("999")
							break
						}
					}
				}
			case "file-replacement":
				h.after = func() {
					if _, err := ledger.engine.files.AtomicWrite(ledger.name, bytes.Clone(ledger.body), &ledger.identity); err != nil {
						t.Error("protected replacement unavailable")
					}
				}
			case "outer-error":
				a := w.actors.clients[ordinaryControllerActor]
				prior := a.client.Transport
				a.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
					response, err := prior.RoundTrip(r)
					if r.Method != http.MethodPut {
						return response, err
					}
					if response == nil {
						t.Error("inner marker reply unavailable")
						return response, err
					}
					body, _ := io.ReadAll(response.Body)
					if string(body) != "{}" || response.Header.Get("X-Private-Canary") != "" {
						t.Error("raw marker reply escaped below-wrapper privacy boundary")
					}
					_ = response.Body.Close()
					return nil, errors.New("PRIVATE-OUTER-CANARY")
				})
			}
			result, err := retainedMarkerLearningOnce(t.Context(), w)
			if fault == "private-shape" {
				if err != nil || result == nil || retainedMarkerLearningPublic(ledger, result, time.Now().UTC()) != ErrFixtures {
					t.Fatal("reliable ACK or separate private-shape refusal lost")
				}
			} else {
				want := ErrFixtures
				if unknown {
					want = ErrOutcomeUnknown
				}
				if err != want || result != nil || strings.Contains(err.Error(), "PRIVATE") {
					t.Fatal("marker refusal lost closed boundary", err)
				}
			}
			ack := !unknown && fault != "file-replacement"
			if h.updates != 1 || ledger.markerAck || ledger.markerEffect || (ledger.document.RetainedMarker.State == fixtureRetainedMarkerAcknowledged) != ack {
				t.Fatal("marker ACK ordering/uncertainty/capability contract violated")
			}
			if _, err := retainedMarkerLearningOnce(t.Context(), w); err != ErrFixtures || h.updates != 1 {
				t.Fatal("refused marker effect replayed")
			}
			if unknown {
				live, absent, getErr := w.get(t.Context(), fixtureRetainedPVC)
				if getErr != nil || absent || live == nil || ledger.document.RetainedMarker.State != fixtureRetainedMarkerAttempted {
					t.Fatal("marker GET adopted an unknown ACK")
				}
				if ledger.close() != nil {
					t.Fatal("unknown marker close unavailable")
				}
				loaded, loadErr := ledger.engine.loadFixtureLedger(t.Context(), h.f.actor.request.Snapshot)
				if loadErr != nil {
					t.Fatal("unknown marker reload unavailable")
				}
				defer loaded.close()
				rebuilt, buildErr := w.actors.fixtures(t.Context(), loaded)
				if buildErr != nil {
					t.Fatal("unknown marker wire unavailable")
				}
				if _, err := retainedMarkerLearningOnce(t.Context(), rebuilt); err != ErrFixtures || loaded.markerAck || loaded.markerEffect || h.updates != 1 {
					t.Fatal("unknown marker adopted/replayed after reload")
				}
			}
		})
	}
}

func TestRetainedMarkerLearningPreflightAndPrivacyCapture(t *testing.T) {
	newMarker := retainedMarkerLearningFactory(t)
	h := newMarker(t)
	h.deny = true
	if _, err := retainedMarkerLearningOnce(t.Context(), h.f.wire); err != ErrFixtures || h.updates != 0 || h.f.wire.ledger.markerAck || h.f.wire.ledger.markerEffect {
		t.Fatal("denied named UPDATE sent marker")
	}
	h = newMarker(t)
	o, err := retainedMarkerLearningOnce(t.Context(), h.f.wire)
	if err != nil {
		t.Fatal("public diagnostic reply unavailable")
	}
	dir := t.TempDir()
	if os.Chmod(dir, 0700) != nil {
		t.Fatal("private capture unavailable")
	}
	t.Setenv("ARCADECTL_TEST_NATIVE_FIXTURE_SHAPES", dir)
	for _, fault := range []string{"foreign-manager", "private-owned-path", "extra-attribute", "status", "annotations", "spec", "attempted", "wrong-stage-slot"} {
		x := o.DeepCopy()
		ledger := h.f.wire.ledger
		originalState := ledger.document.RetainedMarker.State
		slot := fixtureRetainedPVC
		switch fault {
		case "foreign-manager":
			x.Object["metadata"].(map[string]any)["managedFields"].([]any)[0].(map[string]any)["manager"] = "PRIVATE-CANARY"
		case "private-owned-path":
			x.Object["metadata"].(map[string]any)["managedFields"].([]any)[0].(map[string]any)["fieldsV1"].(map[string]any)["f:PRIVATE-CANARY"] = map[string]any{}
		case "extra-attribute":
			x.Object["metadata"].(map[string]any)["managedFields"].([]any)[0].(map[string]any)["private"] = "PRIVATE-CANARY"
		case "status":
			x.Object["status"] = map[string]any{"phase": "Bound"}
		case "annotations":
			x.SetAnnotations(map[string]string{platformkube.AnnotationColdBackupUID: ledger.document.RunID})
		case "spec":
			_ = unstructured.SetNestedField(x.Object, "foreign", "spec", "volumeName")
		case "attempted":
			ledger.document.RetainedMarker.State = fixtureRetainedMarkerAttempted
		case "wrong-stage-slot":
			slot = fixturePlainPVC
		}
		refused := captureNativeFixtureShape(ledger, slot, "retained-marker-learning", x) == ErrFixtures
		ledger.document.RetainedMarker.State = originalState
		if !refused {
			t.Fatal("private/foreign marker capture accepted", fault)
		}
		files, readErr := os.ReadDir(dir)
		if readErr != nil || len(files) != 0 {
			t.Fatal("refused marker diagnostic wrote bytes")
		}
	}
	// A schema-derived diagnostic positive exercises the NEW literal owned
	// annotation path, without asserting native count/order/ownership.
	withLeaf := o.DeepCopy()
	fields := withLeaf.Object["metadata"].(map[string]any)["managedFields"].([]any)
	tree := fields[0].(map[string]any)["fieldsV1"].(map[string]any)
	tree["f:metadata"].(map[string]any)["f:annotations"].(map[string]any)["f:"+platformkube.AnnotationColdBackupUID] = map[string]any{}
	if retainedMarkerLearningPublic(h.f.wire.ledger, withLeaf, time.Now().UTC()) != nil {
		t.Fatal("known new public annotation dictionary refused")
	}
	if captureNativeFixtureShape(h.f.wire.ledger, fixtureRetainedPVC, "retained-marker-learning", o) != nil {
		t.Fatal("closed public marker diagnostic refused")
	}
	files, err := os.ReadDir(dir)
	if err != nil || len(files) != 1 {
		t.Fatal("public diagnostic publication unavailable")
	}
	info, err := files[0].Info()
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("marker diagnostic was not private")
	}
}

func TestRetainedMarkerLearningMissingIdentityAndDualCaptureTamperingSendNothing(t *testing.T) {
	newMarker := retainedMarkerLearningFactory(t)
	for _, fault := range []string{"missing-actor", "wrong-actor", "missing-actor-capture", "wrong-identity", "body", "query", "method"} {
		t.Run(fault, func(t *testing.T) {
			h := newMarker(t)
			w := h.f.wire
			a := w.actors.clients[ordinaryControllerActor]
			switch fault {
			case "missing-actor":
				w.actors.clients[ordinaryControllerActor] = nil
			case "wrong-actor":
				w.actors.clients[ordinaryControllerActor] = w.actors.clients[destroyControllerActor]
			default:
				prior := a.client.Transport
				a.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
					if r.Method != http.MethodPut {
						return prior.RoundTrip(r)
					}
					switch fault {
					case "missing-actor-capture":
						r.Context().Value(attemptKey{}).(*requestAttempt).actor = nil
					case "wrong-identity":
						r.Header.Set("Impersonate-User", "system:serviceaccount:foreign:foreign")
					case "body":
						r.Body = io.NopCloser(strings.NewReader(`{}`))
						r.ContentLength = 2
					case "query":
						r.URL.RawQuery = "dryRun=All"
					case "method":
						r.Method = http.MethodGet
					}
					return prior.RoundTrip(r)
				})
			}
			_, err := retainedMarkerLearningOnce(t.Context(), w)
			if err != ErrFixtures && err != ErrOutcomeUnknown {
				t.Fatal("bad marker authority/request accepted")
			}
			if h.updates != 0 || w.ledger.markerAck || w.ledger.markerEffect || w.ledger.document.RetainedMarker.State != fixtureRetainedMarkerAttempted {
				t.Fatal("bad dual-capture request sent or gained ACK")
			}
		})
	}
}
