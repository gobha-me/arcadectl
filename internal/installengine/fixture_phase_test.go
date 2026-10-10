// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installobserve"
	"github.com/gobha-me/arcadectl/internal/installstate"
	authv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// Real sealed observer, immutable companion and original actor/WAL transport;
// fake HTTPS objects are NOT native admission, effect or lifecycle certification.
type fixturePhaseTest struct {
	test             *testing.T
	f                *fixtureWireTest
	lists, gets      int
	hide             map[int]bool
	gcRows           func(installobserve.GCResource, []metav1.PartialObjectMetadata) []metav1.PartialObjectMetadata
	afterList        func(int)
	afterAccountList func()
	afterGet         func(int)
	publicGets       int
	afterPublicGet   func(int)
	extra            []*unstructured.Unstructured
}

func fixturePhaseFactory(t *testing.T) func(*testing.T) *fixturePhaseTest {
	return fixturePhaseFactoryWithSetup(t, nil)
}

func fixturePhaseFactoryWithSetup(t *testing.T, setup func(*fixturePhaseTest)) func(*testing.T) *fixturePhaseTest {
	t.Helper()
	seed := newActorFixture(t)
	seed.v.fail = 0
	s := seed.request.Snapshot
	foundService := false
	for step := 0; step < 60; step++ {
		var err error
		s, err = seed.v.l.Step(t.Context(), s, seed.v.opts)
		if err != nil {
			t.Fatal("signed service checkpoint unavailable", err)
		}
		for _, r := range s.Document().Resources {
			foundService = foundService || r.Key.Kind == "Service"
		}
		if foundService && s.Document().Pending == nil {
			break
		}
	}
	if !foundService {
		t.Fatal("signed service checkpoint not reached")
	}
	newPreview := fixturePreviewFactoryFromActor(t, newActorFixtureAtCheckpoint(t, seed.v, s))
	return fixturePhaseFactoryFromWireFactory(t, newPreview, setup)
}

func fixturePhaseFactoryFromWireFactory(t *testing.T, newPreview func(*testing.T) *fixtureWireTest, setup func(*fixturePhaseTest)) func(*testing.T) *fixturePhaseTest {
	t.Helper()
	return func(t *testing.T) *fixturePhaseTest {
		t.Helper()
		f := newPreview(t)
		h := &fixturePhaseTest{test: t, f: f, hide: map[int]bool{}}
		base := f.actor.fixtureHandler
		groups := map[string][]metav1.APIResource{}
		add := func(gv, kind, plural string, namespaced bool) {
			for _, r := range groups[gv] {
				if r.Name == plural {
					return
				}
			}
			groups[gv] = append(groups[gv], metav1.APIResource{Name: plural, Kind: kind, Namespaced: namespaced, Verbs: metav1.Verbs{"get", "list", "watch", "create", "delete", "update"}})
		}
		for _, c := range proofCollections {
			add(c.gv, c.kind, c.plural, c.namespaced)
		}
		for key := range f.actor.v.f.access.objects {
			path, err := resourcePath(key, true)
			if err == nil {
				add(key.APIVersion, key.Kind, path[strings.LastIndex(path, "/")+1:], key.Namespace != "")
			}
		}
		add("v1", "Namespace", "namespaces", false)
		add("gc.example.test/v1", "Widget", "widgets", true)
		add("arcade.gobha.me/v1alpha1", "GameDestroy", "gamedestroys/status", true)
		f.actor.fixtureHandler = func(w http.ResponseWriter, r *http.Request) bool {
			ns := f.actor.request.Snapshot.Anchor().Namespace
			if r.Method == http.MethodGet && r.URL.Path == "/api/v1/namespaces/"+ns {
				n, err := f.actor.v.f.access.client.CoreV1().Namespaces().Get(r.Context(), ns, metav1.GetOptions{})
				if err != nil {
					t.Error("namespace unavailable")
					w.WriteHeader(500)
					return true
				}
				n.APIVersion, n.Kind = "v1", "Namespace"
				encodeStoppedObject(t, w, r, servingObject(t, n))
				return true
			}
			if r.Method == http.MethodGet && r.URL.Path == "/api" {
				_ = json.NewEncoder(w).Encode(metav1.APIVersions{TypeMeta: metav1.TypeMeta{Kind: "APIVersions"}, Versions: []string{"v1"}})
				return true
			}
			if r.Method == http.MethodGet && r.URL.Path == "/apis" {
				list := metav1.APIGroupList{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "APIGroupList"}, Groups: []metav1.APIGroup{}}
				versions := []string{}
				for gv := range groups {
					if gv != "v1" {
						versions = append(versions, gv)
					}
				}
				sort.Strings(versions)
				for _, version := range versions {
					gv, _ := schema.ParseGroupVersion(version)
					v := metav1.GroupVersionForDiscovery{GroupVersion: version, Version: gv.Version}
					list.Groups = append(list.Groups, metav1.APIGroup{Name: gv.Group, Versions: []metav1.GroupVersionForDiscovery{v}, PreferredVersion: v})
				}
				_ = json.NewEncoder(w).Encode(list)
				return true
			}
			for gv, resources := range groups {
				path := "/apis/" + gv
				if gv == "v1" {
					path = "/api/v1"
				}
				if r.Method == http.MethodGet && r.URL.Path == path {
					_ = json.NewEncoder(w).Encode(metav1.APIResourceList{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "APIResourceList"}, GroupVersion: gv, APIResources: resources})
					return true
				}
			}
			if r.URL.Path == "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" {
				body, _ := io.ReadAll(r.Body)
				r.Body = io.NopCloser(bytes.NewReader(body))
				var review authv1.SelfSubjectAccessReview
				if json.Unmarshal(body, &review) != nil {
					t.Error("review unavailable")
					return false
				}
				if attrs := review.Spec.ResourceAttributes; attrs != nil && attrs.Verb == "list" {
					if r.Method != http.MethodPost || r.Header.Get("Impersonate-User") != "" || attrs.Namespace != ns {
						t.Error("metadata review escaped original administrator")
					}
					review.Status.Allowed = true
					_ = json.NewEncoder(w).Encode(review)
					return true
				}
				if attrs := review.Spec.ResourceAttributes; attrs != nil && attrs.Verb == "get" && attrs.Group == "" && attrs.Version == "v1" && attrs.Resource == "serviceaccounts" && attrs.Namespace == ns && r.Header.Get("Impersonate-User") == "" {
					known := false
					for key := range f.actor.v.f.access.objects {
						known = known || key.Kind == "ServiceAccount" && key.Name == attrs.Name
					}
					for _, entry := range f.wire.ledger.document.Entries {
						known = known || entry.Key.Kind == "ServiceAccount" && entry.Key.Name == attrs.Name
					}
					for _, object := range h.extra {
						known = known || object.GetKind() == "ServiceAccount" && object.GetName() == attrs.Name
					}
					review.Status.Allowed = known
					_ = json.NewEncoder(w).Encode(review)
					return true
				}
			}
			for gv, resources := range groups {
				prefix := "/apis/" + gv
				if gv == "v1" {
					prefix = "/api/v1"
				}
				for _, resource := range resources {
					if strings.Contains(resource.Name, "/") {
						continue
					}
					path := prefix
					if resource.Namespaced {
						path += "/namespaces/" + ns
					}
					path += "/" + resource.Name
					if r.Method != http.MethodGet || r.URL.Path != path {
						continue
					}
					items := []any{}
					metadata := []metav1.PartialObjectMetadata{}
					appendObject := func(o *unstructured.Unstructured) {
						if o == nil || o.GetAPIVersion() != gv || o.GetKind() != resource.Kind {
							return
						}
						items = append(items, o.DeepCopy().Object)
						metadata = append(metadata, metav1.PartialObjectMetadata{TypeMeta: metav1.TypeMeta{APIVersion: "meta.k8s.io/v1", Kind: "PartialObjectMetadata"}, ObjectMeta: fixtureGCMetadata(o)})
					}
					for _, o := range f.actor.v.f.access.objects {
						appendObject(o)
					}
					for slot, o := range f.objects {
						if !h.hide[slot] {
							appendObject(o)
						}
					}
					for _, o := range h.extra {
						appendObject(o)
					}
					if strings.Contains(r.Header.Get("Accept"), "PartialObjectMetadataList") {
						if resource.Namespaced && h.gcRows != nil {
							groupVersion, _ := schema.ParseGroupVersion(gv)
							metadata = h.gcRows(installobserve.GCResource{GVR: groupVersion.WithResource(resource.Name), Kind: resource.Kind}, metadata)
						}
						_ = json.NewEncoder(w).Encode(metav1.PartialObjectMetadataList{TypeMeta: metav1.TypeMeta{APIVersion: "meta.k8s.io/v1", Kind: "PartialObjectMetadataList"}, ListMeta: metav1.ListMeta{ResourceVersion: "100"}, Items: metadata})
					} else {
						_ = json.NewEncoder(w).Encode(map[string]any{"apiVersion": gv, "kind": resource.Kind + "List", "metadata": map[string]any{"resourceVersion": "100"}, "items": items})
						if resource.Kind == "ServiceAccount" && h.afterAccountList != nil {
							h.afterAccountList()
						}
					}
					h.lists++
					if h.afterList != nil {
						h.afterList(h.lists)
					}
					return true
				}
			}
			for key, original := range f.actor.v.f.access.objects {
				path, err := resourcePath(key, false)
				if err == nil && r.Method == http.MethodGet && r.URL.Path == path {
					encodeStoppedObject(t, w, r, original.DeepCopy())
					h.publicGets++
					if h.afterPublicGet != nil {
						h.afterPublicGet(h.publicGets)
					}
					return true
				}
			}
			for _, original := range h.extra {
				key := resourceKeyFromObject(original)
				fixture := false
				for _, entry := range f.wire.ledger.document.Entries {
					fixture = fixture || entry.Key == key
				}
				if fixture {
					continue
				} // LIST-only missing-GET control stays meaningful
				path, err := resourcePath(key, false)
				if err == nil && r.Method == http.MethodGet && r.URL.Path == path {
					encodeStoppedObject(t, w, r, original.DeepCopy())
					return true
				}
			}
			handled := base(w, r)
			if handled && r.Method == http.MethodGet {
				for slot, entry := range f.wire.ledger.document.Entries {
					path, _, _ := fixturePath(entry.Key, false)
					if path == r.URL.Path {
						h.gets++
						if h.afterGet != nil {
							h.afterGet(slot)
						}
					}
				}
			}
			return handled
		}
		if setup != nil {
			setup(h)
		}
		initial, err := f.actor.admission.captureInitialPhase(t.Context(), f.actor.request)
		if err != nil {
			t.Fatal("initial sealed phase unavailable", err)
		}
		if f.wire.ledger.document.Recipe == fixtureRecipeV3 {
			// Test-only recipe selection on the legacy engine. The complete
			// production reader still supplies both exact initial collections;
			// this is not baseline runtime-guard or native certification.
			first, err := f.actor.admission.collectPhaseServiceAccounts(t.Context(), f.actor.request)
			if err != nil {
				t.Fatal("initial account collection unavailable", err)
			}
			second, err := f.actor.admission.collectPhaseServiceAccounts(t.Context(), f.actor.request)
			if err != nil || !samePhaseServiceAccounts(first, second) {
				t.Fatal("initial accounts changed", err)
			}
			initial.baseline.Accounts, err = second.baseline(initial.baseline.Public, nil)
			if err != nil {
				t.Fatal("initial accounts floor unavailable", err)
			}
		}
		if initial.seal(f.wire.ledger) != nil {
			t.Fatal("initial sealed phase unavailable", err)
		}
		h.lists = 0
		h.publicGets = 0
		return h
	}
}

func TestFixturePhaseCompleteOriginalAndFixedFixtureAccounting(t *testing.T) {
	newPhase := fixturePhaseFactory(t)
	for _, scenario := range []string{"planned", "original", "missing-companion-phase", "unknown-create", "missing-list", "missing-get", "foreign-same-name", "get-list-rv", "whole-shape", "extra-workload", "custom-descendant", "gc-metadata-drift", "late-world-change", "late-actor-change", "deleted", "delete-present", "absent-orphan"} {
		t.Run(scenario, func(t *testing.T) {
			h := newPhase(t)
			f := h.f
			ledger := f.wire.ledger
			if scenario != "planned" && scenario != "unknown-create" {
				acknowledgeAllRecipeFixtures(t, ledger)
				created := time.Now().UTC().Truncate(time.Second).Add(-20 * time.Second)
				for slot := range fixtureCatalog {
					f.objects[slot] = fixtureResultExample(t, ledger, slot, fixtureStableResult, created)
				}
			}
			switch scenario {
			case "missing-companion-phase": // No unsafe reconstruction of a pre-fixture baseline.
				ledger.document.OriginalWorldsSHA256 = "" // in-memory corruption cannot become accepted evidence
			case "unknown-create":
				next, _ := ledger.nextDocument()
				next.Entries[0].State = fixtureCreateAttempted
				if ledger.advance(next) != nil {
					t.Fatal("intent unavailable")
				}
				ledger.ackSlot, ledger.effectSlot = -1, -1
			case "missing-list":
				h.hide[fixturePlainPod] = true
			case "missing-get":
				delete(f.objects, fixturePlainPod)
				h.extra = append(h.extra, fixtureResultExample(t, ledger, fixturePlainPod, fixtureStableResult, time.Now().UTC().Truncate(time.Second).Add(-20*time.Second)))
			case "foreign-same-name":
				f.objects[fixturePlainPod].SetUID("b0000000-0000-4000-8000-000000000001")
			case "get-list-rv":
				h.afterList = func(n int) {
					if n == 7 {
						f.objects[fixturePlainPod].SetResourceVersion("999")
					}
				}
			case "whole-shape":
				_ = unstructured.SetNestedField(f.objects[fixturePlainPod].Object, "default", "spec", "nodeName")
			case "extra-workload":
				o := f.objects[fixturePlainPod].DeepCopy()
				o.SetName("untracked")
				o.SetUID("b0000000-0000-4000-8000-000000000001")
				h.extra = append(h.extra, o)
			case "custom-descendant", "absent-orphan":
				h.gcRows = func(source installobserve.GCResource, rows []metav1.PartialObjectMetadata) []metav1.PartialObjectMetadata {
					if source.Kind == "Widget" {
						rows = append(rows, metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{Name: "child", Namespace: ledger.document.Entries[6].Key.Namespace, UID: "custom-child", ResourceVersion: "101", OwnerReferences: []metav1.OwnerReference{{APIVersion: "v1", Kind: "Pod", Name: ledger.document.Entries[6].Key.Name, UID: ledger.document.Entries[6].OriginalUID}}}})
					}
					return rows
				}
			case "gc-metadata-drift":
				h.gcRows = func(source installobserve.GCResource, rows []metav1.PartialObjectMetadata) []metav1.PartialObjectMetadata {
					if source.Kind == "Pod" && len(rows) > 0 {
						rows[0].ResourceVersion = "999"
					}
					return rows
				}
			case "late-world-change":
				h.afterGet = func(slot int) {
					if slot == fixtureCancelledDestroy {
						o := f.objects[fixturePlainPVC].DeepCopy()
						o.SetName("foreign-world")
						o.SetUID("b0000000-0000-4000-8000-000000000001")
						h.extra = append(h.extra, o)
						h.afterGet = nil
					}
				}
			case "late-actor-change":
				h.afterGet = func(slot int) {
					if slot == fixtureCancelledDestroy {
						for key, o := range f.actor.v.f.access.objects {
							if key.Kind == "ServiceAccount" {
								o.SetUID("replaced")
								break
							}
						}
						h.afterGet = nil
					}
				}
			}
			if scenario == "deleted" || scenario == "delete-present" || scenario == "absent-orphan" {
				next, _ := ledger.nextDocument()
				next.Entries[6].State = fixtureDeleteAttempted
				next.Entries[6].DeleteResourceVersion = "101"
				if ledger.advance(next) != nil {
					t.Fatal("delete intent unavailable")
				}
				ledger.effectSlot = -1
				if scenario != "delete-present" {
					delete(f.objects, 6)
				}
			}
			body := bytes.Clone(ledger.body)
			identity := ledger.identity
			trace := &admissionTrace{}
			o, err := f.wire.observePhase(context.WithValue(t.Context(), admissionTraceKey{}, trace))
			valid := scenario == "planned" || scenario == "original" || scenario == "deleted"
			if valid && (err != nil || o == nil) || !valid && err != ErrFixtures {
				t.Fatalf("phase %s acceptance incorrect: %v", scenario, err)
			}
			wantRows := map[string]string{"missing-list": "original-row-missing-fixture", "foreign-same-name": "original-row-fixture-identity", "extra-workload": "original-row-floor", "delete-present": "original-row-fixture-identity"}
			if wanted := wantRows[scenario]; wanted != "" {
				if stage, slot := trace.phaseSnapshot(); stage != wanted || slot != -1 {
					t.Fatal("same-attempt row refusal did not retain its closed predicate classification", scenario, stage, slot)
				}
			}
			if !bytes.Equal(body, ledger.body) || identity != ledger.identity || f.creates != 0 || f.deletes != 0 || f.seeds != 0 {
				t.Fatal("observation mutated WAL or issued an effect")
			}
			if valid && (h.gets != 20 || ledger.phaseFloor == nil) {
				t.Fatal("complete repeat or accepted floor missing")
			}
		})
	}
}

func TestFixturePhaseRejectsLegacyWorldOnlyCompanion(t *testing.T) {
	f := newFixtureWireTest(t)
	if f.wire.ledger.sealOriginalWorlds([]fixtureWorldRow{}) != nil {
		t.Fatal("legacy world companion unavailable")
	}
	if o, err := f.wire.observePhase(t.Context()); o != nil || err != ErrFixtures {
		t.Fatal("reconstructed legacy phase")
	}
}

func TestFixturePhasePublicOriginalDriftIncludingSecondPassTail(t *testing.T) {
	newPhase := fixturePhaseFactory(t)
	for _, scenario := range []string{"before-service", "first-service", "second-service", "second-crd"} {
		t.Run(scenario, func(t *testing.T) {
			h := newPhase(t)
			ledger := h.f.wire.ledger
			acknowledgeAllRecipeFixtures(t, ledger)
			created := time.Now().UTC().Truncate(time.Second).Add(-20 * time.Second)
			for slot := range fixtureCatalog {
				h.f.objects[slot] = fixtureResultExample(t, ledger, slot, fixtureStableResult, created)
			}
			mutated := false
			mutate := func() {
				kind := "Service"
				if strings.HasSuffix(scenario, "crd") {
					kind = "CustomResourceDefinition"
				}
				for key, o := range h.f.actor.v.f.access.objects {
					if key.Kind != kind {
						continue
					}
					if kind == "Service" {
						_ = unstructured.SetNestedField(o.Object, "ExternalName", "spec", "type")
					} else {
						_ = unstructured.SetNestedSlice(o.Object, []any{"foreign-version"}, "status", "storedVersions")
					}
					mutated = true
					break
				}
			}
			if strings.HasPrefix(scenario, "before") {
				mutate()
			} else {
				h.afterGet = func(slot int) {
					target := 10
					if strings.HasPrefix(scenario, "second") {
						target = 20
					}
					if h.gets == target {
						mutate()
						h.afterGet = nil
					}
				}
			}
			if o, err := h.f.wire.observePhase(t.Context()); o != nil || err != ErrFixtures || !mutated {
				t.Fatal("accepted same-UID public inventory tail drift", scenario, err)
			}
			if h.f.creates != 0 || h.f.deletes != 0 {
				t.Fatal("public drift issued an effect")
			}
		})
	}
}

func TestFixturePhaseFinalActorReadCannotHideProtectedFileReplacement(t *testing.T) {
	newPhase := fixturePhaseFactory(t)
	control := newPhase(t)
	if _, err := control.f.wire.observePhase(t.Context()); err != nil {
		t.Fatal("positive phase unavailable", err)
	}
	last := control.publicGets
	if last == 0 {
		t.Fatal("no original public reads")
	}
	for _, scenario := range []string{"wal", "companion"} {
		t.Run(scenario, func(t *testing.T) {
			h := newPhase(t)
			ledger := h.f.wire.ledger
			replaced := false
			h.afterPublicGet = func(read int) {
				if read != last {
					return
				}
				if scenario == "wal" {
					if _, err := ledger.engine.files.AtomicWrite(ledger.name, bytes.Clone(ledger.body), &ledger.identity); err != nil {
						t.Error("WAL replacement injection unavailable")
					}
				} else {
					name, _ := ledger.originalWorldsName()
					body, _, err := ledger.engine.files.ReadEvidence(name, 32*1024*1024)
					if err != nil {
						t.Error("companion read unavailable")
						return
					}
					if _, err := ledger.engine.files.AtomicWrite(name, body, ledger.worldIdentity); err != nil {
						t.Error("companion replacement injection unavailable")
					}
				}
				replaced = true
			}
			if o, err := h.f.wire.observePhase(t.Context()); o != nil || err != ErrFixtures || !replaced {
				t.Fatal("final actor read concealed protected file replacement", scenario, err)
			}
			if h.f.creates != 0 || h.f.deletes != 0 || ledger.ackSlot != -1 || ledger.effectSlot != -1 {
				t.Fatal("late-file refusal created an effect capability")
			}
		})
	}
}

func TestFixturePhaseStateReadabilityDoesNotRepairUnknownAcknowledgements(t *testing.T) {
	f := newFixtureWireTest(t)
	ledger := f.wire.ledger
	if !f.wire.phaseReadable() {
		t.Fatal("planned fixed slots refused")
	}
	before := append([]fixtureEntry{}, ledger.document.Entries...)
	for _, state := range []fixtureState{fixtureCreateAttempted, fixtureState("unknown")} {
		ledger.document.Entries[0].State = state
		if f.wire.phaseReadable() {
			t.Fatal("unknown CREATE accepted")
		}
	}
	ledger.document.Entries = before
	for _, flag := range []*bool{&ledger.seedAck, &ledger.seedEffect, &ledger.markerAck, &ledger.markerEffect, &ledger.worldPublication} {
		*flag = true
		if f.wire.phaseReadable() {
			t.Fatal("pending capability accepted")
		}
		*flag = false
	}
	if !reflect.DeepEqual(before, ledger.document.Entries) {
		t.Fatal("readability adopted identity")
	}
}

// Pure dispatch over native-derived whole shapes; this does not authenticate
// the supplied phase or authorize any effect. The bound observer does that.
func TestFixturePhaseDestroyShapeUsesDestroyFamilyNotOrdinaryWarmth(t *testing.T) {
	created := time.Now().UTC().Truncate(time.Second).Add(-30 * time.Second)
	for _, warm := range [][2]bool{{false, false}, {true, false}, {false, true}, {true, true}} {
		f := newFixture(t, false)
		ledger, err := f.engine.prepareFixtureLedger(t.Context(), f.snapshot)
		if err != nil {
			t.Fatal(err)
		}
		acknowledgeAllRecipeFixtures(t, ledger)
		phase := fixturePhaseBaseline{Version: "admission-phase-v1", Rows: []fixtureWorldRow{}, Leaders: []fixturePhaseLeader{}}
		for index, active := range warm {
			if active {
				name := "controller.arcade.gobha.me"
				if index == 1 {
					name = "destroy-controller.arcade.gobha.me"
				}
				phase.Leaders = append(phase.Leaders, fixturePhaseLeader{Row: fixtureWorldRow{Key: installstate.Key{Name: name}}})
			}
		}
		cold := fixtureResultExample(t, ledger, fixtureCancelledDestroy, fixtureStableResult, created)
		hot := fixtureWarmCancelledExample(t, ledger, created, [3]time.Duration{time.Second, 2 * time.Second, 3 * time.Second})
		if (ledger.validatePhaseFixture(fixtureCancelledDestroy, cold, &phase, time.Now().UTC()) == nil) != !warm[1] || (ledger.validatePhaseFixture(fixtureCancelledDestroy, hot, &phase, time.Now().UTC()) == nil) != warm[1] {
			t.Fatal("destroy mode inferred from ordinary family or observed shape")
		}
		if ledger.close() != nil {
			t.Fatal("ledger close unavailable")
		}
	}
}
