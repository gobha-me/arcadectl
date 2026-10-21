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
	"strings"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installobserve"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	authv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Genuine independent original actor/WAL checkpoints; native-shaped synthetic
// ACKs and HTTPS objects are not native CREATE, coldness or effect permission.
type fixtureObservationTest struct {
	f            *fixtureWireTest
	gets         [len(fixtureCatalog)]int
	lists        int
	batchVersion string
	rows         func(installobserve.GCResource, []metav1.PartialObjectMetadata) []metav1.PartialObjectMetadata
	afterList    func()
	afterGet     func(int, int)
}

func fixtureObservationFactory(t *testing.T) func(*testing.T) *fixtureObservationTest {
	t.Helper()
	newPreview := fixturePreviewFactory(t)
	return func(t *testing.T) *fixtureObservationTest {
		t.Helper()
		f := newPreview(t)
		acknowledgeAllRecipeFixtures(t, f.wire.ledger)
		created := time.Now().UTC().Truncate(time.Second).Add(-20 * time.Second)
		for slot := range fixtureCatalog {
			f.objects[slot] = fixtureResultExample(t, f.wire.ledger, slot, fixtureStableResult, created)
		}
		h := &fixtureObservationTest{f: f, batchVersion: "v1"}
		base := f.actor.fixtureHandler
		f.actor.fixtureHandler = func(w http.ResponseWriter, r *http.Request) bool {
			namespace := f.actor.request.Snapshot.Anchor().Namespace
			if r.Method == http.MethodGet && r.URL.Path == "/api/v1/namespaces/"+namespace {
				ns, err := f.actor.v.f.access.client.CoreV1().Namespaces().Get(r.Context(), namespace, metav1.GetOptions{})
				if err != nil {
					t.Error("original namespace unavailable")
					w.WriteHeader(500)
					return true
				}
				ns.APIVersion, ns.Kind = "v1", "Namespace"
				_ = json.NewEncoder(w).Encode(ns)
				return true
			}
			if r.Method == http.MethodGet && r.URL.Path == "/api" {
				_ = json.NewEncoder(w).Encode(metav1.APIVersions{TypeMeta: metav1.TypeMeta{Kind: "APIVersions"}, Versions: []string{"v1"}})
				return true
			}
			if r.Method == http.MethodGet && r.URL.Path == "/apis" {
				groups := []metav1.APIGroup{}
				for _, group := range []string{"batch", "arcade.gobha.me", "gc.example.test"} {
					version := "v1"
					if group == "arcade.gobha.me" {
						version = "v1alpha1"
					}
					v := metav1.GroupVersionForDiscovery{GroupVersion: group + "/" + version, Version: version}
					g := metav1.APIGroup{Name: group, Versions: []metav1.GroupVersionForDiscovery{v}, PreferredVersion: v}
					if group == "batch" && h.batchVersion != "v1" {
						v = metav1.GroupVersionForDiscovery{GroupVersion: group + "/" + h.batchVersion, Version: h.batchVersion}
						g.Versions, g.PreferredVersion = append(g.Versions, v), v
					}
					groups = append(groups, g)
				}
				_ = json.NewEncoder(w).Encode(metav1.APIGroupList{TypeMeta: metav1.TypeMeta{Kind: "APIGroupList", APIVersion: "v1"}, Groups: groups})
				return true
			}
			sources := []installobserve.GCResource{}
			for slot := range fixtureCatalog {
				source, err := fixtureGCSource(f.wire.ledger.document.Entries[slot])
				if err != nil {
					t.Error("fixed source unavailable")
					return false
				}
				duplicate := false
				for _, old := range sources {
					duplicate = duplicate || old == source
				}
				if !duplicate {
					sources = append(sources, source)
					if source.GVR.Group == "batch" && h.batchVersion != "v1" {
						source.GVR.Version = h.batchVersion
						sources = append(sources, source)
					}
				}
			}
			custom := installobserve.GCResource{Kind: "Widget"}
			custom.GVR.Group, custom.GVR.Version, custom.GVR.Resource = "gc.example.test", "v1", "widgets"
			sources = append(sources, custom)
			for _, gv := range []string{"v1", "batch/v1", "batch/v1beta1", "arcade.gobha.me/v1alpha1", "gc.example.test/v1"} {
				path := "/apis/" + gv
				if gv == "v1" {
					path = "/api/v1"
				}
				if r.Method != http.MethodGet || r.URL.Path != path {
					continue
				}
				resources := []metav1.APIResource{}
				for _, source := range sources {
					if source.GVR.GroupVersion().String() == gv {
						resources = append(resources, metav1.APIResource{Name: source.GVR.Resource, Kind: source.Kind, Namespaced: true, Verbs: metav1.Verbs{"get", "list", "watch", "create", "delete"}})
					}
				}
				if gv == "arcade.gobha.me/v1alpha1" {
					resources = append(resources, metav1.APIResource{Name: "gamedestroys/status", Kind: "GameDestroy", Namespaced: true, Verbs: metav1.Verbs{"update"}})
				}
				_ = json.NewEncoder(w).Encode(metav1.APIResourceList{TypeMeta: metav1.TypeMeta{Kind: "APIResourceList", APIVersion: "v1"}, GroupVersion: gv, APIResources: resources})
				return true
			}
			if r.URL.Path == "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error("review unavailable")
					return false
				}
				r.Body = io.NopCloser(bytes.NewReader(body))
				var review authv1.SelfSubjectAccessReview
				if json.Unmarshal(body, &review) != nil {
					t.Error("review malformed")
					return false
				}
				for _, source := range sources {
					if reflect.DeepEqual(review.Spec, gcMetadataPermission(source, namespace).spec) {
						if r.Method != http.MethodPost || r.Header.Get("Impersonate-User") != "" {
							t.Error("LIST review escaped original administrator")
						}
						review.Status.Allowed = true
						_ = json.NewEncoder(w).Encode(review)
						return true
					}
				}
			}
			for _, source := range sources {
				prefix := "/apis/" + source.GVR.GroupVersion().String()
				if source.GVR.Group == "" {
					prefix = "/api/" + source.GVR.Version
				}
				if r.Method != http.MethodGet || r.URL.Path != prefix+"/namespaces/"+namespace+"/"+source.GVR.Resource {
					continue
				}
				h.lists++
				if r.Header.Get("Accept") != "application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1" || r.Header.Get("Impersonate-User") != "" || r.URL.Query().Get("limit") != "128" || strings.Contains(r.URL.RawQuery, "Selector") {
					t.Error("metadata escaped fixed unfiltered original read")
				}
				items := []metav1.PartialObjectMetadata{}
				for slot := range fixtureCatalog {
					object := f.objects[slot]
					originalSource, _ := fixtureGCSource(f.wire.ledger.document.Entries[slot])
					if object == nil || originalSource.GVR.GroupResource() != source.GVR.GroupResource() {
						continue
					}
					metadata := fixtureGCMetadata(object)
					metadata.Annotations, metadata.Labels = map[string]string{"private": "PRIVATE-OBSERVATION-CANARY"}, map[string]string{"private": "PRIVATE-OBSERVATION-CANARY"}
					items = append(items, metav1.PartialObjectMetadata{TypeMeta: metav1.TypeMeta{Kind: "PartialObjectMetadata", APIVersion: "meta.k8s.io/v1"}, ObjectMeta: metadata})
				}
				if h.rows != nil {
					items = h.rows(source, items)
				}
				_ = json.NewEncoder(w).Encode(metav1.PartialObjectMetadataList{TypeMeta: metav1.TypeMeta{Kind: "PartialObjectMetadataList", APIVersion: "meta.k8s.io/v1"}, ListMeta: metav1.ListMeta{ResourceVersion: "101"}, Items: items})
				if h.afterList != nil {
					h.afterList()
				}
				return true
			}
			handled := base(w, r)
			if handled && r.Method == http.MethodGet {
				for slot, entry := range f.wire.ledger.document.Entries {
					path, _, _ := fixturePath(entry.Key, false)
					if r.URL.Path == path {
						h.gets[slot]++
						if h.afterGet != nil {
							h.afterGet(slot, h.gets[slot])
						}
					}
				}
			}
			return handled
		}
		return h
	}
}

func TestSettledFixturesOriginalWholeShapeAndCompleteGCComposition(t *testing.T) {
	newObservation := fixtureObservationFactory(t)
	for _, scenario := range []string{"complete", "seed-acknowledged", "reloaded-seed-ack", "benign-custom", "missing-get", "missing-list", "list-rv", "list-owner-name", "wrong-source", "wrong-version", "custom-child", "custom-bridge", "worker-descendant", "whole-shape", "get-list-get-drift", "post-get-wal", "post-get-actor", "post-list-capability", "post-list-marker-ack", "post-list-marker-send", "post-get-marker-ack", "cancelled"} {
		t.Run(scenario, func(t *testing.T) {
			h := newObservation(t)
			f, ctx := h.f, t.Context()
			ledger := f.wire.ledger
			uid := ledger.document.Entries[1].OriginalUID
			seeded := scenario == "seed-acknowledged" || scenario == "reloaded-seed-ack"
			if seeded {
				if ledger.advance(fixtureSeedIntent(t, ledger)) != nil {
					t.Fatal("seed intent unavailable")
				}
				if _, err := f.wire.seedDestroyStatus(ctx); err != nil {
					t.Fatal("original seed unavailable", err)
				}
				// Seed preparation has its own original GET; do not count that as
				// one of this separate read-only composition's twenty whole reads.
				h.gets = [len(fixtureCatalog)]int{}
				if scenario == "reloaded-seed-ack" {
					if ledger.close() != nil {
						t.Fatal("settled seed close unavailable")
					}
					loaded, err := ledger.engine.loadFixtureLedger(ctx, f.actor.request.Snapshot)
					if err != nil {
						t.Fatal("settled seed reload unavailable", err)
					}
					t.Cleanup(func() { _ = loaded.close() })
					wire, err := f.wire.actors.fixtures(ctx, loaded)
					if err != nil {
						t.Fatal("settled reloaded wire unavailable", err)
					}
					f.wire, ledger = wire, loaded
				}
			}
			switch scenario {
			case "missing-get":
				delete(f.objects, 1)
			case "wrong-version":
				h.batchVersion = "v1beta1"
			case "whole-shape":
				f.objects[1].Object["spec"].(map[string]any)["nodeName"] = "untrusted-node"
			case "get-list-get-drift":
				h.afterList = func() { f.objects[6].SetResourceVersion("999") }
			case "post-get-wal":
				h.afterGet = func(slot, count int) {
					if slot == 9 && count == 2 {
						ledger.identity = privatefs.FileIdentity{}
					}
				}
			case "post-get-actor":
				h.afterGet = func(slot, count int) {
					if slot == 9 && count == 2 {
						for key, object := range f.actor.v.f.access.objects {
							if key.Kind == "ServiceAccount" {
								object.SetResourceVersion("999")
								break
							}
						}
					}
				}
			case "post-list-capability":
				h.afterList = func() { ledger.effectSlot = 7 }
			case "post-list-marker-ack":
				h.afterList = func() { ledger.markerAck = true }
			case "post-list-marker-send":
				h.afterList = func() { ledger.markerEffect = true }
			case "post-get-marker-ack":
				h.afterGet = func(slot, count int) {
					if slot == 9 && count == 2 {
						ledger.markerAck = true
					}
				}
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				h.afterList = cancel
			}
			h.rows = func(source installobserve.GCResource, items []metav1.PartialObjectMetadata) []metav1.PartialObjectMetadata {
				filtered := []metav1.PartialObjectMetadata{}
				for _, item := range items {
					if item.UID == uid {
						switch scenario {
						case "missing-list", "wrong-source":
							continue
						case "list-rv":
							item.ResourceVersion = "999"
						case "list-owner-name":
							item.OwnerReferences[0].Name = "wrong-owner-name"
						}
					}
					filtered = append(filtered, item)
				}
				if source.GVR.Group != "gc.example.test" {
					return filtered
				}
				if scenario == "wrong-source" {
					return append(filtered, metav1.PartialObjectMetadata{TypeMeta: metav1.TypeMeta{Kind: "PartialObjectMetadata", APIVersion: "meta.k8s.io/v1"}, ObjectMeta: fixtureGCMetadata(f.objects[1])})
				}
				custom := metav1.PartialObjectMetadata{TypeMeta: metav1.TypeMeta{Kind: "PartialObjectMetadata", APIVersion: "meta.k8s.io/v1"}, ObjectMeta: metav1.ObjectMeta{Name: "custom", Namespace: ledger.document.Entries[0].Key.Namespace, UID: "custom-uid", ResourceVersion: "101"}}
				switch scenario {
				case "benign-custom":
					return append(filtered, custom)
				case "custom-child", "custom-bridge", "worker-descendant":
					root := 0
					if scenario == "worker-descendant" {
						root = 1
					}
					parent := ledger.document.Entries[root]
					custom.OwnerReferences = []metav1.OwnerReference{{APIVersion: parent.Key.APIVersion, Kind: parent.Key.Kind, Name: parent.Key.Name, UID: parent.OriginalUID}}
					filtered = append(filtered, custom)
					if scenario == "custom-bridge" {
						child := custom.DeepCopy()
						child.Name, child.UID = "nested", "nested-uid"
						child.OwnerReferences = []metav1.OwnerReference{{APIVersion: "gc.example.test/v1", Kind: "Widget", Name: custom.Name, UID: custom.UID}}
						filtered = append(filtered, *child)
					}
				}
				return filtered
			}
			unchanged := fixturePreviewUnchanged(t, f)
			identity := ledger.identity
			observation, err := f.wire.settledFixtures(ctx)
			valid := scenario == "complete" || seeded || scenario == "benign-custom"
			if valid {
				if err != nil || observation == nil || observation.wire != f.wire || observation.identity != identity || observation.gc == nil || !bytes.Equal(observation.body, ledger.body) {
					t.Fatal("original settled observation unavailable", err)
				}
				for slot, count := range h.gets {
					if count != 2 || !reflect.DeepEqual(observation.objects[slot].Object, f.objects[slot].Object) {
						t.Fatal("whole GET/LIST/GET evidence incomplete")
					}
				}
				for _, row := range observation.gc.Objects() {
					if row.Metadata.Labels != nil || row.Metadata.Annotations != nil || len(row.Metadata.ManagedFields) != 0 {
						t.Fatal("private metadata escaped composition")
					}
				}
				observation.objects[0].SetResourceVersion("999")
				if f.objects[0].GetResourceVersion() != "101" {
					t.Fatal("observation aliases native objects")
				}
			} else if err != ErrFixtures || observation != nil {
				t.Fatal("drift/unknown descendant supplied original observation", err)
			}
			wantedSeeds := 0
			if seeded {
				wantedSeeds = 1
			}
			if f.creates != 0 || f.deletes != 0 || f.previews != 0 || f.seeds != wantedSeeds || ledger.seedAck || ledger.seedEffect || ledger.engine.fixtureFence(f.actor.request.Snapshot) != ErrFixtures {
				t.Fatal("read composition changed effects, seed authority or active fence")
			}
			ledger.identity, ledger.effectSlot = identity, -1 // Undo only deliberate in-memory test corruption.
			unchanged()
		})
	}
}

func TestSettledFixturesRefusesUnsettledAndSeedUncertaintyBeforeReads(t *testing.T) {
	newObservation := fixtureObservationFactory(t)
	for _, scenario := range []string{"pending-delete", "active-ack", "active-send", "seed-attempted", "seed-send-consumed", "reloaded-seed-attempt", "seed-ack-rv-drift", "acknowledged-active-seed-ack", "acknowledged-active-seed-send"} {
		t.Run(scenario, func(t *testing.T) {
			h := newObservation(t)
			f, ledger := h.f, h.f.wire.ledger
			switch scenario {
			case "pending-delete":
				next, _ := ledger.nextDocument()
				next.Entries[9].State, next.Entries[9].DeleteResourceVersion = fixtureDeleteAttempted, "101"
				if ledger.advance(next) != nil {
					t.Fatal("pending deletion unavailable")
				}
			case "active-ack":
				ledger.ackSlot = 9
			case "active-send":
				ledger.effectSlot = 9
			default:
				if ledger.advance(fixtureSeedIntent(t, ledger)) != nil {
					t.Fatal("pending seed unavailable")
				}
				if scenario == "seed-send-consumed" {
					ledger.seedEffect = false
				}
				if scenario == "reloaded-seed-attempt" {
					if ledger.close() != nil {
						t.Fatal("original close unavailable")
					}
					loaded, err := ledger.engine.loadFixtureLedger(t.Context(), f.actor.request.Snapshot)
					if err != nil {
						t.Fatal("pending seed reload unavailable", err)
					}
					t.Cleanup(func() { _ = loaded.close() })
					wire, err := f.wire.actors.fixtures(t.Context(), loaded)
					if err != nil {
						t.Fatal("pending reload wire unavailable", err)
					}
					f.wire, ledger = wire, loaded
				}
				if scenario == "seed-ack-rv-drift" || strings.HasPrefix(scenario, "acknowledged-active-seed-") {
					if _, err := f.wire.seedDestroyStatus(t.Context()); err != nil {
						t.Fatal("seed ACK unavailable", err)
					}
					h.gets, f.reads = [len(fixtureCatalog)]int{}, 0
					switch scenario {
					case "seed-ack-rv-drift":
						f.objects[9].SetResourceVersion("103")
					case "acknowledged-active-seed-ack":
						ledger.seedAck = true
					case "acknowledged-active-seed-send":
						ledger.seedEffect = true
					}
				}
			}
			unchanged := fixturePreviewUnchanged(t, f)
			if observation, err := f.wire.settledFixtures(t.Context()); err != ErrFixtures || observation != nil {
				t.Fatal("unsettled ownership or seed ACK drift supplied observation", err)
			}
			if scenario != "seed-ack-rv-drift" && (f.reads != 0 || h.lists != 0) {
				t.Fatal("known unsettled state performed fixture reads")
			}
			if f.creates != 0 || f.deletes != 0 || f.previews != 0 || ledger.engine.fixtureFence(f.actor.request.Snapshot) != ErrFixtures {
				t.Fatal("unsettled observation granted effects or retired fence")
			}
			unchanged()
		})
	}
}
