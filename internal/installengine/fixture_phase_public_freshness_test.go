// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installobserve"
	"github.com/gobha-me/arcadectl/internal/installstate"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	strictjson "sigs.k8s.io/json"
)

// Trusted synthetic reply mutation, preserving integers and case before the
// real strict serving decoder. No fabricated signed plan or observation seal.
func publicInventoryReplyFault(t *testing.T, response *http.Response, change func(*unstructured.Unstructured)) (*http.Response, error) {
	t.Helper()
	if response == nil || response.Body == nil {
		return nil, ErrRead
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 4*1024*1024+1))
	_ = response.Body.Close()
	var object unstructured.Unstructured
	if err != nil || len(body) > 4*1024*1024 || strictjson.UnmarshalCaseSensitivePreserveInts(body, &object.Object) != nil {
		return nil, ErrRead
	}
	change(&object)
	body, err = json.Marshal(object.Object)
	if err != nil {
		return nil, ErrRead
	}
	copyResponse := *response
	copyResponse.Body = io.NopCloser(bytes.NewReader(body))
	copyResponse.ContentLength = int64(len(body))
	return &copyResponse, nil
}

func TestPublicInventoryNativeRechecksFreshWholeReplies(t *testing.T) {
	newPhase := fixturePhaseFactory(t)
	for _, mode := range []string{"uid", "service-spec", "service-unknown", "crd-storage", "crd-spec", "crd-case", "namespace-uid", "namespace-rv", "namespace-journal", "rv-witness"} {
		t.Run(mode, func(t *testing.T) {
			h := newPhase(t)
			a, request := h.f.actor.admission, h.f.actor.request
			kind := "Service"
			if mode == "crd-storage" || mode == "crd-spec" || mode == "crd-case" {
				kind = "CustomResourceDefinition"
			} else if mode == "namespace-uid" || mode == "namespace-rv" || mode == "namespace-journal" {
				kind = "Namespace"
			}
			path := ""
			for _, entry := range request.Snapshot.Document().Resources {
				if entry.Key.Kind == kind {
					var err error
					path, err = resourcePath(entry.Key, false)
					if err != nil {
						t.Fatal(err)
					}
					break
				}
			}
			if path == "" {
				t.Fatal("genuine recorded original unavailable")
			}
			before, err := a.phasePublicInventory(t.Context(), request)
			if err != nil {
				t.Fatal("warm public witness unavailable", err)
			}
			access := a.prerequisites.access
			copyClient := *access.client
			next := copyClient.Transport
			var injected atomic.Int32
			copyClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				response, err := next.RoundTrip(r)
				if err != nil || r.URL.Path != path {
					return response, err
				}
				injected.Add(1)
				return publicInventoryReplyFault(t, response, func(o *unstructured.Unstructured) {
					switch mode {
					case "uid", "namespace-uid":
						o.SetUID("replacement-original")
					case "service-spec":
						_ = unstructured.SetNestedField(o.Object, "ExternalName", "spec", "type")
					case "service-unknown":
						_ = unstructured.SetNestedField(o.Object, true, "spec", "foreignField")
					case "crd-storage":
						_ = unstructured.SetNestedSlice(o.Object, []any{"foreign-version"}, "status", "storedVersions")
					case "crd-spec":
						_ = unstructured.SetNestedField(o.Object, "foreign.example.test", "spec", "group")
					case "crd-case":
						o.Object["Status"] = o.Object["status"]
						delete(o.Object, "status")
					case "namespace-rv", "rv-witness":
						if o.GetResourceVersion() == "999999" {
							o.SetResourceVersion("999998")
						} else {
							o.SetResourceVersion("999999")
						}
					case "namespace-journal":
						annotations := o.GetAnnotations()
						annotations[installstate.Annotation] += " "
						o.SetAnnotations(annotations)
					}
				})
			})
			access.client = &copyClient
			after, err := a.phasePublicInventory(t.Context(), request)
			if injected.Load() != 1 {
				t.Fatal("fault did not reach exactly one fresh original reply")
			}
			if mode == "rv-witness" || mode == "crd-case" {
				// A single read is not an RV lock. It must expose the changed
				// complete row for the caller's paired/floor comparisons.
				// The existing CRD decoder also accepts this case alias;
				// preserve its serial result, not an invented stricter oracle.
				if err != nil || len(after) != len(before) || reflect.DeepEqual(after, before) {
					t.Fatal("fresh whole-row change was hidden or treated as a cached lock", err)
				}
				original := a.prerequisites.engine.access
				a.prerequisites.engine.access = publicInventorySerialAccess{original}
				serial, serialErr := a.phasePublicInventory(t.Context(), request)
				a.prerequisites.engine.access = original
				if serialErr != nil || !reflect.DeepEqual(after, serial) || injected.Load() != 2 {
					t.Fatal("native changed-row witness differs from original serial semantics", serialErr)
				}
			} else if after != nil || err != ErrFixtures {
				t.Fatal("warm public cache hid a fresh original refusal", mode, err)
			}
		})
	}
}

func TestPublicInventoryNativeKeepsCompleteGCCorrelation(t *testing.T) {
	newPhase := fixturePhaseFactory(t)
	for _, mode := range []string{"missing", "empty", "duplicate", "kind", "group", "plural", "metadata", "uid-alias-after-match", "address-alias-after-match"} {
		t.Run(mode, func(t *testing.T) {
			h := newPhase(t)
			a, request := h.f.actor.admission, h.f.actor.request
			gc, err := h.f.wire.gcMetadata(t.Context())
			if err != nil {
				t.Fatal("real metadata collector unavailable", err)
			}
			rows := gc.Objects()
			selected := -1
			for i, row := range rows {
				if row.Source.Kind == "Service" {
					selected = i
					break
				}
			}
			if selected < 0 {
				t.Fatal("recorded Service missing from complete GC collection")
			}
			original := a.prerequisites.engine.access
			a.prerequisites.engine.access = publicInventorySerialAccess{original}
			want, err := a.phasePublicInventoryAgainstGC(t.Context(), request, rows)
			a.prerequisites.engine.access = original
			got, nativeErr := a.phasePublicInventoryAgainstGC(t.Context(), request, rows)
			if err != nil || nativeErr != nil || !reflect.DeepEqual(got, want) {
				t.Fatal("native complete GC public witness differs from serial oracle", err, nativeErr)
			}
			alias := rows[selected]
			alias.Metadata = *alias.Metadata.DeepCopy()
			switch mode {
			case "missing":
				rows = append(rows[:selected], rows[selected+1:]...)
			case "empty":
				rows = []installobserve.GCObject{}
			case "duplicate":
				rows = append(rows, alias)
			case "kind":
				rows[selected].Source.Kind = "Widget"
			case "group":
				rows[selected].Source.GVR.Group = "foreign.example.test"
			case "plural":
				rows[selected].Source.GVR.Resource = "foreignservices"
			case "metadata":
				rows[selected].Metadata.ResourceVersion = "changed-rv"
			case "uid-alias-after-match":
				alias.Source.Kind = "Widget"
				alias.Metadata.Name = "other-address"
				rows = append(rows, alias)
			case "address-alias-after-match":
				alias.Metadata.UID = "replacement-uid"
				rows = append(rows, alias)
			}
			if result, err := a.phasePublicInventoryAgainstGC(t.Context(), request, rows); result != nil || err != ErrFixtures {
				t.Fatal("partial/projected GC correlation accepted", mode, err)
			}
		})
	}
}

func TestPublicInventoryNativeFreezesAllRecordedAuthorityBeforeGET(t *testing.T) {
	h := fixturePhaseFactory(t)(t)
	a, request := h.f.actor.admission, h.f.actor.request
	var last installstate.Resource
	for _, resource := range request.Snapshot.Document().Resources {
		if resource.Key.Kind != "Secret" && !phaseCollectionKey(resource.Key) {
			last = resource
		}
	}
	if last.Key.Kind == "" {
		t.Fatal("no recorded public authority")
	}
	delete(a.prerequisites.engine.templates[last.Key], last.TemplateSHA256)
	var gets atomic.Int32
	access := a.prerequisites.access
	copyClient := *access.client
	next := copyClient.Transport
	copyClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		gets.Add(1)
		return next.RoundTrip(r)
	})
	access.client = &copyClient
	if rows, err := a.phasePublicInventory(t.Context(), request); rows != nil || err != ErrFixtures || gets.Load() != 0 {
		t.Fatal("missing later compiled original authority started a partial lane")
	}
}

func TestPublicInventoryNativeGenuineUpgradeKeepsRecordedCRDs(t *testing.T) {
	previous, target := lifecycleTransitionPlans(t)
	v := newLifecycleFixturePlans(t, previous, target)
	snapshot := v.finish(t, v.f.snapshot)
	var err error
	snapshot, err = v.l.Begin(t.Context(), snapshot, installstate.Upgrade, target.Digest(), v.opts)
	if err != nil {
		t.Fatal("genuine upgrade did not begin", err)
	}
	v.fail = AdmissionEffective
	stopped := false
	for range 100 {
		next, stepErr := v.l.Step(t.Context(), snapshot, v.opts)
		snapshot = next
		if stepErr != nil {
			if !errors.Is(stepErr, ErrLifecycle) || len(v.checks) == 0 || v.checks[len(v.checks)-1] != AdmissionEffective {
				t.Fatal("genuine upgrade failed before admission checkpoint", stepErr)
			}
			stopped = true
			break
		}
	}
	if !stopped {
		t.Fatal("genuine upgrade did not reach admission checkpoint")
	}
	f := newActorFixtureAtCheckpointPlans(t, v, snapshot, previous, target)
	a, request := f.admission, f.request
	d := request.Snapshot.Document()
	if request.Mode != installstate.Upgrade || d.ActivePackage != previous.Digest() || d.TargetPackage != target.Digest() || d.ActivePackage == d.TargetPackage || d.Pending != nil || a.prerequisites.engine.access != a.prerequisites.access || !a.prerequisites.access.actorCompatible() {
		t.Fatal("fixture is not a genuine eligible mixed upgrade")
	}
	_, paths := publicInventoryTestPaths(t, request)
	body, rv := request.Snapshot.Bytes(), request.Snapshot.ResourceVersion()
	writes, nsWrites := v.f.access.writes, v.f.nsUpdates
	e := a.prerequisites.engine
	original := e.access
	e.access = publicInventorySerialAccess{original}
	want, err := a.phasePublicInventory(t.Context(), request)
	e.access = original
	got, nativeErr := a.phasePublicInventory(t.Context(), request)
	if err != nil || nativeErr != nil || len(got) != len(paths) || !reflect.DeepEqual(got, want) {
		t.Fatal("mixed original public inventory differs from serial oracle", err, nativeErr)
	}
	crds := 0
	for _, entry := range d.Resources {
		if entry.Key.Kind != "CustomResourceDefinition" {
			continue
		}
		crds++
		recorded, template := e.inventory(d, entry.Key)
		previousTemplate, previousErr := e.contracts[previous.Digest()].Template(entry.Key, false)
		targetTemplate, targetErr := e.contracts[target.Digest()].Template(entry.Key, false)
		// The compiled legacy/current CRD assets are byte-identical. This
		// tests genuine package identity/recorded lookup and compatibility,
		// not a fabricated differing-schema transition.
		if recorded == nil || template == nil || previousErr != nil || targetErr != nil || template.Hash() != entry.TemplateSHA256 || template.Hash() != previousTemplate.Hash() || previousTemplate.Hash() != targetTemplate.Hash() || template.CheckCRD(v.f.access.objects[entry.Key], entry.UID, targetTemplate) != nil {
			t.Fatal("mixed original CRD authority or compatibility changed")
		}
		found := false
		for _, row := range got {
			if row.Key == entry.Key && row.UID == entry.UID {
				found = true
			}
		}
		if !found {
			t.Fatal("mixed original CRD identity omitted")
		}
	}
	if crds == 0 || !bytes.Equal(body, request.Snapshot.Bytes()) || rv != request.Snapshot.ResourceVersion() || writes != v.f.access.writes || nsWrites != v.f.nsUpdates {
		t.Fatal("mixed public read omitted CRDs or changed the journal/effects")
	}
}
