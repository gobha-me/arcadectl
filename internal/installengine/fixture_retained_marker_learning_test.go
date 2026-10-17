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
	"time"

	"github.com/go-logr/logr"
	platformkube "github.com/gobha-me/arcadectl/internal/platform/kube"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// TEST ONLY: one fixed original synthetic PVC, existing ordinary software
// identity and named UPDATE right. No production factory/route/provider is
// extended. This PUT learns admission UPDATE bookkeeping; it is not the real
// controller's optimistic-lock PATCH implementation or cleanup permission.
func retainedMarkerLearningOnce(ctx context.Context, w *fixtureWire) (*unstructured.Unstructured, error) {
	if w == nil || w.ledger == nil {
		return nil, ErrFixtures
	}
	f := w.ledger
	f.wireMu.Lock()
	defer f.wireMu.Unlock()
	if !retainedMarkerLearningReady(f) {
		return nil, ErrFixtures
	}
	defer func() { f.markerAck, f.markerEffect = false, false }()
	if ctx == nil || w.current(ctx) != nil {
		return nil, ErrFixtures
	}
	entry := f.document.Entries[fixtureRetainedPVC]
	a := w.actors.clients[ordinaryControllerActor]
	permission, err := actorPermission(entry.Key, probeUpdateOperation)
	if err != nil || a == nil || a.actor == nil || a.actor.actor != ordinaryControllerActor || !a.actor.allows(entry.Key, probeUpdateOperation) || a.base == nil || a.client == nil {
		return nil, ErrFixtures
	}
	parent := w.actors.admission.prerequisites.access
	discovery, err := parent.discover(ctx, entry.Key.APIVersion)
	if err != nil || !discoveredPermission(discovery, permission) || a.authorize(ctx, permission.spec) != nil || w.current(ctx) != nil {
		return nil, ErrFixtures
	}
	live, absent, err := w.getLocked(ctx, fixtureRetainedPVC)
	if err != nil || absent || live == nil || live.GetResourceVersion() != f.document.RetainedMarker.BeforeResourceVersion || f.validateResult(fixtureRetainedPVC, fixtureStableResult, live, time.Now().UTC()) != nil || !retainedMarkerLearningReady(f) || w.current(ctx) != nil {
		return nil, ErrFixtures
	}
	// Every byte is constructor-derived. In particular preserve the certified
	// synthetic binder annotation; never put it on a real/adopted world.
	payload, err := retainedMarkerLearningRecipe(f)
	path, _, pathErr := fixturePath(entry.Key, false)
	if err != nil || pathErr != nil {
		return nil, ErrFixtures
	}
	payload.SetUID(entry.OriginalUID)
	payload.SetResourceVersion(f.document.RetainedMarker.BeforeResourceVersion)
	payload.SetFinalizers([]string{"kubernetes.io/pvc-protection"})
	body, err := json.Marshal(payload.Object)
	if err != nil || len(body) > 65536 {
		return nil, ErrFixtures
	}
	u := *a.base
	u.Path = strings.TrimRight(u.Path, "/") + path
	u.RawQuery = "fieldManager=arcadectl-installer&fieldValidation=Strict"
	identity := fixtureWireIdentity{actor: ordinaryControllerActor, namespace: a.actor.namespace, username: a.actor.username, authorization: a.actor.authorization}
	capture := &fixtureCapture{identity: identity, method: http.MethodPut, url: u.String(), body: body, key: entry.Key, seedUID: entry.OriginalUID, seedBeforeRV: f.document.RetainedMarker.BeforeResourceVersion}
	actor := &actorRequestCapture{identity: *a.actor, method: http.MethodPut, url: u.String(), body: body}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	ctx = logr.NewContext(ctx, logr.Discard())
	ctx = context.WithValue(ctx, attemptKey{}, &requestAttempt{method: http.MethodPut, actor: actor, fixture: capture})
	r, err := http.NewRequestWithContext(ctx, http.MethodPut, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, ErrFixtures
	}
	r.GetBody = nil
	r.Header.Set("Accept", "application/json")
	r.Header.Set("Content-Type", "application/json")
	f.markerEffect = false // consume BEFORE Do, shared by all clients/rebuilds
	response, requestErr := a.client.Do(r)
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	if capture.seedAcknowledgedRV == "" || capture.seedUID != entry.OriginalUID || capture.uid != "" {
		return nil, ErrOutcomeUnknown
	}
	next, err := f.nextDocument()
	if err != nil || next.RetainedMarker == nil {
		return nil, ErrFixtures
	}
	next.RetainedMarker.State = fixtureRetainedMarkerAcknowledged
	next.RetainedMarker.AcknowledgedResourceVersion = capture.seedAcknowledgedRV
	// Reliable ACK is durable before ANY later wrapper/witness/privacy refusal.
	if f.advance(next) != nil || requestErr != nil || !capture.success || w.current(ctx) != nil || capture.result == nil || capture.result.GetResourceVersion() != f.document.RetainedMarker.AcknowledgedResourceVersion {
		return nil, ErrFixtures
	}
	return capture.result.DeepCopy(), nil // diagnostic only, NOT whole acceptance
}

func retainedMarkerLearningReady(f *fixtureLedger) bool {
	if f == nil || !f.markerAck || !f.markerEffect || f.seedAck || f.seedEffect || f.ackSlot != -1 || f.effectSlot != -1 || f.document.RetainedMarker == nil || f.document.RetainedMarker.State != fixtureRetainedMarkerAttempted {
		return false
	}
	_, err := f.object(fixtureRetainedPVC) // validates canonical protected evidence
	return err == nil && validFixtureRetainedMarkerDocument(f.document)
}

func retainedMarkerLearningRecipe(f *fixtureLedger) (*unstructured.Unstructured, error) {
	if f == nil || f.document.RetainedMarker == nil {
		return nil, ErrFixtures
	}
	o, err := f.object(fixtureRetainedPVC)
	if err != nil {
		return nil, ErrFixtures
	}
	annotations := o.GetAnnotations()
	annotations[platformkube.AnnotationColdBackupUID] = f.document.RunID
	o.SetAnnotations(annotations)
	return o, nil
}

// PRIVATE diagnostic/privacy gate only. Do not infer post-update MF count,
// order or ownership from a pre-update example. Closed public attribute/path
// dictionaries bound learning bytes; actual native records must be inspected
// before a separate exact production whole-shape contract is introduced.
func retainedMarkerLearningPublic(f *fixtureLedger, o *unstructured.Unstructured, observed time.Time) error {
	if f == nil || o == nil || len(f.document.Entries) != len(fixtureCatalog) || observed.IsZero() || observed.Year() < 1 || observed.Year() > 9999 || f.document.RetainedMarker == nil || f.document.RetainedMarker.State != fixtureRetainedMarkerAcknowledged || o.GetResourceVersion() != f.document.RetainedMarker.AcknowledgedResourceVersion || o.GetUID() != f.document.Entries[fixtureRetainedPVC].OriginalUID {
		return ErrFixtures
	}
	want, err := retainedMarkerLearningRecipe(f)
	var typed corev1.PersistentVolumeClaim
	fields, found, fieldsErr := unstructured.NestedSlice(o.Object, "metadata", "managedFields")
	if err != nil || decodeServing(o, &typed) != nil || fieldsErr != nil || !found || len(fields) == 0 || len(fields) > 8 || !reflect.DeepEqual(o.Object["spec"], want.Object["spec"]) || !reflect.DeepEqual(o.Object["status"], map[string]any{"phase": "Lost"}) {
		return ErrFixtures
	}
	creation := o.GetCreationTimestamp().Time
	rawMetadata, ok := o.Object["metadata"].(map[string]any)
	if !ok || !fixtureResultTime(rawMetadata["creationTimestamp"], creation, observed.UTC().Add(time.Second)) || creation.IsZero() {
		return ErrFixtures
	}
	seen := map[string]bool{}
	for _, raw := range fields {
		field, ok := raw.(map[string]any)
		if !ok || !fixtureResultTime(field["time"], creation, observed.UTC().Add(time.Second)) {
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
			allowed = fixtureResultFieldset(want)
		case "kube-controller-manager:status":
			allowed = map[string]any{"f:status": fixtureFieldLeaves("phase")}
		default:
			return ErrFixtures
		}
		if !managerOK || seen[role] || !warmSeedLearningFieldSubset(field["fieldsV1"], allowed) {
			return ErrFixtures
		}
		seen[role] = true
		expected := map[string]any{"manager": manager, "operation": "Update", "apiVersion": "v1", "fieldsType": "FieldsV1", "fieldsV1": field["fieldsV1"], "time": field["time"]}
		if present {
			expected["subresource"] = "status"
		}
		if !reflect.DeepEqual(field, expected) {
			return ErrFixtures
		}
	}
	metadata := map[string]any{"name": want.GetName(), "namespace": want.GetNamespace(), "uid": string(o.GetUID()), "resourceVersion": o.GetResourceVersion(), "creationTimestamp": creation.UTC().Format(time.RFC3339), "managedFields": fields, "finalizers": []any{"kubernetes.io/pvc-protection"}}
	for _, key := range []string{"labels", "annotations", "ownerReferences"} {
		if value, present := want.Object["metadata"].(map[string]any)[key]; present {
			metadata[key] = value
		}
	}
	expected := map[string]any{"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": metadata, "spec": want.Object["spec"], "status": map[string]any{"phase": "Lost"}}
	if !reflect.DeepEqual(o.Object, expected) {
		return ErrFixtures
	}
	return nil
}

// TEST-only before/after learning delta, never an ordinary observation filter.
// Managed-field bookkeeping is deliberately learned rather than repaired into
// production acceptance. Every other raw field, including creation time, must
// remain EXACTLY the original pre-write body.
func retainedMarkerLearningDelta(f *fixtureLedger, before, after *unstructured.Unstructured, observed time.Time) error {
	if before == nil || after == nil || f == nil || f.validateResult(fixtureRetainedPVC, fixtureStableResult, before, observed) != nil || retainedMarkerLearningPublic(f, after, observed) != nil {
		return ErrFixtures
	}
	copy := after.DeepCopy()
	annotations := copy.GetAnnotations()
	if annotations[platformkube.AnnotationColdBackupUID] != f.document.RunID {
		return ErrFixtures
	}
	delete(annotations, platformkube.AnnotationColdBackupUID)
	copy.SetAnnotations(annotations)
	copy.SetResourceVersion(before.GetResourceVersion())
	original := before.DeepCopy()
	copy.Object["metadata"].(map[string]any)["managedFields"] = original.Object["metadata"].(map[string]any)["managedFields"]
	if !reflect.DeepEqual(copy.Object, before.Object) {
		return ErrFixtures
	}
	return nil
}
