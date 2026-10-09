//go:build envtest

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installcontract"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

// Native signed Service allocation and foreground envelope in the exact-owned
// API-server-only fixture. No executor, token, controller, storage or Captain.
func testBaselineNativeForegroundService(t *testing.T, ctx context.Context, admin *kubernetes.Clientset, access *HTTPAccess, plan *installrender.Plan) {
	t.Helper()
	contract, err := installcontract.New(plan)
	if err != nil {
		t.Fatal("native signed metadata contract unavailable")
	}
	key := installstate.Key{APIVersion: "v1", Kind: "Service", Namespace: plan.Namespace(), Name: "arcadectl-api"}
	template, err := contract.Template(key, false)
	if err != nil {
		t.Fatal("native signed API Service unavailable")
	}
	// Some supported native Service storage deletes same-name legacy Endpoints
	// upon finalization. Assert absence before ANY DELETE, including cleanup.
	noEndpoints := func(checkCtx context.Context) bool {
		_, err := admin.CoreV1().Endpoints(key.Namespace).Get(checkCtx, key.Name, metav1.GetOptions{})
		return apierrors.IsNotFound(err)
	}
	if !noEndpoints(ctx) {
		t.Fatal("native isolated Service address has unowned Endpoints")
	}
	candidate, err := template.Candidate(strings.Repeat("e", 32))
	if err != nil {
		t.Fatal("native signed Service candidate unavailable")
	}
	ack, err := access.Create(ctx, key, candidate, false)
	if err != nil || ack == nil || ack.GetName() != key.Name || ack.GetNamespace() != key.Namespace || ack.GetKind() != key.Kind || ack.GetAPIVersion() != key.APIVersion || !nativeFixtureUID(string(ack.GetUID())) || !baselineParentRV(ack.GetResourceVersion()) {
		t.Fatal("native signed Service original acknowledgement unavailable")
	}
	uid := ack.GetUID()
	var pending *installstate.Pending
	cleaned := false
	cleanup := func(cleanupCtx context.Context) error {
		live, err := access.Get(cleanupCtx, key)
		if apierrors.IsNotFound(err) {
			return nil
		}
		if err != nil || live == nil || live.GetUID() != uid || !baselineParentRV(live.GetResourceVersion()) || !noEndpoints(cleanupCtx) {
			return ErrOwnership
		}
		rv := live.GetResourceVersion()
		if live.GetDeletionTimestamp() == nil {
			if template.MatchLive(live, uid) != nil {
				return ErrOwnership
			}
			background := metav1.DeletePropagationBackground
			if admin.CoreV1().Services(key.Namespace).Delete(cleanupCtx, key.Name, metav1.DeleteOptions{PropagationPolicy: &background, Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &rv}}) != nil {
				return ErrRead
			}
		} else {
			if !baselineDeletingOriginal(template, pending, live) {
				return ErrOwnership
			}
			patch, err := json.Marshal([]map[string]any{
				{"op": "test", "path": "/metadata/uid", "value": string(uid)},
				{"op": "test", "path": "/metadata/resourceVersion", "value": rv},
				{"op": "test", "path": "/metadata/finalizers", "value": []string{"foregroundDeletion"}},
				{"op": "replace", "path": "/metadata/finalizers", "value": []string{}},
			})
			if err != nil {
				return ErrInvalid
			}
			if _, err := admin.CoreV1().Services(key.Namespace).Patch(cleanupCtx, key.Name, types.JSONPatchType, patch, metav1.PatchOptions{FieldManager: "arcadectl-installer", FieldValidation: "Strict"}); err != nil {
				return ErrRead
			}
		}
		if _, err := access.Get(cleanupCtx, key); !apierrors.IsNotFound(err) {
			return ErrRead
		}
		return nil
	}
	t.Cleanup(func() {
		if cleaned {
			return
		}
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if cleanup(cleanupCtx) != nil {
			t.Error("original-only native Service cleanup failed")
		}
	})
	original, err := access.Get(ctx, key)
	if err != nil || original == nil || !reflect.DeepEqual(original.Object, ack.Object) || template.MatchLive(original, uid) != nil {
		t.Fatal("whole native Service acknowledgement or allocated signed shape refused")
	}
	pods, podErr := admin.CoreV1().Pods(key.Namespace).List(ctx, metav1.ListOptions{})
	slices, sliceErr := admin.DiscoveryV1().EndpointSlices(key.Namespace).List(ctx, metav1.ListOptions{})
	if podErr != nil || sliceErr != nil || len(pods.Items) != 0 || len(slices.Items) != 0 || !noEndpoints(ctx) {
		t.Fatal("native isolated Service fixture has runtime or endpoint consumers")
	}
	pending = &installstate.Pending{Action: installstate.Delete, Key: key, CreateNonce: strings.Repeat("f", 32), BeforeUID: uid, BeforeResourceVersion: original.GetResourceVersion(), BeforeSHA256: template.Hash()}
	if !baselineDeletingOriginal(template, pending, original) {
		t.Fatal("native original Service before DELETE refused")
	}
	rv := original.GetResourceVersion()
	foreground := metav1.DeletePropagationForeground
	if admin.CoreV1().Services(key.Namespace).Delete(ctx, key.Name, metav1.DeleteOptions{PropagationPolicy: &foreground, Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &rv}}) != nil {
		t.Fatal("native original foreground Service DELETE refused")
	}
	deleting, err := access.Get(ctx, key)
	if err != nil || deleting == nil {
		t.Fatal("native foreground Service envelope unavailable")
	}
	whole := deleting.DeepCopy()
	if !baselineDeletingOriginal(template, pending, deleting) || !reflect.DeepEqual(whole.Object, deleting.Object) || !reflect.DeepEqual(original.Object["spec"], deleting.Object["spec"]) {
		t.Fatal("native Service envelope or exact allocation changed")
	}
	for _, mutate := range []func(*unstructured.Unstructured){
		func(o *unstructured.Unstructured) { o.SetUID("foreign-same-name") },
		func(o *unstructured.Unstructured) { o.SetResourceVersion(rv) },
		func(o *unstructured.Unstructured) { o.SetFinalizers([]string{"foreign.example/hold"}) },
		func(o *unstructured.Unstructured) {
			o.SetFinalizers([]string{"foregroundDeletion", "foreign.example/hold"})
		},
		func(o *unstructured.Unstructured) { grace := int64(1); o.SetDeletionGracePeriodSeconds(&grace) },
		func(o *unstructured.Unstructured) {
			_ = unstructured.SetNestedField(o.Object, "foreign", "spec", "selector", "app")
		},
		func(o *unstructured.Unstructured) {
			_ = unstructured.SetNestedField(o.Object, "10.96.0.99", "spec", "clusterIP")
		},
		func(o *unstructured.Unstructured) {
			_ = unstructured.SetNestedField(o.Object, []any{}, "spec", "ports")
		},
	} {
		changed := deleting.DeepCopy()
		mutate(changed)
		if baselineDeletingOriginal(template, pending, changed) {
			t.Fatal("native Service classifier accepted replacement or unsigned deletion shape")
		}
	}
	if cleanup(ctx) != nil {
		t.Fatal("native original Service finalization or named absence failed")
	}
	cleaned = true
}
