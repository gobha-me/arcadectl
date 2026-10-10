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

// Actual native foreground envelope, not manufactured metadata or completed
// GC. This owns a signed replicas-zero parent in the private API-server-only
// environment: no KCM/kubelet, Pods, tokens, worlds or production cluster.
func testBaselineNativeForegroundParent(t *testing.T, ctx context.Context, admin *kubernetes.Clientset, access *HTTPAccess, plan *installrender.Plan) {
	t.Helper()
	contract, err := installcontract.New(plan)
	if err != nil {
		t.Fatal("native signed parent contract unavailable")
	}
	key := deploymentKey(plan.Namespace(), "arcadectl-controller")
	template, err := contract.Template(key, true)
	if err != nil {
		t.Fatal("native signed paused parent unavailable")
	}
	candidate, err := template.Candidate(strings.Repeat("e", 32))
	if err != nil || candidate == nil {
		t.Fatal("native signed paused candidate unavailable")
	}
	replicas, found, specErr := unstructured.NestedInt64(candidate.Object, "spec", "replicas")
	if specErr != nil || !found || replicas != 0 {
		t.Fatal("native parent fixture was not signed replicas-zero")
	}
	ack, err := access.Create(ctx, key, candidate, false)
	if err != nil || ack == nil || !nativeFixtureUID(string(ack.GetUID())) || !baselineParentRV(ack.GetResourceVersion()) {
		t.Fatal("native original parent acknowledgement unavailable")
	}
	uid := ack.GetUID()
	var pending *installstate.Pending
	cleaned := false
	cleanup := func(cleanupCtx context.Context) error {
		live, err := access.Get(cleanupCtx, key)
		if apierrors.IsNotFound(err) {
			return nil
		}
		if err != nil || live == nil || live.GetUID() != uid || !baselineParentRV(live.GetResourceVersion()) {
			return ErrOwnership
		}
		rv := live.GetResourceVersion()
		if live.GetDeletionTimestamp() == nil {
			if template.MatchLive(live, uid) != nil {
				return ErrOwnership
			}
			background := metav1.DeletePropagationBackground
			if admin.AppsV1().Deployments(key.Namespace).Delete(cleanupCtx, key.Name, metav1.DeleteOptions{PropagationPolicy: &background, Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &rv}}) != nil {
				return ErrRead
			}
		} else {
			if !baselineDeletingParent(template, pending, live) {
				return ErrOwnership
			}
			// This private API server has no garbage collector. Remove only
			// its known native finalizer with UID/RV/whole-finalizer CAS tests.
			// No unknown finalizer, replacement or ordinary cluster is touched.
			patch, err := json.Marshal([]map[string]any{
				{"op": "test", "path": "/metadata/uid", "value": string(uid)},
				{"op": "test", "path": "/metadata/resourceVersion", "value": rv},
				{"op": "test", "path": "/metadata/finalizers", "value": []string{"foregroundDeletion"}},
				{"op": "replace", "path": "/metadata/finalizers", "value": []string{}},
			})
			if err != nil {
				return ErrInvalid
			}
			if _, err := admin.AppsV1().Deployments(key.Namespace).Patch(cleanupCtx, key.Name, types.JSONPatchType, patch, metav1.PatchOptions{FieldManager: "arcadectl-installer", FieldValidation: "Strict"}); err != nil {
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
			t.Error("original-only native parent cleanup failed")
		}
	})
	original, err := access.Get(ctx, key)
	if err != nil || original == nil || !reflect.DeepEqual(original.Object, ack.Object) || template.MatchLive(original, uid) != nil {
		t.Fatal("whole independent native parent acknowledgement or signed defaults refused")
	}
	pending = &installstate.Pending{Action: installstate.Delete, Key: key, CreateNonce: strings.Repeat("f", 32), BeforeUID: uid, BeforeResourceVersion: original.GetResourceVersion(), BeforeSHA256: template.Hash()}
	rv := original.GetResourceVersion()
	foreground := metav1.DeletePropagationForeground
	if err := admin.AppsV1().Deployments(key.Namespace).Delete(ctx, key.Name, metav1.DeleteOptions{PropagationPolicy: &foreground, Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &rv}}); err != nil {
		t.Fatal("original native foreground parent DELETE refused")
	}
	deleting, err := access.Get(ctx, key)
	if err != nil || deleting == nil {
		t.Fatal("native foreground envelope unavailable")
	}
	whole := deleting.DeepCopy()
	if !baselineDeletingParent(template, pending, deleting) || !reflect.DeepEqual(whole.Object, deleting.Object) {
		t.Fatal("actual native foreground identity refused or raw evidence changed")
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
			_ = unstructured.SetNestedField(o.Object, "foreign", "spec", "template", "spec", "serviceAccountName")
		},
	} {
		changed := deleting.DeepCopy()
		mutate(changed)
		if baselineDeletingParent(template, pending, changed) {
			t.Fatal("native parent classifier accepted replacement or unsigned deletion envelope")
		}
	}
	if cleanup(ctx) != nil {
		t.Fatal("original native parent finalization or named absence refused")
	}
	cleaned = true
	pods, podErr := admin.CoreV1().Pods(key.Namespace).List(ctx, metav1.ListOptions{})
	sets, setErr := admin.AppsV1().ReplicaSets(key.Namespace).List(ctx, metav1.ListOptions{})
	if podErr != nil || setErr != nil || len(pods.Items) != 0 || len(sets.Items) != 0 {
		t.Fatal("native paused parent fixture created executable descendants")
	}
}
