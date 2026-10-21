//go:build envtest

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installobserve"
	"github.com/gobha-me/arcadectl/internal/installstate"
	authv1 "k8s.io/api/authorization/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
)

// Native SSAR decisions using actual acknowledged installation access and the
// real three-family descendants in the owned API-server-only fixture. This is
// not a sealed production journal/observer or wired full-runtime-guard proof.
func testBaselineNativeDeniedCatalog(t *testing.T, ctx context.Context, admin *kubernetes.Clientset, access *HTTPAccess, f *fixture, d installstate.Document, c *installobserve.ExecutableCollections) {
	t.Helper()
	witness := map[installstate.Key]admissionIdentity{}
	var originals []installstate.Resource
	cleaned := false
	cleanup := func(ctx context.Context) bool {
		ok := true
		for i := len(originals) - 1; i >= 0; i-- {
			r := originals[i]
			live, err := access.Get(ctx, r.Key)
			if apierrors.IsNotFound(err) {
				continue
			}
			if err != nil || live == nil || live.GetUID() != r.UID || !baselineParentRV(live.GetResourceVersion()) || len(live.GetFinalizers()) != 0 {
				ok = false
				continue
			}
			rv, uid := live.GetResourceVersion(), r.UID
			background := metav1.DeletePropagationBackground
			options := metav1.DeleteOptions{PropagationPolicy: &background, Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &rv}}
			if r.Key.Kind == "ClusterRole" {
				err = admin.RbacV1().ClusterRoles().Delete(ctx, r.Key.Name, options)
			} else {
				err = admin.RbacV1().ClusterRoleBindings().Delete(ctx, r.Key.Name, options)
			}
			if err != nil {
				ok = false
				continue
			}
			if _, err := access.Get(ctx, r.Key); !apierrors.IsNotFound(err) {
				ok = false
			}
		}
		return ok
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if !cleaned && !cleanup(cleanupCtx) {
			t.Error("original-only native catalog RBAC cleanup failed")
		}
	})
	for _, r := range f.plan.Resources() {
		key := resourceKey(r)
		if !accessRetirementKey(key) {
			continue
		}
		live, err := access.Get(ctx, key)
		if apierrors.IsNotFound(err) && (key.Kind == "ClusterRole" || key.Kind == "ClusterRoleBinding") {
			ack, createErr := access.Create(ctx, key, r.Object, false)
			if createErr != nil || ack == nil {
				t.Fatal("signed native original cluster access CREATE refused")
			}
			originals = append(originals, installstate.Resource{Key: key, UID: ack.GetUID()})
			live, err = access.Get(ctx, key)
			if err != nil || live == nil || !reflect.DeepEqual(live.Object, ack.Object) {
				t.Fatal("whole native original cluster acknowledgement changed")
			}
		}
		if err != nil || live == nil || !nativeFixtureUID(string(live.GetUID())) || !baselineParentRV(live.GetResourceVersion()) {
			t.Fatal("native original signed access unavailable")
		}
		template, err := f.engine.contracts[d.TargetPackage].Template(key, false)
		if err != nil {
			t.Fatal("native access template unavailable")
		}
		d.Resources = append(d.Resources, installstate.Resource{Key: key, UID: live.GetUID(), TemplateSHA256: template.Hash(), Phase: template.Phase(), Retained: template.Retained()})
		witness[key] = admissionIdentity{UID: live.GetUID(), ResourceVersion: live.GetResourceVersion(), TemplateSHA256: template.Hash()}
	}
	guarded := map[installstate.Key]*unstructured.Unstructured{}
	for index, list := range []runtime.Object{c.Pods, c.Jobs, c.Deployments, c.ReplicaSets, c.StatefulSets, c.DaemonSets, c.ReplicationControllers, c.CronJobs} {
		items, err := meta.ExtractList(list)
		if err != nil {
			t.Fatal("native catalog executable inventory unavailable")
		}
		collection := baselineExecutableCollections[index]
		for _, item := range items {
			whole := servingObject(t, item)
			// The typed fixture API omitted envelopes; apply only the known
			// literal family here, not production raw-observer certification.
			if whole.GetAPIVersion() == "" && whole.GetKind() == "" {
				whole.SetAPIVersion(collection.gv)
				whole.SetKind(collection.kind)
			}
			key := installstate.Key{APIVersion: collection.gv, Kind: collection.kind, Namespace: d.Namespace, Name: whole.GetName()}
			selected, err := baselineGuardedExecutable(key, whole)
			if err != nil {
				t.Fatal("native catalog executable selection unavailable")
			}
			if selected {
				guarded[key] = whole
			}
		}
	}
	scope, err := f.engine.baselineDeniedCatalog(d, witness, guarded)
	if err != nil {
		t.Fatal("native original denied catalog unavailable")
	}
	for _, actor := range []admissionActor{ordinaryControllerActor, destroyControllerActor} {
		client, err := access.baselineDeniedClient(actor, scope)
		if err != nil {
			t.Fatal("native SSAR-only original actor unavailable")
		}
		for _, row := range scope.rows[actor] {
			if client.authorizationDecision(ctx, authv1.SelfSubjectAccessReviewSpec{ResourceAttributes: row.attributes()}, false) != nil {
				t.Fatal("native signed actor unexpectedly authorized or finite negative review unproved")
			}
		}
	}
	testBaselineNativeProxyRules(t, ctx, admin, access, d.Namespace, guarded)
	if !cleanup(ctx) {
		t.Fatal("original native catalog RBAC absence unproved")
	}
	cleaned = true
}
