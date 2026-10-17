//go:build envtest

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"
)

// Actual authenticated GC admission requests in an owned API-only environment.
// No controller-manager/kubelet runs: replicas-zero parents create no Pods or
// worlds. This proves finalizer PATCH admission and exact original absence,
// not native controller-driven Deployment -> ReplicaSet -> Pod garbage collection.
func testStandaloneGarbageCollectorUpdateBoundary(t *testing.T, ctx context.Context,
	admin, gc, nonadmin, ordinary *kubernetes.Clientset, namespace string, installed *appsv1.Deployment,
	actorCan func(*kubernetes.Clientset, string, string, string, string, string, bool)) {
	t.Helper()
	patch := func(client *kubernetes.Clientset, plural, name string, body map[string]any, dry bool) error {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal("closed GC patch encoding unavailable")
		}
		options := metav1.PatchOptions{FieldValidation: "Strict", FieldManager: "arcadectl-gc-proof"}
		if dry {
			options.DryRun = []string{metav1.DryRunAll}
		}
		return client.AppsV1().RESTClient().Patch(types.MergePatchType).Namespace(namespace).Resource(plural).Name(name).
			VersionedParams(&options, scheme.ParameterCodec).Body(encoded).Do(ctx).Error()
	}
	get := func(plural, name string) (*unstructured.Unstructured, error) {
		live := &unstructured.Unstructured{}
		err := admin.AppsV1().RESTClient().Get().Namespace(namespace).Resource(plural).Name(name).Do(ctx).Into(live)
		return live, err
	}
	deny := func(family string, err error) {
		t.Helper()
		if !baselineDenial(err, family, namespace) {
			t.Fatal("GC negative request lacked the exact baseline policy/binding/message denial")
		}
	}
	for _, row := range []struct{ kind, plural, family string }{
		{"Deployment", "deployments", "template"}, {"ReplicaSet", "replicasets", "replicaset"},
	} {
		t.Run("gc-update-"+row.kind, func(t *testing.T) {
			name := "owned-gc-" + row.plural
			meta := metav1.ObjectMeta{Name: name, Namespace: namespace}
			var desired runtime.Object
			if row.kind == "Deployment" {
				owner := &appsv1.Deployment{TypeMeta: metav1.TypeMeta{APIVersion: "apps/v1", Kind: row.kind}, ObjectMeta: meta, Spec: *installed.Spec.DeepCopy()}
				owner.Spec.Replicas = ptr.To(int32(0))
				desired = owner
				if _, err := admin.AppsV1().Deployments(namespace).Create(ctx, owner, metav1.CreateOptions{}); err != nil {
					t.Fatal("owned inert GC Deployment unavailable")
				}
			} else {
				owner := &appsv1.ReplicaSet{TypeMeta: metav1.TypeMeta{APIVersion: "apps/v1", Kind: row.kind}, ObjectMeta: meta,
					Spec: appsv1.ReplicaSetSpec{Replicas: ptr.To(int32(0)), Selector: installed.Spec.Selector.DeepCopy(), Template: *installed.Spec.Template.DeepCopy()}}
				desired = owner
				if _, err := admin.AppsV1().ReplicaSets(namespace).Create(ctx, owner, metav1.CreateOptions{}); err != nil {
					t.Fatal("owned inert GC ReplicaSet unavailable")
				}
			}
			original, err := get(row.plural, name)
			if err != nil || original.GetUID() == "" || !baselineParentRV(original.GetResourceVersion()) {
				t.Fatal("independent original GC owner unavailable")
			}
			uid := original.GetUID()
			t.Cleanup(func() {
				live, err := get(row.plural, name)
				if apierrors.IsNotFound(err) {
					return
				}
				if err != nil || live.GetUID() != uid || !reflect.DeepEqual(live.Object["spec"], original.Object["spec"]) || !baselineParentRV(live.GetResourceVersion()) {
					t.Error("refusing cleanup of a replaced/altered GC fixture")
					return
				}
				finalizers := live.GetFinalizers()
				if len(finalizers) != 0 && !reflect.DeepEqual(finalizers, []string{metav1.FinalizerDeleteDependents}) {
					t.Error("refusing unowned GC fixture finalizer cleanup")
					return
				}
				if len(finalizers) != 0 {
					if patch(admin, row.plural, name, map[string]any{"metadata": map[string]any{"uid": string(uid), "resourceVersion": live.GetResourceVersion(), "finalizers": []string{}}}, false) != nil {
						t.Error("original-only GC fixture finalizer cleanup refused")
						return
					}
				}
				live, err = get(row.plural, name)
				if apierrors.IsNotFound(err) {
					return
				}
				if err != nil || live.GetUID() != uid {
					t.Error("original GC fixture cleanup read refused")
					return
				}
				rv := live.GetResourceVersion()
				background := metav1.DeletePropagationBackground
				options := metav1.DeleteOptions{PropagationPolicy: &background, Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &rv}}
				if admin.AppsV1().RESTClient().Delete().Namespace(namespace).Resource(row.plural).Name(name).Body(&options).Do(ctx).Error() != nil {
					t.Error("original-only inert GC fixture cleanup refused")
				}
			})
			actorCan(gc, "patch", "apps", row.plural, "", name, true)
			actorCan(gc, "impersonate", "", "serviceaccounts", "", "arcadectl-destroy-controller", false)
			unchanged := func(want *unstructured.Unstructured) {
				t.Helper()
				live, err := get(row.plural, name)
				if err != nil || !reflect.DeepEqual(live.Object, want.Object) {
					t.Fatal("dry-run/denied GC request changed complete original owner")
				}
			}
			// This is deliberately metadata-only, not claimed finalizer-only.
			metadata := map[string]any{"resourceVersion": original.GetResourceVersion(), "annotations": map[string]string{"gc-proof": "metadata-only"}}
			if patch(gc, row.plural, name, map[string]any{"metadata": metadata}, true) != nil {
				t.Fatal("exact authenticated GC metadata-only update refused")
			}
			unchanged(original)
			deny(row.family, patch(nonadmin, row.plural, name, map[string]any{"metadata": metadata}, true))
			unchanged(original)
			for _, changed := range []map[string]any{
				{"replicas": int64(2)}, {"minReadySeconds": int64(9)},
				{"template": map[string]any{"metadata": map[string]any{"annotations": map[string]string{"foreign-template": "not-metadata-only"}}}},
			} {
				body := map[string]any{"metadata": map[string]any{"resourceVersion": original.GetResourceVersion()}, "spec": changed}
				// Native validity precedes policy attribution; no invalid-body
				// refusal is substituted for an actual security denial.
				if patch(admin, row.plural, name, body, true) != nil {
					t.Fatal("GC spec-change negative control was not native-valid")
				}
				deny(row.family, patch(gc, row.plural, name, body, true))
				unchanged(original)
			}
			candidate, err := runtime.DefaultUnstructuredConverter.ToUnstructured(desired)
			if err != nil {
				t.Fatal("native GC create control unavailable")
			}
			probe := &unstructured.Unstructured{Object: candidate}
			probe.SetName("gc-create-denied-" + row.plural)
			encoded, _ := json.Marshal(probe.Object)
			createOptions := metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}, FieldValidation: "Strict"}
			create := func(client *kubernetes.Clientset) error {
				return client.AppsV1().RESTClient().Post().Namespace(namespace).Resource(row.plural).
					VersionedParams(&createOptions, scheme.ParameterCodec).Body(encoded).Do(ctx).Error()
			}
			if create(admin) != nil {
				t.Fatal("GC create negative control was not native-valid")
			}
			deny(row.family, create(gc))
			if _, err := get(row.plural, probe.GetName()); !apierrors.IsNotFound(err) {
				t.Fatal("denied/dry-run GC create persisted an owner")
			}
			rv := original.GetResourceVersion()
			foreground := metav1.DeletePropagationForeground
			options := metav1.DeleteOptions{PropagationPolicy: &foreground, Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &rv}}
			if admin.AppsV1().RESTClient().Delete().Namespace(namespace).Resource(row.plural).Name(name).Body(&options).Do(ctx).Error() != nil {
				t.Fatal("original native foreground GC envelope refused")
			}
			deleting, err := get(row.plural, name)
			if err != nil || deleting.GetUID() != uid || deleting.GetDeletionTimestamp() == nil || !reflect.DeepEqual(deleting.GetFinalizers(), []string{metav1.FinalizerDeleteDependents}) {
				t.Fatal("original native foreground GC owner unavailable")
			}
			body := map[string]any{"metadata": map[string]any{"resourceVersion": deleting.GetResourceVersion(), "finalizers": []string{}}}
			if patch(gc, row.plural, name, body, true) != nil {
				t.Fatal("authenticated GC foreground-finalizer dry-run PATCH refused")
			}
			unchanged(deleting)
			deny(row.family, patch(nonadmin, row.plural, name, body, true))
			unchanged(deleting)
			if patch(gc, row.plural, name, body, false) != nil {
				t.Fatal("authenticated original GC finalizer PATCH refused")
			}
			if _, err := get(row.plural, name); !apierrors.IsNotFound(err) {
				t.Fatal("GC finalizer PATCH did not establish original owner absence")
			}
		})
	}
	// Runtime identity does not inherit native GC metadata permission.
	metadata := map[string]any{"metadata": map[string]any{"resourceVersion": installed.ResourceVersion, "annotations": map[string]string{"foreign": "runtime-actor"}}}
	deny("template", patch(ordinary, "deployments", installed.Name, metadata, true))
	account, err := admin.CoreV1().ServiceAccounts(namespace).Get(ctx, "arcadectl-destroy-controller", metav1.GetOptions{})
	if err != nil {
		t.Fatal("reserved identity control unavailable")
	}
	account.Annotations = map[string]string{"foreign": "gc-identity-update"}
	_, err = gc.CoreV1().ServiceAccounts(namespace).Update(ctx, account, metav1.UpdateOptions{DryRun: []string{metav1.DryRunAll}, FieldValidation: "Strict"})
	deny("identity", err)
	scale, err := admin.AppsV1().Deployments(namespace).GetScale(ctx, installed.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal("reserved Scale control unavailable")
	}
	scale.Spec.Replicas = 0
	_, err = gc.AppsV1().Deployments(namespace).UpdateScale(ctx, installed.Name, scale, metav1.UpdateOptions{DryRun: []string{metav1.DryRunAll}, FieldValidation: "Strict"})
	deny("scale", err)
}
