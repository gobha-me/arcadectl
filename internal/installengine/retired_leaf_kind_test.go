//go:build kindinstall

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"encoding/json"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	authenticationv1 "k8s.io/api/authentication/v1"
	authv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// Native component control in each existing owned 1.35/1.37 baseline fixture,
// never the signed CLI, cold-world or durable withdrawal proof. No workload,
// Secret or world is created. Foreground negatives stay stranded until exact
// owned Kind teardown; never remove finalizers or alter retained policies.
func testKindProtectedAccessLeafGC(t *testing.T, ctx context.Context, config *rest.Config, access *HTTPAccess, engine *Engine, snapshot *installstate.Snapshot, plan *installrender.Plan) {
	t.Helper()
	baseline, err := NewClusterSecurityBaseline(engine, access)
	if err != nil {
		t.Fatal("original native baseline observer unavailable")
	}
	openingPolicies, err := baseline.configured(ctx, snapshot)
	if err != nil {
		t.Fatal("opening original native baseline policies unavailable")
	}
	admin, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatal("owned native administrator unavailable")
	}
	adminDynamic, err := dynamic.NewForConfig(config)
	if err != nil {
		t.Fatal("owned native metadata control unavailable")
	}
	gcConfig := rest.CopyConfig(config)
	gcConfig.Impersonate = rest.ImpersonationConfig{UserName: "system:serviceaccount:kube-system:generic-garbage-collector", Groups: []string{"system:serviceaccounts", "system:serviceaccounts:kube-system", "system:authenticated"}}
	gc, err := kubernetes.NewForConfig(gcConfig)
	if err != nil {
		t.Fatal("native GC identity client unavailable")
	}
	identity, err := gc.AuthenticationV1().SelfSubjectReviews().Create(ctx, &authenticationv1.SelfSubjectReview{}, metav1.CreateOptions{})
	if err != nil || identity.Status.UserInfo.Username != gcConfig.Impersonate.UserName || len(identity.Status.UserInfo.Extra) != 0 {
		t.Fatal("native GC identity differs from exact actor")
	}
	actual, expected := slices.Clone(identity.Status.UserInfo.Groups), slices.Clone(gcConfig.Impersonate.Groups)
	slices.Sort(actual)
	slices.Sort(expected)
	if !slices.Equal(actual, expected) {
		t.Fatal("native GC groups differ from exact actor")
	}
	gcDynamic, err := dynamic.NewForConfig(gcConfig)
	if err != nil {
		t.Fatal("native GC metadata control unavailable")
	}
	sentinel, err := admin.CoreV1().ConfigMaps(plan.Namespace()).Create(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "foreign-leaf-sentinel"}, Data: map[string]string{"untouched": "true"}}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal("owned foreign sentinel unavailable")
	}
	for _, family := range []struct{ kind, plural string }{{"RoleBinding", "rolebindings"}, {"Role", "roles"}, {"ServiceAccount", "serviceaccounts"}} {
		t.Run(family.kind, func(t *testing.T) {
			var originals []installstate.Key
			for _, resource := range plan.Resources() {
				key := resourceKey(resource)
				if key.Kind != family.kind {
					continue
				}
				live, readErr := access.Get(ctx, key)
				if apierrors.IsNotFound(readErr) {
					live, readErr = access.Create(ctx, key, resource.Object, false)
				} else {
					entry, template := engine.inventory(snapshot.Document(), key)
					if entry == nil || template == nil || readErr != nil || template.MatchLive(live, entry.UID) != nil {
						t.Fatal("preexisting protected identity not the original component inventory")
					}
				}
				if readErr != nil || live == nil || live.GetUID() == "" || live.GetResourceVersion() == "" || len(live.GetOwnerReferences()) != 0 || len(live.GetFinalizers()) != 0 {
					t.Fatal("owned original leaf unavailable")
				}
				originals = append(originals, key)
				if len(originals) == 2 {
					break
				}
			}
			if len(originals) != 2 {
				t.Fatal("two independent signed protected leaves unavailable")
			}
			gv, _ := schema.ParseGroupVersion(originals[0].APIVersion)
			review, err := gc.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, &authv1.SelfSubjectAccessReview{Spec: authv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authv1.ResourceAttributes{Group: gv.Group, Version: gv.Version, Resource: family.plural, Namespace: plan.Namespace(), Verb: "patch", Name: originals[0].Name}}}, metav1.CreateOptions{})
			if err != nil || !review.Status.Allowed || review.Status.Denied || review.Status.EvaluationError != "" {
				t.Fatal("native GC lacks independent finalizer PATCH authorization")
			}
			foreground, background := metav1.DeletePropagationForeground, metav1.DeletePropagationBackground
			negative, err := access.Get(ctx, originals[0])
			if err != nil {
				t.Fatal("original foreground negative unavailable")
			}
			target := gv.WithResource(family.plural)
			openingPatch, _ := json.Marshal([]map[string]any{{"op": "test", "path": "/metadata/uid", "value": negative.GetUID()}, {"op": "test", "path": "/metadata/resourceVersion", "value": negative.GetResourceVersion()}, {"op": "add", "path": "/metadata/finalizers", "value": []string{metav1.FinalizerDeleteDependents}}})
			if _, err := adminDynamic.Resource(target).Namespace(plan.Namespace()).Patch(ctx, originals[0].Name, types.JSONPatchType, openingPatch, metav1.PatchOptions{DryRun: []string{metav1.DryRunAll}}); err != nil {
				t.Fatal("administrator-valid opening finalizer control refused")
			}
			// Typechecking alone is not serving evidence. Wait only for this
			// nonpersistent negative control before the ONE real foreground
			// DELETE, so a cache warm-up cannot let GC remove its finalizer.
			if wait.PollUntilContextTimeout(ctx, 100*time.Millisecond, 30*time.Second, true, func(ctx context.Context) (bool, error) {
				_, err := gcDynamic.Resource(target).Namespace(plan.Namespace()).Patch(ctx, originals[0].Name, types.JSONPatchType, openingPatch, metav1.PatchOptions{DryRun: []string{metav1.DryRunAll}})
				return baselineDenial(err, "identity", plan.Namespace()), nil
			}) != nil {
				t.Fatal("native GC opening finalizer control lacks served identity policy denial")
			}
			openingReadback, readErr := access.Get(ctx, originals[0])
			if readErr != nil || !reflect.DeepEqual(openingReadback.Object, negative.Object) {
				t.Fatal("opening native dry-run controls changed original leaf")
			}
			uid, rv := negative.GetUID(), negative.GetResourceVersion()
			if access.Delete(ctx, originals[0], metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &rv}, PropagationPolicy: &foreground}) != nil {
				t.Fatal("one original foreground control DELETE refused")
			}
			if wait.PollUntilContextTimeout(ctx, 100*time.Millisecond, 10*time.Second, true, func(ctx context.Context) (bool, error) {
				negative, err = access.Get(ctx, originals[0])
				if err != nil || negative.GetUID() != uid {
					return false, ErrOwnership
				}
				return negative.GetDeletionTimestamp() != nil && slices.Contains(negative.GetFinalizers(), metav1.FinalizerDeleteDependents), nil
			}) != nil {
				t.Fatal("native original foreground finalizer not observed")
			}
			patch, _ := json.Marshal([]map[string]any{{"op": "test", "path": "/metadata/uid", "value": uid}, {"op": "test", "path": "/metadata/resourceVersion", "value": negative.GetResourceVersion()}, {"op": "replace", "path": "/metadata/finalizers", "value": []string{}}})
			if _, err := adminDynamic.Resource(target).Namespace(plan.Namespace()).Patch(ctx, originals[0].Name, types.JSONPatchType, patch, metav1.PatchOptions{DryRun: []string{metav1.DryRunAll}}); err != nil {
				t.Fatal("administrator-valid finalizer control refused")
			}
			unchanged, readErr := access.Get(ctx, originals[0])
			if readErr != nil || !reflect.DeepEqual(unchanged.Object, negative.Object) {
				t.Fatal("administrator dry-run changed original foreground object")
			}
			if _, err := gcDynamic.Resource(target).Namespace(plan.Namespace()).Patch(ctx, originals[0].Name, types.JSONPatchType, patch, metav1.PatchOptions{DryRun: []string{metav1.DryRunAll}}); !baselineDenial(err, "identity", plan.Namespace()) {
				t.Fatal("native GC finalizer control lacks exact identity policy denial")
			}
			unchanged, readErr = access.Get(ctx, originals[0])
			if readErr != nil || !reflect.DeepEqual(unchanged.Object, negative.Object) {
				t.Fatal("denied GC dry-run changed original foreground object")
			}
			positive, err := access.Get(ctx, originals[1])
			if err != nil || len(positive.GetOwnerReferences()) != 0 || len(positive.GetFinalizers()) != 0 {
				t.Fatal("separate original background leaf unavailable")
			}
			uid, rv = positive.GetUID(), positive.GetResourceVersion()
			if access.Delete(ctx, originals[1], metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &rv}, PropagationPolicy: &background}) != nil {
				t.Fatal("one original background control DELETE refused")
			}
			if wait.PollUntilContextTimeout(ctx, 100*time.Millisecond, 10*time.Second, true, func(ctx context.Context) (bool, error) {
				live, err := access.Get(ctx, originals[1])
				if apierrors.IsNotFound(err) {
					return true, nil
				}
				if err != nil || live.GetUID() != uid {
					return false, ErrOwnership
				}
				return false, nil
			}) != nil {
				t.Fatal("native original background leaf actual absence not proved")
			}
		})
	}
	live, err := admin.CoreV1().ConfigMaps(plan.Namespace()).Get(ctx, sentinel.Name, metav1.GetOptions{})
	if err != nil || !reflect.DeepEqual(live, sentinel) {
		t.Fatal("foreign sentinel changed during native leaf controls")
	}
	closingPolicies, err := baseline.configured(ctx, snapshot)
	if err != nil || !reflect.DeepEqual(openingPolicies, closingPolicies) {
		t.Fatal("original baseline UID/RV/shape/typechecking changed during native leaf controls")
	}
	t.Log("native protected access finalizer policy denial and independent background leaf absence proved without finalizer edits")
}
