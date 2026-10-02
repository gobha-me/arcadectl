//go:build envtest

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package install

import (
	"context"
	"testing"

	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func assertAPIAdmissionAndRBAC(t *testing.T, ctx context.Context, config *rest.Config, admin client.Client, scheme *runtime.Scheme) {
	t.Helper()
	objects := decodeObjects(t, renderAPI(t, testAPIImage))
	for _, object := range objects[:3] {
		if err := admin.Create(ctx, object); err != nil {
			t.Fatal(err)
		}
	}
	impersonated := rest.CopyConfig(config)
	impersonated.Impersonate = rest.ImpersonationConfig{UserName: "system:serviceaccount:arcadectl-system:arcadectl-api"}
	api, err := client.New(impersonated, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	access, err := kubernetes.NewForConfig(impersonated)
	if err != nil {
		t.Fatal(err)
	}
	for _, resource := range []string{"gameservers", "gamebackups", "gamerestores", "gamedestroys"} {
		for _, verb := range []string{"get", "list", "watch", "create", "update", "patch", "delete"} {
			assertAPIResourceAccess(t, ctx, access, "arcade.gobha.me", resource, "", "arcadectl-system", verb, true)
		}
		assertAPIResourceAccess(t, ctx, access, "arcade.gobha.me", resource, "status", "arcadectl-system", "update", false)
		assertAPIResourceAccess(t, ctx, access, "arcade.gobha.me", resource, "", "foreign", "create", false)
	}
	for _, target := range []struct{ group, resource string }{
		{"", "secrets"}, {"", "services"}, {"", "configmaps"}, {"", "persistentvolumeclaims"},
		{"", "persistentvolumes"}, {"", "pods"}, {"", "serviceaccounts"}, {"", "namespaces"},
		{"apps", "deployments"}, {"apps", "statefulsets"}, {"batch", "jobs"},
		{"coordination.k8s.io", "leases"}, {"storage.k8s.io", "volumeattachments"},
		{"rbac.authorization.k8s.io", "roles"}, {"rbac.authorization.k8s.io", "rolebindings"},
		{"rbac.authorization.k8s.io", "clusterroles"}, {"rbac.authorization.k8s.io", "clusterrolebindings"},
	} {
		for _, verb := range []string{"get", "create", "update", "patch", "delete"} {
			assertAPIResourceAccess(t, ctx, access, target.group, target.resource, "", "arcadectl-system", verb, false)
		}
	}
	// Also prove an actual core-resource write is forbidden, not just an access
	// review result. API cannot retrieve or replace the projected Secret.
	if err := api.Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "forbidden-api-secret", Namespace: "arcadectl-system"}}); !apierrors.IsForbidden(err) {
		t.Fatalf("API Secret create not forbidden: %v", err)
	}
	unsafe := destroyAdmissionUnsafeRequest("api-unsafe-refused")
	unsafe.Annotations = map[string]string{"arcade.gobha.me/unsafe-requested-by": "system:serviceaccount:arcadectl-system:arcadectl-destroy-admin"}
	waitDestroyAdmissionDenied(t, func() error {
		return api.Create(ctx, unsafe.DeepCopy(), &client.CreateOptions{DryRun: []string{metav1.DryRunAll}})
	}, "distinct Arcadectl destroy admin identity")
}

func assertAPIResourceAccess(t *testing.T, ctx context.Context, access kubernetes.Interface, group, resource, subresource, namespace, verb string, want bool) {
	t.Helper()
	review, err := access.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, &authorizationv1.SelfSubjectAccessReview{Spec: authorizationv1.SelfSubjectAccessReviewSpec{
		ResourceAttributes: &authorizationv1.ResourceAttributes{Namespace: namespace, Verb: verb, Group: group, Resource: resource, Subresource: subresource},
	}}, metav1.CreateOptions{})
	if err != nil || review.Status.Allowed != want {
		t.Fatalf("API %s %s/%s sub=%s ns=%s allowed=%v want=%v err=%v", verb, group, resource, subresource, namespace, review, want, err)
	}
}
