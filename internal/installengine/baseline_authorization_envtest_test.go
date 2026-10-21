//go:build envtest

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"fmt"
	"testing"
	"time"

	authv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
)

// Native RBAC validates the wildcard SSAR catalog and detects each narrowly
// granted permission for both original actors. These test-only grants run on
// the owned API-server fixture (no controllers/kubelets). This is NOT evidence
// of actual header impersonation containment under a version-sensitive
// authorizer: an empty SSAR version would normalize to wildcard too.
func testBaselineNativeWildcardContainment(t *testing.T, ctx context.Context, admin *kubernetes.Clientset, access *HTTPAccess, namespace string) {
	t.Helper()
	// This is the private API server, never a caller-provided cluster. Do not
	// adopt/delete an existing namespace; any newly created namespace belongs
	// only to the enclosing environment, whose Stop cleans its entire storage.
	_, err := admin.CoreV1().Namespaces().Get(ctx, "kube-system", metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err = admin.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system"}}, metav1.CreateOptions{})
	}
	if err != nil {
		t.Fatal("private native review namespace unavailable")
	}
	for _, actorID := range []admissionActor{ordinaryControllerActor, destroyControllerActor} {
		actor, err := access.actorClientForPurpose(actorID, namespace, baselineAdmissionPurpose)
		if err != nil {
			t.Fatal("native wildcard review actor unavailable")
		}
		for index, attributes := range testBaselineContainmentAttributes(namespace) {
			t.Run(fmt.Sprintf("wildcard-%s-%d", actorID.account(), index), func(t *testing.T) {
				spec := authv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &attributes}
				if actor.authorizationDecision(ctx, spec, false) != nil {
					t.Fatal("native original actor wildcard denial unavailable")
				}
				name := fmt.Sprintf("arcadectl-test-authz-%s-%d", actorID.account(), index)
				rules := []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{attributes.Resource}, ResourceNames: []string{attributes.Name}, Verbs: []string{"impersonate"}}}
				subjects := []rbacv1.Subject{{Kind: "ServiceAccount", Name: actorID.account(), Namespace: namespace}}
				var roleUID, bindingUID types.UID
				var roleRV, bindingRV string
				if attributes.Namespace == "" {
					ack, err := admin.RbacV1().ClusterRoles().Create(ctx, &rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: name}, Rules: rules}, metav1.CreateOptions{})
					if err != nil {
						t.Fatal("test-owned native user grant refused")
					}
					roleUID, roleRV = ack.UID, ack.ResourceVersion
				} else {
					ack, err := admin.RbacV1().Roles(attributes.Namespace).Create(ctx, &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: name}, Rules: rules}, metav1.CreateOptions{})
					if err != nil {
						t.Fatal("test-owned native account grant refused")
					}
					roleUID, roleRV = ack.UID, ack.ResourceVersion
				}
				if !nativeFixtureUID(string(roleUID)) || !fixtureRV(roleRV) {
					t.Fatal("native test grant lacks original acknowledgement")
				}
				t.Cleanup(func() {
					cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
					defer cancel()
					background := metav1.DeletePropagationBackground
					options := metav1.DeleteOptions{PropagationPolicy: &background, Preconditions: &metav1.Preconditions{UID: &roleUID, ResourceVersion: &roleRV}}
					var err error
					if attributes.Namespace == "" {
						err = admin.RbacV1().ClusterRoles().Delete(cleanupCtx, name, options)
					} else {
						err = admin.RbacV1().Roles(attributes.Namespace).Delete(cleanupCtx, name, options)
					}
					if err != nil && !apierrors.IsNotFound(err) {
						t.Error("original-only native role cleanup failed")
						return
					}
					if attributes.Namespace == "" {
						_, err = admin.RbacV1().ClusterRoles().Get(cleanupCtx, name, metav1.GetOptions{})
					} else {
						_, err = admin.RbacV1().Roles(attributes.Namespace).Get(cleanupCtx, name, metav1.GetOptions{})
					}
					if !apierrors.IsNotFound(err) {
						t.Error("native original role cleanup absence was not established")
					}
				})
				if attributes.Namespace == "" {
					ack, err := admin.RbacV1().ClusterRoleBindings().Create(ctx, &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: name}, RoleRef: rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: name}, Subjects: subjects}, metav1.CreateOptions{})
					if err != nil {
						t.Fatal("test-owned native user grant binding refused")
					}
					bindingUID, bindingRV = ack.UID, ack.ResourceVersion
				} else {
					ack, err := admin.RbacV1().RoleBindings(attributes.Namespace).Create(ctx, &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: name}, RoleRef: rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: name}, Subjects: subjects}, metav1.CreateOptions{})
					if err != nil {
						t.Fatal("test-owned native account grant binding refused")
					}
					bindingUID, bindingRV = ack.UID, ack.ResourceVersion
				}
				if !nativeFixtureUID(string(bindingUID)) || !fixtureRV(bindingRV) {
					t.Fatal("native test binding lacks original acknowledgement")
				}
				cleanupBinding := func(ctx context.Context) error {
					background := metav1.DeletePropagationBackground
					options := metav1.DeleteOptions{PropagationPolicy: &background, Preconditions: &metav1.Preconditions{UID: &bindingUID, ResourceVersion: &bindingRV}}
					var err error
					if attributes.Namespace == "" {
						err = admin.RbacV1().ClusterRoleBindings().Delete(ctx, name, options)
					} else {
						err = admin.RbacV1().RoleBindings(attributes.Namespace).Delete(ctx, name, options)
					}
					if err != nil && !apierrors.IsNotFound(err) {
						return ErrRead
					}
					if attributes.Namespace == "" {
						_, err = admin.RbacV1().ClusterRoleBindings().Get(ctx, name, metav1.GetOptions{})
					} else {
						_, err = admin.RbacV1().RoleBindings(attributes.Namespace).Get(ctx, name, metav1.GetOptions{})
					}
					if !apierrors.IsNotFound(err) {
						return ErrRead
					}
					return nil
				}
				bindingRemoved := false
				t.Cleanup(func() {
					if bindingRemoved {
						return
					}
					cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
					defer cancel()
					if cleanupBinding(cleanupCtx) != nil {
						t.Error("original-only native binding cleanup failed")
					}
				})
				if wait.PollUntilContextTimeout(ctx, 100*time.Millisecond, 10*time.Second, true, func(ctx context.Context) (bool, error) {
					return actor.authorizationDecision(ctx, spec, true) == nil, nil
				}) != nil {
					t.Fatal("native test grant never became effective")
				}
				if actor.authorizationDecision(ctx, spec, false) == nil {
					t.Fatal("native wildcard containment accepted a granted producer or maintenance identity")
				}
				if cleanupBinding(ctx) != nil {
					t.Fatal("original-only native grant withdrawal refused")
				}
				bindingRemoved = true
				if wait.PollUntilContextTimeout(ctx, 100*time.Millisecond, 10*time.Second, true, func(ctx context.Context) (bool, error) {
					return actor.authorizationDecision(ctx, spec, false) == nil, nil
				}) != nil {
					t.Fatal("native wildcard denial did not recover after original grant withdrawal")
				}
			})
		}
	}
}
