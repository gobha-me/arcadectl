//go:build envtest

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installstate"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
)

// Read-only actor SSRRs over the actual private API server and native RBAC,
// including noncanonical resourceNames and inherited group/cluster grants.
// Temporary administrative RBAC is test-owned, not installation authority.
// No token, workload, world, proxy connection or production cluster is used.
func testBaselineNativeProxyRules(t *testing.T, ctx context.Context, admin *kubernetes.Clientset, access *HTTPAccess, namespace string, guarded map[installstate.Key]*unstructured.Unstructured) {
	t.Helper()
	executables := &baselineExecutables{guarded: guarded}
	clients := map[admissionActor]*HTTPAccess{}
	for _, actor := range []admissionActor{ordinaryControllerActor, destroyControllerActor} {
		client, err := access.baselineRulesClient(actor, namespace)
		if err != nil {
			t.Fatal("native rules-only original actor unavailable")
		}
		rules, err := client.baselineRules(ctx)
		if err != nil || !baselineProxyRulesContained(rules, executables) {
			t.Fatal("native signed actor complete effective rules unavailable or unexpectedly granted")
		}
		clients[actor] = client
	}
	for index, source := range []string{"serviceaccount", "user", "all-serviceaccounts", "namespace-serviceaccounts", "authenticated", "cluster-binding", "aggregate-materialized", "actual-pod-alias"} {
		name := fmt.Sprintf("test-proxy-raw-alias-%d", index)
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
				uid, rv := r.UID, live.GetResourceVersion()
				background := metav1.DeletePropagationBackground
				options := metav1.DeleteOptions{PropagationPolicy: &background, Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &rv}}
				switch r.Key.Kind {
				case "Role":
					err = admin.RbacV1().Roles(namespace).Delete(ctx, r.Key.Name, options)
				case "RoleBinding":
					err = admin.RbacV1().RoleBindings(namespace).Delete(ctx, r.Key.Name, options)
				case "ClusterRole":
					err = admin.RbacV1().ClusterRoles().Delete(ctx, r.Key.Name, options)
				case "ClusterRoleBinding":
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
				t.Error("native raw-alias grant original-only cleanup failed")
			}
		})
		// This single finite literal name is absent from the canonical SSAR
		// catalog but accepted by native Service proxy URL parsing.
		rules := []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"services/proxy"}, Verbs: []string{"get"}, ResourceNames: []string{"https:arcadectl-api:+00443"}}}
		if source == "actual-pod-alias" {
			podName := ""
			for key := range guarded {
				if key.APIVersion == "v1" && key.Kind == "Pod" {
					podName = key.Name
					break
				}
			}
			if podName == "" {
				t.Fatal("native proxy rule lacks actual guarded Pod witness")
			}
			rules[0].Resources, rules[0].ResourceNames = []string{"pods/proxy"}, []string{"https:" + podName + ":+008081"}
		}
		roleKind := "Role"
		var ack metav1.Object
		var err error
		if source == "cluster-binding" || source == "aggregate-materialized" {
			roleKind = "ClusterRole"
			role := &rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: name}, Rules: rules}
			if source == "aggregate-materialized" {
				// No KCM exists here. Prove authorization of actual current
				// materialized rules, not selector expansion or aggregation.
				role.AggregationRule = &rbacv1.AggregationRule{ClusterRoleSelectors: []metav1.LabelSelector{{MatchLabels: map[string]string{"test-no-aggregation-source": "true"}}}}
			}
			ack, err = admin.RbacV1().ClusterRoles().Create(ctx, role, metav1.CreateOptions{FieldValidation: "Strict"})
		} else {
			ack, err = admin.RbacV1().Roles(namespace).Create(ctx, &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace}, Rules: rules}, metav1.CreateOptions{FieldValidation: "Strict"})
		}
		if err != nil || ack == nil || !nativeFixtureUID(string(ack.GetUID())) {
			t.Fatal("native inert raw-alias rule CREATE acknowledgement unavailable")
		}
		originals = append(originals, installstate.Resource{Key: installstate.Key{APIVersion: "rbac.authorization.k8s.io/v1", Kind: roleKind, Namespace: ack.GetNamespace(), Name: name}, UID: ack.GetUID()})
		subjects := []rbacv1.Subject{}
		for _, actor := range []admissionActor{ordinaryControllerActor, destroyControllerActor} {
			if source == "user" {
				subjects = append(subjects, rbacv1.Subject{Kind: "User", APIGroup: rbacv1.GroupName, Name: "system:serviceaccount:" + namespace + ":" + actor.account()})
			} else {
				subjects = append(subjects, rbacv1.Subject{Kind: "ServiceAccount", Namespace: namespace, Name: actor.account()})
			}
		}
		group := ""
		if source == "all-serviceaccounts" {
			group = "system:serviceaccounts"
		} else if source == "namespace-serviceaccounts" {
			group = "system:serviceaccounts:" + namespace
		} else if source == "authenticated" {
			group = "system:authenticated"
		}
		if group != "" {
			subjects = []rbacv1.Subject{{Kind: "Group", APIGroup: rbacv1.GroupName, Name: group}}
		}
		roleRef := rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: roleKind, Name: name}
		bindingKind := "RoleBinding"
		if source == "cluster-binding" {
			bindingKind = "ClusterRoleBinding"
			ack, err = admin.RbacV1().ClusterRoleBindings().Create(ctx, &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: name}, Subjects: subjects, RoleRef: roleRef}, metav1.CreateOptions{FieldValidation: "Strict"})
		} else {
			ack, err = admin.RbacV1().RoleBindings(namespace).Create(ctx, &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace}, Subjects: subjects, RoleRef: roleRef}, metav1.CreateOptions{FieldValidation: "Strict"})
		}
		if err != nil || ack == nil || !nativeFixtureUID(string(ack.GetUID())) {
			t.Fatal("native raw-alias binding CREATE acknowledgement unavailable")
		}
		originals = append(originals, installstate.Resource{Key: installstate.Key{APIVersion: "rbac.authorization.k8s.io/v1", Kind: bindingKind, Namespace: ack.GetNamespace(), Name: name}, UID: ack.GetUID()})
		for _, actor := range []admissionActor{ordinaryControllerActor, destroyControllerActor} {
			if wait.PollUntilContextTimeout(ctx, 50*time.Millisecond, 5*time.Second, true, func(ctx context.Context) (bool, error) {
				rules, err := clients[actor].baselineRules(ctx)
				return err == nil && !baselineProxyRulesContained(rules, executables), nil
			}) != nil {
				t.Fatal("native direct, inherited or cluster raw-alias grant was not detected")
			}
		}
		if !cleanup(ctx) {
			t.Fatal("native raw-alias grant exact original absence unproved")
		}
		cleaned = true
		for _, actor := range []admissionActor{ordinaryControllerActor, destroyControllerActor} {
			if wait.PollUntilContextTimeout(ctx, 50*time.Millisecond, 5*time.Second, true, func(ctx context.Context) (bool, error) {
				rules, err := clients[actor].baselineRules(ctx)
				return err == nil && baselineProxyRulesContained(rules, executables), nil
			}) != nil {
				t.Fatal("native raw-alias grant withdrawal remains unproved")
			}
		}
	}
}
