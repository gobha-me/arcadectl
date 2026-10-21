// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installstate

import (
	"slices"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestRuntimeIdentitiesCannotModifyNamespaceJournal(t *testing.T) {
	plan := testPlan(t)
	roles := 0
	for _, resource := range plan.Resources() {
		if resource.Object.GetKind() != "ClusterRole" && resource.Object.GetKind() != "Role" {
			continue
		}
		var rules []rbacv1.PolicyRule
		if resource.Object.GetKind() == "ClusterRole" {
			var role rbacv1.ClusterRole
			if err := runtime.DefaultUnstructuredConverter.FromUnstructured(resource.Object.Object, &role); err != nil {
				t.Fatal(err)
			}
			rules = role.Rules
		} else {
			var role rbacv1.Role
			if err := runtime.DefaultUnstructuredConverter.FromUnstructured(resource.Object.Object, &role); err != nil {
				t.Fatal(err)
			}
			rules = role.Rules
		}
		roles++
		for _, rule := range rules {
			if !slices.Contains(rule.APIGroups, "") && !slices.Contains(rule.APIGroups, "*") {
				continue
			}
			if !slices.Contains(rule.Resources, "namespaces") && !slices.Contains(rule.Resources, "*") {
				continue
			}
			for _, verb := range []string{"*", "create", "update", "patch", "delete", "deletecollection"} {
				if slices.Contains(rule.Verbs, verb) {
					t.Fatal("runtime authority can modify the installation journal anchor")
				}
			}
		}
	}
	if roles != 6 {
		t.Fatalf("checked %d roles, want all six packaged roles", roles)
	}
}
