// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"os"
	"slices"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/yaml"
)

func TestControllerRoleCannotDeletePersistentClaims(t *testing.T) {
	t.Parallel()

	role := loadControllerRole(t)
	foundClaims := false
	for _, rule := range role.Rules {
		if !slices.Contains(rule.APIGroups, "") || !slices.Contains(rule.Resources, "persistentvolumeclaims") {
			continue
		}
		foundClaims = true
		if slices.Contains(rule.Verbs, "delete") || slices.Contains(rule.Verbs, "deletecollection") || slices.Contains(rule.Verbs, "*") {
			t.Fatalf("persistent-volume-claim verbs allow deletion: %v", rule.Verbs)
		}
		for _, required := range []string{"get", "list", "watch", "create", "update", "patch"} {
			if !slices.Contains(rule.Verbs, required) {
				t.Errorf("persistent-volume-claim verbs %v omit %q", rule.Verbs, required)
			}
		}
	}
	if !foundClaims {
		t.Fatal("generated role has no persistent-volume-claim rule")
	}
}

func TestControllerRoleCanManageDisposableConfiguration(t *testing.T) {
	t.Parallel()

	role := loadControllerRole(t)
	for _, rule := range role.Rules {
		if !slices.Contains(rule.APIGroups, "") || !slices.Contains(rule.Resources, "configmaps") {
			continue
		}
		for _, required := range []string{"get", "list", "watch", "create", "update", "patch", "delete"} {
			if !slices.Contains(rule.Verbs, required) {
				t.Errorf("ConfigMap verbs %v omit %q", rule.Verbs, required)
			}
		}
		return
	}
	t.Fatal("generated role has no ConfigMap rule")
}

func loadControllerRole(t *testing.T) *rbacv1.Role {
	t.Helper()
	contents, err := os.ReadFile("../../config/rbac/role.yaml")
	if err != nil {
		t.Fatalf("read generated controller role: %v", err)
	}
	role := &rbacv1.Role{}
	if err := yaml.Unmarshal(contents, role); err != nil {
		t.Fatalf("decode generated controller role: %v", err)
	}
	if role.Kind != "Role" || role.APIVersion != rbacv1.SchemeGroupVersion.String() || role.Namespace != "arcadectl-system" {
		t.Fatalf("generated RBAC identity = %s %s %q/%q, want namespaced Role", role.APIVersion, role.Kind, role.Namespace, role.Name)
	}
	return role
}
