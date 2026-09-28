// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"os"
	"slices"
	"strings"
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

func TestControllerRoleBackupWorkerAuthorityIsNarrow(t *testing.T) {
	t.Parallel()

	role := loadControllerRole(t)
	assertExactResourceVerbs(t, role, "arcade.gobha.me", "gamebackups", []string{"get", "list", "patch", "update", "watch"})
	assertExactResourceVerbs(t, role, "arcade.gobha.me", "gamebackups/status", []string{"get", "patch", "update"})
	assertExactResourceVerbs(t, role, "arcade.gobha.me", "gamerestores", []string{"get", "list", "watch"})
	assertExactResourceVerbs(t, role, "arcade.gobha.me", "gamerestores/status", []string{"get", "patch", "update"})
	assertExactResourceVerbs(t, role, "", "secrets", []string{"get"})
	assertExactResourceVerbs(t, role, "", "pods", []string{"get", "list", "update", "watch"})
	assertExactResourceVerbs(t, role, "", "serviceaccounts", []string{"create", "get", "list", "watch"})
	assertExactResourceVerbs(t, role, "batch", "jobs", []string{"create", "delete", "get", "list", "update", "watch"})
	assertExactResourceVerbs(t, role, "coordination.k8s.io", "leases", []string{"create", "delete", "get", "list", "patch", "update", "watch"})
	assertExactResourceVerbs(t, role, "rbac.authorization.k8s.io", "roles", []string{"create", "get", "list", "watch"})
	assertExactResourceVerbs(t, role, "rbac.authorization.k8s.io", "rolebindings", []string{"create", "get", "list", "watch"})
}

func TestControllerRoleHasNoWildcardOrRBACEscalationAuthority(t *testing.T) {
	t.Parallel()

	role := loadControllerRole(t)
	for _, rule := range role.Rules {
		if len(rule.NonResourceURLs) != 0 {
			t.Fatalf("controller Role contains non-resource authority: %v", rule.NonResourceURLs)
		}
		for _, value := range append(append(slices.Clone(rule.APIGroups), rule.Resources...), rule.Verbs...) {
			if value == "*" {
				t.Fatalf("controller Role contains wildcard authority: %#v", rule)
			}
		}
		for _, verb := range rule.Verbs {
			if slices.Contains([]string{"bind", "escalate", "impersonate"}, strings.ToLower(verb)) {
				t.Fatalf("controller Role contains escalation verb %q: %#v", verb, rule)
			}
		}
	}
}

func assertExactResourceVerbs(t *testing.T, role *rbacv1.Role, group, resource string, want []string) {
	t.Helper()
	for _, rule := range role.Rules {
		if slices.Contains(rule.APIGroups, group) && slices.Contains(rule.Resources, resource) {
			got := slices.Clone(rule.Verbs)
			slices.Sort(got)
			want = slices.Clone(want)
			slices.Sort(want)
			if !slices.Equal(got, want) {
				t.Fatalf("%s verbs = %v, want %v", resource, got, want)
			}
			return
		}
	}
	t.Fatalf("generated role has no %s rule", resource)
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
