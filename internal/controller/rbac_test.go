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

	contents, err := os.ReadFile("../../config/rbac/role.yaml")
	if err != nil {
		t.Fatalf("read generated controller role: %v", err)
	}
	role := &rbacv1.ClusterRole{}
	if err := yaml.Unmarshal(contents, role); err != nil {
		t.Fatalf("decode generated controller role: %v", err)
	}
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
