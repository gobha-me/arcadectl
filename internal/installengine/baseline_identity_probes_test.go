// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"reflect"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installrender"
)

func TestBaselineIdentityCreateProbeClosedLiteralSchemas(t *testing.T) {
	plan := fixturePlan(t)
	for _, actor := range []admissionActor{ordinaryControllerActor, destroyControllerActor} {
		for _, name := range []string{"arcadectl-controller", "arcadectl-api", "arcadectl-destroy-controller", "arcadectl-destroy-admin"} {
			for _, kind := range []string{"ServiceAccount", "Role", "RoleBinding", "Service"} {
				object, err := baselineIdentityCreateProbe(plan, actor, kind, name)
				if kind == "Service" && actor == destroyControllerActor {
					if err == nil || object != nil {
						t.Fatal("destroy actor got ordinary-only Service constructor")
					}
					continue
				}
				version := "v1"
				want := map[string]any{"kind": kind, "metadata": map[string]any{"namespace": plan.Namespace(), "name": name}}
				switch kind {
				case "ServiceAccount":
					want["automountServiceAccountToken"] = false
				case "Role":
					version = "rbac.authorization.k8s.io/v1"
					want["rules"] = []any{}
				case "RoleBinding":
					version = "rbac.authorization.k8s.io/v1"
					want["roleRef"] = map[string]any{"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": actor.account()}
					want["subjects"] = []any{}
				case "Service":
					want["spec"] = map[string]any{"type": "ClusterIP", "clusterIP": "None", "ports": []any{map[string]any{"name": "identity-probe", "port": int64(1), "protocol": "TCP", "targetPort": int64(1)}}}
				}
				want["apiVersion"] = version
				if err != nil || object == nil || !reflect.DeepEqual(object.Object, want) {
					t.Fatal("identity constructor differs from independent inert literal schema")
				}
				object.SetAnnotations(map[string]string{"foreign": "test"})
				again, err := baselineIdentityCreateProbe(plan, actor, kind, name)
				if err != nil || !reflect.DeepEqual(again.Object, want) {
					t.Fatal("identity constructor shares mutable state")
				}
			}
		}
	}
	for _, row := range []struct {
		plan       *installrender.Plan
		actor      admissionActor
		kind, name string
	}{
		{nil, ordinaryControllerActor, "Role", "arcadectl-controller"},
		{plan, destroyAdministratorActor, "Role", "arcadectl-controller"},
		{plan, 255, "Role", "arcadectl-controller"},
		{plan, ordinaryControllerActor, "Secret", "arcadectl-controller"},
		{plan, ordinaryControllerActor, "Pod", "arcadectl-controller"},
		{plan, ordinaryControllerActor, "Role", "unreserved"},
		{plan, ordinaryControllerActor, "Role", "arcadectl-controller/foreign"},
	} {
		if object, err := baselineIdentityCreateProbe(row.plan, row.actor, row.kind, row.name); err == nil || object != nil {
			t.Fatal("identity constructor accepts untrusted or arbitrary input")
		}
	}
}
