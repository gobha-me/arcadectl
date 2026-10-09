// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"github.com/gobha-me/arcadectl/internal/installrender"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Closed schema-valid negative CREATE constructors. The Role has no rights;
// the binding has no subjects and references only the actor's acknowledged
// own Role; the Service is selectorless/headless. No arbitrary settings,
// account, namespace, permissions or executables can enter the request.
// This is not an ownership or original-access proof, and never persists.
func baselineIdentityCreateProbe(plan *installrender.Plan, actor admissionActor, kind, name string) (*unstructured.Unstructured, error) {
	if !plan.IsTrusted() || actor != ordinaryControllerActor && actor != destroyControllerActor || !baselineReservedAccount(name) {
		return nil, ErrInvalid
	}
	version := "v1"
	fields := map[string]any{}
	switch kind {
	case "ServiceAccount":
		fields["automountServiceAccountToken"] = false
	case "Role":
		version = "rbac.authorization.k8s.io/v1"
		fields["rules"] = []any{}
	case "RoleBinding":
		version = "rbac.authorization.k8s.io/v1"
		fields["roleRef"] = map[string]any{"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": actor.account()}
		fields["subjects"] = []any{}
	case "Service":
		if actor != ordinaryControllerActor {
			return nil, ErrInvalid
		}
		fields["spec"] = map[string]any{"type": "ClusterIP", "clusterIP": "None", "ports": []any{map[string]any{"name": "identity-probe", "port": int64(1), "protocol": "TCP", "targetPort": int64(1)}}}
	default:
		return nil, ErrInvalid
	}
	fields["apiVersion"], fields["kind"] = version, kind
	fields["metadata"] = map[string]any{"namespace": plan.Namespace(), "name": name}
	return &unstructured.Unstructured{Object: fields}, nil
}
