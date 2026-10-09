// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"reflect"

	"github.com/gobha-me/arcadectl/internal/installbaseline"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	authv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type actorWirePurpose uint8

const (
	runtimeAdmissionPurpose actorWirePurpose = iota // preserves old private identities
	baselineAdmissionPurpose
	baselineDeniedReviewPurpose // SSAR only; never an executable mutation protocol
	baselineRulesReviewPurpose  // exact-namespace SSRR only; no SSAR or mutations
)

func baselineReservedAccount(name string) bool {
	switch name {
	case "arcadectl-controller", "arcadectl-api", "arcadectl-destroy-controller", "arcadectl-destroy-admin":
		return true
	}
	return false
}

func baselineIdentityKey(key installstate.Key) bool {
	switch key.APIVersion + "/" + key.Kind {
	case "v1/ServiceAccount", "v1/Service", "rbac.authorization.k8s.io/v1/Role", "rbac.authorization.k8s.io/v1/RoleBinding":
		return true
	}
	return false
}

// This protocol admits only dry-run behavioral requests for the two software
// controllers. It has no GameDestroy, PVC, token, persistent-write, generic GET
// or arbitrary impersonation route. Parent original-identity/phase proof must
// still bracket every operation; a transport alone is not runtime authority.
func (identity actorWireIdentity) baselineAllows(key installstate.Key, operation admissionProbeOperation) bool {
	if identity.purpose != baselineAdmissionPurpose ||
		identity.actor != ordinaryControllerActor && identity.actor != destroyControllerActor ||
		key.Namespace != identity.namespace || !installrender.ValidNamespace(key.Namespace) || !addressPart(key.Name) {
		return false
	}
	switch key.APIVersion + "/" + key.Kind {
	case "batch/v1/Job":
		return operation == probeCreateOperation || operation == probeUpdateOperation || operation == probeDeleteExecutableOperation
	case "apps/v1/Deployment":
		return identity.actor == ordinaryControllerActor && (operation == probeCreateOperation || operation == probeUpdateOperation || operation == probeDeleteExecutableOperation || operation == probePatchMetadataOperation)
	case "v1/Pod":
		return operation == probeUpdateOperation
	case "v1/ServiceAccount":
		return (operation == probeCreateOperation || operation == probeDeleteAccountOperation) && baselineReservedAccount(key.Name)
	case "rbac.authorization.k8s.io/v1/Role", "rbac.authorization.k8s.io/v1/RoleBinding":
		return (operation == probeCreateOperation || operation == probeDeleteIdentityOperation) && baselineReservedAccount(key.Name)
	case "v1/Service":
		return identity.actor == ordinaryControllerActor && baselineReservedAccount(key.Name) && (operation == probeCreateOperation || operation == probeUpdateOperation || operation == probeDeleteIdentityOperation || operation == probePatchMetadataOperation)
	}
	return false
}

func baselineProbePath(key installstate.Key) (string, string, error) {
	if !installrender.ValidNamespace(key.Namespace) || !addressPart(key.Name) {
		return "", "", ErrInvalid
	}
	prefix, plural := "/api/v1", ""
	switch key.APIVersion + "/" + key.Kind {
	case "v1/Pod":
		plural = "pods"
	case "v1/ServiceAccount":
		plural = "serviceaccounts"
	case "v1/Service":
		plural = "services"
	case "rbac.authorization.k8s.io/v1/Role":
		prefix, plural = "/apis/rbac.authorization.k8s.io/v1", "roles"
	case "rbac.authorization.k8s.io/v1/RoleBinding":
		prefix, plural = "/apis/rbac.authorization.k8s.io/v1", "rolebindings"
	case "batch/v1/Job":
		prefix, plural = "/apis/batch/v1", "jobs"
	case "apps/v1/Deployment":
		prefix, plural = "/apis/apps/v1", "deployments"
	default:
		return "", "", ErrInvalid
	}
	return prefix + "/namespaces/" + key.Namespace + "/" + plural, plural, nil
}

func expectedBaselineProbeDenial(key installstate.Key, plural, policy, binding, validation string) (map[string]any, error) {
	_, expectedPlural, err := baselineProbePath(key)
	family := "template"
	if baselineIdentityKey(key) {
		family = "identity"
	} else if key.Kind == "Pod" {
		family = "pod"
	}
	name := "arcadectl-identity-" + family + "-" + key.Namespace
	gv, versionErr := schema.ParseGroupVersion(key.APIVersion)
	if err != nil || versionErr != nil || plural != expectedPlural || policy != name || binding != name || validation != installbaseline.DenialMessage {
		return nil, ErrInvalid
	}
	return expectedProbeDenialGroup(key, plural, gv.Group, policy, binding, validation)
}

// Reviews are nonpersistent evaluations with fixed names/routes. Negative
// containment of unsupported producer/scale writes must not be relabelled as
// admission behavior. No extra rights are created to make a probe work.
func (identity actorWireIdentity) baselineAllowsReview(a *authv1.ResourceAttributes) bool {
	if identity.purpose != baselineAdmissionPurpose || a == nil ||
		identity.actor != ordinaryControllerActor && identity.actor != destroyControllerActor ||
		!installrender.ValidNamespace(identity.namespace) ||
		a.FieldSelector != nil || a.LabelSelector != nil {
		return false
	}
	if a.Verb == "impersonate" {
		for _, permission := range baselineAuthorizationContainmentPermissions(identity.namespace) {
			if reflect.DeepEqual(a, permission.ResourceAttributes) {
				return true
			}
		}
		return false
	}
	if a.Namespace != identity.namespace || a.Version != "v1" {
		return false
	}
	// These are review-only negative permission checks. There is no token,
	// bind/escalate, SA or RBAC UPDATE/PATCH mutation primitive.
	if a.Group == "" && a.Resource == "serviceaccounts" && a.Subresource == "token" {
		return a.Verb == "create" && baselineReservedAccount(a.Name)
	}
	if a.Subresource == "scale" {
		if a.Name != "arcadectl-controller" || a.Verb != "create" && a.Verb != "update" && a.Verb != "patch" && a.Verb != "delete" {
			return false
		}
		return a.Group == "apps" && (a.Resource == "deployments" || a.Resource == "replicasets" || a.Resource == "statefulsets") ||
			a.Group == "" && a.Resource == "replicationcontrollers"
	}
	if a.Subresource != "" {
		return false
	}
	if (a.Group == "" && a.Resource == "serviceaccounts" || a.Group == "rbac.authorization.k8s.io" && (a.Resource == "roles" || a.Resource == "rolebindings")) && (a.Verb == "update" || a.Verb == "patch") {
		return baselineReservedAccount(a.Name)
	}
	if a.Group == "rbac.authorization.k8s.io" && (a.Resource == "roles" || a.Resource == "rolebindings") && (a.Verb == "bind" || a.Verb == "escalate") {
		return baselineReservedAccount(a.Name)
	}
	// These fixed review-only routes certify DENIED namespace containment.
	// They deliberately do not create any corresponding mutation opcode.
	if a.Group == "apps" && (a.Resource == "replicasets" || a.Resource == "daemonsets" || a.Resource == "statefulsets" || a.Resource == "deployments" && identity.actor == destroyControllerActor) ||
		a.Group == "batch" && a.Resource == "cronjobs" || a.Group == "" && (a.Resource == "replicationcontrollers" || a.Resource == "services" && identity.actor == destroyControllerActor) {
		return a.Verb == "create" && a.Name == "" ||
			(a.Verb == "update" || a.Verb == "patch" || a.Verb == "delete") && a.Name == "arcadectl-controller"
	}
	if a.Group == "" && a.Resource == "pods" && (a.Verb == "create" || a.Verb == "patch" || a.Verb == "delete") ||
		a.Group == "batch" && a.Resource == "jobs" && a.Verb == "patch" {
		return a.Verb == "create" && a.Name == "" || a.Verb != "create" && a.Name == "arcadectl-controller"
	}
	key := installstate.Key{APIVersion: a.Version, Namespace: a.Namespace, Name: a.Name}
	operation := probeUpdateOperation
	if a.Verb == "create" && a.Name == "" {
		operation, key.Name = probeCreateOperation, "authorization-collection"
		if a.Group == "" && (a.Resource == "serviceaccounts" || a.Resource == "services") || a.Group == "rbac.authorization.k8s.io" && (a.Resource == "roles" || a.Resource == "rolebindings") {
			// CREATE authorization is collection-scoped even though the
			// behavioral protocol permits only the four fixed names.
			key.Name = "arcadectl-controller"
		}
	} else if a.Verb == "delete" {
		operation = probeDeleteAccountOperation
		if a.Group == "batch" && a.Resource == "jobs" || a.Group == "apps" && a.Resource == "deployments" {
			operation = probeDeleteExecutableOperation
		} else if a.Group == "" && a.Resource == "services" || a.Group == "rbac.authorization.k8s.io" && (a.Resource == "roles" || a.Resource == "rolebindings") {
			operation = probeDeleteIdentityOperation
		}
	} else if a.Verb == "patch" {
		operation = probePatchMetadataOperation
	} else if a.Verb != "update" {
		return false
	}
	switch {
	case a.Group == "" && a.Resource == "pods":
		key.Kind = "Pod"
	case a.Group == "" && a.Resource == "serviceaccounts":
		key.Kind = "ServiceAccount"
	case a.Group == "" && a.Resource == "services":
		key.Kind = "Service"
	case a.Group == "rbac.authorization.k8s.io" && a.Resource == "roles":
		key.APIVersion, key.Kind = "rbac.authorization.k8s.io/v1", "Role"
	case a.Group == "rbac.authorization.k8s.io" && a.Resource == "rolebindings":
		key.APIVersion, key.Kind = "rbac.authorization.k8s.io/v1", "RoleBinding"
	case a.Group == "apps" && a.Resource == "deployments":
		key.APIVersion, key.Kind = "apps/v1", "Deployment"
	case a.Group == "batch" && a.Resource == "jobs":
		key.APIVersion, key.Kind = "batch/v1", "Job"
	default:
		return false
	}
	return identity.baselineAllows(key, operation)
}
