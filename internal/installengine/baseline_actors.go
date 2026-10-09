// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"reflect"
	"time"

	"github.com/gobha-me/arcadectl/internal/installstate"
	authv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// Closed, short-lived authority for baseline dry-run proof, not ordinary
// installer effects or a persistent receipt. All identities are original
// signed installation access; no accounts, permissions or tokens are minted.
type baselineActors struct {
	baseline *ClusterSecurityBaseline
	snapshot *installstate.Snapshot
	access   map[installstate.Key]admissionIdentity
	policies map[installstate.Key]admissionIdentity
	clients  map[admissionActor]*HTTPAccess
}

func (c *ClusterSecurityBaseline) newBaselineActors(ctx context.Context, snapshot *installstate.Snapshot) (*baselineActors, error) {
	if c == nil || c.engine == nil || c.engine.baseline == nil || c.access == nil || c.engine.access != c.access || ctx == nil || snapshot == nil || !c.access.actorCompatible() {
		return nil, ErrSecurityBaseline
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	access, err := c.engine.baseline.runtimeAccessWitness(ctx, snapshot)
	if err != nil {
		return nil, ErrSecurityBaseline
	}
	policies, err := c.configured(ctx, snapshot)
	if err != nil {
		return nil, ErrSecurityBaseline
	}
	actors := &baselineActors{baseline: c, snapshot: snapshot, access: access, policies: policies, clients: map[admissionActor]*HTTPAccess{}}
	for _, actor := range []admissionActor{ordinaryControllerActor, destroyControllerActor} {
		permission := baselineMaintenancePermission(snapshot.Anchor().Namespace)
		permission.ResourceAttributes.Name = actor.account()
		if c.access.authorize(ctx, permission) != nil {
			return nil, ErrSecurityBaseline
		}
		client, err := c.access.actorClientForPurpose(actor, snapshot.Anchor().Namespace, baselineAdmissionPurpose)
		if err != nil {
			return nil, ErrSecurityBaseline
		}
		actors.clients[actor] = client
	}
	if actors.verify(ctx) != nil {
		return nil, ErrSecurityBaseline
	}
	return actors, nil
}

func baselineMaintenancePermission(namespace string) authv1.SelfSubjectAccessReviewSpec {
	// On both supported profiles the CEL authorizer uses APIVersion "*".
	// An ordinary v1 review can disagree with the rule's actual decision.
	return authv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authv1.ResourceAttributes{Version: "*", Resource: "serviceaccounts", Namespace: namespace, Name: "arcadectl-destroy-controller", Verb: "impersonate"}}
}

// This finite catalog establishes wildcard authorization decisions, including
// the exact CEL maintenance decision. It does NOT certify actual header
// impersonation containment: the impersonation filter uses an empty version,
// but both supported SSAR handlers normalize an empty version to "*". Do not
// substitute an empty-version SSAR or RBAC-only evidence for that separate
// actor-authenticated behavioral proof. No producer identity is impersonated
// by this protocol, and these reviews grant no mutation or runtime authority.
func baselineAuthorizationContainmentPermissions(namespace string) []authv1.SelfSubjectAccessReviewSpec {
	permissions := []authv1.SelfSubjectAccessReviewSpec{
		baselineMaintenancePermission(namespace),
		{ResourceAttributes: &authv1.ResourceAttributes{Version: "*", Resource: "serviceaccounts", Namespace: namespace, Name: "arcadectl-controller", Verb: "impersonate"}},
		{ResourceAttributes: &authv1.ResourceAttributes{Version: "*", Resource: "serviceaccounts", Namespace: namespace, Name: "arcadectl-api", Verb: "impersonate"}},
		{ResourceAttributes: &authv1.ResourceAttributes{Version: "*", Resource: "serviceaccounts", Namespace: namespace, Name: "arcadectl-destroy-admin", Verb: "impersonate"}},
		{ResourceAttributes: &authv1.ResourceAttributes{Version: "*", Resource: "users", Name: "system:kube-controller-manager", Verb: "impersonate"}},
	}
	for _, name := range []string{"replicaset-controller", "job-controller", "replication-controller", "daemon-set-controller", "statefulset-controller", "deployment-controller", "cronjob-controller", "generic-garbage-collector"} {
		permissions = append(permissions, authv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authv1.ResourceAttributes{Version: "*", Resource: "serviceaccounts", Namespace: "kube-system", Name: name, Verb: "impersonate"}})
	}
	return permissions
}

func baselineActorPermission(identity *actorWireIdentity, key installstate.Key, operation admissionProbeOperation) (authv1.SelfSubjectAccessReviewSpec, error) {
	if identity == nil || !identity.baselineAllows(key, operation) {
		return authv1.SelfSubjectAccessReviewSpec{}, ErrInvalid
	}
	_, plural, err := baselineProbePath(key)
	gv, versionErr := schema.ParseGroupVersion(key.APIVersion)
	verb, name := "update", key.Name
	if operation == probeCreateOperation {
		verb, name = "create", ""
	} else if operation == probeDeleteAccountOperation || operation == probeDeleteExecutableOperation || operation == probeDeleteIdentityOperation {
		verb = "delete"
	} else if operation == probePatchMetadataOperation {
		verb = "patch"
	}
	if err != nil || versionErr != nil {
		return authv1.SelfSubjectAccessReviewSpec{}, ErrInvalid
	}
	return authv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authv1.ResourceAttributes{Group: gv.Group, Version: gv.Version, Resource: plural, Namespace: key.Namespace, Name: name, Verb: verb}}, nil
}

func (actors *baselineActors) verify(ctx context.Context) error {
	if actors == nil || actors.baseline == nil || ctx == nil || actors.snapshot == nil || len(actors.clients) != 2 {
		return ErrSecurityBaseline
	}
	c := actors.baseline
	if c.engine == nil || c.engine.baseline == nil || c.access == nil || c.engine.access != c.access || !c.access.actorCompatible() {
		return ErrSecurityBaseline
	}
	plan := c.engine.plans[actors.snapshot.Document().TargetPackage]
	if plan == nil || c.access.checkVersion(ctx, plan.Profile()) != nil {
		return ErrSecurityBaseline
	}
	current, err := c.engine.baseline.runtimeAccessWitness(ctx, actors.snapshot)
	if err != nil || !reflect.DeepEqual(current, actors.access) {
		return ErrSecurityBaseline
	}
	policies, err := c.configured(ctx, actors.snapshot)
	if err != nil || !reflect.DeepEqual(policies, actors.policies) {
		return ErrSecurityBaseline
	}
	for _, actor := range []admissionActor{ordinaryControllerActor, destroyControllerActor} {
		client := actors.clients[actor]
		if client == nil || client.actor == nil || client.actor.actor != actor || client.actor.namespace != actors.snapshot.Anchor().Namespace || client.actor.purpose != baselineAdmissionPurpose {
			return ErrSecurityBaseline
		}
		for _, permission := range baselineAuthorizationContainmentPermissions(actors.snapshot.Anchor().Namespace) {
			if client.authorizationDecision(ctx, permission, false) != nil {
				return ErrSecurityBaseline
			}
		}
	}
	// A successful collection of reviews does not pin original identities.
	// Repeat both independent witnesses across the entire two-actor catalog.
	current, err = c.engine.baseline.runtimeAccessWitness(ctx, actors.snapshot)
	if err != nil || !reflect.DeepEqual(current, actors.access) {
		return ErrSecurityBaseline
	}
	policies, err = c.configured(ctx, actors.snapshot)
	if err != nil || !reflect.DeepEqual(policies, actors.policies) {
		return ErrSecurityBaseline
	}
	// Configuration performs additional remote reads. Close access again so
	// replacement or withdrawal reached during that closing configuration
	// cannot disappear between the witness sets and this return.
	current, err = c.engine.baseline.runtimeAccessWitness(ctx, actors.snapshot)
	if err != nil || !reflect.DeepEqual(current, actors.access) {
		return ErrSecurityBaseline
	}
	return nil
}

// Callers still owe strict whole permitted-result validation and complete
// original runtime-Pod/producer inventory. This primitive alone is NOT the
// runtime guard. Each request carries fresh actor permission and independent
// denial of maintenance rights, with original access/configuration brackets.
func (actors *baselineActors) probe(ctx context.Context, actor admissionActor, operation admissionProbeOperation, object *unstructured.Unstructured, policy, binding, message string) (*unstructured.Unstructured, error) {
	if actors == nil || ctx == nil || object == nil {
		return nil, ErrInvalid
	}
	client := actors.clients[actor]
	if client == nil || client.actor == nil || client.actor.purpose != baselineAdmissionPurpose {
		return nil, ErrInvalid
	}
	key := installstate.Key{APIVersion: object.GetAPIVersion(), Kind: object.GetKind(), Namespace: object.GetNamespace(), Name: object.GetName()}
	permission, err := baselineActorPermission(client.actor, key, operation)
	if err != nil {
		return nil, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	discovery, discoveryErr := actors.baseline.access.discover(ctx, key.APIVersion)
	if discoveryErr != nil || !discoveredPermission(discovery, proofPermission{spec: permission, kind: key.Kind}) {
		return nil, ErrSecurityBaseline
	}
	if actors.verify(ctx) != nil || client.authorize(ctx, permission) != nil || actors.verify(ctx) != nil {
		return nil, ErrSecurityBaseline
	}
	result, err := client.probeOperation(ctx, operation, object, policy, binding, message)
	if err != nil || actors.verify(ctx) != nil {
		return nil, ErrSecurityBaseline
	}
	return result, nil
}
