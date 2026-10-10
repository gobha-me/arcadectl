// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	authv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// Immutable scalar descriptors are finite authority for nonpersistent SSARs,
// never rights to perform the described write. A private scope pointer keeps
// actorWireIdentity comparable for the inner authenticated one-attempt guard.
type baselineDeniedDescriptor struct{ group, version, resource, subresource, namespace, name, verb string }
type baselineDeniedScope struct {
	namespace string
	rows      map[admissionActor][]baselineDeniedDescriptor
}

func (r baselineDeniedDescriptor) attributes() *authv1.ResourceAttributes {
	return &authv1.ResourceAttributes{Group: r.group, Version: r.version, Resource: r.resource, Subresource: r.subresource, Namespace: r.namespace, Name: r.name, Verb: r.verb}
}

func (s *baselineDeniedScope) allows(identity actorWireIdentity, a *authv1.ResourceAttributes) bool {
	if s == nil || identity.purpose != baselineDeniedReviewPurpose || identity.deniedScope != s || identity.namespace != s.namespace || !installrender.ValidNamespace(s.namespace) ||
		identity.username != "system:serviceaccount:"+s.namespace+":"+identity.actor.account() ||
		identity.actor != ordinaryControllerActor && identity.actor != destroyControllerActor || a == nil || a.FieldSelector != nil || a.LabelSelector != nil {
		return false
	}
	row := baselineDeniedDescriptor{a.Group, a.Version, a.Resource, a.Subresource, a.Namespace, a.Name, a.Verb}
	for _, allowed := range s.rows[identity.actor] {
		if row == allowed {
			return true
		}
	}
	return false
}

// Called only after the closed provider has proved original access and complete
// executable evidence. Copies all scalar inputs, authenticates cluster names
// against registered signed plans, and accepts no caller review descriptor.
func (e *Engine) baselineDeniedCatalog(d installstate.Document, access map[installstate.Key]admissionIdentity, guarded map[installstate.Key]*unstructured.Unstructured) (*baselineDeniedScope, error) {
	if e == nil || !e.baselineObservable(d) || access == nil || guarded == nil {
		return nil, ErrSecurityBaseline
	}
	ns := d.Namespace
	signedAccess := map[installstate.Key]bool{}
	for _, digest := range []string{d.ActivePackage, d.TargetPackage, d.PreviousPackage} {
		plan := e.plans[digest]
		if plan == nil {
			continue
		}
		for _, r := range plan.ResourceMetadata() {
			key := installstate.Key{APIVersion: r.APIVersion, Kind: r.Kind, Namespace: r.Namespace, Name: r.Name}
			if accessRetirementKey(key) {
				signedAccess[key] = true
			}
		}
	}
	for _, name := range []string{"arcadectl-controller", "arcadectl-destroy-controller", "arcadectl-api", "arcadectl-destroy-admin"} {
		if !receiptUID.MatchString(string(access[installstate.Key{APIVersion: "v1", Kind: "ServiceAccount", Namespace: ns, Name: name}].UID)) {
			return nil, ErrSecurityBaseline
		}
	}
	for key, identity := range access {
		if !accessRetirementKey(key) || !receiptUID.MatchString(string(identity.UID)) || !baselineParentRV(identity.ResourceVersion) || key.Namespace != "" && key.Namespace != ns {
			return nil, ErrSecurityBaseline
		}
		entry, _ := e.inventory(d, key)
		if !signedAccess[key] || entry == nil || entry.UID != identity.UID {
			return nil, ErrSecurityBaseline
		}
	}
	// At least the complete active/target original access catalog is required.
	plan := e.plans[d.TargetPackage]
	if d.ActivePackage != "" {
		plan = e.plans[d.ActivePackage]
	}
	if plan == nil {
		return nil, ErrSecurityBaseline
	}
	for _, r := range plan.ResourceMetadata() {
		key := installstate.Key{APIVersion: r.APIVersion, Kind: r.Kind, Namespace: r.Namespace, Name: r.Name}
		if accessRetirementKey(key) && access[key].UID == "" {
			return nil, ErrSecurityBaseline
		}
	}
	names := map[string]map[string]bool{}
	for _, c := range baselineExecutableCollections {
		names[c.kind] = map[string]bool{}
		for _, name := range []string{"arcadectl-controller", "arcadectl-destroy-controller", "arcadectl-api", "arcadectl-destroy-admin"} {
			names[c.kind][name] = true
		}
	}
	for key, object := range guarded {
		selected, err := baselineGuardedExecutable(key, object)
		if err != nil || !selected || object == nil || !receiptUID.MatchString(string(object.GetUID())) || !baselineParentRV(object.GetResourceVersion()) || names[key.Kind] == nil || key.Namespace != ns {
			return nil, ErrSecurityBaseline
		}
		names[key.Kind][key.Name] = true
	}
	// Proxy authorization retains its raw colon-qualified URL name. Enumerate
	// canonical planned endpoints, not arbitrary ports/textual aliases or an
	// absence-of-every-ambient-RBAC-grant claim. The separate complete effective-
	// rules protocol closes actual native resourceNames aliases for these targets.
	podProxy := map[string]map[string]bool{}
	serviceProxy := map[string]map[string]bool{}
	for _, name := range []string{"arcadectl-controller", "arcadectl-destroy-controller", "arcadectl-api", "arcadectl-destroy-admin"} {
		podProxy[name] = baselineProxyAliases(name, nil)
		serviceProxy[name] = baselineProxyAliases(name, nil)
	}
	for key, object := range guarded {
		if key.Kind != "Pod" {
			continue
		}
		var pod corev1.Pod
		if decodeServing(object, &pod) != nil {
			return nil, ErrSecurityBaseline
		}
		var ports []string
		for _, container := range pod.Spec.Containers {
			for _, port := range container.Ports {
				if port.ContainerPort < 1 || port.ContainerPort > 65535 {
					return nil, ErrSecurityBaseline
				}
				ports = append(ports, strconv.Itoa(int(port.ContainerPort)))
			}
		}
		podProxy[key.Name] = baselineProxyAliases(key.Name, ports)
	}
	for _, digest := range []string{d.ActivePackage, d.TargetPackage, d.PreviousPackage} {
		plan := e.plans[digest]
		if plan == nil {
			continue
		}
		for _, r := range plan.Resources() {
			if r.Object.GetKind() != "Service" || !baselineReservedAccount(r.Object.GetName()) {
				continue
			}
			var service corev1.Service
			if decodeServing(r.Object, &service) != nil || service.Namespace != ns {
				return nil, ErrSecurityBaseline
			}
			var ports []string
			for _, port := range service.Spec.Ports {
				if port.Port < 1 || port.Port > 65535 {
					return nil, ErrSecurityBaseline
				}
				ports = append(ports, strconv.Itoa(int(port.Port)))
				if port.Name != "" {
					ports = append(ports, port.Name)
				}
			}
			for name := range baselineProxyAliases(service.Name, ports) {
				serviceProxy[service.Name][name] = true
			}
		}
	}
	scope := &baselineDeniedScope{namespace: ns, rows: map[admissionActor][]baselineDeniedDescriptor{}}
	for _, actor := range []admissionActor{ordinaryControllerActor, destroyControllerActor} {
		rows := map[baselineDeniedDescriptor]bool{}
		add := func(group, resource, subresource, namespace, name string, verbs ...string) {
			for _, verb := range verbs {
				rows[baselineDeniedDescriptor{group, "v1", resource, subresource, namespace, name, verb}] = true
			}
		}
		for _, name := range []string{"arcadectl-controller", "arcadectl-destroy-controller", "arcadectl-api", "arcadectl-destroy-admin"} {
			add("", "serviceaccounts", "", ns, name, "update", "patch")
			add("", "serviceaccounts", "token", ns, name, "create")
			add("rbac.authorization.k8s.io", "roles", "", ns, name, "update", "patch", "bind", "escalate")
			add("rbac.authorization.k8s.io", "rolebindings", "", ns, name, "update", "patch")
			add("", "services", "status", ns, name, "update", "patch")
			if actor == destroyControllerActor {
				add("", "services", "", ns, name, "update", "patch", "delete")
			}
		}
		if actor == destroyControllerActor {
			add("", "services", "", ns, "", "create")
		}
		add("", "serviceaccounts", "", ns, "", "deletecollection")
		add("rbac.authorization.k8s.io", "roles", "", ns, "", "deletecollection")
		add("rbac.authorization.k8s.io", "rolebindings", "", ns, "", "deletecollection")
		for _, aliases := range podProxy {
			for name := range aliases {
				add("", "pods", "proxy", ns, name, "get", "create", "update", "patch", "delete")
			}
		}
		for _, aliases := range serviceProxy {
			for name := range aliases {
				add("", "services", "proxy", ns, name, "get", "create", "update", "patch", "delete")
			}
		}
		for _, c := range baselineExecutableCollections {
			gv, err := schema.ParseGroupVersion(c.gv)
			if err != nil || gv.Version != "v1" {
				return nil, ErrSecurityBaseline
			}
			add(gv.Group, c.plural, "", ns, "", "deletecollection")
			switch c.kind {
			case "ReplicaSet", "DaemonSet", "StatefulSet", "ReplicationController", "CronJob":
				add(gv.Group, c.plural, "", ns, "", "create")
			case "Pod":
				add("", "pods", "", ns, "", "create")
			case "Deployment":
				if actor == destroyControllerActor {
					add(gv.Group, c.plural, "", ns, "", "create")
				}
			}
			for name := range names[c.kind] {
				add(gv.Group, c.plural, "status", ns, name, "update", "patch")
				switch c.kind {
				case "ReplicaSet", "DaemonSet", "StatefulSet", "ReplicationController", "CronJob":
					add(gv.Group, c.plural, "", ns, name, "update", "patch", "delete")
				case "Pod":
					add("", "pods", "", ns, name, "patch", "delete")
					for _, sub := range []string{"ephemeralcontainers", "resize"} {
						add("", "pods", sub, ns, name, "update", "patch")
					}
					for _, sub := range []string{"binding", "eviction"} {
						add("", "pods", sub, ns, name, "create")
					}
					for _, sub := range []string{"exec", "attach", "portforward"} {
						add("", "pods", sub, ns, name, "get", "create")
					}
					add("", "pods", "log", ns, name, "get")
				case "Job":
					add("batch", "jobs", "", ns, name, "patch")
				case "Deployment":
					if actor == destroyControllerActor {
						add("apps", "deployments", "", ns, name, "update", "patch", "delete")
					}
				}
				if c.kind == "Deployment" || c.kind == "ReplicaSet" || c.kind == "StatefulSet" || c.kind == "ReplicationController" {
					add(gv.Group, c.plural, "scale", ns, name, "update", "patch")
				}
			}
		}
		for key := range access {
			if key.Kind == "ClusterRole" {
				add("rbac.authorization.k8s.io", "clusterroles", "", "", "", "deletecollection")
				add("rbac.authorization.k8s.io", "clusterroles", "", "", "", "create")
				add("rbac.authorization.k8s.io", "clusterroles", "", "", key.Name, "update", "patch", "delete", "bind", "escalate")
			}
			if key.Kind == "ClusterRoleBinding" {
				add("rbac.authorization.k8s.io", "clusterrolebindings", "", "", "", "deletecollection")
				add("rbac.authorization.k8s.io", "clusterrolebindings", "", "", "", "create")
				add("rbac.authorization.k8s.io", "clusterrolebindings", "", "", key.Name, "update", "patch", "delete")
			}
		}
		for row := range rows {
			scope.rows[actor] = append(scope.rows[actor], row)
		}
		sort.Slice(scope.rows[actor], func(i, j int) bool {
			a, b := scope.rows[actor][i], scope.rows[actor][j]
			return strings.Join([]string{a.group, a.version, a.resource, a.subresource, a.namespace, a.name, a.verb}, "\x00") < strings.Join([]string{b.group, b.version, b.resource, b.subresource, b.namespace, b.name, b.verb}, "\x00")
		})
	}
	return scope, nil
}

func baselineProxyAliases(name string, ports []string) map[string]bool {
	result := map[string]bool{name: true, name + ":": true, ":" + name + ":": true, "http:" + name + ":": true, "https:" + name + ":": true}
	for _, port := range ports {
		result[name+":"+port] = true
		for _, scheme := range []string{"", "http", "https"} {
			result[scheme+":"+name+":"+port] = true
		}
	}
	return result
}

// A separate SSAR-only client purpose. Historical mutation clients and the
// caller-facing purpose constructor cannot select or extend this scope.
func (a *HTTPAccess) baselineDeniedClient(actor admissionActor, scope *baselineDeniedScope) (*HTTPAccess, error) {
	if scope == nil || len(scope.rows[actor]) == 0 {
		return nil, ErrInvalid
	}
	return a.frozenActorClient(actor, scope.namespace, baselineDeniedReviewPurpose, scope)
}

// Whole observation, original authority and successful explicit allowed:false
// reviews bracket this finite catalog. The eventual full guard still owes its
// behavioral driver, parent/receipt closure and operation-bound effect fence.
func (actors *baselineActors) verifyDenied(ctx context.Context, executables *baselineExecutables) error {
	return actors.verifyDeniedComposition(ctx, executables, nil)
}

// Private, original-snapshot-bound whole behavioral composition, never an
// arbitrary callback supplied by a caller. Each catalog pass closes ALL the
// opening components before effective rules close. These are paired temporal
// observations, not an atomic multi-resource cluster snapshot.
func (actors *baselineActors) verifyDeniedBehavior(ctx context.Context, behavior *baselineBehavior) error {
	if behavior == nil || behavior.actors != actors || behavior.metadata == nil || behavior.parents == nil || behavior.family == nil {
		return ErrSecurityBaseline
	}
	return actors.verifyDeniedComposition(ctx, behavior.executables, behavior)
}

func (actors *baselineActors) verifyDeniedComposition(ctx context.Context, executables *baselineExecutables, behavior *baselineBehavior) error {
	if actors == nil || actors.baseline == nil || ctx == nil || baselineDeniedObservation(actors.snapshot, executables) != nil {
		return ErrSecurityBaseline
	}
	traceBaselineBoundary(ctx, baselineBoundaryDeniedActorsOpening)
	if actors.verify(ctx) != nil {
		return ErrSecurityBaseline
	}
	traceBaselineBoundary(ctx, baselineBoundaryDeniedCatalog)
	scope, err := actors.baseline.engine.baselineDeniedCatalog(actors.snapshot.Document(), actors.access, executables.guarded)
	if err != nil {
		return ErrSecurityBaseline
	}
	traceBaselineBoundary(ctx, baselineBoundaryDeniedRulesOpening)
	rulesClients, openingRules, err := actors.rulesClients(ctx, executables)
	if err != nil {
		return ErrSecurityBaseline
	}
	clients := map[admissionActor]*HTTPAccess{}
	traceBaselineBoundary(ctx, baselineBoundaryDeniedClients)
	for _, actor := range []admissionActor{ordinaryControllerActor, destroyControllerActor} {
		client, err := actors.baseline.access.baselineDeniedClient(actor, scope)
		if err != nil {
			return ErrSecurityBaseline
		}
		clients[actor] = client
	}
	for pass := 0; pass < 2; pass++ {
		traceBaselineBoundary(ctx, baselineBoundaryDeniedReviews)
		if baselineDeniedReviews(ctx, scope, clients) != nil {
			return ErrSecurityBaseline
		}
		traceBaselineBoundary(ctx, baselineBoundaryDeniedExecutablesClosing)
		closing, err := actors.baseline.collectExecutables(ctx, actors.snapshot)
		if err != nil {
			return ErrSecurityBaseline
		}
		traceBaselineBoundary(ctx, baselineBoundaryDeniedExecutablesStable)
		if !sameBaselineExecutables(executables, closing) {
			traceBaselineExecutableDifference(ctx, executables, closing)
			return ErrSecurityBaseline
		}
		traceBaselineBoundary(ctx, baselineBoundaryDeniedOriginalsClosing)
		if behavior != nil && behavior.closeOriginals(ctx, closing) != nil {
			return ErrSecurityBaseline
		}
		traceBaselineBoundary(ctx, baselineBoundaryDeniedActorsClosing)
		if actors.verify(ctx) != nil || ctx.Err() != nil {
			return ErrSecurityBaseline
		}
		traceBaselineBoundary(ctx, baselineBoundaryDeniedRulesClosing)
		for _, actor := range []admissionActor{ordinaryControllerActor, destroyControllerActor} {
			rules, err := rulesClients[actor].baselineRules(ctx)
			if err != nil || !baselineProxyRulesContained(rules, closing) || !sameBaselineRules(openingRules[actor], rules) {
				return ErrSecurityBaseline
			}
		}
		traceBaselineBoundary(ctx, baselineBoundaryDeniedActorsFinal)
		if actors.verify(ctx) != nil || ctx.Err() != nil {
			return ErrSecurityBaseline
		}
	}
	return nil
}

// Bind catalog membership to the sealed complete LIST and whole GET witness;
// a dropped guarded key or an invented GET cannot shrink the negative proof.
func baselineDeniedObservation(snapshot *installstate.Snapshot, executables *baselineExecutables) error {
	if snapshot == nil || executables == nil || executables.observation == nil || executables.whole == nil || executables.guarded == nil {
		return ErrSecurityBaseline
	}
	observed := executables.observation.Journal()
	if observed == nil || observed.Anchor() != snapshot.Anchor() || observed.ResourceVersion() != snapshot.ResourceVersion() || !bytes.Equal(observed.Bytes(), snapshot.Bytes()) {
		return ErrSecurityBaseline
	}
	listed := executables.observation.Whole()
	if listed == nil || len(listed) != len(executables.whole) {
		return ErrSecurityBaseline
	}
	count := 0
	for key, whole := range executables.whole {
		if key.Namespace != snapshot.Anchor().Namespace || !baselineExecutableListedMatches(key, listed[key], whole) {
			return ErrSecurityBaseline
		}
		selected, err := baselineGuardedExecutable(key, whole)
		if err != nil {
			return ErrSecurityBaseline
		}
		if selected {
			count++
			if candidate := executables.guarded[key]; candidate == nil || !reflect.DeepEqual(candidate.Object, whole.Object) {
				return ErrSecurityBaseline
			}
		}
	}
	if len(executables.guarded) != count {
		return ErrSecurityBaseline
	}
	return nil
}
