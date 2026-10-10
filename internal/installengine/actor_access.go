// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	authv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"
)

type admissionActor uint8

const (
	ordinaryControllerActor admissionActor = iota + 1
	destroyControllerActor
	destroyAdministratorActor
)

func (actor admissionActor) account() string {
	switch actor {
	case ordinaryControllerActor:
		return "arcadectl-controller"
	case destroyControllerActor:
		return "arcadectl-destroy-controller"
	case destroyAdministratorActor:
		return "arcadectl-destroy-admin"
	}
	return ""
}

// Selection is explicit, not an authentication fallback or permission grant.
// The final administrator CLI/provider must select this existing-right mode.
type actorAccessMode uint8

const existingScopedImpersonation actorAccessMode = 1

type admissionActors struct {
	admission *ClusterAdmission
	request   LifecycleCheck
	witness   map[installstate.Key]admissionIdentity
	policies  *admissionConfiguration
	clients   map[admissionActor]*HTTPAccess // never exported as generic access
}

func (a *ClusterAdmission) newActors(ctx context.Context, request LifecycleCheck, mode actorAccessMode) (*admissionActors, error) {
	if a == nil || a.prerequisites == nil || ctx == nil || request.Checkpoint != AdmissionEffective || request.Snapshot == nil || mode != existingScopedImpersonation || request.Options.Now.IsZero() {
		return nil, ErrInvalid
	}
	p := a.prerequisites
	if p.engine == nil || p.access == nil || p.engine.access != p.access || p.access.frozen == nil || !p.access.direct {
		return nil, ErrInvalid
	}
	// Never replace an already selected effective identity, supplied transport,
	// routing callback or credential plugin with an apparently working actor.
	if !p.access.actorCompatible() {
		return nil, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	witness, err := a.actorAccessWitness(ctx, request)
	if err != nil {
		return nil, ErrAdmission
	}
	policies, err := a.configured(ctx, request)
	if err != nil {
		return nil, ErrAdmission
	}
	discovery, err := p.access.discover(ctx, "v1")
	if err != nil {
		return nil, ErrAdmission
	}
	actors := &admissionActors{admission: a, request: request, witness: witness, policies: policies, clients: map[admissionActor]*HTTPAccess{}}
	for _, actor := range []admissionActor{ordinaryControllerActor, destroyControllerActor, destroyAdministratorActor} {
		key := installstate.Key{APIVersion: "v1", Kind: "ServiceAccount", Namespace: request.Target.Namespace(), Name: actor.account()}
		get, err := publicPermission(key, "get")
		if err != nil || !discoveredPermission(discovery, get) {
			return nil, ErrAdmission
		}
		// 'impersonate' is an authorization-only verb, not a discovery route.
		permission := get.spec
		permission.ResourceAttributes.Verb = "impersonate"
		if p.access.authorize(ctx, permission) != nil {
			return nil, ErrAdmission
		}
		access, err := p.access.actorClient(actor, key.Namespace)
		if err != nil {
			return nil, ErrAdmission
		}
		actors.clients[actor] = access
	}
	if actors.verify(ctx) != nil {
		return nil, ErrAdmission
	}
	return actors, nil
}

func (a *HTTPAccess) actorCompatible() bool {
	if a == nil || !a.direct || a.frozen == nil || a.actor != nil {
		return false
	}
	c := a.frozen
	return c.Impersonate.UserName == "" && c.Impersonate.UID == "" && len(c.Impersonate.Groups) == 0 && len(c.Impersonate.Extra) == 0 && c.WrapTransport == nil && c.Transport == nil && c.Proxy == nil && c.Dial == nil && c.ExecProvider == nil && c.AuthProvider == nil
}

// Private transport construction, not authorization or original-inventory
// evidence. Only newActors grants production use after independent proofs.
func (a *HTTPAccess) actorClient(actor admissionActor, namespace string) (*HTTPAccess, error) {
	return a.actorClientForPurpose(actor, namespace, runtimeAdmissionPurpose)
}

// Separate finite protocols share authentication and the inner one-attempt
// wire guard, not operation authority. Existing runtime clients retain exactly
// their historical routes; baseline clients cannot use those runtime routes.
func (a *HTTPAccess) actorClientForPurpose(actor admissionActor, namespace string, purpose actorWirePurpose) (*HTTPAccess, error) {
	if !a.actorCompatible() || actor.account() == "" || !installrender.ValidNamespace(namespace) ||
		purpose != runtimeAdmissionPurpose && purpose != baselineAdmissionPurpose ||
		purpose == baselineAdmissionPurpose && actor != ordinaryControllerActor && actor != destroyControllerActor {
		return nil, ErrInvalid
	}
	return a.frozenActorClient(actor, namespace, purpose, nil)
}

// Private shared authentication machinery, not a public actor/scope selector.
// Each entrypoint validates its own finite purpose before arriving here.
func (a *HTTPAccess) frozenActorClient(actor admissionActor, namespace string, purpose actorWirePurpose, scope *baselineDeniedScope) (*HTTPAccess, error) {
	if !a.actorCompatible() || !installrender.ValidNamespace(namespace) || actor.account() == "" ||
		purpose != runtimeAdmissionPurpose && purpose != baselineAdmissionPurpose && purpose != baselineDeniedReviewPurpose && purpose != baselineRulesReviewPurpose ||
		(purpose == baselineAdmissionPurpose || purpose == baselineRulesReviewPurpose) && actor != ordinaryControllerActor && actor != destroyControllerActor ||
		purpose == baselineDeniedReviewPurpose && (scope == nil || scope.namespace != namespace || actor != ordinaryControllerActor && actor != destroyControllerActor) ||
		purpose != baselineDeniedReviewPurpose && scope != nil {
		return nil, ErrInvalid
	}
	c := a.frozen
	config := rest.CopyConfig(c) // already-frozen credentials; no file reload
	identity := actorWireIdentity{actor: actor, purpose: purpose, namespace: namespace, username: "system:serviceaccount:" + namespace + ":" + actor.account(), deniedScope: scope}
	if c.BearerToken != "" {
		identity.authorization = "Bearer " + c.BearerToken
	} else if c.Username != "" || c.Password != "" {
		identity.authorization = "Basic " + base64.StdEncoding.EncodeToString([]byte(c.Username+":"+c.Password))
	}
	config.Impersonate = rest.ImpersonationConfig{UserName: identity.username}
	config.WrapTransport = func(next http.RoundTripper) http.RoundTripper {
		return actorWireTransport{next: next, identity: identity}
	}
	access, err := NewDirectHTTPAccess(config)
	if err != nil {
		return nil, ErrInvalid
	}
	access.actor = &identity
	return access, nil
}

// All original signed access objects must remain live, including during a
// mixed-package upgrade. Missing identities are never default/name adoption.
func (a *ClusterAdmission) actorAccessWitness(ctx context.Context, request LifecycleCheck) (map[installstate.Key]admissionIdentity, error) {
	p := a.prerequisites
	d := request.Snapshot.Document()
	if d.Pending != nil || d.AdmissionRetirementRevision != 0 || request.Mode != d.Mode || request.Target == nil || request.Target.Digest() != d.TargetPackage || p.original(ctx, request.Snapshot) != nil {
		return nil, ErrAdmission
	}
	if _, err := p.permissions(request); err != nil {
		return nil, ErrAdmission
	}
	witness := map[installstate.Key]admissionIdentity{}
	for _, resource := range request.Target.ResourceMetadata() {
		key := installstate.Key{APIVersion: resource.APIVersion, Kind: resource.Kind, Namespace: resource.Namespace, Name: resource.Name}
		if !accessRetirementKey(key) {
			continue
		}
		entry, template := p.engine.inventory(d, key)
		if entry == nil || template == nil {
			return nil, ErrAdmission
		}
		live, err := p.access.Get(ctx, key)
		if err != nil || template.MatchLive(live, entry.UID) != nil {
			return nil, ErrAdmission
		}
		witness[key] = admissionIdentity{entry.UID, live.GetResourceVersion(), template.Hash()}
	}
	for _, actor := range []admissionActor{ordinaryControllerActor, destroyControllerActor, destroyAdministratorActor} {
		key := installstate.Key{APIVersion: "v1", Kind: "ServiceAccount", Namespace: d.Namespace, Name: actor.account()}
		if _, found := witness[key]; !found {
			return nil, ErrAdmission
		}
	}
	return witness, nil
}

func (actors *admissionActors) verify(ctx context.Context) error {
	if actors == nil || actors.admission == nil || ctx == nil {
		return ErrInvalid
	}
	current, err := actors.admission.actorAccessWitness(ctx, actors.request)
	if err != nil || !reflect.DeepEqual(current, actors.witness) {
		return ErrAdmission
	}
	policies, err := actors.admission.configured(ctx, actors.request)
	if err != nil || !sameAdmissionConfiguration(policies, actors.policies) {
		return ErrAdmission
	}
	return nil
}

// probe exposes only fixed actor/kind/operation combinations and dry-run
// effects. The complete provider must additionally own fixtures, validate whole
// accepted shapes and prove cleanup; this primitive alone proves none of those.
func (actors *admissionActors) probe(ctx context.Context, actor admissionActor, operation admissionProbeOperation, object *unstructured.Unstructured, policy, binding, validation string) (*unstructured.Unstructured, error) {
	if actors == nil || ctx == nil || object == nil {
		return nil, ErrInvalid
	}
	access := actors.clients[actor]
	if access == nil || access.actor == nil || !actors.allowsDenial(policy, binding, validation) {
		return nil, ErrInvalid
	}
	key := installstate.Key{APIVersion: object.GetAPIVersion(), Kind: object.GetKind(), Namespace: object.GetNamespace(), Name: object.GetName()}
	if !access.actor.allows(key, operation) {
		return nil, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if actors.verify(ctx) != nil {
		return nil, ErrAdmission
	}
	permission, err := actorPermission(key, operation)
	if err != nil || access.authorize(ctx, permission.spec) != nil || actors.verify(ctx) != nil {
		return nil, ErrAdmission
	}
	result, err := access.probeOperation(ctx, operation, object, policy, binding, validation)
	if err != nil || actors.verify(ctx) != nil {
		return nil, ErrAdmission
	}
	return result, nil
}

func actorPermission(key installstate.Key, operation admissionProbeOperation) (proofPermission, error) {
	_, plural, err := probePath(key)
	verb := actorOperationVerb(operation)
	if err != nil || verb == "" {
		return proofPermission{}, ErrInvalid
	}
	gv, err := schema.ParseGroupVersion(key.APIVersion)
	if err != nil {
		return proofPermission{}, ErrInvalid
	}
	name := key.Name
	if operation == probeCreateOperation {
		name = ""
	}
	return proofPermission{spec: authv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authv1.ResourceAttributes{Group: gv.Group, Version: gv.Version, Resource: plural, Namespace: key.Namespace, Name: name, Verb: verb}}, kind: key.Kind}, nil
}

func (actors *admissionActors) allowsDenial(policy, binding, validation string) bool {
	if policy == "" && binding == "" && validation == "" {
		return true
	}
	if actors.policies == nil || policy == "" || binding == "" || validation == "" {
		return false
	}
	p, b := actors.policies.policies[policy], actors.policies.bindings[binding]
	if p == nil || b == nil || b.Spec.PolicyName != policy {
		return false
	}
	for _, signed := range p.Spec.Validations {
		if signed.Message == validation {
			return true
		}
	}
	return false
}

func actorOperationVerb(operation admissionProbeOperation) string {
	switch operation {
	case probeCreateOperation:
		return "create"
	case probeUpdateOperation:
		return "update"
	case probeDeletePVCOperation:
		return "delete"
	}
	return ""
}

type actorWireIdentity struct {
	actor               admissionActor
	purpose             actorWirePurpose
	namespace, username string
	authorization       string               // confidential, never logged/persisted/reported
	deniedScope         *baselineDeniedScope // immutable private finite SSAR descriptors
}

func (identity actorWireIdentity) allows(key installstate.Key, operation admissionProbeOperation) bool {
	if identity.actor.account() == "" || key.Namespace != identity.namespace || !addressPart(key.Name) {
		return false
	}
	if identity.purpose == baselineAdmissionPurpose {
		return identity.baselineAllows(key, operation)
	}
	if identity.purpose != runtimeAdmissionPurpose {
		return false
	}
	if key.APIVersion == "v1" && key.Kind == "Pod" && operation == probeUpdateOperation {
		return identity.actor == ordinaryControllerActor || identity.actor == destroyControllerActor
	}
	if key.APIVersion == "v1" && key.Kind == "PersistentVolumeClaim" {
		return identity.actor == ordinaryControllerActor && (operation == probeCreateOperation || operation == probeUpdateOperation) || identity.actor == destroyControllerActor && operation == probeDeletePVCOperation
	}
	return key.APIVersion == "arcade.gobha.me/v1alpha1" && key.Kind == "GameDestroy" && (identity.actor == destroyAdministratorActor && (operation == probeCreateOperation || operation == probeUpdateOperation) || identity.actor == destroyControllerActor && operation == probeUpdateOperation)
}

func (identity actorWireIdentity) allowsReview(review *authv1.SelfSubjectAccessReview) bool {
	if review == nil || review.APIVersion != "authorization.k8s.io/v1" || review.Kind != "SelfSubjectAccessReview" || !reflect.DeepEqual(review.ObjectMeta, metav1.ObjectMeta{}) || review.Spec.NonResourceAttributes != nil || review.Spec.ResourceAttributes == nil {
		return false
	}
	a := review.Spec.ResourceAttributes
	if identity.purpose == baselineDeniedReviewPurpose {
		return identity.deniedScope.allows(identity, a)
	}
	if a.Namespace != identity.namespace || a.Subresource != "" || a.FieldSelector != nil || a.LabelSelector != nil {
		if identity.purpose != baselineAdmissionPurpose {
			return false
		}
	}
	if identity.purpose == baselineAdmissionPurpose {
		return identity.baselineAllowsReview(a)
	}
	if identity.purpose != runtimeAdmissionPurpose {
		return false
	}
	operation := probeUpdateOperation
	if a.Verb == "create" && a.Name == "" {
		operation = probeCreateOperation
	} else if a.Verb == "delete" {
		operation = probeDeletePVCOperation
	} else if a.Verb != "update" {
		return false
	}
	key := installstate.Key{APIVersion: a.Version, Namespace: a.Namespace, Name: a.Name}
	if operation == probeCreateOperation {
		key.Name = "authorization-collection" // authorization has no CREATE name
	}
	switch {
	case a.Group == "" && a.Resource == "pods":
		key.Kind = "Pod"
	case a.Group == "" && a.Resource == "persistentvolumeclaims":
		key.Kind = "PersistentVolumeClaim"
	case a.Group == "arcade.gobha.me" && a.Resource == "gamedestroys":
		key.APIVersion, key.Kind = a.Group+"/"+a.Version, "GameDestroy"
	default:
		return false
	}
	return identity.allows(key, operation)
}

type actorRequestCapture struct {
	identity    actorWireIdentity
	method, url string
	body        []byte
	contentType string // empty preserves historical JSON-only captures
}

type actorWireTransport struct {
	next     http.RoundTripper
	identity actorWireIdentity
}

func (transport actorWireTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request == nil {
		return nil, ErrAdmission
	}
	attempt, ok := request.Context().Value(attemptKey{}).(*requestAttempt)
	if !ok || attempt == nil || attempt.actor == nil || attempt.actor.identity != transport.identity || !attempt.actor.guard(request) {
		return nil, ErrAdmission
	}
	return transport.next.RoundTrip(request)
}

func (capture *actorRequestCapture) guard(request *http.Request) bool {
	if capture == nil {
		return false
	}
	contentType := capture.contentType
	if contentType == "" {
		contentType = "application/json"
	}
	if contentType != "application/json" && (contentType != "application/merge-patch+json" || capture.identity.purpose != baselineAdmissionPurpose || capture.method != http.MethodPatch) {
		return false
	}
	if request == nil || request.URL == nil || request.Host != request.URL.Host || request.RequestURI != "" || request.Method != capture.method || request.URL.String() != capture.url || request.GetBody != nil || request.Body == nil || request.ContentLength != int64(len(capture.body)) || len(request.TransferEncoding) != 0 || !exactProbeHeader(request.Header, "Accept", "application/json") || !exactProbeHeader(request.Header, "Content-Type", contentType) {
		return false
	}
	userSeen, authSeen := false, false
	for key, values := range request.Header {
		switch {
		case strings.EqualFold(key, "Impersonate-User"):
			if userSeen || key != "Impersonate-User" || len(values) != 1 || values[0] != capture.identity.username {
				return false
			}
			userSeen = true
		case strings.HasPrefix(strings.ToLower(key), "impersonate-"):
			return false
		case strings.EqualFold(key, "Authorization"):
			if authSeen || key != "Authorization" || capture.identity.authorization == "" || len(values) != 1 || values[0] != capture.identity.authorization {
				return false
			}
			authSeen = true
		}
	}
	if !userSeen || authSeen != (capture.identity.authorization != "") {
		return false
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, 65537))
	_ = request.Body.Close()
	if err != nil || !bytes.Equal(body, capture.body) {
		return false
	}
	request.Body = io.NopCloser(bytes.NewReader(body))
	return true
}
