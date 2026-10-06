// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installstate"
	authv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/rest"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

type actorFixture struct {
	admission                            *ClusterAdmission
	request                              LifecycleCheck
	v                                    *lifecycleFixture
	adminReviews, actorReviews, probes   int
	denyAdmin, denyActor, forbiddenProbe bool
	denial                               map[string]any
	afterReview, afterProbe              func()
	fixtureHandler                       func(http.ResponseWriter, *http.Request) bool
}

// Uses the actual closed HTTP factory and original sealed inventory. Responses
// are fixtures, not claims of native policy evaluation or a full lifecycle.
func newActorFixture(t *testing.T) *actorFixture {
	t.Helper()
	v, s := bootstrapReadyFixture(t)
	v.fail = AdmissionEffective
	stopped := false
	for i := 0; i < 100; i++ {
		next, err := v.l.Step(context.Background(), s, v.opts)
		s = next
		if errors.Is(err, ErrLifecycle) {
			stopped = true
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if !stopped {
		t.Fatal("fixture did not reach full admission barrier")
	}
	namespace, err := v.f.access.client.CoreV1().Namespaces().Get(context.Background(), s.Anchor().Namespace, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	f := &actorFixture{v: v}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") != "Bearer FAKE-ADMIN-CANARY" {
			t.Error("frozen administrator authentication changed")
		}
		if f.fixtureHandler != nil && f.fixtureHandler(w, r) {
			return
		}
		if r.URL.Path == "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" {
			var review authv1.SelfSubjectAccessReview
			if r.Method != http.MethodPost || r.URL.RawQuery != "fieldManager=arcadectl-installer&fieldValidation=Strict" || json.NewDecoder(r.Body).Decode(&review) != nil {
				t.Error("unexpected review route or body")
				w.WriteHeader(500)
				return
			}
			allowed := true
			if user := r.Header.Get("Impersonate-User"); user == "" {
				f.adminReviews++
				a := review.Spec.ResourceAttributes
				if a == nil || a.Verb != "impersonate" || a.Resource != "serviceaccounts" || a.Group != "" || a.Version != "v1" || a.Namespace != namespace.Name || a.Name == "" || a.Subresource != "" {
					t.Error("unscoped administrator impersonation review")
				}
				allowed = !f.denyAdmin
			} else {
				f.actorReviews++
				valid := false
				for _, actor := range []admissionActor{ordinaryControllerActor, destroyControllerActor, destroyAdministratorActor} {
					identity := actorWireIdentity{actor: actor, namespace: namespace.Name, username: "system:serviceaccount:" + namespace.Name + ":" + actor.account()}
					if user == identity.username && identity.allowsReview(&review) {
						valid = true
					}
				}
				if !valid {
					t.Error("actor identity or operation review escaped fixed bounds")
				}
				allowed = !f.denyActor
			}
			body, _ := json.Marshal(review)
			var fields map[string]any
			_ = json.Unmarshal(body, &fields)
			fields["status"] = map[string]any{"allowed": allowed}
			_ = json.NewEncoder(w).Encode(fields)
			if f.afterReview != nil {
				f.afterReview()
			}
			return
		}
		if r.Method == http.MethodGet {
			if r.Header.Get("Impersonate-User") != "" {
				t.Error("actor used general GET")
			}
			if serveBootstrapObservationFixture(t, w, r, v, namespace, false) {
				return
			}
			w.WriteHeader(404)
			return
		}
		f.probes++
		if r.Header.Get("Impersonate-User") == "" || !strings.Contains(r.URL.RawQuery, "dryRun=All") {
			t.Error("unidentified or persistent actor operation")
		}
		if f.denial != nil {
			w.WriteHeader(422)
			_ = json.NewEncoder(w).Encode(f.denial)
		} else if f.forbiddenProbe {
			w.WriteHeader(403)
			_, _ = io.WriteString(w, `{"message":"PRIVATE-ERROR-CANARY"}`)
		} else {
			var object unstructured.Unstructured
			if r.Method != http.MethodPut || json.NewDecoder(r.Body).Decode(&object.Object) != nil {
				t.Error("unexpected fixture operation")
				w.WriteHeader(500)
				return
			}
			_ = json.NewEncoder(w).Encode(object.Object)
		}
		if f.afterProbe != nil {
			f.afterProbe()
		}
	}))
	t.Cleanup(server.Close)
	config := serverConfig(server)
	config.BearerToken, config.QPS, config.Burst = "FAKE-ADMIN-CANARY", 100, 200
	access, err := NewDirectHTTPAccess(config)
	if err != nil {
		t.Fatal(err)
	}
	store, err := installstate.New(access.Namespaces(), v.f.plan)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewWithAccess(access, store, v.f.engine.files, v.f.plan)
	if err != nil {
		t.Fatal(err)
	}
	f.admission, err = NewClusterAdmission(engine, access)
	if err != nil {
		t.Fatal(err)
	}
	input, err := store.Load(context.Background(), s.Anchor())
	if err != nil {
		t.Fatal(err)
	}
	f.request = LifecycleCheck{Checkpoint: AdmissionEffective, Snapshot: input, Mode: installstate.Install, Target: v.f.plan, Options: v.opts}
	return f
}

func TestActorFactoryRequiresExplicitRightsOriginalAccessAndStableWitnesses(t *testing.T) {
	f := newActorFixture(t)
	ctx := context.Background()
	if actors, err := f.admission.newActors(ctx, f.request, existingScopedImpersonation); err != nil || len(actors.clients) != 3 || f.adminReviews != 3 {
		t.Fatal("original actor factory refused", err)
	}
	before := f.adminReviews
	access := f.admission.prerequisites.access
	access.direct = false
	if _, err := f.admission.newActors(ctx, f.request, existingScopedImpersonation); err != ErrInvalid || f.adminReviews != before {
		t.Fatal("environment-routed access used for actor derivation")
	}
	access.direct = true
	for _, mode := range []actorAccessMode{0, 2, 255} {
		if _, err := f.admission.newActors(ctx, f.request, mode); err != ErrInvalid {
			t.Fatal("implicit or unreviewed identity selection")
		}
	}
	if f.adminReviews != before {
		t.Fatal("invalid mode reached wire")
	}
	f.denyAdmin = true
	if _, err := f.admission.newActors(ctx, f.request, existingScopedImpersonation); err != ErrAdmission {
		t.Fatal("missing existing impersonation right accepted")
	}
	f.denyAdmin = false
	for _, kind := range []string{"ServiceAccount", "Role", "RoleBinding", "ClusterRole", "ClusterRoleBinding"} {
		var key installstate.Key
		for k := range f.v.f.access.objects {
			if k.Kind == kind {
				key = k
				break
			}
		}
		original := f.v.f.access.objects[key].DeepCopy()
		for _, change := range []string{"missing", "uid", "spec"} {
			t.Run(kind+"/"+change, func(t *testing.T) {
				object := original.DeepCopy()
				f.v.f.access.objects[key] = object
				switch change {
				case "missing":
					delete(f.v.f.access.objects, key)
				case "uid":
					object.SetUID("foreign-uid")
				case "spec":
					object.SetLabels(map[string]string{"foreign": "true"})
				}
				before := f.adminReviews
				if _, err := f.admission.newActors(ctx, f.request, existingScopedImpersonation); err != ErrAdmission || f.adminReviews != before {
					t.Fatal("foreign access adopted or used")
				}
				f.v.f.access.objects[key] = original.DeepCopy()
			})
		}
	}
	base := f.admission.prerequisites.access.frozen
	for _, change := range []func(*rest.Config){
		func(c *rest.Config) { c.Impersonate.UserName = "foreign" },
		func(c *rest.Config) { c.Impersonate.UID = "foreign" },
		func(c *rest.Config) { c.Impersonate.Groups = []string{"system:masters"} },
		func(c *rest.Config) { c.Impersonate.Extra = map[string][]string{"scope": {"foreign"}} },
		func(c *rest.Config) { c.WrapTransport = func(r http.RoundTripper) http.RoundTripper { return r } },
		func(c *rest.Config) { c.Transport = http.DefaultTransport },
		func(c *rest.Config) { c.Proxy = http.ProxyFromEnvironment },
		func(c *rest.Config) { c.ExecProvider = &clientcmdapi.ExecConfig{} },
	} {
		copy := rest.CopyConfig(base)
		change(copy)
		f.admission.prerequisites.access.frozen = copy
		if _, err := f.admission.newActors(ctx, f.request, existingScopedImpersonation); err != ErrInvalid {
			t.Fatal("existing identity, plugin or transport replaced")
		}
	}
	f.admission.prerequisites.access.frozen = base
	key := installstate.Key{APIVersion: "v1", Kind: "ServiceAccount", Namespace: f.request.Target.Namespace(), Name: ordinaryControllerActor.account()}
	original := f.v.f.access.objects[key].DeepCopy()
	f.afterReview = func() { f.v.f.access.objects[key].SetResourceVersion("999") }
	if _, err := f.admission.newActors(ctx, f.request, existingScopedImpersonation); err != ErrAdmission {
		t.Fatal("identity drift during construction accepted")
	}
	f.afterReview = nil
	f.v.f.access.objects[key] = original
}

func TestActorDirectRoutingIsExplicitAndNativeCapable(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://PRIVATE-PROXY-CANARY.invalid")
	var checked bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("routing construction contacted server") }))
	t.Cleanup(server.Close)
	config := serverConfig(server)
	config.WrapTransport = func(next http.RoundTripper) http.RoundTripper {
		guard, ok := next.(attemptTransport)
		if !ok {
			t.Fatal("missing native single-attempt guard")
		}
		transport, ok := guard.next.(*http.Transport)
		if !ok || transport.Proxy == nil {
			t.Fatal("no explicit direct transport")
		}
		u, _ := url.Parse("https://cluster.example")
		proxy, err := transport.Proxy(&http.Request{URL: u})
		if err != nil || proxy != nil {
			t.Fatal("environment proxy reached direct route")
		}
		checked = true
		return next
	}
	if _, err := NewDirectHTTPAccess(config); err != nil || !checked {
		t.Fatal("explicit direct route not built", err)
	}
	config.WrapTransport = nil
	a, err := NewDirectHTTPAccess(config)
	if err != nil || a.native == nil || !a.direct || a.frozen.Proxy != nil || !a.actorCompatible() {
		t.Fatal("direct HTTP/native routing provenance disagrees", err)
	}
	config.Proxy = http.ProxyFromEnvironment
	if _, err := NewDirectHTTPAccess(config); err != ErrInvalid {
		t.Fatal("caller proxy silently dropped")
	}
	if _, err := a.actorClient(0, "isolated-install"); err != ErrInvalid {
		t.Fatal("unknown actor transport")
	}
	if _, err := a.actorClient(ordinaryControllerActor, "foreign/path"); err != ErrInvalid {
		t.Fatal("invalid actor namespace")
	}
}

func TestActorProbeChecksOwnPermissionAndBracketsAccessAndPolicy(t *testing.T) {
	f := newActorFixture(t)
	actors, err := f.admission.newActors(context.Background(), f.request, existingScopedImpersonation)
	if err != nil {
		t.Fatal(err)
	}
	o := namedProbeFixture("Pod")
	o.SetNamespace(f.request.Target.Namespace())
	probe := func() error {
		_, err := actors.probe(context.Background(), ordinaryControllerActor, probeUpdateOperation, o, "", "", "")
		return err
	}
	if err := probe(); err != nil || f.actorReviews != 1 || f.probes != 1 {
		t.Fatal("own operation authorization/probe refused", err)
	}
	f.denyActor = true
	before := f.probes
	if probe() != ErrAdmission || f.probes != before {
		t.Fatal("administrator rights substituted for actor rights")
	}
	f.denyActor = false
	f.forbiddenProbe = true
	policy, binding, message := "", "", ""
	for name, b := range actors.policies.bindings {
		p := actors.policies.policies[b.Spec.PolicyName]
		policy, binding, message = p.Name, name, p.Spec.Validations[0].Message
		break
	}
	if _, err := actors.probe(context.Background(), ordinaryControllerActor, probeUpdateOperation, o, policy, binding, message); err != ErrAdmission || strings.Contains(err.Error(), "CANARY") {
		t.Fatal("RBAC denial became policy evidence or leaked detail")
	}
	f.forbiddenProbe = false
	_, plural, _ := probePath(resourceKeyFromObject(o))
	f.denial, err = expectedProbeDenial(resourceKeyFromObject(o), plural, policy, binding, message)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := actors.probe(context.Background(), ordinaryControllerActor, probeUpdateOperation, o, policy, binding, message); err != nil || result != nil {
		t.Fatal("original signed denial refused", err)
	}
	f.denial = nil
	before = f.actorReviews
	for _, triple := range [][3]string{{"foreign", binding, message}, {policy, "foreign", message}, {policy, binding, "unsigned"}, {"", binding, message}, {policy, "", message}, {policy, binding, ""}} {
		if _, err := actors.probe(context.Background(), ordinaryControllerActor, probeUpdateOperation, o, triple[0], triple[1], triple[2]); err != ErrInvalid || f.actorReviews != before {
			t.Fatal("unsigned denial evidence reached wire")
		}
	}
	for name, b := range actors.policies.bindings {
		if b.Spec.PolicyName != policy {
			if _, err := actors.probe(context.Background(), ordinaryControllerActor, probeUpdateOperation, o, policy, name, message); err != ErrInvalid || f.actorReviews != before {
				t.Fatal("mismatched original policy/binding reached wire")
			}
			break
		}
	}
	for _, kind := range []string{"ServiceAccount", "RoleBinding", "ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding"} {
		for _, edge := range []string{"before", "review", "probe"} {
			t.Run(kind+"/"+edge, func(t *testing.T) {
				var key installstate.Key
				for k := range f.v.f.access.objects {
					if k.Kind == kind {
						key = k
						break
					}
				}
				original := f.v.f.access.objects[key].DeepCopy()
				change := func() { f.v.f.access.objects[key].SetResourceVersion("999") }
				switch edge {
				case "before":
					change()
				case "review":
					f.afterReview = change
				case "probe":
					f.afterProbe = change
				}
				before := f.probes
				if probe() != ErrAdmission || edge != "probe" && f.probes != before {
					t.Fatal("drift permitted actor probe or accepted evidence")
				}
				f.afterReview, f.afterProbe = nil, nil
				f.v.f.access.objects[key] = original
			})
		}
	}
	if _, err := actors.probe(context.Background(), destroyAdministratorActor, probeUpdateOperation, o, "", "", ""); err != ErrInvalid {
		t.Fatal("administrator actor used Pod authority")
	}
	if _, err := actors.probe(context.Background(), ordinaryControllerActor, probeResizeOperation, o, "", "", ""); err != ErrInvalid {
		t.Fatal("actor used ungranted subresource")
	}
}

func actorTestAccess(t *testing.T, handler http.HandlerFunc, actor admissionActor) *HTTPAccess {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	identity := actorWireIdentity{actor: actor, namespace: "isolated-install", username: "system:serviceaccount:isolated-install:" + actor.account(), authorization: "Bearer FAKE-ADMIN-CANARY"}
	config := serverConfig(server)
	config.BearerToken = "FAKE-ADMIN-CANARY"
	config.Impersonate.UserName = identity.username
	config.WrapTransport = func(next http.RoundTripper) http.RoundTripper {
		return actorWireTransport{next: next, identity: identity}
	}
	access, err := NewDirectHTTPAccess(config)
	if err != nil {
		t.Fatal(err)
	}
	access.actor = &identity
	return access
}

func TestActorWireGuardRejectsIdentityBodyRouteAndContextTampering(t *testing.T) {
	for name, mutate := range map[string]func(*http.Request){
		"user":           func(r *http.Request) { r.Header.Set("Impersonate-User", "system:admin") },
		"user-alias":     func(r *http.Request) { r.Header["impersonate-user"] = []string{"foreign"} },
		"user-duplicate": func(r *http.Request) { r.Header["Impersonate-User"] = []string{"foreign", "foreign"} },
		"groups":         func(r *http.Request) { r.Header.Set("Impersonate-Group", "system:masters") },
		"empty-groups":   func(r *http.Request) { r.Header["Impersonate-Group"] = nil },
		"uid":            func(r *http.Request) { r.Header.Set("Impersonate-Uid", "foreign") },
		"extra":          func(r *http.Request) { r.Header.Set("Impersonate-Extra-Scope", "foreign") },
		"auth":           func(r *http.Request) { r.Header.Set("Authorization", "Bearer FOREIGN-CANARY") },
		"auth-alias":     func(r *http.Request) { r.Header["authorization"] = []string{"Bearer FOREIGN-CANARY"} },
		"route":          func(r *http.Request) { r.URL.Path += "/status" },
		"method":         func(r *http.Request) { r.Method = http.MethodGet },
		"persistent":     func(r *http.Request) { r.URL.RawQuery = "" },
		"body":           func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader(`{}`)); r.ContentLength = 2 },
		"context":        func(r *http.Request) { *r = *r.WithContext(context.Background()) },
	} {
		t.Run(name, func(t *testing.T) {
			var requests atomic.Int32
			a := actorTestAccess(t, func(w http.ResponseWriter, r *http.Request) { requests.Add(1) }, ordinaryControllerActor)
			next := a.client.Transport
			a.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) { mutate(r); return next.RoundTrip(r) })
			if _, err := a.probeOperation(context.Background(), probeUpdateOperation, namedProbeFixture("Pod"), "", "", ""); err != ErrAdmission || requests.Load() != 0 {
				t.Fatal("tampered probe reached network")
			}
			permission, _ := actorPermission(resourceKeyFromObject(namedProbeFixture("Pod")), probeUpdateOperation)
			if err := a.authorize(context.Background(), permission.spec); err == nil || requests.Load() != 0 {
				t.Fatal("tampered actor review reached network")
			}
		})
	}
}

func TestActorClientsNeverExposeGenericAccessOrForeignAuthorization(t *testing.T) {
	var requests atomic.Int32
	a := actorTestAccess(t, func(w http.ResponseWriter, r *http.Request) { requests.Add(1) }, ordinaryControllerActor)
	key, object := accessObject()
	_, _ = a.Get(context.Background(), key)
	_, _ = a.Create(context.Background(), key, object, false)
	_, _ = a.Create(context.Background(), key, object, true)
	_, _ = a.Update(context.Background(), key, object, false)
	_ = a.Delete(context.Background(), key, metav1.DeleteOptions{})
	_, _ = a.discover(context.Background(), "v1")
	for _, spec := range []authv1.SelfSubjectAccessReviewSpec{
		{ResourceAttributes: &authv1.ResourceAttributes{Namespace: "foreign", Version: "v1", Resource: "pods", Name: "probe", Verb: "update"}},
		{ResourceAttributes: &authv1.ResourceAttributes{Namespace: "isolated-install", Version: "v1", Resource: "pods", Name: "probe", Subresource: "resize", Verb: "update"}},
		{ResourceAttributes: &authv1.ResourceAttributes{Namespace: "isolated-install", Version: "v1", Resource: "persistentvolumeclaims", Name: "world", Verb: "delete"}},
		{NonResourceAttributes: &authv1.NonResourceAttributes{Path: "/version", Verb: "get"}},
	} {
		if a.authorize(context.Background(), spec) == nil {
			t.Fatal("foreign actor authorization accepted")
		}
	}
	if requests.Load() != 0 {
		t.Fatal("general or foreign access reached network")
	}
}

func TestActorOperationMatrixIsClosedAndMatchesAuthorization(t *testing.T) {
	allowed := map[admissionActor]map[string]bool{
		ordinaryControllerActor:   {"Pod/update": true, "PersistentVolumeClaim/create": true, "PersistentVolumeClaim/update": true},
		destroyControllerActor:    {"Pod/update": true, "PersistentVolumeClaim/delete": true, "GameDestroy/update": true},
		destroyAdministratorActor: {"GameDestroy/create": true, "GameDestroy/update": true},
	}
	for _, actor := range []admissionActor{0, ordinaryControllerActor, destroyControllerActor, destroyAdministratorActor, 255} {
		identity := actorWireIdentity{actor: actor, namespace: "isolated-install"}
		for _, kind := range []string{"Pod", "PersistentVolumeClaim", "GameDestroy"} {
			for _, op := range []admissionProbeOperation{probeCreateOperation, probeUpdateOperation, probeDeletePVCOperation, probeEphemeralOperation, probeResizeOperation, 255} {
				key := resourceKeyFromObject(namedProbeFixture(kind))
				want := allowed[actor][kind+"/"+actorOperationVerb(op)]
				if identity.allows(key, op) != want {
					t.Fatal("unexpected actor operation matrix", actor, kind, op)
				}
				permission, err := actorPermission(key, op)
				if err != nil {
					if want {
						t.Fatal("allowed operation has no permission")
					}
					continue
				}
				review := &authv1.SelfSubjectAccessReview{TypeMeta: metav1.TypeMeta{APIVersion: "authorization.k8s.io/v1", Kind: "SelfSubjectAccessReview"}, Spec: permission.spec}
				if identity.allowsReview(review) != want {
					t.Fatal("operation/authorization bounds disagree", actor, kind, op)
				}
				before := *review.Spec.ResourceAttributes
				review.Spec.ResourceAttributes.Namespace = "foreign"
				if identity.allowsReview(review) {
					t.Fatal("foreign namespace authorization")
				}
				*review.Spec.ResourceAttributes = before
				review.Spec.ResourceAttributes.LabelSelector = &authv1.LabelSelectorAttributes{RawSelector: "scope=foreign"}
				if identity.allowsReview(review) {
					t.Fatal("selector authorization")
				}
				if !reflect.DeepEqual(key, resourceKeyFromObject(namedProbeFixture(kind))) {
					t.Fatal("matrix mutated fixture")
				}
			}
		}
	}
}
