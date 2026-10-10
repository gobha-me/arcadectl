// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	authv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
)

// Actual closed constructor AND driver, over explicit synthetic whole replies.
// Native health/status, enrollment and full lifecycle remain separate.
// Each literal scenario is a compiled top-level test so bounded CI workers
// can distribute the existing complete proofs without splitting assertions.
func TestBaselineBehaviorWholeProviderHealthy(t *testing.T) {
	testBaselineBehaviorWholeProvider(t, "healthy")
}

// Additional coverage, not a replacement for the 23 original scenarios.
// Inventory/health are synthetic; this proves the actual closed driver accepts
// the pre-controller cardinality, not a native installer or archive lifecycle.
func TestBaselinePrecontrollerWholeProviderHealthy(t *testing.T) {
	testBaselineBehaviorWholeProvider(t, "precontroller")
}

func TestBaselinePrecontrollerWholeProviderRuntimeHealthy(t *testing.T) {
	testBaselineBehaviorWholeProvider(t, "runtime-precontroller")
}

func TestBaselineBehaviorWholeProviderPendingService(t *testing.T) {
	testBaselineBehaviorWholeProvider(t, "pending-service")
}

func TestBaselineBehaviorWholeProviderPendingParent(t *testing.T) {
	testBaselineBehaviorWholeProvider(t, "pending-parent")
}

func TestBaselineBehaviorWholeProviderCompleteInstall(t *testing.T) {
	testBaselineBehaviorWholeProvider(t, "complete-install")
}

func TestBaselineBehaviorWholeProviderCompleteUpgrade(t *testing.T) {
	testBaselineBehaviorWholeProvider(t, "complete-upgrade")
}

func TestBaselineBehaviorWholeProviderCompleteRollback(t *testing.T) {
	testBaselineBehaviorWholeProvider(t, "complete-rollback")
}

func TestBaselineBehaviorWholeProviderWrongPodFamily(t *testing.T) {
	testBaselineBehaviorWholeProvider(t, "wrong-pod-family")
}

func TestBaselineBehaviorWholeProviderMissingDenial(t *testing.T) {
	testBaselineBehaviorWholeProvider(t, "missing-denial")
}

func TestBaselineBehaviorWholeProviderProducerDenialBefore(t *testing.T) {
	testBaselineBehaviorWholeProvider(t, "producer-denial-before")
}

func TestBaselineBehaviorWholeProviderProducerDenialAfter(t *testing.T) {
	testBaselineBehaviorWholeProvider(t, "producer-denial-after")
}

func TestBaselineBehaviorWholeProviderBadPositive(t *testing.T) {
	testBaselineBehaviorWholeProvider(t, "bad-positive")
}

func TestBaselineBehaviorWholeProviderClosingNewPod(t *testing.T) {
	testBaselineBehaviorWholeProvider(t, "closing-new-pod")
}

func TestBaselineBehaviorWholeProviderClosingProxyGrant(t *testing.T) {
	testBaselineBehaviorWholeProvider(t, "closing-proxy-grant")
}

func TestBaselineBehaviorWholeProviderClosingServiceRv(t *testing.T) {
	testBaselineBehaviorWholeProvider(t, "closing-service-rv")
}

func TestBaselineBehaviorWholeProviderFinalCatalogFirstServiceRv(t *testing.T) {
	testBaselineBehaviorWholeProvider(t, "final-catalog-first-service-rv")
}

func TestBaselineBehaviorWholeProviderFinalCatalogSecondServiceRv(t *testing.T) {
	testBaselineBehaviorWholeProvider(t, "final-catalog-second-service-rv")
}

func TestBaselineBehaviorWholeProviderFinalReceiptReplacement(t *testing.T) {
	testBaselineBehaviorWholeProvider(t, "final-receipt-replacement")
}

func TestBaselineBehaviorWholeProviderFinalParentReceiptReplacement(t *testing.T) {
	testBaselineBehaviorWholeProvider(t, "final-parent-receipt-replacement")
}

func TestBaselineBehaviorWholeProviderRuntimeHealthy(t *testing.T) {
	testBaselineBehaviorWholeProvider(t, "runtime-healthy")
}

func TestBaselineBehaviorWholeProviderRuntimeClosingProxyGrant(t *testing.T) {
	testBaselineBehaviorWholeProvider(t, "runtime-closing-proxy-grant")
}

func TestBaselineBehaviorWholeProviderRuntimeClosingNewPod(t *testing.T) {
	testBaselineBehaviorWholeProvider(t, "runtime-closing-new-pod")
}

func TestBaselineBehaviorWholeProviderRuntimeFinalReceiptReplacement(t *testing.T) {
	testBaselineBehaviorWholeProvider(t, "runtime-final-receipt-replacement")
}

func TestBaselineBehaviorWholeProviderRuntimeFinalParentReceiptReplacement(t *testing.T) {
	testBaselineBehaviorWholeProvider(t, "runtime-final-parent-receipt-replacement")
}

func TestBaselineBehaviorWholeProviderRuntimeFinalCloseOrderService(t *testing.T) {
	testBaselineBehaviorWholeProvider(t, "runtime-final-close-order-service")
}

func TestBaselineBehaviorWholeProviderRuntimeFinalCloseOrderParent(t *testing.T) {
	testBaselineBehaviorWholeProvider(t, "runtime-final-close-order-parent")
}

func testBaselineBehaviorWholeProvider(t *testing.T, scenario string) {
	t.Helper()
	testBaselineBehaviorWholeProviderWithProtocol(t, scenario, nil)
}

// Test-only protocol substitution shares the complete independent responder
// and final literal request oracle. Existing scenario wrappers still exercise
// their original dispatch unchanged; this seam effects no production hook.
func testBaselineBehaviorWholeProviderWithProtocol(t *testing.T, scenario string, protocol func(*Engine, *installstate.Snapshot, *ClusterSecurityBaseline, func() int) error) {
	testBaselineBehaviorWholeProviderWithActivation(t, scenario, protocol, nil)
}

// Opt-in fixture for actual owned activation. The original 23 scenarios and
// their independent 97-row oracle remain unchanged when this is nil.
type baselineBehaviorActivationFixture struct {
	serving    *servingFixture
	forwards   *atomic.Int32
	apiCalls   *atomic.Int32
	proofs     int
	rulePasses int
	onUpgrade  func()
	onAPI      func()
	onRead     func(string, map[installstate.Key]*unstructured.Unstructured)
}

func testBaselineBehaviorWholeProviderWithActivation(t *testing.T, scenario string, protocol func(*Engine, *installstate.Snapshot, *ClusterSecurityBaseline, func() int) error, activation *baselineBehaviorActivationFixture) {
	testBaselineBehaviorWholeProviderComposition(t, scenario, protocol, activation, nil)
}

func testBaselineBehaviorWholeProviderComposition(t *testing.T, scenario string, protocol func(*Engine, *installstate.Snapshot, *ClusterSecurityBaseline, func() int) error, activation *baselineBehaviorActivationFixture, effect *baselineBehaviorEffectFixture, fences ...*testDeniedCompositionFence) {
	t.Helper()
	runtime := strings.HasPrefix(scenario, "runtime-")
	mode := strings.TrimPrefix(scenario, "runtime-")
	closeOrder := mode == "final-close-order-service" || mode == "final-close-order-parent"
	f := seedBaselineAccessWitness(t)
	plans := []*installrender.Plan{f.plan}
	complete := strings.HasPrefix(mode, "complete-")
	precontroller := mode == "precontroller"
	positive := mode == "healthy" || mode == "pending-service" || mode == "pending-parent" || complete || closeOrder || precontroller
	pendingService := mode == "pending-service" || mode == "final-receipt-replacement" || mode == "final-close-order-service"
	pendingParent := mode == "pending-parent" || mode == "final-parent-receipt-replacement" || mode == "final-close-order-parent"
	if mode == "complete-upgrade" || mode == "complete-rollback" {
		previous, target := lifecycleTransitionPlans(t)
		plans = []*installrender.Plan{target, previous}
		if mode == "complete-rollback" {
			plans = []*installrender.Plan{previous, target}
		}
		f = seedBaselineAccessWitnessWithPlans(t, plans...)
	}
	// Keep synthetic discovery independently pinned to each supported server
	// profile. Transition fixtures use 1.37, not the default 1.35 fixture.
	var serverVersion map[string]any
	switch f.plan.Profile().KubernetesVersion {
	case "1.35.8":
		serverVersion = map[string]any{"major": "1", "minor": "35", "gitVersion": "v1.35.8"}
	case "1.37.0":
		serverVersion = map[string]any{"major": "1", "minor": "37", "gitVersion": "v1.37.0"}
	default:
		t.Fatal("whole provider fixture has no independently pinned server version")
	}
	v := newBaselineDescendantsFixtureWithPlans(t, plans...)
	if precontroller {
		v.objects.Deployments.Items = nil
		v.objects.ReplicaSets.Items = nil
		v.objects.Pods.Items = nil
	}
	d := f.snapshot.Document()
	objects := map[installstate.Key]*unstructured.Unstructured{}
	for key, object := range f.access.objects {
		copy := object.DeepCopy()
		if key.Kind == "ValidatingAdmissionPolicy" {
			copy.SetGeneration(1)
			copy.Object["status"] = map[string]any{"observedGeneration": int64(1), "typeChecking": map[string]any{}}
		}
		objects[key] = copy
	}
	for _, resource := range v.d.Resources {
		if resource.Key.Kind == "Deployment" && !precontroller {
			d.Resources = append(d.Resources, resource)
		}
	}
	for i := range v.objects.Deployments.Items {
		object := servingObject(t, &v.objects.Deployments.Items[i])
		objects[baselineObjectKey(object)] = object
	}
	for i := range v.objects.ReplicaSets.Items {
		object := servingObject(t, &v.objects.ReplicaSets.Items[i])
		object.SetAPIVersion("apps/v1")
		object.SetKind("ReplicaSet")
		objects[baselineObjectKey(object)] = object
	}
	for i := range v.objects.Pods.Items {
		object := servingObject(t, &v.objects.Pods.Items[i])
		objects[baselineObjectKey(object)] = object
	}
	serviceKey := installstate.Key{APIVersion: "v1", Kind: "Service", Namespace: d.Namespace, Name: "arcadectl-api"}
	template, err := f.engine.contracts[d.TargetPackage].Template(serviceKey, false)
	if err != nil {
		t.Fatal("signed provider Service unavailable")
	}
	service := testBaselineMetadataLive(t, template, strings.Repeat("b", 32))
	service.SetUID("original-behavior-service")
	service.SetResourceVersion("17")
	objects[serviceKey] = service
	if pendingService {
		d.Pending = &installstate.Pending{Action: installstate.Create, Key: serviceKey, CreateNonce: strings.Repeat("c", 32), AfterSHA256: template.Hash()}
		annotations := service.GetAnnotations()
		annotations[installstate.MutationAnnotation] = d.Pending.CreateNonce
		service.SetAnnotations(annotations)
	} else {
		d.Resources = append(d.Resources, installstate.Resource{Key: serviceKey, UID: service.GetUID(), TemplateSHA256: template.Hash(), Phase: template.Phase(), Retained: template.Retained()})
	}
	if pendingParent {
		key := deploymentKey(d.Namespace, "arcadectl-api")
		template, err := f.engine.contracts[d.TargetPackage].Template(key, false)
		if err != nil || objects[key] == nil {
			t.Fatal("signed original pending parent unavailable")
		}
		d.Pending = &installstate.Pending{Action: installstate.Create, Key: key, CreateNonce: strings.Repeat("c", 32), AfterSHA256: template.Hash()}
		resources := make([]installstate.Resource, 0, len(d.Resources)-1)
		for _, resource := range d.Resources {
			if resource.Key != key {
				resources = append(resources, resource)
			}
		}
		d.Resources = resources
		annotations := objects[key].GetAnnotations()
		annotations[installstate.MutationAnnotation] = d.Pending.CreateNonce
		objects[key].SetAnnotations(annotations)
	}
	installstate.SortResources(d.Resources)
	if complete || precontroller {
		// Explicitly synthetic complete inventory, followed by the real
		// Verifying→Complete namespace CAS. Native/full lifecycle proof is
		// separate; these cases exercise every actual behavior helper at
		// a sealed Complete state without relabelling it as in-progress.
		for _, metadata := range f.plan.ResourceMetadata() {
			key := installstate.Key{APIVersion: metadata.APIVersion, Kind: metadata.Kind, Namespace: metadata.Namespace, Name: metadata.Name}
			if precontroller && key.Kind == "Deployment" {
				continue
			}
			found := false
			for _, recorded := range d.Resources {
				found = found || recorded.Key == key
			}
			if found {
				continue
			}
			template, err := f.engine.contracts[f.plan.Digest()].Template(key, false)
			if err != nil {
				t.Fatal("complete synthetic signed inventory unavailable")
			}
			d.Resources = append(d.Resources, installstate.Resource{Key: key, UID: types.UID("complete-" + key.Kind + "-" + key.Name), TemplateSHA256: template.Hash(), Phase: template.Phase(), Retained: template.Retained()})
			if precontroller {
				object := testBaselineMetadataLive(t, template, strings.Repeat("b", 32))
				object.SetUID(types.UID("complete-" + key.Kind + "-" + key.Name))
				object.SetResourceVersion("17")
				objects[key] = object
			}
		}
		for _, name := range []string{"arcadectl-admin-credential", "arcadectl-api-tls"} {
			d.Resources = append(d.Resources, installstate.Resource{Key: secretKey(d.Namespace, name), UID: types.UID("complete-secret-" + name), Phase: installrender.API, Retained: true})
		}
		if complete {
			d.Stage = installstate.Verifying
		}
		if mode == "complete-upgrade" {
			d.Mode, d.ActivePackage, d.Installed = installstate.Upgrade, plans[1].Digest(), true
		} else if mode == "complete-rollback" {
			d.Mode, d.ActivePackage, d.PreviousPackage, d.Installed = installstate.Rollback, plans[1].Digest(), f.plan.Digest(), true
		}
		installstate.SortResources(d.Resources)
	}
	if protocol != nil {
		// Explicitly synthetic settled Verifying inventory. This is not a
		// native installer, enrollment or successful authentication claim.
		d.Stage = installstate.Verifying
	}
	if activation != nil {
		if mode != "healthy" || protocol == nil || complete || precontroller || pendingService || pendingParent {
			t.Fatal("owned activation fixture escaped its explicit healthy scope")
		}
		x := newServingFixtureWithPlan(t, f.plan)
		// The baseline family proof requires genuine creation-time metadata;
		// legacy serving-only fixtures intentionally do not exercise that gate.
		x.access.rs.CreationTimestamp = metav1.NewTime(time.Unix(100, 0).UTC())
		x.access.pod.CreationTimestamp = metav1.NewTime(time.Unix(101, 0).UTC())
		activation.serving = x
		activation.apiCalls = activationServer(t, x, d.Namespace, activation.onAPI)
		// Replace only the API family with independently ready whole objects.
		// Keep the other two complete executor chains and literal probe oracle.
		for key, object := range objects {
			if key.Kind == "ReplicaSet" || key.Kind == "Pod" {
				owner := object.GetOwnerReferences()
				account, _, _ := unstructured.NestedString(object.Object, "spec", "serviceAccountName")
				if key.Kind == "ReplicaSet" && len(owner) == 1 && owner[0].Name == "arcadectl-api" || key.Kind == "Pod" && account == "arcadectl-api" {
					delete(objects, key)
				}
			}
		}
		for _, key := range []installstate.Key{serviceKey, deploymentKey(d.Namespace, "arcadectl-api")} {
			object := x.f.access.objects[key].DeepCopy()
			objects[key] = object
			for i := range d.Resources {
				if d.Resources[i].Key == key {
					d.Resources[i].UID = object.GetUID()
				}
			}
		}
		for i := range v.objects.Pods.Items {
			if v.objects.Pods.Items[i].Spec.ServiceAccountName == "arcadectl-api" {
				v.objects.Pods.Items[i] = *x.access.pod.DeepCopy()
			}
		}
		for _, object := range []*unstructured.Unstructured{servingObject(t, x.access.pod), servingObject(t, x.access.rs)} {
			objects[baselineObjectKey(object)] = object
		}
		for _, name := range []string{"arcadectl-admin-credential", "arcadectl-api-tls"} {
			secret := x.secrets.objects[name].DeepCopy()
			secret.APIVersion, secret.Kind = "v1", "Secret"
			objects[secretKey(d.Namespace, name)] = servingObject(t, secret)
			d.Resources = append(d.Resources, installstate.Resource{Key: secretKey(d.Namespace, name), UID: secret.UID, Phase: installrender.API, Retained: true})
		}
		installstate.SortResources(d.Resources)
	}
	if effect != nil {
		if mode != "healthy" || protocol == nil || activation != nil {
			t.Fatal("effect fixture escaped its explicit original Deployment scope")
		}
		effect.prepare(t, &d, objects, f.plan)
	}
	d.Revision++
	seedBaselineAccessUnitDocument(t, f, d)
	if precontroller && (d.Stage != installstate.Applying || d.Mode != installstate.Install || d.Installed || d.Pending != nil || len(d.Resources) != 37 || len(d.SecurityBaseline.Resources) != 12) {
		t.Fatal("synthetic pre-controller fixture lost its exact settled inventory")
	}
	if complete {
		var err error
		f.snapshot, err = (&Lifecycle{engine: f.engine}).stage(t.Context(), f.snapshot, installstate.Complete)
		if err != nil {
			t.Fatal("real completed-state CAS refused synthetic original inventory")
		}
		d = f.snapshot.Document()
		wantMode, wantPrevious := installstate.Install, ""
		if mode == "complete-upgrade" {
			wantMode, wantPrevious = installstate.Upgrade, plans[1].Digest()
		} else if mode == "complete-rollback" {
			wantMode, wantPrevious = installstate.Rollback, plans[1].Digest()
		}
		if d.Stage != installstate.Complete || d.Mode != wantMode || !d.Installed || d.Pending != nil || len(d.Resources) != 40 || d.ActivePackage != f.plan.Digest() || d.TargetPackage != f.plan.Digest() || d.PreviousPackage != wantPrevious {
			t.Fatal("provider fixture did not reach its exact genuine completed journal transition")
		}
	}
	if (pendingService || pendingParent) && (f.engine.prepareCreateReceipt(d) != nil || f.engine.saveCreateUID(d, objects[d.Pending.Key].GetUID()) != nil) {
		t.Fatal("protected synthetic original CREATE ACK unavailable")
	}
	ns, err := f.access.client.CoreV1().Namespaces().Get(t.Context(), d.Namespace, metav1.GetOptions{})
	if err != nil {
		t.Fatal("protected original provider namespace unavailable")
	}
	if effect != nil {
		effect.namespace = ns
	}
	// Independent literal resources, not production catalog derivation.
	resources := [][3]string{{"v1", "Pod", "pods"}, {"batch/v1", "Job", "jobs"}, {"apps/v1", "Deployment", "deployments"}, {"apps/v1", "ReplicaSet", "replicasets"}, {"apps/v1", "StatefulSet", "statefulsets"}, {"apps/v1", "DaemonSet", "daemonsets"}, {"v1", "ReplicationController", "replicationcontrollers"}, {"batch/v1", "CronJob", "cronjobs"}, {"v1", "ServiceAccount", "serviceaccounts"}, {"v1", "Service", "services"}, {"rbac.authorization.k8s.io/v1", "Role", "roles"}, {"rbac.authorization.k8s.io/v1", "RoleBinding", "rolebindings"}}
	objectPaths := map[string]installstate.Key{}
	for key := range objects {
		path, err := resourcePath(key, false)
		if key.Kind == "Secret" && activation != nil {
			path, err = privateSecretPath(key, false)
		}
		if err != nil {
			path, _, err = baselineExecutableRead(key, "get")
		}
		if err != nil {
			t.Fatal("original provider object route unavailable")
		}
		objectPaths[path] = key
	}
	if effect != nil {
		for key := range effect.family {
			path, _, err := baselineExecutableRead(key, "get")
			if err != nil {
				t.Fatal("effect fixture future family route unavailable")
			}
			objectPaths[path] = key
		}
	}
	var mu sync.Mutex
	requests := 0
	var probes, positives, podProbes, persistent int
	var injected, proxyGrant bool
	rules := map[string]int{}
	rows := map[string]int{}
	detailedRows := map[string]int{}
	producerBodies := map[string]*unstructured.Unstructured{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		requests++
		w.Header().Set("Content-Type", "application/json")
		user := r.Header.Get("Impersonate-User")
		actor := strings.TrimPrefix(user, "system:serviceaccount:"+d.Namespace+":")
		bearer := "Bearer FAKE-BEHAVIOR-PROVIDER"
		if activation != nil {
			bearer = "Bearer TEST-ONLY-KUBE-BEARER"
		}
		if r.Header.Get("Authorization") != bearer || user != "" && actor != "arcadectl-controller" && actor != "arcadectl-destroy-controller" {
			t.Error("behavior provider changed frozen original identity")
		}
		if effect != nil && effect.serve(t, w, r, objects) {
			return
		}
		if r.Method == http.MethodPost && r.URL.Path == "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" {
			var review authv1.SelfSubjectAccessReview
			if json.NewDecoder(r.Body).Decode(&review) != nil || review.Spec.ResourceAttributes == nil || review.Spec.NonResourceAttributes != nil {
				t.Error("behavior review malformed")
				w.WriteHeader(500)
				return
			}
			a := review.Spec.ResourceAttributes
			if effect != nil && effect.effects == 1 && !effect.proofOpening && user == "" && a.Verb == "impersonate" && a.Resource == "serviceaccounts" && a.Version == "*" {
				// Quiet collection asks only read/list. The first maintenance
				// impersonation review opens actual newBaselineActors; freeze
				// the last PRE-proof collection timestamp before later reads.
				effect.proofOpening = true
				effect.quietCollection = effect.lastCollection
			}
			// A literal catalog-only token descriptor, never the outer
			// wildcard impersonation bracket between catalog passes.
			if probes == 97 && user != "" && !injected && a.Group == "" && a.Version == "v1" && a.Resource == "serviceaccounts" && a.Subresource == "token" && a.Verb == "create" && a.Name == "arcadectl-api" &&
				(mode == "final-catalog-first-service-rv" && rules["arcadectl-destroy-controller"] == 4 || mode == "final-catalog-second-service-rv" && rules["arcadectl-destroy-controller"] == 5) {
				objects[serviceKey].SetResourceVersion("18")
				injected = true
			}
			allowed := false
			if user == "" {
				allowed = a.Verb == "get" || a.Verb == "list" || a.Verb == "impersonate" && a.Version == "*" && a.Resource == "serviceaccounts" && a.Namespace == d.Namespace && (a.Name == "arcadectl-controller" || a.Name == "arcadectl-destroy-controller")
				if effect != nil {
					allowed = allowed || a.Verb == "update" && a.Group == "" && a.Version == "v1" && a.Resource == "namespaces" && a.Name == d.Namespace && a.Namespace == "" && a.Subresource == "" || a.Group == "apps" && a.Version == "v1" && a.Resource == "deployments" && a.Namespace == d.Namespace && a.Subresource == "" && (!effect.update && a.Verb == "create" && a.Name == "" || effect.update && a.Verb == "update" && a.Name == "arcadectl-api")
				}
			} else if a.Version == "v1" && a.Namespace == d.Namespace && a.Subresource == "" && a.FieldSelector == nil && a.LabelSelector == nil {
				collection := a.Verb == "create" && a.Name == ""
				named := a.Name != "" && (a.Verb == "update" || a.Verb == "delete" || a.Verb == "patch")
				switch a.Group + "/" + a.Resource {
				case "batch/jobs":
					allowed = collection
				case "apps/deployments":
					allowed = actor == "arcadectl-controller" && (collection || named)
				case "/pods":
					allowed = named && a.Verb == "update"
				case "/serviceaccounts", "rbac.authorization.k8s.io/roles", "rbac.authorization.k8s.io/rolebindings":
					allowed = collection || named && a.Verb == "delete"
				case "/services":
					allowed = actor == "arcadectl-controller" && (collection || named)
				}
			}
			review.TypeMeta = metav1.TypeMeta{APIVersion: "authorization.k8s.io/v1", Kind: "SelfSubjectAccessReview"}
			review.Status = authv1.SubjectAccessReviewStatus{Allowed: allowed}
			_ = json.NewEncoder(w).Encode(review)
			return
		}
		if r.Method == http.MethodPost && r.URL.Path == "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews" {
			var review authv1.SelfSubjectRulesReview
			if json.NewDecoder(r.Body).Decode(&review) != nil || review.Spec.Namespace != d.Namespace || user == "" {
				t.Error("behavior rules review escaped its exact actor namespace")
				w.WriteHeader(500)
				return
			}
			rules[actor]++
			status := map[string]any{"incomplete": false, "resourceRules": []any{}, "nonResourceRules": []any{}}
			if proxyGrant {
				status["resourceRules"] = []any{map[string]any{"verbs": []any{"get"}, "apiGroups": []any{""}, "resources": []any{"services/proxy"}, "resourceNames": []any{"https:arcadectl-api:+00443"}}}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"apiVersion": "authorization.k8s.io/v1", "kind": "SelfSubjectRulesReview", "spec": map[string]any{}, "status": status})
			return
		}
		if r.Method == http.MethodGet {
			if activation != nil {
				if activation.onRead != nil {
					activation.onRead(r.URL.Path, objects)
				}
				if r.URL.Path == "/apis/discovery.k8s.io/v1/namespaces/"+d.Namespace+"/endpointslices" {
					_ = json.NewEncoder(w).Encode(activation.serving.access.list)
					return
				}
			}
			if user != "" {
				t.Error("behavior actor acquired generic GET")
			}
			if r.URL.Path == "/version" {
				_ = json.NewEncoder(w).Encode(serverVersion)
				return
			}
			if r.URL.Path == "/api/v1/namespaces/"+d.Namespace {
				if (mode == "final-receipt-replacement" || mode == "final-parent-receipt-replacement" || closeOrder) && rules["arcadectl-destroy-controller"] == 6 && !injected {
					name := "create-" + d.Pending.CreateNonce + ".json"
					owners := testBaselineReceiptDescriptors(t, name)
					if !closeOrder && owners != 1 {
						t.Error("actual Verify did not retain its own opening descriptor through final remote reads")
					}
					// Audit the enclosing current() boundary, not just Verify:
					// a trailing original Namespace read after receipt release
					// must not exist. If it does, expose stale success using two
					// identical-byte replacements with no external owner safety net.
					if closeOrder && owners != 0 {
						copy := ns.DeepCopy()
						copy.APIVersion, copy.Kind = "v1", "Namespace"
						_ = json.NewEncoder(w).Encode(copy)
						return
					}
					body, identity, err := f.engine.files.Read(name, 4096)
					if err != nil {
						t.Error("opening receipt unavailable")
					} else {
						for range 2 {
							identity, err = f.engine.files.AtomicWrite(name, body, &identity)
							if err != nil {
								t.Error("whole-driver repeated identical receipt replacement unavailable")
								break
							}
						}
						injected = err == nil
					}
				}
				copy := ns.DeepCopy()
				if effect != nil {
					copy = effect.namespace.DeepCopy()
				}
				copy.APIVersion, copy.Kind = "v1", "Namespace"
				_ = json.NewEncoder(w).Encode(copy)
				return
			}
			for _, gv := range []string{"v1", "apps/v1", "batch/v1", "rbac.authorization.k8s.io/v1"} {
				path, _ := discoveryPath(gv)
				if r.URL.Path == path {
					list := metav1.APIResourceList{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "APIResourceList"}, GroupVersion: gv}
					for _, resource := range resources {
						if resource[0] == gv {
							list.APIResources = append(list.APIResources, metav1.APIResource{Name: resource[2], Kind: resource[1], Namespaced: true, Verbs: metav1.Verbs{"get", "list", "create", "update", "patch", "delete"}})
						}
					}
					_ = json.NewEncoder(w).Encode(list)
					return
				}
			}
			if key, ok := objectPaths[r.URL.Path]; ok {
				if objects[key] == nil {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				if mode == "producer-denial-before" && probes == 20 && key == deploymentKey(d.Namespace, "arcadectl-controller") && !injected {
					objects[key].SetResourceVersion("18")
					objects[key].Object["status"] = map[string]any{"private": "PRIVATE-CANARY"}
					injected = true
				}
				if effect != nil && effect.failure == "late-producer-status" && effect.effects == 1 && effect.proofOpening && effect.postEffectRules == 6 && effect.postEffectProbes == 20 && key == deploymentKey(d.Namespace, "arcadectl-controller") && !effect.injected {
					objects[key].SetResourceVersion("200")
					objects[key].Object["status"] = map[string]any{"observedGeneration": int64(1), "replicas": int64(0)}
					effect.injected = true
				}
				if probes == 97 && key == serviceKey && !injected {
					switch mode {
					case "closing-new-pod":
						pod := servingObject(t, &v.objects.Pods.Items[0])
						pod.SetName("late-classified-pod")
						pod.SetUID("late-classified-pod-uid")
						objects[baselineObjectKey(pod)] = pod
						objectPaths["/api/v1/namespaces/"+d.Namespace+"/pods/late-classified-pod"] = baselineObjectKey(pod)
						injected = true
					case "closing-proxy-grant":
						proxyGrant, injected = true, true
					case "closing-service-rv":
						objects[key].SetResourceVersion("18")
						injected = true
					}
				}
				_ = json.NewEncoder(w).Encode(objects[key].Object)
				return
			}
			for _, resource := range resources {
				prefix := "/apis/" + resource[0]
				if resource[0] == "v1" {
					prefix = "/api/v1"
				}
				path := prefix + "/namespaces/" + d.Namespace + "/" + resource[2]
				if r.URL.Path == path {
					items := []any{}
					for key, object := range objects {
						if key.Kind == resource[1] && key.APIVersion == resource[0] && key.Namespace == d.Namespace {
							items = append(items, object.Object)
						}
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"apiVersion": resource[0], "kind": resource[1] + "List", "metadata": map[string]any{"resourceVersion": "50"}, "items": items})
					return
				}
			}
			w.WriteHeader(404)
			return
		}
		if user == "" || r.URL.Query().Get("dryRun") != "All" {
			persistent++
			w.WriteHeader(500)
			return
		}
		probes++
		if effect != nil && effect.effects == 1 {
			effect.postEffectProbes++
		}
		var object unstructured.Unstructured
		if json.NewDecoder(r.Body).Decode(&object.Object) != nil {
			t.Error("behavior mutation probe malformed")
			w.WriteHeader(500)
			return
		}
		var resource [3]string
		var name string
		for _, candidate := range resources {
			prefix := "/apis/" + candidate[0]
			if candidate[0] == "v1" {
				prefix = "/api/v1"
			}
			path := prefix + "/namespaces/" + d.Namespace + "/" + candidate[2]
			if r.URL.Path == path || strings.HasPrefix(r.URL.Path, path+"/") {
				resource, name = candidate, strings.TrimPrefix(r.URL.Path, path+"/")
				if r.Method == http.MethodPost {
					name = object.GetName()
				}
			}
		}
		if resource == [3]string{} {
			t.Error("behavior probe escaped native finite families")
			w.WriteHeader(500)
			return
		}
		policyFamily := "identity"
		if resource[1] == "Pod" {
			policyFamily = "pod"
			podProbes++
		} else if resource[1] == "Job" || resource[1] == "Deployment" {
			policyFamily = "template"
		}
		row := actor + "/" + r.Method + "/" + resource[1]
		rows[row]++
		key := installstate.Key{APIVersion: resource[0], Kind: resource[1], Namespace: d.Namespace, Name: name}
		if effect != nil && (!effect.update && (probes == 93 || probes == 185 || probes == 277) || effect.update && (probes == 98 || probes == 195 || probes == 292)) && actor == "arcadectl-controller" && r.Method == http.MethodPost && resource[1] == "Job" {
			producerBodies = map[string]*unstructured.Unstructured{}
		}
		if activation != nil && activation.proofs == 2 && probes == 98 && positives == 3 && len(producerBodies) == 3 && actor == "arcadectl-controller" && r.Method == http.MethodPost && resource[1] == "Job" {
			account, _, _ := unstructured.NestedString(object.Object, "spec", "template", "spec", "serviceAccountName")
			previous := producerBodies["arcadectl-controller/Job"]
			if account == "default" && previous != nil && name != previous.GetName() {
				// Only the literal first producer of the second complete97-row
				// cycle may establish new negative-variant reference bodies.
				// Original one-proof scenarios still reject repeated producers.
				producerBodies = map[string]*unstructured.Unstructured{}
			}
		}
		membership, valid := testBaselineBehaviorRequestRow(r, actor, key, &object, objects[key], producerBodies)
		if !valid {
			// Fixed diagnostic only; never print a captured request/body.
			t.Error("behavior request differs from literal original body, scope or variant", row)
			w.WriteHeader(500)
			return
		}
		detailedRows[row+"/"+membership]++
		if r.Method == http.MethodPost && (resource[1] == "Job" || resource[1] == "Deployment") {
			account, _, _ := unstructured.NestedString(object.Object, "spec", "template", "spec", "serviceAccountName")
			if strings.HasPrefix(name, "arcadectl-identity-probe-") && account == "default" {
				positives++
				reply := baselineProducerReply(t, &object, time.Now().UTC())
				if mode == "bad-positive" {
					reply.Object["status"], injected = map[string]any{"observedGeneration": int64(1)}, true
				}
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode(reply.Object)
				return
			}
		}
		if mode == "wrong-pod-family" && resource[1] == "Pod" {
			policyFamily, injected = "template", true
		}
		policy := "arcadectl-identity-" + policyFamily + "-" + d.Namespace
		// Independent native Status oracle. In particular a wrong Pod
		// policy is a valid 422 body, not a helper-generated nil reply.
		group := ""
		if resource[0] != "v1" {
			group = strings.TrimSuffix(resource[0], "/v1")
		}
		qualified := resource[2]
		if group != "" {
			qualified += "." + group
		}
		cause := "ValidatingAdmissionPolicy '" + policy + "' with binding '" + policy + "' denied request: Arcadectl installation identities and executables require trusted maintenance authority."
		status := metav1.Status{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: "Failure", Code: 422, Reason: metav1.StatusReasonInvalid,
			Message: fmt.Sprintf("%s %q is forbidden: %s", qualified, name, cause), Details: &metav1.StatusDetails{Group: group, Kind: resource[2], Name: name, Causes: []metav1.StatusCause{{Message: cause}}}}
		if mode == "missing-denial" {
			status.Message, injected = "PRIVATE-CANARY", true
		}
		if mode == "producer-denial-after" && probes == 21 && key == deploymentKey(d.Namespace, "arcadectl-controller") && !injected {
			objects[key].SetResourceVersion("18")
			objects[key].Object["status"] = map[string]any{"private": "PRIVATE-CANARY"}
			injected = true
		}
		w.WriteHeader(http.StatusUnprocessableEntity)
		_ = json.NewEncoder(w).Encode(status)
	})
	var access *HTTPAccess
	if len(fences) > 1 {
		t.Fatal("multiple test-only denied fences requested")
	}
	if len(fences) == 1 {
		handler = fences[0].wrap(t, handler)
	}
	if activation == nil {
		server := httptest.NewTLSServer(handler)
		t.Cleanup(server.Close)
		config := serverConfig(server)
		config.BearerToken, config.QPS, config.Burst = "FAKE-BEHAVIOR-PROVIDER", 1000, 2000 // In-process synthetic only.
		access, err = NewDirectHTTPAccess(config)
	} else {
		access, activation.forwards = nativeForwardFixtureProtocol(t, activation.serving, "success", activation.onUpgrade, true, func(w http.ResponseWriter, r *http.Request) bool {
			if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/portforward") {
				return false
			}
			handler.ServeHTTP(w, r)
			return true
		})
	}
	if err != nil {
		t.Fatal("closed behavior transport unavailable")
	}
	store, err := installstate.NewWithBaseline(access.Namespaces(), f.engine.baselinePlan(), plans...)
	if err != nil {
		t.Fatal("original behavior journal unavailable")
	}
	engine, err := NewWithBaselineAccess(access, store, f.engine.files, f.engine.baselinePlan(), plans...)
	if err != nil {
		t.Fatal("closed behavior engine unavailable")
	}
	snapshot, err := store.Load(t.Context(), f.snapshot.Anchor())
	if err != nil {
		t.Fatal("original sealed behavior journal unavailable")
	}
	provider, err := NewClusterSecurityBaseline(engine, access)
	if err != nil {
		t.Fatal("closed behavior provider unavailable")
	}
	guard := &baselineParentRefusingRuntimeGuard{}
	if runtime || protocol != nil {
		lifecycle, constructorErr := NewClusterLifecycle(engine, access)
		closed, ok := engine.baseline.runtimeGuard.(*ClusterSecurityBaseline)
		if constructorErr != nil || lifecycle == nil || !ok || closed == nil || closed != engine.baseline.prerequisites || closed.engine != engine || closed.access != access {
			t.Fatal("actual lifecycle did not wire the same complete closed provider")
		}
		provider = closed
	} else {
		engine.baseline.runtimeGuard = guard // Nonrecursion instrument ONLY.
		defer func() { engine.baseline.runtimeGuard = nil }()
	}
	constructorContext, constructorDiagnostic := WithLifecycleDiagnostic(t.Context())
	behavior, err := provider.newBaselineBehavior(constructorContext, snapshot)
	t.Cleanup(behavior.release)
	wantMembers := 3
	if effect != nil && !effect.update {
		wantMembers = 2
	}
	if precontroller {
		wantMembers = 0
	}
	if err != nil || behavior == nil || len(behavior.family.pods) != wantMembers || len(behavior.parents) != wantMembers {
		t.Fatalf("whole original behavior constructor refused authentic synthetic chains: %s", constructorDiagnostic.BoundarySnapshot())
	}
	var receiptName string
	if pendingService || pendingParent {
		receiptName = "create-" + d.Pending.CreateNonce + ".json"
		if testBaselineReceiptDescriptors(t, receiptName) != 1 {
			t.Fatal("inspected behavior did not own exactly one opening receipt")
		}
		// Do not let the inspected constructor protect Verify's inode.
		// Actual dispatch must acquire and hold its own original witness.
		behavior.release()
		if testBaselineReceiptDescriptors(t, receiptName) != 0 {
			t.Fatal("inspected constructor receipt was not released before actual Verify")
		}
	}
	// The actual dispatch reconstructs the complete proof rather than
	// trusting the separately inspected constructor result above.
	if protocol != nil {
		err = protocol(engine, snapshot, provider, func() int {
			mu.Lock()
			defer mu.Unlock()
			return requests
		})
	} else if runtime {
		current, currentErr := engine.current(t.Context(), snapshot)
		err = currentErr
		if positive && (current == nil || current.ResourceVersion() != snapshot.ResourceVersion() || current.Anchor() != snapshot.Anchor() || !bytes.Equal(current.Bytes(), snapshot.Bytes())) || !positive && (current != nil || err != ErrSecurityBaseline) {
			t.Fatal("actual guarded current boundary lost original snapshot or admitted changing evidence")
		}
	} else {
		proofContext, diagnostic := WithLifecycleDiagnostic(t.Context())
		err = provider.Verify(proofContext, snapshot)
		wantFailure := map[string]string{
			"missing-denial":         "check=denial-probe family=Job changes=unknown",
			"producer-denial-before": "check=denial-read-before family=Deployment changes=resource-version,metadata,status",
			"producer-denial-after":  "check=denial-read-after family=Deployment changes=resource-version,metadata,status",
		}[mode]
		if wantFailure != "" && diagnostic.FailureSnapshot() != wantFailure {
			t.Fatal("actual negative proof lost fixed refusal attribution", diagnostic.FailureSnapshot())
		}
		if (mode == "producer-denial-before" || mode == "producer-denial-after") && diagnostic.DeploymentSnapshot() != "role=controller metadata-first=resource-version-only status-first=other" {
			t.Fatal("actual negative proof lost fixed per-object detail")
		}
	}
	if (err == nil) != positive {
		t.Fatal("whole behavior driver confused healthy composition and injected refusal")
	}
	if receiptName != "" {
		if testBaselineReceiptDescriptors(t, receiptName) != 0 {
			t.Fatal("whole Verify leaked a closing collection or original behavior receipt")
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if closeOrder && injected {
		t.Fatal("current accepted identical receipt replacement during remote reads after releasing final runtime proof ownership")
	}
	if persistent != 0 || guard.calls.Load() != 0 || !bytes.Equal(snapshot.Bytes(), f.snapshot.Bytes()) {
		t.Fatal("behavior driver persisted, recursed or changed sealed journal")
	}
	if !positive && !injected {
		t.Fatal("intended whole-driver fault was never reached")
	}
	wantProbes, wantPodProbes := 97, 6
	wantPositives, wantRules := 3, 6
	if activation != nil {
		wantProbes, wantPodProbes = 97*activation.proofs, 6*activation.proofs
		wantPositives, wantRules = 3*activation.proofs, activation.rulePasses
	}
	if precontroller {
		wantProbes, wantPodProbes = 82, 0
	}
	if effect != nil {
		wantProbes, wantPodProbes, wantPositives, wantRules = 373, 18, 12, 24
		if effect.failure != "" && effect.failure != "receipt-at-settlement" && !(effect.update && effect.failure == "ambiguous-response") {
			wantProbes, wantPodProbes, wantPositives, wantRules = 276, 12, 9, 18
			if effect.failure == "late-status" || effect.failure == "receipt-after-wait" {
				wantRules++ // opening denied-catalog rules only, no fourth behavioral cycle
			}
		}
		if effect.update {
			// All three original families are present in the first three
			// complete proofs, unlike the explicit missing-parent CREATE case.
			wantProbes += 15
			wantPodProbes += 6
			if effect.failure == "ambiguous-response" {
				wantRules++ // first recovery's denied window, before later public proof
			}
		}
		if effect.failure == "late-producer-status" {
			wantProbes += 20
			wantPositives, wantRules = 12, 21
		}
	}
	if positive && (probes != wantProbes || positives != wantPositives || podProbes != wantPodProbes || rules["arcadectl-controller"] != wantRules || rules["arcadectl-destroy-controller"] != wantRules) {
		t.Fatal("healthy driver omitted finite behavioral rows or closing rule passes")
	}
	if positive {
		want := map[string]int{"arcadectl-controller/POST/Job": 9, "arcadectl-destroy-controller/POST/Job": 9, "arcadectl-controller/POST/Deployment": 9,
			"arcadectl-controller/POST/ServiceAccount": 4, "arcadectl-destroy-controller/POST/ServiceAccount": 4, "arcadectl-controller/POST/Role": 4, "arcadectl-destroy-controller/POST/Role": 4,
			"arcadectl-controller/POST/RoleBinding": 4, "arcadectl-destroy-controller/POST/RoleBinding": 4, "arcadectl-controller/POST/Service": 4,
			"arcadectl-controller/DELETE/ServiceAccount": 4, "arcadectl-destroy-controller/DELETE/ServiceAccount": 4, "arcadectl-controller/DELETE/Role": 4, "arcadectl-destroy-controller/DELETE/Role": 4,
			"arcadectl-controller/DELETE/RoleBinding": 4, "arcadectl-destroy-controller/DELETE/RoleBinding": 4, "arcadectl-controller/PUT/Service": 1, "arcadectl-controller/PATCH/Service": 1, "arcadectl-controller/DELETE/Service": 1,
			"arcadectl-controller/PUT/Deployment": 3, "arcadectl-controller/PATCH/Deployment": 3, "arcadectl-controller/DELETE/Deployment": 3, "arcadectl-controller/PUT/Pod": 3, "arcadectl-destroy-controller/PUT/Pod": 3}
		if precontroller {
			for _, absent := range []string{"arcadectl-controller/PUT/Deployment", "arcadectl-controller/PATCH/Deployment", "arcadectl-controller/DELETE/Deployment", "arcadectl-controller/PUT/Pod", "arcadectl-destroy-controller/PUT/Pod"} {
				delete(want, absent)
			}
		}
		if activation != nil {
			for row, count := range want {
				if activation.proofs == 0 {
					delete(want, row)
				} else {
					want[row] = count * activation.proofs
				}
			}
		}
		if effect != nil {
			cycles := 4
			if wantPositives == 9 || effect.failure == "late-producer-status" {
				cycles = 3
			}
			for row, count := range want {
				want[row] = count * cycles
			}
			if !effect.update {
				for _, row := range []string{"arcadectl-controller/PUT/Deployment", "arcadectl-controller/PATCH/Deployment", "arcadectl-controller/DELETE/Deployment", "arcadectl-controller/PUT/Pod", "arcadectl-destroy-controller/PUT/Pod"} {
					want[row] -= 3 // API parent and Pod absent in the first three proofs.
				}
			}
			if effect.failure == "late-producer-status" {
				want["arcadectl-controller/POST/Job"] += 9
				want["arcadectl-destroy-controller/POST/Job"] += 9
				want["arcadectl-controller/POST/Deployment"] += 2
			}
		}
		if !reflect.DeepEqual(want, rows) {
			t.Fatal("behavior driver request multiset differs from independent literal protocol")
		}
		wantDetailed := testBaselineBehaviorLiteralRows(v.objects.Pods.Items)
		if effect != nil {
			cycles := 4
			if wantPositives == 9 || effect.failure == "late-producer-status" {
				cycles = 3
			}
			for row, count := range wantDetailed {
				wantDetailed[row] = count * cycles
				if !effect.update && (strings.HasSuffix(row, "/Deployment/arcadectl-api") || strings.Contains(row, "/Pod/") && strings.HasSuffix(row, "/"+effect.podName)) {
					wantDetailed[row] -= 3
				}
				if wantDetailed[row] == 0 {
					delete(wantDetailed, row)
				}
			}
			if effect.failure == "late-producer-status" {
				// Literal fourth-cycle prefix: both complete Job groups and
				// only two Deployment rows. The reserved-name denial is NOT sent.
				for row, count := range testBaselineBehaviorLiteralRows(nil) {
					if strings.Contains(row, "/POST/Job/") {
						wantDetailed[row] += count
					}
				}
				wantDetailed["arcadectl-controller/POST/Deployment/positive"]++
				wantDetailed["arcadectl-controller/POST/Deployment/account/arcadectl-controller"]++
			}
		}
		if activation != nil {
			for row, count := range wantDetailed {
				if activation.proofs == 0 {
					delete(wantDetailed, row)
				} else {
					wantDetailed[row] = count * activation.proofs
				}
			}
		}
		if precontroller {
			for _, method := range []string{"PUT", "PATCH", "DELETE"} {
				for _, name := range []string{"arcadectl-controller", "arcadectl-api", "arcadectl-destroy-controller"} {
					delete(wantDetailed, "arcadectl-controller/"+method+"/Deployment/"+name)
				}
			}
		}
		if !reflect.DeepEqual(wantDetailed, detailedRows) {
			t.Fatal("behavior driver omitted or repeated a literal named/variant row")
		}
	}
}

// Independent request oracle: no production operation, constructor, route or
// permission helper is used to derive these original-body expectations.
func testBaselineBehaviorRequestRow(r *http.Request, actor string, key installstate.Key, body, original *unstructured.Unstructured, producers map[string]*unstructured.Unstructured) (string, bool) {
	query, typ := "dryRun=All&fieldManager=arcadectl-installer&fieldValidation=Strict", "application/json"
	if r.Method == "DELETE" {
		query = "dryRun=All"
	} else if r.Method == "PATCH" {
		typ = "application/merge-patch+json"
	}
	if r.URL.RawQuery != query || r.Header.Get("Content-Type") != typ || r.Header.Get("Accept") != "application/json" || body == nil {
		return "", false
	}
	if r.Method != "POST" {
		if original == nil {
			return "", false
		}
		var want any
		switch r.Method {
		case "PUT":
			copy := original.DeepCopy()
			annotations := copy.GetAnnotations()
			if annotations == nil {
				annotations = map[string]string{}
			}
			annotations["arcade.gobha.me/identity-probe"] = "dry-run"
			copy.SetAnnotations(annotations)
			want = copy.Object
		case "DELETE":
			want = map[string]any{"apiVersion": "v1", "kind": "DeleteOptions", "dryRun": []any{"All"}, "preconditions": map[string]any{"uid": string(original.GetUID()), "resourceVersion": original.GetResourceVersion()}}
		case "PATCH":
			want = map[string]any{"metadata": map[string]any{"uid": string(original.GetUID()), "resourceVersion": original.GetResourceVersion(), "annotations": map[string]any{"arcade.gobha.me/identity-probe": "dry-run"}}}
		default:
			return "", false
		}
		return key.Name, testBaselineBehaviorJSONEqual(want, body.Object)
	}
	if body.GetAPIVersion() != key.APIVersion || body.GetKind() != key.Kind || body.GetNamespace() != key.Namespace || body.GetName() != key.Name || body.GetUID() != "" || body.GetResourceVersion() != "" {
		return "", false
	}
	reserved := func(name string) bool {
		return name == "arcadectl-controller" || name == "arcadectl-api" || name == "arcadectl-destroy-controller" || name == "arcadectl-destroy-admin"
	}
	if key.Kind == "Job" || key.Kind == "Deployment" {
		label := body.GetLabels()["arcade.gobha.me/identity-probe"]
		nonce := strings.TrimPrefix(label, "arcadectl-identity-probe-")
		decoded, err := hex.DecodeString(nonce)
		if err != nil || len(decoded) != 16 || hex.EncodeToString(decoded) != nonce || label != "arcadectl-identity-probe-"+nonce {
			return "", false
		}
		account, _, _ := unstructured.NestedString(body.Object, "spec", "template", "spec", "serviceAccountName")
		alias, _, _ := unstructured.NestedString(body.Object, "spec", "template", "spec", "serviceAccount")
		if account != alias {
			return "", false
		}
		producerKey := actor + "/" + key.Kind
		if key.Name == label && account == "default" {
			if producers[producerKey] != nil {
				return "", false
			}
			producers[producerKey] = body.DeepCopy()
			return "positive", true
		}
		positive := producers[producerKey]
		if positive == nil {
			return "", false
		}
		want := positive.DeepCopy()
		if key.Name == label && reserved(account) {
			_ = unstructured.SetNestedField(want.Object, account, "spec", "template", "spec", "serviceAccountName")
			_ = unstructured.SetNestedField(want.Object, account, "spec", "template", "spec", "serviceAccount")
			return "account/" + account, testBaselineBehaviorJSONEqual(want.Object, body.Object)
		}
		if reserved(key.Name) && account == "default" {
			want.SetName(key.Name)
			return "name/" + key.Name, testBaselineBehaviorJSONEqual(want.Object, body.Object)
		}
		return "", false
	}
	if !reserved(key.Name) {
		return "", false
	}
	want := map[string]any{"apiVersion": key.APIVersion, "kind": key.Kind, "metadata": map[string]any{"namespace": key.Namespace, "name": key.Name}}
	switch key.Kind {
	case "ServiceAccount":
		want["automountServiceAccountToken"] = false
	case "Role":
		want["rules"] = []any{}
	case "RoleBinding":
		want["roleRef"] = map[string]any{"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": actor}
		want["subjects"] = []any{}
	case "Service":
		want["spec"] = map[string]any{"type": "ClusterIP", "clusterIP": "None", "ports": []any{map[string]any{"name": "identity-probe", "port": 1, "protocol": "TCP", "targetPort": 1}}}
	default:
		return "", false
	}
	return key.Name, testBaselineBehaviorJSONEqual(want, body.Object)
}

func testBaselineBehaviorJSONEqual(want, actual any) bool {
	body, err := json.Marshal(want)
	var normalized any
	return err == nil && json.Unmarshal(body, &normalized) == nil && reflect.DeepEqual(normalized, actual)
}

func testBaselineBehaviorLiteralRows(pods []corev1.Pod) map[string]int {
	want := map[string]int{}
	for _, actor := range []string{"arcadectl-controller", "arcadectl-destroy-controller"} {
		kinds := []string{"Job"}
		if actor == "arcadectl-controller" {
			kinds = append(kinds, "Deployment")
		}
		for _, kind := range kinds {
			prefix := actor + "/POST/" + kind + "/"
			want[prefix+"positive"] = 1
			for _, name := range []string{"arcadectl-controller", "arcadectl-api", "arcadectl-destroy-controller", "arcadectl-destroy-admin"} {
				want[prefix+"account/"+name], want[prefix+"name/"+name] = 1, 1
			}
		}
		for _, name := range []string{"arcadectl-controller", "arcadectl-api", "arcadectl-destroy-controller", "arcadectl-destroy-admin"} {
			for _, kind := range []string{"ServiceAccount", "Role", "RoleBinding"} {
				want[actor+"/POST/"+kind+"/"+name], want[actor+"/DELETE/"+kind+"/"+name] = 1, 1
			}
			if actor == "arcadectl-controller" {
				want[actor+"/POST/Service/"+name] = 1
			}
		}
		for _, pod := range pods {
			want[actor+"/PUT/Pod/"+pod.Name] = 1
		}
	}
	for _, method := range []string{"PUT", "PATCH", "DELETE"} {
		want["arcadectl-controller/"+method+"/Service/arcadectl-api"] = 1
		for _, name := range []string{"arcadectl-controller", "arcadectl-api", "arcadectl-destroy-controller"} {
			want["arcadectl-controller/"+method+"/Deployment/"+name] = 1
		}
	}
	return want
}
