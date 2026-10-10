// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	authv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Genuine fake-lifecycle completed history mirrored by an independent TLS
// responder, then consumed through the actual closed production composition.
// Health, storage and RBAC decisions are synthetic, NOT native certification.
type enrollmentSafetyTLSFixture struct {
	lifecycle *Lifecycle
	snapshot  *installstate.Snapshot
	inputs    *baselineEnrollmentInputs
	legacy    *lifecycleFixture
	objects   map[installstate.Key]*unstructured.Unstructured
	mu        sync.Mutex
	onRead    func(string)
	onRules   func(string)
	writes    int
	actors    map[string]int
	rules     map[string]int
	reviews   map[string]map[authv1.ResourceAttributes]int
	expected  map[string]map[authv1.ResourceAttributes]bool
	trace     []string
}

func newEnrollmentSafetyTLSFixture(t *testing.T, mode installstate.Mode) *enrollmentSafetyTLSFixture {
	t.Helper()
	v, source, name, _ := baselineEnrollmentSourceFixture(t, mode)
	ns, err := v.f.access.Get(t.Context(), namespaceKey(source.Anchor().Namespace))
	if err != nil {
		t.Fatal("original synthetic historical Namespace unavailable")
	}
	f := &enrollmentSafetyTLSFixture{legacy: v, objects: map[installstate.Key]*unstructured.Unstructured{}, actors: map[string]int{}, rules: map[string]int{}, reviews: map[string]map[authv1.ResourceAttributes]int{}, expected: map[string]map[authv1.ResourceAttributes]bool{}}
	f.objects[namespaceKey(source.Anchor().Namespace)] = ns
	for key, object := range v.f.access.objects {
		f.objects[key] = object.DeepCopy()
	}
	for name, secret := range v.private.objects {
		copy := secret.DeepCopy()
		copy.APIVersion, copy.Kind = "v1", "Secret"
		f.objects[secretKey(source.Anchor().Namespace, name)] = servingObject(t, copy)
	}
	// A retained bound world whose GameServer was already removed still belongs
	// to the immutable world floor. No live game or destructive operation is used.
	claim := &corev1.PersistentVolumeClaim{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "PersistentVolumeClaim"}, ObjectMeta: metav1.ObjectMeta{Name: "retained-world", Namespace: source.Anchor().Namespace, UID: "original-retained-world", ResourceVersion: "20"}, Spec: corev1.PersistentVolumeClaimSpec{VolumeName: "world-pv", AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce}, Resources: corev1.VolumeResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("10Gi")}}}, Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound, Capacity: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("10Gi")}}}
	volume := coldPVFixture()
	volume.Spec.ClaimRef = &corev1.ObjectReference{Namespace: claim.Namespace, Name: claim.Name, UID: claim.UID}
	for _, object := range []*unstructured.Unstructured{servingObject(t, claim), servingObject(t, volume)} {
		f.objects[baselineObjectKey(object)] = object
	}
	clusterKeys := []installstate.Key{}
	for _, row := range source.Document().Resources {
		if row.Key.Kind == "ClusterRole" || row.Key.Kind == "ClusterRoleBinding" {
			clusterKeys = append(clusterKeys, row.Key)
		}
	}
	for _, actor := range []admissionActor{ordinaryControllerActor, destroyControllerActor} {
		user := "system:serviceaccount:" + source.Anchor().Namespace + ":" + actor.account()
		f.expected[user], f.reviews[user] = map[authv1.ResourceAttributes]bool{}, map[authv1.ResourceAttributes]int{}
		// This independent literal oracle also covers generated descendants in
		// other fixtures. This particular original inventory has no descendants.
		for row := range testBaselineDeniedAttributes(source.Anchor().Namespace, actor, clusterKeys) {
			if !strings.Contains(row.Name, "generated-") {
				f.expected[user][row] = true
			}
		}
		for _, row := range testBaselineContainmentAttributes(source.Anchor().Namespace) {
			f.expected[user][row] = true
		}
	}
	// Independent complete discovery, not permission/proof catalog derivation.
	resources := []proofCollection{
		{"v1", "Namespace", "namespaces", false}, {"v1", "PersistentVolume", "persistentvolumes", false},
		{"v1", "Pod", "pods", true}, {"v1", "Secret", "secrets", true}, {"v1", "PersistentVolumeClaim", "persistentvolumeclaims", true}, {"v1", "ServiceAccount", "serviceaccounts", true}, {"v1", "Service", "services", true}, {"v1", "ReplicationController", "replicationcontrollers", true},
		{"apps/v1", "Deployment", "deployments", true}, {"apps/v1", "ReplicaSet", "replicasets", true}, {"apps/v1", "StatefulSet", "statefulsets", true}, {"apps/v1", "DaemonSet", "daemonsets", true},
		{"batch/v1", "Job", "jobs", true}, {"batch/v1", "CronJob", "cronjobs", true},
		{"rbac.authorization.k8s.io/v1", "Role", "roles", true}, {"rbac.authorization.k8s.io/v1", "RoleBinding", "rolebindings", true}, {"rbac.authorization.k8s.io/v1", "ClusterRole", "clusterroles", false}, {"rbac.authorization.k8s.io/v1", "ClusterRoleBinding", "clusterrolebindings", false},
		{"apiextensions.k8s.io/v1", "CustomResourceDefinition", "customresourcedefinitions", false},
		{"admissionregistration.k8s.io/v1", "ValidatingAdmissionPolicy", "validatingadmissionpolicies", false}, {"admissionregistration.k8s.io/v1", "ValidatingAdmissionPolicyBinding", "validatingadmissionpolicybindings", false},
		{"arcade.gobha.me/v1alpha1", "GameServer", "gameservers", true}, {"arcade.gobha.me/v1alpha1", "GameBackup", "gamebackups", true}, {"arcade.gobha.me/v1alpha1", "GameRestore", "gamerestores", true}, {"arcade.gobha.me/v1alpha1", "GameDestroy", "gamedestroys", true}, {"arcade.gobha.me/v1alpha1", "ArcadeOperation", "arcadeoperations", true},
		{"coordination.k8s.io/v1", "Lease", "leases", true}, {"storage.k8s.io/v1", "VolumeAttachment", "volumeattachments", false}, {"discovery.k8s.io/v1", "EndpointSlice", "endpointslices", true},
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		// Fixed request addresses only: no bodies, credentials or world data.
		f.trace = append(f.trace, r.Method+" "+r.URL.Path)
		if len(f.trace) > 20 {
			f.trace = f.trace[len(f.trace)-20:]
		}
		w.Header().Set("Content-Type", "application/json")
		user := r.Header.Get("Impersonate-User")
		if r.Header.Get("Authorization") != "Bearer FAKE-HISTORICAL-ADMIN" {
			t.Error("historical proof changed frozen administrator credential")
		}
		if user != "" && user != "system:serviceaccount:"+source.Anchor().Namespace+":arcadectl-controller" && user != "system:serviceaccount:"+source.Anchor().Namespace+":arcadectl-destroy-controller" {
			t.Error("historical safety impersonated an extra identity")
		}
		if r.Method == http.MethodPost && r.URL.Path == "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" {
			var review authv1.SelfSubjectAccessReview
			if json.NewDecoder(r.Body).Decode(&review) != nil || review.Spec.ResourceAttributes == nil || review.Spec.NonResourceAttributes != nil || r.URL.RawQuery != "fieldManager=arcadectl-installer&fieldValidation=Strict" {
				t.Error("historical review malformed")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			attributes := *review.Spec.ResourceAttributes
			allowed := false
			if user != "" {
				f.actors[user]++
				if !f.expected[user][attributes] {
					t.Error("historical denied review escaped independent literal catalog")
				} else {
					f.reviews[user][attributes]++
				}
			} else {
				allowed = attributes.Verb == "get" || attributes.Verb == "list" || attributes == (authv1.ResourceAttributes{Version: "*", Resource: "serviceaccounts", Namespace: source.Anchor().Namespace, Name: "arcadectl-controller", Verb: "impersonate"}) || attributes == (authv1.ResourceAttributes{Version: "*", Resource: "serviceaccounts", Namespace: source.Anchor().Namespace, Name: "arcadectl-destroy-controller", Verb: "impersonate"})
				if !allowed || attributes.FieldSelector != nil || attributes.LabelSelector != nil {
					t.Error("historical administrator requested unexpected mutation/identity authority")
				}
			}
			review.TypeMeta = metav1.TypeMeta{APIVersion: "authorization.k8s.io/v1", Kind: "SelfSubjectAccessReview"}
			review.Status = authv1.SubjectAccessReviewStatus{Allowed: allowed}
			_ = json.NewEncoder(w).Encode(review)
			return
		}
		if r.Method == http.MethodPost && r.URL.Path == "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews" {
			var review authv1.SelfSubjectRulesReview
			if json.NewDecoder(r.Body).Decode(&review) != nil || review.Spec.Namespace != source.Anchor().Namespace || user == "" || r.URL.RawQuery != "fieldManager=arcadectl-installer&fieldValidation=Strict" {
				t.Error("historical rules review escaped actor/namespace")
			}
			f.rules[user]++
			if f.onRules != nil {
				f.onRules(user)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"apiVersion": "authorization.k8s.io/v1", "kind": "SelfSubjectRulesReview", "spec": map[string]any{}, "status": map[string]any{"incomplete": false, "resourceRules": []any{}, "nonResourceRules": []any{}}})
			return
		}
		if r.Method != http.MethodGet || user != "" {
			f.writes++
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if f.onRead != nil {
			f.onRead(r.URL.Path)
		}
		if r.URL.Path == "/version" {
			_ = json.NewEncoder(w).Encode(map[string]any{"major": "1", "minor": "37", "gitVersion": "v1.37.0"})
			return
		}
		for _, collection := range resources {
			base := "/apis/" + collection.gv
			if collection.gv == "v1" {
				base = "/api/v1"
			}
			if r.URL.Path == base {
				list := metav1.APIResourceList{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "APIResourceList"}, GroupVersion: collection.gv}
				for _, row := range resources {
					if row.gv == collection.gv {
						list.APIResources = append(list.APIResources, metav1.APIResource{Name: row.plural, Kind: row.kind, Namespaced: row.namespaced, Verbs: metav1.Verbs{"get", "list"}})
					}
				}
				_ = json.NewEncoder(w).Encode(list)
				return
			}
			if collection.namespaced {
				base += "/namespaces/" + source.Anchor().Namespace
			}
			base += "/" + collection.plural
			partial := strings.Contains(r.Header.Get("Accept"), "as=PartialObjectMetadata")
			if r.URL.Path == base {
				items := []any{}
				for key, object := range f.objects {
					if key.Kind != collection.kind || key.APIVersion != collection.gv {
						continue
					}
					if partial {
						items = append(items, object.Object["metadata"])
					} else {
						items = append(items, object.Object)
					}
				}
				if partial {
					metadata := []any{}
					for _, row := range items {
						metadata = append(metadata, map[string]any{"apiVersion": "meta.k8s.io/v1", "kind": "PartialObjectMetadata", "metadata": row})
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"apiVersion": "meta.k8s.io/v1", "kind": "PartialObjectMetadataList", "metadata": map[string]any{"resourceVersion": "20"}, "items": metadata})
				} else {
					_ = json.NewEncoder(w).Encode(map[string]any{"apiVersion": collection.gv, "kind": collection.kind + "List", "metadata": map[string]any{"resourceVersion": "20"}, "items": items})
				}
				return
			}
			for key, object := range f.objects {
				if key.Kind == collection.kind && key.APIVersion == collection.gv && r.URL.Path == base+"/"+key.Name {
					if partial {
						_ = json.NewEncoder(w).Encode(map[string]any{"apiVersion": "meta.k8s.io/v1", "kind": "PartialObjectMetadata", "metadata": object.Object["metadata"]})
					} else {
						_ = json.NewEncoder(w).Encode(object.Object)
					}
					return
				}
			}
		}
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(metav1.Status{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: metav1.StatusFailure, Reason: metav1.StatusReasonNotFound, Code: http.StatusNotFound})
	}))
	t.Cleanup(server.Close)
	config := serverConfig(server)
	config.BearerToken = "FAKE-HISTORICAL-ADMIN"
	access, err := NewDirectHTTPAccess(config)
	if err != nil {
		t.Fatal("historical direct TLS transport unavailable")
	}
	plans := []*installrender.Plan{}
	for _, plan := range v.f.engine.plans {
		plans = append(plans, plan)
	}
	store, err := installstate.NewWithBaseline(access.Namespaces(), v.f.engine.baselinePlan(), plans...)
	if err != nil {
		t.Fatal("historical TLS journal unavailable")
	}
	engine, err := NewWithBaselineAccess(access, store, v.f.engine.files, v.f.engine.baselinePlan(), plans...)
	if err != nil {
		t.Fatal("historical TLS engine unavailable")
	}
	f.lifecycle, err = NewClusterLifecycle(engine, access)
	if err != nil {
		t.Fatal("closed historical TLS composition unavailable")
	}
	f.snapshot, err = store.Load(t.Context(), source.Anchor())
	if err != nil {
		t.Fatal("real historical TLS journal unavailable")
	}
	f.inputs, err = engine.openBaselineEnrollmentInputs(t.Context(), f.snapshot, v.f.plan, name, v.opts.Activation.CAFile)
	if err != nil {
		t.Fatal("original historical TLS input owners unavailable")
	}
	t.Cleanup(f.inputs.release)
	return f
}

func TestBaselineEnrollmentSafetyHistoricalModesClosedTLS(t *testing.T) {
	for _, mode := range []installstate.Mode{installstate.Install, installstate.Upgrade, installstate.Rollback} {
		t.Run(string(mode), func(t *testing.T) {
			f := newEnrollmentSafetyTLSFixture(t, mode)
			owner, err := f.lifecycle.openBaselineEnrollmentSafety(t.Context(), f.snapshot, f.inputs, nil, f.legacy.opts)
			if err != nil || owner == nil {
				t.Fatal("closed historical original safety refused", err, f.trace)
			}
			defer owner.release()
			if owner.snapshot.Document().Mode != mode || owner.snapshot.Document().SecurityBaseline != nil || f.writes != 0 || len(f.actors) != 2 || len(f.rules) != 2 || len(owner.opening.worlds.Claims) != 1 || len(owner.opening.worlds.Volumes) != 1 {
				t.Fatal("historical safety rewrote history, minted authority or issued an effect")
			}
			for actor, expected := range f.expected {
				if f.actors[actor] != 2*len(expected) || len(f.reviews[actor]) != len(expected) || f.rules[actor] != 3 {
					t.Fatal("historical containment omitted a pass or complete rules")
				}
				for row := range expected {
					if f.reviews[actor][row] != 2 {
						t.Fatal("historical containment omitted an independent denied descriptor/pass")
					}
				}
			}
			if _, err := f.lifecycle.engine.baseline.runtimeAccessWitness(t.Context(), f.snapshot); err != ErrSecurityBaseline {
				t.Fatal("historical safety opened verified baseline guard")
			}
			copiedInputs := *f.inputs
			if _, err := f.lifecycle.openBaselineEnrollmentSafety(t.Context(), f.snapshot, &copiedInputs, nil, f.legacy.opts); err != ErrSecurityBaseline || owner.confirmLocal(t.Context(), owner.opening) != nil {
				t.Fatal("copied input owner accepted or damaged held originals")
			}
			// The mutable cached map cannot replace its complete sealed LIST/GET.
			changed := *owner.opening
			changedExecutables := *changed.executables
			changedExecutables.whole = map[installstate.Key]*unstructured.Unstructured{}
			changed.executables = &changedExecutables
			if owner.confirmLocal(t.Context(), &changed) != ErrSecurityBaseline || owner.confirmLocal(t.Context(), owner.opening) != nil {
				t.Fatal("shrunken executable cache accepted or changed sealed evidence")
			}
			copy := *owner
			copy.release()
			if copy.close(t.Context()) != ErrSecurityBaseline || owner.confirmLocal(t.Context(), owner.opening) != nil {
				t.Fatal("copied owner accepted or released real original descriptors")
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if owner.close(ctx) != ErrSecurityBaseline {
				t.Fatal("cancelled historical closure succeeded")
			}
		})
	}
}

func TestBaselineEnrollmentSafetyOriginalAndLateEvidenceClosedTLS(t *testing.T) {
	f := newEnrollmentSafetyTLSFixture(t, installstate.Install)
	owner, err := f.lifecycle.openBaselineEnrollmentSafety(t.Context(), f.snapshot, f.inputs, nil, f.legacy.opts)
	if err != nil {
		t.Fatal("positive closed safety prerequisite refused", err)
	}
	defer owner.release()
	for _, which := range []string{"original-access", "original-policy", "late-secret", "final-rules-world", "final-rules-producer"} {
		t.Run(which, func(t *testing.T) {
			before := map[installstate.Key]*unstructured.Unstructured{}
			for key, object := range f.objects {
				before[key] = object.DeepCopy()
			}
			defer func() { f.objects, f.onRead, f.onRules = before, nil, nil }()
			injected := false
			switch which {
			case "original-access":
				key := installstate.Key{APIVersion: "v1", Kind: "ServiceAccount", Namespace: f.snapshot.Anchor().Namespace, Name: "arcadectl-controller"}
				f.objects[key].SetUID("same-name-foreign-access")
				injected = true
			case "original-policy":
				for key, object := range f.objects {
					if key.Kind == "ValidatingAdmissionPolicy" {
						object.SetResourceVersion("999999")
						injected = true
						break
					}
				}
			case "late-secret":
				coldSeen := false
				f.onRead = func(path string) {
					if strings.HasSuffix(path, "/endpointslices") {
						coldSeen = true
					}
					if coldSeen && !injected && path == "/api/v1/namespaces/"+f.snapshot.Anchor().Namespace {
						f.objects[secretKey(f.snapshot.Anchor().Namespace, "arcadectl-api-tls")].SetResourceVersion("999999")
						injected = true
					}
				}
			case "final-rules-world", "final-rules-producer":
				f.onRules = func(user string) {
					// Existing opening/first proof has three SSRRs per actor. The
					// second invocation's final destroy-actor SSRR is number six.
					if injected || !strings.HasSuffix(user, ":arcadectl-destroy-controller") || f.rules[user] != 6 {
						return
					}
					if which == "final-rules-world" {
						claim := &corev1.PersistentVolumeClaim{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "PersistentVolumeClaim"}, ObjectMeta: metav1.ObjectMeta{Name: "late-world", Namespace: f.snapshot.Anchor().Namespace, UID: "late-world-uid", ResourceVersion: "1"}, Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimPending}}
						object := servingObject(t, claim)
						f.objects[baselineObjectKey(object)] = object
					} else {
						probe, err := baselineProducerProbe(f.lifecycle.engine.plans[f.snapshot.Document().TargetPackage], "Job", strings.Repeat("c", 32))
						if err != nil {
							t.Fatal("inert foreign producer control unavailable")
						}
						probe.SetName("arcadectl-controller")
						probe.SetUID("late-foreign-producer")
						probe.SetResourceVersion("1")
						probe.SetGeneration(1)
						probe.Object["status"] = map[string]any{}
						f.objects[baselineObjectKey(probe)] = probe
					}
					injected = true
				}
				// Keep exact per-actor trigger counts independent of earlier
				// refused cases, which do not all reach rules collection.
				for actor := range f.rules {
					f.rules[actor] = 3
				}
			}
			var refusal error
			if strings.HasPrefix(which, "final-rules") {
				refusal = owner.verifyActorContainment(t.Context())
			} else {
				refusal = owner.close(t.Context())
			}
			if !injected || refusal != ErrSecurityBaseline || f.writes != 0 {
				t.Fatal("original/late evidence change accepted, injection vacuous or effect issued", fmt.Sprint(refusal))
			}
		})
	}
}

func TestBaselineEnrollmentSafetySourceBackedResumeClosedTLS(t *testing.T) {
	f := newEnrollmentSafetyTLSFixture(t, installstate.Upgrade)
	e := f.lifecycle.engine
	opening, err := f.lifecycle.openBaselineEnrollmentSafety(t.Context(), f.snapshot, f.inputs, nil, f.legacy.opts)
	if err != nil {
		t.Fatal("closed original source safety unavailable", err)
	}
	witness, err := e.saveBaselineEnrollmentSource(t.Context(), f.snapshot, f.inputs, opening.opening.worlds)
	if err != nil {
		opening.release()
		t.Fatal("protected actual-world source publication unavailable", err)
	}
	defer witness.release()
	opening.release()
	if f.inputs.confirm(t.Context(), e, f.snapshot.Anchor()) != nil {
		t.Fatal("safety release closed borrowed original input descriptors")
	}
	// Use the existing real fake-store source-introduction CAS, then mirror its
	// Namespace into the independent TLS reader. No native mutation is claimed.
	legacy, err := f.legacy.f.store.Load(t.Context(), f.snapshot.Anchor())
	if err != nil {
		t.Fatal("original legacy introduction snapshot unavailable")
	}
	introduced := introduceBaselineEnrollmentSource(t, f.legacy, legacy, witness)
	namespace, err := f.legacy.f.access.Get(t.Context(), namespaceKey(introduced.Anchor().Namespace))
	if err != nil {
		t.Fatal("genuine synthetic source-introduction Namespace unavailable")
	}
	f.objects[namespaceKey(introduced.Anchor().Namespace)] = namespace
	f.snapshot, err = e.journal.Load(t.Context(), introduced.Anchor())
	if err != nil {
		t.Fatal("actual TLS source-backed snapshot unavailable")
	}
	before := f.snapshot.Bytes()
	resumed, err := f.lifecycle.openBaselineEnrollmentSafety(t.Context(), f.snapshot, witness.inputs, witness, f.legacy.opts)
	if err != nil {
		t.Fatal("closed original source-backed safety refused", err)
	}
	resumed.release()
	if string(before) != string(f.snapshot.Bytes()) || f.snapshot.Document().Mode != installstate.Upgrade || f.snapshot.Document().SecurityBaseline.Enrollment == nil || f.writes != 0 || e.confirmBaselineEnrollmentSource(t.Context(), witness, f.snapshot) != nil {
		t.Fatal("resume rewrote genuine history, emitted effects or released borrowed source")
	}
	witness.release()
	if _, err := f.lifecycle.openBaselineEnrollmentSafety(t.Context(), f.snapshot, witness.inputs, witness, f.legacy.opts); err != ErrSecurityBaseline {
		t.Fatal("released original source supplied resume authority")
	}
}
