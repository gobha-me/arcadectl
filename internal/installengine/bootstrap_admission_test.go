// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/adminauth"
	"github.com/gobha-me/arcadectl/internal/installsafety"
	"github.com/gobha-me/arcadectl/internal/installstate"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
)

func bootstrapReadyFixture(t *testing.T) (*lifecycleFixture, *installstate.Snapshot) {
	t.Helper()
	v := newLifecycleFixture(t)
	v.fail = BootstrapAdmission
	s := v.f.snapshot
	for i := 0; i < 100; i++ {
		next, err := v.l.Step(context.Background(), s, v.opts)
		s = next
		if errors.Is(err, ErrLifecycle) {
			if _, err := v.f.engine.bootstrapAccess(context.Background(), s); err != nil {
				t.Fatal("did not reach original RBAC bootstrap barrier", err)
			}
			return v, s
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Fatal("did not reach bootstrap barrier")
	return nil, nil
}

func TestBootstrapAdmissionFailureOrIdentityDriftHasNoEffect(t *testing.T) {
	for _, scenario := range []string{"proof", "missing-account", "replaced-account", "account-spec", "changed-during-proof", "foreign-service", "foreign-deployment", "foreign-later-rolebinding", "foreign-later-clusterrolebinding", "service-read-error"} {
		t.Run(scenario, func(t *testing.T) {
			v, s := bootstrapReadyFixture(t)
			if scenario != "proof" {
				v.fail = 0
			}
			account := installstate.Key{APIVersion: "v1", Kind: "ServiceAccount", Namespace: s.Anchor().Namespace, Name: "arcadectl-controller"}
			switch scenario {
			case "missing-account":
				delete(v.f.access.objects, account)
			case "replaced-account":
				v.f.access.objects[account].SetUID("replacement")
			case "account-spec":
				v.f.access.objects[account].Object["automountServiceAccountToken"] = true
			case "changed-during-proof":
				v.probe = func(request LifecycleCheck) error {
					if request.Checkpoint == BootstrapAdmission {
						v.f.access.objects[account].SetResourceVersion("changed-during-proof")
					}
					return nil
				}
			case "foreign-service", "foreign-deployment":
				kind, api := "Service", "v1"
				if scenario == "foreign-deployment" {
					kind, api = "Deployment", "apps/v1"
				}
				key := installstate.Key{APIVersion: api, Kind: kind, Namespace: account.Namespace, Name: apiFamily}
				v.f.access.objects[key] = &unstructured.Unstructured{Object: map[string]any{"apiVersion": api, "kind": kind, "metadata": map[string]any{"name": key.Name, "namespace": key.Namespace, "uid": "foreign", "resourceVersion": "1"}}}
			case "service-read-error":
				v.f.access.get = func(key installstate.Key) error {
					if key.Kind == "Service" {
						return errors.New("PRIVATE-CANARY")
					}
					return nil
				}
			case "foreign-later-rolebinding", "foreign-later-clusterrolebinding":
				kind := "RoleBinding"
				if scenario == "foreign-later-clusterrolebinding" {
					kind = "ClusterRoleBinding"
				}
				for _, resource := range v.f.plan.Resources() {
					key := resourceKey(resource)
					if key.Kind == kind {
						v.f.access.objects[key] = &unstructured.Unstructured{Object: map[string]any{"apiVersion": key.APIVersion, "kind": kind, "metadata": map[string]any{"name": key.Name, "namespace": key.Namespace, "uid": "foreign", "resourceVersion": "1"}}}
						break
					}
				}
			}
			writes, nsWrites := v.f.access.writes, v.f.nsUpdates
			next, err := v.l.Step(context.Background(), s, v.opts)
			if err == nil || next == nil || !bytes.Equal(next.Bytes(), s.Bytes()) || v.f.access.writes != writes || v.f.nsUpdates != nsWrites || strings.Contains(err.Error(), "CANARY") {
				t.Fatal("unproved bootstrap changed state, adopted access or exposed detail")
			}
		})
	}
}

func TestBootstrapAdmissionResumeRechecksGateAndKeepsFullBoundary(t *testing.T) {
	v, s := bootstrapReadyFixture(t)
	v.fail = 0
	s = v.step(t, s) // one original signed ClusterRole
	v.fail = BootstrapAdmission
	l, err := NewLifecycleWithChecks(v.f.engine, v.l.secrets, v)
	if err != nil {
		t.Fatal(err)
	}
	v.l = l
	writes := v.f.access.writes
	next, err := v.l.Step(context.Background(), s, v.opts)
	if !errors.Is(err, ErrLifecycle) || !bytes.Equal(next.Bytes(), s.Bytes()) || v.f.access.writes != writes {
		t.Fatal("partial RBAC resume bypassed fresh bootstrap proof")
	}
	v.fail = AdmissionEffective
	for i := 0; i < 100; i++ {
		next, err = v.l.Step(context.Background(), s, v.opts)
		s = next
		if err != nil {
			if !errors.Is(err, ErrLifecycle) {
				t.Fatal(err)
			}
			break
		}
	}
	for _, resource := range v.f.plan.Resources() {
		key := resourceKey(resource)
		r, _ := v.f.engine.inventory(s.Document(), key)
		if bootstrapRBACKey(key) && r == nil || (key.Kind == "Deployment" || key.Kind == "Service") && r != nil {
			t.Fatal("bootstrap did not remain restricted to signed RBAC")
		}
	}
	if len(v.private.objects) != 0 || !slices.Contains(v.checks, BootstrapAdmission) {
		t.Fatal("bootstrap created credentials or skipped its separate proof")
	}
}

func TestBootstrapAdmissionPendingRBACRecoveryObservesWithoutReplay(t *testing.T) {
	t.Run("acknowledged-original-uid", func(t *testing.T) { testBootstrapPendingRBAC(t, false) })
	t.Run("lost-response-no-original-uid", func(t *testing.T) { testBootstrapPendingRBAC(t, true) })
}

func testBootstrapPendingRBAC(t *testing.T, loseResponse bool) {
	t.Helper()
	v, s := bootstrapReadyFixture(t)
	v.fail = 0
	originalWrite := v.f.access.write
	failReadback := false
	v.f.access.write = func(action installstate.Action, key installstate.Key, object *unstructured.Unstructured) (*unstructured.Unstructured, error) {
		result, err := originalWrite(action, key, object)
		if err == nil && bootstrapRBACKey(key) {
			failReadback = true
			if loseResponse {
				return nil, errors.New("lost acknowledgement")
			}
		}
		return result, err
	}
	v.f.access.get = func(key installstate.Key) error {
		if failReadback && bootstrapRBACKey(key) {
			failReadback = false
			return ErrRead // block immediate correlation of the lost response
		}
		return nil
	}
	next, err := v.l.Step(context.Background(), s, v.opts)
	if !errors.Is(err, ErrOutcomeUnknown) || next.Document().Pending == nil || !bootstrapRBACKey(next.Document().Pending.Key) {
		t.Fatal("no original pending RBAC create")
	}
	s = next
	if _, err := v.f.engine.bootstrapAccess(context.Background(), s); err == nil {
		t.Fatal("pending effect authorized new bootstrap proof")
	}
	v.fail = BootstrapAdmission
	writes := v.f.access.writes
	if loseResponse {
		// Neither an acknowledgement nor the original invocation's immediate
		// readback pinned a UID. A later matching nonce is not original identity.
		checks := len(v.checks)
		next, err = v.l.Step(context.Background(), s, v.opts)
		if !errors.Is(err, ErrOutcomeUnknown) || next.Document().Pending == nil || !bytes.Equal(next.Bytes(), s.Bytes()) || v.f.access.writes != writes || len(v.checks) != checks {
			t.Fatal("unknown original UID was adopted, replayed or bypassed proof")
		}
		return
	}
	s = v.step(t, s) // observation-only settlement, not a second effect
	if s.Document().Pending != nil || v.f.access.writes != writes {
		t.Fatal("pending RBAC was replayed")
	}
	next, err = v.l.Step(context.Background(), s, v.opts)
	if !errors.Is(err, ErrLifecycle) || !bytes.Equal(next.Bytes(), s.Bytes()) || v.f.access.writes != writes {
		t.Fatal("settled RBAC recovery bypassed the next bootstrap gate")
	}
}

func bootstrapEmptyRuntime() (*installsafety.Snapshot, *installsafety.RuntimeSnapshot) {
	m := metav1.ListMeta{ResourceVersion: "1"}
	return &installsafety.Snapshot{Pods: &corev1.PodList{ListMeta: m}, Jobs: &batchv1.JobList{ListMeta: m}}, &installsafety.RuntimeSnapshot{
		Deployments: &appsv1.DeploymentList{ListMeta: m}, ReplicaSets: &appsv1.ReplicaSetList{ListMeta: m}, StatefulSets: &appsv1.StatefulSetList{ListMeta: m}, DaemonSets: &appsv1.DaemonSetList{ListMeta: m}, ReplicationControllers: &corev1.ReplicationControllerList{ListMeta: m}, CronJobs: &batchv1.CronJobList{ListMeta: m}, EndpointSlices: &discoveryv1.EndpointSliceList{ListMeta: m},
	}
}

func TestBootstrapAdmissionRuntimeRequiresWholeEmptyCollections(t *testing.T) {
	for _, kind := range []string{"empty", "Pod", "Job", "Deployment", "ReplicaSet", "StatefulSet", "DaemonSet", "ReplicationController", "CronJob", "EndpointSlice", "nil", "partial", "remaining", "no-rv"} {
		t.Run(kind, func(t *testing.T) {
			s, r := bootstrapEmptyRuntime()
			switch kind {
			case "Pod":
				s.Pods.Items = []corev1.Pod{{Status: corev1.PodStatus{Phase: corev1.PodSucceeded}}}
			case "Job":
				s.Jobs.Items = []batchv1.Job{{Spec: batchv1.JobSpec{Suspend: ptr.To(true)}}}
			case "Deployment":
				r.Deployments.Items = []appsv1.Deployment{{}}
			case "ReplicaSet":
				r.ReplicaSets.Items = []appsv1.ReplicaSet{{}}
			case "StatefulSet":
				r.StatefulSets.Items = []appsv1.StatefulSet{{}}
			case "DaemonSet":
				r.DaemonSets.Items = []appsv1.DaemonSet{{}}
			case "ReplicationController":
				r.ReplicationControllers.Items = []corev1.ReplicationController{{}}
			case "CronJob":
				r.CronJobs.Items = []batchv1.CronJob{{}}
			case "EndpointSlice":
				r.EndpointSlices.Items = []discoveryv1.EndpointSlice{{}}
			case "nil":
				r.CronJobs = nil
			case "partial":
				r.Deployments.Continue = "next"
			case "remaining":
				s.Pods.RemainingItemCount = ptr.To[int64](1)
			case "no-rv":
				s.Jobs.ResourceVersion = ""
			}
			if bootstrapRuntimeAbsent(s, r) != (kind == "empty") {
				t.Fatal("nonempty/partial bootstrap runtime accepted")
			}
		})
	}
	if bootstrapRuntimeAbsent(nil, nil) {
		t.Fatal("nil observation proved absence")
	}
}

func TestBootstrapAdmissionCredentialsDistinguishFreshAndRetainingReinstall(t *testing.T) {
	d := installstate.Document{Namespace: "isolated"}
	s := &installsafety.Snapshot{Secrets: &metav1.PartialObjectMetadataList{ListMeta: metav1.ListMeta{ResourceVersion: "1"}}}
	if !bootstrapCredentials(d, s) {
		t.Fatal("fresh absence refused")
	}
	for _, name := range []string{adminauth.CredentialSecretName, "arcadectl-api-tls"} {
		d.Resources = append(d.Resources, installstate.Resource{Key: secretKey(d.Namespace, name), UID: types.UID("original-" + name), Retained: true})
		s.Secrets.Items = append(s.Secrets.Items, metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: d.Namespace, UID: types.UID("original-" + name), ResourceVersion: "1"}})
	}
	if bootstrapCredentials(d, s) {
		t.Fatal("fresh credential collision accepted")
	}
	d.ActivePackage = "original"
	if !bootstrapCredentials(d, s) {
		t.Fatal("exact retained original credentials refused")
	}
	s.Secrets.Items[0].UID = "replacement"
	if bootstrapCredentials(d, s) {
		t.Fatal("recreated retained credential accepted")
	}
}

// Actual closed HTTP clients, journal and sealed observer, with fixture policy
// responses. This does not certify native evaluation, kubelet or the installer.
func TestBootstrapAdmissionClosedProviderBracketsWholeObservationAndProbes(t *testing.T) {
	v, s := bootstrapReadyFixture(t)
	v.fail = 0
	s = v.step(t, s) // include one already recorded original RBAC object
	namespace, err := v.f.access.client.CoreV1().Namespaces().Get(context.Background(), s.Anchor().Namespace, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	probes := 0
	runtimePresent := false
	accountRace := false
	rbacRace := false
	runtimeRace := false
	access := quiescenceServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			probes++
			if r.URL.RawQuery != "dryRun=All&fieldManager=arcadectl-installer&fieldValidation=Strict" {
				t.Error("bootstrap probe was persistent or nonstrict")
			}
			var object unstructured.Unstructured
			if json.NewDecoder(r.Body).Decode(&object.Object) != nil {
				t.Error("bad fixture probe")
				return
			}
			name := strings.TrimPrefix(object.GetName(), "restore-")
			for key, live := range v.f.access.objects {
				if key.Kind != "ValidatingAdmissionPolicy" {
					continue
				}
				positive, negative, index, err := admissionCreateProbe(v.f.plan, key.Name, "arcadectl-controller", name)
				if err != nil {
					t.Error(err)
					return
				}
				// Round-trip the independent recipe through the same JSON numeric
				// representation as this HTTP fixture's decoded request.
				matches := func(candidate *unstructured.Unstructured) bool {
					body, _ := json.Marshal(candidate.Object)
					var expected map[string]any
					_ = json.Unmarshal(body, &expected)
					return reflect.DeepEqual(expected, object.Object)
				}
				if matches(positive) {
					w.WriteHeader(201)
					_ = json.NewEncoder(w).Encode(probeResultFixture(t, positive, time.Now().UTC()).Object)
				} else if matches(negative) {
					var policy admissionv1.ValidatingAdmissionPolicy
					_ = decodeServing(live, &policy)
					binding := ""
					for bindingKey, value := range v.f.access.objects {
						if bindingKey.Kind == "ValidatingAdmissionPolicyBinding" {
							policyName, _, _ := unstructured.NestedString(value.Object, "spec", "policyName")
							if policyName == key.Name {
								binding = bindingKey.Name
							}
						}
					}
					probeKey := resourceKeyFromObject(&object)
					_, plural, _ := probePath(probeKey)
					denial, err := expectedProbeDenial(probeKey, plural, key.Name, binding, policy.Spec.Validations[index].Message)
					if err != nil {
						t.Error(err)
					}
					w.WriteHeader(422)
					_ = json.NewEncoder(w).Encode(denial)
				} else {
					continue
				}
				if accountRace {
					for accountKey, value := range v.f.access.objects {
						if accountKey.Kind == "ServiceAccount" && accountKey.Name != "arcadectl-controller" {
							value.SetResourceVersion("changed")
							break
						}
					}
				}
				if rbacRace {
					for recordedKey, value := range v.f.access.objects {
						if bootstrapRBACKey(recordedKey) {
							value.SetResourceVersion("changed-rbac")
							break
						}
					}
				}
				if runtimeRace {
					runtimePresent = true
				}
				return
			}
			t.Error("unknown fixture probe")
			w.WriteHeader(500)
			return
		}
		if r.Method != http.MethodGet {
			t.Error("unexpected bootstrap effect")
			w.WriteHeader(403)
			return
		}
		if serveBootstrapObservationFixture(t, w, r, v, namespace, runtimePresent) {
			return
		}
		w.WriteHeader(404)
		_ = json.NewEncoder(w).Encode(metav1.Status{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: metav1.StatusFailure, Reason: metav1.StatusReasonNotFound, Code: 404})
	})
	store, err := installstate.New(access.Namespaces(), v.f.plan)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewWithAccess(access, store, v.f.engine.files, v.f.plan)
	if err != nil {
		t.Fatal(err)
	}
	a, err := NewClusterAdmission(engine, access)
	if err != nil {
		t.Fatal(err)
	}
	input, err := store.Load(context.Background(), s.Anchor())
	if err != nil {
		t.Fatal(err)
	}
	request := LifecycleCheck{Checkpoint: BootstrapAdmission, Snapshot: input, Mode: installstate.Install, Target: v.f.plan, Options: v.opts}
	if err := a.VerifyBootstrap(context.Background(), request); err != nil || probes != 12 {
		t.Fatal("closed bootstrap proof refused healthy original state", err, probes)
	}
	if a.VerifyCreateProbes(context.Background(), request) != ErrInvalid {
		t.Fatal("bootstrap substituted for full actor proof entrypoint")
	}
	runtimePresent = true
	before := probes
	if a.VerifyBootstrap(context.Background(), request) != ErrAdmission || probes != before {
		t.Fatal("runtime present during bootstrap was probed or accepted")
	}
	runtimePresent = false
	accountRace = true
	if a.VerifyBootstrap(context.Background(), request) != ErrAdmission {
		t.Fatal("non-controller original account race during probes accepted")
	}
	accountRace = false
	rbacRace = true
	if a.VerifyBootstrap(context.Background(), request) != ErrAdmission {
		t.Fatal("original RBAC version race during probes accepted")
	}
	rbacRace = false
	runtimeRace = true
	if a.VerifyBootstrap(context.Background(), request) != ErrAdmission {
		t.Fatal("workload appearing after initial observation accepted")
	}
}

func resourceKeyFromObject(object *unstructured.Unstructured) installstate.Key {
	return installstate.Key{APIVersion: object.GetAPIVersion(), Kind: object.GetKind(), Namespace: object.GetNamespace(), Name: object.GetName()}
}

func serveBootstrapObservationFixture(t *testing.T, w http.ResponseWriter, r *http.Request, v *lifecycleFixture, namespace *corev1.Namespace, runtimePresent bool) bool {
	t.Helper()
	for _, gv := range proofGroups {
		path := "/apis/" + gv
		if gv == "v1" {
			path = "/api/v1"
		}
		if r.URL.Path != path {
			continue
		}
		resources := []metav1.APIResource{}
		seen := map[string]bool{}
		add := func(kind, plural string, namespaced bool) {
			if !seen[plural] {
				resources = append(resources, metav1.APIResource{Name: plural, Kind: kind, Namespaced: namespaced, Verbs: metav1.Verbs{"get", "list"}})
				seen[plural] = true
			}
		}
		for _, resource := range v.f.plan.Resources() {
			key := resourceKey(resource)
			if key.APIVersion == gv {
				collection, _ := resourcePath(key, true)
				add(key.Kind, collection[strings.LastIndex(collection, "/")+1:], key.Namespace != "")
			}
		}
		for _, collection := range proofCollections {
			if collection.gv == gv {
				add(collection.kind, collection.plural, collection.namespaced)
			}
		}
		_ = json.NewEncoder(w).Encode(metav1.APIResourceList{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "APIResourceList"}, GroupVersion: gv, APIResources: resources})
		return true
	}
	if r.URL.Path == "/api/v1/namespaces/"+namespace.Name {
		n := namespace.DeepCopy()
		n.APIVersion, n.Kind = "v1", "Namespace"
		encodeStoppedObject(t, w, r, servingObject(t, n))
		return true
	}
	for _, collection := range proofCollections {
		path := "/apis/" + collection.gv
		if collection.gv == "v1" {
			path = "/api/v1"
		}
		if collection.namespaced {
			path += "/namespaces/" + namespace.Name
		}
		path += "/" + collection.plural
		if r.URL.Path != path {
			continue
		}
		items := []any{}
		for key, object := range v.f.access.objects {
			if key.Kind == collection.kind {
				items = append(items, object.DeepCopy().Object)
			}
		}
		if runtimePresent && collection.kind == "Pod" {
			items = append(items, map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": "foreign", "namespace": namespace.Name, "uid": "foreign-pod", "resourceVersion": "1"}, "spec": map[string]any{"containers": []any{map[string]any{"name": "foreign", "image": "foreign"}}}})
		}
		gv, kind := collection.gv, collection.kind+"List"
		if collection.kind == "Secret" {
			gv, kind = "meta.k8s.io/v1", "PartialObjectMetadataList"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"apiVersion": gv, "kind": kind, "metadata": map[string]any{"resourceVersion": "100"}, "items": items})
		return true
	}
	for key, object := range v.f.access.objects {
		path, err := resourcePath(key, false)
		if err == nil && path == r.URL.Path {
			encodeStoppedObject(t, w, r, object.DeepCopy())
			return true
		}
	}
	return false
}
