// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// General observer fixtures support non-direct clients. The complete lifecycle
// requires explicit direct routing; derive it through the real constructor,
// never by changing provenance fields or bypassing its guard.
func convergenceDirectAccess(t *testing.T, access *HTTPAccess) *HTTPAccess {
	t.Helper()
	direct, err := NewDirectHTTPAccess(access.frozen)
	if err != nil {
		t.Fatal(err)
	}
	return direct
}

// Actual strict observer and original HTTP journal, not a permissive callback.
// The fake server already refuses writes; only native tests prove kubelet timing.
func TestLifecycleConvergenceControllersWaitWithoutEffects(t *testing.T) {
	for _, fault := range []string{"delayed-ready", "journal-changed", "foreign-original", "invalid-checkpoint"} {
		t.Run(fault, func(t *testing.T) {
			plan := fixturePlan(t)
			v, ns, lists := readyControllerFixture(t, plan)
			objects := map[installstate.Key]*unstructured.Unstructured{}
			for key, object := range v.f.access.objects {
				objects[key] = object.DeepCopy()
			}
			for name, secret := range v.secrets.objects {
				objects[secretKey(ns.Name, name)] = servingObject(t, secret)
			}
			pods := lists["Pod"].(*corev1.PodList)
			ready := pods.Items[0].DeepCopy()
			if fault == "delayed-ready" || fault == "journal-changed" {
				pods.Items[0].Status.Phase = corev1.PodPending
			}
			access, observations := controllerProofAccess(t, ns, objects, lists, func(n int) {
				if n == 2 {
					if fault == "delayed-ready" {
						pods.Items[0] = *ready.DeepCopy()
					} else if fault == "journal-changed" {
						ns.ResourceVersion = "999"
					}
				}
			}, "")
			if fault == "foreign-original" {
				key := deploymentKey(ns.Name, controllerFamilies[0])
				objects[key].SetUID("foreign-original")
			}
			access = convergenceDirectAccess(t, access)
			store, err := installstate.New(access.Namespaces(), plan)
			if err != nil {
				t.Fatal(err)
			}
			engine, err := NewWithAccess(access, store, v.f.engine.files, plan)
			if err != nil {
				t.Fatal(err)
			}
			lifecycle, err := NewClusterLifecycle(engine, access)
			if err != nil {
				t.Fatal("closed production lifecycle unavailable")
			}
			s, err := store.Load(t.Context(), v.f.snapshot.Anchor())
			if err != nil {
				t.Fatal(err)
			}
			request := LifecycleCheck{Checkpoint: ControllersAvailable, Snapshot: s, Mode: s.Document().Mode, Target: plan, Options: LifecycleOptions{Now: time.Now().UTC()}}
			writes := v.f.access.writes
			if fault == "invalid-checkpoint" {
				request.Checkpoint = AdmissionEffective
			}
			ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
			defer cancel()
			start := time.Now()
			err = lifecycle.checks.(*clusterLifecycleChecks).waitObserved(ctx, request)
			if fault == "delayed-ready" {
				if err != nil || observations() < 3 || time.Since(start) < time.Second {
					t.Fatal("observational convergence failed or skipped complete repeated proof", err)
				}
			} else if fault == "invalid-checkpoint" {
				if err != ErrInvalid || observations() != 0 {
					t.Fatal("wait accepted a behavioral/effect checkpoint")
				}
			} else if err != ErrControllers || observations() == 0 {
				t.Fatal("invalid original or changed journal became readiness")
			}
			if fresh, err := store.Load(t.Context(), s.Anchor()); err != nil || !bytes.Equal(fresh.Bytes(), s.Bytes()) || v.f.access.writes != writes {
				t.Fatal("convergence changed journal or performed an effect")
			}
		})
	}
}

func TestLifecycleConvergenceShutdownWaitsForActualOriginalAbsence(t *testing.T) {
	for _, checkpoint := range []Checkpoint{APIStopped, RuntimeStopped} {
		t.Run(map[Checkpoint]string{APIStopped: "api", RuntimeStopped: "runtime"}[checkpoint], func(t *testing.T) {
			v, ns, lists := stoppedFixture(t)
			objects := map[installstate.Key]*unstructured.Unstructured{}
			for key, object := range v.f.access.objects {
				objects[key] = object.DeepCopy()
			}
			for name, secret := range v.secrets.objects {
				objects[secretKey(ns.Name, name)] = servingObject(t, secret)
			}
			// A deleted Deployment does not yet prove its actual original Pod
			// is gone. Simulate asynchronous native foreground/Pod convergence.
			pods := &corev1.PodList{Items: []corev1.Pod{*v.access.pod.DeepCopy()}}
			lists["Pod"] = pods
			access, observations := controllerProofAccess(t, ns, objects, lists, func(n int) {
				if n == 2 {
					pods.Items = nil
				}
			}, "")
			access = convergenceDirectAccess(t, access)
			store, err := installstate.New(access.Namespaces(), v.f.plan)
			if err != nil {
				t.Fatal(err)
			}
			engine, err := NewWithAccess(access, store, v.f.engine.files, v.f.plan)
			if err != nil {
				t.Fatal(err)
			}
			lifecycle, err := NewClusterLifecycle(engine, access)
			if err != nil {
				t.Fatal(err)
			}
			s, err := store.Load(t.Context(), v.f.snapshot.Anchor())
			if err != nil {
				t.Fatal(err)
			}
			request := LifecycleCheck{Checkpoint: checkpoint, Snapshot: s, Mode: s.Document().Mode, Target: v.f.plan, Options: LifecycleOptions{Now: time.Now().UTC()}}
			ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
			defer cancel()
			writes := v.f.access.writes
			start := time.Now()
			if lifecycle.checks.Check(ctx, request) != nil || observations() < 3 || time.Since(start) < time.Second {
				t.Fatal("shutdown did not wait for actual original Pod absence")
			}
			fresh, err := store.Load(t.Context(), s.Anchor())
			if err != nil || !bytes.Equal(fresh.Bytes(), s.Bytes()) || fresh.ResourceVersion() != s.ResourceVersion() || v.f.access.writes != writes {
				t.Fatal("shutdown convergence changed original journal/effects")
			}
		})
	}
}

func TestLifecycleConvergenceCRDsWaitForEstablishedOriginals(t *testing.T) {
	plan := fixturePlan(t)
	v, ns, _ := readyControllerFixture(t, plan)
	var crds []installstate.Key
	discovery := metav1.APIResourceList{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "APIResourceList"}, GroupVersion: "arcade.gobha.me/v1alpha1"}
	for _, resource := range plan.ResourceMetadata() {
		key := installstate.Key{APIVersion: resource.APIVersion, Kind: resource.Kind, Namespace: resource.Namespace, Name: resource.Name}
		if key.Kind != "CustomResourceDefinition" {
			continue
		}
		crds = append(crds, key)
		object := v.f.access.objects[key]
		// Serving fixtures need only signed CRD addresses. This test observes
		// their establishment too, so supply the native healthy status used by
		// the existing CRD contract tests before delaying one establishment.
		object.SetGeneration(1)
		if _, found, err := unstructured.NestedMap(object.Object, "spec", "conversion"); err != nil {
			t.Fatal("signed CRD conversion unavailable")
		} else if !found {
			if unstructured.SetNestedMap(object.Object, map[string]any{"strategy": "None"}, "spec", "conversion") != nil {
				t.Fatal("native default conversion fixture unavailable")
			}
		}
		names, found, err := unstructured.NestedMap(object.Object, "spec", "names")
		if err != nil || !found {
			t.Fatal("signed CRD names unavailable")
		}
		object.Object["status"] = map[string]any{"acceptedNames": names, "storedVersions": []any{"v1alpha1"}, "conditions": []any{map[string]any{"type": "Established", "status": "True"}, map[string]any{"type": "NamesAccepted", "status": "True"}}}
		template, err := v.f.engine.contracts[plan.Digest()].Template(key, false)
		if err != nil || template.CheckCRD(object, object.GetUID(), template) != nil {
			t.Fatal("baseline original CRD fixture does not satisfy its strict contract")
		}
		plural, _, _ := unstructured.NestedString(object.Object, "spec", "names", "plural")
		kind, _, _ := unstructured.NestedString(object.Object, "spec", "names", "kind")
		discovery.APIResources = append(discovery.APIResources, metav1.APIResource{Name: plural, Kind: kind, Namespaced: true, Verbs: metav1.Verbs{"get", "list", "create"}})
	}
	if len(crds) != 5 {
		t.Fatal("signed original CRD catalogue incomplete")
	}
	var firstReads atomic.Int32
	access := proofServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Error("CRD convergence attempted an effect")
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/version":
			_ = json.NewEncoder(w).Encode(map[string]string{"major": "1", "minor": "35", "gitVersion": "v1.35.8"})
			return
		case "/api/v1/namespaces/" + ns.Name:
			copy := ns.DeepCopy()
			copy.APIVersion, copy.Kind = "v1", "Namespace"
			_ = json.NewEncoder(w).Encode(copy)
			return
		case "/apis/arcade.gobha.me/v1alpha1":
			_ = json.NewEncoder(w).Encode(discovery)
			return
		}
		for _, key := range crds {
			path, _ := resourcePath(key, false)
			if r.URL.Path == path {
				copy := v.f.access.objects[key].DeepCopy()
				if key == crds[0] && firstReads.Add(1) == 1 {
					unstructured.RemoveNestedField(copy.Object, "status", "conditions")
				}
				_ = json.NewEncoder(w).Encode(copy.Object)
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	})
	access = convergenceDirectAccess(t, access)
	store, err := installstate.New(access.Namespaces(), plan)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewWithAccess(access, store, v.f.engine.files, plan)
	if err != nil {
		t.Fatal(err)
	}
	lifecycle, err := NewClusterLifecycle(engine, access)
	if err != nil {
		t.Fatal(err)
	}
	s, err := store.Load(t.Context(), v.f.snapshot.Anchor())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
	defer cancel()
	request := LifecycleCheck{Checkpoint: CRDsAvailable, Snapshot: s, Mode: s.Document().Mode, Target: plan, Options: LifecycleOptions{Now: time.Now().UTC()}}
	if err := lifecycle.checks.Check(ctx, request); err != nil || firstReads.Load() < 3 {
		t.Fatal("CRD convergence skipped establishment or exact repeated original reads", err, firstReads.Load())
	}
	fresh, err := store.Load(t.Context(), s.Anchor())
	if err != nil || !bytes.Equal(fresh.Bytes(), s.Bytes()) || fresh.ResourceVersion() != s.ResourceVersion() {
		t.Fatal("CRD convergence changed original journal")
	}
}

func TestLifecycleConvergenceServingBeforeSingleAuthentication(t *testing.T) {
	for _, mode := range []string{"success", "fingerprint-changed", "foreign-pod", "journal-changed", "invalid-stage", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			x := newServingFixture(t)
			requests := activationServer(t, x, x.f.plan.Namespace(), nil)
			change := false
			start := time.Now()
			var changedAt atomic.Int64
			var podReads atomic.Int32
			c, request, posts := closedTargetFixtureObserved(t, x, mode, nil, func(ns *corev1.Namespace) {
				if change {
					ns.ResourceVersion = "999"
				}
				if mode == "fingerprint-changed" && time.Since(start) >= 2*time.Second && changedAt.CompareAndSwap(0, time.Now().UnixNano()) {
					x.access.pod.ResourceVersion = "999"
				}
			}, func(path string) {
				if path == "/api/v1/namespaces/"+x.f.plan.Namespace()+"/pods/"+x.access.pod.Name {
					podReads.Add(1)
				}
			})
			if mode == "invalid-stage" {
				request.Mode = installstate.Uninstall
			}
			// Rebind both journal and engine to the real direct client. The
			// shared forwarding fixture remains unchanged for its other tests.
			access := convergenceDirectAccess(t, c.prerequisites.access)
			plans := make([]*installrender.Plan, 0, len(c.prerequisites.engine.plans))
			for _, plan := range c.prerequisites.engine.plans {
				plans = append(plans, plan)
			}
			store, err := installstate.New(access.Namespaces(), plans...)
			if err != nil {
				t.Fatal(err)
			}
			engine, err := NewWithAccess(access, store, c.prerequisites.engine.files, plans...)
			if err != nil {
				t.Fatal(err)
			}
			request.Snapshot, err = store.Load(t.Context(), request.Snapshot.Anchor())
			if err != nil {
				t.Fatal(err)
			}
			lifecycle, err := NewClusterLifecycle(engine, access)
			if err != nil {
				t.Fatal("closed production lifecycle unavailable")
			}
			checks := lifecycle.checks.(*clusterLifecycleChecks)
			budget := 11 * time.Second
			if mode == "foreign-pod" {
				budget = 2 * time.Second
			}
			ctx, cancel := context.WithTimeout(t.Context(), budget)
			defer cancel()
			if mode == "cancelled" {
				cancel() // parent cancellation cannot proceed to authentication
			}
			if mode == "journal-changed" {
				change = true
			}
			if mode == "success" || mode == "fingerprint-changed" {
				if checks.Check(ctx, request) != nil || time.Since(start) < 5*time.Second || posts.Load() != 1 || requests.Load() != 1 {
					t.Fatal("production composition skipped convergence or single authentication")
				}
				if mode == "fingerprint-changed" && (changedAt.Load() == 0 || time.Since(time.Unix(0, changedAt.Load())) < 5*time.Second) {
					t.Fatal("changed serving fingerprint did not reset the quiet interval")
				}
				return
			}
			err = checks.waitServing(ctx, request)
			if posts.Load() != 0 || requests.Load() != 0 {
				t.Fatal("serving convergence opened a forward or authenticated")
			}
			if err == nil || mode == "invalid-stage" && err != ErrInvalid || mode != "invalid-stage" && err != ErrActivation {
				t.Fatal("invalid/cancelled original became serving or lost refusal boundary")
			}
			if mode == "foreign-pod" && podReads.Load() == 0 {
				t.Fatal("foreign-Pod test did not reach its actual named GET")
			}
		})
	}
}

func TestLifecycleConvergenceAdmissionWaitsForOriginalPolicyStatus(t *testing.T) {
	for _, mode := range []string{"delayed-typechecking", "foreign-policy", "journal-changed"} {
		t.Run(mode, func(t *testing.T) {
			v := newLifecycleFixture(t)
			v.fail = AdmissionConfigured
			s := v.f.snapshot
			stopped := false
			for step := 0; step < 100; step++ {
				next, err := v.l.Step(t.Context(), s, v.opts)
				s = next
				if err != nil {
					if !errors.Is(err, ErrLifecycle) {
						t.Fatal(err)
					}
					stopped = true
					break
				}
			}
			if !stopped {
				t.Fatal("fixture did not reach original policy barrier")
			}
			ns, err := v.f.access.client.CoreV1().Namespaces().Get(t.Context(), s.Anchor().Namespace, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			var firstPolicy installstate.Key
			for _, resource := range v.f.plan.ResourceMetadata() {
				if resource.Kind == "ValidatingAdmissionPolicy" {
					firstPolicy = installstate.Key{APIVersion: resource.APIVersion, Kind: resource.Kind, Name: resource.Name}
					break
				}
			}
			if firstPolicy.Name == "" {
				t.Fatal("signed policy catalogue unavailable")
			}
			var policyReads atomic.Int32
			access := convergenceDirectAccess(t, proofServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.RawQuery != "" {
					t.Error("policy convergence attempted an effect or filtered read")
				}
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path == "/api/v1/namespaces/"+ns.Name {
					copy := ns.DeepCopy()
					copy.APIVersion, copy.Kind = "v1", "Namespace"
					if mode == "journal-changed" && policyReads.Load() > 0 {
						copy.ResourceVersion = "999"
					}
					_ = json.NewEncoder(w).Encode(copy)
					return
				}
				for key, object := range v.f.access.objects {
					path, err := resourcePath(key, false)
					if err != nil || r.URL.Path != path {
						continue
					}
					copy := object.DeepCopy()
					if key == firstPolicy {
						n := policyReads.Add(1)
						if mode == "delayed-typechecking" && n == 1 {
							unstructured.RemoveNestedField(copy.Object, "status", "typeChecking")
						} else if mode == "foreign-policy" {
							copy.SetUID("foreign-policy")
						}
					}
					_ = json.NewEncoder(w).Encode(copy.Object)
					return
				}
				w.WriteHeader(http.StatusNotFound)
			}))
			store, err := installstate.New(access.Namespaces(), v.f.plan)
			if err != nil {
				t.Fatal(err)
			}
			engine, err := NewWithAccess(access, store, v.f.engine.files, v.f.plan)
			if err != nil {
				t.Fatal(err)
			}
			lifecycle, err := NewClusterLifecycle(engine, access)
			if err != nil {
				t.Fatal(err)
			}
			input, err := store.Load(t.Context(), s.Anchor())
			if err != nil {
				t.Fatal(err)
			}
			request := LifecycleCheck{Checkpoint: AdmissionConfigured, Snapshot: input, Mode: input.Document().Mode, Target: v.f.plan, Options: LifecycleOptions{Now: time.Now().UTC()}}
			ctx, cancel := context.WithTimeout(t.Context(), 2500*time.Millisecond)
			defer cancel()
			writes := v.f.access.writes
			started := time.Now()
			err = lifecycle.checks.Check(ctx, request)
			if mode == "delayed-typechecking" {
				if err != nil || policyReads.Load() < 2 || time.Since(started) < time.Second {
					t.Fatal("policy convergence skipped healthy original status", err)
				}
			} else if err != ErrAdmission || policyReads.Load() == 0 {
				t.Fatal("foreign policy or journal drift became configured admission")
			}
			if v.f.access.writes != writes {
				t.Fatal("policy convergence performed an effect")
			}
		})
	}
}
