// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Original signed API and complete native-shaped descendants, not a fabricated
// readiness result. This fixture exposes only observation/authorization reads;
// the tests do not invoke an actor effect or authenticate the administrator.
func initialServingPhaseFixture(t *testing.T, fault string) (*ClusterAdmission, LifecycleCheck, func() int, *atomic.Int64, *atomic.Bool) {
	t.Helper()
	plan := fixturePlan(t)
	v, ns, lists := readyControllerFixture(t, plan)
	d, err := installstate.Decode([]byte(ns.Annotations[installstate.Annotation]), plan)
	if err != nil {
		t.Fatal(err)
	}
	d.Stage = installstate.Verifying
	d.Revision++
	key := deploymentKey(ns.Name, apiFamily)
	template, err := v.f.engine.contracts[plan.Digest()].Template(key, false)
	if err != nil {
		t.Fatal("original signed API template unavailable")
	}
	if fault != "missing-recorded-api" {
		d.Resources = append(d.Resources, installstate.Resource{Key: key, UID: v.deployment.UID, TemplateSHA256: template.Hash(), Phase: installrender.API})
	}
	installstate.SortResources(d.Resources)
	body, err := installstate.Encode(d, plan)
	if err != nil {
		t.Fatal(err)
	}
	ns.Annotations[installstate.Annotation] = string(body)
	objects := maps.Clone(v.f.access.objects)
	objects[key] = servingObject(t, v.deployment)
	for name, secret := range v.secrets.objects {
		objects[secretKey(ns.Name, name)] = servingObject(t, secret)
	}
	policies, bindings := &admissionv1.ValidatingAdmissionPolicyList{}, &admissionv1.ValidatingAdmissionPolicyBindingList{}
	for key, object := range objects {
		object = object.DeepCopy()
		objects[key] = object
		switch key.Kind {
		case "CustomResourceDefinition":
			object.SetGeneration(1)
			if unstructured.SetNestedMap(object.Object, map[string]any{"strategy": "None"}, "spec", "conversion") != nil {
				t.Fatal("original conversion fixture unavailable")
			}
			names, found, err := unstructured.NestedMap(object.Object, "spec", "names")
			if err != nil || !found {
				t.Fatal("original CRD names unavailable")
			}
			object.Object["status"] = map[string]any{"acceptedNames": names, "storedVersions": []any{"v1alpha1"}, "conditions": []any{map[string]any{"type": "Established", "status": "True"}, map[string]any{"type": "NamesAccepted", "status": "True"}}}
		case "ValidatingAdmissionPolicy":
			object.SetGeneration(1)
			object.Object["status"] = map[string]any{"observedGeneration": object.GetGeneration(), "typeChecking": map[string]any{}}
			var policy admissionv1.ValidatingAdmissionPolicy
			if decodeServing(object, &policy) != nil {
				t.Fatal("original policy fixture unavailable")
			}
			policies.Items = append(policies.Items, policy)
		case "ValidatingAdmissionPolicyBinding":
			var binding admissionv1.ValidatingAdmissionPolicyBinding
			if decodeServing(object, &binding) != nil {
				t.Fatal("original binding fixture unavailable")
			}
			bindings.Items = append(bindings.Items, binding)
		}
	}
	lists["ValidatingAdmissionPolicy"], lists["ValidatingAdmissionPolicyBinding"] = policies, bindings
	pods := lists["Pod"].(*corev1.PodList)
	leases := &coordinationv1.LeaseList{}
	for index := range pods.Items {
		leases.Items = append(leases.Items, phaseLeaderFixture(&pods.Items[index], index, time.Now().UTC().Truncate(time.Microsecond)))
	}
	lists["Lease"] = leases
	lists["Deployment"].(*appsv1.DeploymentList).Items = append(lists["Deployment"].(*appsv1.DeploymentList).Items, *v.deployment.DeepCopy())
	lists["ReplicaSet"].(*appsv1.ReplicaSetList).Items = append(lists["ReplicaSet"].(*appsv1.ReplicaSetList).Items, *v.access.rs.DeepCopy())
	ready := v.access.pod.DeepCopy()
	pod := ready.DeepCopy()
	if fault == "delayed-ready" {
		pod.Status.Phase = corev1.PodPending
	} else if fault == "foreign-pod" {
		pod.UID = "foreign-pod"
	} else if fault == "foreign-owner" {
		pod.OwnerReferences[0].UID = "foreign-parent"
	}
	apiPodIndex := len(pods.Items)
	pods.Items = append(pods.Items, *pod)
	podKey := installstate.Key{APIVersion: "v1", Kind: "Pod", Namespace: ns.Name, Name: pod.Name}
	setKey := installstate.Key{APIVersion: "apps/v1", Kind: "ReplicaSet", Namespace: ns.Name, Name: v.access.rs.Name}
	objects[podKey], objects[setKey] = servingObject(t, pod), servingObject(t, v.access.rs)
	lists["EndpointSlice"] = v.access.list.DeepCopy()
	var reads atomic.Int32
	changedAt := new(atomic.Int64)
	drift := new(atomic.Bool)
	var injectedWAL atomic.Bool
	access, _ := controllerProofAccessWithRequests(t, ns, objects, lists, nil, "", func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method != http.MethodGet {
			t.Error("initial serving convergence attempted mutation or authentication")
		}
		if strings.Contains(r.URL.Path, "/secrets/") && !strings.Contains(r.Header.Get("Accept"), "PartialObjectMetadata") {
			t.Error("initial convergence requested Secret data")
		}
		if !injectedWAL.Load() && fault != "post-seal-api-drift" {
			if _, _, err := v.f.engine.files.Read(fixtureLedgerName(v.f.snapshot), fixtureLedgerMaxBytes); !errors.Is(err, privatefs.ErrNotFound) {
				t.Error("convergence prepared a fixture WAL before the complete proof")
			}
		}
		if drift.CompareAndSwap(true, false) {
			fresh := ready.DeepCopy()
			fresh.ResourceVersion = "13"
			objects[podKey], pods.Items[apiPodIndex] = servingObject(t, fresh), *fresh
		}
		if r.URL.Path == "/apis/apps/v1/namespaces/"+ns.Name+"/replicasets/"+v.access.rs.Name {
			encodeStoppedObject(t, w, r, objects[setKey].DeepCopy())
			return true
		}
		if r.URL.Path != "/api/v1/namespaces/"+ns.Name+"/pods/"+pod.Name {
			return false
		}
		namedRead := reads.Add(1)
		if fault == "late-wal" && namedRead == 1 {
			if _, err := v.f.engine.files.CreateExclusive(fixtureLedgerName(v.f.snapshot), []byte("uncertain fixture run")); err != nil {
				t.Error("unable to inject late fixture WAL", err)
			}
			injectedWAL.Store(true)
		}
		if fault == "journal-changed" {
			ns.ResourceVersion = "999"
		}
		if fault == "delayed-ready" && namedRead == 2 || fault == "fingerprint-changed" && namedRead == 3 {
			fresh := ready.DeepCopy()
			fresh.ResourceVersion = "12"
			objects[podKey], pods.Items[apiPodIndex] = servingObject(t, fresh), *fresh
			changedAt.Store(time.Now().UnixNano())
		}
		encodeStoppedObject(t, w, r, objects[podKey].DeepCopy())
		return true
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
	a, err := NewClusterAdmission(engine, access)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.Load(t.Context(), v.f.snapshot.Anchor())
	if err != nil {
		t.Fatal(err)
	}
	request := LifecycleCheck{Checkpoint: AdmissionEffective, Snapshot: snapshot, Mode: d.Mode, Target: plan, Options: LifecycleOptions{Now: time.Now().UTC()}}
	return a, request, func() int { return int(reads.Load()) }, changedAt, drift
}

func TestAdmissionInitialServingConvergenceBeforeWAL(t *testing.T) {
	for _, fault := range []string{"healthy", "delayed-ready", "fingerprint-changed", "foreign-pod", "foreign-owner", "journal-changed", "late-wal", "missing-recorded-api", "cancelled"} {
		t.Run(fault, func(t *testing.T) {
			a, request, reads, changedAt, _ := initialServingPhaseFixture(t, fault)
			budget := 12 * time.Second
			wantSuccess := slices.Contains([]string{"healthy", "delayed-ready", "fingerprint-changed"}, fault)
			if !wantSuccess {
				budget = 2 * time.Second
			}
			ctx, cancel := context.WithTimeout(t.Context(), budget)
			defer cancel()
			if fault == "cancelled" {
				cancel()
			}
			start := time.Now()
			initial, err := a.waitInitialPhase(ctx, request)
			if wantSuccess {
				if err != nil || initial == nil || reads() < 6 || time.Since(start) < 5*time.Second {
					t.Fatal("initial admission sealed before complete original serving convergence", err, reads())
				}
				if fault != "healthy" && (changedAt.Load() == 0 || time.Since(time.Unix(0, changedAt.Load())) < 5*time.Second) {
					t.Fatal("original readiness/fingerprint change did not restart the quiet interval")
				}
			} else if err != ErrAdmission || initial != nil {
				t.Fatal("invalid/cancelled original API became an initial admission phase")
			}
			fresh, err := a.prerequisites.engine.journal.Load(t.Context(), request.Snapshot.Anchor())
			wantRV := request.Snapshot.ResourceVersion()
			if fault == "journal-changed" {
				wantRV = "999" // deliberately injected external drift must not be repaired
			}
			if err != nil || !bytes.Equal(fresh.Bytes(), request.Snapshot.Bytes()) || fresh.ResourceVersion() != wantRV {
				t.Fatal("read-only serving convergence changed the original journal")
			}
			wal, _, err := a.prerequisites.engine.files.Read(fixtureLedgerName(request.Snapshot), fixtureLedgerMaxBytes)
			if fault == "late-wal" {
				if err != nil || !bytes.Equal(wal, []byte("uncertain fixture run")) || reads() != 1 {
					t.Fatal("late fixture fence was retried, removed, or repaired")
				}
			} else if !errors.Is(err, privatefs.ErrNotFound) {
				t.Fatal("initial serving convergence created a fixture WAL")
			}
		})
	}
}

func TestAdmissionOriginalAPIDriftAfterInitialSealRefused(t *testing.T) {
	a, request, _, _, drift := initialServingPhaseFixture(t, "post-seal-api-drift")
	ctx, cancel := context.WithTimeout(t.Context(), 12*time.Second)
	defer cancel()
	initial, err := a.waitInitialPhase(ctx, request)
	if err != nil || initial == nil {
		t.Fatal("original serving phase did not converge", err)
	}
	engine := a.prerequisites.engine
	if _, _, err := engine.files.Read(fixtureLedgerName(request.Snapshot), fixtureLedgerMaxBytes); !errors.Is(err, privatefs.ErrNotFound) {
		t.Fatal("initial phase created a fixture WAL")
	}
	ledger, err := engine.prepareFixtureLedgerV2(ctx, request.Snapshot)
	if err != nil {
		t.Fatal("unable to prepare genuine fixture ledger", err)
	}
	defer ledger.close()
	if initial.seal(ledger) != nil {
		t.Fatal("unable to seal genuine converged phase")
	}
	body, identity := bytes.Clone(ledger.body), ledger.identity
	worlds, err := ledger.loadOriginalWorlds()
	if err != nil || worlds.Phase == nil {
		t.Fatal("sealed original phase unavailable")
	}
	before, err := a.prerequisites.observe(ctx, request)
	if err != nil {
		t.Fatal("complete original observation unavailable", err)
	}
	if _, _, err := ledger.accountPhase(before, initial.baseline, time.Now().UTC()); err != nil {
		t.Fatal("unchanged sealed original API was refused", err)
	}
	drift.Store(true)
	after, err := a.prerequisites.observe(ctx, request)
	if err != nil {
		t.Fatal("changed original observation unavailable", err)
	}
	if _, _, err := ledger.accountPhase(after, initial.baseline, time.Now().UTC()); err != ErrFixtures {
		t.Fatal("API drift after sealing was accepted")
	}
	freshWorlds, err := ledger.loadOriginalWorlds()
	if err != nil || !samePhaseBaseline(*worlds.Phase, *freshWorlds.Phase) || !bytes.Equal(body, ledger.body) || identity != ledger.identity || ledger.phaseFloor != nil {
		t.Fatal("refused API drift rebased the sealed phase or ledger")
	}
}
