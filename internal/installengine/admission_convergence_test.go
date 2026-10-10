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
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installstate"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Complete production initial-phase proof over fake HTTPS, BEFORE any fixture
// WAL. This tests readiness/election convergence, not native controller timing.
func TestAdmissionInitialPhaseConvergenceBeforeWALForPartialAndFullFamilies(t *testing.T) {
	for _, scenario := range []struct {
		name        string
		familyCount int
		mode        installstate.Mode
	}{{"first-original-second-absent", 1, installstate.Install}, {"both-originals", 2, installstate.Install}, {"uninstall-originals", 2, installstate.Uninstall}} {
		t.Run(scenario.name, func(t *testing.T) {
			familyCount := scenario.familyCount
			plan := fixturePlan(t)
			v, ns, lists := readyControllerFixture(t, plan)
			d, err := installstate.Decode([]byte(ns.Annotations[installstate.Annotation]), plan)
			if err != nil {
				t.Fatal(err)
			}
			if scenario.mode == installstate.Install {
				d.Stage = installstate.Applying
				if entry, _ := v.f.engine.inventory(d, deploymentKey(ns.Name, apiFamily)); entry != nil {
					t.Fatal("partial Applying control unexpectedly has API inventory")
				}
			}
			if scenario.mode == installstate.Uninstall {
				d.Mode, d.Stage, d.ActivePackage, d.Installed = installstate.Uninstall, installstate.Preparing, plan.Digest(), true
			}
			parents := lists["Deployment"].(*appsv1.DeploymentList)
			sets := lists["ReplicaSet"].(*appsv1.ReplicaSetList)
			pods := lists["Pod"].(*corev1.PodList)
			if familyCount == 1 {
				key := deploymentKey(ns.Name, controllerFamilies[1])
				uid := v.f.access.objects[key].GetUID()
				d.Resources = slices.DeleteFunc(d.Resources, func(r installstate.Resource) bool { return r.Key == key })
				delete(v.f.access.objects, key)
				parents.Items = slices.DeleteFunc(parents.Items, func(p appsv1.Deployment) bool { return p.Name == key.Name })
				sets.Items = slices.DeleteFunc(sets.Items, func(s appsv1.ReplicaSet) bool { return len(s.OwnerReferences) == 1 && s.OwnerReferences[0].UID == uid })
				pods.Items = slices.DeleteFunc(pods.Items, func(p corev1.Pod) bool { return p.Spec.ServiceAccountName == key.Name })
			}
			body, err := installstate.Encode(d, plan)
			if err != nil {
				t.Fatal(err)
			}
			ns.Annotations[installstate.Annotation] = string(body)
			objects := maps.Clone(v.f.access.objects)
			for name, secret := range v.secrets.objects {
				objects[secretKey(ns.Name, name)] = servingObject(t, secret)
			}
			policies := &admissionv1.ValidatingAdmissionPolicyList{}
			bindings := &admissionv1.ValidatingAdmissionPolicyBindingList{}
			for key, object := range objects {
				object = object.DeepCopy()
				objects[key] = object
				switch key.Kind {
				case "CustomResourceDefinition":
					object.SetGeneration(1)
					_ = unstructured.SetNestedMap(object.Object, map[string]any{"strategy": "None"}, "spec", "conversion")
					names, found, err := unstructured.NestedMap(object.Object, "spec", "names")
					if err != nil || !found {
						t.Fatal("original CRD names unavailable")
					}
					object.Object["status"] = map[string]any{"acceptedNames": names, "storedVersions": []any{"v1alpha1"}, "conditions": []any{map[string]any{"type": "Established", "status": "True"}, map[string]any{"type": "NamesAccepted", "status": "True"}}}
					template, err := v.f.engine.contracts[plan.Digest()].Template(key, false)
					if err != nil || template.CheckCRD(object, object.GetUID(), template) != nil {
						t.Fatal("baseline original CRD does not satisfy strict native contract")
					}
				case "ValidatingAdmissionPolicy":
					object.SetGeneration(1)
					object.Object["status"] = map[string]any{"observedGeneration": object.GetGeneration(), "typeChecking": map[string]any{}}
					var policy admissionv1.ValidatingAdmissionPolicy
					if decodeServing(object, &policy) != nil {
						t.Fatal("original healthy policy fixture unavailable")
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
			if len(policies.Items) != 6 || len(bindings.Items) != 6 || len(pods.Items) != familyCount {
				t.Fatal("incomplete original fixture prerequisites")
			}
			lists["ValidatingAdmissionPolicy"], lists["ValidatingAdmissionPolicyBinding"] = policies, bindings
			leases := &coordinationv1.LeaseList{}
			now := time.Now().UTC().Truncate(time.Microsecond)
			for index := range pods.Items {
				family := 0
				if pods.Items[index].Spec.ServiceAccountName == controllerFamilies[1] {
					family = 1
				}
				leases.Items = append(leases.Items, phaseLeaderFixture(&pods.Items[index], family, now))
			}
			// Acknowledged parents precede both Pod readiness and election.
			// The first ready observation still has no elected Lease.
			lists["Lease"] = &coordinationv1.LeaseList{}
			ready := pods.Items[0].DeepCopy()
			pods.Items[0].Status.Phase = corev1.PodPending
			walChecks := 0
			access, observations := controllerProofAccessWithRequests(t, ns, objects, lists, func(n int) {
				if n == 2 {
					pods.Items[0] = *ready.DeepCopy()
					pods.Items[0].ResourceVersion = "11"
				}
				if n == 3 {
					lists["Lease"] = leases
				}
			}, "", func(_ http.ResponseWriter, request *http.Request) bool {
				if request.Method == http.MethodGet && request.URL.Path == "/apis/apps/v1/namespaces/"+ns.Name+"/deployments/arcadectl-api" {
					t.Error("partial Applying without an API attempted a serving wait")
				}
				walChecks++
				if _, _, err := v.f.engine.files.Read(fixtureLedgerName(v.f.snapshot), fixtureLedgerMaxBytes); !errors.Is(err, privatefs.ErrNotFound) {
					t.Error("startup/election wait created fixture WAL before complete proof")
				}
				return false
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
			s, err := store.Load(t.Context(), v.f.snapshot.Anchor())
			if err != nil {
				t.Fatal(err)
			}
			request := LifecycleCheck{Checkpoint: AdmissionEffective, Snapshot: s, Mode: d.Mode, Target: plan, Options: LifecycleOptions{Now: time.Now().UTC()}}
			writes, namespaceRV := v.f.access.writes, ns.ResourceVersion
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			start := time.Now()
			initial, err := a.waitInitialPhase(ctx, request)
			if err != nil {
				// Bounded public stage diagnostics only; never dump bodies,
				// credentials or raw storage settings on a fixture failure.
				cold, _ := NewClusterCold(a.prerequisites)
				coldRequest := request
				coldRequest.Checkpoint = ColdSafety
				_, o, _, _, coldErr := cold.collectEvidence(t.Context(), coldRequest)
				t.Log("ready control cold evidence", coldErr)
				if coldErr == nil {
					states, familyErr := engine.admissionControllers(t.Context(), request, o)
					t.Log("ready control original families", familyErr)
					_, baselineErr := capturePhaseBaseline(o, states, time.Now().UTC())
					t.Log("ready control baseline", baselineErr)
				}
				_, publicErr := a.phasePublicInventory(t.Context(), request)
				t.Log("ready control public inventory", publicErr)
			}
			if err != nil || initial == nil || len(initial.baseline.Leaders) != familyCount || observations() < 4 || walChecks == 0 || time.Since(start) < 2*time.Second {
				t.Fatal("complete pre-WAL original startup/election convergence failed", err, observations())
			}
			fresh, err := store.Load(t.Context(), s.Anchor())
			if err != nil || !bytes.Equal(fresh.Bytes(), s.Bytes()) || fresh.ResourceVersion() != s.ResourceVersion() || ns.ResourceVersion != namespaceRV || v.f.access.writes != writes {
				t.Fatal("observational startup wait changed original journal or effects")
			}
			if _, _, err := engine.files.Read(fixtureLedgerName(s), fixtureLedgerMaxBytes); !errors.Is(err, privatefs.ErrNotFound) {
				t.Fatal("completed initial proof prepared fixture WAL")
			}
			// Exercise SAME-attempt diagnostics in the real initializer. These
			// remain observations only: neither a failed proof nor its trace may
			// create a WAL, change the journal or authorize a fixture effect.
			for _, fault := range []string{"configured", "pending-original-pod"} {
				trace := &admissionTrace{}
				traceCtx := context.WithValue(t.Context(), admissionTraceKey{}, trace)
				traceAdmission(traceCtx, admissionInitialPhase, -1)
				var restore func()
				want := "initial-whole-rows"
				if fault == "configured" {
					want = "configured"
					for key, object := range objects {
						if key.Kind == "ValidatingAdmissionPolicy" {
							original := object.DeepCopy()
							object.SetUID("foreign-initial-policy")
							restore = func() { objects[key] = original }
							break
						}
					}
				} else {
					original := pods.Items[0].DeepCopy()
					pods.Items[0].Status.Phase = corev1.PodPending
					restore = func() { pods.Items[0] = *original }
				}
				if restore == nil {
					t.Fatal("initial proof diagnostic fault unavailable")
				}
				result, proofErr := a.captureInitialPhase(traceCtx, request)
				restore()
				phase, slot := trace.phaseSnapshot()
				if result != nil || proofErr != ErrAdmission || phase != want || slot != -1 {
					t.Fatal("initial proof refusal lost its closed same-attempt diagnostic", fault, phase, slot)
				}
				if v.f.access.writes != writes || ns.ResourceVersion != namespaceRV {
					t.Fatal("initial diagnostic refusal changed original state")
				}
				if _, _, err := engine.files.Read(fixtureLedgerName(s), fixtureLedgerMaxBytes); !errors.Is(err, privatefs.ErrNotFound) {
					t.Fatal("initial diagnostic refusal prepared a fixture WAL")
				}
			}
			// client-go samples AcquireTime before GET/CREATE. The server can
			// create the original Lease in a later second; subsequent renewals
			// preserve that earlier acquisition. Test the real complete initializer,
			// both partial/full families, and unchanged original identity after
			// renewal. No fixture WAL or mutation is allowed by this observation.
			probeNow := time.Now().UTC().Truncate(time.Microsecond)
			for index := range leases.Items {
				lease := &leases.Items[index]
				lease.CreationTimestamp = metav1.NewTime(probeNow.Add(-2 * time.Second).Truncate(time.Second))
				acquire := metav1.NewMicroTime(lease.CreationTimestamp.Add(-time.Second))
				lease.Spec.AcquireTime = &acquire
			}
			var accepted *initialAdmissionPhase
			for pass := range 2 {
				for index := range leases.Items {
					lease := &leases.Items[index]
					lease.ResourceVersion = []string{"102", "103"}[pass]
					renew := metav1.NewMicroTime(probeNow.Add(-time.Second + time.Duration(pass)*time.Microsecond))
					lease.Spec.RenewTime = &renew
					managed := metav1.NewTime(probeNow.Add(-time.Second).Truncate(time.Second))
					lease.ManagedFields[0].Time = &managed
				}
				observed, proofErr := a.captureInitialPhase(t.Context(), request)
				if proofErr != nil || observed == nil || len(observed.baseline.Leaders) != familyCount || accepted != nil && !samePhaseBaseline(accepted.baseline, observed.baseline) {
					t.Fatal("original client-acquired-before-server-created Lease refused complete initial proof", pass, proofErr)
				}
				accepted = observed
			}
			if v.f.access.writes != writes || ns.ResourceVersion != namespaceRV {
				t.Fatal("client/server timestamp observation changed original state")
			}
			if _, _, err := engine.files.Read(fixtureLedgerName(s), fixtureLedgerMaxBytes); !errors.Is(err, privatefs.ErrNotFound) {
				t.Fatal("client/server timestamp observation prepared a fixture WAL")
			}
			bad := request
			bad.Mode = installstate.Mode("invalid")
			before := observations()
			if result, err := a.waitInitialPhase(t.Context(), bad); result != nil || err != ErrInvalid || observations() != before {
				t.Fatal("invalid lifecycle mode waited or observed instead of immediate refusal")
			}
			trace := &admissionTrace{}
			if a.VerifyEffective(context.WithValue(t.Context(), admissionTraceKey{}, trace), bad) != ErrFixtures || observations() != before || v.f.access.writes != writes {
				t.Fatal("traced public admission changed refusal, observation or effect counts")
			}
			if stage, index := trace.snapshot(); stage != "initial-phase" || index != -1 {
				t.Fatal("traced public refusal did not identify its bounded stage")
			}
			if _, _, err := engine.files.Read(fixtureLedgerName(s), fixtureLedgerMaxBytes); !errors.Is(err, privatefs.ErrNotFound) {
				t.Fatal("traced invalid public proof prepared fixture WAL")
			}
		})
	}
}
