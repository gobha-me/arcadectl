// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installobserve"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
)

func TestAdmissionControllerFamiliesIndependentInitialStates(t *testing.T) {
	plan := fixturePlan(t)
	for _, warm := range [][2]bool{{false, false}, {true, false}, {false, true}, {true, true}} {
		name := "cold"
		if warm[0] {
			name += "-controller"
		}
		if warm[1] {
			name += "-destroy"
		}
		t.Run(name, func(t *testing.T) {
			v, ns, lists := readyControllerFixture(t, plan)
			d := admissionPauseFamilies(t, v, lists, warm)
			states, err := admissionClassifyTest(t, v, ns, lists, d, plan, "")
			if err != nil {
				t.Fatal(err)
			}
			for i, state := range states {
				if state.Name != controllerFamilies[i] || state.Executing != warm[i] || state.Available != warm[i] || state.Deployment == nil || len(state.Sets) != 6 || (len(state.Pods) == 1) != warm[i] {
					t.Fatalf("family %d classified incorrectly: %+v", i, state)
				}
			}
		})
	}
}

// A paused parent is not proof of process absence. Conversely, retained
// ServiceAccounts do not imply a removed parent's descendants may survive.
func TestAdmissionControllerFamiliesRefuseUnprovedDescendants(t *testing.T) {
	plan := fixturePlan(t)
	for _, scenario := range []string{"terminal-paused-pod", "deleting-paused-pod", "live-paused-pod", "executable-history", "parent-paused", "wrong-current-owner", "selector-orphan", "nested-job", "foreign-sa", "missing-sa", "absent-parent-history", "absent-parent-replacement", "missing-pods", "page-failure"} {
		t.Run(scenario, func(t *testing.T) {
			v, ns, lists := readyControllerFixture(t, plan)
			d := v.f.snapshot.Document()
			// readyControllerFixture updates the journal copy in ns, not the
			// fixture store. Decode that exact journal for all modifications.
			var err error
			d, err = installstate.Decode([]byte(ns.Annotations[installstate.Annotation]), plan)
			if err != nil {
				t.Fatal(err)
			}
			parents := lists["Deployment"].(*appsv1.DeploymentList)
			sets := lists["ReplicaSet"].(*appsv1.ReplicaSetList)
			pods := lists["Pod"].(*corev1.PodList)
			first := parents.Items[0].Name
			switch scenario {
			case "terminal-paused-pod", "deleting-paused-pod", "live-paused-pod":
				old := pods.Items[0].DeepCopy()
				d = admissionPauseFamilies(t, v, lists, [2]bool{false, true})
				if scenario == "terminal-paused-pod" {
					old.Status.Phase = corev1.PodSucceeded
				}
				if scenario == "deleting-paused-pod" {
					now := metav1.Now()
					old.DeletionTimestamp = &now
				}
				pods.Items = append(pods.Items, *old)
			case "executable-history":
				sets.Items[0].Spec.Replicas = ptr.To[int32](1)
			case "parent-paused":
				parents.Items[0].Spec.Paused = true
				v.f.access.objects[deploymentKey(ns.Name, first)] = servingObject(t, &parents.Items[0])
			case "wrong-current-owner":
				pods.Items[0].OwnerReferences[0].UID = "replacement-set"
			case "selector-orphan":
				orphan := pods.Items[0].DeepCopy()
				orphan.Name, orphan.UID, orphan.OwnerReferences = "renamed", "orphan", nil
				pods.Items = append(pods.Items, *orphan)
			case "nested-job":
				job := batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "renamed", Namespace: ns.Name, UID: "nested-job", ResourceVersion: "10", OwnerReferences: fixtureOwner("apps/v1", "ReplicaSet", sets.Items[0].Name, sets.Items[0].UID)}, Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "other", Image: "example.invalid/other"}}}}}}
				lists["Job"] = &batchv1.JobList{Items: []batchv1.Job{job}}
			case "foreign-sa", "missing-sa":
				key := installstate.Key{APIVersion: "v1", Kind: "ServiceAccount", Namespace: ns.Name, Name: first}
				if scenario == "missing-sa" {
					delete(v.f.access.objects, key)
				} else {
					v.f.access.objects[key].SetUID("replacement-sa")
				}
			case "absent-parent-history", "absent-parent-replacement":
				key := deploymentKey(ns.Name, first)
				d.Resources = slices.DeleteFunc(d.Resources, func(r installstate.Resource) bool { return r.Key == key })
				delete(v.f.access.objects, key)
				if scenario == "absent-parent-history" {
					parents.Items = parents.Items[1:]
				} else {
					v.f.access.objects[key] = servingObject(t, &parents.Items[0])
				}
			}
			_, err = admissionClassifyTest(t, v, ns, lists, d, plan, scenario)
			if err != ErrAdmission {
				t.Fatalf("accepted %s: %v", scenario, err)
			}
		})
	}
}

func TestAdmissionControllerFamiliesAllowOriginalAbsenceNotAdoption(t *testing.T) {
	plan := fixturePlan(t)
	v, ns, lists := readyControllerFixture(t, plan)
	d := admissionPauseFamilies(t, v, lists, [2]bool{})
	for _, name := range controllerFamilies {
		key := deploymentKey(ns.Name, name)
		d.Resources = slices.DeleteFunc(d.Resources, func(r installstate.Resource) bool { return r.Key == key })
		delete(v.f.access.objects, key)
	}
	lists["Deployment"] = &appsv1.DeploymentList{}
	lists["ReplicaSet"] = &appsv1.ReplicaSetList{}
	states, err := admissionClassifyTest(t, v, ns, lists, d, plan, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range states {
		if state.Executing || state.Available || state.Deployment != nil || len(state.Sets) != 0 || len(state.Pods) != 0 {
			t.Fatal("absent parent adopted runtime")
		}
	}
}

func TestAdmissionControllerFamiliesRecordedPredecessorNotTargetOnly(t *testing.T) {
	previous, target := lifecycleTransitionPlans(t)
	v, ns, lists := readyControllerFixture(t, previous, target)
	d, err := installstate.Decode([]byte(ns.Annotations[installstate.Annotation]), previous, target)
	if err != nil {
		t.Fatal(err)
	}
	d.Mode, d.Stage, d.Installed, d.ActivePackage, d.TargetPackage = installstate.Upgrade, installstate.Quiescing, true, previous.Digest(), target.Digest()
	d.Revision++
	states, err := admissionClassifyTest(t, v, ns, lists, d, target, "", previous)
	if err != nil || !states[0].Available || !states[1].Available {
		t.Fatalf("original predecessor refused: %v", err)
	}
}

func TestAdmissionSignedPredecessorExecutionDoesNotClaimReadiness(t *testing.T) {
	previous, target := lifecycleTransitionPlans(t)
	for _, scenario := range []string{"failed-rollout", "failed-rollout-pending-target", "unsigned-pending-target", "third-executor", "pending-signed-pod", "unknown-executor"} {
		t.Run(scenario, func(t *testing.T) {
			v, ns, lists := readyControllerFixture(t, previous, target)
			d, err := installstate.Decode([]byte(ns.Annotations[installstate.Annotation]), previous, target)
			if err != nil {
				t.Fatal(err)
			}
			d.Mode, d.Stage, d.Installed, d.ActivePackage, d.TargetPackage = installstate.Upgrade, installstate.Quiescing, true, previous.Digest(), target.Digest()
			d.Revision++
			parents := lists["Deployment"].(*appsv1.DeploymentList)
			parent := &parents.Items[0]
			key := deploymentKey(ns.Name, parent.Name)
			template, err := v.f.engine.contracts[target.Digest()].Template(key, false)
			if err != nil {
				t.Fatal(err)
			}
			podTemplate, err := template.PodTemplate()
			if err != nil {
				t.Fatal(err)
			}
			parent.Spec.Template = *podTemplate
			parent.Generation++
			parent.Status.ObservedGeneration, parent.Status.UpdatedReplicas, parent.Status.AvailableReplicas = parent.Generation, 0, 0
			parent.Annotations[installstate.MutationAnnotation] = strings.Repeat("d", 32)
			v.f.access.objects[key] = servingObject(t, parent)
			for i := range d.Resources {
				if d.Resources[i].Key == key {
					d.Resources[i].TemplateSHA256 = template.Hash()
				}
			}
			pods := lists["Pod"].(*corev1.PodList)
			if scenario == "failed-rollout-pending-target" || scenario == "unsigned-pending-target" || scenario == "third-executor" {
				sets := lists["ReplicaSet"].(*appsv1.ReplicaSetList)
				appendTarget := func(hash string) {
					set := inertFixture(parent, hash, 7)
					set.CreationTimestamp = metav1.NewTime(time.Unix(200, 0).UTC())
					set.Spec.Template = *parent.Spec.Template.DeepCopy()
					set.Spec.Template.Labels[appsv1.DefaultDeploymentUniqueLabelKey] = hash
					set.Labels = maps.Clone(set.Spec.Template.Labels)
					set.Annotations[installstate.MutationAnnotation] = parent.Annotations[installstate.MutationAnnotation]
					set.Spec.Replicas = ptr.To[int32](1)
					set.Status = appsv1.ReplicaSetStatus{ObservedGeneration: set.Generation, Replicas: 1, FullyLabeledReplicas: 1}
					pod := pods.Items[0].DeepCopy()
					pod.Name, pod.GenerateName, pod.UID = set.Name+"-bcdfg", set.Name+"-", set.UID+"-pod"
					pod.Labels = maps.Clone(set.Spec.Template.Labels)
					pod.Annotations = maps.Clone(set.Spec.Template.Annotations)
					pod.OwnerReferences = fixtureOwner("apps/v1", "ReplicaSet", set.Name, set.UID)
					old := pod.Spec.DeepCopy()
					projection, mount := old.Volumes[len(old.Volumes)-1], old.Containers[0].VolumeMounts[len(old.Containers[0].VolumeMounts)-1]
					pod.Spec = *set.Spec.Template.Spec.DeepCopy()
					pod.Spec.EnableServiceLinks, pod.Spec.Priority, pod.Spec.PreemptionPolicy, pod.Spec.Tolerations = old.EnableServiceLinks, old.Priority, old.PreemptionPolicy, old.Tolerations
					pod.Spec.Volumes = append(pod.Spec.Volumes, projection)
					pod.Spec.Containers[0].VolumeMounts = append(pod.Spec.Containers[0].VolumeMounts, mount)
					pod.Status = corev1.PodStatus{Phase: corev1.PodPending}
					if scenario == "unsigned-pending-target" {
						set.Spec.Template.Spec.Containers[0].Image = "unregistered.example/controller@sha256:" + strings.Repeat("f", 64)
						pod.Spec.Containers[0].Image = set.Spec.Template.Spec.Containers[0].Image
					}
					if scenario == "failed-rollout-pending-target" {
						if !controllerSetIdentity(set, parent) || !v.f.engine.controllerRuntimeSet(set, parent, d) || !validOriginalPodTemplate(pod, set, false) {
							t.Fatalf("target fixture invalid: identity=%v signed=%v pod=%v", controllerSetIdentity(set, parent), v.f.engine.controllerRuntimeSet(set, parent, d), validOriginalPodTemplate(pod, set, false))
						}
					}
					sets.Items = append(sets.Items, *set)
					pods.Items = append(pods.Items, *pod)
				}
				appendTarget("bcdfg98765")
				if scenario == "third-executor" {
					appendTarget("bcdfg98766")
				}
				parent.Status.Replicas, parent.Status.UpdatedReplicas = 2, 1
				v.f.access.objects[key] = servingObject(t, parent)
			}
			if scenario == "pending-signed-pod" {
				pods.Items[0].Status.Phase = corev1.PodPending
				pods.Items[0].Status.Conditions = nil
				pods.Items[0].Status.ContainerStatuses = nil
			}
			if scenario == "unknown-executor" {
				sets := lists["ReplicaSet"].(*appsv1.ReplicaSetList)
				for i := range sets.Items {
					if sets.Items[i].UID == pods.Items[0].OwnerReferences[0].UID {
						sets.Items[i].Spec.Template.Spec.Containers[0].Image = "unregistered.example/controller@sha256:" + strings.Repeat("f", 64)
						pods.Items[0].Spec.Containers[0].Image = sets.Items[i].Spec.Template.Spec.Containers[0].Image
					}
				}
			}
			states, err := admissionClassifyTest(t, v, ns, lists, d, target, "", previous)
			if scenario == "unknown-executor" || scenario == "unsigned-pending-target" || scenario == "third-executor" {
				if err != ErrAdmission {
					t.Fatalf("adopted unregistered executable history: %v", err)
				}
				return
			}
			if err != nil || !states[0].Executing || states[0].Available || len(states[0].Pods) == 0 || scenario == "failed-rollout-pending-target" && len(states[0].Pods) != 2 {
				t.Fatalf("signed recovery provenance/readiness confused: %+v, %v", states[0], err)
			}
		})
	}
}

func TestAdmissionControllerExecutionDoesNotInventScheduledReadiness(t *testing.T) {
	plan := fixturePlan(t)
	v, ns, lists := readyControllerFixture(t, plan)
	d, err := installstate.Decode([]byte(ns.Annotations[installstate.Annotation]), plan)
	if err != nil {
		t.Fatal(err)
	}
	lists["Pod"].(*corev1.PodList).Items[0].Spec.NodeName = ""
	states, err := admissionClassifyTest(t, v, ns, lists, d, plan, "")
	if err != nil || !states[0].Executing || states[0].Available {
		t.Fatalf("unscheduled status invented readiness: %+v, %v", states[0], err)
	}
}

func admissionPauseFamilies(t *testing.T, v *servingFixture, lists map[string]runtime.Object, warm [2]bool) installstate.Document {
	t.Helper()
	// The ready journal differs from the fixture's paused store. Start from
	// its document but reproduce ready parents' exact recorded normal hashes.
	d := v.f.snapshot.Document()
	d.Mode, d.Stage, d.ActivePackage, d.Installed = installstate.Uninstall, installstate.Quiescing, d.TargetPackage, true
	d.Revision++
	parents := lists["Deployment"].(*appsv1.DeploymentList)
	sets := lists["ReplicaSet"].(*appsv1.ReplicaSetList)
	pods := lists["Pod"].(*corev1.PodList)
	for family, name := range controllerFamilies {
		key := deploymentKey(d.Namespace, name)
		template, err := v.f.engine.contracts[d.TargetPackage].Template(key, !warm[family])
		if err != nil {
			t.Fatal(err)
		}
		for index := range d.Resources {
			if d.Resources[index].Key == key {
				d.Resources[index].TemplateSHA256 = template.Hash()
			}
		}
		if warm[family] {
			continue
		}
		for index := range parents.Items {
			parent := &parents.Items[index]
			if parent.Name != name {
				continue
			}
			parent.Spec.Replicas = ptr.To[int32](0)
			parent.Generation++
			parent.Status = appsv1.DeploymentStatus{ObservedGeneration: parent.Generation}
			v.f.access.objects[key] = servingObject(t, parent)
			if err := template.MatchLive(v.f.access.objects[key], parent.UID); err != nil {
				t.Fatalf("paused fixture does not match recorded template: %v", err)
			}
			if !stoppedDeployment(parent) {
				t.Fatal("paused fixture is not stopped")
			}
			for setIndex := range sets.Items {
				set := &sets.Items[setIndex]
				if set.OwnerReferences[0].UID != parent.UID {
					continue
				}
				set.Spec.Replicas = ptr.To[int32](0)
				set.Status = appsv1.ReplicaSetStatus{ObservedGeneration: set.Generation}
				if !inertReplicaSet(set, parent) {
					t.Fatal("paused fixture history is not inert")
				}
			}
			pods.Items = slices.DeleteFunc(pods.Items, func(p corev1.Pod) bool { return p.Spec.ServiceAccountName == name })
		}
	}
	return d
}

func admissionClassifyTest(t *testing.T, v *servingFixture, ns *corev1.Namespace, lists map[string]runtime.Object, d installstate.Document, target *installrender.Plan, fault string, others ...*installrender.Plan) ([2]admissionControllerState, error) {
	states, _, err := admissionClassifyObservationTest(t, v, ns, lists, d, target, fault, others...)
	return states, err
}

func admissionClassifyObservationTest(t *testing.T, v *servingFixture, ns *corev1.Namespace, lists map[string]runtime.Object, d installstate.Document, target *installrender.Plan, fault string, others ...*installrender.Plan) ([2]admissionControllerState, *installobserve.Observation, error) {
	t.Helper()
	registered := append([]*installrender.Plan{target}, others...)
	body, err := installstate.Encode(d, registered...)
	if err != nil {
		t.Fatal(err)
	}
	ns.Annotations[installstate.Annotation] = string(body)
	objects := maps.Clone(v.f.access.objects)
	for name, secret := range v.secrets.objects {
		objects[secretKey(ns.Name, name)] = servingObject(t, secret)
	}
	access, _ := controllerProofAccess(t, ns, objects, lists, nil, fault)
	store, err := installstate.New(access.Namespaces(), registered...)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewWithAccess(access, store, v.f.engine.files, registered...)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewClusterPrerequisites(engine, access)
	if err != nil {
		t.Fatal(err)
	}
	s, err := store.Load(context.Background(), v.f.snapshot.Anchor())
	if err != nil {
		t.Fatal(err)
	}
	request := LifecycleCheck{Checkpoint: AdmissionEffective, Snapshot: s, Mode: d.Mode, Target: target, Options: LifecycleOptions{Now: time.Now().UTC()}}
	o, err := p.observe(context.Background(), request)
	if err != nil {
		if fault == "" {
			t.Fatalf("initial observation failed: %v", err)
		}
		return [2]admissionControllerState{}, nil, ErrAdmission
	}
	if fault == "" {
		for _, parent := range o.Runtime().Deployments.Items {
			got, err := engine.access.Get(context.Background(), deploymentKey(d.Namespace, parent.Name))
			var decoded appsv1.Deployment
			if err != nil || decodeServing(got, &decoded) != nil || !reflect.DeepEqual(&parent, &decoded) {
				t.Fatalf("GET/list disagreement for %s: %v", parent.Name, err)
			}
		}
	}
	states, err := engine.admissionControllers(context.Background(), request, o)
	return states, o, err
}

// Keep the API's repository/name distinct from its scoped role evidence.
func TestAdmissionControllerFamiliesIgnoreUnrelatedSharedRepository(t *testing.T) {
	plan := fixturePlan(t)
	v, ns, lists := readyControllerFixture(t, plan)
	d, err := installstate.Decode([]byte(ns.Annotations[installstate.Annotation]), plan)
	if err != nil {
		t.Fatal(err)
	}
	pod := v.access.pod.DeepCopy()
	pod.Labels = map[string]string{"app.kubernetes.io/name": "unrelated"}
	pod.Name, pod.UID, pod.OwnerReferences = "unrelated", "unrelated-pod", nil
	pod.Spec.ServiceAccountName, pod.Spec.DeprecatedServiceAccount = "unrelated", ""
	pod.Spec.Containers[0].Image = strings.Split(lists["Pod"].(*corev1.PodList).Items[0].Spec.Containers[0].Image, "@")[0] + "@sha256:" + strings.Repeat("f", 64)
	pods := lists["Pod"].(*corev1.PodList)
	pods.Items = append(pods.Items, *pod)
	if _, err := admissionClassifyTest(t, v, ns, lists, d, plan, ""); err != nil {
		t.Fatal(err)
	}
}
