// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installpackage"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
)

func inertFixture(d *appsv1.Deployment, hash string, revision int) *appsv1.ReplicaSet {
	template := d.Spec.Template.DeepCopy()
	template.Labels[appsv1.DefaultDeploymentUniqueLabelKey] = hash
	// Historical payload intentionally falls outside the current signature set.
	template.Spec.Containers[0].Image = "obsolete.example/controller@sha256:" + strings.Repeat(strconv.Itoa(revision), 64)
	selector := d.Spec.Selector.DeepCopy()
	selector.MatchLabels[appsv1.DefaultDeploymentUniqueLabelKey] = hash
	return &appsv1.ReplicaSet{TypeMeta: metav1.TypeMeta{APIVersion: "apps/v1", Kind: "ReplicaSet"}, ObjectMeta: metav1.ObjectMeta{
		Name: d.Name + "-" + hash, Namespace: d.Namespace, UID: types.UID("original-" + d.Name + "-" + hash), ResourceVersion: "10", Generation: 2,
		Labels: template.Labels, OwnerReferences: fixtureOwner("apps/v1", "Deployment", d.Name, d.UID), Annotations: map[string]string{
			installstate.MutationAnnotation: strings.Repeat("c", 32), "deployment.kubernetes.io/revision": strconv.Itoa(revision), "deployment.kubernetes.io/desired-replicas": "1", "deployment.kubernetes.io/max-replicas": "2",
		},
	}, Spec: appsv1.ReplicaSetSpec{Replicas: ptr.To[int32](0), Selector: selector, Template: *template}, Status: appsv1.ReplicaSetStatus{ObservedGeneration: 2}}
}

func stoppedFixture(t *testing.T) (*servingFixture, *corev1.Namespace, map[string]runtime.Object) {
	t.Helper()
	return stoppedFixtureWithPlan(t, fixturePlan(t))
}

func stoppedFixtureWithPlan(t *testing.T, plan *installrender.Plan, others ...*installrender.Plan) (*servingFixture, *corev1.Namespace, map[string]runtime.Object) {
	t.Helper()
	v := newServingFixtureWithPlan(t, plan, others...)
	d := v.f.snapshot.Document()
	d.Mode, d.Stage, d.Installed, d.ActivePackage = installstate.Uninstall, installstate.Quiescing, true, d.TargetPackage
	d.Revision++
	apiKey := deploymentKey(d.Namespace, apiFamily)
	d.Resources = slices.DeleteFunc(d.Resources, func(r installstate.Resource) bool { return r.Key == apiKey })
	delete(v.f.access.objects, apiKey)
	lists := map[string]runtime.Object{}
	deployments := &appsv1.DeploymentList{}
	sets := &appsv1.ReplicaSetList{}
	for _, name := range controllerFamilies {
		key := deploymentKey(d.Namespace, name)
		template, err := v.f.engine.contracts[d.ActivePackage].Template(key, true)
		if err != nil {
			t.Fatal(err)
		}
		candidate, err := template.Candidate(strings.Repeat("b", 32))
		if err != nil {
			t.Fatal(err)
		}
		candidate.SetUID(v.f.access.objects[key].GetUID())
		candidate.SetResourceVersion("10")
		var deployment appsv1.Deployment
		if decodeServing(candidate, &deployment) != nil {
			t.Fatal("controller fixture")
		}
		podTemplate, err := template.PodTemplate()
		if err != nil {
			t.Fatal(err)
		}
		deployment.Spec.Template = *podTemplate
		deployment.Spec.RevisionHistoryLimit = ptr.To[int32](10)
		deployment.Spec.ProgressDeadlineSeconds = ptr.To[int32](600)
		deployment.Spec.Strategy = appsv1.DeploymentStrategy{Type: appsv1.RollingUpdateDeploymentStrategyType, RollingUpdate: &appsv1.RollingUpdateDeployment{MaxSurge: ptr.To(intstr.FromString("25%")), MaxUnavailable: ptr.To(intstr.FromString("25%"))}}
		deployment.Generation = 2
		deployment.Annotations["deployment.kubernetes.io/revision"] = "6"
		deployment.Status.ObservedGeneration = 2
		v.f.access.objects[key] = servingObject(t, &deployment)
		for i := range d.Resources {
			if d.Resources[i].Key == key {
				d.Resources[i].TemplateSHA256 = template.Hash()
			}
		}
		deployments.Items = append(deployments.Items, deployment)
		// Five inert old revisions prove no dependency on three trusted plans.
		for i := 1; i <= 5; i++ {
			sets.Items = append(sets.Items, *inertFixture(&deployment, fmt.Sprintf("bcdfg%d", i), i))
		}
	}
	lists["Deployment"], lists["ReplicaSet"] = deployments, sets
	emptySlice := v.access.list.Items[0].DeepCopy()
	emptySlice.Endpoints = nil
	emptySlice.Ports = nil
	lists["EndpointSlice"] = &discoveryv1.EndpointSliceList{Items: []discoveryv1.EndpointSlice{*emptySlice}}
	body, err := installstate.Encode(d, v.f.plan)
	if err != nil {
		t.Fatal(err)
	}
	ns, err := v.f.access.client.CoreV1().Namespaces().Get(context.Background(), d.Namespace, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ns.Annotations[installstate.Annotation] = string(body)
	ns, err = v.f.access.client.CoreV1().Namespaces().Update(context.Background(), ns, metav1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	v.f.snapshot, err = v.f.store.Load(context.Background(), v.f.snapshot.Anchor())
	if err != nil {
		t.Fatal(err)
	}
	return v, ns, lists
}

func TestQuiescenceInertHistoryRequiresOriginalParentAndNativeZeroState(t *testing.T) {
	_, _, lists := stoppedFixture(t)
	d := &lists["Deployment"].(*appsv1.DeploymentList).Items[0]
	original := inertFixture(d, "bcdfg1", 5)
	for _, test := range []struct {
		name   string
		change func(*appsv1.ReplicaSet)
		valid  bool
	}{
		{"unknown-old-template", func(*appsv1.ReplicaSet) {}, true},
		{"native-historical-condition", func(r *appsv1.ReplicaSet) {
			r.Status.Conditions = []appsv1.ReplicaSetCondition{{Type: appsv1.ReplicaSetReplicaFailure, Status: corev1.ConditionFalse}}
		}, true},
		{"old-desired-max-not-zero", func(r *appsv1.ReplicaSet) {
			r.Annotations["deployment.kubernetes.io/desired-replicas"] = "2147483647"
			r.Annotations["deployment.kubernetes.io/max-replicas"] = "2147483647"
		}, true},
		{"history", func(r *appsv1.ReplicaSet) { r.Annotations["deployment.kubernetes.io/revision-history"] = "1,2,3,4" }, true},
		{"lost-parent", func(r *appsv1.ReplicaSet) { r.OwnerReferences[0].UID = "replacement" }, false},
		{"owner-controller", func(r *appsv1.ReplicaSet) { r.OwnerReferences[0].Controller = ptr.To(false) }, false},
		{"owner-block", func(r *appsv1.ReplicaSet) { r.OwnerReferences[0].BlockOwnerDeletion = ptr.To(false) }, false},
		{"stale-observed", func(r *appsv1.ReplicaSet) { r.Status.ObservedGeneration = 1 }, false},
		{"spec-one", func(r *appsv1.ReplicaSet) { r.Spec.Replicas = ptr.To[int32](1) }, false},
		{"nil-replicas", func(r *appsv1.ReplicaSet) { r.Spec.Replicas = nil }, false},
		{"status-one", func(r *appsv1.ReplicaSet) { r.Status.Replicas = 1 }, false},
		{"fully-labeled", func(r *appsv1.ReplicaSet) { r.Status.FullyLabeledReplicas = 1 }, false},
		{"ready", func(r *appsv1.ReplicaSet) { r.Status.ReadyReplicas = 1 }, false},
		{"available", func(r *appsv1.ReplicaSet) { r.Status.AvailableReplicas = 1 }, false},
		{"terminating", func(r *appsv1.ReplicaSet) { r.Status.TerminatingReplicas = ptr.To[int32](1) }, false},
		{"deleting", func(r *appsv1.ReplicaSet) { r.DeletionTimestamp = ptr.To(metav1.Now()) }, false},
		{"finalizer", func(r *appsv1.ReplicaSet) { r.Finalizers = []string{"block.example"} }, false},
		{"hash-label", func(r *appsv1.ReplicaSet) {
			r.Spec.Template.Labels = maps.Clone(r.Spec.Template.Labels)
			r.Spec.Template.Labels[appsv1.DefaultDeploymentUniqueLabelKey] = "different"
		}, false},
		{"selector", func(r *appsv1.ReplicaSet) { r.Spec.Selector.MatchLabels["extra"] = "extra" }, false},
		{"no-selector", func(r *appsv1.ReplicaSet) { r.Spec.Selector = nil }, false},
		{"revision-overflow", func(r *appsv1.ReplicaSet) { r.Annotations["deployment.kubernetes.io/revision"] = "9223372036854775808" }, false},
		{"counter-overflow", func(r *appsv1.ReplicaSet) { r.Annotations["deployment.kubernetes.io/max-replicas"] = "2147483648" }, false},
		{"negative", func(r *appsv1.ReplicaSet) { r.Annotations["deployment.kubernetes.io/desired-replicas"] = "-1" }, false},
		{"noncanonical", func(r *appsv1.ReplicaSet) { r.Annotations["deployment.kubernetes.io/desired-replicas"] = "01" }, false},
		{"nonce", func(r *appsv1.ReplicaSet) { r.Annotations[installstate.MutationAnnotation] = strings.Repeat("G", 32) }, false},
		{"history-future", func(r *appsv1.ReplicaSet) { r.Annotations["deployment.kubernetes.io/revision-history"] = "1,5" }, false},
		{"history-duplicate", func(r *appsv1.ReplicaSet) { r.Annotations["deployment.kubernetes.io/revision-history"] = "1,1" }, false},
		{"history-decreasing", func(r *appsv1.ReplicaSet) { r.Annotations["deployment.kubernetes.io/revision-history"] = "3,2" }, false},
		{"history-budget", func(r *appsv1.ReplicaSet) {
			r.Annotations["deployment.kubernetes.io/revision-history"] = strings.Repeat("1,", 1001)
		}, false},
		{"rollback-directive", func(r *appsv1.ReplicaSet) { r.Annotations["deprecated.deployment.rollback.to"] = "1" }, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := original.DeepCopy()
			test.change(r)
			before := r.DeepCopy()
			if inertReplicaSet(r, d) != test.valid || !reflect.DeepEqual(before, r) {
				t.Fatal("inert proof accepted executable/drift state or mutated evidence")
			}
		})
	}
	long := original.DeepCopy()
	long.Annotations["deployment.kubernetes.io/revision"] = "301"
	parts := []string{}
	for i := 1; i <= 300; i++ {
		parts = append(parts, strconv.Itoa(i))
	}
	long.Annotations["deployment.kubernetes.io/revision-history"] = strings.Join(parts, ",")
	if !inertReplicaSet(long, d) {
		t.Fatal("native history was limited to 128 rollbacks")
	}
}

// Production HTTPS transports and the real sealed observer/journal are used;
// fixture counters are NOT kubelet/controller-manager execution evidence.
func TestQuiescenceBoundProviderRefusesExecutableAndRacingDescendants(t *testing.T) {
	quiescenceCases(t, fixturePlan(t), []string{"healthy", "api-only-controllers-running", "api-only-pending-controller", "uninstall-controllers-removed", "api-pod", "terminal-api-pod", "deleting-api-pod", "orphan-api-rs", "endpoint-unready", "endpoint-terminating", "endpoint-replacement-service", "endpoint-corrupted-original-owner", "endpoint-drained-port", "api-deployment-survives", "service-missing-recorded", "service-replacement", "deployment-replacement", "controller-stale", "controller-paused", "controller-ready", "controller-missing-unrecorded", "controller-missing-recorded", "unknown-rs-running", "controller-pod-by-owner-uid", "daemonset-zero", "statefulset-zero", "cronjob-suspended", "job-terminal", "replicationcontroller-zero", "secret-env", "secret-projected", "init-api-image", "ephemeral-api-image", "missing-endpoint-list", "endpoint-page-failure", "journal-rv", "namespace-uid", "controller-rv-second", "rs-rv-second", "pod-second", "unrelated-pod-renewal", "unrelated-empty-slice"})
}

func TestQuiescenceOwnershipClosureIsIndependentOfListOrderAndOwnerKind(t *testing.T) {
	quiescenceCases(t, fixturePlan(t), []string{"nested-rs-first", "transitive-job-owner"})
}

func TestQuiescenceSharedTaggedRepositoriesRequireWholeOriginalControllerIdentity(t *testing.T) {
	images := installpackage.Images{Controller: "registry.example:5000/runtime:controller@sha256:" + strings.Repeat("a", 64), API: "registry.example:5000/runtime:api@sha256:" + strings.Repeat("b", 64)}
	plan := fixturePlanImages(t, "isolated-install", installrender.Profile135, images)
	quiescenceCases(t, plan, []string{"healthy", "api-only-controllers-running", "api-only-pending-controller", "orphan-bare-api-repository", "orphan-other-tag-api-repository", "api-only-controller-pod-drift"})
}

func TestQuiescenceSignedPredecessorCanQuiesceFailedRolloutWithoutAdoptingHistory(t *testing.T) {
	previous, target := lifecycleTransitionPlans(t)
	quiescenceCases(t, target, []string{"api-only-signed-predecessor", "api-only-extra-unreferenced-plan", "api-only-extra-unregistered-plan", "api-only-predecessor-pod-drift"}, previous)
}

func quiescenceCases(t *testing.T, plan *installrender.Plan, scenarios []string, others ...*installrender.Plan) {
	t.Helper()
	v, ns, baseLists := stoppedFixtureWithPlan(t, plan, others...)
	for _, scenario := range scenarios {
		t.Run(scenario, func(t *testing.T) {
			lists := map[string]runtime.Object{}
			for kind, list := range baseLists {
				lists[kind] = list.DeepCopyObject()
			}
			objects := map[installstate.Key]*unstructured.Unstructured{}
			for key, obj := range v.f.access.objects {
				objects[key] = obj.DeepCopy()
			}
			for name, secret := range v.secrets.objects {
				objects[secretKey(ns.Name, name)] = servingObject(t, secret)
			}
			currentNS := ns.DeepCopy()
			checkpoint := RuntimeStopped
			deployments := lists["Deployment"].(*appsv1.DeploymentList)
			sets := lists["ReplicaSet"].(*appsv1.ReplicaSetList)
			endpointList := lists["EndpointSlice"].(*discoveryv1.EndpointSliceList)
			pod := corev1.Pod{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"}, ObjectMeta: metav1.ObjectMeta{Name: "renamed", Namespace: ns.Name, UID: "pod-uid", ResourceVersion: "10"}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "test", Image: "unrelated.example/test"}}}}
			apiPod := pod.DeepCopy()
			apiPod.Spec.ServiceAccountName = apiFamily
			doc := v.f.snapshot.Document()
			switch scenario {
			case "nested-rs-first":
				original := sets.Items[0]
				nested := inertFixture(&deployments.Items[0], "bcdfg99999", 3)
				nested.Name, nested.UID, nested.Labels = "renamed", "nested-rs", map[string]string{"other": "label"}
				nested.Spec.Template.Labels = maps.Clone(nested.Labels)
				nested.Spec.Template.Spec = *pod.Spec.DeepCopy()
				nested.OwnerReferences = fixtureOwner("apps/v1", "ReplicaSet", original.Name, original.UID)
				nested.OwnerReferences[0].Name = "damaged-owner-name"
				sets.Items = append([]appsv1.ReplicaSet{*nested}, sets.Items...)
				pod.OwnerReferences = fixtureOwner("apps/v1", "ReplicaSet", nested.Name, nested.UID)
				lists["Pod"] = &corev1.PodList{Items: []corev1.Pod{pod}}
			case "transitive-job-owner":
				original := sets.Items[0]
				job := batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "renamed-job", Namespace: ns.Name, UID: "nested-job", ResourceVersion: "10", OwnerReferences: fixtureOwner("apps/v1", "ReplicaSet", original.Name, original.UID)}, Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{Spec: *pod.Spec.DeepCopy()}}}
				lists["Job"] = &batchv1.JobList{Items: []batchv1.Job{job}}
				pod.OwnerReferences = fixtureOwner("batch/v1", "Job", job.Name, job.UID)
				lists["Pod"] = &corev1.PodList{Items: []corev1.Pod{pod}}
			case "api-only-controllers-running", "api-only-pending-controller", "api-only-controller-pod-drift", "api-only-signed-predecessor", "api-only-extra-unreferenced-plan", "api-only-extra-unregistered-plan", "api-only-predecessor-pod-drift":
				checkpoint = APIStopped
				deployments.Items[0].Spec.Replicas = ptr.To[int32](1)
				sets.Items[0].Spec.Replicas = ptr.To[int32](1)
				sets.Items[0].Spec.Template = *deployments.Items[0].Spec.Template.DeepCopy()
				sets.Items[0].Spec.Template.Labels[appsv1.DefaultDeploymentUniqueLabelKey] = sets.Items[0].Labels[appsv1.DefaultDeploymentUniqueLabelKey]
				sets.Items[0].Labels = maps.Clone(sets.Items[0].Spec.Template.Labels)
				normal, err := v.f.engine.contracts[doc.TargetPackage].Template(deploymentKey(ns.Name, controllerFamilies[0]), false)
				if err != nil {
					t.Fatal(err)
				}
				for i := range doc.Resources {
					if doc.Resources[i].Key == normal.Key() {
						doc.Resources[i].TemplateSHA256 = normal.Hash()
					}
				}
				if strings.Contains(scenario, "predecessor") || strings.HasPrefix(scenario, "api-only-extra-") {
					if len(others) != 1 {
						t.Fatal("missing signed predecessor fixture")
					}
					if !strings.HasPrefix(scenario, "api-only-extra-") {
						doc.Mode, doc.ActivePackage = installstate.Upgrade, others[0].Digest()
					}
					old, err := v.f.engine.contracts[others[0].Digest()].Template(deploymentKey(ns.Name, controllerFamilies[0]), false)
					if err != nil {
						t.Fatal(err)
					}
					oldTemplate, err := old.PodTemplate()
					if err != nil {
						t.Fatal(err)
					}
					sets.Items[0].Spec.Template = *oldTemplate
					sets.Items[0].Spec.Template.Labels[appsv1.DefaultDeploymentUniqueLabelKey] = sets.Items[0].Labels[appsv1.DefaultDeploymentUniqueLabelKey]
					sets.Items[0].Labels = maps.Clone(sets.Items[0].Spec.Template.Labels)
				}
				if scenario != "api-only-controllers-running" {
					r := &sets.Items[0]
					p := v.access.pod.DeepCopy()
					p.ObjectMeta = metav1.ObjectMeta{Name: r.Name + "-bcdfg", GenerateName: r.Name + "-", Namespace: ns.Name, UID: "controller-pod", ResourceVersion: "10", Labels: maps.Clone(r.Spec.Template.Labels), Annotations: maps.Clone(r.Spec.Template.Annotations), OwnerReferences: fixtureOwner("apps/v1", "ReplicaSet", r.Name, r.UID)}
					// Preserve reviewed Pod-only defaults while replacing the entire
					// signed API template with the original controller template.
					projection := p.Spec.Volumes[len(p.Spec.Volumes)-1]
					mount := p.Spec.Containers[0].VolumeMounts[len(p.Spec.Containers[0].VolumeMounts)-1]
					old := p.Spec.DeepCopy()
					p.Spec = *r.Spec.Template.Spec.DeepCopy()
					p.Spec.NodeName = ""
					p.Spec.EnableServiceLinks = old.EnableServiceLinks
					p.Spec.Priority = old.Priority
					p.Spec.PreemptionPolicy = old.PreemptionPolicy
					p.Spec.Tolerations = old.Tolerations
					p.Spec.Volumes = append(p.Spec.Volumes, projection)
					p.Spec.Containers[0].VolumeMounts = append(p.Spec.Containers[0].VolumeMounts, mount)
					p.Status = corev1.PodStatus{Phase: corev1.PodPending}
					if strings.Contains(scenario, "predecessor") || strings.HasPrefix(scenario, "api-only-extra-") {
						p.Spec.NodeName = "node1"
						p.Status.Phase = corev1.PodRunning
						// The failed target is still Pending alongside its running
						// signed predecessor, just as in a stalled native rollout.
						targetSet := inertFixture(&deployments.Items[0], "bcdfg9", 6)
						targetSet.Spec.Template = *deployments.Items[0].Spec.Template.DeepCopy()
						targetSet.Spec.Template.Labels[appsv1.DefaultDeploymentUniqueLabelKey] = "bcdfg9"
						targetSet.Labels = maps.Clone(targetSet.Spec.Template.Labels)
						targetSet.Spec.Replicas = ptr.To[int32](1)
						targetPod := p.DeepCopy()
						targetPod.Name, targetPod.GenerateName, targetPod.UID = targetSet.Name+"-bcdfg", targetSet.Name+"-", "target-pending-pod"
						targetPod.Labels = maps.Clone(targetSet.Labels)
						targetPod.OwnerReferences = fixtureOwner("apps/v1", "ReplicaSet", targetSet.Name, targetSet.UID)
						targetPod.Spec.Containers = targetSet.Spec.Template.Spec.DeepCopy().Containers
						targetPod.Spec.Containers[0].VolumeMounts = append(targetPod.Spec.Containers[0].VolumeMounts, mount)
						targetPod.Spec.NodeName = ""
						targetPod.Status.Phase = corev1.PodPending
						sets.Items = append(sets.Items, *targetSet)
						lists["Pod"] = &corev1.PodList{Items: []corev1.Pod{*targetPod}}
					}
					if scenario == "api-only-controller-pod-drift" {
						p.Spec.Containers[0].Image = plan.Manifest().Images.API
					}
					if scenario == "api-only-predecessor-pod-drift" {
						p.Spec.Containers[0].Args = append(p.Spec.Containers[0].Args, "--unreviewed")
					}
					if existing, ok := lists["Pod"].(*corev1.PodList); ok {
						existing.Items = append(existing.Items, *p)
					} else {
						lists["Pod"] = &corev1.PodList{Items: []corev1.Pod{*p}}
					}
				}
			case "uninstall-controllers-removed", "controller-missing-unrecorded":
				for _, name := range controllerFamilies {
					key := deploymentKey(ns.Name, name)
					delete(objects, key)
					doc.Resources = slices.DeleteFunc(doc.Resources, func(r installstate.Resource) bool { return r.Key == key })
				}
				deployments.Items = nil
				sets.Items = nil
				if scenario == "controller-missing-unrecorded" {
					doc.Mode, doc.Stage = installstate.Install, installstate.Applying
				}
			case "api-pod", "terminal-api-pod", "deleting-api-pod":
				if scenario == "terminal-api-pod" {
					apiPod.Status.Phase = corev1.PodSucceeded
				}
				if scenario == "deleting-api-pod" {
					apiPod.DeletionTimestamp = ptr.To(metav1.Now())
				}
				lists["Pod"] = &corev1.PodList{Items: []corev1.Pod{*apiPod}}
			case "orphan-api-rs":
				r := v.access.rs.DeepCopy()
				r.Spec.Replicas = ptr.To[int32](0)
				r.Status = appsv1.ReplicaSetStatus{ObservedGeneration: r.Generation}
				sets.Items = append(sets.Items, *r)
			case "endpoint-unready", "endpoint-terminating":
				endpoint := v.access.list.Items[0].Endpoints[0].DeepCopy()
				endpoint.Conditions.Ready = ptr.To(false)
				endpoint.Conditions.Terminating = ptr.To(scenario == "endpoint-terminating")
				endpointList.Items[0].Endpoints = []discoveryv1.Endpoint{*endpoint}
			case "endpoint-replacement-service":
				endpointList.Items[0].OwnerReferences[0].UID = "replacement"
			case "endpoint-corrupted-original-owner":
				endpointList.Items[0].Name = "renamed-slice"
				endpointList.Items[0].Labels = nil
				endpointList.Items[0].OwnerReferences[0].Name = "renamed-service"
				endpointList.Items[0].Endpoints = v.access.list.Items[0].Endpoints
			case "endpoint-drained-port":
				endpointList.Items[0].Ports = v.access.list.Items[0].Ports
			case "api-deployment-survives":
				objects[deploymentKey(ns.Name, apiFamily)] = servingObject(t, v.deployment)
			case "service-missing-recorded":
				delete(objects, installstate.Key{APIVersion: "v1", Kind: "Service", Namespace: ns.Name, Name: apiFamily})
			case "service-replacement":
				objects[installstate.Key{APIVersion: "v1", Kind: "Service", Namespace: ns.Name, Name: apiFamily}].SetUID("replacement")
			case "deployment-replacement":
				deployments.Items[0].UID = "replacement"
			case "controller-stale":
				deployments.Items[0].Status.ObservedGeneration = 1
			case "controller-paused":
				deployments.Items[0].Spec.Paused = true
			case "controller-ready":
				deployments.Items[0].Status.ReadyReplicas = 1
			case "controller-missing-recorded":
				delete(objects, deploymentKey(ns.Name, controllerFamilies[0]))
				deployments.Items = deployments.Items[1:]
			case "unknown-rs-running":
				sets.Items[0].Spec.Replicas = ptr.To[int32](1)
			case "controller-pod-by-owner-uid":
				pod.OwnerReferences = fixtureOwner("apps/v1", "ReplicaSet", "renamed-owner", sets.Items[0].UID)
				lists["Pod"] = &corev1.PodList{Items: []corev1.Pod{pod}}
			case "daemonset-zero":
				lists["DaemonSet"] = &appsv1.DaemonSetList{Items: []appsv1.DaemonSet{{ObjectMeta: apiPod.ObjectMeta, Spec: appsv1.DaemonSetSpec{Template: corev1.PodTemplateSpec{Spec: apiPod.Spec}}}}}
			case "statefulset-zero":
				lists["StatefulSet"] = &appsv1.StatefulSetList{Items: []appsv1.StatefulSet{{ObjectMeta: apiPod.ObjectMeta, Spec: appsv1.StatefulSetSpec{Replicas: ptr.To[int32](0), Template: corev1.PodTemplateSpec{Spec: apiPod.Spec}}}}}
			case "cronjob-suspended":
				lists["CronJob"] = &batchv1.CronJobList{Items: []batchv1.CronJob{{ObjectMeta: apiPod.ObjectMeta, Spec: batchv1.CronJobSpec{Suspend: ptr.To(true), JobTemplate: batchv1.JobTemplateSpec{Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{Spec: apiPod.Spec}}}}}}}
			case "job-terminal":
				lists["Job"] = &batchv1.JobList{Items: []batchv1.Job{{ObjectMeta: apiPod.ObjectMeta, Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{Spec: apiPod.Spec}}, Status: batchv1.JobStatus{Succeeded: 1}}}}
			case "replicationcontroller-zero":
				lists["ReplicationController"] = &corev1.ReplicationControllerList{Items: []corev1.ReplicationController{{ObjectMeta: apiPod.ObjectMeta, Spec: corev1.ReplicationControllerSpec{Replicas: ptr.To[int32](0), Template: &corev1.PodTemplateSpec{Spec: apiPod.Spec}}}}}
			case "secret-env":
				pod.Spec.Containers[0].Env = []corev1.EnvVar{{Name: "AUTH", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "arcadectl-admin-credential"}, Key: "auth.json"}}}}
				lists["Pod"] = &corev1.PodList{Items: []corev1.Pod{pod}}
			case "secret-projected":
				pod.Spec.Volumes = []corev1.Volume{{Name: "auth", VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{Sources: []corev1.VolumeProjection{{Secret: &corev1.SecretProjection{LocalObjectReference: corev1.LocalObjectReference{Name: "arcadectl-api-tls"}}}}}}}}
				lists["Pod"] = &corev1.PodList{Items: []corev1.Pod{pod}}
			case "init-api-image":
				pod.Spec.InitContainers = []corev1.Container{{Name: "init", Image: v.f.plan.Manifest().Images.API}}
				lists["Pod"] = &corev1.PodList{Items: []corev1.Pod{pod}}
			case "ephemeral-api-image":
				pod.Spec.EphemeralContainers = []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug", Image: v.f.plan.Manifest().Images.API}}}
				lists["Pod"] = &corev1.PodList{Items: []corev1.Pod{pod}}
			case "orphan-bare-api-repository", "orphan-other-tag-api-repository":
				checkpoint = APIStopped
				pod.Spec.Containers[0].Image = imageRepository(plan.Manifest().Images.API) + "@sha256:" + strings.Repeat("b", 64)
				if scenario == "orphan-other-tag-api-repository" {
					pod.Spec.Containers[0].Image = imageRepository(plan.Manifest().Images.API) + ":other"
				}
				lists["Pod"] = &corev1.PodList{Items: []corev1.Pod{pod}}
			case "unrelated-pod-renewal":
				lists["Pod"] = &corev1.PodList{Items: []corev1.Pod{pod}}
			case "unrelated-empty-slice":
				item := endpointList.Items[0].DeepCopy()
				item.Name = "other-bcdfg"
				item.GenerateName = "other-"
				item.UID = "other-slice"
				item.OwnerReferences = nil
				item.Labels = nil
				endpointList.Items = append(endpointList.Items, *item)
			}
			// Mirror the independently GET-read controller objects unless testing
			// a deliberate list/GET identity contradiction.
			for i := range deployments.Items {
				item := &deployments.Items[i]
				key := deploymentKey(ns.Name, item.Name)
				if objects[key] != nil && scenario != "deployment-replacement" {
					objects[key] = servingObject(t, item)
				}
			}
			if scenario == "uninstall-controllers-removed" || scenario == "controller-missing-unrecorded" || strings.HasPrefix(scenario, "api-only-") {
				body, err := installstate.Encode(doc, append([]*installrender.Plan{v.f.plan}, others...)...)
				if err != nil {
					t.Fatal(err)
				}
				currentNS.Annotations[installstate.Annotation] = string(body)
			}
			observations := 0
			routes := []string{}
			access := quiescenceServer(t, func(w http.ResponseWriter, r *http.Request) {
				routes = append(routes, r.URL.Path)
				w.Header().Set("Content-Type", "application/json")
				if r.Method != http.MethodGet {
					t.Error("runtime proof attempted mutation")
				}
				resources := map[string]map[string]metav1.APIResource{}
				add := func(gv, kind, plural string, namespaced bool) {
					if resources[gv] == nil {
						resources[gv] = map[string]metav1.APIResource{}
					}
					resources[gv][kind] = metav1.APIResource{Name: plural, Kind: kind, Namespaced: namespaced, Verbs: metav1.Verbs{"get", "list"}}
				}
				for _, c := range proofCollections {
					add(c.gv, c.kind, c.plural, c.namespaced)
				}
				for key := range objects {
					path, err := resourcePath(key, true)
					if err == nil {
						parts := strings.Split(path, "/")
						add(key.APIVersion, key.Kind, parts[len(parts)-1], key.Namespace != "")
					}
				}
				add("v1", "Namespace", "namespaces", false)
				for gv, items := range resources {
					path, _ := discoveryPath(gv)
					if path == r.URL.Path {
						list := metav1.APIResourceList{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "APIResourceList"}, GroupVersion: gv}
						for _, item := range items {
							list.APIResources = append(list.APIResources, item)
						}
						_ = json.NewEncoder(w).Encode(list)
						return
					}
				}
				if r.URL.Path == "/api/v1/namespaces/"+ns.Name {
					copy := currentNS.DeepCopy()
					copy.APIVersion, copy.Kind = "v1", "Namespace"
					if observations >= 2 && scenario == "journal-rv" {
						copy.ResourceVersion = "changed"
					}
					if observations >= 2 && scenario == "namespace-uid" {
						copy.UID = "replacement"
					}
					encodeStoppedObject(t, w, r, servingObject(t, copy))
					return
				}
				for _, c := range proofCollections {
					path := "/apis/" + c.gv
					if c.gv == "v1" {
						path = "/api/v1"
					}
					if c.namespaced {
						path += "/namespaces/" + ns.Name
					}
					path += "/" + c.plural
					if path != r.URL.Path {
						continue
					}
					if c.kind == "GameServer" {
						observations++
					}
					if c.kind == "EndpointSlice" && (scenario == "missing-endpoint-list" || scenario == "endpoint-page-failure" && r.URL.Query().Get("continue") != "") {
						w.WriteHeader(403)
						_, _ = w.Write([]byte("PRIVATE-CANARY"))
						return
					}
					items := []any{}
					if list := lists[c.kind]; list != nil {
						raw, err := runtime.DefaultUnstructuredConverter.ToUnstructured(list.DeepCopyObject())
						if err != nil {
							t.Fatal(err)
						}
						if values, ok := raw["items"].([]any); ok {
							items = values
						}
					}
					if c.kind == "Secret" {
						for key, obj := range objects {
							if key.Kind == "Secret" {
								items = append(items, map[string]any{"metadata": map[string]any{"name": obj.GetName(), "namespace": obj.GetNamespace(), "uid": obj.GetUID(), "resourceVersion": obj.GetResourceVersion()}})
							}
						}
					}
					for _, item := range items {
						obj := item.(map[string]any)
						obj["apiVersion"], obj["kind"] = c.gv, c.kind
						if c.kind == "Secret" {
							obj["apiVersion"], obj["kind"] = "meta.k8s.io/v1", "PartialObjectMetadata"
						}
						if observations >= 2 && scenario == "rs-rv-second" && c.kind == "ReplicaSet" {
							obj["metadata"].(map[string]any)["resourceVersion"] = "changed"
						}
						if observations >= 2 && scenario == "unrelated-pod-renewal" && c.kind == "Pod" {
							obj["metadata"].(map[string]any)["resourceVersion"] = "changed"
						}
					}
					if observations >= 2 && scenario == "pod-second" && c.kind == "Pod" {
						items = append(items, servingObject(t, apiPod).Object)
					}
					meta := map[string]any{"resourceVersion": "20"}
					if scenario == "endpoint-page-failure" && c.kind == "EndpointSlice" {
						meta["continue"] = "second-page"
					}
					gv, kind := c.gv, c.kind+"List"
					if c.kind == "Secret" {
						gv, kind = "meta.k8s.io/v1", "PartialObjectMetadataList"
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"apiVersion": gv, "kind": kind, "metadata": meta, "items": items})
					return
				}
				for key, obj := range objects {
					path, err := resourcePath(key, false)
					if key.Kind == "Secret" {
						path, err = privateSecretPath(key, false)
					}
					if err != nil || path != r.URL.Path {
						continue
					}
					copy := obj.DeepCopy()
					if observations >= 2 && scenario == "controller-rv-second" && key == deploymentKey(ns.Name, controllerFamilies[0]) {
						copy.SetResourceVersion("changed")
					}
					encodeStoppedObject(t, w, r, copy)
					return
				}
				w.WriteHeader(http.StatusNotFound)
				_ = json.NewEncoder(w).Encode(metav1.Status{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: metav1.StatusFailure, Reason: metav1.StatusReasonNotFound, Code: 404})
			})
			registered := append([]*installrender.Plan{v.f.plan}, others...)
			if scenario == "api-only-extra-unregistered-plan" {
				registered = registered[:1]
			}
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
			q, err := NewClusterQuiescence(p)
			if err != nil {
				t.Fatal(err)
			}
			input, err := store.Load(context.Background(), v.f.snapshot.Anchor())
			if err != nil {
				t.Fatal(err)
			}
			request := LifecycleCheck{Checkpoint: checkpoint, Snapshot: input, Mode: input.Document().Mode, Target: v.f.plan, Options: LifecycleOptions{Now: time.Now().UTC()}}
			err = q.Verify(context.Background(), request)
			valid := scenario == "healthy" || scenario == "api-only-controllers-running" || scenario == "api-only-pending-controller" || scenario == "api-only-signed-predecessor" || scenario == "endpoint-drained-port" || scenario == "uninstall-controllers-removed" || scenario == "unrelated-pod-renewal" || scenario == "unrelated-empty-slice"
			if (err == nil) != valid || err != nil && err != ErrQuiescence {
				t.Fatalf("shutdown evidence incorrect: %v, observations=%d routes=%v", err, observations, routes)
			}
			if valid && observations != 2 {
				t.Fatal("proof skipped repeated complete observation")
			}
			if valid {
				if scenario == "api-only-signed-predecessor" {
					request.Checkpoint = RuntimeStopped
					if q.Verify(context.Background(), request) != ErrQuiescence {
						t.Fatal("predecessor execution substituted for stopped runtime")
					}
				}
				request.Checkpoint = ControllersAvailable
				if q.Verify(context.Background(), request) != ErrInvalid {
					t.Fatal("partial proof substituted for readiness")
				}
				request.Checkpoint = checkpoint
				request.Mode = installstate.Rollback
				if q.Verify(context.Background(), request) != ErrInvalid {
					t.Fatal("foreign operation accepted")
				}
				engine.access = &HTTPAccess{}
				if _, err := NewClusterQuiescence(p); err != ErrInvalid {
					t.Fatal("foreign cluster accepted")
				}
			}
		})
	}
}

func quiescenceServer(t *testing.T, handler http.HandlerFunc) *HTTPAccess {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	config := serverConfig(server)
	// Avoid SDK throttling an in-process fixture. Collection bounds and static
	// cluster identity stay exactly the production observer's contract.
	config.QPS, config.Burst = 100, 200
	access, err := NewHTTPAccess(config)
	if err != nil {
		t.Fatal(err)
	}
	return access
}

func encodeStoppedObject(t *testing.T, w http.ResponseWriter, r *http.Request, obj *unstructured.Unstructured) {
	t.Helper()
	if strings.Contains(r.Header.Get("Accept"), "as=PartialObjectMetadata;") {
		obj = &unstructured.Unstructured{Object: map[string]any{"apiVersion": "meta.k8s.io/v1", "kind": "PartialObjectMetadata", "metadata": obj.Object["metadata"]}}
	}
	if json.NewEncoder(w).Encode(obj.Object) != nil {
		t.Error("fixture encoding")
	}
}

func TestQuiescenceServingDecodeRefusesCaseAliases(t *testing.T) {
	for _, field := range []string{"Spec", "STATUS", "Metadata", "APIVersion", "Kind"} {
		object := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "v1", "kind": "Pod", field: map[string]any{}}}
		if decodeServing(object, &corev1.Pod{}) != ErrServing {
			t.Fatal("case alias accepted", field)
		}
	}
}
