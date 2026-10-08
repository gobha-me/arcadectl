// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"encoding/json"
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installpackage"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
)

func readyControllerFixture(t *testing.T, plan *installrender.Plan, others ...*installrender.Plan) (*servingFixture, *corev1.Namespace, map[string]runtime.Object) {
	t.Helper()
	v, ns, lists := stoppedFixtureWithPlan(t, plan, others...)
	d := v.f.snapshot.Document()
	d.Mode, d.Stage, d.ActivePackage, d.Installed = installstate.Install, installstate.Applying, "", false
	d.Revision++
	deployments := lists["Deployment"].(*appsv1.DeploymentList)
	sets := lists["ReplicaSet"].(*appsv1.ReplicaSetList)
	pods := &corev1.PodList{}
	for i := range deployments.Items {
		parent := &deployments.Items[i]
		parent.Spec.Replicas = ptr.To[int32](1)
		parent.Status = appsv1.DeploymentStatus{ObservedGeneration: parent.Generation, Replicas: 1, UpdatedReplicas: 1, ReadyReplicas: 1, AvailableReplicas: 1}
		template, err := v.f.engine.contracts[d.TargetPackage].Template(deploymentKey(ns.Name, parent.Name), false)
		if err != nil {
			t.Fatal(err)
		}
		for j := range d.Resources {
			if d.Resources[j].Key == template.Key() {
				d.Resources[j].TemplateSHA256 = template.Hash()
			}
		}
		v.f.access.objects[template.Key()] = servingObject(t, parent)
		set := inertFixture(parent, "bcdfg23456", 6)
		set.CreationTimestamp = metav1.NewTime(time.Unix(100, 0).UTC())
		set.Spec.Template = *parent.Spec.Template.DeepCopy()
		set.Spec.Template.Labels[appsv1.DefaultDeploymentUniqueLabelKey] = "bcdfg23456"
		set.Labels = maps.Clone(set.Spec.Template.Labels)
		set.Annotations[installstate.MutationAnnotation] = parent.Annotations[installstate.MutationAnnotation]
		set.Spec.Replicas = ptr.To[int32](1)
		set.Status = appsv1.ReplicaSetStatus{ObservedGeneration: set.Generation, Replicas: 1, FullyLabeledReplicas: 1, ReadyReplicas: 1, AvailableReplicas: 1}
		sets.Items = append(sets.Items, *set)
		pod := v.access.pod.DeepCopy()
		pod.ObjectMeta = metav1.ObjectMeta{Name: set.Name + "-bcdfg", GenerateName: set.Name + "-", Namespace: ns.Name, UID: set.UID + "-pod", ResourceVersion: "10", Labels: maps.Clone(set.Spec.Template.Labels), Annotations: maps.Clone(set.Spec.Template.Annotations), OwnerReferences: fixtureOwner("apps/v1", "ReplicaSet", set.Name, set.UID)}
		old := pod.Spec.DeepCopy()
		projection, mount := old.Volumes[len(old.Volumes)-1], old.Containers[0].VolumeMounts[len(old.Containers[0].VolumeMounts)-1]
		pod.Spec = *set.Spec.Template.Spec.DeepCopy()
		pod.Spec.NodeName, pod.Spec.EnableServiceLinks, pod.Spec.Priority, pod.Spec.PreemptionPolicy, pod.Spec.Tolerations = old.NodeName, old.EnableServiceLinks, old.Priority, old.PreemptionPolicy, old.Tolerations
		pod.Spec.Volumes = append(pod.Spec.Volumes, projection)
		pod.Spec.Containers[0].VolumeMounts = append(pod.Spec.Containers[0].VolumeMounts, mount)
		pod.Status.ContainerStatuses[0].Name = pod.Spec.Containers[0].Name
		pods.Items = append(pods.Items, *pod)
	}
	for i := range sets.Items {
		if sets.Items[i].CreationTimestamp.IsZero() {
			sets.Items[i].CreationTimestamp = metav1.NewTime(time.Unix(50, 0).UTC())
		}
	}
	lists["Pod"] = pods
	body, err := installstate.Encode(d, plan)
	if err != nil {
		t.Fatal(err)
	}
	ns.Annotations[installstate.Annotation] = string(body)
	return v, ns, lists
}

// Actual frozen HTTPAccess + sealed production observer, including all twenty
// collections, metadata-only Secrets and original Namespace/journal barriers.
func controllerProofAccess(t *testing.T, ns *corev1.Namespace, objects map[installstate.Key]*unstructured.Unstructured, lists map[string]runtime.Object, onObservation func(int), fault string) (*HTTPAccess, func() int) {
	return controllerProofAccessWithRequests(t, ns, objects, lists, onObservation, fault, nil)
}

func controllerProofAccessWithRequests(t *testing.T, ns *corev1.Namespace, objects map[installstate.Key]*unstructured.Unstructured, lists map[string]runtime.Object, onObservation func(int), fault string, beforeRequest func(http.ResponseWriter, *http.Request) bool) (*HTTPAccess, func() int) {
	t.Helper()
	var mutex sync.Mutex
	observations := 0
	access := quiescenceServer(t, func(w http.ResponseWriter, request *http.Request) {
		mutex.Lock()
		defer mutex.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if beforeRequest != nil && beforeRequest(w, request) {
			return
		}
		if request.Method != http.MethodGet {
			t.Error("readiness proof attempted mutation")
		}
		groups := map[string][]metav1.APIResource{}
		add := func(gv, kind, plural string, namespaced bool) {
			for _, old := range groups[gv] {
				if old.Kind == kind {
					return
				}
			}
			groups[gv] = append(groups[gv], metav1.APIResource{Name: plural, Kind: kind, Namespaced: namespaced, Verbs: metav1.Verbs{"get", "list"}})
		}
		for _, collection := range proofCollections {
			add(collection.gv, collection.kind, collection.plural, collection.namespaced)
		}
		add("v1", "Namespace", "namespaces", false)
		for key := range objects {
			path, err := resourcePath(key, true)
			if key.Kind == "Secret" {
				path, err = privateSecretPath(key, true)
			}
			if err == nil {
				add(key.APIVersion, key.Kind, path[strings.LastIndex(path, "/")+1:], key.Namespace != "")
			}
		}
		for gv, resources := range groups {
			path, _ := discoveryPath(gv)
			if request.URL.Path == path {
				_ = json.NewEncoder(w).Encode(metav1.APIResourceList{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "APIResourceList"}, GroupVersion: gv, APIResources: resources})
				return
			}
		}
		if request.URL.Path == "/api/v1/namespaces/"+ns.Name {
			copy := ns.DeepCopy()
			copy.APIVersion, copy.Kind = "v1", "Namespace"
			encodeStoppedObject(t, w, request, servingObject(t, copy))
			return
		}
		for _, collection := range proofCollections {
			path := "/apis/" + collection.gv
			if collection.gv == "v1" {
				path = "/api/v1"
			}
			if collection.namespaced {
				path += "/namespaces/" + ns.Name
			}
			path += "/" + collection.plural
			if request.URL.Path != path {
				continue
			}
			if collection.kind == "GameServer" {
				observations++
				if onObservation != nil {
					onObservation(observations)
				}
			}
			if fault == "missing-pods" && collection.kind == "Pod" || fault == "page-failure" && collection.kind == "ReplicaSet" && request.URL.Query().Get("continue") != "" {
				w.WriteHeader(403)
				_, _ = w.Write([]byte("PRIVATE-CANARY"))
				return
			}
			items := []any{}
			if list := lists[collection.kind]; list != nil {
				raw, err := runtime.DefaultUnstructuredConverter.ToUnstructured(list.DeepCopyObject())
				if err != nil {
					t.Error(err)
					return
				}
				if values, ok := raw["items"].([]any); ok {
					items = values
				}
			}
			if collection.kind == "Secret" {
				for key, object := range objects {
					if key.Kind == "Secret" {
						items = append(items, map[string]any{"metadata": map[string]any{"name": object.GetName(), "namespace": key.Namespace, "uid": object.GetUID(), "resourceVersion": object.GetResourceVersion()}})
					}
				}
			}
			gv, kind := collection.gv, collection.kind+"List"
			if collection.kind == "Secret" {
				gv, kind = "meta.k8s.io/v1", "PartialObjectMetadataList"
			}
			for _, item := range items {
				item.(map[string]any)["apiVersion"], item.(map[string]any)["kind"] = collection.gv, collection.kind
				if collection.kind == "Secret" {
					item.(map[string]any)["apiVersion"], item.(map[string]any)["kind"] = "meta.k8s.io/v1", "PartialObjectMetadata"
				}
			}
			metadata := map[string]any{"resourceVersion": "20"}
			if fault == "page-failure" && collection.kind == "ReplicaSet" {
				metadata["continue"] = "second-page"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"apiVersion": gv, "kind": kind, "metadata": metadata, "items": items})
			return
		}
		for key, object := range objects {
			path, err := resourcePath(key, false)
			if key.Kind == "Secret" {
				path, err = privateSecretPath(key, false)
			}
			if err == nil && request.URL.Path == path {
				encodeStoppedObject(t, w, request, object.DeepCopy())
				return
			}
		}
		w.WriteHeader(404)
		_ = json.NewEncoder(w).Encode(metav1.Status{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: metav1.StatusFailure, Reason: metav1.StatusReasonNotFound, Code: 404})
	})
	return access, func() int { mutex.Lock(); defer mutex.Unlock(); return observations }
}

func TestControllersAvailablePinsExactTargetAndAllDescendants(t *testing.T) {
	controllerCases(t, fixturePlan(t), []string{"healthy", "verifying", "sa-replacement", "sa-drift", "sa-missing", "deployment-replacement", "deployment-stale", "deployment-terminating", "deployment-paused", "set-stale", "set-unavailable", "set-terminating", "set-wrong-max", "set-revision", "set-nonce", "pod-pending", "pod-unscheduled", "pod-terminal", "pod-deleting", "pod-status-name", "pod-image-drift", "pod-sidecar", "pod-extra", "pod-orphan-original-uid", "historical-pod", "history-executable", "duplicate-target-inert", "oldest-zero-matching", "name-tie-zero", "nested-first-uid", "nested-template-role", "selector-orphan", "job-template-role", "missing-pods", "page-failure", "journal-race", "namespace-replaced", "deployment-second-rv", "sa-second-rv", "set-second-rv", "pod-second-rv", "unrelated-churn"})
}

func TestControllersAvailableSharedRepositoryDoesNotInventWorkerAuthority(t *testing.T) {
	images := installpackage.Images{Controller: "registry.example:5000/runtime:controller@sha256:" + strings.Repeat("a", 64), API: "registry.example:5000/runtime:api@sha256:" + strings.Repeat("b", 64)}
	controllerCases(t, fixturePlanImages(t, "isolated-install", installrender.Profile135, images), []string{"healthy", "shared-api-worker", "pod-image-drift", "job-template-role"})
}

func TestControllersAvailableUpgradeAndRollbackRequireTargetNotActive(t *testing.T) {
	previous, target := lifecycleTransitionPlans(t)
	controllerCases(t, target, []string{"upgrade-target", "upgrade-active-only"}, previous)
	controllerCases(t, previous, []string{"rollback-target", "rollback-active-only"}, target)
}

func TestControllersAvailableClosesAllBuiltinAndRecursiveOwnerSignals(t *testing.T) {
	controllerCases(t, fixturePlan(t), []string{"daemon-template-role", "stateful-template-role", "cron-template-role", "rc-template-role", "transitive-job-owner", "recursive-owner-pod"})
}

func TestControllersAvailableClosesEveryObservedClusterMetadataKind(t *testing.T) {
	controllerCases(t, fixturePlan(t), []string{"foreign-policy-bridge", "foreign-binding-bridge", "foreign-attachment-bridge"})
}

func controllerCases(t *testing.T, plan *installrender.Plan, scenarios []string, others ...*installrender.Plan) {
	t.Helper()
	v, baseNS, baseLists := readyControllerFixture(t, plan, others...)
	for _, scenario := range scenarios {
		t.Run(scenario, func(t *testing.T) {
			ns := baseNS.DeepCopy()
			lists := map[string]runtime.Object{}
			for kind, list := range baseLists {
				lists[kind] = list.DeepCopyObject()
			}
			objects := map[installstate.Key]*unstructured.Unstructured{}
			for key, object := range v.f.access.objects {
				objects[key] = object.DeepCopy()
			}
			for name, secret := range v.secrets.objects {
				objects[secretKey(ns.Name, name)] = servingObject(t, secret)
			}
			parents := lists["Deployment"].(*appsv1.DeploymentList)
			sets := lists["ReplicaSet"].(*appsv1.ReplicaSetList)
			pods := lists["Pod"].(*corev1.PodList)
			parent := &parents.Items[0]
			current := &sets.Items[len(sets.Items)-2]
			pod := &pods.Items[0]
			accountKey := installstate.Key{APIVersion: "v1", Kind: "ServiceAccount", Namespace: ns.Name, Name: parent.Name}
			valid := slices.Contains([]string{"healthy", "verifying", "duplicate-target-inert", "unrelated-churn", "shared-api-worker", "upgrade-target", "rollback-target"}, scenario)
			switch scenario {
			case "foreign-policy-bridge", "foreign-binding-bridge", "foreign-attachment-bridge":
				metadata := metav1.ObjectMeta{Name: "foreign-bridge", UID: "bridge-uid", ResourceVersion: "10", OwnerReferences: fixtureOwner("apps/v1", "Deployment", "damaged-owner-name", parent.UID)}
				kind, version := "ValidatingAdmissionPolicy", "admissionregistration.k8s.io/v1"
				switch scenario {
				case "foreign-policy-bridge":
					lists["ValidatingAdmissionPolicy"] = &admissionv1.ValidatingAdmissionPolicyList{Items: []admissionv1.ValidatingAdmissionPolicy{{ObjectMeta: metadata}}}
				case "foreign-binding-bridge":
					kind = "ValidatingAdmissionPolicyBinding"
					lists[kind] = &admissionv1.ValidatingAdmissionPolicyBindingList{Items: []admissionv1.ValidatingAdmissionPolicyBinding{{ObjectMeta: metadata}}}
				case "foreign-attachment-bridge":
					kind, version = "VolumeAttachment", "storage.k8s.io/v1"
					lists[kind] = &storagev1.VolumeAttachmentList{Items: []storagev1.VolumeAttachment{{ObjectMeta: metadata}}}
				}
				child := v.access.pod.DeepCopy()
				child.Name, child.UID = "unrelated-looking-child", "child-uid"
				child.OwnerReferences = fixtureOwner(version, kind, metadata.Name, metadata.UID)
				pods.Items = append(pods.Items, *child)
			case "upgrade-target", "upgrade-active-only", "rollback-target", "rollback-active-only":
				doc, err := installstate.Decode([]byte(ns.Annotations[installstate.Annotation]), plan, others[0])
				if err != nil {
					t.Fatal(err)
				}
				doc.Mode, doc.ActivePackage, doc.Installed = installstate.Upgrade, others[0].Digest(), true
				if strings.HasPrefix(scenario, "rollback-") {
					doc.Mode, doc.PreviousPackage = installstate.Rollback, plan.Digest()
				}
				if strings.HasSuffix(scenario, "active-only") {
					active, err := v.f.engine.contracts[doc.ActivePackage].Template(deploymentKey(ns.Name, parent.Name), false)
					if err != nil {
						t.Fatal(err)
					}
					template, err := active.PodTemplate()
					if err != nil {
						t.Fatal(err)
					}
					parent.Spec.Template = *template
					for i := range doc.Resources {
						if doc.Resources[i].Key == active.Key() {
							doc.Resources[i].TemplateSHA256 = active.Hash()
						}
					}
				}
				body, err := installstate.Encode(doc, plan, others[0])
				if err != nil {
					t.Fatal(err)
				}
				ns.Annotations[installstate.Annotation] = string(body)
			case "verifying":
				doc, err := installstate.Decode([]byte(ns.Annotations[installstate.Annotation]), plan)
				if err != nil {
					t.Fatal(err)
				}
				doc.Stage = installstate.Verifying
				body, err := installstate.Encode(doc, plan)
				if err != nil {
					t.Fatal(err)
				}
				ns.Annotations[installstate.Annotation] = string(body)
			case "sa-replacement":
				objects[accountKey].SetUID("replacement")
			case "sa-drift":
				objects[accountKey].Object["automountServiceAccountToken"] = false
			case "sa-missing":
				delete(objects, accountKey)
			case "deployment-replacement":
				parent.UID = "replacement"
			case "deployment-stale":
				parent.Status.ObservedGeneration--
			case "deployment-terminating":
				parent.Status.TerminatingReplicas = ptr.To[int32](1)
			case "deployment-paused":
				parent.Spec.Paused = true
			case "set-stale":
				current.Status.ObservedGeneration--
			case "set-unavailable":
				current.Status.AvailableReplicas = 0
			case "set-terminating":
				current.Status.TerminatingReplicas = ptr.To[int32](1)
			case "set-wrong-max":
				current.Annotations["deployment.kubernetes.io/max-replicas"] = "1"
			case "set-revision":
				current.Annotations["deployment.kubernetes.io/revision"] = "5"
			case "set-nonce":
				current.Annotations[installstate.MutationAnnotation] = strings.Repeat("e", 32)
			case "pod-pending":
				pod.Status.Phase = corev1.PodPending
			case "pod-unscheduled":
				pod.Spec.NodeName = ""
			case "pod-terminal":
				pod.Status.Phase = corev1.PodSucceeded
			case "pod-deleting":
				now := metav1.Now()
				pod.DeletionTimestamp = &now
			case "pod-status-name":
				pod.Status.ContainerStatuses[0].Name = "api"
			case "pod-image-drift":
				pod.Spec.Containers[0].Image = plan.Manifest().Images.API
			case "pod-sidecar":
				pod.Spec.Containers = append(pod.Spec.Containers, corev1.Container{Name: "sidecar", Image: "other.example/image"})
			case "pod-extra":
				extra := pod.DeepCopy()
				extra.Name += "x"
				extra.UID += "x"
				pods.Items = append(pods.Items, *extra)
			case "pod-orphan-original-uid":
				pod.Name, pod.GenerateName, pod.Labels, pod.Spec.ServiceAccountName = "renamed", "", nil, "other"
				pod.OwnerReferences[0].Name, pod.OwnerReferences[0].Kind, pod.OwnerReferences[0].Controller = "other", "ConfigMap", ptr.To(false)
			case "historical-pod":
				pod.OwnerReferences = fixtureOwner("apps/v1", "ReplicaSet", sets.Items[0].Name, sets.Items[0].UID)
			case "history-executable":
				sets.Items[0].Spec.Replicas = ptr.To[int32](1)
			case "duplicate-target-inert", "oldest-zero-matching", "name-tie-zero":
				extra := inertFixture(parent, "bcdfg11111", 6)
				extra.Spec.Template = *current.Spec.Template.DeepCopy()
				extra.Spec.Template.Labels[appsv1.DefaultDeploymentUniqueLabelKey] = "bcdfg11111"
				extra.Labels = maps.Clone(extra.Spec.Template.Labels)
				extra.CreationTimestamp = metav1.NewTime(time.Unix(110, 0).UTC())
				if scenario == "oldest-zero-matching" {
					extra.CreationTimestamp = metav1.NewTime(time.Unix(90, 0).UTC())
				}
				if scenario == "name-tie-zero" {
					extra.CreationTimestamp = current.CreationTimestamp
				}
				sets.Items = append(sets.Items, *extra)
			case "nested-first-uid", "nested-template-role", "selector-orphan":
				extra := inertFixture(parent, "bcdfg11111", 4)
				extra.Name, extra.UID, extra.Labels = "renamed-set", "nested-set", map[string]string{"other": "label"}
				extra.Spec.Template.Labels = maps.Clone(extra.Labels)
				extra.Spec.Template.Spec.ServiceAccountName = "other"
				extra.OwnerReferences = nil
				if scenario == "nested-first-uid" {
					extra.OwnerReferences = fixtureOwner("apps/v1", "ReplicaSet", current.Name, current.UID)
					extra.OwnerReferences[0].Name = "damaged-owner-name"
				}
				if scenario == "nested-template-role" {
					extra.Spec.Template.Spec.ServiceAccountName = parent.Name
				}
				if scenario == "selector-orphan" {
					extra.Spec.Template.Labels = maps.Clone(parent.Spec.Selector.MatchLabels)
				}
				sets.Items = append([]appsv1.ReplicaSet{*extra}, sets.Items...)
			case "job-template-role":
				lists["Job"] = &batchv1.JobList{Items: []batchv1.Job{{ObjectMeta: metav1.ObjectMeta{Name: "renamed-job", Namespace: ns.Name, UID: "job-uid", ResourceVersion: "10"}, Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{ServiceAccountName: parent.Name}}}}}}
			case "daemon-template-role", "stateful-template-role", "cron-template-role", "rc-template-role", "transitive-job-owner":
				metadata := metav1.ObjectMeta{Name: "renamed", Namespace: ns.Name, UID: "other-workload", ResourceVersion: "10"}
				template := corev1.PodTemplateSpec{Spec: corev1.PodSpec{ServiceAccountName: parent.Name}}
				switch scenario {
				case "daemon-template-role":
					lists["DaemonSet"] = &appsv1.DaemonSetList{Items: []appsv1.DaemonSet{{ObjectMeta: metadata, Spec: appsv1.DaemonSetSpec{Template: template}}}}
				case "stateful-template-role":
					lists["StatefulSet"] = &appsv1.StatefulSetList{Items: []appsv1.StatefulSet{{ObjectMeta: metadata, Spec: appsv1.StatefulSetSpec{Template: template, Replicas: ptr.To[int32](0)}}}}
				case "cron-template-role":
					lists["CronJob"] = &batchv1.CronJobList{Items: []batchv1.CronJob{{ObjectMeta: metadata, Spec: batchv1.CronJobSpec{Suspend: ptr.To(true), JobTemplate: batchv1.JobTemplateSpec{Spec: batchv1.JobSpec{Template: template}}}}}}
				case "rc-template-role":
					lists["ReplicationController"] = &corev1.ReplicationControllerList{Items: []corev1.ReplicationController{{ObjectMeta: metadata, Spec: corev1.ReplicationControllerSpec{Template: &template, Replicas: ptr.To[int32](0)}}}}
				case "transitive-job-owner":
					metadata.OwnerReferences = fixtureOwner("apps/v1", "ReplicaSet", current.Name, current.UID)
					lists["Job"] = &batchv1.JobList{Items: []batchv1.Job{{ObjectMeta: metadata, Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{ServiceAccountName: "other"}}}}}}
					child := v.access.pod.DeepCopy()
					child.Name, child.UID = "renamed-child", "child-uid"
					child.OwnerReferences = fixtureOwner("batch/v1", "Job", metadata.Name, metadata.UID)
					pods.Items = append(pods.Items, *child)
				}
			case "recursive-owner-pod":
				bridge := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "bridge", Namespace: ns.Name, UID: "bridge-uid", ResourceVersion: "10", OwnerReferences: fixtureOwner("apps/v1", "Deployment", parent.Name, parent.UID)}}
				objects[installstate.Key{APIVersion: "v1", Kind: "ConfigMap", Namespace: ns.Name, Name: bridge.Name}] = servingObject(t, bridge)
				lists["PersistentVolumeClaim"] = &corev1.PersistentVolumeClaimList{Items: []corev1.PersistentVolumeClaim{{ObjectMeta: metav1.ObjectMeta{Name: "world", Namespace: ns.Name, UID: "claim-uid", ResourceVersion: "10", OwnerReferences: fixtureOwner("v1", "ConfigMap", bridge.Name, bridge.UID)}}}}
				child := v.access.pod.DeepCopy()
				child.Name, child.UID = "renamed-child", "child-uid"
				child.OwnerReferences = fixtureOwner("v1", "ConfigMap", bridge.Name, bridge.UID)
				pods.Items = append(pods.Items, *child)
			case "shared-api-worker", "unrelated-churn":
				lists["Job"] = &batchv1.JobList{Items: []batchv1.Job{{ObjectMeta: metav1.ObjectMeta{Name: "worker", Namespace: ns.Name, UID: "job-uid", ResourceVersion: "10"}, Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{ServiceAccountName: "bounded-worker", Containers: []corev1.Container{{Name: "worker", Image: plan.Manifest().Images.Controller}}}}}}}}
				pods.Items = append(pods.Items, *v.access.pod.DeepCopy())
			}
			for i := range parents.Items {
				objects[deploymentKey(ns.Name, parents.Items[i].Name)] = servingObject(t, &parents.Items[i])
			}
			if scenario == "shared-api-worker" || scenario == "unrelated-churn" {
				sets.Items = append(sets.Items, *v.access.rs.DeepCopy())
				objects[deploymentKey(ns.Name, apiFamily)] = servingObject(t, v.deployment)
			}
			callback := func(observation int) {
				if observation != 2 {
					return
				}
				switch scenario {
				case "journal-race":
					ns.ResourceVersion = "changed"
				case "namespace-replaced":
					ns.UID = "replacement"
				case "deployment-second-rv":
					parents.Items[0].ResourceVersion = "changed"
					objects[deploymentKey(ns.Name, parent.Name)].SetResourceVersion("changed")
				case "sa-second-rv":
					objects[accountKey].SetResourceVersion("changed")
				case "set-second-rv":
					sets.Items[len(sets.Items)-2].ResourceVersion = "changed"
				case "pod-second-rv":
					pods.Items[0].ResourceVersion = "changed"
				case "unrelated-churn":
					pods.Items[len(pods.Items)-1].ResourceVersion = "changed"
					lists["Job"].(*batchv1.JobList).Items[0].ResourceVersion = "changed"
				}
			}
			access, observations := controllerProofAccess(t, ns, objects, lists, callback, scenario)
			registered := append([]*installrender.Plan{plan}, others...)
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
			check, err := NewClusterControllers(p)
			if err != nil {
				t.Fatal(err)
			}
			s, err := store.Load(context.Background(), v.f.snapshot.Anchor())
			if err != nil {
				t.Fatal(err)
			}
			request := LifecycleCheck{Checkpoint: ControllersAvailable, Snapshot: s, Mode: s.Document().Mode, Target: plan, Options: LifecycleOptions{Now: time.Now().UTC()}}
			err = check.Verify(context.Background(), request)
			if (err == nil) != valid || err != nil && err != ErrControllers {
				t.Fatalf("readiness proof incorrect: %v, observations=%d", err, observations())
			}
			if valid {
				if observations() != 2 {
					t.Fatal("skipped repeated whole observation")
				}
				request.Checkpoint = RuntimeStopped
				if check.Verify(context.Background(), request) != ErrInvalid {
					t.Fatal("availability substituted for shutdown")
				}
			}
		})
	}
}
