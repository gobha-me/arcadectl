// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"testing"

	"github.com/gobha-me/arcadectl/internal/installobserve"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func emptyBaselineExecutableCollections() *installobserve.ExecutableCollections {
	return &installobserve.ExecutableCollections{Pods: &corev1.PodList{}, Jobs: &batchv1.JobList{}, Deployments: &appsv1.DeploymentList{}, ReplicaSets: &appsv1.ReplicaSetList{}, StatefulSets: &appsv1.StatefulSetList{}, DaemonSets: &appsv1.DaemonSetList{}, ReplicationControllers: &corev1.ReplicationControllerList{}, CronJobs: &batchv1.CronJobList{}}
}

// Typed refusal predicates only, not cold storage, original ownership, native
// VAP behavior or whole retired proof certification. Every fresh producer
// collection must participate, including terminal/suspended/renamed objects.
func TestBaselineRetiredExecutableAbsenceDistinguishesReservedAndSoftwareSignals(t *testing.T) {
	f := newFixture(t, false)
	for _, collection := range baselineExecutableCollections {
		for _, signal := range []string{"ordinary", "reserved-name", "reserved-account", "reserved-alias", "controller-image", "api-image", "family-label", "family-generate-name", "secret-volume", "secret-env", "template-label"} {
			if signal == "template-label" && collection.kind == "Pod" {
				continue
			}
			t.Run(collection.kind+"/"+signal, func(t *testing.T) {
				objects := emptyBaselineExecutableCollections()
				object := &unstructured.Unstructured{Object: map[string]any{"apiVersion": collection.gv, "kind": collection.kind, "metadata": map[string]any{"name": "unrelated-completed", "namespace": f.plan.Namespace(), "uid": "observed-unowned", "resourceVersion": "100"}}}
				spec := map[string]any{"serviceAccountName": "default", "containers": []any{map[string]any{"name": "unrelated", "image": "registry.example/unrelated@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}}
				template := []string{"spec", "template"}
				if collection.kind == "CronJob" {
					template = []string{"spec", "jobTemplate", "spec", "template"}
					_ = unstructured.SetNestedField(object.Object, true, "spec", "suspend")
				}
				path := append(append([]string(nil), template...), "spec")
				if collection.kind == "Pod" {
					path = []string{"spec"}
					object.Object["status"] = map[string]any{"phase": "Succeeded"}
				} else if collection.kind == "Job" {
					object.Object["status"] = map[string]any{"succeeded": int64(1)}
				}
				container := spec["containers"].([]any)[0].(map[string]any)
				switch signal {
				case "reserved-name":
					object.SetName("arcadectl-destroy-admin")
				case "reserved-account":
					spec["serviceAccountName"] = "arcadectl-destroy-controller"
				case "reserved-alias":
					spec["serviceAccount"] = "arcadectl-api"
				case "controller-image":
					container["image"] = f.plan.Manifest().Images.Controller
				case "api-image":
					container["image"] = f.plan.Manifest().Images.API
				case "family-label":
					object.SetLabels(map[string]string{"app.kubernetes.io/name": apiFamily})
				case "family-generate-name":
					object.SetGenerateName("arcadectl-controller-")
				case "secret-volume":
					spec["volumes"] = []any{map[string]any{"name": "auth", "secret": map[string]any{"secretName": "arcadectl-admin-credential"}}}
				case "secret-env":
					container["env"] = []any{map[string]any{"name": "AUTH", "valueFrom": map[string]any{"secretKeyRef": map[string]any{"name": "arcadectl-admin-credential", "key": "token"}}}}
				case "template-label":
					_ = unstructured.SetNestedStringMap(object.Object, map[string]string{"app.kubernetes.io/name": apiFamily}, append(template, "metadata", "labels")...)
				}
				if unstructured.SetNestedMap(object.Object, spec, path...) != nil {
					t.Fatal("typed fixture producer path unavailable")
				}
				switch collection.kind {
				case "Pod":
					var value corev1.Pod
					if decodeServing(object, &value) != nil {
						t.Fatal("typed Pod fixture unavailable")
					}
					objects.Pods.Items = append(objects.Pods.Items, value)
				case "Job":
					var value batchv1.Job
					if decodeServing(object, &value) != nil {
						t.Fatal("typed Job fixture unavailable")
					}
					objects.Jobs.Items = append(objects.Jobs.Items, value)
				case "Deployment":
					var value appsv1.Deployment
					if decodeServing(object, &value) != nil {
						t.Fatal("typed Deployment fixture unavailable")
					}
					objects.Deployments.Items = append(objects.Deployments.Items, value)
				case "ReplicaSet":
					var value appsv1.ReplicaSet
					if decodeServing(object, &value) != nil {
						t.Fatal("typed ReplicaSet fixture unavailable")
					}
					objects.ReplicaSets.Items = append(objects.ReplicaSets.Items, value)
				case "StatefulSet":
					var value appsv1.StatefulSet
					if decodeServing(object, &value) != nil {
						t.Fatal("typed StatefulSet fixture unavailable")
					}
					objects.StatefulSets.Items = append(objects.StatefulSets.Items, value)
				case "DaemonSet":
					var value appsv1.DaemonSet
					if decodeServing(object, &value) != nil {
						t.Fatal("typed DaemonSet fixture unavailable")
					}
					objects.DaemonSets.Items = append(objects.DaemonSets.Items, value)
				case "ReplicationController":
					var value corev1.ReplicationController
					if decodeServing(object, &value) != nil {
						t.Fatal("typed ReplicationController fixture unavailable")
					}
					objects.ReplicationControllers.Items = append(objects.ReplicationControllers.Items, value)
				case "CronJob":
					var value batchv1.CronJob
					if decodeServing(object, &value) != nil {
						t.Fatal("typed CronJob fixture unavailable")
					}
					objects.CronJobs.Items = append(objects.CronJobs.Items, value)
				}
				reserved := signal == "reserved-name" || signal == "reserved-account" || signal == "reserved-alias"
				if err := baselineReservedCollectionsAbsent(objects); (err != nil) != reserved {
					t.Fatal("reserved selector conflated benign history with identity use", err)
				}
				// destroy-admin is a reserved identity, not a software runtime
				// family; the separate reserved selector must still refuse it.
				software := signal != "ordinary" && signal != "reserved-name"
				if err := f.engine.baselineSoftwareFamiliesAbsent(objects); (err != nil) != software {
					t.Fatal("broader process classifier omitted a renamed/terminal signal", err)
				}
			})
		}
	}
	if baselineReservedCollectionsAbsent(nil) == nil || f.engine.baselineSoftwareFamiliesAbsent(nil) == nil {
		t.Fatal("missing complete producer lists accepted")
	}
	for index := range baselineExecutableCollections {
		objects := emptyBaselineExecutableCollections()
		switch index {
		case 0:
			objects.Pods = nil
		case 1:
			objects.Jobs = nil
		case 2:
			objects.Deployments = nil
		case 3:
			objects.ReplicaSets = nil
		case 4:
			objects.StatefulSets = nil
		case 5:
			objects.DaemonSets = nil
		case 6:
			objects.ReplicationControllers = nil
		case 7:
			objects.CronJobs = nil
		}
		if baselineReservedCollectionsAbsent(objects) == nil || f.engine.baselineSoftwareFamiliesAbsent(objects) == nil {
			t.Fatal("partial producer lists accepted")
		}
	}
}
