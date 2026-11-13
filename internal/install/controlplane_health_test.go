// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package install

import (
	"reflect"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func TestControlPlaneHealthProbesKeepOriginalStartupBudget(t *testing.T) {
	want := map[string]string{"arcadectl-controller": "/healthz", "arcadectl-destroy-controller": "/healthz", "arcadectl-api": "/livez"}
	seen := map[string]bool{}
	probe := func(path string, initial, period, timeout, failures int32) *corev1.Probe {
		return &corev1.Probe{
			ProbeHandler:        corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: path, Port: intstr.FromString("health")}},
			InitialDelaySeconds: initial, PeriodSeconds: period, TimeoutSeconds: timeout, FailureThreshold: failures,
		}
	}
	objects := append(decodeObjects(t, renderController(t, testControllerImage)), decodeObjects(t, renderAPI(t, testAPIImage))...)
	for _, object := range objects {
		if object.GetKind() != "Deployment" {
			continue
		}
		deployment := &appsv1.Deployment{}
		convertObject(t, object, deployment)
		path, known := want[deployment.Name]
		if !known || seen[deployment.Name] || len(deployment.Spec.Template.Spec.Containers) != 1 {
			t.Fatal("unexpected control-plane deployment or container")
		}
		seen[deployment.Name] = true
		container := deployment.Spec.Template.Spec.Containers[0]
		if container.StartupProbe != nil {
			t.Fatal("startup probe delays the original liveness/readiness schedule")
		}
		live, ready := probe(path, 2, 10, 2, 3), probe("/readyz", 2, 10, 2, 3)
		if deployment.Name == "arcadectl-api" {
			// The API manifest retains Kubernetes' default failure threshold.
			live, ready = probe(path, 0, 10, 1, 0), probe("/readyz", 0, 2, 1, 0)
		}
		if !reflect.DeepEqual(container.LivenessProbe, live) || !reflect.DeepEqual(container.ReadinessProbe, ready) {
			t.Fatal("private health probes changed the original startup failure budget")
		}
	}
	if len(seen) != len(want) {
		t.Fatal("control-plane health probe coverage is incomplete")
	}
}
