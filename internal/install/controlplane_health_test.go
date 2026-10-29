// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package install

import (
	"testing"

	appsv1 "k8s.io/api/apps/v1"
)

func TestControlPlaneStartupProbesUsePrivateLivenessEndpoints(t *testing.T) {
	want := map[string]string{"arcadectl-controller": "/healthz", "arcadectl-destroy-controller": "/healthz", "arcadectl-api": "/livez"}
	seen := map[string]bool{}
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
		probe := container.StartupProbe
		if probe == nil || probe.HTTPGet == nil || probe.HTTPGet.Path != path || probe.HTTPGet.Port.StrVal != "health" || probe.HTTPGet.Host != "" || len(probe.HTTPGet.HTTPHeaders) != 0 || probe.PeriodSeconds != 2 || probe.TimeoutSeconds != 1 || probe.FailureThreshold != 30 || container.ReadinessProbe == nil || container.LivenessProbe == nil {
			t.Fatal("startup probe changed its bounded private liveness contract")
		}
	}
	if len(seen) != len(want) {
		t.Fatal("control-plane startup probe coverage is incomplete")
	}
}
