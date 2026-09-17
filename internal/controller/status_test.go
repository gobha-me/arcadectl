// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"slices"
	"testing"
	"time"

	arcadev1alpha1 "github.com/gobha-me/arcadectl/api/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
)

func TestWorkloadAvailableRequiresCurrentExactSingleton(t *testing.T) {
	t.Parallel()

	available := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Generation: 4},
		Spec:       appsv1.DeploymentSpec{Replicas: ptr.To[int32](1)},
		Status: appsv1.DeploymentStatus{
			ObservedGeneration: 4,
			Replicas:           1,
			UpdatedReplicas:    1,
			ReadyReplicas:      1,
			AvailableReplicas:  1,
		},
	}
	if !workloadAvailable(available) {
		t.Fatal("exact current singleton was not available")
	}

	tests := []struct {
		name   string
		mutate func(*appsv1.Deployment)
	}{
		{"stale generation", func(deployment *appsv1.Deployment) { deployment.Status.ObservedGeneration = 3 }},
		{"surplus replica", func(deployment *appsv1.Deployment) { deployment.Status.Replicas = 2 }},
		{"old replica available", func(deployment *appsv1.Deployment) { deployment.Status.UpdatedReplicas = 0 }},
		{"not ready", func(deployment *appsv1.Deployment) { deployment.Status.ReadyReplicas = 0 }},
		{"not available", func(deployment *appsv1.Deployment) { deployment.Status.AvailableReplicas = 0 }},
		{"unavailable replica", func(deployment *appsv1.Deployment) { deployment.Status.UnavailableReplicas = 1 }},
		{"terminating", func(deployment *appsv1.Deployment) {
			timestamp := metav1.NewTime(time.Unix(1_700_000_001, 0))
			deployment.DeletionTimestamp = &timestamp
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			deployment := available.DeepCopy()
			test.mutate(deployment)
			if workloadAvailable(deployment) {
				t.Fatalf("workloadAvailable(%s) = true", test.name)
			}
		})
	}
}

func TestTerminalWorkloadFailureRequiresCurrentNativeFailure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		condition  appsv1.DeploymentCondition
		wantFailed bool
	}{
		{
			name: "progress deadline exceeded",
			condition: appsv1.DeploymentCondition{
				Type: appsv1.DeploymentProgressing, Status: corev1.ConditionFalse, Reason: "ProgressDeadlineExceeded",
			},
			wantFailed: true,
		},
		{
			name: "replica failure",
			condition: appsv1.DeploymentCondition{
				Type: appsv1.DeploymentReplicaFailure, Status: corev1.ConditionTrue, Reason: "FailedCreate",
			},
			wantFailed: true,
		},
		{
			name: "ordinary progress",
			condition: appsv1.DeploymentCondition{
				Type: appsv1.DeploymentProgressing, Status: corev1.ConditionTrue, Reason: "NewReplicaSetAvailable",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			deployment := &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Generation: 2},
				Status: appsv1.DeploymentStatus{
					ObservedGeneration: 2,
					Conditions:         []appsv1.DeploymentCondition{test.condition},
				},
			}
			if got := terminalWorkloadFailure(deployment); (got != "") != test.wantFailed {
				t.Fatalf("terminalWorkloadFailure() = %q, want failed %t", got, test.wantFailed)
			}
			deployment.Status.ObservedGeneration = 1
			if got := terminalWorkloadFailure(deployment); got != "" {
				t.Fatalf("stale native condition produced failure %q", got)
			}
		})
	}
}

func TestObservedEndpointsUsesCertifiedPlayerAllowlist(t *testing.T) {
	t.Parallel()

	desired := &corev1.Service{Spec: corev1.ServiceSpec{Ports: []corev1.ServicePort{
		{Name: "players", Protocol: corev1.ProtocolTCP, Port: 1234, TargetPort: intstr.FromString("players")},
		{Name: "game", Protocol: corev1.ProtocolUDP, Port: 34197, TargetPort: intstr.FromString("game")},
	}}}
	actual := desired.DeepCopy()
	actual.Spec.Ports = append(actual.Spec.Ports,
		corev1.ServicePort{Name: "rcon", Protocol: corev1.ProtocolTCP, Port: 27015, TargetPort: intstr.FromString("rcon")},
		corev1.ServicePort{Name: "internal", Protocol: corev1.ProtocolTCP, Port: 9000, TargetPort: intstr.FromString("internal")},
		corev1.ServicePort{Name: "rogue", Protocol: corev1.ProtocolUDP, Port: 9999, TargetPort: intstr.FromString("rogue")},
	)
	actual.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{
		{Hostname: "z.example.test"},
		{IP: "192.0.2.20"},
		{IP: "192.0.2.10"},
		{Hostname: "A.example.test"},
		{IP: "not-an-ip"},
		{IP: "0.0.0.0"},
		{IP: "127.0.0.1"},
		{IP: "169.254.1.1"},
		{IP: "224.0.0.1"},
	}

	want := []arcadev1alpha1.ObservedEndpoint{
		{Name: "game", Protocol: "UDP", Address: "192.0.2.10", Port: 34197},
		{Name: "players", Protocol: "TCP", Address: "192.0.2.10", Port: 1234},
	}
	if got := observedEndpoints(actual, desired); !slices.Equal(got, want) {
		t.Fatalf("observed endpoints = %#v, want %#v", got, want)
	}

	actual.Spec.Ports[0].Port++
	if got := observedEndpoints(actual, desired); got != nil {
		t.Fatalf("mismatched certified port produced endpoints: %#v", got)
	}
	actual = desired.DeepCopy()
	actual.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{Hostname: "players.example.test"}}
	timestamp := metav1.NewTime(time.Unix(1_700_000_001, 0))
	actual.DeletionTimestamp = &timestamp
	if got := observedEndpoints(actual, desired); got != nil {
		t.Fatalf("terminating Service produced endpoints: %#v", got)
	}
}

func TestObservedEndpointsRequiresHealthyIngressPorts(t *testing.T) {
	t.Parallel()

	desired := &corev1.Service{Spec: corev1.ServiceSpec{Ports: []corev1.ServicePort{
		{Name: "players", Protocol: corev1.ProtocolTCP, Port: 1234, TargetPort: intstr.FromString("players")},
		{Name: "game", Protocol: corev1.ProtocolUDP, Port: 34197, TargetPort: intstr.FromString("game")},
	}}}
	actual := desired.DeepCopy()
	providerFailure := "UnsupportedProtocol"
	actual.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{
		IP: "192.0.2.10",
		Ports: []corev1.PortStatus{
			{Port: 1234, Protocol: corev1.ProtocolTCP},
			{Port: 34197, Protocol: corev1.ProtocolUDP, Error: &providerFailure},
		},
	}}
	if got := observedEndpoints(actual, desired); got != nil {
		t.Fatalf("failed load-balancer port produced endpoints: %#v", got)
	}

	actual.Status.LoadBalancer.Ingress[0].Ports[1].Error = nil
	if got := observedEndpoints(actual, desired); len(got) != 2 {
		t.Fatalf("healthy load-balancer ports produced endpoints: %#v", got)
	}

	actual.Status.LoadBalancer.Ingress[0].Ports = append(actual.Status.LoadBalancer.Ingress[0].Ports,
		corev1.PortStatus{Port: 34197, Protocol: corev1.ProtocolUDP, Error: &providerFailure})
	if got := observedEndpoints(actual, desired); got != nil {
		t.Fatalf("ambiguous healthy and failed load-balancer port produced endpoints: %#v", got)
	}
	actual.Status.LoadBalancer.Ingress[0].Ports[2].Error = nil
	if got := observedEndpoints(actual, desired); got != nil {
		t.Fatalf("duplicate healthy load-balancer port produced endpoints: %#v", got)
	}

	actual.Status.LoadBalancer.Ingress[0].Ports = actual.Status.LoadBalancer.Ingress[0].Ports[:1]
	if got := observedEndpoints(actual, desired); got != nil {
		t.Fatalf("partially reported load-balancer ports produced endpoints: %#v", got)
	}
}

func TestCanonicalEndpointsAreDeterministic(t *testing.T) {
	t.Parallel()

	input := []arcadev1alpha1.ObservedEndpoint{
		{Name: "z", Protocol: "UDP", Address: "example.test", Port: 2},
		{Name: "a", Protocol: "TCP", Address: "example.test", Port: 1},
	}
	got := canonicalEndpoints(input)
	if got[0].Name != "a" || input[0].Name != "z" {
		t.Fatalf("canonical endpoints = %#v; input mutated = %#v", got, input)
	}
}
