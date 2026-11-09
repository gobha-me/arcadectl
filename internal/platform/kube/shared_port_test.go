// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package kube

import (
	"encoding/json"
	"reflect"
	"testing"

	arcadev1alpha1 "github.com/gobha-me/arcadectl/api/v1alpha1"
	"github.com/gobha-me/arcadectl/internal/platform/game"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func TestBuildSharedPortAcrossTCPAndUDP(t *testing.T) {
	definition := game.Definition{
		ID: "dual-transport", DisplayName: "Dual transport fixture", ImageRepository: "registry.example/fixtures/dual",
		Endpoints: []game.Endpoint{
			{Name: "game-tcp", Protocol: game.ProtocolTCP, ContainerPort: 8080, Scope: game.ScopePlayer},
			{Name: "game-udp", Protocol: game.ProtocolUDP, ContainerPort: 8080, Scope: game.ScopePlayer},
			{Name: "admin", Protocol: game.ProtocolTCP, ContainerPort: 8081, Scope: game.ScopeAdmin},
		},
		PersistentPaths:   []game.PersistentPath{{Name: "world", MountPath: "/srv/world"}},
		ReadinessEndpoint: "game-tcp", ReadinessMode: game.ReadinessTCP,
		SettingsSchema:       []byte(`{"type":"object","additionalProperties":false}`),
		ConfigurationTargets: []game.ConfigurationTarget{{Name: "config", MountPath: "/srv/world/server.conf"}},
		RenderSettings: func(json.RawMessage) (map[string][]byte, error) {
			return map[string][]byte{"config": []byte("enabled=true\n")}, nil
		},
		RuntimeIdentity: game.RuntimeIdentity{UserID: 1000, GroupID: 1000, FSGroup: 1000},
	}
	server := testServer("dual", definition.ID, arcadev1alpha1.DesiredStateRunning)
	server.Spec.Settings = structJSON(`{}`)
	plan, err := Build(server, definition)
	if err != nil {
		t.Fatalf("Build() refused shared TCP/UDP port: %v", err)
	}
	if plan.Workload == nil || plan.PlayerService == nil || len(plan.Workload.Spec.Template.Spec.Containers) != 1 {
		t.Fatalf("missing single-container workload or player service: %#v", plan)
	}
	wantContainer := []corev1.ContainerPort{
		{Name: "game-tcp", ContainerPort: 8080, Protocol: corev1.ProtocolTCP},
		{Name: "game-udp", ContainerPort: 8080, Protocol: corev1.ProtocolUDP},
	}
	container := plan.Workload.Spec.Template.Spec.Containers[0]
	if !reflect.DeepEqual(container.Ports, wantContainer) {
		t.Fatalf("container ports = %#v, want %#v", container.Ports, wantContainer)
	}
	wantService := []corev1.ServicePort{
		{Name: "game-tcp", Port: 8080, Protocol: corev1.ProtocolTCP, TargetPort: intstr.FromString("game-tcp")},
		{Name: "game-udp", Port: 8080, Protocol: corev1.ProtocolUDP, TargetPort: intstr.FromString("game-udp")},
	}
	if !reflect.DeepEqual(plan.PlayerService.Spec.Ports, wantService) {
		t.Fatalf("service ports = %#v, want %#v", plan.PlayerService.Spec.Ports, wantService)
	}
	if container.ReadinessProbe == nil || container.ReadinessProbe.TCPSocket == nil || container.ReadinessProbe.TCPSocket.Port != intstr.FromString("game-tcp") {
		t.Fatalf("readiness = %#v, want named TCP player port", container.ReadinessProbe)
	}
}
