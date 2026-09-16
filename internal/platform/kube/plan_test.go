// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package kube

import (
	"strings"
	"testing"

	arcadev1alpha1 "github.com/gobha-me/arcadectl/api/v1alpha1"
	"github.com/gobha-me/arcadectl/internal/games/factorio"
	"github.com/gobha-me/arcadectl/internal/games/synthetic"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

const testDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestBuildRunningFactorioPlan(t *testing.T) {
	t.Parallel()

	server := testServer("factory", "factorio", arcadev1alpha1.DesiredStateRunning)
	plan, err := Build(server, factorio.Definition())
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if len(plan.DataClaims) != 1 {
		t.Fatalf("data claims = %d, want 1", len(plan.DataClaims))
	}
	claim := plan.DataClaims[0]
	if claim.Name != "factory-factorio-world" {
		t.Errorf("claim name = %q, want factory-factorio-world", claim.Name)
	}
	if len(claim.OwnerReferences) != 0 {
		t.Fatalf("retained data claim has owner references: %#v", claim.OwnerReferences)
	}
	if claim.Labels[LabelDataPolicy] != "retain" {
		t.Errorf("data policy label = %q, want retain", claim.Labels[LabelDataPolicy])
	}
	if claim.Labels[LabelDataPath] != "world" {
		t.Errorf("data path label = %q, want world", claim.Labels[LabelDataPath])
	}
	if plan.Workload == nil || plan.PlayerService == nil {
		t.Fatalf("running plan = %#v, want workload and service", plan)
	}
	if plan.Workload.Spec.Strategy.Type != "Recreate" {
		t.Errorf("deployment strategy = %q, want Recreate", plan.Workload.Spec.Strategy.Type)
	}
	if got := *plan.Workload.Spec.Replicas; got != 1 {
		t.Errorf("replicas = %d, want 1", got)
	}
	container := plan.Workload.Spec.Template.Spec.Containers[0]
	if container.Image != "factoriotools/factorio@"+testDigest {
		t.Errorf("image = %q, want a digest-pinned Factorio image", container.Image)
	}
	if container.ReadinessProbe == nil || container.ReadinessProbe.TCPSocket == nil || container.ReadinessProbe.TCPSocket.Port.StrVal != "rcon" {
		t.Errorf("readiness probe = %#v, want named TCP rcon probe", container.ReadinessProbe)
	}
	if plan.Workload.Spec.Template.Spec.AutomountServiceAccountToken == nil || *plan.Workload.Spec.Template.Spec.AutomountServiceAccountToken {
		t.Error("game pod must not mount a Kubernetes service-account token")
	}
	assertControlledByServer(t, plan.Workload.OwnerReferences, server)
	assertControlledByServer(t, plan.PlayerService.OwnerReferences, server)

	ports := plan.PlayerService.Spec.Ports
	if len(ports) != 1 || ports[0].Name != "game" || ports[0].Protocol != corev1.ProtocolUDP {
		t.Errorf("public ports = %#v, want only the UDP player endpoint", ports)
	}
	for _, port := range ports {
		if port.Name == "rcon" {
			t.Fatal("administrator endpoint must not be published by the player service")
		}
	}
	plan.Workload.Labels[LabelInstance] = "changed"
	if plan.PlayerService.Labels[LabelInstance] != "factory" || plan.Workload.Spec.Selector.MatchLabels[LabelInstance] != "factory" {
		t.Fatal("planned resource label maps alias one another")
	}
}

func TestBuildCopiesStorageClass(t *testing.T) {
	t.Parallel()

	server := testServer("factory", "factorio", arcadev1alpha1.DesiredStateStopped)
	className := "fast-storage"
	server.Spec.Storage.StorageClassName = &className
	plan, err := Build(server, factorio.Definition())
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	*server.Spec.Storage.StorageClassName = "changed"
	if got := *plan.DataClaims[0].Spec.StorageClassName; got != "fast-storage" {
		t.Fatalf("planned storage class changed through input alias: %q", got)
	}
}

func TestBuildStoppedPlanRetainsOnlyData(t *testing.T) {
	t.Parallel()

	server := testServer("factory", "factorio", arcadev1alpha1.DesiredStateStopped)
	server.UID = ""
	plan, err := Build(server, factorio.Definition())
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if len(plan.DataClaims) != 1 || len(plan.DataClaims[0].OwnerReferences) != 0 {
		t.Fatalf("stopped data claims = %#v, want one independently retained claim", plan.DataClaims)
	}
	if plan.Workload != nil || plan.PlayerService != nil {
		t.Fatalf("stopped plan has active resources: %#v", plan)
	}
}

func TestBuildIsGameNeutral(t *testing.T) {
	t.Parallel()

	server := testServer("echo", "conformance-echo", arcadev1alpha1.DesiredStateRunning)
	server.Spec.Settings = structJSON(`{}`)
	plan, err := Build(server, synthetic.Definition())
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if got := plan.DataClaims[0].Name; got != "echo-conformance-echo-state" {
		t.Errorf("claim name = %q, want echo-conformance-echo-state", got)
	}
	container := plan.Workload.Spec.Template.Spec.Containers[0]
	if len(container.VolumeMounts) != 1 || container.VolumeMounts[0].MountPath != "/srv/world" {
		t.Errorf("volume mounts = %#v, want synthetic adapter path", container.VolumeMounts)
	}
	if len(plan.PlayerService.Spec.Ports) != 1 || plan.PlayerService.Spec.Ports[0].Protocol != corev1.ProtocolTCP {
		t.Errorf("service ports = %#v, want synthetic TCP endpoint", plan.PlayerService.Spec.Ports)
	}
}

func TestBuildRejectsInvalidIntent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*arcadev1alpha1.GameServer)
		want   string
	}{
		{"game mismatch", func(server *arcadev1alpha1.GameServer) { server.Spec.Game = "other" }, "does not match"},
		{"mutable image", func(server *arcadev1alpha1.GameServer) { server.Spec.ImageDigest = "latest" }, "image digest"},
		{"unknown state", func(server *arcadev1alpha1.GameServer) { server.Spec.DesiredState = "Paused" }, "unsupported desired state"},
		{"zero CPU", func(server *arcadev1alpha1.GameServer) { server.Spec.Compute.CPURequest = resource.Quantity{} }, "CPU request must be positive"},
		{"CPU request over limit", func(server *arcadev1alpha1.GameServer) { server.Spec.Compute.CPURequest = resource.MustParse("3") }, "CPU request cannot exceed"},
		{"memory request over limit", func(server *arcadev1alpha1.GameServer) { server.Spec.Compute.MemoryRequest = resource.MustParse("3Gi") }, "memory request cannot exceed"},
		{"zero storage", func(server *arcadev1alpha1.GameServer) { server.Spec.Storage.Size = resource.Quantity{} }, "storage size must be positive"},
		{"invalid storage class", func(server *arcadev1alpha1.GameServer) {
			className := "Not Valid"
			server.Spec.Storage.StorageClassName = &className
		}, "invalid storage class name"},
		{"invalid settings", func(server *arcadev1alpha1.GameServer) { server.Spec.Settings.Raw = []byte(`{"maxPlayers":0}`) }, "do not satisfy adapter schema"},
		{"oversized settings", func(server *arcadev1alpha1.GameServer) {
			server.Spec.Settings.Raw = []byte(strings.Repeat(" ", maxSettingsLen+1))
		}, "64 KiB"},
		{"missing UID while running", func(server *arcadev1alpha1.GameServer) { server.UID = "" }, "requires a Kubernetes UID"},
		{"invalid namespace", func(server *arcadev1alpha1.GameServer) { server.Namespace = "Not Valid" }, "invalid game server namespace"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			server := testServer("factory", "factorio", arcadev1alpha1.DesiredStateRunning)
			test.mutate(server)
			_, err := Build(server, factorio.Definition())
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Build() error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func testServer(name, gameID string, desiredState arcadev1alpha1.DesiredState) *arcadev1alpha1.GameServer {
	return &arcadev1alpha1.GameServer{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "games", UID: types.UID("test-uid")},
		Spec: arcadev1alpha1.GameServerSpec{
			Game:         gameID,
			ImageDigest:  testDigest,
			DesiredState: desiredState,
			Compute: arcadev1alpha1.ComputeSpec{
				CPURequest:    resource.MustParse("500m"),
				CPULimit:      resource.MustParse("2"),
				MemoryRequest: resource.MustParse("1Gi"),
				MemoryLimit:   resource.MustParse("2Gi"),
			},
			Storage:  arcadev1alpha1.StorageSpec{Size: resource.MustParse("10Gi")},
			Settings: structJSON(`{"name":"test","maxPlayers":16,"visibility":"private"}`),
		},
	}
}

func structJSON(raw string) runtime.RawExtension {
	return runtime.RawExtension{Raw: []byte(raw)}
}

func assertControlledByServer(t *testing.T, references []metav1.OwnerReference, server *arcadev1alpha1.GameServer) {
	t.Helper()
	if len(references) != 1 {
		t.Fatalf("owner references = %#v, want exactly one", references)
	}
	reference := references[0]
	if reference.Name != server.Name || reference.UID != server.UID || reference.Controller == nil || !*reference.Controller {
		t.Errorf("owner reference = %#v, want controlling GameServer reference", reference)
	}
}
