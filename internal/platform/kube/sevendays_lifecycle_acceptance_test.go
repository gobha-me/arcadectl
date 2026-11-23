// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package kube_test

import (
	"path"
	"strings"
	"testing"

	arcadev1alpha1 "github.com/gobha-me/arcadectl/api/v1alpha1"
	"github.com/gobha-me/arcadectl/internal/games/sevendays"
	"github.com/gobha-me/arcadectl/internal/platform/game"
	platformkube "github.com/gobha-me/arcadectl/internal/platform/kube"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const sevenDaysAcceptanceSettings = `{"name":"Acceptance world","description":"Original description","visibility":"unlisted"}`

func TestSevenDaysAcceptanceReadinessAndPlayerEndpointProjection(t *testing.T) {
	t.Parallel()
	plan, definition, server := sevenDaysAcceptanceBuild(t, sevenDaysAcceptanceSettings)
	container := sevenDaysAcceptanceContainer(t, plan, definition, server)
	if container.ReadinessProbe == nil || container.ReadinessProbe.TCPSocket == nil ||
		container.ReadinessProbe.TCPSocket.Port.Type != intstr.String || container.ReadinessProbe.TCPSocket.Port.StrVal != "game-tcp" {
		t.Fatalf("readiness=%#v; want TCP on named game-tcp port", container.ReadinessProbe)
	}
	playerEndpoints := make(map[string]game.Endpoint)
	for _, endpoint := range definition.Endpoints {
		if endpoint.Scope == game.ScopePlayer {
			playerEndpoints[endpoint.Name] = endpoint
		}
	}
	for name, protocol := range map[string]game.Protocol{"game-tcp": game.ProtocolTCP, "game-udp": game.ProtocolUDP} {
		endpoint, ok := playerEndpoints[name]
		if !ok || endpoint.Protocol != protocol {
			t.Fatalf("adapter endpoint %q=%#v; want a player-scoped %s endpoint", name, endpoint, protocol)
		}
		matches := 0
		for _, port := range container.Ports {
			if port.Name == name {
				matches++
				if port.Protocol != corev1.Protocol(protocol) || port.ContainerPort != int32(endpoint.ContainerPort) {
					t.Errorf("container endpoint %q=%#v; want declared %s port %d", name, port, protocol, endpoint.ContainerPort)
				}
			}
		}
		if matches != 1 {
			t.Errorf("container endpoint %q occurs %d times; want once", name, matches)
		}
	}
	if plan.PlayerService == nil || plan.PlayerService.Spec.Type != corev1.ServiceTypeLoadBalancer {
		t.Fatal("running plan lacks a LoadBalancer player Service")
	}
	if len(plan.PlayerService.Spec.Ports) != len(playerEndpoints) {
		t.Fatalf("Service has %d ports; want exactly the %d declared player endpoints", len(plan.PlayerService.Spec.Ports), len(playerEndpoints))
	}
	seen := make(map[string]bool)
	for _, port := range plan.PlayerService.Spec.Ports {
		endpoint, player := playerEndpoints[port.Name]
		if !player || seen[port.Name] {
			t.Fatalf("Service publishes an undeclared, non-player or duplicate endpoint: %#v", port)
		}
		seen[port.Name] = true
		if port.Protocol != corev1.Protocol(endpoint.Protocol) || port.Port != int32(endpoint.ContainerPort) {
			t.Errorf("Service endpoint %q=%#v; want declared %s port %d", port.Name, port, endpoint.Protocol, endpoint.ContainerPort)
		}
		// Numeric and named target ports have the same public Kubernetes
		// meaning when they select the declared game endpoint.
		if port.TargetPort.Type == intstr.String {
			if port.TargetPort.StrVal != endpoint.Name {
				t.Errorf("Service target=%q; want named endpoint %q", port.TargetPort.StrVal, endpoint.Name)
			}
		} else if port.TargetPort.IntVal != int32(endpoint.ContainerPort) {
			t.Errorf("Service target=%d; want game port %d", port.TargetPort.IntVal, endpoint.ContainerPort)
		}
	}
}

func TestSevenDaysAcceptanceConfigurationWorldAndRuntimeIdentity(t *testing.T) {
	t.Parallel()
	plan, definition, server := sevenDaysAcceptanceBuild(t, sevenDaysAcceptanceSettings)
	container := sevenDaysAcceptanceContainer(t, plan, definition, server)
	if plan.Configuration == nil || len(plan.Configuration.Data) != 1 || plan.Configuration.Data["serverconfig"] == "" || len(plan.Configuration.BinaryData) != 0 {
		t.Fatalf("configuration=%#v; want exactly one nonempty serverconfig key", plan.Configuration)
	}
	if len(definition.ConfigurationTargets) != 1 || definition.ConfigurationTargets[0].Name != "serverconfig" {
		t.Fatalf("adapter configuration targets=%#v; want the declared serverconfig target", definition.ConfigurationTargets)
	}
	target := definition.ConfigurationTargets[0]
	var world game.PersistentPath
	for _, persistent := range definition.PersistentPaths {
		if persistent.Name == "world" {
			world = persistent
		}
	}
	if world.MountPath == "" || target.MountPath == world.MountPath || !strings.HasPrefix(path.Clean(target.MountPath), path.Clean(world.MountPath)+"/") {
		t.Fatalf("configuration target %q is outside declared world root %q", target.MountPath, world.MountPath)
	}
	if len(plan.DataClaims) != 1 || plan.DataClaims[0].Desired == nil {
		t.Fatal("running plan must contain one world claim")
	}
	claim := plan.DataClaims[0].Desired
	if claim.Labels[platformkube.LabelDataPath] != "world" || claim.Labels[platformkube.LabelDataPolicy] != "retain" || len(claim.OwnerReferences) != 0 {
		t.Fatalf("claim lacks independently retained world identity: %#v", claim)
	}
	worldVolume := ""
	sourceVolumes := make(map[string]bool)
	for _, volume := range plan.Workload.Spec.Template.Spec.Volumes {
		if volume.PersistentVolumeClaim != nil && volume.PersistentVolumeClaim.ClaimName == claim.Name {
			if worldVolume != "" {
				t.Fatal("world claim is attached through multiple Pod volumes")
			}
			worldVolume = volume.Name
		}
		if volume.ConfigMap != nil && volume.ConfigMap.Name == plan.Configuration.Name {
			sourceVolumes[volume.Name] = true
			if len(volume.ConfigMap.Items) != 0 {
				found := false
				for _, item := range volume.ConfigMap.Items {
					found = found || item.Key == target.Name
				}
				if !found {
					t.Error("configuration volume projection omits the serverconfig key")
				}
			}
		}
	}
	if worldVolume == "" || len(sourceVolumes) == 0 {
		t.Fatal("Pod does not attach the retained world and rendered configuration")
	}
	if !sevenDaysAcceptanceMounts(container, worldVolume, world.MountPath, false) {
		t.Fatalf("game container does not mount world at declared path %q", world.MountPath)
	}
	pod := plan.Workload.Spec.Template.Spec
	identity := definition.RuntimeIdentity
	if pod.SecurityContext == nil || pod.SecurityContext.RunAsUser == nil || *pod.SecurityContext.RunAsUser != identity.UserID ||
		pod.SecurityContext.RunAsGroup == nil || *pod.SecurityContext.RunAsGroup != identity.GroupID ||
		pod.SecurityContext.FSGroup == nil || *pod.SecurityContext.FSGroup != identity.FSGroup {
		t.Fatalf("Pod security identity=%#v; want adapter identity %#v", pod.SecurityContext, identity)
	}
	materializers := 0
	for _, init := range pod.InitContainers {
		sevenDaysAcceptanceNoIdentityOverride(t, init, identity)
		readsConfiguration := false
		for _, mount := range init.VolumeMounts {
			readsConfiguration = readsConfiguration || sourceVolumes[mount.Name] && mount.ReadOnly
		}
		if readsConfiguration && sevenDaysAcceptanceMounts(init, worldVolume, world.MountPath, false) {
			materializers++
			// This checks the public generated plan, not materializer execution.
			// The destination may be a command argument or literal environment
			// value; neither a shell syntax nor an init-container name is assumed.
			artifacts := append(append([]string(nil), init.Command...), init.Args...)
			for _, environment := range init.Env {
				artifacts = append(artifacts, environment.Value)
			}
			invocation := strings.Join(artifacts, "\x00")
			if !strings.Contains(invocation, target.MountPath) {
				t.Errorf("configuration materializer omits declared target %q", target.MountPath)
			}
		}
	}
	sevenDaysAcceptanceNoIdentityOverride(t, container, identity)
	if materializers != 1 {
		t.Fatalf("source-reading world materializers=%d; want one", materializers)
	}
}

func TestSevenDaysAcceptanceConfigurationHashUsesRenderedMeaning(t *testing.T) {
	t.Parallel()
	original, _, _ := sevenDaysAcceptanceBuild(t, sevenDaysAcceptanceSettings)
	reencoded, _, _ := sevenDaysAcceptanceBuild(t, "{\n  \"visibility\": \"unlisted\", \"description\": \"Original description\",\n  \"name\": \"Acceptance world\"\n}\n")
	changed, _, _ := sevenDaysAcceptanceBuild(t, `{"name":"Acceptance world","description":"Changed description","visibility":"unlisted"}`)
	originalHash := sevenDaysAcceptanceConfigurationHash(t, original)
	reencodedHash := sevenDaysAcceptanceConfigurationHash(t, reencoded)
	changedHash := sevenDaysAcceptanceConfigurationHash(t, changed)
	if originalHash != reencodedHash {
		t.Errorf("semantically identical JSON changed configuration hash: %s != %s", originalHash, reencodedHash)
	}
	if originalHash == changedHash {
		t.Error("changing only description did not change configuration hash")
	}
	if original.Configuration.Data["serverconfig"] != reencoded.Configuration.Data["serverconfig"] {
		t.Error("semantically identical settings changed rendered serverconfig")
	}
	if original.Configuration.Data["serverconfig"] == changed.Configuration.Data["serverconfig"] {
		t.Error("changing only description did not change rendered serverconfig")
	}
}

func sevenDaysAcceptanceBuild(t *testing.T, settings string) (platformkube.Plan, game.Definition, *arcadev1alpha1.GameServer) {
	t.Helper()
	definition := sevendays.Definition()
	server := &arcadev1alpha1.GameServer{
		ObjectMeta: metav1.ObjectMeta{Name: "acceptance-world", Namespace: "acceptance-games", UID: "acceptance-server-uid"},
		Spec: arcadev1alpha1.GameServerSpec{
			Game: definition.ID, ImageDigest: "sha256:" + strings.Repeat("a", 64), DesiredState: arcadev1alpha1.DesiredStateRunning,
			Compute: arcadev1alpha1.ComputeSpec{
				CPURequest: resource.MustParse("500m"), CPULimit: resource.MustParse("2"),
				MemoryRequest: resource.MustParse("1Gi"), MemoryLimit: resource.MustParse("2Gi"),
			},
			Storage:  arcadev1alpha1.StorageSpec{Size: resource.MustParse("10Gi")},
			Settings: runtime.RawExtension{Raw: []byte(settings)},
		},
	}
	plan, err := platformkube.Build(server, definition)
	if err != nil {
		t.Fatal(err)
	}
	return plan, definition, server
}

func sevenDaysAcceptanceContainer(t *testing.T, plan platformkube.Plan, definition game.Definition, server *arcadev1alpha1.GameServer) corev1.Container {
	t.Helper()
	if plan.Workload == nil {
		t.Fatal("running plan lacks a Deployment")
	}
	for _, container := range plan.Workload.Spec.Template.Spec.Containers {
		if container.Image == definition.ImageRepository+"@"+server.Spec.ImageDigest {
			return container
		}
	}
	t.Fatal("Deployment lacks the declared immutable game image")
	return corev1.Container{}
}

func sevenDaysAcceptanceMounts(container corev1.Container, volumeName, mountPath string, readOnly bool) bool {
	for _, mount := range container.VolumeMounts {
		if mount.Name == volumeName && mount.MountPath == mountPath && mount.ReadOnly == readOnly && mount.SubPath == "" && mount.SubPathExpr == "" {
			return true
		}
	}
	return false
}

func sevenDaysAcceptanceNoIdentityOverride(t *testing.T, container corev1.Container, identity game.RuntimeIdentity) {
	t.Helper()
	if container.SecurityContext == nil {
		return
	}
	if container.SecurityContext.RunAsUser != nil && *container.SecurityContext.RunAsUser != identity.UserID ||
		container.SecurityContext.RunAsGroup != nil && *container.SecurityContext.RunAsGroup != identity.GroupID {
		t.Errorf("container %q overrides declared runtime identity: %#v", container.Name, container.SecurityContext)
	}
}

func sevenDaysAcceptanceConfigurationHash(t *testing.T, plan platformkube.Plan) string {
	t.Helper()
	if plan.Workload == nil || plan.Configuration == nil {
		t.Fatal("hash fixture lacks runtime resources")
	}
	hash := plan.Workload.Spec.Template.Annotations[platformkube.AnnotationConfigurationHash]
	if hash == "" {
		t.Fatal("configuration hash annotation is empty")
	}
	return hash
}
