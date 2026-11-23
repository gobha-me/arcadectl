// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package kube

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"testing"

	arcadev1alpha1 "github.com/gobha-me/arcadectl/api/v1alpha1"
	"github.com/gobha-me/arcadectl/internal/games/sevendays"
	"github.com/gobha-me/arcadectl/internal/platform/game"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func TestBuildRunningSevenDaysPlan(t *testing.T) {
	t.Parallel()
	definition := sevendays.Definition()
	server := testServer("survival", definition.ID, arcadev1alpha1.DesiredStateRunning)
	server.Spec.Settings = structJSON(`{"name":"Survival","visibility":"unlisted"}`)
	plan, err := Build(server, definition)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Workload == nil || plan.PlayerService == nil || plan.Configuration == nil {
		t.Fatalf("running plan lacks runtime resources: %#v", plan)
	}
	if len(plan.DataClaims) != 1 {
		t.Fatalf("data claims = %#v, want one world claim", plan.DataClaims)
	}
	claim := plan.DataClaims[0].Desired
	if claim.Name != "survival-seven-days-to-die-world" || claim.Namespace != server.Namespace ||
		claim.Labels[LabelDataPath] != "world" || claim.Labels[LabelDataPolicy] != "retain" || len(claim.OwnerReferences) != 0 {
		t.Fatalf("world claim = %#v, want independent retained world storage", claim)
	}
	identity, err := DataIdentity(server.UID)
	if err != nil {
		t.Fatal(err)
	}
	if plan.DataIdentity != identity || claim.Labels[LabelDataIdentity] != identity {
		t.Fatalf("world identity = plan %q, claim %q; want %q", plan.DataIdentity, claim.Labels[LabelDataIdentity], identity)
	}
	assertControlledByServer(t, plan.Workload.OwnerReferences, server)
	assertControlledByServer(t, plan.PlayerService.OwnerReferences, server)
	assertControlledByServer(t, plan.Configuration.OwnerReferences, server)
	if plan.Workload.Spec.Strategy.Type != "Recreate" || plan.Workload.Spec.Replicas == nil || *plan.Workload.Spec.Replicas != 1 {
		t.Fatalf("workload must replace a single game process: %#v", plan.Workload.Spec)
	}
	pod := plan.Workload.Spec.Template.Spec
	if len(pod.Containers) != 1 {
		t.Fatalf("game containers = %#v, want one", pod.Containers)
	}
	container := pod.Containers[0]
	if container.Image != definition.ImageRepository+"@"+testDigest {
		t.Errorf("image = %q, want immutable adapter image", container.Image)
	}
	probe := container.ReadinessProbe
	if probe == nil || probe.TCPSocket == nil || probe.TCPSocket.Port != intstr.FromString("game-tcp") ||
		probe.Exec != nil || probe.HTTPGet != nil || probe.GRPC != nil {
		t.Fatalf("readiness probe = %#v, want only named game-tcp socket", probe)
	}
	wantPorts := []corev1.ContainerPort{
		{Name: "game-tcp", ContainerPort: 26900, Protocol: corev1.ProtocolTCP},
		{Name: "game-udp", ContainerPort: 26900, Protocol: corev1.ProtocolUDP},
		{Name: "steam-udp", ContainerPort: 26901, Protocol: corev1.ProtocolUDP},
		{Name: "network-udp", ContainerPort: 26902, Protocol: corev1.ProtocolUDP},
		{Name: "reserved-udp", ContainerPort: 26903, Protocol: corev1.ProtocolUDP},
	}
	if !reflect.DeepEqual(container.Ports, wantPorts) {
		t.Errorf("game ports = %#v, want %#v", container.Ports, wantPorts)
	}
	wantServicePorts := make([]corev1.ServicePort, 0, len(wantPorts))
	for _, port := range wantPorts {
		wantServicePorts = append(wantServicePorts, corev1.ServicePort{
			Name: port.Name, Protocol: port.Protocol, Port: port.ContainerPort, TargetPort: intstr.FromString(port.Name),
		})
	}
	if plan.PlayerService.Spec.Type != corev1.ServiceTypeLoadBalancer || !reflect.DeepEqual(plan.PlayerService.Spec.Ports, wantServicePorts) {
		t.Errorf("player service = %#v, want exactly the declared player ports", plan.PlayerService.Spec)
	}
	if !reflect.DeepEqual(plan.PlayerService.Spec.Selector, plan.Workload.Spec.Template.Labels) {
		t.Error("player service does not select the planned game pod")
	}
	if pod.AutomountServiceAccountToken == nil || *pod.AutomountServiceAccountToken {
		t.Error("game pod must not mount a Kubernetes service-account token")
	}
	security := pod.SecurityContext
	if security == nil || security.RunAsUser == nil || *security.RunAsUser != definition.RuntimeIdentity.UserID ||
		security.RunAsGroup == nil || *security.RunAsGroup != definition.RuntimeIdentity.GroupID ||
		security.FSGroup == nil || *security.FSGroup != definition.RuntimeIdentity.FSGroup ||
		security.RunAsNonRoot == nil || !*security.RunAsNonRoot {
		t.Fatalf("pod security context = %#v, want adapter non-root identity %#v", security, definition.RuntimeIdentity)
	}
	files, err := definition.RenderSettingsFiles(server.Spec.Settings.Raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0].Name != "serverconfig" || files[0].MountPath != "/sdtd/config/serverconfig.xml" {
		t.Fatalf("adapter files = %#v, want the declared serverconfig target", files)
	}
	if len(plan.Configuration.Data) != 0 || len(plan.Configuration.BinaryData) != 1 ||
		!bytes.Equal(plan.Configuration.BinaryData["serverconfig"], files[0].Contents) {
		t.Errorf("configuration = %#v, want exactly the rendered serverconfig bytes", plan.Configuration)
	}
	wantMount := corev1.VolumeMount{Name: "world", MountPath: definition.PersistentPaths[0].MountPath}
	if wantMount.MountPath != "/sdtd" || !reflect.DeepEqual(container.VolumeMounts, []corev1.VolumeMount{wantMount}) {
		t.Errorf("game mounts = %#v, want only the adapter world path", container.VolumeMounts)
	}
	wantVolumes := []corev1.Volume{
		{Name: "world", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: claim.Name}}},
		{Name: configurationVolumeName, VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{
			LocalObjectReference: corev1.LocalObjectReference{Name: plan.Configuration.Name},
		}}},
	}
	if !reflect.DeepEqual(pod.Volumes, wantVolumes) {
		t.Errorf("pod volumes = %#v, want retained claim and configuration source", pod.Volumes)
	}
	if len(pod.InitContainers) != 1 {
		t.Fatalf("init containers = %#v, want configuration materializer", pod.InitContainers)
	}
	materializer := pod.InitContainers[0]
	wantArgs := []string{
		materializeConfigurationScript, "arcadectl-configuration-materializer",
		"/sdtd", configurationSourcePath + "/serverconfig", files[0].MountPath,
	}
	if materializer.Image != configurationMaterializer || !reflect.DeepEqual(materializer.Command, []string{"/bin/sh", "-ec"}) ||
		!reflect.DeepEqual(materializer.Args, wantArgs) {
		t.Errorf("materializer = %#v, want the fixed helper and declared XML target", materializer)
	}
	wantMaterializerMounts := []corev1.VolumeMount{wantMount, {Name: configurationVolumeName, MountPath: configurationSourcePath, ReadOnly: true}}
	if !reflect.DeepEqual(materializer.VolumeMounts, wantMaterializerMounts) {
		t.Errorf("materializer mounts = %#v, want writable world and read-only configuration", materializer.VolumeMounts)
	}
}

func TestBuildSevenDaysExcludesPrivateEndpoints(t *testing.T) {
	t.Parallel()
	definition := sevendays.Definition()
	// Exercise scope filtering even though the experimental adapter disables
	// administration and declares no private endpoints of its own.
	definition.Endpoints = append(definition.Endpoints,
		game.Endpoint{Name: "private-admin", Protocol: game.ProtocolTCP, ContainerPort: 29001, Scope: game.ScopeAdmin},
		game.Endpoint{Name: "private-intern", Protocol: game.ProtocolTCP, ContainerPort: 29002, Scope: game.ScopeInternal},
	)
	server := testServer("survival", definition.ID, arcadev1alpha1.DesiredStateRunning)
	server.Spec.Settings = structJSON(`{"name":"Survival","visibility":"unlisted"}`)
	plan, err := Build(server, definition)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Workload.Spec.Template.Spec.Containers[0].Ports) != 5 || len(plan.PlayerService.Spec.Ports) != 5 {
		t.Fatalf("private endpoints changed published port counts: pod %#v; service %#v", plan.Workload.Spec.Template.Spec.Containers[0].Ports, plan.PlayerService.Spec.Ports)
	}
	for _, port := range plan.Workload.Spec.Template.Spec.Containers[0].Ports {
		if port.Name == "private-admin" || port.Name == "private-intern" || port.ContainerPort == 29001 || port.ContainerPort == 29002 {
			t.Errorf("private endpoint appeared in game ports: %#v", port)
		}
	}
	for _, port := range plan.PlayerService.Spec.Ports {
		if port.Name == "private-admin" || port.Name == "private-intern" || port.Port == 29001 || port.Port == 29002 {
			t.Errorf("private endpoint appeared in player Service: %#v", port)
		}
	}
}

func TestBuildStoppedSevenDaysPlanRetainsWorld(t *testing.T) {
	t.Parallel()
	definition := sevendays.Definition()
	server := testServer("survival", definition.ID, arcadev1alpha1.DesiredStateRunning)
	server.Spec.Settings = structJSON(`{"name":"Survival","visibility":"unlisted"}`)
	running, err := Build(server, definition)
	if err != nil {
		t.Fatal(err)
	}
	server.Spec.DesiredState = arcadev1alpha1.DesiredStateStopped
	stopped, err := Build(server, definition)
	if err != nil {
		t.Fatal(err)
	}
	if stopped.Configuration != nil || stopped.Workload != nil || stopped.PlayerService != nil {
		t.Fatalf("stopped plan contains runtime resources: %#v", stopped)
	}
	if len(stopped.DataClaims) != 1 || !reflect.DeepEqual(stopped.DataClaims, running.DataClaims) || stopped.DataIdentity != running.DataIdentity {
		t.Fatalf("stop changed retained world: running %#v, stopped %#v", running.DataClaims, stopped.DataClaims)
	}
	if len(stopped.DataClaims[0].Desired.OwnerReferences) != 0 || stopped.DataClaims[0].Desired.Labels[LabelDataPolicy] != "retain" {
		t.Fatal("stopped world claim must remain independent of runtime ownership")
	}
}

func TestBuildSevenDaysConfigurationHashUsesRenderedMeaning(t *testing.T) {
	t.Parallel()
	definition := sevendays.Definition()
	server := testServer("survival", definition.ID, arcadev1alpha1.DesiredStateRunning)
	inputs := []string{
		`{"name":"Survival","description":"Original","maxPlayers":16,"visibility":"unlisted"}`,
		"{\n  \"visibility\": \"unlisted\", \"maxPlayers\": 16,\n  \"description\": \"Original\", \"name\": \"Survival\"\n}",
		`{"name":"Survival","description":"Changed","maxPlayers":16,"visibility":"unlisted"}`,
	}
	hashes := make([]string, len(inputs))
	for i, input := range inputs {
		server.Spec.Settings = structJSON(input)
		plan, err := Build(server, definition)
		if err != nil {
			t.Fatalf("Build input %d: %v", i, err)
		}
		hashes[i] = plan.Workload.Spec.Template.Annotations[AnnotationConfigurationHash]
		if decoded, err := hex.DecodeString(hashes[i]); err != nil || len(decoded) != 32 {
			t.Fatalf("configuration hash %d = %q, want SHA-256 hex", i, hashes[i])
		}
	}
	if hashes[0] != hashes[1] {
		t.Errorf("equivalent settings have different hashes: %q != %q", hashes[0], hashes[1])
	}
	if hashes[0] == hashes[2] {
		t.Error("changing only description did not change the configuration hash")
	}
}
