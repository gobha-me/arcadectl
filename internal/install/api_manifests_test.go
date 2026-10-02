// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package install

import (
	"bytes"
	"context"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
)

const testAPIImage = "registry.example/arcadectl/api@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func renderAPI(t *testing.T, image string) []byte {
	t.Helper()
	command := exec.CommandContext(context.Background(), "bash", filepath.Join(repositoryRoot(t), "hack", "render-api.sh"), image)
	contents, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("render API: %v: %s", err, contents)
	}
	return contents
}

func TestAPIRBACAndExposureAreSeparateFromController(t *testing.T) {
	first := renderAPI(t, testAPIImage)
	if !bytes.Equal(first, renderAPI(t, testAPIImage)) {
		t.Fatal("API render nondeterministic")
	}
	objects := decodeObjects(t, first)
	want := []string{
		"/v1, Kind=ServiceAccount arcadectl-system/arcadectl-api",
		"rbac.authorization.k8s.io/v1, Kind=RoleBinding arcadectl-system/arcadectl-api",
		"rbac.authorization.k8s.io/v1, Kind=Role arcadectl-system/arcadectl-api",
		"/v1, Kind=Service arcadectl-system/arcadectl-api",
		"apps/v1, Kind=Deployment arcadectl-system/arcadectl-api",
	}
	if !slices.Equal(objectIdentities(objects), want) {
		t.Fatal("unexpected API install objects")
	}
	binding, role := &rbacv1.RoleBinding{}, &rbacv1.Role{}
	convertObject(t, objects[1], binding)
	convertObject(t, objects[2], role)
	if binding.RoleRef.Kind != "Role" || binding.RoleRef.Name != "arcadectl-api" || len(binding.Subjects) != 1 || binding.Subjects[0].Name != "arcadectl-api" || binding.Subjects[0].Namespace != "arcadectl-system" || binding.Subjects[0].Kind != "ServiceAccount" {
		t.Fatal("API binding not isolated")
	}
	if len(role.Rules) != 1 {
		t.Fatal("API role gained additional authority")
	}
	rule := role.Rules[0]
	if !slices.Equal(rule.APIGroups, []string{"arcade.gobha.me"}) || !slices.Equal(rule.Resources, []string{"gameservers", "gamebackups", "gamerestores", "gamedestroys"}) || !slices.Equal(rule.Verbs, []string{"get", "list", "watch", "create", "update", "patch", "delete"}) || len(rule.ResourceNames) != 0 || len(rule.NonResourceURLs) != 0 {
		t.Fatalf("API role gained controller/Secret/status/escalation authority: %#v", rule)
	}
	service := &corev1.Service{}
	convertObject(t, objects[3], service)
	if service.Spec.Type != corev1.ServiceTypeClusterIP || len(service.Spec.Ports) != 1 || service.Spec.Ports[0].Port != 443 || service.Spec.Ports[0].TargetPort.StrVal != "https" || service.Spec.Ports[0].NodePort != 0 || len(service.Spec.ExternalIPs) != 0 || service.Spec.LoadBalancerIP != "" {
		t.Fatal("API service exposes plaintext/health or public network")
	}
	deployment := &appsv1.Deployment{}
	convertObject(t, objects[4], deployment)
	if deployment.Spec.Replicas == nil || *deployment.Spec.Replicas != 1 || deployment.Spec.Strategy.Type != appsv1.RecreateDeploymentStrategyType {
		t.Fatal("rotation needs single Recreate API replica")
	}
	pod := deployment.Spec.Template.Spec
	if pod.ServiceAccountName != "arcadectl-api" || pod.HostNetwork || pod.SecurityContext == nil || pod.SecurityContext.FSGroup == nil || *pod.SecurityContext.FSGroup != 65532 || pod.SecurityContext.RunAsNonRoot == nil || !*pod.SecurityContext.RunAsNonRoot {
		t.Fatal("API pod identity/security mismatch")
	}
	if len(pod.Containers) != 1 || pod.Containers[0].Image != testAPIImage || len(pod.InitContainers) != 0 {
		t.Fatal("API image/sidecar boundary mismatch")
	}
	container := pod.Containers[0]
	if container.SecurityContext == nil || container.SecurityContext.AllowPrivilegeEscalation == nil || *container.SecurityContext.AllowPrivilegeEscalation || container.SecurityContext.ReadOnlyRootFilesystem == nil || !*container.SecurityContext.ReadOnlyRootFilesystem || container.SecurityContext.Capabilities == nil || !slices.Equal(container.SecurityContext.Capabilities.Drop, []corev1.Capability{"ALL"}) || container.Resources.Limits.Memory().IsZero() {
		t.Fatal("API container not bounded/restricted")
	}
	if container.ReadinessProbe == nil || container.ReadinessProbe.HTTPGet == nil || container.ReadinessProbe.HTTPGet.Path != "/readyz" || container.ReadinessProbe.HTTPGet.Port.StrVal != "health" {
		t.Fatal("API lacks private readiness")
	}
	if len(pod.Volumes) != 2 || len(container.VolumeMounts) != 2 {
		t.Fatal("unexpected API secret/material mounts")
	}
	for _, mount := range container.VolumeMounts {
		if !mount.ReadOnly || mount.SubPath != "" || mount.SubPathExpr != "" {
			t.Fatal("Secret projection cannot hot reload or is writable")
		}
	}
	verifier, tls := pod.Volumes[0].Secret, pod.Volumes[1].Secret
	if verifier == nil || verifier.SecretName != "arcadectl-admin-credential" || verifier.DefaultMode == nil || *verifier.DefaultMode != 0440 || len(verifier.Items) != 1 || verifier.Items[0].Key != "auth.json" || verifier.Items[0].Path != "auth.json" {
		t.Fatal("API mounts raw token or incorrect verifier mode")
	}
	if tls == nil || tls.SecretName != "arcadectl-api-tls" || len(tls.Items) != 2 || tls.DefaultMode == nil || *tls.DefaultMode != 0440 {
		t.Fatal("TLS prerequisite not explicit")
	}
	for _, env := range container.Env {
		if env.ValueFrom != nil || strings.Contains(strings.ToLower(env.Name), "token") {
			t.Fatal("credential passed through environment")
		}
	}
}

func TestRenderAPIRejectsTagsAndUntrustedImageText(t *testing.T) {
	for _, image := range []string{"", "api:latest", "api@sha256:deadbeef", "api@sha256:" + strings.Repeat("a", 64) + "\n"} {
		command := exec.CommandContext(context.Background(), "bash", filepath.Join(repositoryRoot(t), "hack", "render-api.sh"), image)
		if err := command.Run(); err == nil {
			t.Fatal("API renderer accepted unpinned image")
		}
	}
}
