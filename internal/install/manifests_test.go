// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package install

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
)

const testControllerImage = "registry.example/arcadectl/controller@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestRenderedControllerManifest(t *testing.T) {
	t.Parallel()

	first := renderController(t, testControllerImage)
	second := renderController(t, testControllerImage)
	if !bytes.Equal(first, second) {
		t.Fatal("install rendering is not deterministic")
	}
	objects := decodeObjects(t, first)
	expected := []string{
		"/v1, Kind=ServiceAccount arcadectl-system/arcadectl-controller",
		"rbac.authorization.k8s.io/v1, Kind=Role arcadectl-system/arcadectl-controller",
		"rbac.authorization.k8s.io/v1, Kind=RoleBinding arcadectl-system/arcadectl-controller",
		"apps/v1, Kind=Deployment arcadectl-system/arcadectl-controller",
	}
	if got := objectIdentities(objects); !slices.Equal(got, expected) {
		t.Fatalf("rendered objects = %#v, want %#v", got, expected)
	}

	assertRole(t, objects[1])
	assertRoleBinding(t, objects[2])
	assertControllerDeployment(t, objects[3], testControllerImage)
}

func TestClusterAnchorsAreRetainedAndRestricted(t *testing.T) {
	t.Parallel()

	contents, err := os.ReadFile(filepath.Join(repositoryRoot(t), "config", "install", "anchors.yaml"))
	if err != nil {
		t.Fatalf("read cluster anchors: %v", err)
	}
	objects := decodeObjects(t, contents)
	expected := []string{
		"/v1, Kind=Namespace /arcadectl-system",
		"apiextensions.k8s.io/v1, Kind=CustomResourceDefinition /gameservers.arcade.gobha.me",
	}
	if got := objectIdentities(objects); !slices.Equal(got, expected) {
		t.Fatalf("anchor objects = %#v, want %#v", got, expected)
	}
	namespace := objects[0]
	for _, label := range []string{"pod-security.kubernetes.io/enforce", "pod-security.kubernetes.io/audit", "pod-security.kubernetes.io/warn"} {
		if namespace.GetLabels()[label] != "restricted" {
			t.Errorf("namespace label %q = %q, want restricted", label, namespace.GetLabels()[label])
		}
		if namespace.GetLabels()[label+"-version"] != "v1.37" {
			t.Errorf("namespace label %q = %q, want v1.37", label+"-version", namespace.GetLabels()[label+"-version"])
		}
	}
}

func TestCanonicalControllerManifestIsGenerated(t *testing.T) {
	t.Parallel()

	const canonical = "ghcr.io/gobha-me/arcadectl-controller@sha256:0000000000000000000000000000000000000000000000000000000000000000"
	want := renderController(t, canonical)
	got, err := os.ReadFile(filepath.Join(repositoryRoot(t), "config", "install", "controller.yaml"))
	if err != nil {
		t.Fatalf("read generated install manifest: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("generated install manifest is stale; run make generate")
	}
}

func TestRenderControllerRejectsUnpinnedImage(t *testing.T) {
	t.Parallel()

	for _, image := range []string{"", "controller:latest", "registry.example/controller@sha256:deadbeef", "Registry.example/controller@sha256:" + strings.Repeat("a", 64)} {
		command := exec.CommandContext(context.Background(), filepath.Join(repositoryRoot(t), "hack", "render-controller.sh"), image)
		if output, err := command.CombinedOutput(); err == nil {
			t.Fatalf("render-controller accepted %q:\n%s", image, output)
		}
	}
}

func TestUninstallManifestPreservesClusterAnchorsAndData(t *testing.T) {
	t.Parallel()

	contents, err := os.ReadFile(filepath.Join(repositoryRoot(t), "config", "install", "uninstall.yaml"))
	if err != nil {
		t.Fatalf("read uninstall manifest: %v", err)
	}
	objects := decodeObjects(t, contents)
	expected := []string{
		"apps/v1, Kind=Deployment arcadectl-system/arcadectl-controller",
		"rbac.authorization.k8s.io/v1, Kind=RoleBinding arcadectl-system/arcadectl-controller",
		"rbac.authorization.k8s.io/v1, Kind=Role arcadectl-system/arcadectl-controller",
		"/v1, Kind=ServiceAccount arcadectl-system/arcadectl-controller",
	}
	if got := objectIdentities(objects); !slices.Equal(got, expected) {
		t.Fatalf("uninstall objects = %#v, want controller-only set %#v", got, expected)
	}
}

func TestInstallScriptAppliesAnchorsThenController(t *testing.T) {
	t.Parallel()

	fakeKubectl, logPath := writeFakeKubectl(t)
	command := exec.CommandContext(context.Background(), filepath.Join(repositoryRoot(t), "hack", "install.sh"), testControllerImage)
	command.Env = append(os.Environ(), "KUBECTL="+fakeKubectl, "KUBECTL_LOG="+logPath)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("install script failed: %v\n%s", err, output)
	}
	logContents, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read fake kubectl log: %v", err)
	}
	logText := string(logContents)
	for _, commandFragment := range []string{
		"apply -f " + filepath.Join(repositoryRoot(t), "config", "install", "anchors.yaml"),
		"wait --for=condition=Established customresourcedefinition/gameservers.arcade.gobha.me --timeout=60s",
		"apply -f /tmp/",
		"rollout status deployment/arcadectl-controller --namespace arcadectl-system --timeout=120s",
	} {
		if !strings.Contains(logText, commandFragment) {
			t.Errorf("install command log %q omits %q", logText, commandFragment)
		}
	}
}

func TestInstallRejectsInvalidImageBeforeMutation(t *testing.T) {
	t.Parallel()

	fakeKubectl, logPath := writeFakeKubectl(t)
	command := exec.CommandContext(context.Background(), filepath.Join(repositoryRoot(t), "hack", "install.sh"), "controller:latest")
	command.Env = append(os.Environ(), "KUBECTL="+fakeKubectl, "KUBECTL_LOG="+logPath)
	if output, err := command.CombinedOutput(); err == nil {
		t.Fatalf("install accepted mutable image:\n%s", output)
	}
	logContents, err := os.ReadFile(logPath)
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("read fake kubectl log: %v", err)
	}
	if len(logContents) != 0 {
		t.Fatalf("invalid install mutated the cluster: %s", logContents)
	}
}

func TestUninstallRequiresEveryServerStopped(t *testing.T) {
	t.Parallel()

	t.Run("refuses running server", func(t *testing.T) {
		fakeKubectl, logPath := writeFakeKubectl(t)
		command := exec.CommandContext(context.Background(), filepath.Join(repositoryRoot(t), "hack", "uninstall.sh"))
		command.Env = append(os.Environ(), "KUBECTL="+fakeKubectl, "KUBECTL_LOG="+logPath, "KUBECTL_SERVERS=factory\tRunning\tReady\t2\t2\n")
		if output, err := command.CombinedOutput(); err == nil || !strings.Contains(string(output), "refusing uninstall") {
			t.Fatalf("unsafe uninstall result = %v\n%s", err, output)
		}
		logContents, err := os.ReadFile(logPath)
		if err != nil {
			t.Fatalf("read fake kubectl log: %v", err)
		}
		if strings.Contains(string(logContents), "delete") {
			t.Fatalf("unsafe uninstall reached delete: %s", logContents)
		}
	})

	t.Run("refuses stale stopped status", func(t *testing.T) {
		fakeKubectl, logPath := writeFakeKubectl(t)
		command := exec.CommandContext(context.Background(), filepath.Join(repositoryRoot(t), "hack", "uninstall.sh"))
		command.Env = append(os.Environ(), "KUBECTL="+fakeKubectl, "KUBECTL_LOG="+logPath, "KUBECTL_SERVERS=factory\tStopped\tStopped\t2\t1\n")
		if output, err := command.CombinedOutput(); err == nil || !strings.Contains(string(output), "current generation") {
			t.Fatalf("stale uninstall result = %v\n%s", err, output)
		}
		logContents, err := os.ReadFile(logPath)
		if err != nil {
			t.Fatalf("read fake kubectl log: %v", err)
		}
		if strings.Contains(string(logContents), "delete") {
			t.Fatalf("stale uninstall reached delete: %s", logContents)
		}
	})

	t.Run("removes controller for stopped server", func(t *testing.T) {
		fakeKubectl, logPath := writeFakeKubectl(t)
		command := exec.CommandContext(context.Background(), filepath.Join(repositoryRoot(t), "hack", "uninstall.sh"))
		command.Env = append(os.Environ(), "KUBECTL="+fakeKubectl, "KUBECTL_LOG="+logPath, "KUBECTL_SERVERS=factory\tStopped\tStopped\t2\t2\n")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("safe uninstall failed: %v\n%s", err, output)
		}
		logContents, err := os.ReadFile(logPath)
		if err != nil {
			t.Fatalf("read fake kubectl log: %v", err)
		}
		if !strings.Contains(string(logContents), "delete --filename "+filepath.Join(repositoryRoot(t), "config", "install", "uninstall.yaml")+" --ignore-not-found=true") {
			t.Fatalf("safe uninstall did not delete controller resources: %s", logContents)
		}
	})
}

func renderController(t *testing.T, image string) []byte {
	t.Helper()
	command := exec.CommandContext(context.Background(), filepath.Join(repositoryRoot(t), "hack", "render-controller.sh"), image)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("render install: %v\n%s", err, output)
	}
	return output
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}
	return root
}

func writeFakeKubectl(t *testing.T) (string, string) {
	t.Helper()
	directory := t.TempDir()
	commandPath := filepath.Join(directory, "kubectl")
	logPath := filepath.Join(directory, "kubectl.log")
	contents := `#!/bin/sh
set -eu
printf '%s\n' "$*" >>"$KUBECTL_LOG"
if [ "${1:-}" = "get" ]; then
  printf '%b' "${KUBECTL_SERVERS:-}"
fi
if [ "${1:-}" = "apply" ] && [ "${3:-}" = "-" ]; then
  cat >/dev/null
fi
`
	if err := os.WriteFile(commandPath, []byte(contents), 0o755); err != nil {
		t.Fatalf("write fake kubectl: %v", err)
	}
	return commandPath, logPath
}

func decodeObjects(t *testing.T, contents []byte) []*unstructured.Unstructured {
	t.Helper()
	decoder := utilyaml.NewYAMLOrJSONDecoder(bytes.NewReader(contents), 4096)
	var objects []*unstructured.Unstructured
	for {
		object := &unstructured.Unstructured{}
		if err := decoder.Decode(object); err != nil {
			if err == io.EOF {
				break
			}
			t.Fatalf("decode manifest: %v", err)
		}
		if len(object.Object) != 0 {
			objects = append(objects, object)
		}
	}
	return objects
}

func objectIdentities(objects []*unstructured.Unstructured) []string {
	identities := make([]string, 0, len(objects))
	for _, object := range objects {
		identities = append(identities, object.GroupVersionKind().String()+" "+object.GetNamespace()+"/"+object.GetName())
	}
	return identities
}

func assertRole(t *testing.T, object *unstructured.Unstructured) {
	t.Helper()
	role := &rbacv1.Role{}
	convertObject(t, object, role)
	if role.Namespace != "arcadectl-system" {
		t.Errorf("Role namespace = %q", role.Namespace)
	}
	expected := []rbacv1.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"configmaps", "services"}, Verbs: []string{"create", "delete", "get", "list", "patch", "update", "watch"}},
		{APIGroups: []string{""}, Resources: []string{"persistentvolumeclaims"}, Verbs: []string{"create", "get", "list", "patch", "update", "watch"}},
		{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"create", "delete", "get", "list", "patch", "update", "watch"}},
		{APIGroups: []string{"arcade.gobha.me"}, Resources: []string{"gameservers"}, Verbs: []string{"get", "list", "watch"}},
		{APIGroups: []string{"arcade.gobha.me"}, Resources: []string{"gameservers/status"}, Verbs: []string{"get", "patch", "update"}},
		{APIGroups: []string{"coordination.k8s.io"}, Resources: []string{"leases"}, Verbs: []string{"create", "get", "list", "patch", "update", "watch"}},
	}
	got := normalizedRules(role.Rules)
	want := normalizedRules(expected)
	if !slices.EqualFunc(got, want, func(a, b rbacv1.PolicyRule) bool {
		return slices.Equal(a.APIGroups, b.APIGroups) &&
			slices.Equal(a.Resources, b.Resources) &&
			slices.Equal(a.ResourceNames, b.ResourceNames) &&
			slices.Equal(a.NonResourceURLs, b.NonResourceURLs) &&
			slices.Equal(a.Verbs, b.Verbs)
	}) {
		t.Fatalf("Role rules = %#v, want exact least-privilege matrix %#v", got, want)
	}
}

func normalizedRules(source []rbacv1.PolicyRule) []rbacv1.PolicyRule {
	rules := make([]rbacv1.PolicyRule, len(source))
	for index, sourceRule := range source {
		rule := *sourceRule.DeepCopy()
		slices.Sort(rule.APIGroups)
		slices.Sort(rule.Resources)
		slices.Sort(rule.ResourceNames)
		slices.Sort(rule.NonResourceURLs)
		slices.Sort(rule.Verbs)
		rules[index] = rule
	}
	slices.SortFunc(rules, func(a, b rbacv1.PolicyRule) int {
		aKey := strings.Join(a.APIGroups, "\x00") + "\x01" + strings.Join(a.Resources, "\x00")
		bKey := strings.Join(b.APIGroups, "\x00") + "\x01" + strings.Join(b.Resources, "\x00")
		return strings.Compare(aKey, bKey)
	})
	return rules
}

func assertRoleBinding(t *testing.T, object *unstructured.Unstructured) {
	t.Helper()
	binding := &rbacv1.RoleBinding{}
	convertObject(t, object, binding)
	if binding.Namespace != "arcadectl-system" || binding.RoleRef.Kind != "Role" || binding.RoleRef.Name != "arcadectl-controller" {
		t.Fatalf("RoleBinding target = %#v", binding.RoleRef)
	}
	if len(binding.Subjects) != 1 || binding.Subjects[0].Kind != "ServiceAccount" || binding.Subjects[0].Name != "arcadectl-controller" || binding.Subjects[0].Namespace != "arcadectl-system" {
		t.Fatalf("RoleBinding subjects = %#v", binding.Subjects)
	}
}

func assertControllerDeployment(t *testing.T, object *unstructured.Unstructured, image string) {
	t.Helper()
	deployment := &appsv1.Deployment{}
	convertObject(t, object, deployment)
	if deployment.Namespace != "arcadectl-system" || deployment.Spec.Template.Spec.ServiceAccountName != "arcadectl-controller" {
		t.Fatalf("controller deployment identity = namespace %q service account %q", deployment.Namespace, deployment.Spec.Template.Spec.ServiceAccountName)
	}
	pod := deployment.Spec.Template.Spec
	if pod.AutomountServiceAccountToken == nil || !*pod.AutomountServiceAccountToken || pod.SecurityContext == nil || pod.SecurityContext.RunAsNonRoot == nil || !*pod.SecurityContext.RunAsNonRoot || pod.SecurityContext.RunAsUser == nil || *pod.SecurityContext.RunAsUser != 65532 || pod.SecurityContext.RunAsGroup == nil || *pod.SecurityContext.RunAsGroup != 65532 || pod.SecurityContext.SeccompProfile == nil || pod.SecurityContext.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
		t.Fatalf("controller pod security context = %#v", pod.SecurityContext)
	}
	if len(pod.Containers) != 1 {
		t.Fatalf("controller containers = %#v", pod.Containers)
	}
	container := pod.Containers[0]
	if container.Image != image || container.ImagePullPolicy != corev1.PullIfNotPresent {
		t.Fatalf("controller image = %q pull policy %q", container.Image, container.ImagePullPolicy)
	}
	for _, argument := range []string{"--watch-namespace=$(POD_NAMESPACE)", "--leader-elect=true", "--metrics-bind-address=0", "--health-probe-bind-address=:8081"} {
		if !slices.Contains(container.Args, argument) {
			t.Errorf("controller args %v omit %q", container.Args, argument)
		}
	}
	if container.LivenessProbe == nil || container.ReadinessProbe == nil || container.LivenessProbe.HTTPGet == nil || container.LivenessProbe.HTTPGet.Path != "/healthz" || container.ReadinessProbe.HTTPGet == nil || container.ReadinessProbe.HTTPGet.Path != "/readyz" {
		t.Fatalf("controller probes = liveness %#v readiness %#v", container.LivenessProbe, container.ReadinessProbe)
	}
	if container.SecurityContext == nil || container.SecurityContext.AllowPrivilegeEscalation == nil || *container.SecurityContext.AllowPrivilegeEscalation || container.SecurityContext.ReadOnlyRootFilesystem == nil || !*container.SecurityContext.ReadOnlyRootFilesystem || container.SecurityContext.Capabilities == nil || !slices.Contains(container.SecurityContext.Capabilities.Drop, corev1.Capability("ALL")) {
		t.Fatalf("controller container security context = %#v", container.SecurityContext)
	}
	for _, resources := range []corev1.ResourceList{container.Resources.Requests, container.Resources.Limits} {
		if resources.Cpu().Sign() <= 0 || resources.Memory().Sign() <= 0 {
			t.Fatalf("controller resources are not bounded: %#v", container.Resources)
		}
	}
}

func convertObject(t *testing.T, source *unstructured.Unstructured, target any) {
	t.Helper()
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(source.Object, target); err != nil {
		t.Fatalf("convert %s: %v", source.GroupVersionKind(), err)
	}
}
