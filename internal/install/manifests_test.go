// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package install

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
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
		"rbac.authorization.k8s.io/v1, Kind=ClusterRole /arcadectl-volumeattachment-reader",
		"rbac.authorization.k8s.io/v1, Kind=ClusterRoleBinding /arcadectl-volumeattachment-reader",
		"admissionregistration.k8s.io/v1, Kind=ValidatingAdmissionPolicy /arcadectl-backup-worker-gate",
		"admissionregistration.k8s.io/v1, Kind=ValidatingAdmissionPolicyBinding /arcadectl-backup-worker-gate",
		"apps/v1, Kind=Deployment arcadectl-system/arcadectl-controller",
	}
	if got := objectIdentities(objects); !slices.Equal(got, expected) {
		t.Fatalf("rendered objects = %#v, want %#v", got, expected)
	}

	assertRole(t, objects[1])
	assertRoleBinding(t, objects[2])
	assertVolumeAttachmentAuthority(t, objects[3], objects[4])
	assertBackupWorkerAdmission(t, objects[5], objects[6])
	assertControllerDeployment(t, objects[7], testControllerImage)
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
		"apiextensions.k8s.io/v1, Kind=CustomResourceDefinition /gamebackups.arcade.gobha.me",
		"apiextensions.k8s.io/v1, Kind=CustomResourceDefinition /gamerestores.arcade.gobha.me",
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
		"rbac.authorization.k8s.io/v1, Kind=ClusterRoleBinding /arcadectl-volumeattachment-reader",
		"rbac.authorization.k8s.io/v1, Kind=ClusterRole /arcadectl-volumeattachment-reader",
		"rbac.authorization.k8s.io/v1, Kind=RoleBinding arcadectl-system/arcadectl-controller",
		"rbac.authorization.k8s.io/v1, Kind=Role arcadectl-system/arcadectl-controller",
		"/v1, Kind=ServiceAccount arcadectl-system/arcadectl-controller",
	}
	if got := objectIdentities(objects); !slices.Equal(got, expected) {
		t.Fatalf("uninstall objects = %#v, want controller-only set %#v", got, expected)
	}
}

func assertBackupWorkerAdmission(t *testing.T, policyObject, bindingObject *unstructured.Unstructured) {
	t.Helper()
	policy := &admissionregistrationv1.ValidatingAdmissionPolicy{}
	convertObject(t, policyObject, policy)
	if policy.Spec.FailurePolicy == nil || *policy.Spec.FailurePolicy != admissionregistrationv1.Fail {
		t.Fatalf("backup worker admission failure policy = %#v, want Fail", policy.Spec.FailurePolicy)
	}
	if len(policy.Spec.MatchConstraints.ResourceRules) != 1 || len(policy.Spec.Validations) != 4 {
		t.Fatalf("backup worker admission shape = rules %#v validations %#v", policy.Spec.MatchConstraints.ResourceRules, policy.Spec.Validations)
	}
	rule := policy.Spec.MatchConstraints.ResourceRules[0]
	for _, resource := range []string{"pods", "pods/ephemeralcontainers", "pods/resize"} {
		if !slices.Contains(rule.Resources, resource) {
			t.Errorf("backup worker admission resources %v omit %q", rule.Resources, resource)
		}
	}
	expressions := make([]string, 0, len(policy.Spec.Validations))
	for _, variable := range policy.Spec.Variables {
		expressions = append(expressions, variable.Expression)
	}
	for _, validation := range policy.Spec.Validations {
		expressions = append(expressions, validation.Expression)
	}
	joined := strings.Join(expressions, "\n")
	for _, required := range []string{"backup-authorized", "backup-pod-authorized", "request.userInfo.username", "object.spec.containers == oldObject.spec.containers"} {
		if !strings.Contains(joined, required) {
			t.Errorf("backup worker admission validation omits %q", required)
		}
	}

	binding := &admissionregistrationv1.ValidatingAdmissionPolicyBinding{}
	convertObject(t, bindingObject, binding)
	if binding.Spec.PolicyName != policy.Name || !slices.Equal(binding.Spec.ValidationActions, []admissionregistrationv1.ValidationAction{admissionregistrationv1.Deny}) ||
		binding.Spec.MatchResources == nil || binding.Spec.MatchResources.NamespaceSelector == nil ||
		binding.Spec.MatchResources.NamespaceSelector.MatchLabels["kubernetes.io/metadata.name"] != "arcadectl-system" {
		t.Fatalf("backup worker admission binding = %#v", binding.Spec)
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
		"wait --for=condition=Established customresourcedefinition/gamebackups.arcade.gobha.me --timeout=60s",
		"wait --for=condition=Established customresourcedefinition/gamerestores.arcade.gobha.me --timeout=60s",
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

	t.Run("refuses deleting stopped server", func(t *testing.T) {
		fakeKubectl, logPath := writeFakeKubectl(t)
		command := exec.CommandContext(context.Background(), filepath.Join(repositoryRoot(t), "hack", "uninstall.sh"))
		command.Env = append(os.Environ(), "KUBECTL="+fakeKubectl, "KUBECTL_LOG="+logPath,
			"KUBECTL_SERVERS=factory\tStopped\tStopped\t2\t2\t2026-09-21T00:00:00Z\n")
		if output, err := command.CombinedOutput(); err == nil || !strings.Contains(string(output), "non-deleting") {
			t.Fatalf("deleting-server uninstall result = %v\n%s", err, output)
		}
		logContents, err := os.ReadFile(logPath)
		if err != nil {
			t.Fatalf("read fake kubectl log: %v", err)
		}
		if strings.Contains(string(logContents), "delete") {
			t.Fatalf("deleting-server uninstall reached delete: %s", logContents)
		}
	})

	t.Run("removes controller for stopped server", func(t *testing.T) {
		fakeKubectl, logPath := writeFakeKubectl(t)
		command := exec.CommandContext(context.Background(), filepath.Join(repositoryRoot(t), "hack", "uninstall.sh"))
		command.Env = append(os.Environ(), "KUBECTL="+fakeKubectl, "KUBECTL_LOG="+logPath,
			"KUBECTL_SERVERS=factory\tStopped\tStopped\t2\t2\t\n", "KUBECTL_CONTROLLER_REPLICAS=1")
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
		if !strings.Contains(string(logContents), "scale deployment/arcadectl-controller --namespace arcadectl-system --replicas=0") {
			t.Fatalf("safe uninstall did not quiesce the controller: %s", logContents)
		}
	})
}

func TestUninstallRequiresSettledDataOperations(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		backups string
		jobs    string
		pods    string
		leases  string
		message string
	}{
		{name: "running backup", backups: "nightly\tRunning\t1\t1\t\n", message: "every GameBackup must be terminal"},
		{name: "preparing backup", backups: "nightly\tPreparing\t1\t1\t\n", message: "every GameBackup must be terminal"},
		{name: "verifying backup", backups: "nightly\tVerifying\t1\t1\t\n", message: "every GameBackup must be terminal"},
		{name: "stale terminal backup", backups: "nightly\tSucceeded\t2\t1\t\n", message: "current generation"},
		{name: "deleting terminal backup", backups: "nightly\tSucceeded\t2\t2\t2026-09-21T00:00:00Z\n", message: "not deleting"},
		{name: "backup job by name", backups: "nightly\tSucceeded\t1\t1\t\n", jobs: "backup-deadbeef\t\t\t\n", message: "Jobs, Pods, or Leases"},
		{name: "backup job by labels", backups: "nightly\tSucceeded\t1\t1\t\n", jobs: "renamed\tarcadectl\tbackup-worker\t\n", message: "Jobs, Pods, or Leases"},
		{name: "backup pod by service account", backups: "nightly\tFailed\t1\t1\t\n", pods: "renamed\t\t\t\tbackup-deadbeef-authority\t\n", message: "Jobs, Pods, or Leases"},
		{name: "backup pod by owner", backups: "nightly\tFailed\t1\t1\t\n", pods: "renamed\t\t\t\tdefault\tbatch/v1/Job/backup-deadbeef \n", message: "Jobs, Pods, or Leases"},
		{name: "data operation lease by name", backups: "nightly\tCancelled\t1\t1\t\n", leases: "data-operation-deadbeef\t\t\n", message: "Jobs, Pods, or Leases"},
		{name: "data operation lease by labels", backups: "nightly\tCancelled\t1\t1\t\n", leases: "renamed\tarcadectl\tidentity\n", message: "Jobs, Pods, or Leases"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fakeKubectl, logPath := writeFakeKubectl(t)
			command := exec.CommandContext(context.Background(), filepath.Join(repositoryRoot(t), "hack", "uninstall.sh"))
			command.Env = append(os.Environ(),
				"KUBECTL="+fakeKubectl,
				"KUBECTL_LOG="+logPath,
				"KUBECTL_SERVERS=factory\tStopped\tStopped\t2\t2\n",
				"KUBECTL_BACKUPS="+test.backups,
				"KUBECTL_DATA_JOBS="+test.jobs,
				"KUBECTL_DATA_PODS="+test.pods,
				"KUBECTL_DATA_LEASES="+test.leases,
			)
			output, err := command.CombinedOutput()
			if err == nil || !strings.Contains(string(output), test.message) {
				t.Fatalf("unsafe uninstall result = %v, want %q\n%s", err, test.message, output)
			}
			logContents, readErr := os.ReadFile(logPath)
			if readErr != nil {
				t.Fatalf("read fake kubectl log: %v", readErr)
			}
			if strings.Contains(string(logContents), "delete") {
				t.Fatalf("unsafe uninstall reached delete: %s", logContents)
			}
		})
	}
}

func TestUninstallFailsClosedWhenSafetyStateCannotBeRead(t *testing.T) {
	t.Parallel()

	fakeKubectl, logPath := writeFakeKubectl(t)
	command := exec.CommandContext(context.Background(), filepath.Join(repositoryRoot(t), "hack", "uninstall.sh"))
	command.Env = append(os.Environ(),
		"KUBECTL="+fakeKubectl,
		"KUBECTL_LOG="+logPath,
		"KUBECTL_SERVERS=factory\tStopped\tStopped\t2\t2\t\n",
		"KUBECTL_BACKUPS=nightly\tSucceeded\t1\t1\t\n",
		"KUBECTL_FAIL_GET=jobs.batch",
	)
	if output, err := command.CombinedOutput(); err == nil {
		t.Fatalf("unreadable safety state was accepted:\n%s", output)
	}
	logContents, readErr := os.ReadFile(logPath)
	if readErr != nil {
		t.Fatalf("read fake kubectl log: %v", readErr)
	}
	if strings.Contains(string(logContents), "delete") || strings.Contains(string(logContents), "scale") {
		t.Fatalf("unreadable safety state mutated the controller: %s", logContents)
	}
}

func TestUninstallRequiresEffectiveRetainedAdmissionGate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		env  string
	}{
		{name: "policy missing", env: "KUBECTL_FAIL_GET=validatingadmissionpolicies.admissionregistration.k8s.io"},
		{name: "binding missing", env: "KUBECTL_FAIL_GET=validatingadmissionpolicybindings.admissionregistration.k8s.io"},
		{name: "policy only detects labels", env: `KUBECTL_POLICY_FILTER=.spec.variables[0].expression = "has(object.metadata.labels) && object.metadata.labels['app.kubernetes.io/name'] == 'backup-worker'"`},
		{name: "policy allows gate removal", env: `KUBECTL_POLICY_FILTER=.spec.validations[3].expression = "true"`},
		{name: "policy omits update", env: `KUBECTL_POLICY_FILTER=.spec.matchConstraints.resourceRules[0].operations = ["CREATE"]`},
		{name: "policy object selector excludes workers", env: `KUBECTL_POLICY_FILTER=.spec.matchConstraints.objectSelector = {"matchLabels":{"exclude":"workers"}}`},
		{name: "binding only warns", env: `KUBECTL_BINDING_FILTER=.spec.validationActions = ["Warn"]`},
		{name: "binding object selector excludes workers", env: `KUBECTL_BINDING_FILTER=.spec.matchResources.objectSelector = {"matchLabels":{"exclude":"workers"}}`},
		{name: "gate does not deny", env: "KUBECTL_ADMISSION_MODE=allow"},
		{name: "unexpected admission failure", env: "KUBECTL_ADMISSION_MODE=unexpected"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fakeKubectl, logPath := writeFakeKubectl(t)
			command := exec.CommandContext(context.Background(), filepath.Join(repositoryRoot(t), "hack", "uninstall.sh"))
			command.Env = append(os.Environ(),
				"KUBECTL="+fakeKubectl,
				"KUBECTL_LOG="+logPath,
				"KUBECTL_SERVERS=factory\tStopped\tStopped\t2\t2\t\n",
				test.env,
			)
			if output, err := command.CombinedOutput(); err == nil {
				t.Fatalf("unsafe admission gate result = %v\n%s", err, output)
			}
			logContents, readErr := os.ReadFile(logPath)
			if readErr != nil {
				t.Fatalf("read fake kubectl log: %v", readErr)
			}
			if strings.Contains(string(logContents), "delete") || strings.Contains(string(logContents), "scale") {
				t.Fatalf("unsafe admission gate mutated the controller: %s", logContents)
			}
		})
	}
}

func TestUninstallWaitsForTerminatingControllerAtZeroReplicas(t *testing.T) {
	t.Parallel()

	fakeKubectl, logPath := writeFakeKubectl(t)
	command := exec.CommandContext(context.Background(), filepath.Join(repositoryRoot(t), "hack", "uninstall.sh"))
	command.Env = append(os.Environ(),
		"KUBECTL="+fakeKubectl,
		"KUBECTL_LOG="+logPath,
		"KUBECTL_SERVERS=factory\tStopped\tStopped\t2\t2\t\n",
		"KUBECTL_CONTROLLER_REPLICAS=0",
		"KUBECTL_CONTROLLER_PODS_ONCE=pod/arcadectl-controller-terminating\n",
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("zero-replica uninstall failed: %v\n%s", err, output)
	}
	logContents, readErr := os.ReadFile(logPath)
	if readErr != nil {
		t.Fatalf("read fake kubectl log: %v", readErr)
	}
	lines := strings.Split(strings.TrimSpace(string(logContents)), "\n")
	var serverGets, controllerPodGets []int
	for index, line := range lines {
		if strings.HasPrefix(line, "get gameservers.arcade.gobha.me ") {
			serverGets = append(serverGets, index)
		}
		if strings.Contains(line, "get pods --namespace arcadectl-system --selector=app.kubernetes.io/name=arcadectl-controller") {
			controllerPodGets = append(controllerPodGets, index)
		}
	}
	if len(serverGets) != 2 || len(controllerPodGets) < 2 || controllerPodGets[len(controllerPodGets)-1] >= serverGets[1] {
		t.Fatalf("post-quiesce safety check was not ordered after controller Pod absence: %s", logContents)
	}
	if strings.Contains(string(logContents), "scale deployment/arcadectl-controller") {
		t.Fatalf("zero-replica uninstall changed the declared replica count: %s", logContents)
	}
}

func TestUninstallRestoresControllerWhenStateChangesAfterQuiescing(t *testing.T) {
	t.Parallel()

	fakeKubectl, logPath := writeFakeKubectl(t)
	command := exec.CommandContext(context.Background(), filepath.Join(repositoryRoot(t), "hack", "uninstall.sh"))
	command.Env = append(os.Environ(),
		"KUBECTL="+fakeKubectl,
		"KUBECTL_LOG="+logPath,
		"KUBECTL_SERVERS=factory\tStopped\tStopped\t2\t2\t\n",
		"KUBECTL_BACKUPS=nightly\tSucceeded\t1\t1\t\n",
		"KUBECTL_BACKUPS_AFTER_QUIESCE=nightly\tRunning\t1\t1\t\n",
		"KUBECTL_CONTROLLER_REPLICAS=1",
	)
	output, err := command.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "restoring the controller to 1 replicas") {
		t.Fatalf("racing uninstall result = %v\n%s", err, output)
	}
	logContents, readErr := os.ReadFile(logPath)
	if readErr != nil {
		t.Fatalf("read fake kubectl log: %v", readErr)
	}
	logText := string(logContents)
	for _, commandFragment := range []string{
		"scale deployment/arcadectl-controller --namespace arcadectl-system --replicas=0",
		"scale deployment/arcadectl-controller --namespace arcadectl-system --replicas=1",
		"rollout status deployment/arcadectl-controller --namespace arcadectl-system --timeout=120s",
	} {
		if !strings.Contains(logText, commandFragment) {
			t.Errorf("racing uninstall log %q omits %q", logText, commandFragment)
		}
	}
	if strings.Contains(logText, "delete --filename") {
		t.Fatalf("racing uninstall reached delete: %s", logContents)
	}
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
	for _, fixture := range []string{"backup-worker-admission-policy", "backup-worker-admission-policy-binding"} {
		contents, err := os.ReadFile(filepath.Join(repositoryRoot(t), "config", "install", fixture+".yaml"))
		if err != nil {
			t.Fatalf("read admission fixture: %v", err)
		}
		objects := decodeObjects(t, contents)
		if len(objects) != 1 {
			t.Fatalf("admission fixture %s has %d objects", fixture, len(objects))
		}
		encoded, err := json.Marshal(objects[0])
		if err != nil {
			t.Fatalf("encode admission fixture: %v", err)
		}
		if err := os.WriteFile(filepath.Join(directory, fixture+".json"), encoded, 0o600); err != nil {
			t.Fatalf("write admission fixture: %v", err)
		}
	}
	contents := `#!/bin/sh
set -eu
fixture_dir=$(dirname "$0")
printf '%s\n' "$*" >>"$KUBECTL_LOG"
if [ "${1:-}" = "get" ]; then
  if [ -n "${KUBECTL_FAIL_GET:-}" ] && [ "${2:-}" = "$KUBECTL_FAIL_GET" ]; then
    exit 42
  fi
  case "${2:-}" in
    gameservers.arcade.gobha.me) printf '%b' "${KUBECTL_SERVERS:-}" ;;
    gamebackups.arcade.gobha.me)
      backup_gets=$(grep -c '^get gamebackups.arcade.gobha.me ' "$KUBECTL_LOG")
      if [ "$backup_gets" -gt 1 ] && [ "${KUBECTL_BACKUPS_AFTER_QUIESCE+x}" = x ]; then
        printf '%b' "$KUBECTL_BACKUPS_AFTER_QUIESCE"
      else
        printf '%b' "${KUBECTL_BACKUPS:-}"
      fi
      ;;
    jobs.batch) printf '%b' "${KUBECTL_DATA_JOBS:-}" ;;
    pods)
      case "$*" in
        *app.kubernetes.io/name=arcadectl-controller*)
          controller_pod_gets=$(grep -c -- '--selector=app.kubernetes.io/name=arcadectl-controller' "$KUBECTL_LOG")
          if [ "$controller_pod_gets" -eq 1 ] && [ "${KUBECTL_CONTROLLER_PODS_ONCE+x}" = x ]; then
            printf '%b' "$KUBECTL_CONTROLLER_PODS_ONCE"
          else
            printf '%b' "${KUBECTL_CONTROLLER_PODS:-}"
          fi
          ;;
        *) printf '%b' "${KUBECTL_DATA_PODS:-}" ;;
      esac
      ;;
    leases.coordination.k8s.io) printf '%b' "${KUBECTL_DATA_LEASES:-}" ;;
    deployment) printf '%b' "${KUBECTL_CONTROLLER_REPLICAS:-}" ;;
    validatingadmissionpolicies.admissionregistration.k8s.io)
      jq "${KUBECTL_POLICY_FILTER:-.}" "$fixture_dir/backup-worker-admission-policy.json"
      ;;
    validatingadmissionpolicybindings.admissionregistration.k8s.io)
      jq "${KUBECTL_BINDING_FILTER:-.}" "$fixture_dir/backup-worker-admission-policy-binding.json"
      ;;
  esac
fi
if [ "${1:-}" = "create" ]; then
  case "$*" in
    *--dry-run=client*)
      case "$*" in
        *backup-worker-admission-policy-binding.yaml*) cat "$fixture_dir/backup-worker-admission-policy-binding.json" ;;
        *backup-worker-admission-policy.yaml*) cat "$fixture_dir/backup-worker-admission-policy.json" ;;
        *) exit 42 ;;
      esac
      exit 0
      ;;
  esac
  cat >/dev/null
  case "${KUBECTL_ADMISSION_MODE:-deny}" in
    allow) exit 0 ;;
    unexpected)
      printf '%s\n' 'admission service unavailable' >&2
      exit 1
      ;;
    deny)
      printf '%s\n' 'Arcadectl backup worker Pods must enter admission with exactly one execution gate and no authorization marker.' >&2
      exit 1
      ;;
  esac
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
		{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "list", "update", "watch"}},
		{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}},
		{APIGroups: []string{""}, Resources: []string{"serviceaccounts"}, Verbs: []string{"create", "get", "list", "watch"}},
		{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"create", "delete", "get", "list", "patch", "update", "watch"}},
		{APIGroups: []string{"arcade.gobha.me"}, Resources: []string{"gamebackups", "gameservers"}, Verbs: []string{"get", "list", "patch", "update", "watch"}},
		{APIGroups: []string{"arcade.gobha.me"}, Resources: []string{"gamebackups/status", "gamerestores/status", "gameservers/status"}, Verbs: []string{"get", "patch", "update"}},
		{APIGroups: []string{"arcade.gobha.me"}, Resources: []string{"gamerestores"}, Verbs: []string{"get", "list", "watch"}},
		{APIGroups: []string{"batch"}, Resources: []string{"jobs"}, Verbs: []string{"create", "delete", "get", "list", "update", "watch"}},
		{APIGroups: []string{"coordination.k8s.io"}, Resources: []string{"leases"}, Verbs: []string{"create", "delete", "get", "list", "patch", "update", "watch"}},
		{APIGroups: []string{"rbac.authorization.k8s.io"}, Resources: []string{"rolebindings", "roles"}, Verbs: []string{"create", "get", "list", "watch"}},
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

func assertVolumeAttachmentAuthority(t *testing.T, roleObject, bindingObject *unstructured.Unstructured) {
	t.Helper()
	role := &rbacv1.ClusterRole{}
	convertObject(t, roleObject, role)
	want := []rbacv1.PolicyRule{{APIGroups: []string{"storage.k8s.io"}, Resources: []string{"volumeattachments"}, Verbs: []string{"get", "list", "watch"}}}
	if got := normalizedRules(role.Rules); !slices.EqualFunc(got, normalizedRules(want), func(a, b rbacv1.PolicyRule) bool {
		return slices.Equal(a.APIGroups, b.APIGroups) && slices.Equal(a.Resources, b.Resources) && slices.Equal(a.Verbs, b.Verbs)
	}) {
		t.Fatalf("VolumeAttachment ClusterRole rules = %#v", role.Rules)
	}
	binding := &rbacv1.ClusterRoleBinding{}
	convertObject(t, bindingObject, binding)
	if binding.RoleRef.Kind != "ClusterRole" || binding.RoleRef.Name != role.Name || len(binding.Subjects) != 1 ||
		binding.Subjects[0].Kind != "ServiceAccount" || binding.Subjects[0].Name != "arcadectl-controller" || binding.Subjects[0].Namespace != "arcadectl-system" {
		t.Fatalf("VolumeAttachment ClusterRoleBinding = role %#v subjects %#v", binding.RoleRef, binding.Subjects)
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
	for _, argument := range []string{"--watch-namespace=$(POD_NAMESPACE)", "--backup-worker-image=$(BACKUP_WORKER_IMAGE)", "--leader-elect=true", "--metrics-bind-address=0", "--health-probe-bind-address=:8081"} {
		if !slices.Contains(container.Args, argument) {
			t.Errorf("controller args %v omit %q", container.Args, argument)
		}
	}
	foundWorkerImage := false
	for _, environment := range container.Env {
		if environment.Name == "BACKUP_WORKER_IMAGE" && environment.Value == image {
			foundWorkerImage = true
		}
	}
	if !foundWorkerImage {
		t.Fatalf("controller environment does not pin the backup worker to %q: %#v", image, container.Env)
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
