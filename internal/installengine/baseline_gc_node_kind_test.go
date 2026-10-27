//go:build kindinstall

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/ptr"
)

// Captured by the same fixture that creates and cleans this exact node. These
// methods never adopt an external cluster, container name or image tag.
type gcOwnedKindNode struct {
	name, id, cluster string
	pilotCommand      kindNodePilotCommand
	pilotRestore      bool
	pilotLimits       kindNodeCPULimits
}

type gcBoundedOutput struct {
	bytes.Buffer
	remaining int
}

func (w *gcBoundedOutput) Write(p []byte) (int, error) {
	if len(p) > w.remaining {
		return 0, errors.New("owned diagnostic output exceeds bound")
	}
	w.remaining -= len(p)
	return w.Buffer.Write(p)
}

func gcBoundedCommand(ctx context.Context, args ...string) ([]byte, error) {
	output := &gcBoundedOutput{remaining: 1 << 20}
	command := exec.CommandContext(ctx, args[0], args[1:]...)
	command.Stdout, command.Stderr = output, io.Discard
	err := command.Run()
	return output.Bytes(), err
}

func (n *gcOwnedKindNode) checkedExec(ctx context.Context, args ...string) ([]byte, error) {
	if n == nil || n.id == "" || n.cluster == "" || n.name != n.cluster+"-control-plane" {
		return nil, ErrOutcomeUnknown
	}
	output, err := gcBoundedCommand(ctx, "docker", "inspect", "--format", "{{.Id}} {{index .Config.Labels \"io.x-k8s.kind.cluster\"}}", n.name)
	if err != nil || strings.TrimSpace(string(output)) != n.id+" "+n.cluster {
		return nil, ErrOutcomeUnknown
	}
	return gcBoundedCommand(ctx, append([]string{"docker", "exec", n.id}, args...)...)
}

func (n *gcOwnedKindNode) pauseImage(t *testing.T, ctx context.Context) string {
	t.Helper()
	readCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	output, err := n.checkedExec(readCtx, "crictl", "images", "--output=json")
	var inventory struct {
		Images []struct {
			ID          string   `json:"id"`
			RepoTags    []string `json:"repoTags"`
			RepoDigests []string `json:"repoDigests"`
		} `json:"images"`
	}
	if err != nil || json.Unmarshal(output, &inventory) != nil {
		t.Fatal("owned node image inventory unavailable")
	}
	image := ""
	tag, imageID := "", ""
	for _, item := range inventory.Images {
		for _, candidate := range item.RepoTags {
			if strings.HasPrefix(candidate, "registry.k8s.io/pause:") {
				if tag != "" && (tag != candidate || imageID != item.ID) || item.ID == "" {
					t.Fatal("owned official pause cache identity is ambiguous")
				}
				tag, imageID = candidate, item.ID
			}
		}
		for _, digest := range item.RepoDigests {
			const prefix = "registry.k8s.io/pause@sha256:"
			if !strings.HasPrefix(digest, prefix) {
				continue
			}
			sha := strings.TrimPrefix(digest, prefix)
			decoded, err := hex.DecodeString(sha)
			if err != nil || len(decoded) != 32 || sha != strings.ToLower(sha) || image != "" && image != digest {
				t.Fatal("owned official pause repository digest is malformed or ambiguous")
			}
			image = digest
		}
	}
	if image == "" {
		// Kind imports its pinned node image's pause manifest by tag. CRI then
		// has no RepoDigest, even though containerd retains the immutable manifest
		// digest. Resolve only that exact preloaded tag and add a digest alias in
		// this owned node's cache; never pull or resolve a mutable registry tag.
		if tag == "" {
			t.Fatal("owned node lacks an official preloaded pause image")
		}
		output, err = n.checkedExec(readCtx, "ctr", "--namespace", "k8s.io", "images", "list")
		if err != nil {
			t.Fatal("owned containerd manifest inventory unavailable")
		}
		for _, line := range strings.Split(string(output), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 3 || fields[0] != tag {
				continue
			}
			if fields[1] != "application/vnd.oci.image.index.v1+json" && fields[1] != "application/vnd.oci.image.manifest.v1+json" && fields[1] != "application/vnd.docker.distribution.manifest.list.v2+json" && fields[1] != "application/vnd.docker.distribution.manifest.v2+json" {
				t.Fatal("owned pause target is not an image manifest")
			}
			sha := strings.TrimPrefix(fields[2], "sha256:")
			decoded, err := hex.DecodeString(sha)
			if err != nil || len(decoded) != 32 || fields[2] != "sha256:"+sha || sha != strings.ToLower(sha) || image != "" {
				t.Fatal("owned pause manifest digest is malformed or ambiguous")
			}
			image = "registry.k8s.io/pause@sha256:" + sha
		}
		if image == "" {
			t.Fatal("owned official pause manifest digest unavailable")
		}
		if _, err := n.checkedExec(readCtx, "ctr", "--namespace", "k8s.io", "images", "tag", tag, image); err != nil {
			t.Fatal("owned pause digest cache alias unavailable")
		}
		output, err = n.checkedExec(readCtx, "crictl", "inspecti", "--output=json", image)
		var inspected struct {
			Status struct {
				ID          string   `json:"id"`
				RepoDigests []string `json:"repoDigests"`
			} `json:"status"`
		}
		if err != nil || json.Unmarshal(output, &inspected) != nil || inspected.Status.ID != imageID {
			t.Fatal("owned pause digest alias differs from the original cached image")
		}
		found := false
		for _, digest := range inspected.Status.RepoDigests {
			found = found || digest == image
		}
		if !found {
			t.Fatal("owned pause digest cache alias lacks exact CRI readback")
		}
	}
	return image
}

func (n *gcOwnedKindNode) kubeletDenial(ctx context.Context, since time.Time, pod *corev1.Pod) (bool, bool) {
	output, err := n.checkedExec(ctx, "journalctl", "--unit=kubelet", "--since="+since.UTC().Format("2006-01-02 15:04:05"), "--lines=2000", "--no-pager", "--output=cat")
	if err != nil || pod == nil {
		return false, false
	}
	return true, gcNameCorrelatedKubeletDenial(output, pod)
}

// Native v1.37 logs namespace/name, NOT UID, on final status-manager DELETE
// failure. Never combine separate entries or call this original-UID proof.
func gcNameCorrelatedKubeletDenial(output []byte, pod *corev1.Pod) bool {
	if pod == nil || pod.Namespace == "" || pod.Name == "" {
		return false
	}
	policy := "arcadectl-identity-pod-" + pod.Namespace
	podToken := ` pod="` + pod.Namespace + `/` + pod.Name + `"`
	for _, line := range strings.Split(string(output), "\n") {
		if strings.Contains(line, `"Failed to delete status for pod"`) && strings.Contains(line, podToken) && strings.Contains(line, "ValidatingAdmissionPolicy '"+policy+"'") && strings.Contains(line, "with binding '"+policy+"'") && strings.Contains(line, "Arcadectl installation identities and executables require trusted maintenance authority.") {
			return true
		}
	}
	return false
}

func testGCNativeDiagnosticControls(t *testing.T) {
	t.Helper()
	const serviceMessage = "ValidatingAdmissionPolicy 'arcadectl-identity-identity-owned-ns' with binding 'arcadectl-identity-identity-owned-ns': Arcadectl installation identities and executables require trusted maintenance authority."
	serviceError := &apierrors.StatusError{ErrStatus: metav1.Status{Reason: metav1.StatusReasonForbidden, Message: serviceMessage,
		Details: &metav1.StatusDetails{Causes: []metav1.StatusCause{{Type: metav1.CauseTypeFieldValueInvalid, Field: "metadata.finalizers", Message: serviceMessage}}}}}
	if gcComponentDenialFlags(serviceError, "identity", "owned-ns") != "policy-present=true message-present=true cause-policy-present=true field=metadata.finalizers cause-type=FieldValueInvalid" || gcComponentOutcome(serviceError) != "forbidden" {
		t.Fatal("Service diagnostic lacks its exact fixed-family classifications")
	}
	if gcComponentDenialFlags(serviceError, "pod", "owned-ns") != "policy-present=false message-present=true cause-policy-present=false field=metadata.finalizers cause-type=FieldValueInvalid" {
		t.Fatal("Service diagnostic falsely attributed the Pod family")
	}
	if gcComponentDenialFlags(errors.New("fixture-sensitive-unclassified-error"), "identity", "owned-ns") != "policy-present=false message-present=false cause-policy-present=false field=unknown cause-type=unknown" || gcComponentOutcome(errors.New("fixture-sensitive-unclassified-error")) != "unknown" || gcComponentOutcome(nil) != "accepted" {
		t.Fatal("native diagnostics exposed unclassified input or lost the closed outcome")
	}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "owned-ns", Name: "owned-pod"}}
	const line = `I1010 "Failed to delete status for pod" pod="owned-ns/owned-pod" err="ValidatingAdmissionPolicy 'arcadectl-identity-pod-owned-ns' with binding 'arcadectl-identity-pod-owned-ns': Arcadectl installation identities and executables require trusted maintenance authority."`
	if !gcNameCorrelatedKubeletDenial([]byte(line), pod) {
		t.Fatal("literal native entry without UID lacks name-correlated attribution")
	}
	for _, negative := range []string{
		strings.Replace(line, "Failed to delete status for pod", "Failed to update status for pod", 1),
		strings.Replace(line, `pod="owned-ns/owned-pod"`, `pod="foreign-ns/owned-pod"`, 1),
		strings.Replace(line, `pod="owned-ns/owned-pod"`, `pod="owned-ns/owned-pod-prefix"`, 1),
		strings.Replace(line, "ValidatingAdmissionPolicy 'arcadectl-identity-pod-owned-ns'", "ValidatingAdmissionPolicy 'foreign'", 1),
		strings.Replace(line, "with binding 'arcadectl-identity-pod-owned-ns'", "with binding 'foreign'", 1),
		strings.Replace(line, "identities and executables", "unrelated", 1),
		strings.Replace(line, ` err=`, "\n err=", 1),
	} {
		if gcNameCorrelatedKubeletDenial([]byte(negative), pod) {
			t.Fatal("unrelated or split native entries produced false attribution")
		}
	}
	output := &gcBoundedOutput{remaining: 3}
	if n, err := output.Write([]byte("ab")); n != 2 || err != nil {
		t.Fatal("bounded native output lost accepted bytes")
	}
	if n, err := output.Write([]byte("cd")); n != 0 || err == nil || output.String() != "ab" || output.remaining != 1 {
		t.Fatal("bounded native output silently accepted excess bytes")
	}
}

func proveKindNodeTermination(t *testing.T, ctx context.Context, admin, nodeActor *kubernetes.Clientset, node *gcOwnedKindNode, namespace string) {
	t.Helper()
	image := node.pauseImage(t, ctx)
	deployment, err := admin.AppsV1().Deployments(namespace).Create(ctx, &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "arcadectl-node-termination", Namespace: namespace},
		Spec: appsv1.DeploymentSpec{Replicas: ptr.To(int32(1)), Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"arcade.gobha.me/component": "node-termination"}},
			Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"arcade.gobha.me/component": "node-termination"}}, Spec: corev1.PodSpec{
				ServiceAccountName: "arcadectl-api", AutomountServiceAccountToken: ptr.To(false),
				SecurityContext: &corev1.PodSecurityContext{RunAsNonRoot: ptr.To(true), RunAsUser: ptr.To(int64(65532)), RunAsGroup: ptr.To(int64(65532)), SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}},
				Containers: []corev1.Container{{Name: "pause", Image: image, ImagePullPolicy: corev1.PullNever,
					SecurityContext: &corev1.SecurityContext{AllowPrivilegeEscalation: ptr.To(false), ReadOnlyRootFilesystem: ptr.To(true), Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}},
					Resources:       corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("5m"), corev1.ResourceMemory: resource.MustParse("8Mi")}, Limits: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("50m"), corev1.ResourceMemory: resource.MustParse("16Mi")}}}},
			}},
		},
	}, metav1.CreateOptions{})
	if err != nil || deployment.UID == "" {
		t.Fatal("owned node-termination Deployment unavailable")
	}
	var replicaSet appsv1.ReplicaSet
	var pod corev1.Pod
	if wait.PollUntilContextTimeout(ctx, 200*time.Millisecond, 2*time.Minute, true, func(ctx context.Context) (bool, error) {
		sets, setErr := admin.AppsV1().ReplicaSets(namespace).List(ctx, metav1.ListOptions{})
		pods, podErr := admin.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
		if setErr != nil || podErr != nil || sets.Continue != "" || sets.RemainingItemCount != nil && *sets.RemainingItemCount != 0 || pods.Continue != "" || pods.RemainingItemCount != nil && *pods.RemainingItemCount != 0 {
			return false, ErrOutcomeUnknown
		}
		if len(sets.Items) != 1 || len(pods.Items) != 1 {
			return false, nil
		}
		replicaSet, pod = sets.Items[0], pods.Items[0]
		setOwner, podOwner := metav1.GetControllerOf(&replicaSet), metav1.GetControllerOf(&pod)
		if setOwner == nil || setOwner.UID != deployment.UID || setOwner.Name != deployment.Name || setOwner.Kind != "Deployment" || podOwner == nil || podOwner.UID != replicaSet.UID || podOwner.Name != replicaSet.Name || podOwner.Kind != "ReplicaSet" {
			return false, ErrOutcomeUnknown
		}
		return pod.UID != "" && replicaSet.UID != "" && pod.Spec.NodeName == node.name && pod.Spec.ServiceAccountName == "arcadectl-api" && pod.Spec.AutomountServiceAccountToken != nil && !*pod.Spec.AutomountServiceAccountToken && len(pod.Spec.Volumes) == 0 && len(pod.Spec.SchedulingGates) == 0 && pod.Status.Phase == corev1.PodRunning && len(pod.Status.ContainerStatuses) == 1 && pod.Status.ContainerStatuses[0].State.Running != nil, nil
	}) != nil {
		t.Fatal("original actual node-bound Running inert Pod chain unavailable")
	}
	if err := nodeActor.CoreV1().Pods(namespace).Delete(ctx, pod.Name, metav1.DeleteOptions{DryRun: []string{metav1.DryRunAll}, GracePeriodSeconds: ptr.To(int64(0)), Preconditions: &metav1.Preconditions{UID: &pod.UID}}); !baselineDenial(err, "pod", namespace) {
		t.Fatal("own node initial Running Pod DELETE lacks exact baseline refusal")
	}
	uid := deployment.UID
	since := time.Now().UTC()
	if err := gcDeleteReadyNodeDeployment(ctx, admin, deployment); err != nil {
		t.Fatal("one original node-termination foreground DELETE refused: outcome=" + gcComponentOutcome(err) + " " + gcComponentDenialFlags(err, "template", namespace))
	}
	var terminal, deleting bool
	err = wait.PollUntilContextTimeout(ctx, 200*time.Millisecond, 5*time.Minute, true, func(ctx context.Context) (bool, error) {
		current, deploymentErr := admin.AppsV1().Deployments(namespace).Get(ctx, deployment.Name, metav1.GetOptions{})
		sets, setErr := admin.AppsV1().ReplicaSets(namespace).List(ctx, metav1.ListOptions{})
		pods, podErr := admin.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
		if deploymentErr != nil && !apierrors.IsNotFound(deploymentErr) || deploymentErr == nil && current.UID != uid || setErr != nil || podErr != nil || sets.Continue != "" || sets.RemainingItemCount != nil && *sets.RemainingItemCount != 0 || pods.Continue != "" || pods.RemainingItemCount != nil && *pods.RemainingItemCount != 0 {
			return false, ErrOutcomeUnknown
		}
		for _, set := range sets.Items {
			if set.UID != replicaSet.UID || set.Name != replicaSet.Name {
				return false, ErrOutcomeUnknown
			}
		}
		for _, item := range pods.Items {
			if item.UID != pod.UID || item.Name != pod.Name {
				return false, ErrOutcomeUnknown
			}
			terminal = item.Status.Phase == corev1.PodSucceeded || item.Status.Phase == corev1.PodFailed
			deleting = item.DeletionTimestamp != nil
		}
		return apierrors.IsNotFound(deploymentErr) && len(sets.Items) == 0 && len(pods.Items) == 0, nil
	})
	if err != nil {
		diagnosticCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		available, attributed := node.kubeletDenial(diagnosticCtx, since, &pod)
		probeErr := nodeActor.CoreV1().Pods(namespace).Delete(diagnosticCtx, pod.Name, metav1.DeleteOptions{DryRun: []string{metav1.DryRunAll}, GracePeriodSeconds: ptr.To(int64(0)), Preconditions: &metav1.Preconditions{UID: &pod.UID}})
		t.Fatalf("actual node-termination foreground chain not absent: terminal=%t deleting=%t kubelet-log-available=%t name-correlated-kubelet-policy-denial=%t own-node-original-uid-dryrun-policy-denial=%t", terminal, deleting, available, attributed, baselineDenial(probeErr, "pod", namespace))
	}
	t.Log("actual node-bound Running Pod foreground chain absent without manual finalizer removal or force deletion")
}
