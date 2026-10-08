//go:build kindapi

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package install

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	adminv1 "github.com/gobha-me/arcadectl/api/admin/v1"
	arcadev1 "github.com/gobha-me/arcadectl/api/v1alpha1"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Shares the caller's one disposable Kind node and private registry. Nothing
// here discovers or adopts a user cluster. The bearer stays in memory only.
type kindAPILifecycleFixture struct {
	ctx                                                context.Context
	root, workspace, node, nodeID, kubeconfig, kubectl string
	registryHost, registryName, apiBaseURL, token      string
	httpClient                                         *http.Client
	config                                             *rest.Config
	cluster                                            kubernetes.Interface
	public                                             func(string, ...string) string
	runCLI                                             func(...string) []byte
}

type kindAPIResult struct {
	status    int
	etag      string
	operation adminv1.Operation
	server    adminv1.Server
	retained  adminv1.RetainedWorld
	code      string
	err       bool
}

func runKindAPILifecycle(t *testing.T, f kindAPILifecycleFixture) {
	t.Helper()
	const namespace = "arcadectl-system"
	const verifierImage = "busybox@sha256:9db7b59979c38555a39def84a31fb98b5296952f9e3afd4f6f11f05b07adfab0"
	run := strings.TrimSuffix(f.node, "-control-plane")
	name := "api-factorio"
	className := ""
	if f.nodeID == "" || f.registryName != run+"-registry" || f.ctx == nil || f.config == nil || f.cluster == nil || f.token == "" || f.httpClient == nil {
		t.Fatal("incomplete owned lifecycle fixture")
	}
	assertNode := func() {
		t.Helper()
		if f.public("", "docker", "inspect", "--format", "{{.Id}}", f.node) != f.nodeID || f.public("", "docker", "inspect", "--format", "{{index .Config.Labels \"io.x-k8s.kind.cluster\"}}", f.node) != run {
			t.Fatal("refusing lifecycle fixture on an unowned node")
		}
	}
	assertNode()
	scheme := runtime.NewScheme()
	if corev1.AddToScheme(scheme) != nil || arcadev1.AddToScheme(scheme) != nil {
		t.Fatal("lifecycle scheme unavailable")
	}
	admin, err := client.New(f.config, client.Options{Scheme: scheme, Log: logr.Discard()})
	if err != nil {
		t.Fatal("lifecycle administrator unavailable")
	}
	kube := func(input string, args ...string) string {
		return f.public(input, append([]string{f.kubectl, "--kubeconfig", f.kubeconfig}, args...)...)
	}
	// Exactly-owned tags are removed without deleting shared base/build-cache
	// images. Register before building so partial failures are covered as well.
	type ownedImage struct{ tag, id string }
	images := []*ownedImage{}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		command := func(args ...string) *exec.Cmd {
			cmd := exec.CommandContext(ctx, args[0], args[1:]...)
			cmd.Env = append(os.Environ(), "DOCKER_CONFIG="+filepath.Join(f.workspace, "docker-config"))
			return cmd
		}
		for _, image := range images {
			output, err := command("docker", "image", "inspect", "--format", "{{.Id}}", image.tag).CombinedOutput()
			if err != nil {
				if !bytes.Contains(bytes.ToLower(output), []byte("no such image")) {
					t.Error("lifecycle image absence not proven")
				}
				continue
			}
			if image.id == "" || strings.TrimSpace(string(output)) != image.id {
				t.Error("refusing changed lifecycle image cleanup")
				continue
			}
			if command("docker", "image", "rm", image.tag).Run() != nil {
				t.Error("owned lifecycle image cleanup failed")
				continue
			}
			output, err = command("docker", "image", "inspect", image.tag).CombinedOutput()
			if err == nil || !bytes.Contains(bytes.ToLower(output), []byte("no such image")) {
				t.Error("owned lifecycle image remains")
			}
		}
	})
	sha := f.public("", "git", "rev-parse", "HEAD")
	epoch := f.public("", "git", "show", "-s", "--format=%ct", "HEAD")
	dirty := boolText(f.public("", "git", "status", "--porcelain") != "")
	digestPattern := regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	build := func(repository, suffix string, args ...string) (string, string) {
		t.Helper()
		tag := f.registryHost + "/" + repository + ":" + run + suffix
		probe := exec.CommandContext(f.ctx, "docker", "image", "inspect", tag)
		probe.Env = append(os.Environ(), "DOCKER_CONFIG="+filepath.Join(f.workspace, "docker-config"))
		output, probeErr := probe.CombinedOutput()
		if probeErr == nil || !bytes.Contains(bytes.ToLower(output), []byte("no such image")) {
			t.Fatal("lifecycle image preflight failed")
		}
		owned := &ownedImage{tag: tag}
		images = append(images, owned)
		f.public("", append([]string{"docker", "build", "--tag", tag}, args...)...)
		owned.id = f.public("", "docker", "image", "inspect", "--format", "{{.Id}}", tag)
		f.public("", "docker", "push", tag)
		refs := f.public("", "docker", "image", "inspect", "--format", "{{range .RepoDigests}}{{println .}}{{end}}", tag)
		prefix := f.registryHost + "/" + repository + "@"
		for _, ref := range strings.Fields(refs) {
			if strings.HasPrefix(ref, prefix) && digestPattern.MatchString(strings.TrimPrefix(ref, prefix)) {
				return tag, strings.TrimPrefix(ref, prefix)
			}
		}
		t.Fatal("immutable lifecycle image digest unavailable")
		return "", ""
	}
	t.Log("building normal controller and two pinned Factorio runtime variants serially")
	_, controllerDigest := build("arcadectl-controller", "-lifecycle", "--build-arg", "VCS_REF="+sha, "--build-arg", "SOURCE_DATE_EPOCH="+epoch, "--build-arg", "SOURCE_DIRTY="+dirty, f.root)
	_, digestA := build("gobha-me/arcadectl-factorio", "-a", "--file", filepath.Join(f.root, "images/factorio/Dockerfile"), "--label", "arcade.gobha.me/lifecycle-variant=a", filepath.Join(f.root, "images/factorio"))
	_, digestB := build("gobha-me/arcadectl-factorio", "-b", "--file", filepath.Join(f.root, "images/factorio/Dockerfile"), "--label", "arcade.gobha.me/lifecycle-variant=b", filepath.Join(f.root, "images/factorio"))
	if digestA == digestB {
		t.Fatal("update fixture variants have identical digests")
	}
	controllerImage := f.registryHost + "/arcadectl-controller@" + controllerDigest
	assertNode()
	f.public("", "docker", "exec", f.node, "mkdir", "-p", "/etc/containerd/certs.d/ghcr.io")
	// Same curated name as production; only this exact disposable node uses the
	// private mirror. The images retain the checked-in checksum-pinned runtime.
	f.public("server = \"https://ghcr.io\"\n[host.\"http://"+f.registryName+":5000\"]\n  capabilities = [\"pull\", \"resolve\"]\n", "docker", "exec", "--interactive", f.node, "tee", "/etc/containerd/certs.d/ghcr.io/hosts.toml")
	for _, image := range []string{controllerImage, "ghcr.io/gobha-me/arcadectl-factorio@" + digestA, "ghcr.io/gobha-me/arcadectl-factorio@" + digestB} {
		f.public("", "docker", "exec", f.node, "ctr", "--namespace", "k8s.io", "images", "pull", "--hosts-dir", "/etc/containerd/certs.d", image)
	}
	kube("", "apply", "-f", filepath.Join(f.root, "config/install/anchors.yaml"))
	for _, kind := range []string{"gameservers", "gamebackups", "gamerestores", "gamedestroys", "arcadeoperations"} {
		kube("", "wait", "--for=condition=Established", "crd/"+kind+".arcade.gobha.me", "--timeout=60s")
	}
	manifest := f.public("", filepath.Join(f.root, "hack/render-controller.sh"), controllerImage)
	kube(manifest, "apply", "-f", "-")
	for _, deployment := range []string{"arcadectl-controller", "arcadectl-destroy-controller"} {
		kube("", "rollout", "status", "deployment/"+deployment, "--namespace", namespace, "--timeout=120s")
	}
	for _, policy := range []string{"arcadectl-destroy-worker-gate", "arcadectl-retained-world-pvc-delete", "arcadectl-destroy-unsafe-admin"} {
		waitKindAPI(t, f.ctx, func() bool {
			p, err := f.cluster.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(f.ctx, policy, metav1.GetOptions{})
			if err != nil || p.Status.ObservedGeneration != p.Generation || p.Status.TypeChecking == nil {
				return false
			}
			if len(p.Status.TypeChecking.ExpressionWarnings) != 0 {
				t.Fatal("native policy has CEL typechecking warnings")
			}
			return true
		})
	}
	// Actual API-server authorization reviews of the shipped service account,
	// not assumptions about an in-memory client or mocked capability boundary.
	for _, target := range []struct{ group, resource string }{{"arcade.gobha.me", "gameservers"}, {"arcade.gobha.me", "gamebackups"}, {"arcade.gobha.me", "gamerestores"}, {"arcade.gobha.me", "gamedestroys"}, {"", "secrets"}, {"", "persistentvolumeclaims"}, {"", "pods"}, {"", "services"}, {"apps", "deployments"}, {"batch", "jobs"}} {
		for _, verb := range []string{"create", "update", "patch", "delete"} {
			review, err := f.cluster.AuthorizationV1().SubjectAccessReviews().Create(f.ctx, &authorizationv1.SubjectAccessReview{Spec: authorizationv1.SubjectAccessReviewSpec{User: "system:serviceaccount:" + namespace + ":arcadectl-api", ResourceAttributes: &authorizationv1.ResourceAttributes{Namespace: namespace, Group: target.group, Resource: target.resource, Verb: verb}}}, metav1.CreateOptions{})
			if err != nil || review.Status.Allowed {
				t.Fatal("shipped API role has forbidden native/core mutation authority")
			}
		}
	}
	// Stock Kind's local-path provisioner cannot select a node for Immediate
	// claims, and WaitingForFirstConsumer deadlocks the controller's bound-
	// storage-before-runtime contract. Use the existing Factorio harness's
	// prebound Retain fixture, not a pretend dynamic provisioning proof.
	fixturePath := "/var/arcadectl-e2e/" + run
	assertNode()
	f.public("", "docker", "exec", f.node, "install", "-d", "-o", "845", "-g", "845", "-m", "0770", fixturePath)
	directory := corev1.HostPathDirectory
	fixtureVolume, err := f.cluster.CoreV1().PersistentVolumes().Create(f.ctx, &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: run + "-world-retain", Labels: map[string]string{"arcade.gobha.me/e2e-run": run}},
		Spec: corev1.PersistentVolumeSpec{
			Capacity:                      corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("512Mi")},
			AccessModes:                   []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			PersistentVolumeReclaimPolicy: corev1.PersistentVolumeReclaimRetain,
			StorageClassName:              "",
			ClaimRef:                      &corev1.ObjectReference{Namespace: namespace, Name: name + "-factorio-world"},
			PersistentVolumeSource:        corev1.PersistentVolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: fixturePath, Type: &directory}},
		},
	}, metav1.CreateOptions{})
	if err != nil || fixtureVolume.UID == "" {
		t.Fatal("owned prebound Retain storage fixture unavailable")
	}
	request := func(method, path, key, etag string, body []byte) kindAPIResult {
		result := kindAPIResult{}
		r, err := http.NewRequestWithContext(f.ctx, method, f.apiBaseURL+path, bytes.NewReader(body))
		if err != nil {
			result.err = true
			return result
		}
		r.Header.Set("Authorization", "Bearer "+f.token)
		if body != nil {
			r.Header.Set("Content-Type", "application/json")
		}
		if key != "" {
			r.Header.Set("Idempotency-Key", key)
		}
		if etag == "*" {
			r.Header.Set("If-None-Match", "*")
		} else if etag != "" {
			r.Header.Set("If-Match", etag)
		}
		response, err := f.httpClient.Do(r)
		if err != nil {
			result.err = true
			return result
		}
		defer response.Body.Close()
		contents, err := io.ReadAll(io.LimitReader(response.Body, 65537))
		if err != nil || len(contents) > 65536 || !json.Valid(contents) {
			result.err = true
			return result
		}
		result.status, result.etag = response.StatusCode, response.Header.Get("ETag")
		_ = json.Unmarshal(contents, &result.operation)
		_ = json.Unmarshal(contents, &result.server)
		_ = json.Unmarshal(contents, &result.retained)
		var problem adminv1.Error
		_ = json.Unmarshal(contents, &problem)
		result.code = problem.Code
		return result
	}
	encode := func(value any) []byte {
		contents, err := json.Marshal(value)
		if err != nil {
			t.Fatal("typed lifecycle body unavailable")
		}
		return contents
	}
	readServer := func() kindAPIResult {
		result := request("GET", "/v1/servers/"+name, "", "", nil)
		if result.err || result.status != 200 || result.etag == "" || result.server.UID == "" {
			t.Fatal("exact server HTTP read failed")
		}
		return result
	}
	// Kind intentionally has no cloud load-balancer provider. This test-only
	// admin fixture supplies the owned Service endpoint; the API never does it.
	provideEndpoint := func() {
		service, err := f.cluster.CoreV1().Services(namespace).Get(f.ctx, name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return
		}
		if err != nil {
			t.Fatal("owned Service read unavailable")
		}
		if service.Labels["app.kubernetes.io/instance"] != name || service.Spec.ClusterIP == "" || service.Spec.ClusterIP == "None" {
			t.Fatal("unexpected lifecycle Service identity")
		}
		if len(service.Status.LoadBalancer.Ingress) == 1 && service.Status.LoadBalancer.Ingress[0].IP == service.Spec.ClusterIP {
			return
		}
		service.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: service.Spec.ClusterIP}}
		if _, err := f.cluster.CoreV1().Services(namespace).UpdateStatus(f.ctx, service, metav1.UpdateOptions{}); err != nil {
			t.Fatal("test-only load-balancer endpoint unavailable")
		}
	}
	waitOperation := func(id string) adminv1.Operation {
		var operation adminv1.Operation
		waitKindAPI(t, f.ctx, func() bool {
			provideEndpoint()
			result := request("GET", "/v1/operations/"+id, "", "", nil)
			if result.err || result.status != 200 {
				t.Fatal("durable operation poll unavailable")
			}
			operation = result.operation
			if operation.Phase == "Failed" || operation.Phase == "Cancelled" {
				t.Fatalf("HTTP lifecycle operation failed: action=%s phase=%s", operation.Action, operation.Phase)
			}
			if operation.Action == "server.create" && (operation.Child == nil || operation.Child.UID == "") {
				return false
			}
			return operation.Phase == "Succeeded" && operation.ObservedGeneration == operation.Generation && operation.CompletedAt != ""
		})
		return operation
	}
	create := adminv1.CreateRequest{Version: "v1", Name: name, Game: "factorio", Image: adminv1.Image{Digest: digestA}, DesiredState: "Stopped", Compute: adminv1.Compute{CPURequest: "100m", CPULimit: "2", MemoryRequest: "256Mi", MemoryLimit: "2Gi"}, Storage: adminv1.Storage{Size: "512Mi", StorageClassName: &className}, Settings: json.RawMessage(`{"name":"API lifecycle proof","visibility":"private","maxPlayers":20}`)}
	body := encode(create)
	accepted := request("POST", "/v1/servers", run+"-create", "*", body)
	if accepted.err || accepted.status != 202 || accepted.operation.OperationID == "" {
		t.Fatal("HTTP create did not admit a durable receipt")
	}
	// In-flight storms and numeric-equivalent retries must converge on one
	// receipt even while the controller is binding its first native child.
	results := make(chan kindAPIResult, 8)
	var storm sync.WaitGroup
	for i := 0; i < 8; i++ {
		storm.Add(1)
		go func() { defer storm.Done(); results <- request("POST", "/v1/servers", run+"-create", "*", body) }()
	}
	storm.Wait()
	close(results)
	for result := range results {
		if result.err || result.status != 200 || result.operation.OperationID != accepted.operation.OperationID || result.operation.UID != accepted.operation.UID {
			t.Fatal("in-flight HTTP retries diverged")
		}
	}
	for _, numeric := range []string{"20.0", "2e1"} {
		create.Settings = json.RawMessage(`{"name":"API lifecycle proof","visibility":"private","maxPlayers":` + numeric + `}`)
		retry := request("POST", "/v1/servers", run+"-create", "*", encode(create))
		if retry.err || retry.status != 200 || retry.operation.UID != accepted.operation.UID {
			t.Fatal("equivalent integral settings created a second intent")
		}
	}
	create.Settings = json.RawMessage(`{"name":"conflicting intent","visibility":"private","maxPlayers":20}`)
	conflict := request("POST", "/v1/servers", run+"-create", "*", encode(create))
	if conflict.err || conflict.status != 409 || conflict.code != "idempotency_conflict" {
		t.Fatal("different input did not conflict for the same key")
	}
	created := waitOperation(accepted.operation.OperationID)
	current := readServer()
	serverUID := current.server.UID
	if current.server.Phase != "Stopped" || created.Child.Kind != "GameServer" || created.Child.Name != name || created.Child.UID != serverUID {
		t.Fatal("HTTP receipt/native server attribution differs")
	}
	native := &arcadev1.GameServer{}
	if admin.Get(f.ctx, types.NamespacedName{Namespace: namespace, Name: name}, native) != nil || native.Status.ObservedData == nil || len(native.Status.ObservedData.Claims) != 1 {
		t.Fatal("current bound world journal absent")
	}
	claimRef := native.Status.ObservedData.Claims[0].ClaimRef
	claim, err := f.cluster.CoreV1().PersistentVolumeClaims(namespace).Get(f.ctx, claimRef.Name, metav1.GetOptions{})
	if err != nil || string(claim.UID) != claimRef.UID || claim.Status.Phase != corev1.ClaimBound || claim.Spec.StorageClassName == nil || *claim.Spec.StorageClassName != className {
		t.Fatal("prebound world claim identity not proven")
	}
	volume, err := f.cluster.CoreV1().PersistentVolumes().Get(f.ctx, claim.Spec.VolumeName, metav1.GetOptions{})
	if err != nil || volume.UID != fixtureVolume.UID || volume.Spec.PersistentVolumeReclaimPolicy != corev1.PersistentVolumeReclaimRetain || volume.Spec.ClaimRef == nil || volume.Spec.ClaimRef.UID != claim.UID || volume.Spec.StorageClassName != className || volume.Spec.HostPath == nil || volume.Spec.HostPath.Path != fixturePath {
		t.Fatal("prebound Retain PV binding not proven")
	}
	claimUID, volumeUID, volumePath := claim.UID, volume.UID, volume.Spec.HostPath.Path
	assertWorld := func() {
		t.Helper()
		pvc, err := f.cluster.CoreV1().PersistentVolumeClaims(namespace).Get(f.ctx, claimRef.Name, metav1.GetOptions{})
		if err != nil || pvc.UID != claimUID || pvc.Spec.VolumeName != volume.Name || pvc.Status.Phase != corev1.ClaimBound {
			t.Fatal("world PVC identity drift")
		}
		pv, err := f.cluster.CoreV1().PersistentVolumes().Get(f.ctx, volume.Name, metav1.GetOptions{})
		if err != nil || pv.UID != volumeUID || pv.Spec.ClaimRef == nil || pv.Spec.ClaimRef.UID != claimUID || pv.Spec.HostPath == nil || pv.Spec.HostPath.Path != volumePath || pv.Spec.PersistentVolumeReclaimPolicy != corev1.PersistentVolumeReclaimRetain {
			t.Fatal("world PV identity drift")
		}
	}
	runtimePod := func(stage nativeRuntimeStage, digest string) types.UID {
		pods, err := f.cluster.CoreV1().Pods(namespace).List(f.ctx, metav1.ListOptions{LabelSelector: "app.kubernetes.io/name=game-server,app.kubernetes.io/instance=" + name})
		if err != nil || len(pods.Items) != 1 {
			t.Fatal("expected exactly one real Factorio Pod")
		}
		pod := pods.Items[0]
		wanted := "ghcr.io/gobha-me/arcadectl-factorio@" + digest
		if pod.DeletionTimestamp != nil || pod.Status.Phase != corev1.PodRunning || pod.UID == "" {
			t.Fatal("Factorio runtime is not live")
		}
		found := false
		for _, status := range pod.Status.ContainerStatuses {
			if status.Name == "game" && (status.RestartCount != 0 || status.LastTerminationState.Terminated != nil && status.LastTerminationState.Terminated.Reason == "OOMKilled") {
				t.Fatalf("fresh Factorio runtime crashed or was OOM killed (%s); private output withheld", nativeRuntimeDiagnostic(stage, status))
			}
			if status.Name == "game" && status.Ready && status.RestartCount == 0 && strings.Contains(status.ImageID, digest) {
				found = true
			}
		}
		for _, container := range pod.Spec.Containers {
			if container.Name == "game" && container.Image != wanted {
				t.Fatal("Factorio workload digest differs")
			}
		}
		if !found || pod.Spec.SecurityContext == nil || pod.Spec.SecurityContext.RunAsUser == nil || *pod.Spec.SecurityContext.RunAsUser != 845 {
			t.Fatal("Factorio runtime identity not proven")
		}
		return pod.UID
	}
	sequence := 0
	mutate := func(method, action string, input any) adminv1.Operation {
		before := readServer()
		if before.server.UID != serverUID {
			t.Fatal("live server identity changed")
		}
		path := "/v1/servers/" + name
		if method == "POST" {
			path += "/" + action
		}
		sequence++
		key := run + "-" + action + "-" + strconv.Itoa(sequence)
		result := request(method, path, key, before.etag, encode(input))
		if result.err || result.status != 202 {
			t.Fatalf("HTTP %s admission failed with status %d", action, result.status)
		}
		operation := waitOperation(result.operation.OperationID)
		receipt := &arcadev1.ArcadeOperation{}
		if admin.Get(f.ctx, types.NamespacedName{Namespace: namespace, Name: operation.OperationID}, receipt) != nil || string(receipt.UID) != operation.UID || receipt.Status.Plan == nil || receipt.Status.Plan.Server == nil || receipt.Status.Plan.Server.Name != name || receipt.Status.Plan.Server.UID != serverUID || receipt.Spec.Request.Target == nil || receipt.Spec.Request.Target.Generation != before.server.Generation || receipt.Spec.Request.Target.UID != serverUID {
			t.Fatal("completed HTTP operation did not journal the exact admitted native target")
		}
		retry := request(method, path, key, before.etag, encode(input))
		if retry.err || retry.status != 200 || retry.operation.UID != operation.UID {
			t.Fatal("completed lifecycle retry was revalidated against changed target")
		}
		if action == "configure" {
			for _, numeric := range []string{"20.0", "2e1"} {
				equivalent := bytes.ReplaceAll(encode(input), []byte(`"maxPlayers":20`), []byte(`"maxPlayers":`+numeric))
				result := request(method, path, key, before.etag, equivalent)
				if result.err || result.status != 200 || result.operation.UID != operation.UID {
					t.Fatal("equivalent configure settings did not return the original receipt")
				}
			}
		}
		assertWorld()
		return operation
	}
	settingsName := "API lifecycle proof"
	verifyBytes := func(seed, requireSave bool) {
		t.Helper()
		assertWorld()
		pods, err := f.cluster.CoreV1().Pods(namespace).List(f.ctx, metav1.ListOptions{})
		if err != nil {
			t.Fatal("world mount inventory unavailable")
		}
		for _, pod := range pods.Items {
			for _, mount := range pod.Spec.Volumes {
				if mount.PersistentVolumeClaim != nil && mount.PersistentVolumeClaim.ClaimName == claimRef.Name {
					t.Fatal("cold world still has a Pod user")
				}
			}
		}
		verifierName := name + "-verifier"
		uid, group, nonRoot, disabled, fsGroup := int64(845), int64(845), true, false, int64(845)
		readOnly := !seed
		markerDigest := sha256.Sum256([]byte(run))
		script := "test ! -L /world/.api-world-id; test \"$(cat /world/.api-world-id)\" = '" + run + "'; test \"$(sha256sum /world/.api-world-id | cut -d ' ' -f 1)\" = '" + hex.EncodeToString(markerDigest[:]) + "'; printf 'world-preserved\n'"
		if seed {
			script = "test ! -e /world/.api-world-id; printf '%s' '" + run + "' > /world/.api-world-id; printf 'world-seeded\n'"
		}
		if requireSave {
			script = "set -- /world/saves/*.zip; test -s \"$1\"; test \"$(stat -c '%u:%g' \"$1\")\" = '845:845'; grep -Fq '\"name\": \"" + settingsName + "\"' /world/config/server-settings.json; " + script
		}
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: verifierName, Namespace: namespace, Labels: map[string]string{"arcade.gobha.me/e2e-run": run}}, Spec: corev1.PodSpec{AutomountServiceAccountToken: &disabled, RestartPolicy: corev1.RestartPolicyNever, SecurityContext: &corev1.PodSecurityContext{RunAsUser: &uid, RunAsGroup: &group, RunAsNonRoot: &nonRoot, FSGroup: &fsGroup, SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}}, Containers: []corev1.Container{{Name: "verifier", Image: verifierImage, Command: []string{"sh", "-ec", script}, SecurityContext: &corev1.SecurityContext{AllowPrivilegeEscalation: &disabled, ReadOnlyRootFilesystem: &nonRoot, Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}}, Resources: corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("5m"), corev1.ResourceMemory: resource.MustParse("8Mi")}, Limits: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("50m"), corev1.ResourceMemory: resource.MustParse("32Mi")}}, VolumeMounts: []corev1.VolumeMount{{Name: "world", MountPath: "/world", ReadOnly: readOnly}}}}, Volumes: []corev1.Volume{{Name: "world", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: claimRef.Name, ReadOnly: readOnly}}}}}}
		created, err := f.cluster.CoreV1().Pods(namespace).Create(f.ctx, pod, metav1.CreateOptions{})
		if err != nil || created.UID == "" {
			t.Fatal("bounded world verifier unavailable")
		}
		waitKindAPI(t, f.ctx, func() bool {
			actual, err := f.cluster.CoreV1().Pods(namespace).Get(f.ctx, verifierName, metav1.GetOptions{})
			if err != nil || actual.UID != created.UID {
				t.Fatal("verifier identity drift")
			}
			if actual.Status.Phase == corev1.PodFailed {
				t.Fatal("world-byte continuity proof failed")
			}
			return actual.Status.Phase == corev1.PodSucceeded
		})
		output, err := f.cluster.CoreV1().Pods(namespace).GetLogs(verifierName, &corev1.PodLogOptions{Container: "verifier", LimitBytes: func() *int64 { v := int64(256); return &v }()}).DoRaw(f.ctx)
		wanted := "world-preserved\n"
		if seed {
			wanted = "world-seeded\n"
		}
		if err != nil || string(output) != wanted {
			t.Fatal("world-byte proof did not produce its fixed evidence")
		}
		uidPrecondition := created.UID
		if f.cluster.CoreV1().Pods(namespace).Delete(f.ctx, verifierName, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uidPrecondition}}) != nil {
			t.Fatal("owned verifier cleanup failed")
		}
		waitKindAPI(t, f.ctx, func() bool {
			_, err := f.cluster.CoreV1().Pods(namespace).Get(f.ctx, verifierName, metav1.GetOptions{})
			if apierrors.IsNotFound(err) {
				return true
			}
			if err != nil {
				t.Fatal("verifier cleanup absence unavailable")
			}
			return false
		})
		assertWorld()
	}
	verifyBytes(true, false)
	empty := adminv1.EmptyRequest{Version: "v1"}
	mutate("POST", "start", empty)
	initialPod := runtimePod(nativeRuntimeInitialStart, digestA)
	mutate("POST", "stop", empty)
	verifyBytes(false, true)
	mutate("PATCH", "configure", adminv1.ConfigureRequest{Version: "v1", Settings: json.RawMessage(`{"name":"Configured API proof","visibility":"private","maxPlayers":20}`)})
	settingsName = "Configured API proof"
	mutate("POST", "start", empty)
	configuredPod := runtimePod(nativeRuntimeConfigure, digestA)
	if configuredPod == initialPod {
		t.Fatal("stop/start reused the old Factorio Pod identity")
	}
	mutate("POST", "restart", empty)
	restartedPod := runtimePod(nativeRuntimeRestart, digestA)
	if restartedPod == configuredPod {
		t.Fatal("restart did not replace the actual Factorio Pod")
	}
	mutate("POST", "update", adminv1.UpdateRequest{Version: "v1", Image: adminv1.Image{Digest: digestB}})
	updatedPod := runtimePod(nativeRuntimeImageUpdate, digestB)
	if updatedPod == restartedPod {
		t.Fatal("immutable image update did not replace the actual Factorio Pod")
	}
	mutate("POST", "stop", empty)
	verifyBytes(false, true)
	t.Log("proving CLI status, admission, exact wait, and stop against real Factorio controllers")
	var cliServer adminv1.Server
	if json.Unmarshal(f.runCLI("server", "status", name), &cliServer) != nil || cliServer.UID != serverUID || cliServer.Phase != "Stopped" {
		t.Fatal("CLI status lost current server identity")
	}
	var admission struct {
		AttemptID   string            `json:"attemptID"`
		OperationID string            `json:"operationID"`
		Operation   adminv1.Operation `json:"operation"`
	}
	if json.Unmarshal(f.runCLI("server", "start", name, "--no-wait"), &admission) != nil || admission.AttemptID == "" || admission.OperationID == "" || admission.Operation.UID == "" {
		t.Fatal("CLI admission lost exact recovery identities")
	}
	started := waitOperation(admission.OperationID)
	runtimePod(nativeRuntimeCLIStart, digestB)
	var cliWait adminv1.Operation
	if json.Unmarshal(f.runCLI("operation", "wait", admission.OperationID), &cliWait) != nil || cliWait.UID != started.UID || cliWait.Phase != "Succeeded" {
		t.Fatal("CLI wait lost exact terminal receipt")
	}
	var cliStop adminv1.Operation
	if json.Unmarshal(f.runCLI("server", "stop", name), &cliStop) != nil || cliStop.Phase != "Succeeded" || cliStop.Action != "server.stop" || cliStop.CompletedAt == "" {
		t.Fatal("CLI stopped before durable completion")
	}
	verifyBytes(false, true)
	const cliReceipts = 2
	decommission := mutate("POST", "decommission", empty)
	missing := request("GET", "/v1/servers/"+name, "", "", nil)
	if missing.err || missing.status != 404 {
		t.Fatal("successful decommission left a live server")
	}
	retained := request("GET", "/v1/retained-worlds/"+decommission.OperationID, "", "", nil)
	if retained.err || retained.status != 200 || retained.etag == "" || retained.retained.OperationUID != decommission.UID || retained.retained.OriginalServer.UID != serverUID || retained.retained.OriginalServer.Name != name || retained.retained.Game != "factorio" || len(retained.retained.Claims) != 1 || retained.retained.Claims[0].ClaimRef.UID != string(claimUID) || retained.retained.Claims[0].ClaimRef.Name != claimRef.Name || retained.retained.SnapshotDigest == "" {
		t.Fatal("retained HTTP projection lost original server/world identity")
	}
	verifyBytes(false, true)
	servers := &arcadev1.GameServerList{}
	if admin.List(f.ctx, servers, client.InNamespace(namespace)) != nil || len(servers.Items) != 0 {
		t.Fatal("lifecycle left a native server or duplicate child")
	}
	operations := &arcadev1.ArcadeOperationList{}
	if admin.List(f.ctx, operations, client.InNamespace(namespace)) != nil || len(operations.Items) != sequence+1+cliReceipts {
		t.Fatal("HTTP retries created duplicate durable receipts")
	}
	for _, operation := range operations.Items {
		if operation.Status.Phase != arcadev1.OperationPhaseSucceeded || operation.Status.ObservedGeneration != operation.Generation || operation.Status.CompletedAt == nil {
			t.Fatal("lifecycle receipt is not durably complete")
		}
	}
	waitKindAPI(t, f.ctx, func() bool {
		current := &arcadev1.ArcadeOperationList{}
		if admin.List(f.ctx, current, client.InNamespace(namespace)) != nil || len(current.Items) != sequence+1+cliReceipts {
			t.Fatal("operation cleanup inventory unavailable or changed")
		}
		for _, operation := range current.Items {
			if operation.Status.Phase != arcadev1.OperationPhaseSucceeded || operation.Status.ObservedGeneration != operation.Generation || operation.Status.CompletedAt == nil {
				t.Fatal("completed receipt drifted during fence cleanup")
			}
			if len(operation.Finalizers) != 0 {
				return false
			}
		}
		leases, err := f.cluster.CoordinationV1().Leases(namespace).List(f.ctx, metav1.ListOptions{})
		if err != nil {
			t.Fatal("operation fence cleanup inventory unavailable")
		}
		for _, lease := range leases.Items {
			if strings.HasPrefix(lease.Name, "data-operation-") || lease.Labels["arcade.gobha.me/data-identity"] != "" {
				return false
			}
		}
		return true
	})
	assertWorld()
	t.Log("real HTTP lifecycle passed: one admitted create, configure/start/stop/restart/update/decommission; exact retained PVC/PV and marker SHA preserved; API native/core writes forbidden")
}
