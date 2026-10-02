//go:build kindapi

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package install

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/gobha-me/arcadectl/internal/adminauth"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const apiKindNode = "kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5"
const apiKindRegistry = "registry:3.0.0@sha256:6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e"

// This is an opt-in, disposable-cluster proof, never the operator's cluster.
// Private output stays in the task-owned temporary directory, never artifacts.
func TestKindAuthenticatedAdmin(t *testing.T) {
	root := repositoryRoot(t)
	workspace := t.TempDir()
	if os.Chmod(workspace, 0700) != nil {
		t.Fatal("secure fixture directory")
	}
	dockerConfig := filepath.Join(workspace, "docker-config")
	if os.Mkdir(dockerConfig, 0700) != nil {
		t.Fatal("private Docker configuration unavailable")
	}
	newCommand := func(commandContext context.Context, args ...string) *exec.Cmd {
		command := exec.CommandContext(commandContext, args[0], args[1:]...)
		command.Env = append(os.Environ(), "DOCKER_CONFIG="+dockerConfig)
		command.Dir = root
		return command
	}
	random := make([]byte, 6)
	if _, err := rand.Read(random); err != nil {
		t.Fatal("fixture identity unavailable")
	}
	name := "arcadectl-api-" + hex.EncodeToString(random)
	registryName := name + "-registry"
	kubeconfig := filepath.Join(workspace, "kubeconfig")
	utility := filepath.Join(workspace, "credential-admin")
	ctx, cancel := context.WithTimeout(context.Background(), 18*time.Minute)
	defer cancel()
	public := func(input string, args ...string) string {
		t.Helper()
		command := newCommand(ctx, args...)
		command.Stdin = strings.NewReader(input)
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("public fixture step %s failed: %s", args[0], output)
		}
		return strings.TrimSpace(string(output))
	}
	public("", "docker", "info", "--format", "{{.ServerVersion}}")
	for _, target := range []string{name + "-control-plane", registryName} {
		command := newCommand(ctx, "docker", "inspect", target)
		output, err := command.CombinedOutput()
		if err == nil || (!bytes.Contains(bytes.ToLower(output), []byte("no such")) && !bytes.Contains(bytes.ToLower(output), []byte("not found"))) {
			t.Fatal("owned container name preflight failed")
		}
	}
	// Build the trusted-admin utility before starting any heavy Docker build.
	t.Log("building trusted-admin utility")
	public("", "go", "build", "-p", "2", "-o", utility, "./cmd/arcadectl-admin-credential")
	sha := public("", "git", "rev-parse", "HEAD")
	epoch := public("", "git", "show", "-s", "--format=%ct", "HEAD")
	dirty := public("", "git", "status", "--porcelain") != ""
	// All destructive cleanup is guarded by exact task-owned names/IDs/labels.
	registryID := ""
	registryArmed := false
	imageTag := ""
	imageID := ""
	nodeID := ""
	clusterArmed := false
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cleanupCancel()
		inspect := func(args ...string) (string, bool) {
			contents, err := newCommand(cleanupCtx, append([]string{"docker", "inspect", "--format"}, args...)...).CombinedOutput()
			if err != nil {
				if bytes.Contains(bytes.ToLower(contents), []byte("no such object")) || bytes.Contains(bytes.ToLower(contents), []byte("no such image")) {
					return "", true
				}
				t.Error("Docker cleanup inspection unavailable; absence not proven")
				return "", false
			}
			return strings.TrimSpace(string(contents)), true
		}
		if clusterArmed {
			node := name + "-control-plane"
			label, labelOK := inspect("{{index .Config.Labels \"io.x-k8s.kind.cluster\"}}", node)
			id, idOK := inspect("{{.Id}}", node)
			if idOK && labelOK && id != "" && label == name && (nodeID == "" || id == nodeID) {
				command := newCommand(cleanupCtx, "go", "tool", "kind", "delete", "cluster", "--name", name)
				if command.Run() != nil {
					t.Error("owned Kind cluster cleanup failed")
				}
			} else if id != "" {
				t.Error("refusing unowned Kind cleanup")
			}
		}
		if registryArmed {
			currentID, idOK := inspect("{{.Id}}", registryName)
			label, labelOK := inspect("{{index .Config.Labels \"arcade.gobha.me/e2e-run\"}}", registryName)
			if idOK && labelOK && currentID != "" && (registryID == "" || currentID == registryID) && label == name {
				if newCommand(cleanupCtx, "docker", "rm", "--force", currentID).Run() != nil {
					t.Error("owned registry cleanup failed")
				}
			} else if currentID != "" {
				t.Error("refusing unowned registry cleanup")
			}
		}
		if imageTag != "" {
			currentID, ok := inspect("{{.Id}}", imageTag)
			if ok && currentID != "" {
				if imageID != "" && currentID == imageID {
					if newCommand(cleanupCtx, "docker", "image", "rm", imageTag).Run() != nil {
						t.Error("owned image tag cleanup failed")
					}
				} else {
					t.Error("image ownership is unconfirmed; refusing cleanup")
				}
			}
			if remaining, _ := inspect("{{.Id}}", imageTag); remaining != "" {
				t.Error("owned image tag remains after cleanup")
			}
		}
		nodeRemaining, _ := inspect("{{.Id}}", name+"-control-plane")
		registryRemaining, _ := inspect("{{.Id}}", registryName)
		if nodeRemaining != "" || registryRemaining != "" {
			t.Error("owned container remains after cleanup")
		}
	})
	t.Log("starting pinned private registry")
	public("", "docker", "pull", apiKindRegistry)
	registryArmed = true
	registryID = public("", "docker", "run", "--detach", "--pull=never", "--restart=no", "--publish", "127.0.0.1::5000", "--name", registryName,
		"--label", "arcade.gobha.me/e2e-run="+name, apiKindRegistry)
	port := strings.TrimSpace(public("", "docker", "port", registryName, "5000/tcp"))
	_, registryPort, err := net.SplitHostPort(port)
	if err != nil {
		t.Fatal("registry port unavailable")
	}
	registryHost := "127.0.0.1:" + registryPort
	imageTag = registryHost + "/arcadectl-api:" + name
	if output, err := newCommand(ctx, "docker", "image", "inspect", imageTag).CombinedOutput(); err == nil || !bytes.Contains(bytes.ToLower(output), []byte("no such image")) {
		t.Fatal("owned image tag preflight failed")
	}
	t.Log("building API image")
	public("", "docker", "build", "--file", "Dockerfile.api", "--build-arg", "VCS_REF="+sha, "--build-arg", "SOURCE_DATE_EPOCH="+epoch,
		"--build-arg", "SOURCE_DIRTY="+boolText(dirty), "--tag", imageTag, ".")
	imageID = public("", "docker", "image", "inspect", "--format", "{{.Id}}", imageTag)
	public("", "docker", "push", imageTag)
	var references []string
	if json.Unmarshal([]byte(public("", "docker", "image", "inspect", "--format", "{{json .RepoDigests}}", imageTag)), &references) != nil {
		t.Fatal("image digest unavailable")
	}
	apiImage := ""
	for _, reference := range references {
		if strings.HasPrefix(reference, registryHost+"/arcadectl-api@sha256:") {
			apiImage = reference
		}
	}
	if apiImage == "" {
		t.Fatal("API image is not digest pinned")
	}
	kindConfig := filepath.Join(workspace, "kind.yaml")
	if os.WriteFile(kindConfig, []byte("kind: Cluster\napiVersion: kind.x-k8s.io/v1alpha4\ncontainerdConfigPatches:\n- |-\n  [plugins.\"io.containerd.cri.v1.images\".registry]\n    config_path = \"/etc/containerd/certs.d\"\n"), 0600) != nil {
		t.Fatal("write Kind fixture")
	}
	t.Log("creating isolated Kind cluster")
	clusterArmed = true
	public("", "go", "tool", "kind", "create", "cluster", "--name", name, "--image", apiKindNode, "--config", kindConfig, "--kubeconfig", kubeconfig, "--wait", "180s")
	node := name + "-control-plane"
	nodeID = public("", "docker", "inspect", "--format", "{{.Id}}", node)
	if public("", "docker", "inspect", "--format", "{{index .Config.Labels \"io.x-k8s.kind.cluster\"}}", node) != name {
		t.Fatal("Kind ownership mismatch")
	}
	public("", "docker", "network", "connect", "kind", registryName)
	hostsDirectory := "/etc/containerd/certs.d/" + registryHost
	public("", "docker", "exec", node, "mkdir", "-p", hostsDirectory)
	public("[host.\"http://"+registryName+":5000\"]\n  capabilities = [\"pull\", \"resolve\"]\n", "docker", "exec", "--interactive", node, "tee", hostsDirectory+"/hosts.toml")
	public("", "docker", "exec", node, "ctr", "--namespace", "k8s.io", "images", "pull", "--hosts-dir", "/etc/containerd/certs.d", apiImage)
	kubectl := filepath.Join(workspace, "kubectl")
	// The binary is extracted from the checksum-pinned, owned Kind node image.
	public("", "docker", "cp", node+":/usr/bin/kubectl", kubectl)
	if os.Chmod(kubectl, 0700) != nil {
		t.Fatal("secure kubectl fixture")
	}
	configuration, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		t.Fatal("isolated kubeconfig unavailable")
	}
	cluster, err := kubernetes.NewForConfig(configuration)
	if err != nil {
		t.Fatal("isolated Kubernetes client unavailable")
	}
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	admin, err := client.New(configuration, client.Options{Scheme: scheme, Log: logr.Discard()})
	if err != nil {
		t.Fatal("isolated dynamic client unavailable")
	}
	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: adminauth.CredentialNamespace, Labels: map[string]string{
		"pod-security.kubernetes.io/enforce": "restricted", "pod-security.kubernetes.io/enforce-version": "v1.37",
	}}}
	if _, err := cluster.CoreV1().Namespaces().Create(ctx, namespace, metav1.CreateOptions{}); err != nil {
		t.Fatal("create isolated namespace")
	}
	certificatePEM, keyPEM := kindAPICertificate(t)
	caFile := filepath.Join(workspace, "api-ca.crt")
	if os.WriteFile(caFile, certificatePEM, 0600) != nil {
		t.Fatal("write fixture CA")
	}
	if _, err := cluster.CoreV1().Secrets(adminauth.CredentialNamespace).Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "arcadectl-api-tls", Namespace: adminauth.CredentialNamespace}, Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{"tls.crt": certificatePEM, "tls.key": keyPEM},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatal("create fixture TLS Secret")
	}
	initialPath := filepath.Join(workspace, "initial.json")
	// Never print credential utility output, even when a regression emits a
	// credential on failure. Successful output is checked privately below.
	var credentialOutputs [][]byte
	privateRunner := func(args ...string) {
		t.Helper()
		command := newCommand(ctx, append([]string{utility}, args...)...)
		capture := &privateOutputCapture{}
		command.Stdout, command.Stderr = capture, capture
		if command.Run() != nil || capture.truncated {
			t.Fatal("private credential fixture command failed; output withheld")
		}
		credentialOutputs = append(credentialOutputs, capture.contents)
	}
	privateRunner("init", "--kubeconfig", kubeconfig, "--output", initialPath, "--lifetime", "30m")
	initial := kindClientCredential(t, initialPath)
	for _, object := range decodeObjects(t, renderAPI(t, apiImage)) {
		if admin.Create(ctx, object) != nil {
			t.Fatal("install digest-pinned API fixture")
		}
	}
	public("", kubectl, "--kubeconfig", kubeconfig, "--namespace", adminauth.CredentialNamespace, "rollout", "status", "deployment/arcadectl-api", "--timeout=120s")
	initialPods, err := cluster.CoreV1().Pods(adminauth.CredentialNamespace).List(ctx, metav1.ListOptions{LabelSelector: "app.kubernetes.io/name=arcadectl-api"})
	if err != nil || len(initialPods.Items) != 1 {
		t.Fatal("initial API Pod identity unavailable")
	}
	initialPodUID := initialPods.Items[0].UID
	forwardContext, forwardCancel := context.WithCancel(ctx)
	defer forwardCancel()
	forward := exec.CommandContext(forwardContext, kubectl, "--kubeconfig", kubeconfig, "--namespace", adminauth.CredentialNamespace,
		"port-forward", "deployment/arcadectl-api", "0:8443", "--address", "127.0.0.1")
	stdout, err := forward.StdoutPipe()
	if err != nil {
		t.Fatal("port-forward pipe unavailable")
	}
	forward.Stderr = io.Discard
	if forward.Start() != nil {
		t.Fatal("port-forward unavailable")
	}
	defer func() { forwardCancel(); _ = forward.Wait() }()
	line := make([]byte, 1)
	var announcement strings.Builder
	for announcement.Len() < 256 {
		if _, err := stdout.Read(line); err != nil {
			t.Fatal("port-forward announcement unavailable")
		}
		announcement.WriteByte(line[0])
		if line[0] == '\n' {
			break
		}
	}
	parts := strings.Fields(announcement.String())
	if len(parts) < 3 || !strings.HasPrefix(parts[2], "127.0.0.1:") {
		t.Fatal("port-forward address unavailable")
	}
	endpoint := "https://" + parts[2] + "/v1/auth/self"
	go func() { _, _ = io.Copy(io.Discard, stdout) }()
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(certificatePEM)
	httpClient := &http.Client{Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: "arcadectl-api.arcadectl-system.svc"}}, Timeout: 5 * time.Second}
	defer httpClient.CloseIdleConnections()
	self := func(token string) (int, []byte) {
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
		}
		response, err := httpClient.Do(request)
		if err != nil {
			return 0, nil
		}
		defer response.Body.Close()
		contents, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return response.StatusCode, contents
	}
	if status, _ := self(""); status != 401 {
		t.Fatal("missing bearer accepted in cluster")
	}
	if status, contents := self(initial.Token); status != 200 || !bytes.Contains(contents, []byte(initial.CredentialID)) || bytes.Contains(contents, []byte(initial.Token)) {
		t.Fatal("initial cluster authentication failed")
	}
	rotatedPath := filepath.Join(workspace, "rotated.json")
	t.Log("proving asynchronous projected-secret rotation and old-token revocation")
	privateRunner("rotate", "--kubeconfig", kubeconfig, "--output", rotatedPath, "--lifetime", "30m", "--api-url", endpoint,
		"--ca-file", caFile, "--tls-server-name", "arcadectl-api.arcadectl-system.svc", "--timeout", "3m")
	rotated := kindClientCredential(t, rotatedPath)
	if status, _ := self(initial.Token); status != 401 {
		t.Fatal("old bearer remained active after proven rotation")
	}
	if status, _ := self(rotated.Token); status != 200 {
		t.Fatal("new bearer not active")
	}
	// Trusted test administrator forces the current credential to expire, then
	// proves recovery rotation from a zero-ready-endpoint state without restart.
	secret, err := cluster.CoreV1().Secrets(adminauth.CredentialNamespace).Get(ctx, adminauth.CredentialSecretName, metav1.GetOptions{})
	if err != nil {
		t.Fatal("fixture credential readback unavailable")
	}
	bundle, err := adminauth.ParseVerifierBundle(secret.Data[adminauth.VerifierSecretKey])
	if err != nil {
		t.Fatal("fixture verifier unavailable")
	}
	bundle.Serial++
	bundle.ExpiresAt = time.Now().UTC().Add(-time.Minute)
	secret.Data[adminauth.VerifierSecretKey], _ = adminauth.MarshalVerifierBundle(bundle)
	if _, err := cluster.CoreV1().Secrets(adminauth.CredentialNamespace).Update(ctx, secret, metav1.UpdateOptions{}); err != nil {
		t.Fatal("set fixture expiry")
	}
	waitKindAPI(t, ctx, func() bool { status, _ := self(rotated.Token); return status == 401 })
	waitKindAPI(t, ctx, func() bool {
		deployment, err := cluster.AppsV1().Deployments(adminauth.CredentialNamespace).Get(ctx, "arcadectl-api", metav1.GetOptions{})
		return err == nil && deployment.Status.ReadyReplicas == 0
	})
	t.Log("proving expired-credential recovery through trusted-admin rotation")
	recoveredPath := filepath.Join(workspace, "recovered.json")
	privateRunner("rotate", "--kubeconfig", kubeconfig, "--output", recoveredPath, "--lifetime", "30m", "--api-url", endpoint,
		"--ca-file", caFile, "--tls-server-name", "arcadectl-api.arcadectl-system.svc", "--timeout", "3m")
	recovered := kindClientCredential(t, recoveredPath)
	if status, _ := self(recovered.Token); status != 200 {
		t.Fatal("expired-credential recovery failed")
	}
	if status, _ := self(rotated.Token); status != 401 {
		t.Fatal("expired old credential revived")
	}
	// Check actual Pod identity remained stable and the raw token is absent from
	// logs/projection. No Secret dump or credential file is persisted as evidence.
	pods, err := cluster.CoreV1().Pods(adminauth.CredentialNamespace).List(ctx, metav1.ListOptions{LabelSelector: "app.kubernetes.io/name=arcadectl-api"})
	if err != nil || len(pods.Items) != 1 || pods.Items[0].UID != initialPodUID {
		t.Fatal("API serving topology changed")
	}
	verifierProjection := false
	for _, volume := range pods.Items[0].Spec.Volumes {
		if volume.Secret != nil && volume.Secret.SecretName == adminauth.CredentialSecretName {
			if len(volume.Secret.Items) != 1 || volume.Secret.Items[0].Key != adminauth.VerifierSecretKey {
				t.Fatal("raw credential projected into actual API Pod")
			}
			verifierProjection = true
		}
	}
	if !verifierProjection {
		t.Fatal("actual API verifier projection absent")
	}
	for _, status := range pods.Items[0].Status.ContainerStatuses {
		if status.RestartCount != 0 {
			t.Fatal("credential reload required API restart")
		}
	}
	logs, err := cluster.CoreV1().Pods(adminauth.CredentialNamespace).GetLogs(pods.Items[0].Name, &corev1.PodLogOptions{}).DoRaw(ctx)
	if err != nil {
		t.Fatal("API audit unavailable")
	}
	for _, credential := range []adminauth.ClientCredential{initial, rotated, recovered} {
		if bytes.Contains(logs, []byte(credential.Token)) || bytes.Contains(logs, []byte(adminauth.TokenDigest(credential.Token))) {
			t.Fatal("credential leaked to cluster audit")
		}
		for _, output := range credentialOutputs {
			if bytes.Contains(output, []byte(credential.Token)) || bytes.Contains(output, []byte(adminauth.TokenDigest(credential.Token))) {
				t.Fatal("credential utility output leaked private material; output withheld")
			}
		}
	}
	t.Logf("cluster API bootstrap, rotation, revocation, expiry recovery, and redaction passed; source=%s dirty=%t image=%s; exact-owned cleanup follows", sha, dirty, apiImage)
}

type privateOutputCapture struct {
	contents  []byte
	truncated bool
}

func (capture *privateOutputCapture) Write(contents []byte) (int, error) {
	n := len(contents)
	remaining := 8192 - len(capture.contents)
	if n > remaining {
		capture.truncated = true
		contents = contents[:remaining]
	}
	capture.contents = append(capture.contents, contents...)
	return n, nil
}

func boolText(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func kindClientCredential(t *testing.T, path string) adminauth.ClientCredential {
	t.Helper()
	stat, err := os.Stat(path)
	if err != nil || stat.Mode().Perm() != 0600 {
		t.Fatal("private credential file permissions invalid")
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("private candidate unavailable")
	}
	credential, err := adminauth.ParseClientCredential(contents)
	if err != nil {
		t.Fatal("private candidate invalid")
	}
	return credential
}

func waitKindAPI(t *testing.T, ctx context.Context, predicate func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Minute)
	for time.Now().Before(deadline) && ctx.Err() == nil {
		if predicate() {
			return
		}
		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
		}
	}
	t.Fatal("bounded cluster API state did not settle")
}

func kindAPICertificate(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("fixture key unavailable")
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "arcadectl-api.arcadectl-system.svc"},
		DNSNames: []string{"arcadectl-api.arcadectl-system.svc"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal("fixture certificate unavailable")
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal("fixture private key unavailable")
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}
