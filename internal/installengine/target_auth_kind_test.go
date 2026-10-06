//go:build kindinstall

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/adminauth"
	"github.com/gobha-me/arcadectl/internal/installpackage"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Official v0.33.0 release nodes, never mutable tags. These run sequentially.
// https://github.com/kubernetes-sigs/kind/releases/tag/v0.33.0
const targetKind135 = "kindest/node:v1.35.8@sha256:07b2536e30b803ed61d1677a79df6115f798ce64c80f9e22f6ed45afd09323c0"
const targetKind137 = "kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5"
const targetKindRegistry = "registry:3.0.0@sha256:6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e"

// A task-owned registry/Kind cluster. No external cluster configuration is read.
// Cleanup is registered before creation and checks exact identity and labels.
func targetKindFixture(t *testing.T, nodeImage string) (context.Context, *rest.Config, string) {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal("repository root unavailable")
	}
	workspace := t.TempDir()
	if os.Chmod(workspace, 0700) != nil {
		t.Fatal("private fixture directory unavailable")
	}
	dockerConfig := filepath.Join(workspace, "docker-config")
	if os.Mkdir(dockerConfig, 0700) != nil {
		t.Fatal("private Docker configuration unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	t.Cleanup(cancel)
	command := func(ctx context.Context, args ...string) *exec.Cmd {
		c := exec.CommandContext(ctx, args[0], args[1:]...)
		c.Dir = root
		c.Env = append(os.Environ(), "DOCKER_CONFIG="+dockerConfig, "GOMAXPROCS=2", "GOMEMLIMIT=1GiB")
		return c
	}
	public := func(input string, args ...string) string {
		t.Helper()
		c := command(ctx, args...)
		c.Stdin = strings.NewReader(input)
		output, err := c.CombinedOutput()
		if err != nil {
			t.Fatalf("public fixture step %s failed: %s", args[0], output)
		}
		return strings.TrimSpace(string(output))
	}
	random := make([]byte, 6)
	if _, err := rand.Read(random); err != nil {
		t.Fatal("fixture identity unavailable")
	}
	name := "arcadectl-install-auth-" + hex.EncodeToString(random)
	node, registry := name+"-control-plane", name+"-registry"
	kubeconfig := filepath.Join(workspace, "kubeconfig")
	public("", "docker", "info", "--format", "{{.ServerVersion}}")
	for _, name := range []string{node, registry} {
		output, err := command(ctx, "docker", "inspect", name).CombinedOutput()
		if err == nil || !bytes.Contains(bytes.ToLower(output), []byte("no such")) {
			t.Fatal("owned container name preflight failed")
		}
	}
	var nodeID, registryID, imageTag, imageID string
	var clusterArmed, registryArmed bool
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cleanupCancel()
		inspect := func(format, name string) (string, bool) {
			output, err := command(cleanupCtx, "docker", "inspect", "--format", format, name).CombinedOutput()
			if err != nil {
				if bytes.Contains(bytes.ToLower(output), []byte("no such")) {
					return "", true
				}
				t.Error("cleanup inspection failed; absence not proved")
				return "", false
			}
			return strings.TrimSpace(string(output)), true
		}
		if clusterArmed {
			id, ok := inspect("{{.Id}}", node)
			label, labelOK := inspect("{{index .Config.Labels \"io.x-k8s.kind.cluster\"}}", node)
			if ok && labelOK && id != "" && label == name && (nodeID == "" || id == nodeID) {
				if command(cleanupCtx, "go", "tool", "kind", "delete", "cluster", "--name", name).Run() != nil {
					t.Error("owned Kind cluster cleanup failed")
				}
			} else if id != "" {
				t.Error("refusing unowned Kind cleanup")
			}
		}
		if registryArmed {
			id, ok := inspect("{{.Id}}", registry)
			label, labelOK := inspect("{{index .Config.Labels \"arcade.gobha.me/e2e-run\"}}", registry)
			if ok && labelOK && id != "" && label == name && (registryID == "" || id == registryID) {
				if command(cleanupCtx, "docker", "rm", "--force", id).Run() != nil {
					t.Error("owned registry cleanup failed")
				}
			} else if id != "" {
				t.Error("refusing unowned registry cleanup")
			}
		}
		if imageTag != "" {
			id, ok := inspect("{{.Id}}", imageTag)
			if ok && id != "" {
				if imageID != "" && id == imageID {
					if command(cleanupCtx, "docker", "image", "rm", imageTag).Run() != nil {
						t.Error("owned image tag cleanup failed")
					}
				} else {
					t.Error("refusing image cleanup without exact ownership")
				}
			}
			if id, _ := inspect("{{.Id}}", imageTag); id != "" {
				t.Error("owned image tag remains")
			}
		}
		for _, name := range []string{node, registry} {
			if id, _ := inspect("{{.Id}}", name); id != "" {
				t.Error("owned container remains")
			}
		}
	})
	configPath := filepath.Join(workspace, "kind.yaml")
	if os.WriteFile(configPath, []byte("kind: Cluster\napiVersion: kind.x-k8s.io/v1alpha4\ncontainerdConfigPatches:\n- |-\n  [plugins.\"io.containerd.cri.v1.images\".registry]\n    config_path = \"/etc/containerd/certs.d\"\n"), 0600) != nil {
		t.Fatal("Kind fixture configuration unavailable")
	}
	t.Log("creating checksum-pinned disposable cluster")
	clusterArmed = true
	public("", "go", "tool", "kind", "create", "cluster", "--name", name, "--image", nodeImage, "--config", configPath, "--kubeconfig", kubeconfig, "--wait", "180s")
	nodeID = public("", "docker", "inspect", "--format", "{{.Id}}", node)
	if public("", "docker", "inspect", "--format", "{{index .Config.Labels \"io.x-k8s.kind.cluster\"}}", node) != name {
		t.Fatal("Kind ownership mismatch")
	}
	// Bound only this owned fixture, never shared Docker daemon resources.
	public("", "docker", "update", "--memory", "3g", "--memory-swap", "3g", "--cpus", "2", "--pids-limit", "2048", nodeID)
	public("", "docker", "pull", targetKindRegistry)
	registryArmed = true
	registryID = public("", "docker", "run", "--detach", "--pull=never", "--restart=no", "--memory", "128m", "--memory-swap", "128m", "--cpus", "0.5", "--pids-limit", "128", "--publish", "127.0.0.1::5000", "--name", registry,
		"--label", "arcade.gobha.me/e2e-run="+name, targetKindRegistry)
	// Attaching first avoids ephemeral published-port reassignment.
	public("", "docker", "network", "connect", "kind", registry)
	_, port, err := net.SplitHostPort(public("", "docker", "port", registry, "5000/tcp"))
	if err != nil {
		t.Fatal("registry endpoint unavailable")
	}
	host := "127.0.0.1:" + port
	imageTag = host + "/arcadectl-api:" + name
	if output, err := command(ctx, "docker", "image", "inspect", imageTag).CombinedOutput(); err == nil || !bytes.Contains(bytes.ToLower(output), []byte("no such image")) {
		t.Fatal("owned image tag preflight failed")
	}
	sha := public("", "git", "rev-parse", "HEAD")
	epoch := public("", "git", "show", "-s", "--format=%ct", "HEAD")
	dirty := "false"
	if public("", "git", "status", "--porcelain") != "" {
		dirty = "true"
	}
	t.Log("building digest-pinned API image with bounded Go resources")
	public("", "docker", "build", "--file", "Dockerfile.api", "--build-arg", "VCS_REF="+sha, "--build-arg", "SOURCE_DATE_EPOCH="+epoch,
		"--build-arg", "SOURCE_DIRTY="+dirty, "--tag", imageTag, ".")
	imageID = public("", "docker", "image", "inspect", "--format", "{{.Id}}", imageTag)
	public("", "docker", "push", imageTag)
	var digests []string
	if json.Unmarshal([]byte(public("", "docker", "image", "inspect", "--format", "{{json .RepoDigests}}", imageTag)), &digests) != nil {
		t.Fatal("image digest unavailable")
	}
	image := ""
	for _, digest := range digests {
		if strings.HasPrefix(digest, host+"/arcadectl-api@sha256:") {
			image = digest
		}
	}
	if image == "" {
		t.Fatal("API image is not digest pinned")
	}
	hosts := "/etc/containerd/certs.d/" + host
	public("", "docker", "exec", node, "mkdir", "-p", hosts)
	public("[host.\"http://"+registry+":5000\"]\n  capabilities = [\"pull\", \"resolve\"]\n", "docker", "exec", "--interactive", node, "tee", hosts+"/hosts.toml")
	public("", "docker", "exec", node, "ctr", "--namespace", "k8s.io", "images", "pull", "--hosts-dir", "/etc/containerd/certs.d", image)
	configuration, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		t.Fatal("isolated kubeconfig unavailable")
	}
	return ctx, configuration, image
}

// Actual signed-template effects, original UID journal/Secrets, kubelet-built
// Deployment/ReplicaSet/Pod/EndpointSlices, and native fixed-Pod HTTPS auth.
// Stages are constructed explicitly and controllers are never deployed: this
// is NOT the full installation, upgrade, rollback or uninstall acceptance gate.
func TestKindTargetAuthenticatedNativeKubelet(t *testing.T) {
	for _, profile := range []struct{ id, node string }{{installrender.Profile135, targetKind135}, {installrender.Profile137, targetKind137}} {
		t.Run(profile.id, func(t *testing.T) {
			ctx, config, apiImage := targetKindFixture(t, profile.node)
			plan := fixturePlanImages(t, "isolated-install", profile.id, installpackage.Images{
				Controller: "registry.example/controller@sha256:" + strings.Repeat("a", 64), API: apiImage,
			})
			access, err := NewHTTPAccess(config)
			if err != nil {
				t.Fatal(err)
			}
			base := t.TempDir()
			if os.Chmod(base, 0700) != nil {
				t.Fatal("private evidence directory unavailable")
			}
			files, err := privatefs.Open(base, false)
			if err != nil {
				t.Fatal(err)
			}
			defer files.Close()
			receipt, err := installstate.PrepareBootstrap(files, "bootstrap.json", plan)
			if err != nil {
				t.Fatal(err)
			}
			s, err := receipt.EnsureNamespace(ctx, access.Namespaces())
			if err != nil {
				t.Fatal("original namespace bootstrap: ", err)
			}
			store, err := installstate.New(access.Namespaces(), plan)
			if err != nil {
				t.Fatal(err)
			}
			s, err = store.Load(ctx, s.Anchor())
			if err != nil {
				t.Fatal("original journal load: ", err)
			}
			d := s.Document()
			d.Stage, d.Revision = installstate.Applying, d.Revision+1
			s, err = store.Commit(ctx, s, d)
			if err != nil {
				t.Fatal(err)
			}
			engine, err := NewWithAccess(access, store, files, plan)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			tls := fixtureTLS(t, plan.Namespace(), now)
			credentials, err := engine.PrepareCredentials(ctx, s, tls)
			if err != nil {
				t.Fatal(err)
			}
			secrets, err := NewSecretWorkflow(engine, access.PrivateSecrets())
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{adminauth.CredentialSecretName, "arcadectl-api-tls"} {
				s, err = secrets.Create(ctx, s, credentials, name, now)
				if err != nil {
					t.Fatal("native private effect: ", err)
				}
			}
			for _, resource := range plan.Resources() {
				o := resource.Object
				if o.GetKind() == "Namespace" || o.GetKind() == "Deployment" && resource.Phase == installrender.Controllers {
					continue
				}
				key := installstate.Key{APIVersion: o.GetAPIVersion(), Kind: o.GetKind(), Namespace: o.GetNamespace(), Name: o.GetName()}
				s, err = engine.Apply(ctx, s, key, plan.Digest(), false)
				if err != nil {
					t.Fatalf("native signed effect %s: %v", key.String(), err)
				}
			}
			d = s.Document()
			d.Stage, d.Revision = installstate.Verifying, d.Revision+1
			s, err = store.Commit(ctx, s, d)
			if err != nil {
				t.Fatal(err)
			}
			p, err := NewClusterPrerequisites(engine, access)
			if err != nil {
				t.Fatal(err)
			}
			proof, err := NewClusterTargetAuthenticated(p)
			if err != nil {
				t.Fatal(err)
			}
			readyCtx, readyCancel := context.WithTimeout(ctx, 3*time.Minute)
			defer readyCancel()
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()
			for {
				if _, err := engine.ObserveServing(readyCtx, s, access.Serving()); err == nil {
					break
				}
				select {
				case <-readyCtx.Done():
					t.Fatal("actual original API did not converge to signed Ready serving evidence")
				case <-ticker.C:
				}
			}
			t.Log("proving closed native kubelet portforward and real authenticated HTTPS")
			clientFile := filepath.Join(base, "admin-client-"+s.Anchor().InstallationID+".json")
			caFile := filepath.Join(base, "api-ca-"+s.Anchor().InstallationID+".pem")
			request := LifecycleCheck{Checkpoint: TargetAuthenticated, Snapshot: s, Mode: installstate.Install, Target: plan,
				Options: LifecycleOptions{Now: time.Now().UTC(), Activation: ActivationOptions{CredentialFile: clientFile, CAFile: caFile}}}
			if err := proof.Verify(ctx, request); err != nil {
				t.Fatal("actual native authenticated target proof: ", err)
			}
			proveKindAdmissionFixtureStorage(t, ctx, config, s.Anchor(), plan)
			proveKindAdmissionFixtureRecipes(t, ctx, config, engine, s, plan)
			after, err := store.Load(ctx, s.Anchor())
			if err != nil || !bytes.Equal(after.Bytes(), s.Bytes()) || after.ResourceVersion() != s.ResourceVersion() {
				t.Fatal("native authentication changed the original journal")
			}
		})
	}
}
