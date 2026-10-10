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
	ctx, config, api, _ := targetKindFixtureImages(t, nodeImage, false)
	return ctx, config, api
}

// The complete pre-controller component has 34 public and two original Secret
// effects plus multiple complete runtime barriers. Its measured first attempt
// exceeded the small two-prerequisite fixture's 20-minute envelope. This named,
// finite test-only budget changes no production proof or installer deadline.
func targetKindPrecontrollerFixture(t *testing.T, nodeImage string) (context.Context, *rest.Config, string) {
	t.Helper()
	if nodeImage != targetKind135 && nodeImage != targetKind137 {
		t.Fatal("unsupported pre-controller fixture profile")
	}
	ctx, config, images, _ := targetKindFixtureImagesForBudget(t, nodeImage, false, false, false, false, true)
	return ctx, config, images.API
}

// The closed warm option builds the normal controller, not lifecycle-test code.
// Both images use the same exact-owned registry/cluster and serial build path.
func targetKindFixtureImages(t *testing.T, nodeImage string, withController bool) (context.Context, *rest.Config, string, string) {
	return targetKindFixtureImagesForRecipe(t, nodeImage, withController, false)
}

// A closed, larger finite native-test budget for the eleven-original recipe
// and its complete before/after phase brackets. No kubeconfig, permission or
// cluster ownership behavior changes, and ordinary v1 keeps its existing bound.
func targetKindFixtureImagesV2(t *testing.T, nodeImage string, withController bool) (context.Context, *rest.Config, string, string) {
	return targetKindFixtureImagesForRecipe(t, nodeImage, withController, true)
}

func targetKindFixtureImagesForRecipe(t *testing.T, nodeImage string, withController, recipeV2 bool) (context.Context, *rest.Config, string, string) {
	t.Helper()
	ctx, config, current, _ := targetKindFixtureImagesForScope(t, nodeImage, withController, recipeV2, false, false)
	return ctx, config, current.API, current.Controller
}

// Binary lifecycle has multiple complete behavioral barriers, not a single
// component proof. Its larger finite test-only deadline does not change any
// production proof or command deadline. Only the declared owned node profiles
// are accepted, and 1.37 additionally builds the ACTUAL pinned predecessor tree.
func targetKindInstallerFixture(t *testing.T, nodeImage string, predecessor bool) (context.Context, *rest.Config, installpackage.Images, installpackage.Images) {
	t.Helper()
	if nodeImage != targetKind135 && nodeImage != targetKind137 {
		t.Fatal("unsupported signed-binary fixture profile")
	}
	if predecessor && nodeImage != targetKind137 {
		t.Fatal("unsupported predecessor fixture profile")
	}
	return targetKindFixtureImagesForScope(t, nodeImage, true, true, true, predecessor)
}

func targetKindFixtureImagesForScope(t *testing.T, nodeImage string, withController, recipeV2, binary, predecessor bool) (context.Context, *rest.Config, installpackage.Images, installpackage.Images) {
	t.Helper()
	return targetKindFixtureImagesForBudget(t, nodeImage, withController, recipeV2, binary, predecessor, false)
}

func targetKindFixtureImagesForBudget(t *testing.T, nodeImage string, withController, recipeV2, binary, predecessor, precontroller bool) (context.Context, *rest.Config, installpackage.Images, installpackage.Images) {
	t.Helper()
	if precontroller && (withController || recipeV2 || binary || predecessor) {
		t.Fatal("pre-controller fixture cannot acquire executable or historical scope")
	}
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
	kubeconfig := filepath.Join(workspace, "kubeconfig")
	budget := 20 * time.Minute
	if precontroller {
		budget = 30 * time.Minute
	}
	if recipeV2 {
		budget = 40 * time.Minute
	}
	if binary {
		budget = 330 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	t.Cleanup(cancel)
	command := func(ctx context.Context, args ...string) *exec.Cmd {
		c := exec.CommandContext(ctx, args[0], args[1:]...)
		c.Dir = root
		c.Env = append(os.Environ(), "DOCKER_CONFIG="+dockerConfig, "KUBECONFIG="+kubeconfig, "GOMAXPROCS=2", "GOMEMLIMIT=1GiB")
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
	public("", "docker", "info", "--format", "{{.ServerVersion}}")
	for _, name := range []string{node, registry} {
		output, err := command(ctx, "docker", "inspect", name).CombinedOutput()
		if err == nil || !bytes.Contains(bytes.ToLower(output), []byte("no such")) {
			t.Fatal("owned container name preflight failed")
		}
	}
	var nodeID, registryID string
	type ownedImage struct{ tag, id string }
	var images []ownedImage
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
				if command(cleanupCtx, "go", "tool", "kind", "delete", "cluster", "--name", name, "--kubeconfig", kubeconfig).Run() != nil {
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
		for _, image := range images {
			id, ok := inspect("{{.Id}}", image.tag)
			if ok && id != "" {
				if image.id != "" && id == image.id {
					if command(cleanupCtx, "docker", "image", "rm", image.tag).Run() != nil {
						t.Error("owned image tag cleanup failed")
					}
				} else {
					t.Error("refusing image cleanup without exact ownership")
				}
			}
			if id, _ := inspect("{{.Id}}", image.tag); id != "" {
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
	sha := public("", "git", "rev-parse", "HEAD")
	epoch := public("", "git", "show", "-s", "--format=%ct", "HEAD")
	dirty := "false"
	if public("", "git", "status", "--porcelain") != "" {
		dirty = "true"
	}
	hosts := "/etc/containerd/certs.d/" + host
	public("", "docker", "exec", node, "mkdir", "-p", hosts)
	public("[host.\"http://"+registry+":5000\"]\n  capabilities = [\"pull\", \"resolve\"]\n", "docker", "exec", "--interactive", node, "tee", hosts+"/hosts.toml")
	build := func(repository, dockerfile, sourceRoot, sourceSHA, sourceEpoch, sourceDirty string) string {
		t.Helper()
		tag := host + "/" + repository + ":" + name
		if output, err := command(ctx, "docker", "image", "inspect", tag).CombinedOutput(); err == nil || !bytes.Contains(bytes.ToLower(output), []byte("no such image")) {
			t.Fatal("owned image tag preflight failed")
		}
		images = append(images, ownedImage{tag: tag}) // cleanup armed before build
		t.Log("building digest-pinned " + repository + " image with serialized, concurrency-limited Go build")
		args := []string{"docker", "build", "--file", filepath.Join(sourceRoot, dockerfile), "--build-arg", "VCS_REF=" + sourceSHA, "--build-arg", "SOURCE_DATE_EPOCH=" + sourceEpoch, "--build-arg", "SOURCE_DIRTY=" + sourceDirty}
		if dockerfile == "Dockerfile" {
			args = append(args, "--build-arg", "LIFECYCLE_TEST=false")
		}
		args = append(args, "--tag", tag, sourceRoot)
		public("", args...)
		images[len(images)-1].id = public("", "docker", "image", "inspect", "--format", "{{.Id}}", tag)
		if public("", "docker", "image", "inspect", "--format", "{{index .Config.Labels \"org.opencontainers.image.revision\"}}", tag) != sourceSHA || public("", "docker", "image", "inspect", "--format", "{{index .Config.Labels \"arcade.gobha.me/source-dirty\"}}", tag) != sourceDirty || public("", "docker", "image", "inspect", "--format", "{{.Config.User}}", tag) != "65532:65532" {
			t.Fatal("owned image source/user metadata refused")
		}
		public("", "docker", "push", tag)
		var digests []string
		if json.Unmarshal([]byte(public("", "docker", "image", "inspect", "--format", "{{json .RepoDigests}}", tag)), &digests) != nil {
			t.Fatal("image digest unavailable")
		}
		image := ""
		for _, digest := range digests {
			if strings.HasPrefix(digest, host+"/"+repository+"@sha256:") {
				if image != "" {
					t.Fatal("ambiguous owned image digest")
				}
				image = digest
			}
		}
		if image == "" {
			t.Fatal("owned image is not digest pinned")
		}
		public("", "docker", "exec", node, "ctr", "--namespace", "k8s.io", "images", "pull", "--hosts-dir", "/etc/containerd/certs.d", image)
		return image
	}
	apiImage := build("arcadectl-api", "Dockerfile.api", root, sha, epoch, dirty)
	controllerImage := ""
	if withController {
		controllerImage = build("arcadectl-controller", "Dockerfile", root, sha, epoch, dirty)
	}
	var previous installpackage.Images
	if binary && predecessor && nodeImage == targetKind137 {
		// The archive is generated from tracked original commit bytes, never
		// from a copied current runtime with misleading predecessor metadata.
		// No Git ref/worktree is mutated and no external repository is fetched.
		sourceRoot := filepath.Join(workspace, "predecessor-source")
		archive := filepath.Join(workspace, "predecessor-source.tar")
		if os.Mkdir(sourceRoot, 0700) != nil {
			t.Fatal("private predecessor workspace unavailable")
		}
		public("", "git", "archive", "--format=tar", "--output="+archive, installrender.LegacySourceSHA)
		public("", "tar", "--extract", "--file", archive, "--directory", sourceRoot, "--no-same-owner")
		oldEpoch := public("", "git", "show", "-s", "--format=%ct", installrender.LegacySourceSHA)
		previous.API = build("arcadectl-api-predecessor", "Dockerfile.api", sourceRoot, installrender.LegacySourceSHA, oldEpoch, "false")
		previous.Controller = build("arcadectl-controller-predecessor", "Dockerfile", sourceRoot, installrender.LegacySourceSHA, oldEpoch, "false")
	}
	configuration, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		t.Fatal("isolated kubeconfig unavailable")
	}
	return ctx, configuration, installpackage.Images{API: apiImage, Controller: controllerImage}, previous
}

// Shared signed-template setup; the boolean is a test-only closed choice, not
// a production permission provider. Apply all selected controller effects
// before a fixture WAL can fence ordinary engine work.
func targetKindInstallation(t *testing.T, ctx context.Context, config *rest.Config, plan *installrender.Plan, withControllers bool) (*HTTPAccess, *Engine, *installstate.Store, *installstate.Snapshot, string) {
	t.Helper()
	access, err := NewDirectHTTPAccess(config)
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
	t.Cleanup(func() { _ = files.Close() })
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
	credentials, err := engine.PrepareCredentials(ctx, s, fixtureTLS(t, plan.Namespace(), now))
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
		if resource.Object.GetKind() == "Namespace" || !withControllers && resource.Object.GetKind() == "Deployment" && resource.Phase == installrender.Controllers {
			continue
		}
		s, err = engine.Apply(ctx, s, resourceKey(resource), plan.Digest(), false)
		if err != nil {
			t.Fatalf("native signed effect %s: %v", resourceKey(resource).String(), err)
		}
	}
	d = s.Document()
	d.Stage, d.Revision = installstate.Verifying, d.Revision+1
	s, err = store.Commit(ctx, s, d)
	if err != nil {
		t.Fatal(err)
	}
	return access, engine, store, s, base
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
			access, engine, store, s, base := targetKindInstallation(t, ctx, config, plan, false)
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
			var stableServing *Serving
			var stableSince time.Time
			for {
				// Ready alone can precede native status/EndpointSlice convergence.
				// Settle the full original route fingerprint BEFORE the one-shot
				// proof; never retry authentication or relax its drift refusal.
				observed, err := engine.ObserveServing(readyCtx, s, access.Serving())
				if err != nil || observed == nil {
					stableServing, stableSince = nil, time.Time{}
				} else if stableServing == nil || observed.fingerprint != stableServing.fingerprint {
					stableServing, stableSince = observed, time.Now()
				} else if time.Since(stableSince) >= 5*time.Second {
					break
				}
				select {
				case <-readyCtx.Done():
					t.Fatal("actual original API did not converge to stable signed Ready serving evidence")
				case <-ticker.C:
				}
			}
			t.Log("proving closed native kubelet portforward and real authenticated HTTPS")
			clientFile := filepath.Join(base, "admin-client-"+s.Anchor().InstallationID+".json")
			caFile := filepath.Join(base, "api-ca-"+s.Anchor().InstallationID+".pem")
			request := LifecycleCheck{Checkpoint: TargetAuthenticated, Snapshot: s, Mode: installstate.Install, Target: plan,
				Options: LifecycleOptions{Now: time.Now().UTC(), Activation: ActivationOptions{CredentialFile: clientFile, CAFile: caFile}}}
			trace := &activationTrace{}
			if err := proof.Verify(context.WithValue(ctx, activationTraceKey{}, trace), request); err != nil {
				t.Fatalf("actual native authenticated target proof refused (stage=%s)", trace.stage())
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
