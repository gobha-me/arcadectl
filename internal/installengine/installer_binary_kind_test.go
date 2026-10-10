//go:build kindinstall

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/adminauth"
	"github.com/gobha-me/arcadectl/internal/installbaseline"
	"github.com/gobha-me/arcadectl/internal/installcontract"
	"github.com/gobha-me/arcadectl/internal/installfiles"
	"github.com/gobha-me/arcadectl/internal/installpackage"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/tools/clientcmd"
	configapi "k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/utils/ptr"
)

// No direct Engine.Apply, bootstrap binding, fabricated journal stage, partial
// provider or preinstalled Arcade resource is used. ALL installation effects
// go through a built executable and its actual signed-package production path.
// The only later direct setup is two inert, nonbinding retained claims. This
// proves claim retention, not game bytes/CSI backup (those have separate gates).
func TestKindSignedInstallerBinaryLifecycle(t *testing.T) {
	for _, profile := range []struct{ id, node string }{{installrender.Profile135, targetKind135}, {installrender.Profile137, targetKind137}} {
		t.Run(profile.id, func(t *testing.T) {
			modes := []string{"fresh"}
			if profile.id == installrender.Profile137 {
				modes = append(modes, "transition")
			}
			for _, mode := range modes {
				t.Run(mode, func(t *testing.T) {
					ctx, config, currentImages, previousImages := targetKindInstallerFixture(t, profile.node, mode == "transition")
					root, err := filepath.Abs(filepath.Join("..", ".."))
					if err != nil {
						t.Fatal("repository root unavailable")
					}
					base := t.TempDir()
					if os.Chmod(base, 0700) != nil {
						t.Fatal("protected binary fixture unavailable")
					}
					binary := filepath.Join(base, "arcadectl-installer")
					build := exec.CommandContext(ctx, "go", "build", "-p", "1", "-trimpath", "-o", binary, "./cmd/arcadectl-installer")
					build.Dir = root
					build.Env = append(os.Environ(), "GOMAXPROCS=2", "GOMEMLIMIT=1GiB")
					if output, err := build.CombinedOutput(); err != nil {
						t.Fatalf("installer executable build failed: %s", output)
					}
					git := func(args ...string) string {
						c := exec.CommandContext(ctx, "git", args...)
						c.Dir = root
						out, err := c.Output()
						if err != nil {
							t.Fatal("tracked fixture source identity unavailable")
						}
						return strings.TrimSpace(string(out))
					}
					keyPublic, keyPrivate, err := ed25519.GenerateKey(rand.Reader)
					if err != nil {
						t.Fatal("test-only signing key unavailable")
					}
					publicDER, err := x509.MarshalPKIXPublicKey(keyPublic)
					if err != nil {
						t.Fatal("test-only trust key unavailable")
					}
					trust := filepath.Join(base, "external-trust.pem")
					if os.WriteFile(trust, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}), 0600) != nil {
						t.Fatal("protected external trust key unavailable")
					}
					publish := func(name string, legacy bool, images installpackage.Images, predecessors []installpackage.Predecessor) (*installrender.Plan, string) {
						t.Helper()
						payloads, crds, err := installrender.RenderPayloads(images, legacy)
						if err != nil {
							t.Fatal("closed signed payload rendering refused")
						}
						source := git("rev-parse", "HEAD")
						if legacy {
							source = installrender.LegacySourceSHA
						}
						// Source epoch comes from the exact tracked tree, not wall time.
						epoch := git("show", "-s", "--format=%ct", source)
						manifest := installpackage.Manifest{FormatVersion: installpackage.FormatVersion, RendererVersion: installpackage.RendererVersion, PackageVersion: "0.1.0-rc.1", SourceSHA: source, Images: images, Profiles: installrender.SupportedProfiles(legacy), Prerequisites: installrender.RequiredPrerequisites(), CRDs: crds, Predecessors: predecessors}
						manifest.SourceEpoch, err = strconv.ParseInt(epoch, 10, 64)
						if err != nil {
							t.Fatal("source epoch unavailable")
						}
						body, err := installpackage.Build(manifest, payloads)
						if err != nil {
							t.Fatal("signed manifest build refused")
						}
						sig, err := installpackage.Sign(body, keyPrivate)
						if err != nil {
							t.Fatal("test-only manifest signing refused")
						}
						pkg, err := installpackage.Verify(body, sig, payloads, keyPublic)
						if err != nil {
							t.Fatal("independent package signature verification refused")
						}
						plan, err := installrender.Compile(pkg, installrender.DefaultNamespace, profile.id)
						if err != nil {
							t.Fatal("signed supported profile compilation refused")
						}
						path := filepath.Join(base, name)
						if installfiles.Write(path, body, sig, payloads, keyPublic) != nil {
							t.Fatal("signed package publication refused")
						}
						return plan, path
					}
					var previous *installrender.Plan
					var historicalBinary string
					var previousPath string
					var predecessors []installpackage.Predecessor
					if mode == "transition" {
						historicalBinary = buildHistoricalInstallerBinary(t, ctx, root, base)
						previous, previousPath = publish("previous-package", true, previousImages, nil)
						predecessors = []installpackage.Predecessor{{ID: "issue-26", PackageSHA256: previous.Digest(), SourceSHA: previous.Manifest().SourceSHA, Images: previous.Manifest().Images, Namespace: previous.Namespace(), ProfileIDs: []string{profile.id}}}
					}
					var previousFiles map[string]string
					if previous != nil {
						previousFiles = binaryPackageFileDigests(t, previousPath)
					}
					current, currentPath := publish("current-package", false, currentImages, predecessors)
					original, originalPath := current, currentPath
					plans, paths := []*installrender.Plan{current}, []string{currentPath}
					if previous != nil {
						original, originalPath = previous, previousPath
						plans, paths = append(plans, previous), append(paths, previousPath)
					}
					// One independent non-rollback security artifact protects every
					// runtime package, including the byte-authentic predecessor.
					epoch, err := strconv.ParseInt(git("show", "-s", "--format=%ct", "HEAD"), 10, 64)
					if err != nil {
						t.Fatal("baseline source epoch unavailable")
					}
					manifest, payload, err := installbaseline.Build(git("rev-parse", "HEAD"), epoch)
					if err != nil {
						t.Fatal("separate baseline rendering refused")
					}
					signature, err := installbaseline.Sign(manifest, keyPrivate)
					baselinePath := filepath.Join(base, "security-baseline")
					if err != nil || installfiles.WriteBaseline(baselinePath, manifest, signature, payload, keyPublic) != nil {
						t.Fatal("separate signed baseline publication refused")
					}
					artifact, err := installfiles.LoadBaseline(baselinePath, keyPublic)
					if err != nil {
						t.Fatal("independent baseline authentication refused")
					}
					baseline, err := installbaseline.Compile(artifact, original.Namespace(), profile.id)
					if err != nil {
						t.Fatal("independent baseline scope compilation refused")
					}
					state := filepath.Join(base, "state")
					if os.Mkdir(state, 0700) != nil {
						t.Fatal("protected initial state directory unavailable")
					}
					if len(config.CAData) == 0 || len(config.CertData) == 0 || len(config.KeyData) == 0 {
						t.Fatal("owned static embedded cluster identity unavailable")
					}
					static := configapi.Config{APIVersion: "v1", Kind: "Config", CurrentContext: "owned-installer",
						Clusters:  map[string]*configapi.Cluster{"owned-cluster": {Server: config.Host, CertificateAuthorityData: bytes.Clone(config.CAData)}},
						AuthInfos: map[string]*configapi.AuthInfo{"owned-admin": {ClientCertificateData: bytes.Clone(config.CertData), ClientKeyData: bytes.Clone(config.KeyData)}},
						Contexts:  map[string]*configapi.Context{"owned-installer": {Cluster: "owned-cluster", AuthInfo: "owned-admin", Namespace: original.Namespace()}},
					}
					encoded, err := clientcmd.Write(static)
					kubeconfig := filepath.Join(base, "owned-kubeconfig")
					if err != nil || os.WriteFile(kubeconfig, encoded, 0600) != nil {
						t.Fatal("protected explicit cluster configuration unavailable")
					}
					tls := fixtureTLS(t, original.Namespace(), time.Now().UTC())
					runUsing := func(executable, command, target string, historical bool) {
						t.Helper()
						args := []string{command, "--namespace", original.Namespace(), "--profile", profile.id, "--bootstrap-package", originalPath, "--trust-key", trust, "--state-dir", state, "--bootstrap-receipt", "bootstrap.json", "--kubeconfig", kubeconfig, "--context", "owned-installer", "--api-ca", tls.CAFile, "--timeout", "2h"}
						packageInputs := paths
						if historical {
							packageInputs = []string{originalPath}
						} else {
							args = append(args, "--security-baseline", baselinePath)
						}
						for _, path := range packageInputs {
							args = append(args, "--package", path)
						}
						if target != "" {
							args = append(args, "--target-package", target)
						}
						if command == "install" {
							args = append(args, "--api-certificate", tls.CertificateFile, "--api-key", tls.KeyFile)
						}
						t.Log("running actual signed installer binary: " + command)
						c := exec.CommandContext(ctx, executable, args...)
						c.Dir = root
						c.Env = append(os.Environ(), "GOMAXPROCS=2", "GOMEMLIMIT=1GiB")
						output, err := c.CombinedOutput()
						if err != nil {
							// This executable deliberately emits only fixed diagnostics and
							// journal stages/revisions, not cluster bodies/credential paths.
							t.Fatalf("actual installer %s refused: %s", command, output)
						}
						if command == "uninstall" && !bytes.Contains(output, []byte("namespace, world claims, credentials and protections retained")) {
							t.Fatal("actual uninstall omitted retained-world recovery guidance")
						}
						if command == "enroll-baseline" && !bytes.Contains(output, []byte("security baseline enrollment and native enforcement proof complete")) {
							t.Fatal("actual enrollment omitted full enforcement completion")
						}
					}
					run := func(command, target string) { runUsing(binary, command, target, false) }
					access, err := NewDirectHTTPAccess(config)
					if err != nil {
						t.Fatal("owned observer unavailable")
					}
					store, err := installstate.NewWithBaseline(access.Namespaces(), baseline, plans...)
					if err != nil {
						t.Fatal("independent journal reader unavailable")
					}
					meta, err := metadata.NewForConfig(access.readConfig())
					if err != nil {
						t.Fatal("secret-metadata-only observer unavailable")
					}
					var anchor installstate.Anchor
					retained := map[string]types.UID{}
					retainedSecretRV := map[string]string{}
					retainedFiles := map[string][]byte{}
					originalRetained := map[installstate.Key]types.UID{}
					var originalBaseline []installstate.BaselineResource
					var originalEnrollment *installstate.BaselineEnrollmentProvenance
					var enrollmentSourceBody []byte
					var enrollmentSourceName string
					checkComplete := func(mode installstate.Mode, target *installrender.Plan, installed bool) *installstate.Snapshot {
						t.Helper()
						files, err := privatefs.Open(state, false)
						if err != nil {
							t.Fatal("protected original state unavailable")
						}
						defer files.Close()
						receipt, err := installstate.LoadBootstrapWithBaseline(files, "bootstrap.json", original, baseline)
						if err != nil {
							t.Fatal("original signed bootstrap receipt unavailable")
						}
						freshAnchor, err := receipt.PinnedAnchor(ctx)
						if err != nil || anchor.UID != "" && anchor != freshAnchor {
							t.Fatal("binary changed original namespace/installation identity")
						}
						anchor = freshAnchor
						s, err := store.Load(ctx, anchor)
						if err != nil {
							t.Fatal("binary left an unreadable original journal")
						}
						d := s.Document()
						if d.Stage != installstate.Complete || d.Pending != nil || d.Mode != mode || d.TargetPackage != target.Digest() || d.ActivePackage != target.Digest() || d.Installed != installed {
							t.Fatal("actual binary did not finish the exact signed lifecycle operation")
						}
						if d.SecurityBaseline == nil || d.SecurityBaseline.Version != installbaseline.Version || d.SecurityBaseline.ArtifactDigest != baseline.Digest() || d.SecurityBaseline.Stage != installstate.BaselineVerified || d.SecurityBaseline.Pending != nil || len(d.SecurityBaseline.Resources) != installbaseline.ResourceCount {
							t.Fatal("actual binary did not retain its separate complete baseline identity")
						}
						if originalBaseline == nil {
							originalBaseline = append([]installstate.BaselineResource{}, d.SecurityBaseline.Resources...)
						} else if !reflect.DeepEqual(originalBaseline, d.SecurityBaseline.Resources) {
							t.Fatal("runtime operation rolled back or replaced baseline UID/hash inventory")
						}
						if originalEnrollment == nil && d.SecurityBaseline.Enrollment != nil {
							copy := *d.SecurityBaseline.Enrollment
							originalEnrollment = &copy
						} else if !reflect.DeepEqual(originalEnrollment, d.SecurityBaseline.Enrollment) {
							t.Fatal("runtime operation replaced original enrollment provenance")
						}
						if enrollmentSourceName != "" {
							body, _, err := files.ReadEvidence(enrollmentSourceName, privatefs.MaxEvidenceFileBytes)
							if err != nil || !bytes.Equal(body, enrollmentSourceBody) {
								t.Fatal("runtime operation rewrote original enrollment source evidence")
							}
						}
						baselineContract, err := installcontract.NewBaseline(baseline)
						if err != nil {
							t.Fatal("independent baseline contract unavailable")
						}
						for _, row := range originalBaseline {
							template, templateErr := baselineContract.Template(row.Key, false)
							live, readErr := access.Get(ctx, row.Key)
							if templateErr != nil || readErr != nil || row.TemplateSHA256 != template.Hash() || template.MatchLive(live, row.UID) != nil {
								t.Fatal("binary baseline journal identity differs from original signed live resource")
							}
						}
						if len(originalRetained) == 0 {
							for _, r := range d.Resources {
								if r.Retained {
									originalRetained[r.Key] = r.UID
								}
							}
						}
						for key, uid := range originalRetained {
							found := false
							for _, r := range d.Resources {
								if r.Key == key && r.UID == uid && r.Retained {
									found = true
								}
							}
							if !found {
								t.Fatal("binary lost or replaced an original retained journal identity")
							}
						}
						for _, name := range []string{adminauth.CredentialSecretName, "arcadectl-api-tls"} {
							secret, err := meta.Resource(schema.GroupVersionResource{Version: "v1", Resource: "secrets"}).Namespace(anchor.Namespace).Get(ctx, name, metav1.GetOptions{})
							if err != nil || secret.UID == "" || retained[name] != "" && (retained[name] != secret.UID || retainedSecretRV[name] != secret.ResourceVersion) {
								t.Fatal("binary replaced or removed an original retained credential Secret")
							}
							retained[name] = secret.UID
							retainedSecretRV[name] = secret.ResourceVersion
						}
						for _, name := range []string{"bootstrap.json", "admin-client-" + anchor.InstallationID + ".json", "api-ca-" + anchor.InstallationID + ".pem"} {
							body, _, err := files.Read(name, 65536)
							if err != nil || retainedFiles[name] != nil && !bytes.Equal(retainedFiles[name], body) {
								t.Fatal("binary lost protected retained client recovery evidence")
							}
							retainedFiles[name] = bytes.Clone(body)
						}
						engine, err := NewWithBaselineAccess(access, store, files, baseline, plans...)
						if err != nil || engine.fixtureFence(s) != nil {
							t.Fatal("binary left unresolved original fixture evidence")
						}
						if previous != nil && !reflect.DeepEqual(previousFiles, binaryPackageFileDigests(t, previousPath)) {
							t.Fatal("binary rewrote authentic predecessor manifest, signature or payload bytes")
						}
						return s
					}
					var historicalSnapshot *installstate.Snapshot
					var historicalInputs map[string][]byte
					if previous == nil {
						run("install", originalPath)
						checkComplete(installstate.Install, original, true)
					} else {
						runUsing(historicalBinary, "install", originalPath, true)
						historicalSnapshot, historicalInputs = checkBinaryHistoricalInstall(t, ctx, access, store, state, original, baseline)
						anchor = historicalSnapshot.Anchor()
						for _, row := range historicalSnapshot.Document().Resources {
							if row.Retained {
								originalRetained[row.Key] = row.UID
							}
						}
						for name, body := range historicalInputs {
							retainedFiles[name] = bytes.Clone(body)
						}
						for _, name := range []string{adminauth.CredentialSecretName, "arcadectl-api-tls"} {
							secret, err := meta.Resource(schema.GroupVersionResource{Version: "v1", Resource: "secrets"}).Namespace(anchor.Namespace).Get(ctx, name, metav1.GetOptions{})
							if err != nil || secret.UID == "" {
								t.Fatal("historical original retained Secret metadata unavailable")
							}
							retained[name], retainedSecretRV[name] = secret.UID, secret.ResourceVersion
						}
					}
					client, err := kubernetes.NewForConfig(access.readConfig())
					if err != nil {
						t.Fatal("owned inert claim setup unavailable")
					}
					claims := map[string]*corev1.PersistentVolumeClaim{}
					for _, name := range []string{"retained-world", "unlabeled-retained-claim"} {
						claim := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: original.Namespace()}, Spec: corev1.PersistentVolumeClaimSpec{AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce}, StorageClassName: ptr.To(""), Resources: corev1.VolumeResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("1Mi")}}}}
						if name == "retained-world" {
							claim.Labels = map[string]string{"app.kubernetes.io/managed-by": "arcadectl", "app.kubernetes.io/instance": "binary-world", "arcade.gobha.me/data-identity": "binary-original-identity", "arcade.gobha.me/data-policy": "retain", "arcade.gobha.me/data-path": "world"}
						}
						created, err := client.CoreV1().PersistentVolumeClaims(original.Namespace()).Create(ctx, claim, metav1.CreateOptions{})
						if err != nil || created.UID == "" {
							t.Fatal("owned nonbinding retained claim creation refused")
						}
						if wait.PollUntilContextTimeout(ctx, time.Second, time.Minute, true, func(ctx context.Context) (bool, error) {
							fresh, err := client.CoreV1().PersistentVolumeClaims(original.Namespace()).Get(ctx, name, metav1.GetOptions{})
							if err != nil || fresh.UID != created.UID || fresh.Spec.VolumeName != "" {
								return false, ErrRead
							}
							if fresh.Status.Phase == corev1.ClaimPending {
								claims[name] = fresh.DeepCopy()
								return true, nil
							}
							return false, nil
						}) != nil {
							t.Fatal("owned retained claims did not become nonbinding Pending")
						}
					}
					if previous != nil {
						// The first world floor is nonempty before explicit enrollment.
						listed, err := client.CoreV1().PersistentVolumeClaims(anchor.Namespace).List(ctx, metav1.ListOptions{})
						if err != nil || len(listed.Items) != len(claims) {
							t.Fatal("historical initial claim floor unavailable")
						}
						rows := []fixtureWorldRow{}
						for _, claim := range listed.Items {
							originalClaim := claims[claim.Name]
							if originalClaim == nil || originalClaim.UID != claim.UID {
								t.Fatal("historical initial claim was replaced")
							}
							// Dynamic List decoding supplies omitted item TypeMeta;
							// normalize only this independent typed-client loop copy.
							claim.APIVersion, claim.Kind = "v1", "PersistentVolumeClaim"
							body, err := json.Marshal(&claim)
							if err != nil {
								t.Fatal("historical initial claim hashing refused")
							}
							rows = append(rows, fixtureWorldRow{Key: installstate.Key{APIVersion: "v1", Kind: "PersistentVolumeClaim", Namespace: claim.Namespace, Name: claim.Name}, UID: claim.UID, ResourceVersion: claim.ResourceVersion, SHA256: fixtureWorldDigest(body)})
						}
						sortFixtureWorlds(rows)
						run("enroll-baseline", "")
						enrolled := checkComplete(installstate.Install, original, true)
						enrollmentSourceBody, enrollmentSourceName = checkBinaryHistoricalEnrollment(t, ctx, access, state, original, historicalSnapshot, enrolled, historicalInputs, rows)
						run("upgrade", currentPath)
						checkComplete(installstate.Upgrade, current, true)
						run("rollback", previousPath)
						checkComplete(installstate.Rollback, previous, true)
					}
					run("uninstall", "")
					final := checkComplete(installstate.Uninstall, original, false)
					for _, r := range final.Document().Resources {
						if !r.Retained {
							t.Fatal("uninstall journal retained a runtime/access resource")
						}
					}
					for _, r := range original.Resources() {
						key := resourceKey(r)
						live, err := access.Get(ctx, key)
						if r.Retained {
							if err != nil || live.GetUID() == "" || live.GetUID() != originalRetained[key] {
								t.Fatal("uninstall removed an original retained anchor/protection")
							}
						} else if !apierrors.IsNotFound(err) {
							t.Fatal("uninstall did not prove actual runtime/access absence")
						}
					}
					for name, originalClaim := range claims {
						live, err := client.CoreV1().PersistentVolumeClaims(anchor.Namespace).Get(ctx, name, metav1.GetOptions{})
						if err != nil || live.UID != originalClaim.UID || live.DeletionTimestamp != nil || live.Spec.VolumeName != "" || live.Status.Phase != corev1.ClaimPending || !reflect.DeepEqual(live.Spec, originalClaim.Spec) || !reflect.DeepEqual(live.Labels, originalClaim.Labels) || !reflect.DeepEqual(live.Annotations, originalClaim.Annotations) || !reflect.DeepEqual(live.OwnerReferences, originalClaim.OwnerReferences) {
							t.Fatal("uninstall changed or deleted a retained namespace claim")
						}
					}
					// Whole owned-cluster teardown, not Namespace/world deletion, is the
					// sole final disposal route for these exact temporary retained claims.
				})
			}
		})
	}
}
