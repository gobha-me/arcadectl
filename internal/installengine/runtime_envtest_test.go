//go:build envtest

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/adminauth"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

type lostResponseAccess struct {
	*HTTPAccess
	key            installstate.Key
	writes         int
	failRead       bool
	responseKey    installstate.Key
	responseWrites int
}

type lostPrivateReadback struct {
	PrivateSecretAccess
	writes   int
	failRead bool
}

func (a *lostPrivateReadback) Get(ctx context.Context, namespace, name string) (*corev1.Secret, error) {
	if a.failRead && name == adminauth.CredentialSecretName {
		a.failRead = false
		return nil, ErrRead
	}
	return a.PrivateSecretAccess.Get(ctx, namespace, name)
}
func (a *lostPrivateReadback) Create(ctx context.Context, s *corev1.Secret, dry bool) (*corev1.Secret, error) {
	result, err := a.PrivateSecretAccess.Create(ctx, s, dry)
	if !dry && err == nil {
		a.writes++
		if s.Name == adminauth.CredentialSecretName {
			a.failRead = true
		} else {
			return nil, ErrRead
		}
	}
	return result, err
}

func (a *lostResponseAccess) Get(ctx context.Context, k installstate.Key) (*unstructured.Unstructured, error) {
	if a.failRead && k == a.key {
		a.failRead = false
		return nil, ErrRead
	}
	return a.HTTPAccess.Get(ctx, k)
}
func (a *lostResponseAccess) Create(ctx context.Context, k installstate.Key, o *unstructured.Unstructured, dry bool) (*unstructured.Unstructured, error) {
	result, err := a.HTTPAccess.Create(ctx, k, o, dry)
	if k == a.responseKey && !dry && err == nil {
		a.responseWrites++
		return nil, ErrRead
	}
	if k == a.key && !dry {
		a.writes++
		if err == nil {
			a.failRead = true
			return result, nil
		}
	}
	return result, err
}

// This proves actual journal CAS, real public/private writes, signed default checks and
// lost-response and unavailable-readback recovery against a fresh isolated API
// server. A manually created RS/Pod also checks native admission defaults; no
// kubelet, workload binary, runtime activation or lifecycle uninstall runs.
func TestEnvtestJournaledResourceEffects(t *testing.T) {
	environment := &envtest.Environment{DownloadBinaryAssets: true, DownloadBinaryAssetsVersion: "1.37.0", DownloadBinaryAssetsIndexURL: "https://raw.githubusercontent.com/kubernetes-sigs/controller-tools/1031496fc98a4f51010c3bdfdeb57b5d67bea7bd/envtest-releases.yaml", BinaryAssetsDirectory: t.TempDir(), ControlPlaneStartTimeout: 90 * time.Second, ControlPlaneStopTimeout: 30 * time.Second}
	// The stock envtest disables ServiceAccount admission. This gate must
	// exercise the actual runtime Pod token projection/defaults instead.
	environment.ControlPlane.APIServer = &envtest.APIServer{}
	environment.ControlPlane.APIServer.Configure().Set("disable-admission-plugins", "")
	config, err := environment.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := environment.Stop(); err != nil {
			t.Error(err)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	plan := fixturePlanProfile(t, installrender.DefaultNamespace, installrender.Profile137)
	access, err := NewHTTPAccess(config)
	if err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	if err := os.Chmod(base, 0700); err != nil {
		t.Fatal(err)
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
		t.Fatal("single-attempt namespace bootstrap: ", err)
	}
	store, err := installstate.New(access.Namespaces(), plan)
	if err != nil {
		t.Fatal(err)
	}
	s, err = store.Load(ctx, s.Anchor())
	if err != nil {
		t.Fatal(err)
	}
	d := s.Document()
	d.Revision++
	d.Stage = installstate.Applying
	s, err = store.Commit(ctx, s, d)
	if err != nil {
		t.Fatal("single-attempt journal stage CAS: ", err)
	}
	lost := &lostResponseAccess{HTTPAccess: access}
	for _, r := range plan.Resources() {
		if r.Object.GetKind() == "ServiceAccount" {
			lost.key = installstate.Key{APIVersion: "v1", Kind: "ServiceAccount", Namespace: r.Object.GetNamespace(), Name: r.Object.GetName()}
			break
		}
	}
	for _, r := range plan.Resources() {
		if r.Object.GetKind() == "Role" {
			lost.responseKey = installstate.Key{APIVersion: r.Object.GetAPIVersion(), Kind: "Role", Namespace: r.Object.GetNamespace(), Name: r.Object.GetName()}
			break
		}
	}
	engine, err := NewWithAccess(lost, store, files, plan)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	opts := fixtureTLS(t, plan.Namespace(), now)
	credentials, err := engine.PrepareCredentials(ctx, s, opts)
	if err != nil {
		t.Fatal("real private candidate preparation: ", err)
	}
	private := &lostPrivateReadback{PrivateSecretAccess: access.PrivateSecrets()}
	secrets, err := NewSecretWorkflow(engine, private)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{adminauth.CredentialSecretName, "arcadectl-api-tls"} {
		s, err = secrets.Create(ctx, s, credentials, name, now)
		if name == adminauth.CredentialSecretName {
			if !errors.Is(err, ErrOutcomeUnknown) || s == nil || s.Document().Pending == nil {
				t.Fatal("real private lost readback not retained")
			}
			credentials, err = engine.LoadCredentials(ctx, s, now)
			if err != nil {
				t.Fatal(err)
			}
			s, err = secrets.Recover(ctx, s, credentials, now)
		}
		if err != nil {
			t.Fatal("real private effect recovery: ", err)
		}
	}
	if private.writes != 2 {
		t.Fatal("real private Create replayed")
	}
	if err := secrets.VerifyRetained(ctx, s, opts.CAFile, now); err != nil {
		t.Fatal("real retained original Secret verification: ", err)
	}
	client, err := adminauth.ParseClientCredential(credentials.admin.PrivateBytes())
	if err != nil || bytes.Contains(s.Bytes(), []byte(client.Token)) || bytes.Contains(s.Bytes(), []byte(adminauth.TokenDigest(client.Token))) || bytes.Contains(s.Bytes(), credentials.document.Key) {
		t.Fatal("private material entered public journal")
	}
	for _, r := range plan.Resources() {
		o := r.Object
		if o.GetKind() == "Namespace" {
			continue
		}
		key := installstate.Key{APIVersion: o.GetAPIVersion(), Kind: o.GetKind(), Namespace: o.GetNamespace(), Name: o.GetName()}
		s, err = engine.Apply(ctx, s, key, plan.Digest(), false)
		if key == lost.key {
			if !errors.Is(err, ErrOutcomeUnknown) || s == nil || s.Document().Pending == nil || lost.writes != 1 {
				t.Fatal("unavailable real readback not retained")
			}
			s, err = engine.Recover(ctx, s)
			if err != nil || s.Document().Pending != nil || lost.writes != 1 {
				t.Fatal("real recovery replayed create: ", err)
			}
		}
		if err != nil {
			t.Fatalf("real journaled apply %s: %v", key.String(), err)
		}
	}
	if lost.responseWrites != 1 {
		t.Fatal("lost real Create response path not exercised exactly once")
	}
	if len(s.Document().Resources) != 40 || s.Document().Pending != nil {
		t.Fatal("public/private original inventory incomplete")
	}
	// No kubelet or workload binary runs here. A manually created ReplicaSet
	// and Pod prove native API admission against the independently checked
	// signed template, not Ready, authenticated activation or a lifecycle.
	deploymentObject, err := access.Get(ctx, installstate.Key{APIVersion: "apps/v1", Kind: "Deployment", Namespace: plan.Namespace(), Name: "arcadectl-api"})
	if err != nil {
		t.Fatal(err)
	}
	var deployment appsv1.Deployment
	if decodeServing(deploymentObject, &deployment) != nil {
		t.Fatal("native Deployment decoding")
	}
	kube, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	template := deployment.Spec.Template.DeepCopy()
	const hash = "bcdfg23456"
	template.Labels[appsv1.DefaultDeploymentUniqueLabelKey] = hash
	selector := deployment.Spec.Selector.DeepCopy()
	selector.MatchLabels[appsv1.DefaultDeploymentUniqueLabelKey] = hash
	rs, err := kube.AppsV1().ReplicaSets(plan.Namespace()).Create(ctx, &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: deployment.Name + "-" + hash, Namespace: plan.Namespace(), Labels: template.Labels, OwnerReferences: fixtureOwner("apps/v1", "Deployment", deployment.Name, deployment.UID)}, Spec: appsv1.ReplicaSetSpec{Replicas: ptr.To[int32](1), Selector: selector, Template: *template}}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal("native ReplicaSet admission", err)
	}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{GenerateName: rs.Name + "-", Namespace: plan.Namespace(), Labels: rs.Spec.Template.Labels, Annotations: rs.Spec.Template.Annotations, OwnerReferences: fixtureOwner("apps/v1", "ReplicaSet", rs.Name, rs.UID)}, Spec: *rs.Spec.Template.Spec.DeepCopy()}
	pod.Spec.NodeName = "test-only-node"
	pod, err = kube.CoreV1().Pods(plan.Namespace()).Create(ctx, pod, metav1.CreateOptions{})
	if err != nil {
		t.Fatal("native Pod admission", err)
	}
	if !validServingPodTemplate(pod, rs) {
		t.Fatal("native admitted Pod differs from reviewed serving defaults")
	}
	uid := lost.key
	before, err := access.Get(ctx, uid)
	if err != nil {
		t.Fatal(err)
	}
	s, err = engine.Apply(ctx, s, uid, plan.Digest(), false)
	if err != nil {
		t.Fatal("real original-UID/RV update: ", err)
	}
	after, err := access.Get(ctx, uid)
	if err != nil || after.GetUID() != before.GetUID() || after.GetResourceVersion() == before.GetResourceVersion() {
		t.Fatal("original CAS update not proved")
	}
	if _, err := engine.Delete(ctx, s, namespaceKey(plan.Namespace())); !errors.Is(err, ErrInvalid) {
		t.Fatal("retained Namespace delete accepted")
	}
}
