//go:build envtest

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/adminauth"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	authv1 "k8s.io/api/authorization/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

// Real isolated API servers certify the declared version/discovery/SSAR wire
// contract, fresh pre-namespace proof and durable-candidate resume. They do not
// provide a kubelet, image/storage/network proof or full binary lifecycle.
func TestEnvtestClusterPrerequisitesDeclaredProfiles(t *testing.T) {
	for _, profile := range []string{installrender.Profile135, installrender.Profile137} {
		t.Run(profile, func(t *testing.T) {
			plan := fixturePlanProfile(t, "isolated-install", profile)
			environment := &envtest.Environment{
				UseExistingCluster:   new(bool), // never attach to a caller's cluster
				DownloadBinaryAssets: true, DownloadBinaryAssetsVersion: plan.Profile().KubernetesVersion,
				DownloadBinaryAssetsIndexURL: "https://raw.githubusercontent.com/kubernetes-sigs/controller-tools/1031496fc98a4f51010c3bdfdeb57b5d67bea7bd/envtest-releases.yaml",
				BinaryAssetsDirectory:        t.TempDir(), ControlPlaneStartTimeout: 90 * time.Second, ControlPlaneStopTimeout: 30 * time.Second,
			}
			if profile == installrender.Profile135 {
				prerequisite135Assets(t, environment)
			}
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
			access, err := NewHTTPAccess(config)
			if err != nil {
				t.Fatal(err)
			}
			if err := access.checkVersion(ctx, plan.Profile()); err != nil {
				t.Fatal("actual exact version proof: ", err)
			}
			core, err := access.discover(ctx, "v1")
			if err != nil {
				t.Fatal("actual core discovery: ", err)
			}
			forward := proofPermission{spec: authv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authv1.ResourceAttributes{Version: "v1", Resource: "pods", Subresource: "portforward", Namespace: plan.Namespace(), Verb: "create"}}, kind: "PodPortForwardOptions"}
			if !discoveredPermission(core, forward) {
				for _, resource := range core.APIResources {
					if resource.Name == "pods/portforward" {
						t.Fatalf("actual portforward discovery mismatch: kind=%s scope=%t verbs=%v group=%s version=%s", resource.Kind, resource.Namespaced, resource.Verbs, resource.Group, resource.Version)
					}
				}
				t.Fatal("actual discovery missing reviewed portforward capability")
			}
			if err := access.authorize(ctx, forward.spec); err != nil {
				t.Fatal("actual authorization wire contract: ", err)
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
			store, err := installstate.New(access.Namespaces(), plan)
			if err != nil {
				t.Fatal(err)
			}
			engine, err := NewWithAccess(access, store, files, plan)
			if err != nil {
				t.Fatal(err)
			}
			proof, err := NewClusterPrerequisites(engine, access)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			tls := fixtureTLS(t, plan.Namespace(), now)
			opts := LifecycleOptions{Now: now, Credentials: tls, Activation: ActivationOptions{CAFile: tls.CAFile}}
			// Grant every derived fresh-install permission EXCEPT namespace
			// CREATE. Actual RBAC must refuse bootstrap before any namespace
			// effect; an all-powerful fixture cannot establish this invariant.
			fresh := installstate.Document{Namespace: plan.Namespace(), ProfileID: profile, Mode: installstate.Install, TargetPackage: plan.Digest(), Stage: installstate.Preparing}
			permissions, err := proof.documentPermissions(fresh, installstate.Install, plan)
			if err != nil {
				t.Fatal(err)
			}
			role := &rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "prerequisite-without-namespace-create"}}
			for _, permission := range permissions {
				if attrs := permission.spec.ResourceAttributes; attrs != nil {
					resource := attrs.Resource
					if attrs.Subresource != "" {
						resource += "/" + attrs.Subresource
					}
					rule := rbacv1.PolicyRule{APIGroups: []string{attrs.Group}, Resources: []string{resource}, Verbs: []string{attrs.Verb}}
					if attrs.Name != "" {
						rule.ResourceNames = []string{attrs.Name}
					}
					role.Rules = append(role.Rules, rule)
				} else {
					attrs := permission.spec.NonResourceAttributes
					role.Rules = append(role.Rules, rbacv1.PolicyRule{NonResourceURLs: []string{attrs.Path}, Verbs: []string{attrs.Verb}})
				}
			}
			admin, err := kubernetes.NewForConfig(config)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := admin.RbacV1().ClusterRoles().Create(ctx, role, metav1.CreateOptions{}); err != nil {
				t.Fatal(err)
			}
			if _, err := admin.RbacV1().ClusterRoleBindings().Create(ctx, &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: role.Name}, RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: role.Name}, Subjects: []rbacv1.Subject{{APIGroup: rbacv1.GroupName, Kind: "User", Name: "bootstrap-without-create"}}}, metav1.CreateOptions{}); err != nil {
				t.Fatal(err)
			}
			user, err := environment.AddUser(envtest.User{Name: "bootstrap-without-create"}, config)
			if err != nil {
				t.Fatal(err)
			}
			limitedAccess, err := NewHTTPAccess(user.Config())
			if err != nil {
				t.Fatal(err)
			}
			limitedStore, err := installstate.New(limitedAccess.Namespaces(), plan)
			if err != nil {
				t.Fatal(err)
			}
			limitedEngine, err := NewWithAccess(limitedAccess, limitedStore, files, plan)
			if err != nil {
				t.Fatal(err)
			}
			limitedProof, err := NewClusterPrerequisites(limitedEngine, limitedAccess)
			if err != nil {
				t.Fatal(err)
			}
			update, _ := publicPermission(namespaceKey(plan.Namespace()), "update")
			if err := wait.PollUntilContextTimeout(ctx, 100*time.Millisecond, 10*time.Second, true, func(ctx context.Context) (bool, error) {
				return limitedAccess.authorize(ctx, update.spec) == nil, nil
			}); err != nil {
				t.Fatal("actual reviewed RBAC grants not established")
			}
			create, _ := publicPermission(namespaceKey(plan.Namespace()), "create")
			if err := limitedAccess.authorize(ctx, create.spec); err == nil {
				t.Fatal("restricted identity received namespace CREATE")
			}
			if err := limitedProof.VerifyBootstrap(ctx, plan, opts); err == nil {
				t.Fatal("bootstrap omitted namespace CREATE authorization")
			}
			if _, err := access.Get(ctx, namespaceKey(plan.Namespace())); !apierrors.IsNotFound(err) {
				t.Fatal("denied bootstrap changed namespace state")
			}
			if err := proof.VerifyBootstrap(ctx, plan, opts); err != nil {
				t.Fatal("actual pre-namespace proof: ", err)
			}
			receipt, err := installstate.PrepareBootstrap(files, "bootstrap.json", plan)
			if err != nil {
				t.Fatal(err)
			}
			s, err := receipt.EnsureNamespace(ctx, access.Namespaces())
			if err != nil {
				t.Fatal(err)
			}
			s, err = store.Load(ctx, s.Anchor())
			if err != nil {
				t.Fatal(err)
			}
			request := LifecycleCheck{Checkpoint: Prerequisites, Snapshot: s, Mode: installstate.Install, Target: plan, Options: opts}
			if err := proof.Verify(ctx, request); err != nil {
				t.Fatal("fresh bound proof before custom CRDs exist: ", err)
			}
			if err := proof.VerifyBootstrap(ctx, plan, opts); err == nil {
				t.Fatal("bootstrap adopted existing namespace")
			}
			d := s.Document()
			d.Stage, d.Revision = installstate.Applying, d.Revision+1
			s, err = store.Commit(ctx, s, d)
			if err != nil {
				t.Fatal(err)
			}
			candidate, err := engine.PrepareCredentials(ctx, s, tls)
			if err != nil {
				t.Fatal("durable candidate: ", err)
			}
			// Only these task-owned fixture source files are removed. Durable
			// private evidence, not re-reading issuance inputs, drives resume.
			for _, path := range []string{tls.CertificateFile, tls.KeyFile} {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			}
			request.Snapshot = s
			if err := proof.Verify(ctx, request); err != nil {
				t.Fatal("candidate-backed resume reopened source files: ", err)
			}
			otherTLS := fixtureTLS(t, plan.Namespace(), now)
			request.Options.Activation.CAFile = otherTLS.CAFile
			if err := proof.Verify(ctx, request); err == nil {
				t.Fatal("candidate CA mismatch accepted")
			}
			request.Options = opts
			workflow, err := NewSecretWorkflow(engine, access.PrivateSecrets())
			if err != nil {
				t.Fatal(err)
			}
			s, err = workflow.Create(ctx, s, candidate, adminauth.CredentialSecretName, now)
			if err != nil {
				t.Fatal(err)
			}
			request.Snapshot = s
			if err := proof.Verify(ctx, request); err != nil {
				t.Fatal("original candidate failed after first Secret: ", err)
			}
			// Valid source inputs cannot bless losing a candidate already used
			// by an inventoried Secret, nor authorize token regeneration.
			for path, body := range map[string][]byte{tls.CertificateFile: candidate.document.Certificate, tls.KeyFile: candidate.document.Key} {
				if err := os.WriteFile(path, body, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Remove(filepath.Join(base, credentialName(s.Anchor()))); err != nil {
				t.Fatal(err)
			}
			if err := proof.Verify(ctx, request); err == nil {
				t.Fatal("used missing candidate was replaceable from fresh issuance inputs")
			}
			unchanged, err := store.Load(ctx, s.Anchor())
			if err != nil || unchanged.ResourceVersion() != s.ResourceVersion() {
				t.Fatal("refused missing candidate changed the journal")
			}
		})
	}
}
