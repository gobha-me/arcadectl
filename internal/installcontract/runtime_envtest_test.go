//go:build envtest

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installcontract

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

const contractEnvtestIndex = "https://raw.githubusercontent.com/kubernetes-sigs/controller-tools/1031496fc98a4f51010c3bdfdeb57b5d67bea7bd/envtest-releases.yaml"

// This isolated API-server gate proves real defaults, dry-run admission and
// original-UID/RV updates for the signed public resources. No Pods run here;
// this is not the required full package install/upgrade/rollback lifecycle gate.
func TestEnvtestSignedContractRoundTrip(t *testing.T) {
	environment := &envtest.Environment{DownloadBinaryAssets: true, DownloadBinaryAssetsVersion: "1.37.0", DownloadBinaryAssetsIndexURL: contractEnvtestIndex, BinaryAssetsDirectory: t.TempDir(), ControlPlaneStartTimeout: 90 * time.Second, ControlPlaneStopTimeout: 30 * time.Second}
	config, err := environment.Start()
	if err != nil {
		t.Fatalf("start pinned contract environment: %v", err)
	}
	t.Cleanup(func() {
		if err := environment.Stop(); err != nil {
			t.Errorf("stop contract environment: %v", err)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	client, err := dynamic.NewForConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	core, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	c := testContractVariant(t, false, installrender.DefaultNamespace, installrender.Profile137, "c", "d")
	base := t.TempDir()
	if err := os.Chmod(base, 0700); err != nil {
		t.Fatal(err)
	}
	files, err := privatefs.Open(base, false)
	if err != nil {
		t.Fatal(err)
	}
	defer files.Close()
	receipt, err := installstate.PrepareBootstrap(files, "bootstrap.json", c.plan)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := receipt.EnsureNamespace(ctx, core.CoreV1().Namespaces())
	if err != nil {
		t.Fatal(err)
	}
	nsTemplate := mustTemplate(t, c, "Namespace", "", false)
	ns, err := client.Resource(schema.GroupVersionResource{Version: "v1", Resource: "namespaces"}).Get(ctx, c.plan.Namespace(), metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := nsTemplate.MatchNamespace(ns, journal); err != nil {
		t.Fatal("real Namespace defaults/journal contract: ", err)
	}
	names := map[string]string{"ServiceAccount": "serviceaccounts", "Service": "services", "Deployment": "deployments", "Role": "roles", "RoleBinding": "rolebindings", "ClusterRole": "clusterroles", "ClusterRoleBinding": "clusterrolebindings", "CustomResourceDefinition": "customresourcedefinitions", "ValidatingAdmissionPolicy": "validatingadmissionpolicies", "ValidatingAdmissionPolicyBinding": "validatingadmissionpolicybindings"}
	created := 1
	for _, resource := range c.plan.Resources() {
		o := resource.Object
		if o.GetKind() == "Namespace" {
			continue
		}
		key := installstate.Key{APIVersion: o.GetAPIVersion(), Kind: o.GetKind(), Namespace: o.GetNamespace(), Name: o.GetName()}
		template, err := c.Template(key, false)
		if err != nil {
			t.Fatal(err)
		}
		gv, _ := schema.ParseGroupVersion(key.APIVersion)
		var ri dynamic.ResourceInterface = client.Resource(gv.WithResource(names[key.Kind]))
		if key.Namespace != "" {
			ri = client.Resource(gv.WithResource(names[key.Kind])).Namespace(key.Namespace)
		}
		candidate, err := template.Candidate(strings.Repeat("a", 32))
		if err != nil {
			t.Fatal(err)
		}
		dry, err := ri.Create(ctx, candidate, metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}, FieldValidation: metav1.FieldValidationStrict})
		if err != nil {
			t.Fatalf("dry create %s: %v", key.String(), err)
		}
		if err := template.MatchAdmitted(dry); err != nil {
			t.Fatalf("real dry create defaults %s: %v", key.String(), err)
		}
		live, err := ri.Create(ctx, candidate, metav1.CreateOptions{FieldValidation: metav1.FieldValidationStrict})
		if err != nil {
			t.Fatalf("create %s: %v", key.String(), err)
		}
		originalUID := live.GetUID()
		if err := template.MatchLive(live, originalUID); err != nil {
			t.Fatalf("real create defaults %s: %v", key.String(), err)
		}
		if key.Kind == "CustomResourceDefinition" {
			for deadline := time.Now().Add(20 * time.Second); ; {
				live, err = ri.Get(ctx, key.Name, metav1.GetOptions{})
				if err != nil {
					t.Fatal(err)
				}
				if template.CheckCRD(live, originalUID, template) == nil {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("real CRD did not establish a safe storage contract")
				}
				select {
				case <-ctx.Done():
					t.Fatal("contract fixture timed out")
				case <-time.After(100 * time.Millisecond):
				}
			}
		}
		update, err := template.UpdateCandidate(template, live, originalUID, strings.Repeat("b", 32))
		if err != nil {
			t.Fatal(err)
		}
		dry, err = ri.Update(ctx, update, metav1.UpdateOptions{DryRun: []string{metav1.DryRunAll}, FieldValidation: metav1.FieldValidationStrict})
		if err != nil {
			t.Fatalf("dry update %s: %v", key.String(), err)
		}
		if err := template.MatchLive(dry, originalUID); err != nil {
			t.Fatalf("real dry update defaults %s: %v", key.String(), err)
		}
		live, err = ri.Update(ctx, update, metav1.UpdateOptions{FieldValidation: metav1.FieldValidationStrict})
		if err != nil {
			t.Fatalf("update %s: %v", key.String(), err)
		}
		if err := template.MatchLive(live, originalUID); err != nil {
			t.Fatalf("real update defaults %s: %v", key.String(), err)
		}
		// GET once more: actual storage readback is independent of dry-run.
		live, err = ri.Get(ctx, key.Name, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if err := template.MatchLive(live, originalUID); err != nil {
			t.Fatal(err)
		}
		created++
	}
	if created != 38 {
		t.Fatal("incomplete real default round trip")
	}
}
