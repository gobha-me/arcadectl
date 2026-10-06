//go:build envtest

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installrender"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

// This certifies the private transport's six paired CREATE probes against both
// exact profiles with native ServiceAccount admission enabled. It is not a
// complete lifecycle proof: envtest has no kubelet or VAP status controller,
// and CREATE does not establish UPDATE, subresource or PVC DELETE behavior.
func TestEnvtestNativeAdmissionProbeDeclaredProfiles(t *testing.T) {
	for _, profile := range []string{installrender.Profile135, installrender.Profile137} {
		t.Run(profile, func(t *testing.T) {
			plan := fixturePlanProfile(t, "isolated-install", profile)
			crds, err := filepath.Abs("../../config/crd/bases")
			if err != nil {
				t.Fatal(err)
			}
			environment := &envtest.Environment{UseExistingCluster: new(bool), CRDDirectoryPaths: []string{crds}, ErrorIfCRDPathMissing: true, DownloadBinaryAssets: true, DownloadBinaryAssetsVersion: plan.Profile().KubernetesVersion, DownloadBinaryAssetsIndexURL: "https://raw.githubusercontent.com/kubernetes-sigs/controller-tools/1031496fc98a4f51010c3bdfdeb57b5d67bea7bd/envtest-releases.yaml", BinaryAssetsDirectory: t.TempDir(), ControlPlaneStartTimeout: 90 * time.Second, ControlPlaneStopTimeout: 30 * time.Second}
			if profile == installrender.Profile135 {
				prerequisite135Assets(t, environment)
			} else {
				environment.ControlPlane.APIServer = &envtest.APIServer{}
			}
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
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			access, err := NewHTTPAccess(config)
			if err != nil {
				t.Fatal(err)
			}
			if err := access.checkVersion(ctx, plan.Profile()); err != nil {
				t.Fatal(err)
			}
			admin, err := kubernetes.NewForConfig(config)
			if err != nil {
				t.Fatal(err)
			}
			custom, err := dynamic.NewForConfig(config)
			if err != nil {
				t.Fatal(err)
			}
			policies := map[string]*admissionv1.ValidatingAdmissionPolicy{}
			bindings := map[string]string{}
			for _, resource := range plan.Resources() {
				object := resource.Object
				switch object.GetKind() {
				case "Namespace":
					var ns corev1.Namespace
					if decodeServing(object, &ns) != nil {
						t.Fatal("signed namespace decode")
					}
					if _, err := admin.CoreV1().Namespaces().Create(ctx, &ns, metav1.CreateOptions{}); err != nil {
						t.Fatal(err)
					}
				case "ServiceAccount", "ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding":
					if _, err := access.Create(ctx, resourceKey(resource), object, false); err != nil {
						t.Fatal("signed fixture dependency: ", err)
					}
					if object.GetKind() == "ValidatingAdmissionPolicy" {
						var policy admissionv1.ValidatingAdmissionPolicy
						if decodeServing(object, &policy) != nil {
							t.Fatal("signed policy decode")
						}
						policies[policy.Name] = &policy
					} else if object.GetKind() == "ValidatingAdmissionPolicyBinding" {
						var binding admissionv1.ValidatingAdmissionPolicyBinding
						if decodeServing(object, &binding) != nil {
							t.Fatal("signed binding decode")
						}
						bindings[binding.Spec.PolicyName] = binding.Name
					}
				}
			}
			if len(policies) != 6 || len(bindings) != 6 {
				t.Fatal("not the full signed admission set")
			}
			for name, policy := range policies {
				positive, negative, index, err := admissionCreateProbe(plan, name, "arcadectl-controller", "arcadectl-probe-0123456789abcdef0123456789abcdef")
				if err != nil {
					t.Fatal(err)
				}
				message := policy.Spec.Validations[index].Message
				if err := wait.PollUntilContextTimeout(ctx, 100*time.Millisecond, 15*time.Second, true, func(ctx context.Context) (bool, error) {
					_, err := access.probeCreate(ctx, negative, name, bindings[name], message)
					return err == nil, nil
				}); err != nil {
					// Public-only fixtures in this owned API server: a typed native
					// error diagnoses recipe disagreement without changing the
					// production transport's raw-error redaction contract.
					gvr := schema.GroupVersionResource{Version: "v1", Resource: "pods"}
					if negative.GetKind() == "PersistentVolumeClaim" {
						gvr.Resource = "persistentvolumeclaims"
					}
					if negative.GetKind() == "GameDestroy" {
						gvr = schema.GroupVersionResource{Group: "arcade.gobha.me", Version: "v1alpha1", Resource: "gamedestroys"}
					}
					_, nativeErr := custom.Resource(gvr).Namespace(plan.Namespace()).Create(ctx, negative, metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}, FieldManager: "arcadectl-installer", FieldValidation: "Strict"})
					t.Fatalf("owned public probe native denial mismatch for %s: %v", name, nativeErr)
				}
				start := time.Now().UTC()
				result, err := access.probeCreate(ctx, positive, "", "", "")
				if err != nil {
					t.Fatalf("native positive probe refused for %s: %v", name, err)
				}
				if !validAdmissionProbeResult(positive, result, start, time.Now().UTC()) {
					// Only public fixture shape, never credentials/private errors.
					encoded, _ := json.Marshal(result.Object)
					t.Fatalf("owned native positive shape mismatch %s: %s", name, encoded)
				}
			}
			pods, err := admin.CoreV1().Pods(plan.Namespace()).List(ctx, metav1.ListOptions{})
			if err != nil || len(pods.Items) != 0 {
				t.Fatal("Pod probe persisted")
			}
			claims, err := admin.CoreV1().PersistentVolumeClaims(plan.Namespace()).List(ctx, metav1.ListOptions{})
			if err != nil || len(claims.Items) != 0 {
				t.Fatal("PVC probe persisted")
			}
			destroys, err := custom.Resource(schema.GroupVersionResource{Group: "arcade.gobha.me", Version: "v1alpha1", Resource: "gamedestroys"}).Namespace(plan.Namespace()).List(ctx, metav1.ListOptions{})
			if err != nil || len(destroys.Items) != 0 {
				t.Fatal("GameDestroy probe persisted")
			}
		})
	}
}
