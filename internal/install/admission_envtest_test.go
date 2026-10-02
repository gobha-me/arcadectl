//go:build envtest

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package install

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	arcadev1alpha1 "github.com/gobha-me/arcadectl/api/v1alpha1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/yaml"
)

const destroyAdmissionEnvtestIndex = "https://raw.githubusercontent.com/kubernetes-sigs/controller-tools/1031496fc98a4f51010c3bdfdeb57b5d67bea7bd/envtest-releases.yaml"

// Exercise the shipped CEL with a real API server and impersonated identities.
// The fixture deliberately grants all three identities the tested verbs so a
// denial proves the admission boundary rather than an unrelated RBAC failure.
func TestEnvtestDestroyAdmission(t *testing.T) {
	environment := &envtest.Environment{
		CRDDirectoryPaths:            []string{filepath.Join(repositoryRoot(t), "config", "crd", "bases")},
		ErrorIfCRDPathMissing:        true,
		DownloadBinaryAssets:         true,
		DownloadBinaryAssetsVersion:  "1.37.0",
		DownloadBinaryAssetsIndexURL: destroyAdmissionEnvtestIndex,
		BinaryAssetsDirectory:        t.TempDir(),
		ControlPlaneStartTimeout:     90 * time.Second,
		ControlPlaneStopTimeout:      30 * time.Second,
	}
	config, err := environment.Start()
	if err != nil {
		t.Fatalf("start pinned admission envtest: %v", err)
	}
	t.Cleanup(func() {
		if err := environment.Stop(); err != nil {
			t.Errorf("stop admission envtest: %v", err)
		}
	})
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, rbacv1.AddToScheme, admissionregistrationv1.AddToScheme, arcadev1alpha1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatalf("register admission scheme: %v", err)
		}
	}
	admin, err := client.New(config, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	const namespace = "arcadectl-system"
	if err := admin.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}); err != nil {
		t.Fatal(err)
	}
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{Name: "admission-fixture", Namespace: namespace},
		Rules: []rbacv1.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"persistentvolumeclaims", "pods"}, Verbs: []string{"create", "get", "update", "delete"}},
			{APIGroups: []string{"arcade.gobha.me"}, Resources: []string{"gamedestroys"}, Verbs: []string{"create", "get", "update"}},
		},
	}
	if err := admin.Create(ctx, role); err != nil {
		t.Fatal(err)
	}
	names := []string{"arcadectl-controller", "arcadectl-destroy-controller", "arcadectl-destroy-admin"}
	binding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: role.Name, Namespace: namespace},
		RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: role.Name},
	}
	identities := make([]client.Client, 0, len(names))
	for _, name := range names {
		if err := admin.Create(ctx, &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace}}); err != nil {
			t.Fatal(err)
		}
		binding.Subjects = append(binding.Subjects, rbacv1.Subject{Kind: "ServiceAccount", Name: name, Namespace: namespace})
		impersonated := rest.CopyConfig(config)
		impersonated.Impersonate = rest.ImpersonationConfig{UserName: "system:serviceaccount:" + namespace + ":" + name}
		identity, err := client.New(impersonated, client.Options{Scheme: scheme})
		if err != nil {
			t.Fatal(err)
		}
		identities = append(identities, identity)
	}
	if err := admin.Create(ctx, binding); err != nil {
		t.Fatal(err)
	}
	ordinary, destroy, unsafeAdmin := identities[0], identities[1], identities[2]
	for _, stem := range []string{"destroy-pvc", "destroy-worker", "destroy-unsafe"} {
		policy := &admissionregistrationv1.ValidatingAdmissionPolicy{}
		readDestroyAdmissionYAML(t, stem+"-admission-policy.yaml", policy)
		if err := admin.Create(ctx, policy); err != nil {
			t.Fatalf("install shipped %s policy: %v", stem, err)
		}
		policyBinding := &admissionregistrationv1.ValidatingAdmissionPolicyBinding{}
		readDestroyAdmissionYAML(t, stem+"-admission-policy-binding.yaml", policyBinding)
		if err := admin.Create(ctx, policyBinding); err != nil {
			t.Fatalf("install shipped %s binding: %v", stem, err)
		}
		// envtest has no controller-manager to populate typeChecking status.
		// Positive and negative requests below prove actual API-server CEL
		// evaluation; the Kind lifecycle checks controller-manager warnings.
		current := &admissionregistrationv1.ValidatingAdmissionPolicy{}
		if err := admin.Get(ctx, client.ObjectKeyFromObject(policy), current); err != nil {
			t.Fatal(err)
		}
		if current.Status.TypeChecking != nil && len(current.Status.TypeChecking.ExpressionWarnings) != 0 {
			t.Fatalf("shipped %s CEL warnings: %#v", stem, current.Status.TypeChecking.ExpressionWarnings)
		}
	}

	t.Run("retained PVC identity and cold marker", func(t *testing.T) {
		claim := destroyAdmissionClaim("retained-world")
		if err := ordinary.Create(ctx, claim); err != nil {
			t.Fatalf("create ordinary retained claim: %v", err)
		}
		waitDestroyAdmissionDenied(t, func() error {
			return ordinary.Delete(ctx, claim, &client.DeleteOptions{DryRun: []string{metav1.DryRunAll}})
		}, "dedicated Arcadectl destroy controller")
		forged := destroyAdmissionClaim("forged-marker")
		forged.Annotations = map[string]string{"arcade.gobha.me/cold-backup-uid": "unearned-backup"}
		assertDestroyAdmissionDenied(t, destroy.Create(ctx, forged), "New PVCs cannot claim")
		changed := claim.DeepCopy()
		changed.Annotations = map[string]string{"arcade.gobha.me/cold-backup-uid": "verified-backup"}
		assertDestroyAdmissionDenied(t, destroy.Update(ctx, changed), "ordinary Arcadectl controller")
		if err := ordinary.Update(ctx, changed); err != nil {
			t.Fatalf("ordinary controller records verified cold marker: %v", err)
		}
		cleared := changed.DeepCopy()
		cleared.Annotations = nil
		assertDestroyAdmissionDenied(t, destroy.Update(ctx, cleared), "ordinary Arcadectl controller")
		relabelled := changed.DeepCopy()
		delete(relabelled.Labels, "arcade.gobha.me/data-policy")
		assertDestroyAdmissionDenied(t, ordinary.Update(ctx, relabelled), "identity and retention labels")
		if err := destroy.Delete(ctx, changed); err != nil {
			t.Fatalf("dedicated destroy identity deletes retained PVC: %v", err)
		}
	})

	t.Run("unsafe separate administrative identity", func(t *testing.T) {
		operation := destroyAdmissionUnsafeRequest("unsafe-world")
		operation.Annotations = map[string]string{"arcade.gobha.me/unsafe-requested-by": "system:serviceaccount:arcadectl-system:arcadectl-destroy-admin"}
		waitDestroyAdmissionDenied(t, func() error {
			return ordinary.Create(ctx, operation.DeepCopy(), &client.CreateOptions{DryRun: []string{metav1.DryRunAll}})
		}, "distinct Arcadectl destroy admin identity")
		missingAudit := destroyAdmissionUnsafeRequest("missing-audit")
		assertDestroyAdmissionDenied(t, unsafeAdmin.Create(ctx, missingAudit), "audit identity annotation")
		if err := unsafeAdmin.Create(ctx, operation); err != nil {
			t.Fatalf("audited unsafe admin request: %v", err)
		}
		controllerUpdate := operation.DeepCopy()
		controllerUpdate.Finalizers = []string{"arcade.gobha.me/destroy-protection"}
		if err := destroy.Update(ctx, controllerUpdate); err != nil {
			t.Fatalf("destroy controller updates unsafe metadata without changing specification: %v", err)
		}
		operation = controllerUpdate
		forged := operation.DeepCopy()
		forged.Annotations["arcade.gobha.me/unsafe-requested-by"] = "different-admin"
		assertDestroyAdmissionDenied(t, unsafeAdmin.Update(ctx, forged), "audit identity annotation")
	})

	t.Run("authenticated API least privilege and unsafe refusal", func(t *testing.T) {
		assertAPIAdmissionAndRBAC(t, ctx, config, admin, scheme)
	})

	t.Run("worker scheduling gate", func(t *testing.T) {
		ungated := destroyAdmissionPod("ungated-worker")
		ungated.Spec.SchedulingGates = nil
		waitDestroyAdmissionDenied(t, func() error {
			return ordinary.Create(ctx, ungated.DeepCopy(), &client.CreateOptions{DryRun: []string{metav1.DryRunAll}})
		}, "exactly one execution gate")
		pod := destroyAdmissionPod("gated-worker")
		if err := ordinary.Create(ctx, pod); err != nil {
			t.Fatalf("create gated destroy worker: %v", err)
		}
		preauthorized := destroyAdmissionPod("preauthorized-worker")
		preauthorized.Annotations = map[string]string{"arcade.gobha.me/destroy-pod-authorized": "invented-uid"}
		assertDestroyAdmissionDenied(t, destroy.Create(ctx, preauthorized), "exactly one execution gate")
		unauthorized := pod.DeepCopy()
		unauthorized.Spec.SchedulingGates = nil
		assertDestroyAdmissionDenied(t, ordinary.Update(ctx, unauthorized), "dedicated Arcadectl destroy controller")
		wrongUID := pod.DeepCopy()
		wrongUID.Spec.SchedulingGates = nil
		wrongUID.Annotations = map[string]string{"arcade.gobha.me/destroy-pod-authorized": "other-pod"}
		assertDestroyAdmissionDenied(t, destroy.Update(ctx, wrongUID), "dedicated Arcadectl destroy controller")
		approved := pod.DeepCopy()
		approved.Spec.SchedulingGates = nil
		approved.Annotations = map[string]string{"arcade.gobha.me/destroy-pod-authorized": string(pod.UID)}
		changedImage := approved.DeepCopy()
		changedImage.Spec.Containers[0].Image = "registry.example/foreign:test"
		assertDestroyAdmissionDenied(t, destroy.Update(ctx, changedImage), "executable fields are immutable")
		if err := destroy.Update(ctx, approved); err != nil {
			t.Fatalf("dedicated destroy controller authorizes exact Pod UID: %v", err)
		}
	})
}

func readDestroyAdmissionYAML(t *testing.T, filename string, destination any) {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join(repositoryRoot(t), "config", "install", filename))
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.UnmarshalStrict(contents, destination); err != nil {
		t.Fatalf("decode shipped %s: %v", filename, err)
	}
}

func destroyAdmissionClaim(name string) *corev1.PersistentVolumeClaim {
	return &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "arcadectl-system", Labels: map[string]string{
			"app.kubernetes.io/managed-by": "arcadectl", "app.kubernetes.io/instance": "factory",
			"arcade.gobha.me/data-identity": "original-world", "arcade.gobha.me/data-policy": "retain", "arcade.gobha.me/data-path": "world",
		}},
		Spec: corev1.PersistentVolumeClaimSpec{AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce}, Resources: corev1.VolumeResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("1Gi")}}},
	}
}

func destroyAdmissionUnsafeRequest(name string) *arcadev1alpha1.GameDestroy {
	return &arcadev1alpha1.GameDestroy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "arcadectl-system"},
		Spec: arcadev1alpha1.GameDestroySpec{
			Mode: arcadev1alpha1.DestroyModeUnsafeNoBackup, UnsafeReason: "Explicit isolated admission test",
			Target: arcadev1alpha1.GameDestroyTarget{
				GameServer: arcadev1alpha1.ExactLocalReference{Name: "factory", UID: "original-server-uid"}, Game: "factorio",
				Data: arcadev1alpha1.RetainedDataReference{Identity: "original-world", Claims: []arcadev1alpha1.RetainedDataClaimReference{{Path: "world", ClaimRef: arcadev1alpha1.ExactLocalReference{Name: "world-claim", UID: "original-claim-uid"}}}},
			},
		},
	}
}

func destroyAdmissionPod(name string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: "arcadectl-system",
			Labels:          map[string]string{"app.kubernetes.io/managed-by": "arcadectl", "app.kubernetes.io/name": "destroy-worker"},
			OwnerReferences: []metav1.OwnerReference{{APIVersion: "batch/v1", Kind: "Job", Name: "destroy-fixture", UID: "fixture-job-uid"}},
		},
		Spec: corev1.PodSpec{ServiceAccountName: "destroy-fixture", RestartPolicy: corev1.RestartPolicyNever, Containers: []corev1.Container{{Name: "verify", Image: "registry.example/worker:test"}}, SchedulingGates: []corev1.PodSchedulingGate{{Name: "arcade.gobha.me/destroy-authorized"}}},
	}
}

func assertDestroyAdmissionDenied(t *testing.T, err error, message string) {
	t.Helper()
	if !isDestroyAdmissionDenied(err, message) {
		t.Fatalf("expected admission denial containing %q, got %v", message, err)
	}
}

func waitDestroyAdmissionDenied(t *testing.T, action func() error, message string) {
	t.Helper()
	waitDestroyAdmission(t, func() (bool, error) {
		err := action()
		if err == nil {
			return false, nil
		}
		if isDestroyAdmissionDenied(err, message) {
			return true, nil
		}
		return false, err
	})
}

func isDestroyAdmissionDenied(err error, message string) bool {
	// CEL validations default to the Invalid reason (422); RBAC uses
	// Forbidden (403). Require the policy-specific denial text as well.
	return err != nil && (apierrors.IsForbidden(err) || apierrors.IsInvalid(err)) &&
		strings.Contains(err.Error(), "ValidatingAdmissionPolicy") &&
		strings.Contains(err.Error(), "denied request") && strings.Contains(err.Error(), message)
}

func waitDestroyAdmission(t *testing.T, predicate func() (bool, error)) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		ready, err := predicate()
		if err != nil {
			t.Fatalf("wait for admission readiness: %v", err)
		}
		if ready {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("timed out waiting for API-server admission readiness")
}
