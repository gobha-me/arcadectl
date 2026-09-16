// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"strings"
	"testing"
	"time"

	arcadev1alpha1 "github.com/gobha-me/arcadectl/api/v1alpha1"
	"github.com/gobha-me/arcadectl/internal/catalog"
	platformkube "github.com/gobha-me/arcadectl/internal/platform/kube"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

const controllerTestDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestReconcileRunningThenStoppedRetainsData(t *testing.T) {
	t.Parallel()

	server := controllerTestServer(arcadev1alpha1.DesiredStateRunning)
	reconciler, kubeClient := newTestReconciler(t, server)
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(server)}

	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("first Reconcile() error = %v", err)
	}
	assertObjectExists(t, kubeClient, types.NamespacedName{Namespace: "games", Name: "factory-factorio-world"}, &corev1.PersistentVolumeClaim{})
	deployment := &appsv1.Deployment{}
	assertObjectExists(t, kubeClient, request.NamespacedName, deployment)
	service := &corev1.Service{}
	assertObjectExists(t, kubeClient, request.NamespacedName, service)
	assertControlledBy(t, deployment, server.UID)
	assertControlledBy(t, service, server.UID)

	claim := &corev1.PersistentVolumeClaim{}
	if err := kubeClient.Get(context.Background(), types.NamespacedName{Namespace: "games", Name: "factory-factorio-world"}, claim); err != nil {
		t.Fatalf("get retained claim: %v", err)
	}
	if len(claim.OwnerReferences) != 0 {
		t.Fatalf("retained claim owner references = %#v, want none", claim.OwnerReferences)
	}

	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("idempotent Reconcile() error = %v", err)
	}
	assertListLength(t, kubeClient, &corev1.PersistentVolumeClaimList{}, 1)
	assertListLength(t, kubeClient, &appsv1.DeploymentList{}, 1)
	assertListLength(t, kubeClient, &corev1.ServiceList{}, 1)

	stored := &arcadev1alpha1.GameServer{}
	if err := kubeClient.Get(context.Background(), request.NamespacedName, stored); err != nil {
		t.Fatalf("get GameServer: %v", err)
	}
	stored.Spec.DesiredState = arcadev1alpha1.DesiredStateStopped
	stored.Generation = 2
	if err := kubeClient.Update(context.Background(), stored); err != nil {
		t.Fatalf("stop GameServer: %v", err)
	}
	result, err := reconciler.Reconcile(context.Background(), request)
	if err != nil {
		t.Fatalf("stop Reconcile() error = %v", err)
	}
	if result.RequeueAfter <= 0 {
		t.Fatal("stopping reconciliation did not schedule observation of completed deletion")
	}
	assertNotFound(t, kubeClient, request.NamespacedName, &appsv1.Deployment{})
	assertNotFound(t, kubeClient, request.NamespacedName, &corev1.Service{})
	assertObjectExists(t, kubeClient, types.NamespacedName{Namespace: "games", Name: "factory-factorio-world"}, &corev1.PersistentVolumeClaim{})
	assertPhase(t, kubeClient, request.NamespacedName, arcadev1alpha1.PhaseStopping, metav1.ConditionFalse, "RuntimeStopping")
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("stopped Reconcile() error = %v", err)
	}

	if err := kubeClient.Get(context.Background(), request.NamespacedName, stored); err != nil {
		t.Fatalf("get stopped GameServer: %v", err)
	}
	if stored.Status.Phase != arcadev1alpha1.PhaseStopped || stored.Status.ObservedGeneration != stored.Generation {
		t.Fatalf("stopped status = %#v", stored.Status)
	}
}

func TestReconcileReportsReadyOnlyAfterObservedRuntime(t *testing.T) {
	t.Parallel()

	server := controllerTestServer(arcadev1alpha1.DesiredStateRunning)
	reconciler, kubeClient := newTestReconciler(t, server)
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(server)}
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("first Reconcile() error = %v", err)
	}
	assertPhase(t, kubeClient, request.NamespacedName, arcadev1alpha1.PhaseStarting, metav1.ConditionFalse, "RuntimePending")

	deployment := &appsv1.Deployment{}
	if err := kubeClient.Get(context.Background(), request.NamespacedName, deployment); err != nil {
		t.Fatalf("get Deployment: %v", err)
	}
	deployment.Status.ObservedGeneration = deployment.Generation
	deployment.Status.AvailableReplicas = 1
	deployment.Status.UpdatedReplicas = 1
	if err := kubeClient.Status().Update(context.Background(), deployment); err != nil {
		t.Fatalf("update Deployment status: %v", err)
	}
	service := &corev1.Service{}
	if err := kubeClient.Get(context.Background(), request.NamespacedName, service); err != nil {
		t.Fatalf("get Service: %v", err)
	}
	service.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "192.0.2.10"}}
	if err := kubeClient.Status().Update(context.Background(), service); err != nil {
		t.Fatalf("update Service status: %v", err)
	}

	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("ready Reconcile() error = %v", err)
	}
	assertPhase(t, kubeClient, request.NamespacedName, arcadev1alpha1.PhaseReady, metav1.ConditionTrue, "RuntimeReady")
	stored := &arcadev1alpha1.GameServer{}
	if err := kubeClient.Get(context.Background(), request.NamespacedName, stored); err != nil {
		t.Fatalf("get ready GameServer: %v", err)
	}
	if len(stored.Status.Endpoints) != 1 || stored.Status.Endpoints[0].Address != "192.0.2.10" || stored.Status.Endpoints[0].Name != "game" {
		t.Fatalf("observed endpoints = %#v", stored.Status.Endpoints)
	}
}

func TestReconcileRejectsInvalidSpecBeforeMutation(t *testing.T) {
	t.Parallel()

	server := controllerTestServer(arcadev1alpha1.DesiredStateRunning)
	server.Spec.Settings.Raw = []byte(`{"maxPlayers":0}`)
	reconciler, kubeClient := newTestReconciler(t, server)
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(server)}
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("Reconcile() error = %v, want status-only invalid spec", err)
	}
	assertListLength(t, kubeClient, &corev1.PersistentVolumeClaimList{}, 0)
	assertListLength(t, kubeClient, &appsv1.DeploymentList{}, 0)
	assertListLength(t, kubeClient, &corev1.ServiceList{}, 0)
	assertPhase(t, kubeClient, request.NamespacedName, arcadev1alpha1.PhaseFailed, metav1.ConditionFalse, "InvalidSpec")
}

func TestReconcilePreflightRejectsForeignRuntimeBeforeMutation(t *testing.T) {
	t.Parallel()

	server := controllerTestServer(arcadev1alpha1.DesiredStateRunning)
	foreign := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: server.Name, Namespace: server.Namespace}}
	reconciler, kubeClient := newTestReconciler(t, server, foreign)
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(server)}
	_, err := reconciler.Reconcile(context.Background(), request)
	if err == nil || !strings.Contains(err.Error(), "existing resource has no controller owner") {
		t.Fatalf("Reconcile() error = %v, want foreign-resource refusal", err)
	}
	assertListLength(t, kubeClient, &corev1.PersistentVolumeClaimList{}, 0)
	assertObjectExists(t, kubeClient, request.NamespacedName, &appsv1.Deployment{})
	assertListLength(t, kubeClient, &corev1.ServiceList{}, 0)
	assertPhase(t, kubeClient, request.NamespacedName, arcadev1alpha1.PhaseFailed, metav1.ConditionFalse, "ReconcileFailed")
}

func TestReconcileRejectsOwnedDataClaim(t *testing.T) {
	t.Parallel()

	server := controllerTestServer(arcadev1alpha1.DesiredStateRunning)
	claim := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "factory-factorio-world",
			Namespace: "games",
			Labels: map[string]string{
				platformkube.LabelManagedBy:  platformkube.ManagerName,
				platformkube.LabelName:       "game-data",
				platformkube.LabelInstance:   "factory",
				platformkube.LabelGame:       "factorio",
				platformkube.LabelDataPolicy: "retain",
				platformkube.LabelDataPath:   "world",
			},
			OwnerReferences: []metav1.OwnerReference{{Name: "unsafe-owner", UID: "unsafe"}},
		},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			Resources: corev1.VolumeResourceRequirements{Requests: corev1.ResourceList{
				corev1.ResourceStorage: resource.MustParse("10Gi"),
			}},
		},
	}
	reconciler, kubeClient := newTestReconciler(t, server, claim)
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(server)}
	_, err := reconciler.Reconcile(context.Background(), request)
	if err == nil || !strings.Contains(err.Error(), "must not have owner references") {
		t.Fatalf("Reconcile() error = %v, want unsafe claim refusal", err)
	}
	assertListLength(t, kubeClient, &appsv1.DeploymentList{}, 0)
	assertListLength(t, kubeClient, &corev1.ServiceList{}, 0)
	stored := &corev1.PersistentVolumeClaim{}
	assertObjectExists(t, kubeClient, client.ObjectKeyFromObject(claim), stored)
	if len(stored.OwnerReferences) != 1 {
		t.Fatal("reconciler mutated foreign claim ownership")
	}
}

func TestReconcileExpandsButNeverShrinksRetainedData(t *testing.T) {
	t.Parallel()

	server := controllerTestServer(arcadev1alpha1.DesiredStateStopped)
	reconciler, kubeClient := newTestReconciler(t, server)
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(server)}
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("initial Reconcile() error = %v", err)
	}

	stored := &arcadev1alpha1.GameServer{}
	if err := kubeClient.Get(context.Background(), request.NamespacedName, stored); err != nil {
		t.Fatalf("get GameServer: %v", err)
	}
	stored.Spec.Storage.Size = resource.MustParse("20Gi")
	if err := kubeClient.Update(context.Background(), stored); err != nil {
		t.Fatalf("request expansion: %v", err)
	}
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("expansion Reconcile() error = %v", err)
	}
	claimKey := types.NamespacedName{Namespace: "games", Name: "factory-factorio-world"}
	claim := &corev1.PersistentVolumeClaim{}
	if err := kubeClient.Get(context.Background(), claimKey, claim); err != nil {
		t.Fatalf("get expanded claim: %v", err)
	}
	if got := claim.Spec.Resources.Requests[corev1.ResourceStorage]; got.Cmp(resource.MustParse("20Gi")) != 0 {
		t.Fatalf("expanded storage = %s, want 20Gi", got.String())
	}

	if err := kubeClient.Get(context.Background(), request.NamespacedName, stored); err != nil {
		t.Fatalf("get expanded GameServer: %v", err)
	}
	stored.Spec.Storage.Size = resource.MustParse("5Gi")
	if err := kubeClient.Update(context.Background(), stored); err != nil {
		t.Fatalf("request smaller size: %v", err)
	}
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("non-shrinking Reconcile() error = %v", err)
	}
	if err := kubeClient.Get(context.Background(), claimKey, claim); err != nil {
		t.Fatalf("get retained larger claim: %v", err)
	}
	if got := claim.Spec.Resources.Requests[corev1.ResourceStorage]; got.Cmp(resource.MustParse("20Gi")) != 0 {
		t.Fatalf("storage after smaller request = %s, want retained 20Gi", got.String())
	}
}

func newTestReconciler(t *testing.T, objects ...client.Object) (*GameServerReconciler, client.Client) {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("add core scheme: %v", err)
	}
	if err := appsv1.AddToScheme(scheme); err != nil {
		t.Fatalf("add apps scheme: %v", err)
	}
	if err := arcadev1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("add Arcadectl scheme: %v", err)
	}
	gameCatalog, err := catalog.Builtins()
	if err != nil {
		t.Fatalf("build game catalog: %v", err)
	}
	kubeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&arcadev1alpha1.GameServer{}, &appsv1.Deployment{}, &corev1.Service{}).
		WithInterceptorFuncs(interceptor.Funcs{Patch: applyPatchAsUpdate}).
		WithObjects(objects...).
		Build()
	reconciler := &GameServerReconciler{
		Client:  kubeClient,
		Scheme:  scheme,
		Catalog: gameCatalog,
		Now: func() metav1.Time {
			return metav1.NewTime(time.Unix(1_700_000_000, 0))
		},
	}
	return reconciler, kubeClient
}

// applyPatchAsUpdate supplies the fake client behavior it intentionally lacks
// for server-side apply. API-server apply semantics are covered by the later
// isolated-cluster suite; these tests exercise reconciliation decisions.
func applyPatchAsUpdate(ctx context.Context, kubeClient client.WithWatch, object client.Object, patch client.Patch, _ ...client.PatchOption) error {
	if patch.Type() != types.ApplyPatchType {
		return kubeClient.Patch(ctx, object, patch)
	}
	existing := object.DeepCopyObject().(client.Object)
	if err := kubeClient.Get(ctx, client.ObjectKeyFromObject(object), existing); err != nil {
		return err
	}
	object.SetResourceVersion(existing.GetResourceVersion())
	return kubeClient.Update(ctx, object)
}

func controllerTestServer(state arcadev1alpha1.DesiredState) *arcadev1alpha1.GameServer {
	return &arcadev1alpha1.GameServer{
		TypeMeta: metav1.TypeMeta{APIVersion: arcadev1alpha1.GroupVersion.String(), Kind: "GameServer"},
		ObjectMeta: metav1.ObjectMeta{
			Name:       "factory",
			Namespace:  "games",
			UID:        types.UID("server-uid"),
			Generation: 1,
		},
		Spec: arcadev1alpha1.GameServerSpec{
			Game:         "factorio",
			ImageDigest:  controllerTestDigest,
			DesiredState: state,
			Compute: arcadev1alpha1.ComputeSpec{
				CPURequest:    resource.MustParse("500m"),
				CPULimit:      resource.MustParse("2"),
				MemoryRequest: resource.MustParse("1Gi"),
				MemoryLimit:   resource.MustParse("2Gi"),
			},
			Storage:  arcadev1alpha1.StorageSpec{Size: resource.MustParse("10Gi")},
			Settings: runtime.RawExtension{Raw: []byte(`{"name":"test","maxPlayers":16,"visibility":"private"}`)},
		},
	}
}

func assertObjectExists(t *testing.T, kubeClient client.Client, key types.NamespacedName, object client.Object) {
	t.Helper()
	if err := kubeClient.Get(context.Background(), key, object); err != nil {
		t.Fatalf("get %T %s: %v", object, key, err)
	}
}

func assertNotFound(t *testing.T, kubeClient client.Client, key types.NamespacedName, object client.Object) {
	t.Helper()
	if err := kubeClient.Get(context.Background(), key, object); !apierrors.IsNotFound(err) {
		t.Fatalf("get %T %s error = %v, want NotFound", object, key, err)
	}
}

func assertListLength(t *testing.T, kubeClient client.Client, list client.ObjectList, want int) {
	t.Helper()
	if err := kubeClient.List(context.Background(), list, client.InNamespace("games")); err != nil {
		t.Fatalf("list %T: %v", list, err)
	}
	var got int
	switch list := list.(type) {
	case *corev1.PersistentVolumeClaimList:
		got = len(list.Items)
	case *appsv1.DeploymentList:
		got = len(list.Items)
	case *corev1.ServiceList:
		got = len(list.Items)
	default:
		t.Fatalf("unsupported list type %T", list)
	}
	if got != want {
		t.Fatalf("list %T length = %d, want %d", list, got, want)
	}
}

func assertControlledBy(t *testing.T, object metav1.Object, uid types.UID) {
	t.Helper()
	reference := metav1.GetControllerOf(object)
	if reference == nil || reference.UID != uid {
		t.Fatalf("controller reference = %#v, want UID %q", reference, uid)
	}
}

func assertPhase(t *testing.T, kubeClient client.Client, key types.NamespacedName, phase arcadev1alpha1.GameServerPhase, status metav1.ConditionStatus, reason string) {
	t.Helper()
	server := &arcadev1alpha1.GameServer{}
	if err := kubeClient.Get(context.Background(), key, server); err != nil {
		t.Fatalf("get GameServer status: %v", err)
	}
	if server.Status.Phase != phase {
		t.Fatalf("phase = %q, want %q", server.Status.Phase, phase)
	}
	condition := meta.FindStatusCondition(server.Status.Conditions, readyCondition)
	if condition == nil || condition.Status != status || condition.Reason != reason {
		t.Fatalf("Ready condition = %#v, want status %q reason %q", condition, status, reason)
	}
}
