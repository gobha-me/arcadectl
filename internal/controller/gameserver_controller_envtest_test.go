//go:build envtest

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	arcadev1alpha1 "github.com/gobha-me/arcadectl/api/v1alpha1"
	"github.com/gobha-me/arcadectl/internal/catalog"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

const pinnedEnvtestIndex = "https://raw.githubusercontent.com/kubernetes-sigs/controller-tools/1031496fc98a4f51010c3bdfdeb57b5d67bea7bd/envtest-releases.yaml"

func TestEnvtestLifecycleStatusCollisionAndRecovery(t *testing.T) {
	testEnvironment := &envtest.Environment{
		CRDDirectoryPaths:            []string{filepath.Join("..", "..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing:        true,
		DownloadBinaryAssets:         true,
		DownloadBinaryAssetsVersion:  "1.37.0",
		DownloadBinaryAssetsIndexURL: pinnedEnvtestIndex,
		BinaryAssetsDirectory:        t.TempDir(),
		ControlPlaneStartTimeout:     90 * time.Second,
		ControlPlaneStopTimeout:      30 * time.Second,
	}
	configuration, err := testEnvironment.Start()
	if err != nil {
		t.Fatalf("start pinned envtest control plane: %v", err)
	}
	t.Cleanup(func() {
		if err := testEnvironment.Stop(); err != nil {
			t.Errorf("stop envtest control plane: %v", err)
		}
	})

	scheme := runtime.NewScheme()
	for name, add := range map[string]func(*runtime.Scheme) error{
		"Arcadectl": arcadev1alpha1.AddToScheme,
		"apps":      appsv1.AddToScheme,
		"core":      corev1.AddToScheme,
	} {
		if err := add(scheme); err != nil {
			t.Fatalf("add %s scheme: %v", name, err)
		}
	}
	kubeClient, err := client.New(configuration, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatalf("create envtest client: %v", err)
	}
	ctx := context.Background()
	if err := kubeClient.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "games"}}); err != nil {
		t.Fatalf("create test namespace: %v", err)
	}
	server := controllerTestServer(arcadev1alpha1.DesiredStateRunning)
	server.UID = ""
	server.Generation = 0
	if err := kubeClient.Create(ctx, server); err != nil {
		t.Fatalf("create GameServer: %v", err)
	}
	foreignService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: server.Name, Namespace: server.Namespace},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"foreign": "owner"},
			Ports:    []corev1.ServicePort{{Name: "rogue", Port: 9999}},
		},
	}
	if err := kubeClient.Create(ctx, foreignService); err != nil {
		t.Fatalf("create foreign Service: %v", err)
	}
	gameCatalog, err := catalog.Builtins()
	if err != nil {
		t.Fatalf("build catalog: %v", err)
	}
	reconciler := &GameServerReconciler{Client: kubeClient, Scheme: scheme, Catalog: gameCatalog}
	request := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: server.Namespace, Name: server.Name}}

	if _, err := reconciler.Reconcile(ctx, request); err == nil {
		t.Fatal("foreign Service collision did not return a safe retry error")
	}
	assertPhase(t, kubeClient, request.NamespacedName, arcadev1alpha1.PhaseFailed, metav1.ConditionFalse, arcadev1alpha1.ReasonResourceCollision)
	assertCondition(t, kubeClient, request.NamespacedName, arcadev1alpha1.ConditionNetworkReady, metav1.ConditionFalse, arcadev1alpha1.ReasonResourceCollision)
	assertEnvtestListLength(t, kubeClient, &corev1.PersistentVolumeClaimList{}, 0)
	assertEnvtestListLength(t, kubeClient, &corev1.ConfigMapList{}, 0)
	assertEnvtestListLength(t, kubeClient, &appsv1.DeploymentList{}, 0)
	if err := kubeClient.Delete(ctx, foreignService); err != nil {
		t.Fatalf("resolve foreign Service collision: %v", err)
	}

	if _, err := reconciler.Reconcile(ctx, request); err != nil {
		t.Fatalf("recover from collision: %v", err)
	}
	assertPhase(t, kubeClient, request.NamespacedName, arcadev1alpha1.PhasePending, metav1.ConditionFalse, arcadev1alpha1.ReasonStoragePending)
	claimKey := types.NamespacedName{Namespace: server.Namespace, Name: "factory-factorio-world"}
	claim := &corev1.PersistentVolumeClaim{}
	if err := kubeClient.Get(ctx, claimKey, claim); err != nil {
		t.Fatalf("get retained claim: %v", err)
	}
	claim.Status.Phase = corev1.ClaimBound
	claim.Status.Capacity = corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("10Gi")}
	if err := kubeClient.Status().Update(ctx, claim); err != nil {
		t.Fatalf("mark retained claim bound: %v", err)
	}
	if _, err := reconciler.Reconcile(ctx, request); err != nil {
		t.Fatalf("observe bound storage: %v", err)
	}
	assertPhase(t, kubeClient, request.NamespacedName, arcadev1alpha1.PhaseStarting, metav1.ConditionFalse, arcadev1alpha1.ReasonWorkloadPending)

	deployment := &appsv1.Deployment{}
	service := &corev1.Service{}
	if err := kubeClient.Get(ctx, request.NamespacedName, deployment); err != nil {
		t.Fatalf("get Deployment: %v", err)
	}
	if err := kubeClient.Get(ctx, request.NamespacedName, service); err != nil {
		t.Fatalf("get Service: %v", err)
	}
	deployment.Status.ObservedGeneration = deployment.Generation - 1
	deployment.Status.Replicas = 1
	deployment.Status.UpdatedReplicas = 1
	deployment.Status.ReadyReplicas = 1
	deployment.Status.AvailableReplicas = 1
	if err := kubeClient.Status().Update(ctx, deployment); err != nil {
		t.Fatalf("write stale Deployment status: %v", err)
	}
	service.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "192.0.2.40"}}
	if err := kubeClient.Status().Update(ctx, service); err != nil {
		t.Fatalf("publish player ingress: %v", err)
	}
	if _, err := reconciler.Reconcile(ctx, request); err != nil {
		t.Fatalf("observe stale rollout: %v", err)
	}
	assertPhase(t, kubeClient, request.NamespacedName, arcadev1alpha1.PhaseStarting, metav1.ConditionFalse, arcadev1alpha1.ReasonWorkloadPending)

	if err := kubeClient.Get(ctx, request.NamespacedName, deployment); err != nil {
		t.Fatalf("refresh Deployment: %v", err)
	}
	deployment.Status.ObservedGeneration = deployment.Generation
	deployment.Status.Replicas = 1
	deployment.Status.UpdatedReplicas = 1
	deployment.Status.ReadyReplicas = 1
	deployment.Status.AvailableReplicas = 1
	deployment.Status.UnavailableReplicas = 0
	if err := kubeClient.Status().Update(ctx, deployment); err != nil {
		t.Fatalf("write current Deployment status: %v", err)
	}
	if _, err := reconciler.Reconcile(ctx, request); err != nil {
		t.Fatalf("observe ready runtime: %v", err)
	}
	assertPhase(t, kubeClient, request.NamespacedName, arcadev1alpha1.PhaseReady, metav1.ConditionTrue, arcadev1alpha1.ReasonReady)
	readyServer := &arcadev1alpha1.GameServer{}
	if err := kubeClient.Get(ctx, request.NamespacedName, readyServer); err != nil {
		t.Fatalf("get ready GameServer: %v", err)
	}
	if len(readyServer.Status.Endpoints) != 1 || readyServer.Status.Endpoints[0].Name != "game" || readyServer.Status.Endpoints[0].Port != 34197 {
		t.Fatalf("ready endpoints = %#v, want certified player endpoint", readyServer.Status.Endpoints)
	}
	readyServer.Spec.Settings.Raw = []byte(`{"name":"updated","maxPlayers":8,"visibility":"private"}`)
	if err := kubeClient.Update(ctx, readyServer); err != nil {
		t.Fatalf("update ready GameServer settings: %v", err)
	}
	if _, err := reconciler.Reconcile(ctx, request); err != nil {
		t.Fatalf("reconcile new GameServer generation: %v", err)
	}
	assertPhase(t, kubeClient, request.NamespacedName, arcadev1alpha1.PhaseStarting, metav1.ConditionFalse, arcadev1alpha1.ReasonWorkloadPending)
	if err := kubeClient.Get(ctx, request.NamespacedName, readyServer); err != nil {
		t.Fatalf("get starting new GameServer generation: %v", err)
	}
	if len(readyServer.Status.Endpoints) != 0 || readyServer.Status.ObservedGeneration != readyServer.Generation {
		t.Fatalf("new generation retained stale readiness: generation %d status %#v", readyServer.Generation, readyServer.Status)
	}
	if err := kubeClient.Get(ctx, request.NamespacedName, deployment); err != nil {
		t.Fatalf("get new Deployment generation: %v", err)
	}
	deployment.Status.ObservedGeneration = deployment.Generation
	deployment.Status.Replicas = 1
	deployment.Status.UpdatedReplicas = 1
	deployment.Status.ReadyReplicas = 1
	deployment.Status.AvailableReplicas = 1
	deployment.Status.UnavailableReplicas = 0
	if err := kubeClient.Status().Update(ctx, deployment); err != nil {
		t.Fatalf("mark new Deployment generation ready: %v", err)
	}
	if _, err := reconciler.Reconcile(ctx, request); err != nil {
		t.Fatalf("observe new ready generation: %v", err)
	}
	assertPhase(t, kubeClient, request.NamespacedName, arcadev1alpha1.PhaseReady, metav1.ConditionTrue, arcadev1alpha1.ReasonReady)
	if err := kubeClient.Get(ctx, request.NamespacedName, readyServer); err != nil {
		t.Fatalf("get new ready GameServer: %v", err)
	}
	readyResourceVersion := readyServer.ResourceVersion
	if _, err := reconciler.Reconcile(ctx, request); err != nil {
		t.Fatalf("idempotent ready reconcile: %v", err)
	}
	if err := kubeClient.Get(ctx, request.NamespacedName, readyServer); err != nil {
		t.Fatalf("get idempotent GameServer: %v", err)
	}
	if readyServer.ResourceVersion != readyResourceVersion {
		t.Fatalf("idempotent status changed resourceVersion: %s -> %s", readyResourceVersion, readyServer.ResourceVersion)
	}

	readyServer.Spec.DesiredState = arcadev1alpha1.DesiredStateStopped
	if err := kubeClient.Update(ctx, readyServer); err != nil {
		t.Fatalf("request stop: %v", err)
	}
	if err := kubeClient.Get(ctx, request.NamespacedName, readyServer); err != nil {
		t.Fatalf("get stop generation: %v", err)
	}
	stopGeneration := readyServer.Generation
	if _, err := reconciler.Reconcile(ctx, request); err != nil {
		t.Fatalf("begin stop: %v", err)
	}
	assertPhase(t, kubeClient, request.NamespacedName, arcadev1alpha1.PhaseStopping, metav1.ConditionFalse, arcadev1alpha1.ReasonRuntimeStopping)
	if _, err := reconciler.Reconcile(ctx, request); err != nil {
		t.Fatalf("finish stop: %v", err)
	}
	assertPhase(t, kubeClient, request.NamespacedName, arcadev1alpha1.PhaseStopped, metav1.ConditionFalse, arcadev1alpha1.ReasonRuntimeStopped)
	stopped := &arcadev1alpha1.GameServer{}
	if err := kubeClient.Get(ctx, request.NamespacedName, stopped); err != nil {
		t.Fatalf("get stopped GameServer: %v", err)
	}
	if stopped.Generation != stopGeneration || stopped.Status.ObservedGeneration != stopGeneration || len(stopped.Status.Endpoints) != 0 {
		t.Fatalf("stopped status = generation %d %#v", stopped.Generation, stopped.Status)
	}
}

func assertEnvtestListLength(t *testing.T, kubeClient client.Client, list client.ObjectList, want int) {
	t.Helper()
	if err := kubeClient.List(context.Background(), list, client.InNamespace("games")); err != nil {
		t.Fatalf("list %T: %v", list, err)
	}
	var got int
	switch typed := list.(type) {
	case *corev1.PersistentVolumeClaimList:
		got = len(typed.Items)
	case *corev1.ConfigMapList:
		got = len(typed.Items)
	case *appsv1.DeploymentList:
		got = len(typed.Items)
	default:
		t.Fatalf("unsupported list type %T", list)
	}
	if got != want {
		t.Fatalf("list %T length = %d, want %d", list, got, want)
	}
}
