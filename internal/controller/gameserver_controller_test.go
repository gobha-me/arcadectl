// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	arcadev1alpha1 "github.com/gobha-me/arcadectl/api/v1alpha1"
	"github.com/gobha-me/arcadectl/internal/catalog"
	"github.com/gobha-me/arcadectl/internal/games/factorio"
	"github.com/gobha-me/arcadectl/internal/games/synthetic"
	"github.com/gobha-me/arcadectl/internal/platform/game"
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
	configurationKey := types.NamespacedName{Namespace: "games", Name: "factory-configuration"}
	configuration := &corev1.ConfigMap{}
	assertObjectExists(t, kubeClient, configurationKey, configuration)
	assertControlledBy(t, deployment, server.UID)
	assertControlledBy(t, service, server.UID)
	assertControlledBy(t, configuration, server.UID)

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
	assertListLength(t, kubeClient, &corev1.ConfigMapList{}, 1)
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
	assertNotFound(t, kubeClient, configurationKey, &corev1.ConfigMap{})
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
	assertPhase(t, kubeClient, request.NamespacedName, arcadev1alpha1.PhasePending, metav1.ConditionFalse, arcadev1alpha1.ReasonStoragePending)
	assertCondition(t, kubeClient, request.NamespacedName, arcadev1alpha1.ConditionSpecValid, metav1.ConditionTrue, arcadev1alpha1.ReasonValid)
	assertCondition(t, kubeClient, request.NamespacedName, arcadev1alpha1.ConditionStorageReady, metav1.ConditionFalse, arcadev1alpha1.ReasonClaimsProvisioning)
	assertCondition(t, kubeClient, request.NamespacedName, arcadev1alpha1.ConditionConfigurationReady, metav1.ConditionTrue, arcadev1alpha1.ReasonConfigurationReady)
	assertCondition(t, kubeClient, request.NamespacedName, arcadev1alpha1.ConditionWorkloadReady, metav1.ConditionFalse, arcadev1alpha1.ReasonWorkloadProgressing)
	assertCondition(t, kubeClient, request.NamespacedName, arcadev1alpha1.ConditionNetworkReady, metav1.ConditionFalse, arcadev1alpha1.ReasonPlayerEndpointPending)
	markClaimBound(t, kubeClient, types.NamespacedName{Namespace: "games", Name: "factory-factorio-world"}, resource.MustParse("10Gi"))
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("storage-ready Reconcile() error = %v", err)
	}
	assertPhase(t, kubeClient, request.NamespacedName, arcadev1alpha1.PhaseStarting, metav1.ConditionFalse, arcadev1alpha1.ReasonWorkloadPending)

	deployment := &appsv1.Deployment{}
	if err := kubeClient.Get(context.Background(), request.NamespacedName, deployment); err != nil {
		t.Fatalf("get Deployment: %v", err)
	}
	deployment.Status.ObservedGeneration = deployment.Generation
	deployment.Status.Replicas = 1
	deployment.Status.AvailableReplicas = 1
	deployment.Status.UpdatedReplicas = 1
	deployment.Status.ReadyReplicas = 1
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
	assertPhase(t, kubeClient, request.NamespacedName, arcadev1alpha1.PhaseReady, metav1.ConditionTrue, arcadev1alpha1.ReasonReady)
	assertCondition(t, kubeClient, request.NamespacedName, arcadev1alpha1.ConditionStorageReady, metav1.ConditionTrue, arcadev1alpha1.ReasonClaimsReady)
	assertCondition(t, kubeClient, request.NamespacedName, arcadev1alpha1.ConditionConfigurationReady, metav1.ConditionTrue, arcadev1alpha1.ReasonConfigurationReady)
	assertCondition(t, kubeClient, request.NamespacedName, arcadev1alpha1.ConditionWorkloadReady, metav1.ConditionTrue, arcadev1alpha1.ReasonWorkloadAvailable)
	assertCondition(t, kubeClient, request.NamespacedName, arcadev1alpha1.ConditionNetworkReady, metav1.ConditionTrue, arcadev1alpha1.ReasonPlayerEndpointReady)
	stored := &arcadev1alpha1.GameServer{}
	if err := kubeClient.Get(context.Background(), request.NamespacedName, stored); err != nil {
		t.Fatalf("get ready GameServer: %v", err)
	}
	if len(stored.Status.Endpoints) != 1 || stored.Status.Endpoints[0].Address != "192.0.2.10" || stored.Status.Endpoints[0].Name != "game" {
		t.Fatalf("observed endpoints = %#v", stored.Status.Endpoints)
	}

	if err := kubeClient.Get(context.Background(), request.NamespacedName, service); err != nil {
		t.Fatalf("get ready Service: %v", err)
	}
	providerFailure := "UnsupportedProtocol"
	service.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{
		IP: "192.0.2.10",
		Ports: []corev1.PortStatus{{
			Port: 34197, Protocol: corev1.ProtocolUDP, Error: &providerFailure,
		}},
	}}
	if err := kubeClient.Status().Update(context.Background(), service); err != nil {
		t.Fatalf("report failed player ingress port: %v", err)
	}
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("failed-ingress-port Reconcile() error = %v", err)
	}
	assertPhase(t, kubeClient, request.NamespacedName, arcadev1alpha1.PhaseStarting, metav1.ConditionFalse, arcadev1alpha1.ReasonPlayerEndpointPending)
	if err := kubeClient.Get(context.Background(), request.NamespacedName, stored); err != nil {
		t.Fatalf("get failed-ingress-port GameServer: %v", err)
	}
	if len(stored.Status.Endpoints) != 0 {
		t.Fatalf("failed ingress port retained endpoints: %#v", stored.Status.Endpoints)
	}

	if err := kubeClient.Get(context.Background(), request.NamespacedName, service); err != nil {
		t.Fatalf("get failed-ingress-port Service: %v", err)
	}
	service.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "192.0.2.10"}}
	if err := kubeClient.Status().Update(context.Background(), service); err != nil {
		t.Fatalf("recover player ingress port: %v", err)
	}
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("ingress-port-recovery Reconcile() error = %v", err)
	}
	assertPhase(t, kubeClient, request.NamespacedName, arcadev1alpha1.PhaseReady, metav1.ConditionTrue, arcadev1alpha1.ReasonReady)

	if err := kubeClient.Get(context.Background(), request.NamespacedName, service); err != nil {
		t.Fatalf("get recovered Service: %v", err)
	}
	service.Status.LoadBalancer.Ingress = nil
	if err := kubeClient.Status().Update(context.Background(), service); err != nil {
		t.Fatalf("remove player ingress: %v", err)
	}
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("lost-endpoint Reconcile() error = %v", err)
	}
	assertPhase(t, kubeClient, request.NamespacedName, arcadev1alpha1.PhaseStarting, metav1.ConditionFalse, arcadev1alpha1.ReasonPlayerEndpointPending)
	if err := kubeClient.Get(context.Background(), request.NamespacedName, stored); err != nil {
		t.Fatalf("get endpoint-pending GameServer: %v", err)
	}
	if len(stored.Status.Endpoints) != 0 {
		t.Fatalf("stale endpoints survived reachability loss: %#v", stored.Status.Endpoints)
	}

	if err := kubeClient.Get(context.Background(), request.NamespacedName, service); err != nil {
		t.Fatalf("get endpoint-pending Service: %v", err)
	}
	service.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{Hostname: "factory.example.test"}}
	if err := kubeClient.Status().Update(context.Background(), service); err != nil {
		t.Fatalf("restore player ingress: %v", err)
	}
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("endpoint-recovery Reconcile() error = %v", err)
	}
	assertPhase(t, kubeClient, request.NamespacedName, arcadev1alpha1.PhaseReady, metav1.ConditionTrue, arcadev1alpha1.ReasonReady)
}

func TestReconcileTerminationClearsReachableEndpoints(t *testing.T) {
	t.Parallel()

	server := controllerTestServer(arcadev1alpha1.DesiredStateRunning)
	timestamp := metav1.NewTime(time.Unix(1_700_000_100, 0))
	server.DeletionTimestamp = &timestamp
	server.Finalizers = []string{"test.arcade.gobha.me/hold"}
	server.Status = arcadev1alpha1.GameServerStatus{
		ObservedGeneration: server.Generation,
		Phase:              arcadev1alpha1.PhaseReady,
		Conditions: []metav1.Condition{{
			Type:               arcadev1alpha1.ConditionReady,
			Status:             metav1.ConditionTrue,
			Reason:             arcadev1alpha1.ReasonReady,
			ObservedGeneration: server.Generation,
			LastTransitionTime: timestamp,
		}},
		Endpoints: []arcadev1alpha1.ObservedEndpoint{{Name: "game", Protocol: "UDP", Address: "192.0.2.10", Port: 34197}},
	}
	reconciler, kubeClient := newTestReconciler(t, server)
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(server)}
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("terminating Reconcile() error = %v", err)
	}
	assertPhase(t, kubeClient, request.NamespacedName, arcadev1alpha1.PhaseStopping, metav1.ConditionFalse, arcadev1alpha1.ReasonRuntimeStopping)
	stored := &arcadev1alpha1.GameServer{}
	if err := kubeClient.Get(context.Background(), request.NamespacedName, stored); err != nil {
		t.Fatalf("get terminating GameServer: %v", err)
	}
	if len(stored.Status.Endpoints) != 0 {
		t.Fatalf("terminating status retained endpoints: %#v", stored.Status.Endpoints)
	}
}

func TestReconcileReportsAndRecoversFromLostStorage(t *testing.T) {
	t.Parallel()

	server := controllerTestServer(arcadev1alpha1.DesiredStateRunning)
	reconciler, kubeClient := newTestReconciler(t, server)
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(server)}
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("initial Reconcile() error = %v", err)
	}
	claimKey := types.NamespacedName{Namespace: "games", Name: "factory-factorio-world"}
	claim := &corev1.PersistentVolumeClaim{}
	if err := kubeClient.Get(context.Background(), claimKey, claim); err != nil {
		t.Fatalf("get retained claim: %v", err)
	}
	claim.Status.Phase = corev1.ClaimLost
	if err := kubeClient.Status().Update(context.Background(), claim); err != nil {
		t.Fatalf("mark retained claim lost: %v", err)
	}
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("lost-storage Reconcile() error = %v, want observed status failure", err)
	}
	assertPhase(t, kubeClient, request.NamespacedName, arcadev1alpha1.PhaseFailed, metav1.ConditionFalse, arcadev1alpha1.ReasonReconcileFailed)
	assertCondition(t, kubeClient, request.NamespacedName, arcadev1alpha1.ConditionStorageReady, metav1.ConditionFalse, arcadev1alpha1.ReasonStorageOperationFailed)

	if err := kubeClient.Get(context.Background(), claimKey, claim); err != nil {
		t.Fatalf("get lost retained claim: %v", err)
	}
	claim.Status.Phase = corev1.ClaimPending
	if err := kubeClient.Status().Update(context.Background(), claim); err != nil {
		t.Fatalf("recover retained claim: %v", err)
	}
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("storage-recovery Reconcile() error = %v", err)
	}
	assertPhase(t, kubeClient, request.NamespacedName, arcadev1alpha1.PhasePending, metav1.ConditionFalse, arcadev1alpha1.ReasonStoragePending)
}

func TestReconcileReportsAndRecoversFromTerminalWorkloadFailure(t *testing.T) {
	t.Parallel()

	server := controllerTestServer(arcadev1alpha1.DesiredStateRunning)
	reconciler, kubeClient := newTestReconciler(t, server)
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(server)}
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("initial Reconcile() error = %v", err)
	}
	markClaimBound(t, kubeClient, types.NamespacedName{Namespace: "games", Name: "factory-factorio-world"}, resource.MustParse("10Gi"))
	deployment := &appsv1.Deployment{}
	if err := kubeClient.Get(context.Background(), request.NamespacedName, deployment); err != nil {
		t.Fatalf("get Deployment: %v", err)
	}
	deployment.Status.ObservedGeneration = deployment.Generation
	deployment.Status.Conditions = []appsv1.DeploymentCondition{{
		Type:    appsv1.DeploymentProgressing,
		Status:  corev1.ConditionFalse,
		Reason:  "ProgressDeadlineExceeded",
		Message: "TOPSECRET-provider-diagnostic",
	}}
	if err := kubeClient.Status().Update(context.Background(), deployment); err != nil {
		t.Fatalf("mark Deployment failed: %v", err)
	}
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("failed-workload Reconcile() error = %v, want observed status failure", err)
	}
	assertPhase(t, kubeClient, request.NamespacedName, arcadev1alpha1.PhaseFailed, metav1.ConditionFalse, arcadev1alpha1.ReasonReconcileFailed)
	assertCondition(t, kubeClient, request.NamespacedName, arcadev1alpha1.ConditionWorkloadReady, metav1.ConditionFalse, arcadev1alpha1.ReasonWorkloadUnavailable)
	stored := &arcadev1alpha1.GameServer{}
	if err := kubeClient.Get(context.Background(), request.NamespacedName, stored); err != nil {
		t.Fatalf("get failed GameServer: %v", err)
	}
	encoded, err := json.Marshal(stored.Status)
	if err != nil {
		t.Fatalf("encode failed status: %v", err)
	}
	if strings.Contains(string(encoded), "TOPSECRET") {
		t.Fatalf("status reflected native Deployment diagnostic: %s", encoded)
	}

	if err := kubeClient.Get(context.Background(), request.NamespacedName, deployment); err != nil {
		t.Fatalf("get failed Deployment: %v", err)
	}
	deployment.Status.Conditions = nil
	if err := kubeClient.Status().Update(context.Background(), deployment); err != nil {
		t.Fatalf("recover Deployment: %v", err)
	}
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("workload-recovery Reconcile() error = %v", err)
	}
	assertPhase(t, kubeClient, request.NamespacedName, arcadev1alpha1.PhaseStarting, metav1.ConditionFalse, arcadev1alpha1.ReasonWorkloadPending)
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
	assertListLength(t, kubeClient, &corev1.ConfigMapList{}, 0)
	assertListLength(t, kubeClient, &appsv1.DeploymentList{}, 0)
	assertListLength(t, kubeClient, &corev1.ServiceList{}, 0)
	assertPhase(t, kubeClient, request.NamespacedName, arcadev1alpha1.PhaseFailed, metav1.ConditionFalse, "InvalidSpec")
	stored := &arcadev1alpha1.GameServer{}
	if err := kubeClient.Get(context.Background(), request.NamespacedName, stored); err != nil {
		t.Fatalf("get invalid GameServer: %v", err)
	}
	condition := meta.FindStatusCondition(stored.Status.Conditions, arcadev1alpha1.ConditionSpecValid)
	if condition == nil || !strings.Contains(condition.Message, "settings are invalid") || strings.Contains(condition.Message, "imageDigest") {
		t.Fatalf("invalid-settings condition = %#v, want bounded settings action", condition)
	}
}

func TestReconcileRejectsInvalidRenderedOutputBeforeMutation(t *testing.T) {
	t.Parallel()

	server := controllerTestServer(arcadev1alpha1.DesiredStateRunning)
	reconciler, kubeClient := newTestReconciler(t, server)
	definition := factorio.Definition()
	definition.RenderSettings = func(json.RawMessage) (map[string][]byte, error) {
		return map[string][]byte{"server-settings": []byte(strings.Repeat("x", game.MaxRenderedSettingsBytes+1))}, nil
	}
	reconciler.Catalog = fixedCatalog{definition: definition}
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(server)}
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("Reconcile() error = %v, want status-only invalid spec", err)
	}
	assertListLength(t, kubeClient, &corev1.PersistentVolumeClaimList{}, 0)
	assertListLength(t, kubeClient, &corev1.ConfigMapList{}, 0)
	assertListLength(t, kubeClient, &appsv1.DeploymentList{}, 0)
	assertListLength(t, kubeClient, &corev1.ServiceList{}, 0)
	assertPhase(t, kubeClient, request.NamespacedName, arcadev1alpha1.PhaseFailed, metav1.ConditionFalse, "InvalidSpec")
}

func TestReconcileFailureDoesNotReflectSensitiveCause(t *testing.T) {
	t.Parallel()

	const sensitive = "TOPSECRET-setting-or-admission-text"
	server := controllerTestServer(arcadev1alpha1.DesiredStateRunning)
	reconciler, kubeClient := newTestReconciler(t, server)
	reconciler.Client = &persistentClaimCreateFailingClient{Client: reconciler.Client, failure: errors.New(sensitive)}
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(server)}
	_, err := reconciler.Reconcile(context.Background(), request)
	if err == nil {
		t.Fatal("Reconcile() succeeded despite injected storage failure")
	}
	if strings.Contains(err.Error(), sensitive) {
		t.Fatalf("reconcile error reflected sensitive cause: %v", err)
	}
	stored := &arcadev1alpha1.GameServer{}
	if err := kubeClient.Get(context.Background(), request.NamespacedName, stored); err != nil {
		t.Fatalf("get failed GameServer: %v", err)
	}
	encoded, err := json.Marshal(stored.Status)
	if err != nil {
		t.Fatalf("encode failed status: %v", err)
	}
	if strings.Contains(string(encoded), sensitive) {
		t.Fatalf("status reflected sensitive cause: %s", encoded)
	}
	assertPhase(t, kubeClient, request.NamespacedName, arcadev1alpha1.PhaseFailed, metav1.ConditionFalse, arcadev1alpha1.ReasonReconcileFailed)
	events := &corev1.EventList{}
	if err := kubeClient.List(context.Background(), events, client.InNamespace(server.Namespace)); err != nil {
		t.Fatalf("list Events: %v", err)
	}
	if len(events.Items) != 0 {
		t.Fatalf("reconciler emitted Events for raw error: %#v", events.Items)
	}
}

func TestReconcilePreflightRejectsForeignConfigurationBeforeMutation(t *testing.T) {
	t.Parallel()

	server := controllerTestServer(arcadev1alpha1.DesiredStateRunning)
	foreign := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "factory-configuration", Namespace: "games"},
		BinaryData: map[string][]byte{"server-settings": []byte("foreign")},
	}
	reconciler, kubeClient := newTestReconciler(t, server, foreign)
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(server)}
	_, err := reconciler.Reconcile(context.Background(), request)
	if err == nil || !strings.Contains(err.Error(), "ConfigMap games/factory-configuration conflicts") {
		t.Fatalf("Reconcile() error = %v, want foreign-configuration refusal", err)
	}
	assertListLength(t, kubeClient, &corev1.PersistentVolumeClaimList{}, 0)
	assertListLength(t, kubeClient, &appsv1.DeploymentList{}, 0)
	assertListLength(t, kubeClient, &corev1.ServiceList{}, 0)
	stored := &corev1.ConfigMap{}
	assertObjectExists(t, kubeClient, client.ObjectKeyFromObject(foreign), stored)
	if string(stored.BinaryData["server-settings"]) != "foreign" {
		t.Fatal("reconciler mutated foreign configuration")
	}
	assertPhase(t, kubeClient, request.NamespacedName, arcadev1alpha1.PhaseFailed, metav1.ConditionFalse, arcadev1alpha1.ReasonResourceCollision)
	assertCondition(t, kubeClient, request.NamespacedName, arcadev1alpha1.ConditionConfigurationReady, metav1.ConditionFalse, arcadev1alpha1.ReasonResourceCollision)
	if err := kubeClient.Delete(context.Background(), stored); err != nil {
		t.Fatalf("resolve foreign ConfigMap collision: %v", err)
	}
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("collision-recovery Reconcile() error = %v", err)
	}
	assertPhase(t, kubeClient, request.NamespacedName, arcadev1alpha1.PhasePending, metav1.ConditionFalse, arcadev1alpha1.ReasonStoragePending)
}

func TestReconcileSettingsUpdateChangesConfigurationAndRolloutHash(t *testing.T) {
	t.Parallel()

	server := controllerTestServer(arcadev1alpha1.DesiredStateRunning)
	reconciler, kubeClient := newTestReconciler(t, server)
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(server)}
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("initial Reconcile() error = %v", err)
	}
	initialDeployment := &appsv1.Deployment{}
	assertObjectExists(t, kubeClient, request.NamespacedName, initialDeployment)
	initialHash := initialDeployment.Spec.Template.Annotations[platformkube.AnnotationConfigurationHash]
	initialConfiguration := &corev1.ConfigMap{}
	configurationKey := types.NamespacedName{Namespace: "games", Name: "factory-configuration"}
	assertObjectExists(t, kubeClient, configurationKey, initialConfiguration)
	initialConfiguration.BinaryData["stale"] = []byte("must be pruned")
	if err := kubeClient.Update(context.Background(), initialConfiguration); err != nil {
		t.Fatalf("add stale configuration key: %v", err)
	}

	stored := &arcadev1alpha1.GameServer{}
	if err := kubeClient.Get(context.Background(), request.NamespacedName, stored); err != nil {
		t.Fatalf("get GameServer: %v", err)
	}
	stored.Spec.Settings.Raw = []byte(`{"name":"updated","maxPlayers":16,"visibility":"lan"}`)
	stored.Generation = 2
	if err := kubeClient.Update(context.Background(), stored); err != nil {
		t.Fatalf("update settings: %v", err)
	}
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("updated Reconcile() error = %v", err)
	}

	configuration := &corev1.ConfigMap{}
	assertObjectExists(t, kubeClient, configurationKey, configuration)
	contents := string(configuration.BinaryData["server-settings"])
	if !strings.Contains(contents, `"name": "updated"`) || !strings.Contains(contents, `"lan": true`) {
		t.Fatalf("updated configuration = %q", contents)
	}
	if _, exists := configuration.BinaryData["stale"]; exists {
		t.Fatal("reconciler retained a stale configuration key")
	}
	updatedDeployment := &appsv1.Deployment{}
	assertObjectExists(t, kubeClient, request.NamespacedName, updatedDeployment)
	updatedHash := updatedDeployment.Spec.Template.Annotations[platformkube.AnnotationConfigurationHash]
	if initialHash == "" || updatedHash == initialHash {
		t.Fatalf("configuration hash did not change: initial=%q updated=%q", initialHash, updatedHash)
	}
}

func TestReconcileUnchangedConfigurationDoesNotWrite(t *testing.T) {
	t.Parallel()

	server := controllerTestServer(arcadev1alpha1.DesiredStateRunning)
	reconciler, _ := newTestReconciler(t, server)
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(server)}
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("initial Reconcile() error = %v", err)
	}
	countingClient := &configMapUpdateCountingClient{Client: reconciler.Client}
	reconciler.Client = countingClient
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("unchanged Reconcile() error = %v", err)
	}
	if countingClient.configMapUpdates != 0 {
		t.Fatalf("unchanged reconcile issued %d ConfigMap updates, want zero", countingClient.configMapUpdates)
	}
}

func TestReconcileUnchangedStatusDoesNotWriteOrChurnTransitions(t *testing.T) {
	t.Parallel()

	server := controllerTestServer(arcadev1alpha1.DesiredStateStopped)
	reconciler, kubeClient := newTestReconciler(t, server)
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(server)}
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("initial Reconcile() error = %v", err)
	}
	before := &arcadev1alpha1.GameServer{}
	if err := kubeClient.Get(context.Background(), request.NamespacedName, before); err != nil {
		t.Fatalf("get initial status: %v", err)
	}

	countingClient := &statusUpdateCountingClient{Client: reconciler.Client}
	reconciler.Client = countingClient
	reconciler.Now = func() metav1.Time { return metav1.NewTime(time.Unix(1_800_000_000, 0)) }
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("unchanged Reconcile() error = %v", err)
	}
	if countingClient.gameServerStatusUpdates != 0 {
		t.Fatalf("unchanged reconcile issued %d status updates, want zero", countingClient.gameServerStatusUpdates)
	}
	after := &arcadev1alpha1.GameServer{}
	if err := kubeClient.Get(context.Background(), request.NamespacedName, after); err != nil {
		t.Fatalf("get unchanged status: %v", err)
	}
	if before.ResourceVersion != after.ResourceVersion || !reflect.DeepEqual(before.Status, after.Status) {
		t.Fatalf("unchanged reconcile mutated status: before=%#v after=%#v", before.Status, after.Status)
	}
}

func TestReconcilePreflightRejectsForeignRuntimeBeforeMutation(t *testing.T) {
	t.Parallel()

	server := controllerTestServer(arcadev1alpha1.DesiredStateRunning)
	foreign := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: server.Name, Namespace: server.Namespace}}
	reconciler, kubeClient := newTestReconciler(t, server, foreign)
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(server)}
	_, err := reconciler.Reconcile(context.Background(), request)
	if err == nil || !strings.Contains(err.Error(), "Deployment games/factory conflicts") {
		t.Fatalf("Reconcile() error = %v, want foreign-resource refusal", err)
	}
	assertListLength(t, kubeClient, &corev1.PersistentVolumeClaimList{}, 0)
	assertObjectExists(t, kubeClient, request.NamespacedName, &appsv1.Deployment{})
	assertListLength(t, kubeClient, &corev1.ServiceList{}, 0)
	assertPhase(t, kubeClient, request.NamespacedName, arcadev1alpha1.PhaseFailed, metav1.ConditionFalse, arcadev1alpha1.ReasonResourceCollision)
	assertCondition(t, kubeClient, request.NamespacedName, arcadev1alpha1.ConditionWorkloadReady, metav1.ConditionFalse, arcadev1alpha1.ReasonResourceCollision)
	if err := kubeClient.Delete(context.Background(), foreign); err != nil {
		t.Fatalf("resolve foreign Deployment collision: %v", err)
	}
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("collision-recovery Reconcile() error = %v", err)
	}
	assertPhase(t, kubeClient, request.NamespacedName, arcadev1alpha1.PhasePending, metav1.ConditionFalse, arcadev1alpha1.ReasonStoragePending)
}

func TestReconcileRejectsOwnedDataClaim(t *testing.T) {
	t.Parallel()

	server := controllerTestServer(arcadev1alpha1.DesiredStateRunning)
	dataIdentity, err := platformkube.DataIdentity(server.UID)
	if err != nil {
		t.Fatalf("DataIdentity() error = %v", err)
	}
	claim := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "factory-factorio-world",
			Namespace: "games",
			Labels: map[string]string{
				platformkube.LabelManagedBy:    platformkube.ManagerName,
				platformkube.LabelName:         "game-data",
				platformkube.LabelInstance:     "factory",
				platformkube.LabelGame:         "factorio",
				platformkube.LabelDataPolicy:   "retain",
				platformkube.LabelDataPath:     "world",
				platformkube.LabelDataIdentity: dataIdentity,
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
	_, err = reconciler.Reconcile(context.Background(), request)
	if err == nil || !strings.Contains(err.Error(), "retained data claim conflicts") {
		t.Fatalf("Reconcile() error = %v, want unsafe claim refusal", err)
	}
	assertListLength(t, kubeClient, &appsv1.DeploymentList{}, 0)
	assertListLength(t, kubeClient, &corev1.ServiceList{}, 0)
	stored := &corev1.PersistentVolumeClaim{}
	assertObjectExists(t, kubeClient, client.ObjectKeyFromObject(claim), stored)
	if len(stored.OwnerReferences) != 1 {
		t.Fatal("reconciler mutated foreign claim ownership")
	}
	assertPhase(t, kubeClient, request.NamespacedName, arcadev1alpha1.PhaseFailed, metav1.ConditionFalse, arcadev1alpha1.ReasonRetainedDataConflict)
	assertCondition(t, kubeClient, request.NamespacedName, arcadev1alpha1.ConditionStorageReady, metav1.ConditionFalse, arcadev1alpha1.ReasonRetainedDataConflict)
	stored.OwnerReferences = nil
	if err := kubeClient.Update(context.Background(), stored); err != nil {
		t.Fatalf("resolve retained-claim collision: %v", err)
	}
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("collision-recovery Reconcile() error = %v", err)
	}
	assertPhase(t, kubeClient, request.NamespacedName, arcadev1alpha1.PhasePending, metav1.ConditionFalse, arcadev1alpha1.ReasonStoragePending)
}

func TestReconcileRequiresExplicitRetainedDataReference(t *testing.T) {
	t.Parallel()

	oldServer := controllerTestServer(arcadev1alpha1.DesiredStateRunning)
	oldServer.UID = "old-server-uid"
	claim := plannedBoundClaim(t, oldServer, "retained-pvc-uid")
	before := claim.DeepCopy()
	server := controllerTestServer(arcadev1alpha1.DesiredStateRunning)
	server.UID = "replacement-server-uid"
	reconciler, kubeClient := newTestReconciler(t, server, claim)
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(server)}

	_, err := reconciler.Reconcile(context.Background(), request)
	if err == nil || !strings.Contains(err.Error(), "provide an exact reattach reference") {
		t.Fatalf("Reconcile() error = %v, want explicit reattach requirement", err)
	}
	assertPhase(t, kubeClient, request.NamespacedName, arcadev1alpha1.PhaseFailed, metav1.ConditionFalse, arcadev1alpha1.ReasonRetainedDataReferenceRequired)
	assertNoRuntime(t, kubeClient, request.NamespacedName)
	after := &corev1.PersistentVolumeClaim{}
	assertObjectExists(t, kubeClient, client.ObjectKeyFromObject(claim), after)
	if !reflect.DeepEqual(before.Spec, after.Spec) || !reflect.DeepEqual(before.Labels, after.Labels) || before.UID != after.UID {
		t.Fatalf("blocked implicit reattach mutated claim: before=%#v after=%#v", before, after)
	}
}

func TestReconcileStopsRuntimeBeforeReportingRetainedDataConflict(t *testing.T) {
	t.Parallel()

	server := controllerTestServer(arcadev1alpha1.DesiredStateRunning)
	runningPlan, err := platformkube.Build(server, factorio.Definition())
	if err != nil {
		t.Fatalf("build running fixture: %v", err)
	}
	oldServer := controllerTestServer(arcadev1alpha1.DesiredStateRunning)
	oldServer.UID = "old-server-uid"
	claim := plannedBoundClaim(t, oldServer, "retained-pvc-uid")
	server.Spec.DesiredState = arcadev1alpha1.DesiredStateStopped
	reconciler, kubeClient := newTestReconciler(t, server, claim, runningPlan.Configuration, runningPlan.Workload, runningPlan.PlayerService)
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(server)}

	result, err := reconciler.Reconcile(context.Background(), request)
	if err != nil || result.RequeueAfter <= 0 {
		t.Fatalf("stop Reconcile() = result %#v error %v, want bounded stopping requeue", result, err)
	}
	assertNoRuntime(t, kubeClient, request.NamespacedName)
	assertPhase(t, kubeClient, request.NamespacedName, arcadev1alpha1.PhaseStopping, metav1.ConditionFalse, arcadev1alpha1.ReasonRuntimeStopping)

	if _, err := reconciler.Reconcile(context.Background(), request); err == nil {
		t.Fatal("post-stop Reconcile() error = nil, want retained-data reference requirement")
	}
	assertNoRuntime(t, kubeClient, request.NamespacedName)
	assertPhase(t, kubeClient, request.NamespacedName, arcadev1alpha1.PhaseFailed, metav1.ConditionFalse, arcadev1alpha1.ReasonRetainedDataReferenceRequired)
	assertCondition(t, kubeClient, request.NamespacedName, arcadev1alpha1.ConditionWorkloadReady, metav1.ConditionFalse, arcadev1alpha1.ReasonRuntimeStopped)
}

func TestReconcileRefusesLegacyClaimWithoutInventingIdentity(t *testing.T) {
	t.Parallel()

	server := controllerTestServer(arcadev1alpha1.DesiredStateRunning)
	claim := plannedBoundClaim(t, server, "legacy-pvc-uid")
	delete(claim.Labels, platformkube.LabelDataIdentity)
	before := claim.DeepCopy()
	reconciler, kubeClient := newTestReconciler(t, server, claim)
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(server)}

	if _, err := reconciler.Reconcile(context.Background(), request); err == nil {
		t.Fatal("Reconcile() error = nil, want explicit legacy migration refusal")
	}
	assertPhase(t, kubeClient, request.NamespacedName, arcadev1alpha1.PhaseFailed, metav1.ConditionFalse, arcadev1alpha1.ReasonRetainedDataConflict)
	assertNoRuntime(t, kubeClient, request.NamespacedName)
	after := &corev1.PersistentVolumeClaim{}
	assertObjectExists(t, kubeClient, client.ObjectKeyFromObject(claim), after)
	if !reflect.DeepEqual(before.Spec, after.Spec) || !reflect.DeepEqual(before.Labels, after.Labels) || before.UID != after.UID {
		t.Fatalf("legacy refusal mutated claim: before=%#v after=%#v", before, after)
	}
}

func TestReconcileExactRetainedDataReference(t *testing.T) {
	t.Parallel()

	oldServer := controllerTestServer(arcadev1alpha1.DesiredStateRunning)
	oldServer.UID = "old-server-uid"
	claim := plannedBoundClaim(t, oldServer, "retained-pvc-uid")
	server := controllerTestServer(arcadev1alpha1.DesiredStateRunning)
	server.UID = "replacement-server-uid"
	server.Spec.Storage.Reattach = exactReattach(claim)
	reconciler, kubeClient := newTestReconciler(t, server, claim)
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(server)}

	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	deployment := &appsv1.Deployment{}
	assertObjectExists(t, kubeClient, request.NamespacedName, deployment)
	if got := deployment.Spec.Template.Spec.Volumes[0].PersistentVolumeClaim.ClaimName; got != claim.Name {
		t.Fatalf("workload claim = %q, want exact retained claim %q", got, claim.Name)
	}
	stored := &corev1.PersistentVolumeClaim{}
	assertObjectExists(t, kubeClient, client.ObjectKeyFromObject(claim), stored)
	if stored.UID != claim.UID {
		t.Fatalf("retained claim UID = %q, want %q", stored.UID, claim.UID)
	}
}

func TestStoppedMissingReattachKeepsRuntimeStoppedFence(t *testing.T) {
	t.Parallel()

	server := controllerTestServer(arcadev1alpha1.DesiredStateStopped)
	server.Spec.Storage.Reattach = &arcadev1alpha1.RetainedDataReference{
		Identity: "data-missing",
		Claims: []arcadev1alpha1.RetainedDataClaimReference{{
			Path:     "world",
			ClaimRef: arcadev1alpha1.ExactLocalReference{Name: "missing-world", UID: "missing-uid"},
		}},
	}
	reconciler, kubeClient := newTestReconciler(t, server)
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(server)}

	if _, err := reconciler.Reconcile(context.Background(), request); err == nil {
		t.Fatal("Reconcile() error = nil, want missing retained-data refusal")
	}
	assertPhase(t, kubeClient, request.NamespacedName, arcadev1alpha1.PhaseFailed, metav1.ConditionFalse, arcadev1alpha1.ReasonRetainedDataMissing)
	assertCondition(t, kubeClient, request.NamespacedName, arcadev1alpha1.ConditionWorkloadReady, metav1.ConditionFalse, arcadev1alpha1.ReasonRuntimeStopped)
	assertNoRuntime(t, kubeClient, request.NamespacedName)
}

func TestReconcileRejectsMissingOrConflictingRetainedData(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		seedClaim  bool
		mutateRef  func(*arcadev1alpha1.RetainedDataReference)
		mutatePVC  func(*corev1.PersistentVolumeClaim)
		wantReason string
	}{
		{name: "missing", wantReason: arcadev1alpha1.ReasonRetainedDataMissing},
		{name: "wrong UID", seedClaim: true, mutateRef: func(ref *arcadev1alpha1.RetainedDataReference) { ref.Claims[0].ClaimRef.UID = "wrong-pvc-uid" }, wantReason: arcadev1alpha1.ReasonRetainedDataConflict},
		{name: "wrong identity", seedClaim: true, mutatePVC: func(claim *corev1.PersistentVolumeClaim) { claim.Labels[platformkube.LabelDataIdentity] = "data-other" }, wantReason: arcadev1alpha1.ReasonRetainedDataConflict},
		{name: "wrong game", seedClaim: true, mutatePVC: func(claim *corev1.PersistentVolumeClaim) { claim.Labels[platformkube.LabelGame] = "other" }, wantReason: arcadev1alpha1.ReasonRetainedDataConflict},
		{name: "wrong path", seedClaim: true, mutatePVC: func(claim *corev1.PersistentVolumeClaim) { claim.Labels[platformkube.LabelDataPath] = "other" }, wantReason: arcadev1alpha1.ReasonRetainedDataConflict},
		{name: "wrong storage class", seedClaim: true, mutatePVC: func(claim *corev1.PersistentVolumeClaim) {
			className := "other"
			claim.Spec.StorageClassName = &className
		}, wantReason: arcadev1alpha1.ReasonRetainedDataConflict},
		{name: "wrong access modes", seedClaim: true, mutatePVC: func(claim *corev1.PersistentVolumeClaim) {
			claim.Spec.AccessModes = []corev1.PersistentVolumeAccessMode{corev1.ReadWriteMany}
		}, wantReason: arcadev1alpha1.ReasonRetainedDataConflict},
		{name: "foreign owner", seedClaim: true, mutatePVC: func(claim *corev1.PersistentVolumeClaim) {
			claim.OwnerReferences = []metav1.OwnerReference{{Name: "unsafe", UID: "unsafe"}}
		}, wantReason: arcadev1alpha1.ReasonRetainedDataConflict},
		{name: "terminating", seedClaim: true, mutatePVC: func(claim *corev1.PersistentVolumeClaim) {
			now := metav1.Now()
			claim.DeletionTimestamp = &now
			claim.Finalizers = []string{"test.example/finalizer"}
		}, wantReason: arcadev1alpha1.ReasonRetainedDataConflict},
		{name: "too small", seedClaim: true, mutatePVC: func(claim *corev1.PersistentVolumeClaim) {
			claim.Spec.Resources.Requests[corev1.ResourceStorage] = resource.MustParse("5Gi")
			claim.Status.Capacity[corev1.ResourceStorage] = resource.MustParse("5Gi")
		}, wantReason: arcadev1alpha1.ReasonRetainedDataConflict},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			oldServer := controllerTestServer(arcadev1alpha1.DesiredStateRunning)
			oldServer.UID = "old-server-uid"
			claim := plannedBoundClaim(t, oldServer, "retained-pvc-uid")
			server := controllerTestServer(arcadev1alpha1.DesiredStateRunning)
			server.UID = "replacement-server-uid"
			server.Spec.Storage.Reattach = exactReattach(claim)
			if test.mutateRef != nil {
				test.mutateRef(server.Spec.Storage.Reattach)
			}
			if test.mutatePVC != nil {
				test.mutatePVC(claim)
			}
			objects := []client.Object{server}
			if test.seedClaim {
				objects = append(objects, claim)
			}
			reconciler, kubeClient := newTestReconciler(t, objects...)
			request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(server)}
			var before *corev1.PersistentVolumeClaim
			if test.seedClaim {
				before = &corev1.PersistentVolumeClaim{}
				assertObjectExists(t, kubeClient, client.ObjectKeyFromObject(claim), before)
			}
			if _, err := reconciler.Reconcile(context.Background(), request); err == nil {
				t.Fatal("Reconcile() error = nil, want retained-data refusal")
			}
			assertPhase(t, kubeClient, request.NamespacedName, arcadev1alpha1.PhaseFailed, metav1.ConditionFalse, test.wantReason)
			assertNoRuntime(t, kubeClient, request.NamespacedName)
			if !test.seedClaim {
				assertListLength(t, kubeClient, &corev1.PersistentVolumeClaimList{}, 0)
			} else {
				after := &corev1.PersistentVolumeClaim{}
				assertObjectExists(t, kubeClient, client.ObjectKeyFromObject(claim), after)
				if !reflect.DeepEqual(before, after) {
					t.Fatalf("retained-data refusal mutated claim: before=%#v after=%#v", before, after)
				}
			}
		})
	}
}

func TestReconcileRejectsAmbiguousRetainedDataSet(t *testing.T) {
	t.Parallel()

	oldServer := controllerTestServer(arcadev1alpha1.DesiredStateRunning)
	oldServer.UID = "old-server-uid"
	claim := plannedBoundClaim(t, oldServer, "retained-pvc-uid")
	extra := claim.DeepCopy()
	extra.Name = "unexpected-retained-claim"
	extra.UID = "extra-pvc-uid"
	server := controllerTestServer(arcadev1alpha1.DesiredStateRunning)
	server.UID = "replacement-server-uid"
	server.Spec.Storage.Reattach = exactReattach(claim)
	reconciler, kubeClient := newTestReconciler(t, server, claim, extra)
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(server)}
	beforeClaim := &corev1.PersistentVolumeClaim{}
	beforeExtra := &corev1.PersistentVolumeClaim{}
	assertObjectExists(t, kubeClient, client.ObjectKeyFromObject(claim), beforeClaim)
	assertObjectExists(t, kubeClient, client.ObjectKeyFromObject(extra), beforeExtra)

	if _, err := reconciler.Reconcile(context.Background(), request); err == nil {
		t.Fatal("Reconcile() error = nil, want ambiguous retained-data refusal")
	}
	assertPhase(t, kubeClient, request.NamespacedName, arcadev1alpha1.PhaseFailed, metav1.ConditionFalse, arcadev1alpha1.ReasonRetainedDataConflict)
	assertNoRuntime(t, kubeClient, request.NamespacedName)
	assertListLength(t, kubeClient, &corev1.PersistentVolumeClaimList{}, 2)
	afterClaim := &corev1.PersistentVolumeClaim{}
	afterExtra := &corev1.PersistentVolumeClaim{}
	assertObjectExists(t, kubeClient, client.ObjectKeyFromObject(claim), afterClaim)
	assertObjectExists(t, kubeClient, client.ObjectKeyFromObject(extra), afterExtra)
	if !reflect.DeepEqual(beforeClaim, afterClaim) || !reflect.DeepEqual(beforeExtra, afterExtra) {
		t.Fatalf("ambiguous retained-data refusal mutated claims: selected=%#v extra=%#v", afterClaim, afterExtra)
	}
}

func TestReconcilePreflightsAllFreshClaimsBeforeCreatingAny(t *testing.T) {
	t.Parallel()

	server := controllerTestServer(arcadev1alpha1.DesiredStateRunning)
	server.Spec.Game = "conformance-echo"
	server.Spec.Settings = runtime.RawExtension{Raw: []byte(`{}`)}
	definition := synthetic.Definition()
	definition.PersistentPaths = append(definition.PersistentPaths, game.PersistentPath{Name: "logs", MountPath: "/srv/logs"})
	conflict := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{
		Name: "factory-conformance-echo-logs", Namespace: server.Namespace,
		Labels: map[string]string{platformkube.LabelDataIdentity: "data-from-another-server"},
	}}
	reconciler, kubeClient := newTestReconciler(t, server, conflict)
	reconciler.Catalog = fixedCatalog{definition: definition}
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(server)}

	if _, err := reconciler.Reconcile(context.Background(), request); err == nil {
		t.Fatal("Reconcile() error = nil, want second-path collision")
	}
	assertPhase(t, kubeClient, request.NamespacedName, arcadev1alpha1.PhaseFailed, metav1.ConditionFalse, arcadev1alpha1.ReasonResourceCollision)
	assertListLength(t, kubeClient, &corev1.PersistentVolumeClaimList{}, 1)
	assertNoRuntime(t, kubeClient, request.NamespacedName)
}

func TestStorageClassCompatibility(t *testing.T) {
	t.Parallel()

	empty := ""
	standard := "standard"
	fast := "fast"
	tests := []struct {
		name     string
		existing *string
		desired  *string
		exact    bool
		want     bool
	}{
		{name: "fresh defaulted class", existing: &standard, desired: nil, want: true},
		{name: "exact requires observed class", existing: &standard, desired: nil, exact: true, want: false},
		{name: "explicit empty", existing: &empty, desired: &empty, exact: true, want: true},
		{name: "explicit empty rejects default", existing: &standard, desired: &empty, exact: true, want: false},
		{name: "named exact", existing: &fast, desired: &fast, exact: true, want: true},
		{name: "named mismatch", existing: &standard, desired: &fast, exact: true, want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := storageClassCompatible(test.existing, test.desired, test.exact); got != test.want {
				t.Fatalf("storageClassCompatible() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestReconcilePreflightRejectsForeignServiceAndRecovers(t *testing.T) {
	t.Parallel()

	server := controllerTestServer(arcadev1alpha1.DesiredStateRunning)
	foreign := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: server.Name, Namespace: server.Namespace}}
	reconciler, kubeClient := newTestReconciler(t, server, foreign)
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(server)}
	_, err := reconciler.Reconcile(context.Background(), request)
	if err == nil || !strings.Contains(err.Error(), "Service games/factory conflicts") {
		t.Fatalf("Reconcile() error = %v, want foreign-Service refusal", err)
	}
	assertListLength(t, kubeClient, &corev1.PersistentVolumeClaimList{}, 0)
	assertListLength(t, kubeClient, &corev1.ConfigMapList{}, 0)
	assertListLength(t, kubeClient, &appsv1.DeploymentList{}, 0)
	assertPhase(t, kubeClient, request.NamespacedName, arcadev1alpha1.PhaseFailed, metav1.ConditionFalse, arcadev1alpha1.ReasonResourceCollision)
	assertCondition(t, kubeClient, request.NamespacedName, arcadev1alpha1.ConditionNetworkReady, metav1.ConditionFalse, arcadev1alpha1.ReasonResourceCollision)
	if err := kubeClient.Delete(context.Background(), foreign); err != nil {
		t.Fatalf("resolve foreign Service collision: %v", err)
	}
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("collision-recovery Reconcile() error = %v", err)
	}
	assertPhase(t, kubeClient, request.NamespacedName, arcadev1alpha1.PhasePending, metav1.ConditionFalse, arcadev1alpha1.ReasonStoragePending)
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
		WithStatusSubresource(&arcadev1alpha1.GameServer{}, &appsv1.Deployment{}, &corev1.Service{}, &corev1.PersistentVolumeClaim{}).
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

type fixedCatalog struct {
	definition game.Definition
}

type configMapUpdateCountingClient struct {
	client.Client
	configMapUpdates int
}

type statusUpdateCountingClient struct {
	client.Client
	gameServerStatusUpdates int
}

type persistentClaimCreateFailingClient struct {
	client.Client
	failure error
}

func (c *persistentClaimCreateFailingClient) Create(ctx context.Context, object client.Object, options ...client.CreateOption) error {
	if _, ok := object.(*corev1.PersistentVolumeClaim); ok {
		return c.failure
	}
	return c.Client.Create(ctx, object, options...)
}

func (c *statusUpdateCountingClient) Status() client.SubResourceWriter {
	return &statusUpdateCountingWriter{delegate: c.Client.Status(), parent: c}
}

type statusUpdateCountingWriter struct {
	delegate client.SubResourceWriter
	parent   *statusUpdateCountingClient
}

func (writer *statusUpdateCountingWriter) Create(ctx context.Context, object client.Object, subResource client.Object, options ...client.SubResourceCreateOption) error {
	return writer.delegate.Create(ctx, object, subResource, options...)
}

func (writer *statusUpdateCountingWriter) Update(ctx context.Context, object client.Object, options ...client.SubResourceUpdateOption) error {
	if _, ok := object.(*arcadev1alpha1.GameServer); ok {
		writer.parent.gameServerStatusUpdates++
	}
	return writer.delegate.Update(ctx, object, options...)
}

func (writer *statusUpdateCountingWriter) Patch(ctx context.Context, object client.Object, patch client.Patch, options ...client.SubResourcePatchOption) error {
	return writer.delegate.Patch(ctx, object, patch, options...)
}

func (writer *statusUpdateCountingWriter) Apply(ctx context.Context, object runtime.ApplyConfiguration, options ...client.SubResourceApplyOption) error {
	return writer.delegate.Apply(ctx, object, options...)
}

func (c *configMapUpdateCountingClient) Update(ctx context.Context, object client.Object, options ...client.UpdateOption) error {
	if _, ok := object.(*corev1.ConfigMap); ok {
		c.configMapUpdates++
	}
	return c.Client.Update(ctx, object, options...)
}

func (c fixedCatalog) Get(string) (game.Definition, error) {
	return c.definition.Clone(), nil
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

func plannedBoundClaim(t *testing.T, server *arcadev1alpha1.GameServer, uid types.UID) *corev1.PersistentVolumeClaim {
	t.Helper()
	plan, err := platformkube.Build(server, factorio.Definition())
	if err != nil {
		t.Fatalf("build retained claim fixture: %v", err)
	}
	claim := plan.DataClaims[0].Desired.DeepCopy()
	claim.UID = uid
	claim.Status.Phase = corev1.ClaimBound
	claim.Status.Capacity = corev1.ResourceList{
		corev1.ResourceStorage: claim.Spec.Resources.Requests[corev1.ResourceStorage].DeepCopy(),
	}
	return claim
}

func exactReattach(claim *corev1.PersistentVolumeClaim) *arcadev1alpha1.RetainedDataReference {
	return &arcadev1alpha1.RetainedDataReference{
		Identity: claim.Labels[platformkube.LabelDataIdentity],
		Claims: []arcadev1alpha1.RetainedDataClaimReference{{
			Path: claim.Labels[platformkube.LabelDataPath],
			ClaimRef: arcadev1alpha1.ExactLocalReference{
				Name: claim.Name,
				UID:  string(claim.UID),
			},
		}},
	}
}

func assertNoRuntime(t *testing.T, kubeClient client.Client, serverKey types.NamespacedName) {
	t.Helper()
	assertNotFound(t, kubeClient, serverKey, &appsv1.Deployment{})
	assertNotFound(t, kubeClient, serverKey, &corev1.Service{})
	assertNotFound(t, kubeClient, types.NamespacedName{Namespace: serverKey.Namespace, Name: serverKey.Name + "-configuration"}, &corev1.ConfigMap{})
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

func markClaimBound(t *testing.T, kubeClient client.Client, key types.NamespacedName, capacity resource.Quantity) {
	t.Helper()
	claim := &corev1.PersistentVolumeClaim{}
	if err := kubeClient.Get(context.Background(), key, claim); err != nil {
		t.Fatalf("get PersistentVolumeClaim %s: %v", key, err)
	}
	claim.Status.Phase = corev1.ClaimBound
	claim.Status.Capacity = corev1.ResourceList{corev1.ResourceStorage: capacity}
	if err := kubeClient.Status().Update(context.Background(), claim); err != nil {
		t.Fatalf("mark PersistentVolumeClaim %s bound: %v", key, err)
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
	case *corev1.ConfigMapList:
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
	if len(server.Status.Conditions) != len(conditionOrder) {
		t.Fatalf("condition count = %d, want %d: %#v", len(server.Status.Conditions), len(conditionOrder), server.Status.Conditions)
	}
	for index, conditionType := range conditionOrder {
		condition := server.Status.Conditions[index]
		if condition.Type != conditionType || condition.ObservedGeneration != server.Generation {
			t.Fatalf("condition[%d] = %#v, want type %q generation %d", index, condition, conditionType, server.Generation)
		}
	}
	condition := meta.FindStatusCondition(server.Status.Conditions, arcadev1alpha1.ConditionReady)
	if condition == nil || condition.Status != status || condition.Reason != reason {
		t.Fatalf("Ready condition = %#v, want status %q reason %q", condition, status, reason)
	}
}

func assertCondition(t *testing.T, kubeClient client.Client, key types.NamespacedName, conditionType string, status metav1.ConditionStatus, reason string) {
	t.Helper()
	server := &arcadev1alpha1.GameServer{}
	if err := kubeClient.Get(context.Background(), key, server); err != nil {
		t.Fatalf("get GameServer status: %v", err)
	}
	condition := meta.FindStatusCondition(server.Status.Conditions, conditionType)
	if condition == nil || condition.Status != status || condition.Reason != reason || condition.ObservedGeneration != server.Generation {
		t.Fatalf("%s condition = %#v, want status %q reason %q generation %d", conditionType, condition, status, reason, server.Generation)
	}
}
