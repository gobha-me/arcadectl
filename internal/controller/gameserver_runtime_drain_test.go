// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"errors"
	"testing"
	"time"

	arcade "github.com/gobha-me/arcadectl/api/v1alpha1"
	platformkube "github.com/gobha-me/arcadectl/internal/platform/kube"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func TestStopWaitsForOriginalRuntimePodAfterDeploymentDisappears(t *testing.T) {
	for _, terminating := range []bool{false, true} {
		name := "live"
		if terminating {
			name = "terminating"
		}
		t.Run(name, func(t *testing.T) {
			server := controllerTestServer(arcade.DesiredStateStopped)
			pod := drainTestPod(server, "original-runtime", "factory-factorio-world", false)
			if terminating {
				stamp := metav1.NewTime(time.Unix(1_700_000_000, 0))
				pod.DeletionTimestamp = &stamp
				pod.Finalizers = []string{"test.arcade.gobha.me/hold"}
			}
			r, kube := newTestReconciler(t, server, pod)
			request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(server)}
			result, err := r.Reconcile(context.Background(), request)
			if err != nil {
				t.Fatal(err)
			}
			if result.RequeueAfter <= 0 {
				t.Fatal("stop completed while the original runtime Pod still exists")
			}
			assertPhase(t, kube, request.NamespacedName, arcade.PhaseStopping, metav1.ConditionFalse, arcade.ReasonRuntimeStopping)
			observed := &corev1.Pod{}
			assertObjectExists(t, kube, client.ObjectKeyFromObject(pod), observed)
			if observed.UID != pod.UID {
				t.Fatal("stop changed the original runtime identity")
			}
			if terminating {
				observed.Finalizers = nil
				if err := kube.Update(context.Background(), observed); err != nil {
					t.Fatal(err)
				}
			} else if err := kube.Delete(context.Background(), observed); err != nil {
				t.Fatal(err)
			}
			if _, err := r.Reconcile(context.Background(), request); err != nil {
				t.Fatal(err)
			}
			assertPhase(t, kube, request.NamespacedName, arcade.PhaseStopped, metav1.ConditionFalse, arcade.ReasonRuntimeStopped)
		})
	}
}

func TestRuntimeDrainGuardsStoppedOriginalWorldWriters(t *testing.T) {
	for _, phase := range []corev1.PodPhase{corev1.PodRunning, corev1.PodSucceeded, corev1.PodFailed} {
		t.Run(string(phase), func(t *testing.T) {
			server := controllerTestServer(arcade.DesiredStateStopped)
			server.Status.ObservedData = &arcade.RetainedDataReference{Identity: "original-world", Claims: []arcade.RetainedDataClaimReference{{
				Path: "world", ClaimRef: arcade.ExactLocalReference{Name: "original-world", UID: "world-uid"},
			}}}
			pod := drainTestPod(server, "unlabelled-writer", "original-world", false)
			pod.Labels = nil
			pod.Status.Phase = phase
			r, kube := newTestReconciler(t, server, pod)
			// Drain is independent of adapter/spec validity.
			r.Catalog = nil
			request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(server)}
			result, err := r.Reconcile(context.Background(), request)
			if err != nil {
				t.Fatal(err)
			}
			assertNotFound(t, kube, request.NamespacedName, &appsv1.Deployment{})
			if result.RequeueAfter <= 0 {
				t.Fatal("stop skipped writer observation")
			}
			assertPhase(t, kube, request.NamespacedName, arcade.PhaseStopping, metav1.ConditionFalse, arcade.ReasonRuntimeStopping)
		})
	}
}

func TestStartDoesNotApplyTerminatingOriginalDeployment(t *testing.T) {
	server := controllerTestServer(arcade.DesiredStateRunning)
	r, _ := newTestReconciler(t, server)
	definition, err := r.Catalog.Get(server.Spec.Game)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := platformkube.Build(server, definition)
	if err != nil {
		t.Fatal(err)
	}
	original := plan.Workload.DeepCopy()
	original.UID = "terminating-original-deployment"
	stamp := metav1.NewTime(time.Unix(1_700_000_000, 0))
	original.DeletionTimestamp, original.Finalizers = &stamp, []string{"foregroundDeletion"}
	r, kube := newTestReconciler(t, server, original)
	applied := false
	r.Client = interceptor.NewClient(kube.(client.WithWatch), interceptor.Funcs{Patch: func(ctx context.Context, c client.WithWatch, object client.Object, patch client.Patch, opts ...client.PatchOption) error {
		if _, ok := object.(*appsv1.Deployment); ok {
			applied = true
		}
		return c.Patch(ctx, object, patch, opts...)
	}})
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(server)}
	result, err := r.Reconcile(context.Background(), request)
	if err != nil || result.RequeueAfter <= 0 || applied {
		t.Fatalf("terminating original: result=%v err=%v applied=%v", result, err, applied)
	}
	assertPhase(t, kube, request.NamespacedName, arcade.PhaseStopping, metav1.ConditionFalse, arcade.ReasonRuntimeStopping)
	observed := &appsv1.Deployment{}
	assertObjectExists(t, kube, request.NamespacedName, observed)
	if observed.UID != original.UID || observed.DeletionTimestamp == nil {
		t.Fatal("terminating original identity changed")
	}
	assertNotFound(t, kube, types.NamespacedName{Namespace: server.Namespace, Name: server.Name + "-configuration"}, &corev1.ConfigMap{})
}

func TestStartWaitsForRuntimeDrainBeforeConfigurationOrDeployment(t *testing.T) {
	for _, labelled := range []bool{false, true} {
		t.Run(map[bool]string{false: "unlabelled-world-writer", true: "labelled-runtime"}[labelled], func(t *testing.T) {
			server := controllerTestServer(arcade.DesiredStateRunning)
			pod := drainTestPod(server, "original-runtime", "factory-factorio-world", false)
			if !labelled {
				pod.Labels = nil
			}
			r, kube := newTestReconciler(t, server, pod)
			request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(server)}
			result, err := r.Reconcile(context.Background(), request)
			if err != nil || result.RequeueAfter <= 0 {
				t.Fatalf("draining start: result=%v err=%v", result, err)
			}
			assertPhase(t, kube, request.NamespacedName, arcade.PhaseStopping, metav1.ConditionFalse, arcade.ReasonRuntimeStopping)
			assertNotFound(t, kube, request.NamespacedName, &appsv1.Deployment{})
			assertNotFound(t, kube, types.NamespacedName{Namespace: server.Namespace, Name: server.Name + "-configuration"}, &corev1.ConfigMap{})
			if err := kube.Delete(context.Background(), pod); err != nil {
				t.Fatal(err)
			}
			if _, err := r.Reconcile(context.Background(), request); err != nil {
				t.Fatal(err)
			}
			assertObjectExists(t, kube, request.NamespacedName, &appsv1.Deployment{})
		})
	}
}

func TestRuntimeDrainWaitsForOriginalReplicaSetWithNoPods(t *testing.T) {
	for _, desired := range []arcade.DesiredState{arcade.DesiredStateRunning, arcade.DesiredStateStopped} {
		server := controllerTestServer(desired)
		pod := drainTestPod(server, "template", "factory-factorio-world", false)
		rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "old-replicaset", Namespace: server.Namespace}, Spec: appsv1.ReplicaSetSpec{
			Replicas: ptr.To(int32(1)),
			Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: pod.Labels}, Spec: pod.Spec},
		}}
		r, kube := newTestReconciler(t, server, rs)
		request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(server)}
		result, err := r.Reconcile(context.Background(), request)
		if err != nil || result.RequeueAfter <= 0 {
			t.Fatalf("producer drain: result=%v err=%v", result, err)
		}
		assertPhase(t, kube, request.NamespacedName, arcade.PhaseStopping, metav1.ConditionFalse, arcade.ReasonRuntimeStopping)
		assertNotFound(t, kube, request.NamespacedName, &appsv1.Deployment{})
		assertObjectExists(t, kube, client.ObjectKeyFromObject(rs), &appsv1.ReplicaSet{})
	}
}

func TestRuntimeDrainDoesNotConfuseRestoreCandidateWithOriginalWorld(t *testing.T) {
	server := controllerTestServer(arcade.DesiredStateStopped)
	original, err := platformkube.DataIdentity(server.UID)
	if err != nil {
		t.Fatal(err)
	}
	claims := []*corev1.PersistentVolumeClaim{}
	for name, identity := range map[string]string{"original": original, "candidate": "restore-candidate"} {
		claims = append(claims, &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: server.Namespace, Labels: map[string]string{
			platformkube.LabelManagedBy: platformkube.ManagerName, platformkube.LabelInstance: server.Name,
			platformkube.LabelDataPolicy: "retain", platformkube.LabelDataIdentity: identity,
		}}})
	}
	pod := drainTestPod(server, "restore-populate", "candidate", false)
	pod.Labels = nil
	r, _ := newTestReconciler(t, server, claims[0], claims[1], pod)
	remain, err := r.runtimePodsRemain(context.Background(), server, nil)
	if err != nil || remain {
		t.Fatalf("unselected restore candidate blocks original world: remain=%v err=%v", remain, err)
	}
	server.Status.ActiveData = &arcade.RetainedDataReference{Identity: "restore-candidate", Claims: []arcade.RetainedDataClaimReference{{ClaimRef: arcade.ExactLocalReference{Name: "candidate", UID: "candidate-uid"}}}}
	remain, err = r.runtimePodsRemain(context.Background(), server, nil)
	if err != nil || !remain {
		t.Fatalf("selected active candidate writer was not fenced: remain=%v err=%v", remain, err)
	}
}

func TestRuntimeDrainUsesUncachedPodObservation(t *testing.T) {
	server := controllerTestServer(arcade.DesiredStateStopped)
	r, kube := newTestReconciler(t, server)
	pod := drainTestPod(server, "cache-missed-runtime", "factory-factorio-world", false)
	_, fresh := newTestReconciler(t, pod)
	r.APIReader = fresh
	result, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(server)})
	if err != nil || result.RequeueAfter <= 0 {
		t.Fatalf("uncached stop: result=%v err=%v", result, err)
	}
	assertPhase(t, kube, client.ObjectKeyFromObject(server), arcade.PhaseStopping, metav1.ConditionFalse, arcade.ReasonRuntimeStopping)
}

func TestRuntimeDrainRefusesFailedOrIncompleteObservation(t *testing.T) {
	for _, resource := range []string{"claims", "replicasets", "pods"} {
		for _, failure := range []string{"error", "continue", "remaining"} {
			t.Run(resource+"/"+failure, func(t *testing.T) {
				server := controllerTestServer(arcade.DesiredStateStopped)
				r, kube := newTestReconciler(t, server)
				r.APIReader = interceptor.NewClient(kube.(client.WithWatch), interceptor.Funcs{List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
					options := (&client.ListOptions{}).ApplyOptions(opts)
					if options.Namespace != server.Namespace {
						t.Fatal("drain observation escaped the server namespace")
					}
					kind := ""
					switch list.(type) {
					case *corev1.PersistentVolumeClaimList:
						kind = "claims"
					case *appsv1.ReplicaSetList:
						kind = "replicasets"
					case *corev1.PodList:
						kind = "pods"
					}
					if kind == resource {
						metadata := list.(metav1.ListInterface)
						switch failure {
						case "continue":
							metadata.SetContinue("next-page")
						case "remaining":
							metadata.SetRemainingItemCount(ptr.To(int64(1)))
						default:
							return errors.New("injected observation failure")
						}
						return nil
					}
					return c.List(ctx, list, opts...)
				}})
				_, _ = r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(server)})
				stored := &arcade.GameServer{}
				assertObjectExists(t, kube, client.ObjectKeyFromObject(server), stored)
				if stored.Status.Phase == arcade.PhaseStopped {
					t.Fatal("unverified Pod absence was reported stopped")
				}
			})
		}
	}
}

func TestRuntimeReadonlyEvidenceCoversEveryContainerAndDevice(t *testing.T) {
	for _, kind := range []string{"source", "regular", "init", "ephemeral", "device"} {
		t.Run(kind, func(t *testing.T) {
			server := controllerTestServer(arcade.DesiredStateStopped)
			pod := drainTestPod(server, "readonly-backup", "world", true)
			pod.Spec.Containers = []corev1.Container{{Name: "reader", VolumeMounts: []corev1.VolumeMount{{Name: "world", ReadOnly: true}}}}
			if !runtimeVolumeReadOnly(pod.Spec, pod.Spec.Volumes[0]) {
				t.Fatal("genuinely readonly worker was rejected")
			}
			switch kind {
			case "source":
				pod.Spec.Volumes[0].PersistentVolumeClaim.ReadOnly = false
			case "regular":
				pod.Spec.Containers[0].VolumeMounts[0].ReadOnly = false
			case "init":
				pod.Spec.InitContainers = []corev1.Container{{Name: "init", VolumeMounts: []corev1.VolumeMount{{Name: "world"}}}}
			case "ephemeral":
				pod.Spec.EphemeralContainers = []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{
					Name: "ephemeral", VolumeMounts: []corev1.VolumeMount{{Name: "world"}},
				}}}
			case "device":
				pod.Spec.Containers[0].VolumeDevices = []corev1.VolumeDevice{{Name: "world", DevicePath: "/dev/world"}}
			}
			if runtimeVolumeReadOnly(pod.Spec, pod.Spec.Volumes[0]) {
				t.Fatal("potential writable mount was allowed through readonly exception")
			}
		})
	}
}

func TestRuntimeDrainPreservesReadonlyBackupAuditPods(t *testing.T) {
	server := controllerTestServer(arcade.DesiredStateStopped)
	server.Status.ObservedData = &arcade.RetainedDataReference{Claims: []arcade.RetainedDataClaimReference{{ClaimRef: arcade.ExactLocalReference{Name: "world", UID: "world-uid"}}}}
	pod := drainTestPod(server, "completed-backup", "world", true)
	pod.Labels[platformkube.LabelName] = "game-backup"
	pod.Status.Phase = corev1.PodSucceeded
	pod.Spec.Containers = []corev1.Container{{Name: "backup", VolumeMounts: []corev1.VolumeMount{{Name: "world", ReadOnly: true}}}}
	r, _ := newTestReconciler(t, server, pod)
	remain, err := r.runtimePodsRemain(context.Background(), server, nil)
	if err != nil || remain {
		t.Fatalf("readonly audit Pod blocked lifecycle: remain=%v err=%v", remain, err)
	}
	pod.Spec.InitContainers = []corev1.Container{{Name: "writer", VolumeMounts: []corev1.VolumeMount{{Name: "world"}}}}
	if runtimeVolumeReadOnly(pod.Spec, pod.Spec.Volumes[0]) {
		t.Fatal("writable init-container mount was treated as a readonly backup")
	}
}

func TestStopDeletesOriginalDeploymentWithForegroundIdentityFence(t *testing.T) {
	server := controllerTestServer(arcade.DesiredStateStopped)
	deployment := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: server.Name, Namespace: server.Namespace, UID: "original-deployment",
		OwnerReferences: []metav1.OwnerReference{{APIVersion: arcade.GroupVersion.String(), Kind: "GameServer", Name: server.Name, UID: server.UID, Controller: boolPointer(true)}},
	}}
	r, kube := newTestReconciler(t, server, deployment)
	observed := false
	r.Client = interceptor.NewClient(kube.(client.WithWatch), interceptor.Funcs{Delete: func(ctx context.Context, c client.WithWatch, object client.Object, opts ...client.DeleteOption) error {
		if _, ok := object.(*appsv1.Deployment); ok {
			observed = true
			options := (&client.DeleteOptions{}).ApplyOptions(opts)
			if options.PropagationPolicy == nil || *options.PropagationPolicy != metav1.DeletePropagationForeground ||
				options.Preconditions == nil || options.Preconditions.UID == nil || *options.Preconditions.UID != object.GetUID() ||
				options.Preconditions.ResourceVersion == nil || *options.Preconditions.ResourceVersion != object.GetResourceVersion() {
				t.Fatal("original Deployment deletion lacked foreground UID/RV fencing")
			}
		}
		return c.Delete(ctx, object, opts...)
	}})
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(server)}); err != nil {
		t.Fatal(err)
	}
	if !observed {
		t.Fatal("owned Deployment was not deleted")
	}
}

func drainTestPod(server *arcade.GameServer, name, claim string, readOnly bool) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: server.Namespace, UID: "original-pod-uid", Labels: map[string]string{
			platformkube.LabelManagedBy: platformkube.ManagerName,
			platformkube.LabelName:      "game-server", platformkube.LabelInstance: server.Name,
		}},
		Spec: corev1.PodSpec{Volumes: []corev1.Volume{{Name: "world", VolumeSource: corev1.VolumeSource{
			PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: claim, ReadOnly: readOnly},
		}}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
}
