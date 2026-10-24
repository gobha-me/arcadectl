// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"errors"
	"strings"
	"testing"

	arcade "github.com/gobha-me/arcadectl/api/v1alpha1"
	"github.com/gobha-me/arcadectl/internal/games/factorio"
	platformkube "github.com/gobha-me/arcadectl/internal/platform/kube"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// The backing fake is the live API. Only the manager client's Deployment GET
// is a frozen cache entry. Writes still reach the backing API, so an SSA
// response or a fresh read cannot be manufactured by reading that old entry.
type workloadObservationCache struct {
	client.Client
	cached                                                   *appsv1.Deployment
	cachedPostApplyGets, deploymentPatches, creates, deletes int
	afterApply                                               func(context.Context)
}

func (c *workloadObservationCache) Get(ctx context.Context, key client.ObjectKey, object client.Object, opts ...client.GetOption) error {
	if deployment, ok := object.(*appsv1.Deployment); ok && key == client.ObjectKeyFromObject(c.cached) {
		// The existing running-server ownership preflight intentionally uses
		// the cache before Apply. Only a later cached read can lend old
		// readiness to the newly acknowledged workload generation.
		if c.deploymentPatches > 0 {
			c.cachedPostApplyGets++
		}
		*deployment = *c.cached.DeepCopy()
		return nil
	}
	return c.Client.Get(ctx, key, object, opts...)
}

func (c *workloadObservationCache) Patch(ctx context.Context, object client.Object, patch client.Patch, opts ...client.PatchOption) error {
	_, workload := object.(*appsv1.Deployment)
	if workload {
		if patch.Type() != types.ApplyPatchType {
			return errors.New("unexpected workload patch type")
		}
		// Delegate the actual write and native UID/generation bookkeeping to
		// newTestReconciler's shared fake SSA adapter. This wrapper models only
		// an independently stale manager cache and counts effects.
		c.deploymentPatches++
	}
	if err := c.Client.Patch(ctx, object, patch, opts...); err != nil {
		return err
	}
	if workload && c.afterApply != nil {
		c.afterApply(ctx)
	}
	return nil
}

func (c *workloadObservationCache) Create(ctx context.Context, object client.Object, opts ...client.CreateOption) error {
	c.creates++
	return c.Client.Create(ctx, object, opts...)
}

func (c *workloadObservationCache) Delete(ctx context.Context, object client.Object, opts ...client.DeleteOption) error {
	c.deletes++
	return c.Client.Delete(ctx, object, opts...)
}

type workloadObservationReader struct {
	client.Reader
	cache          *workloadObservationCache
	postApplyError error
	postApplyGets  int
}

func (r *workloadObservationReader) Get(ctx context.Context, key client.ObjectKey, object client.Object, opts ...client.GetOption) error {
	if _, ok := object.(*appsv1.Deployment); ok && r.cache.deploymentPatches > 0 {
		r.postApplyGets++
		if r.postApplyError != nil {
			return r.postApplyError
		}
	}
	return r.Reader.Get(ctx, key, object, opts...)
}

func workloadObservationFixture(t *testing.T) (*GameServerReconciler, client.Client, *workloadObservationCache, *workloadObservationReader, ctrl.Request) {
	t.Helper()
	server := controllerTestServer(arcade.DesiredStateRunning)
	plan, err := platformkube.Build(server, factorio.Definition())
	if err != nil {
		t.Fatal(err)
	}
	deployment := plan.Workload.DeepCopy()
	deployment.UID, deployment.Generation = "original-runtime-uid", 1
	deployment.Status = appsv1.DeploymentStatus{ObservedGeneration: 1, Replicas: 1, UpdatedReplicas: 1, ReadyReplicas: 1, AvailableReplicas: 1}
	service := plan.PlayerService.DeepCopy()
	service.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "192.0.2.40"}}
	claim := plannedBoundClaim(t, server, "original-world-uid")
	r, live := newTestReconciler(t, server, deployment, service, plan.Configuration.DeepCopy(), claim)
	cache := &workloadObservationCache{Client: live, cached: deployment.DeepCopy()}
	reader := &workloadObservationReader{Reader: live, cache: cache}
	r.Client, r.APIReader = cache, reader
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(server)}
	if _, err := r.Reconcile(t.Context(), request); err != nil {
		t.Fatal("initial available workload fixture refused", err)
	}
	assertPhase(t, live, request.NamespacedName, arcade.PhaseReady, metav1.ConditionTrue, arcade.ReasonReady)
	cache.cachedPostApplyGets, cache.deploymentPatches, cache.creates, cache.deletes = 0, 0, 0, 0
	reader.postApplyGets = 0
	return r, live, cache, reader, request
}

func workloadObservationChangeSettings(t *testing.T, live client.Client, request ctrl.Request) {
	t.Helper()
	server := &arcade.GameServer{}
	if err := live.Get(t.Context(), request.NamespacedName, server); err != nil {
		t.Fatal(err)
	}
	server.Spec.Settings.Raw = []byte(`{"name":"updated","maxPlayers":8,"visibility":"private"}`)
	server.Generation = 2 // fake client does not increment metadata.generation
	if err := live.Update(t.Context(), server); err != nil {
		t.Fatal(err)
	}
}

func TestReconcileSettingsReadinessUsesLiveAppliedWorkloadGeneration(t *testing.T) {
	r, live, cache, reader, request := workloadObservationFixture(t)
	workloadObservationChangeSettings(t, live, request)
	if _, err := r.Reconcile(t.Context(), request); err != nil {
		t.Fatal("settings reconciliation failed", err)
	}
	deployment := &appsv1.Deployment{}
	if err := live.Get(t.Context(), request.NamespacedName, deployment); err != nil {
		t.Fatal(err)
	}
	oldHash := cache.cached.Spec.Template.Annotations[platformkube.AnnotationConfigurationHash]
	newHash := deployment.Spec.Template.Annotations[platformkube.AnnotationConfigurationHash]
	if deployment.Generation != 2 || deployment.Status.ObservedGeneration != 1 || oldHash == "" || oldHash == newHash || cache.deploymentPatches != 1 || cache.creates != 0 || cache.deletes != 0 {
		t.Fatal("fixture did not apply a genuinely new workload while retaining old ready status")
	}
	assertPhase(t, live, request.NamespacedName, arcade.PhaseStarting, metav1.ConditionFalse, arcade.ReasonWorkloadPending)
	assertCondition(t, live, request.NamespacedName, arcade.ConditionWorkloadReady, metav1.ConditionFalse, arcade.ReasonWorkloadProgressing)
	server := &arcade.GameServer{}
	if err := live.Get(t.Context(), request.NamespacedName, server); err != nil || server.Status.ObservedGeneration != 2 || len(server.Status.Endpoints) != 0 {
		t.Fatal("new server generation inherited stale readiness or endpoints", err)
	}
	if cache.cachedPostApplyGets != 0 || reader.postApplyGets != 1 {
		t.Fatal("post-apply readiness used the cache or omitted the live observation")
	}
	// All old replica counts were already one; only native observation of the
	// applied generation permits readiness. Keep the cached old object frozen.
	deployment.Status.ObservedGeneration = 2
	deployment.Status.UpdatedReplicas = 0
	if err := live.Status().Update(t.Context(), deployment); err != nil {
		t.Fatal(err)
	}
	cache.deploymentPatches, reader.postApplyGets = 0, 0
	if _, err := r.Reconcile(t.Context(), request); err != nil {
		t.Fatal("observed but incomplete rollout failed", err)
	}
	assertPhase(t, live, request.NamespacedName, arcade.PhaseStarting, metav1.ConditionFalse, arcade.ReasonWorkloadPending)
	if err := live.Get(t.Context(), request.NamespacedName, deployment); err != nil {
		t.Fatal(err)
	}
	deployment.Status.UpdatedReplicas = 1
	if err := live.Status().Update(t.Context(), deployment); err != nil {
		t.Fatal(err)
	}
	cache.deploymentPatches, reader.postApplyGets = 0, 0
	if _, err := r.Reconcile(t.Context(), request); err != nil {
		t.Fatal("current live rollout did not recover", err)
	}
	assertPhase(t, live, request.NamespacedName, arcade.PhaseReady, metav1.ConditionTrue, arcade.ReasonReady)
	if cache.cached.Generation != 1 || cache.cachedPostApplyGets != 0 || reader.postApplyGets != 1 {
		t.Fatal("ready result depended on cache convergence")
	}
}

func TestReconcileAppliedWorkloadReadErrorAndIdentityDriftNeverUseCachedReady(t *testing.T) {
	for _, fault := range []string{"read-error", "not-found", "replacement", "owner", "advanced-generation", "deleting"} {
		t.Run(fault, func(t *testing.T) {
			r, live, cache, reader, request := workloadObservationFixture(t)
			workloadObservationChangeSettings(t, live, request)
			cache.afterApply = func(ctx context.Context) {
				if fault == "read-error" {
					reader.postApplyError = errors.New("PRIVATE-read-error-canary")
					return
				}
				if fault == "not-found" {
					reader.postApplyError = apierrors.NewNotFound(schema.GroupResource{Group: "apps", Resource: "deployments"}, request.Name)
					return
				}
				changed := &appsv1.Deployment{}
				if err := live.Get(ctx, request.NamespacedName, changed); err != nil {
					t.Error(err)
					return
				}
				if fault == "replacement" {
					if err := live.Delete(ctx, changed); err != nil {
						t.Error(err)
						return
					}
					changed.UID, changed.ResourceVersion = "replacement-runtime-uid", ""
					if err := live.Create(ctx, changed); err != nil {
						t.Error(err)
					}
				} else if fault == "owner" {
					changed.OwnerReferences[0].UID = "foreign-server-uid"
					if err := live.Update(ctx, changed); err != nil {
						t.Error(err)
					}
				} else if fault == "advanced-generation" {
					changed.Generation++
					changed.Spec.Template.Annotations["test.arcade.gobha.me/revision"] = "concurrent-revision"
					if err := live.Update(ctx, changed); err != nil {
						t.Error(err)
						return
					}
					changed.Status.ObservedGeneration = changed.Generation
					if err := live.Status().Update(ctx, changed); err != nil {
						t.Error(err)
					}
				} else {
					changed.Finalizers = []string{"test.arcade.gobha.me/hold"}
					if err := live.Update(ctx, changed); err != nil {
						t.Error(err)
						return
					}
					if err := live.Delete(ctx, changed); err != nil {
						t.Error(err)
					}
				}
			}
			result, err := r.Reconcile(t.Context(), request)
			if fault == "deleting" {
				if err != nil || result.RequeueAfter <= 0 {
					t.Fatal("post-apply termination did not preserve drain observation", err)
				}
				assertPhase(t, live, request.NamespacedName, arcade.PhaseStopping, metav1.ConditionFalse, arcade.ReasonRuntimeStopping)
			} else {
				if err == nil {
					t.Fatal("post-apply observation failure was accepted")
				}
				assertPhase(t, live, request.NamespacedName, arcade.PhaseFailed, metav1.ConditionFalse, arcade.ReasonReconcileFailed)
				assertCondition(t, live, request.NamespacedName, arcade.ConditionWorkloadReady, metav1.ConditionFalse, arcade.ReasonWorkloadOperationFailed)
			}
			server := &arcade.GameServer{}
			if err := live.Get(t.Context(), request.NamespacedName, server); err != nil || len(server.Status.Endpoints) != 0 {
				t.Fatal("failed observation published endpoints", err)
			}
			for _, condition := range server.Status.Conditions {
				if strings.Contains(condition.Message, "PRIVATE") {
					t.Fatal("private observation error entered public status")
				}
			}
			if cache.deploymentPatches != 1 || cache.cachedPostApplyGets != 0 || reader.postApplyGets != 1 || cache.creates != 0 || cache.deletes != 0 {
				t.Fatal("post-apply failure retried an effect or fell back to cached readiness")
			}
		})
	}
}

func TestReconcileAppliedWorkloadAllowsStatusResourceVersionAdvance(t *testing.T) {
	r, live, cache, reader, request := workloadObservationFixture(t)
	workloadObservationChangeSettings(t, live, request)
	cache.afterApply = func(ctx context.Context) {
		deployment := &appsv1.Deployment{}
		if err := live.Get(ctx, request.NamespacedName, deployment); err != nil {
			t.Error(err)
			return
		}
		deployment.Status.ObservedGeneration = deployment.Generation
		if err := live.Status().Update(ctx, deployment); err != nil {
			t.Error(err)
		}
	}
	if _, err := r.Reconcile(t.Context(), request); err != nil {
		t.Fatal("same-identity applied generation rejected native status progress", err)
	}
	assertPhase(t, live, request.NamespacedName, arcade.PhaseReady, metav1.ConditionTrue, arcade.ReasonReady)
	if cache.cachedPostApplyGets != 0 || cache.deploymentPatches != 1 || reader.postApplyGets != 1 || cache.creates != 0 || cache.deletes != 0 {
		t.Fatal("status progress changed live read/effect boundaries")
	}
}

func TestControllerFakeWorkloadMetadataFollowsNativeSpecGeneration(t *testing.T) {
	server := controllerTestServer(arcade.DesiredStateRunning)
	_, live := newTestReconciler(t, server)
	plan, err := platformkube.Build(server, factorio.Definition())
	if err != nil {
		t.Fatal(err)
	}
	deployment := plan.Workload.DeepCopy()
	if err := live.Create(t.Context(), deployment); err != nil {
		t.Fatal(err)
	}
	uid := deployment.UID
	if uid == "" || deployment.Generation != 1 {
		t.Fatal("fake Create did not return native Deployment identity/generation")
	}
	deployment.Labels["test.arcade.gobha.me/metadata"] = "changed"
	deployment.Generation = 0 // generated Apply requests omit server generation
	if err := live.Patch(t.Context(), deployment, client.Apply); err != nil || deployment.UID != uid || deployment.Generation != 1 {
		t.Fatal("labels-only Apply changed generation or lost acknowledgement metadata", err)
	}
	deployment.Annotations = map[string]string{"test.arcade.gobha.me/metadata": "changed"}
	deployment.Generation = 0
	if err := live.Patch(t.Context(), deployment, client.Apply); err != nil || deployment.UID != uid || deployment.Generation != 2 {
		t.Fatal("Deployment annotation Apply did not advance generation", err)
	}
	deployment.Spec.Template.Annotations["test.arcade.gobha.me/revision"] = "changed"
	deployment.Generation = 0
	deployment.UID = ""
	if err := live.Patch(t.Context(), deployment, client.Apply); err != nil || deployment.UID != uid || deployment.Generation != 3 {
		t.Fatal("spec Apply did not preserve native UID and advance generation", err)
	}
	beforeStatusRV := deployment.ResourceVersion
	deployment.Status.ObservedGeneration = deployment.Generation
	if err := live.Status().Update(t.Context(), deployment); err != nil || deployment.UID != uid || deployment.Generation != 3 || deployment.ResourceVersion == beforeStatusRV {
		t.Fatal("status progress did not retain generation while advancing resourceVersion", err)
	}
	deployment.Generation = 0
	if err := live.Patch(t.Context(), deployment, client.Apply); err != nil || deployment.UID != uid || deployment.Generation != 3 {
		t.Fatal("identical Apply advanced generation or lost acknowledgement metadata", err)
	}
	if err := live.Delete(t.Context(), deployment); err != nil {
		t.Fatal(err)
	}
	replacement := plan.Workload.DeepCopy()
	if err := live.Create(t.Context(), replacement); err != nil || replacement.UID == "" || replacement.UID == uid || replacement.Generation != 1 {
		t.Fatal("same-name recreation reused the old native identity", err)
	}
}
