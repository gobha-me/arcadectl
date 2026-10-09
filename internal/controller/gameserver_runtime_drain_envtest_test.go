//go:build envtest

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"reflect"
	"testing"

	arcade "github.com/gobha-me/arcadectl/api/v1alpha1"
	"github.com/gobha-me/arcadectl/internal/catalog"
	platformkube "github.com/gobha-me/arcadectl/internal/platform/kube"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type runtimeApplyProbe struct {
	client.Client
	beforeApply  func(context.Context, client.Object)
	beforeDelete func(context.Context, client.Object)
	deleteError  error
}

func (p *runtimeApplyProbe) Patch(ctx context.Context, object client.Object, patch client.Patch, options ...client.PatchOption) error {
	if _, ok := object.(*appsv1.Deployment); ok && p.beforeApply != nil {
		p.beforeApply(ctx, object)
	}
	return p.Client.Patch(ctx, object, patch, options...)
}

func (p *runtimeApplyProbe) Delete(ctx context.Context, object client.Object, options ...client.DeleteOption) error {
	if _, ok := object.(*appsv1.Deployment); ok && p.beforeDelete != nil {
		p.beforeDelete(ctx, object)
	}
	p.deleteError = p.Client.Delete(ctx, object, options...)
	return p.deleteError
}

func testNativeWorkloadApplyIdentityFence(t *testing.T, ctx context.Context, api client.Client) {
	t.Helper()
	const namespace = "runtime-identity-fence"
	if err := api.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}); err != nil {
		t.Fatal(err)
	}
	for _, deleted := range []bool{false, true} {
		name := "workload-revision-race"
		if deleted {
			name = "workload-deletion-race"
		}
		t.Run(name, func(t *testing.T) {
			server := controllerTestServer(arcade.DesiredStateRunning)
			server.Namespace = namespace
			server.Name, server.UID, server.ResourceVersion = name, "", ""
			if err := api.Create(ctx, server); err != nil {
				t.Fatal(err)
			}
			games, err := catalog.Builtins()
			if err != nil {
				t.Fatal(err)
			}
			definition, err := games.Get(server.Spec.Game)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := platformkube.Build(server, definition)
			if err != nil {
				t.Fatal(err)
			}
			original := plan.Workload.DeepCopy()
			if err := api.Create(ctx, original); err != nil {
				t.Fatal(err)
			}
			probe := &runtimeApplyProbe{Client: api}
			calls := 0
			probe.beforeApply = func(ctx context.Context, seen client.Object) {
				calls++
				if seen.GetUID() != original.UID || seen.GetResourceVersion() != original.ResourceVersion {
					t.Fatal("Apply did not bind the exact original Deployment")
				}
				if deleted {
					if err := api.Delete(ctx, original, client.PropagationPolicy(metav1.DeletePropagationBackground)); err != nil {
						t.Fatal(err)
					}
				} else {
					changed := original.DeepCopy()
					changed.Annotations = map[string]string{"test.arcade.gobha.me/revision": "advanced"}
					if err := api.Update(ctx, changed); err != nil {
						t.Fatal(err)
					}
				}
			}
			r := &GameServerReconciler{Client: probe, APIReader: api}
			if _, err := r.reconcileDeployment(ctx, server, plan.Workload); err == nil {
				t.Fatal("stale native Apply was accepted")
			}
			if calls != 1 {
				t.Fatalf("Apply attempts=%d, want exactly one refused effect", calls)
			}
			got := &appsv1.Deployment{}
			err = api.Get(ctx, client.ObjectKeyFromObject(original), got)
			if deleted {
				if !apierrors.IsNotFound(err) {
					t.Fatalf("Apply recreated a disappeared original Deployment: %v", err)
				}
			} else if err != nil || got.UID != original.UID || got.Annotations["test.arcade.gobha.me/revision"] != "advanced" {
				t.Fatalf("Apply mutated the racing original: %v", err)
			}
		})
	}
	for _, replaced := range []bool{false, true} {
		name := "workload-stop-ownership-race"
		if replaced {
			name = "workload-stop-replacement-race"
		}
		t.Run(name, func(t *testing.T) {
			server := controllerTestServer(arcade.DesiredStateRunning)
			server.Name, server.Namespace, server.UID, server.ResourceVersion = name, namespace, "", ""
			if err := api.Create(ctx, server); err != nil {
				t.Fatal(err)
			}
			games, err := catalog.Builtins()
			if err != nil {
				t.Fatal(err)
			}
			definition, err := games.Get(server.Spec.Game)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := platformkube.Build(server, definition)
			if err != nil {
				t.Fatal(err)
			}
			original := plan.Workload.DeepCopy()
			if err := api.Create(ctx, original); err != nil {
				t.Fatal(err)
			}
			probe := &runtimeApplyProbe{Client: api}
			var raced *appsv1.Deployment
			calls := 0
			probe.beforeDelete = func(ctx context.Context, seen client.Object) {
				calls++
				if seen.GetUID() != original.UID || seen.GetResourceVersion() != original.ResourceVersion {
					t.Fatal("stop did not observe the original Deployment identity")
				}
				raced = original.DeepCopy()
				raced.OwnerReferences = nil
				if replaced {
					if err := api.Delete(ctx, original, client.PropagationPolicy(metav1.DeletePropagationBackground)); err != nil {
						t.Fatal(err)
					}
					raced.UID, raced.ResourceVersion = "", ""
					if err := api.Create(ctx, raced); err != nil {
						t.Fatal(err)
					}
					if raced.UID == original.UID {
						t.Fatal("native replacement lacks a distinct UID")
					}
				} else if err := api.Update(ctx, raced); err != nil {
					t.Fatal(err)
				}
				if raced.ResourceVersion == original.ResourceVersion {
					t.Fatal("native ownership drift lacks a changed revision")
				}
			}
			r := &GameServerReconciler{Client: probe, APIReader: api}
			if _, failure := r.deleteControlledRuntime(ctx, server); failure == nil || !apierrors.IsConflict(probe.deleteError) {
				t.Fatal("native stale foreground DELETE was not refused")
			}
			got := &appsv1.Deployment{}
			if err := api.Get(ctx, client.ObjectKeyFromObject(original), got); err != nil || !reflect.DeepEqual(got, raced) || got.DeletionTimestamp != nil {
				t.Fatalf("native stop changed the raced Deployment: %v", err)
			}
			if calls != 1 {
				t.Fatalf("foreground DELETE attempts=%d, want exactly one refused effect", calls)
			}
		})
	}
}
