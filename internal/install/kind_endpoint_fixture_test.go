// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package install

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	clienttesting "k8s.io/client-go/testing"
)

func kindEndpointAction(action string) bool {
	switch action {
	case "server.start", "server.configure", "server.restart", "server.update":
		return true
	}
	return false
}

// Test-only cloud-provider substitute. One attempt per bounded lifecycle poll:
// conflicts/disappearance are misses, never effect replay using stale state.
// No CREATE, adoption, spec mutation or production API behavior is supplied.
func provideOwnedKindEndpoint(ctx context.Context, services typedcorev1.ServiceInterface, namespace, name string, ownerUID types.UID) (bool, error) {
	if ctx == nil || services == nil || namespace == "" || name == "" || ownerUID == "" {
		return false, errors.New("endpoint fixture context invalid")
	}
	service, err := services.Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, kindEndpointFailure("read", err)
	}
	owner := metav1.GetControllerOf(service)
	if service.Namespace != namespace || service.Name != name || service.UID == "" || service.ResourceVersion == "" || !service.DeletionTimestamp.IsZero() ||
		service.Labels["app.kubernetes.io/instance"] != name || service.Spec.Type != corev1.ServiceTypeLoadBalancer ||
		service.Spec.ClusterIP == "" || service.Spec.ClusterIP == "None" || len(service.OwnerReferences) != 1 || owner == nil ||
		owner.APIVersion != "arcade.gobha.me/v1alpha1" || owner.Kind != "GameServer" || owner.Name != name || owner.UID != ownerUID {
		return false, errors.New("endpoint fixture original owner or Service identity invalid")
	}
	if len(service.Status.LoadBalancer.Ingress) == 1 && service.Status.LoadBalancer.Ingress[0].IP == service.Spec.ClusterIP {
		return true, nil
	}
	changed := service.DeepCopy()
	changed.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: service.Spec.ClusterIP}}
	_, err = services.UpdateStatus(ctx, changed, metav1.UpdateOptions{})
	if apierrors.IsConflict(err) || apierrors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, kindEndpointFailure("status", err)
	}
	return true, nil
}

// Fixed diagnostic vocabulary only. Raw Kubernetes errors may contain Secret,
// admission messages, URLs or other arbitrary data and must never be printed.
func kindEndpointFailure(stage string, err error) error {
	class := "other"
	switch {
	case apierrors.IsForbidden(err):
		class = "forbidden"
	case apierrors.IsUnauthorized(err):
		class = "unauthorized"
	case apierrors.IsTimeout(err), apierrors.IsServerTimeout(err), errors.Is(err, context.DeadlineExceeded):
		class = "timeout"
	case errors.Is(err, context.Canceled):
		class = "cancelled"
	case apierrors.IsInvalid(err):
		class = "invalid"
	}
	return errors.New("endpoint fixture " + stage + " failed: class=" + class + "; private error withheld")
}

func TestKindEndpointFixtureRereadsOnlyOriginalOwnedService(t *testing.T) {
	controller := true
	original := &corev1.Service{ObjectMeta: metav1.ObjectMeta{
		Name: "server", Namespace: "isolated", UID: "original-service", ResourceVersion: "17",
		Labels:          map[string]string{"app.kubernetes.io/instance": "server"},
		OwnerReferences: []metav1.OwnerReference{{APIVersion: "arcade.gobha.me/v1alpha1", Kind: "GameServer", Name: "server", UID: "original-server", Controller: &controller}},
	}, Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer, ClusterIP: "10.0.0.42"}}
	for _, mode := range []string{"healthy", "already-ready", "conflict", "disappeared", "foreign-owner", "no-owner", "wrong-namespace", "wrong-type", "wrong-owner-kind", "wrong-owner-name", "no-controller", "no-uid", "no-rv", "terminating", "read-forbidden", "status-forbidden"} {
		t.Run(mode, func(t *testing.T) {
			service := original.DeepCopy()
			switch mode {
			case "already-ready":
				service.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: service.Spec.ClusterIP}}
			case "foreign-owner":
				service.OwnerReferences[0].UID = "foreign-server"
			case "no-owner":
				service.OwnerReferences = nil
			case "wrong-namespace":
				service.Namespace = "foreign"
			case "wrong-type":
				service.Spec.Type = corev1.ServiceTypeClusterIP
			case "wrong-owner-kind":
				service.OwnerReferences[0].Kind = "Secret"
			case "wrong-owner-name":
				service.OwnerReferences[0].Name = "foreign"
			case "no-controller":
				service.OwnerReferences[0].Controller = nil
			case "no-uid":
				service.UID = ""
			case "no-rv":
				service.ResourceVersion = ""
			case "terminating":
				now := metav1.Now()
				service.DeletionTimestamp = &now
			}
			cluster := fake.NewClientset(service)
			reads, writes := 0, 0
			cluster.PrependReactor("get", "services", func(clienttesting.Action) (bool, runtime.Object, error) {
				reads++
				if mode == "read-forbidden" {
					return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "services"}, "PRIVATE-CANARY", errors.New("PRIVATE-CANARY"))
				}
				if mode == "wrong-namespace" {
					return true, service.DeepCopy(), nil
				}
				return false, nil, nil
			})
			cluster.PrependReactor("update", "services", func(action clienttesting.Action) (bool, runtime.Object, error) {
				writes++
				if action.GetSubresource() != "status" {
					t.Fatal("fixture gained a Service spec mutation")
				}
				candidate := action.(clienttesting.UpdateAction).GetObject().(*corev1.Service)
				if !reflect.DeepEqual(candidate.Spec, service.Spec) || !reflect.DeepEqual(candidate.ObjectMeta, service.ObjectMeta) {
					t.Fatal("endpoint fixture altered original Service spec or ownership metadata")
				}
				if candidate.UID != original.UID || candidate.ResourceVersion != service.ResourceVersion {
					t.Fatal("fixture replayed stale or foreign Service state")
				}
				if mode == "conflict" && writes == 1 {
					service.ResourceVersion = "18"
					if cluster.Tracker().Update(corev1.SchemeGroupVersion.WithResource("services"), service, service.Namespace) != nil {
						t.Fatal("owned conflict fixture unavailable")
					}
					return true, nil, apierrors.NewConflict(schema.GroupResource{Resource: "services"}, "PRIVATE-CANARY", errors.New("PRIVATE-CANARY"))
				}
				if mode == "disappeared" {
					if cluster.Tracker().Delete(corev1.SchemeGroupVersion.WithResource("services"), service.Namespace, service.Name) != nil {
						t.Fatal("owned disappearance fixture unavailable")
					}
					return true, nil, apierrors.NewNotFound(schema.GroupResource{Resource: "services"}, "PRIVATE-CANARY")
				}
				if mode == "status-forbidden" {
					return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "services"}, "PRIVATE-CANARY", errors.New("PRIVATE-CANARY"))
				}
				return false, nil, nil
			})
			services := cluster.CoreV1().Services(original.Namespace)
			ready, err := provideOwnedKindEndpoint(t.Context(), services, original.Namespace, service.Name, "original-server")
			wantError := mode != "healthy" && mode != "already-ready" && mode != "conflict" && mode != "disappeared"
			if (err != nil) != wantError || ready != (mode == "healthy" || mode == "already-ready") {
				t.Fatal("fixture mistook failure/drift/race for readiness")
			}
			if err != nil && strings.Contains(err.Error(), "PRIVATE-CANARY") {
				t.Fatal("private endpoint error escaped")
			}
			if (wantError && mode != "status-forbidden" || mode == "already-ready") && writes != 0 {
				t.Fatal("endpoint fixture wrote despite invalid/unneeded authority")
			}
			if mode == "conflict" || mode == "disappeared" {
				ready, err = provideOwnedKindEndpoint(t.Context(), services, service.Namespace, service.Name, "original-server")
				if err != nil || ready != (mode == "conflict") || reads != 2 || writes != map[string]int{"conflict": 2, "disappeared": 1}[mode] {
					t.Fatal("fixture did not independently reread after the bounded polling miss")
				}
			}
		})
	}
	for _, action := range []string{"server.stop", "server.decommission", "server.create", "unknown", ""} {
		if kindEndpointAction(action) {
			t.Fatal("fixture injects an endpoint during removal or unknown actions")
		}
	}
	for _, action := range []string{"server.start", "server.configure", "server.restart", "server.update"} {
		if !kindEndpointAction(action) {
			t.Fatal("fixture omitted an endpoint-producing action")
		}
	}
}
