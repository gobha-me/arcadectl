//go:build kindinstall

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
)

// Only disposable native-GC fixture readiness. Pod Running does not establish
// settled Deployment status. Never adopt replacement/spec/generation drift,
// cache authority, remove an RV precondition or repeat a refused DELETE.
func gcDeleteReadyNodeDeployment(ctx context.Context, admin *kubernetes.Clientset, original *appsv1.Deployment) error {
	if ctx == nil || admin == nil || original == nil || original.UID == "" || original.Name == "" || original.Namespace == "" || original.Generation <= 0 || original.Spec.Replicas == nil || *original.Spec.Replicas != 1 {
		return ErrOutcomeUnknown
	}
	var live *appsv1.Deployment
	previousRV := ""
	err := wait.PollUntilContextTimeout(ctx, 200*time.Millisecond, 30*time.Second, true, func(ctx context.Context) (bool, error) {
		current, err := admin.AppsV1().Deployments(original.Namespace).Get(ctx, original.Name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		if current.Name != original.Name || current.Namespace != original.Namespace || current.UID != original.UID || current.Generation != original.Generation || current.ResourceVersion == "" || current.DeletionTimestamp != nil || !reflect.DeepEqual(current.Spec, original.Spec) {
			return false, ErrOutcomeUnknown
		}
		status := current.Status
		if status.ObservedGeneration != original.Generation || status.Replicas != 1 || status.UpdatedReplicas != 1 || status.ReadyReplicas != 1 || status.AvailableReplicas != 1 || status.UnavailableReplicas != 0 {
			previousRV = ""
			return false, nil
		}
		settled := previousRV == current.ResourceVersion
		previousRV, live = current.ResourceVersion, current
		return settled, nil
	})
	if err != nil {
		return err
	}
	if live == nil || ctx.Err() != nil {
		return ErrOutcomeUnknown
	}
	uid, rv, foreground := live.UID, live.ResourceVersion, metav1.DeletePropagationForeground
	options := metav1.DeleteOptions{PropagationPolicy: &foreground, Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &rv}}
	// The SDK's typed DELETE may replay Retry-After responses. This fixture
	// performs one actual mutation, including on throttling or unavailability.
	return admin.AppsV1().RESTClient().Delete().Namespace(original.Namespace).Resource("deployments").Name(original.Name).Body(&options).MaxRetries(0).Do(ctx).Error()
}

// Also called inside the mandatory native GC root; this separate tagged root
// allows hermetic normal/race checks without creating a cluster.
func TestGCNodeDeleteControls(t *testing.T) { testGCNodeDeleteControls(t) }

func testGCNodeDeleteControls(t *testing.T) {
	original := &appsv1.Deployment{TypeMeta: metav1.TypeMeta{APIVersion: "apps/v1", Kind: "Deployment"}, ObjectMeta: metav1.ObjectMeta{Namespace: "owned-ns", Name: "owned-deployment", UID: types.UID("original-uid"), ResourceVersion: "1", Generation: 1}, Spec: appsv1.DeploymentSpec{Replicas: ptr.To(int32(1))}}
	ready := func(rv string) *appsv1.Deployment {
		live := original.DeepCopy()
		live.ResourceVersion = rv
		live.Status = appsv1.DeploymentStatus{ObservedGeneration: 1, Replicas: 1, UpdatedReplicas: 1, ReadyReplicas: 1, AvailableReplicas: 1}
		return live
	}
	for _, scenario := range []string{"evolving-status", "ready-rv-change", "readiness-regression", "replacement", "spec-drift", "generation-drift", "deleting", "empty-rv", "get-forbidden", "delete-conflict", "delete-forbidden", "delete-throttled", "delete-canary"} {
		t.Run(scenario, func(t *testing.T) {
			var mu sync.Mutex
			gets, deletes := 0, 0
			var sent metav1.DeleteOptions
			wireValid := true
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path != "/apis/apps/v1/namespaces/owned-ns/deployments/owned-deployment" || r.URL.RawQuery != "" {
					wireValid = false
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				statusError := func(code int, reason metav1.StatusReason) {
					w.WriteHeader(code)
					_ = json.NewEncoder(w).Encode(metav1.Status{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: metav1.StatusFailure, Code: int32(code), Reason: reason, Message: "fixture-sensitive-private-canary"})
				}
				switch r.Method {
				case http.MethodGet:
					gets++
					if scenario == "get-forbidden" {
						statusError(http.StatusForbidden, metav1.StatusReasonForbidden)
						return
					}
					live := ready("3")
					switch scenario {
					case "evolving-status":
						if gets == 1 {
							live.ResourceVersion, live.Status.ObservedGeneration = "2", 0
						}
					case "ready-rv-change":
						if gets == 1 {
							live.ResourceVersion = "2"
						}
					case "readiness-regression":
						if gets == 2 {
							live.Status.ReadyReplicas, live.Status.AvailableReplicas = 0, 0
						}
					case "replacement":
						live.UID = "foreign-uid"
					case "spec-drift":
						live.Spec.Replicas = ptr.To(int32(2))
					case "generation-drift":
						live.Generation = 2
					case "deleting":
						now := metav1.Now()
						live.DeletionTimestamp = &now
					case "empty-rv":
						live.ResourceVersion = ""
					}
					_ = json.NewEncoder(w).Encode(live)
				case http.MethodDelete:
					deletes++
					decoder := json.NewDecoder(io.LimitReader(r.Body, 4096))
					decoder.DisallowUnknownFields()
					if decoder.Decode(&sent) != nil || decoder.Decode(new(any)) != io.EOF {
						wireValid = false
					}
					switch scenario {
					case "delete-conflict":
						statusError(http.StatusConflict, metav1.StatusReasonConflict)
					case "delete-forbidden":
						statusError(http.StatusForbidden, metav1.StatusReasonForbidden)
					case "delete-canary":
						w.Header().Set("Retry-After", "1")
						statusError(http.StatusServiceUnavailable, metav1.StatusReasonServiceUnavailable)
					case "delete-throttled":
						w.Header().Set("Retry-After", "1")
						statusError(http.StatusTooManyRequests, metav1.StatusReasonTooManyRequests)
					default:
						_ = json.NewEncoder(w).Encode(metav1.Status{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: metav1.StatusSuccess})
					}
				default:
					wireValid = false
					w.WriteHeader(http.StatusBadRequest)
				}
			}))
			defer server.Close()
			client, err := kubernetes.NewForConfig(&rest.Config{Host: server.URL, ContentConfig: rest.ContentConfig{ContentType: "application/json", AcceptContentTypes: "application/json"}, TLSClientConfig: rest.TLSClientConfig{Insecure: true}})
			if err != nil {
				t.Fatal("owned diagnostic client unavailable")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			err = gcDeleteReadyNodeDeployment(ctx, client, original)
			mu.Lock()
			defer mu.Unlock()
			expectSuccess := scenario == "evolving-status" || scenario == "ready-rv-change" || scenario == "readiness-regression"
			expectDelete := expectSuccess || strings.HasPrefix(scenario, "delete-")
			if !wireValid || gets == 0 || deletes != 0 && !expectDelete || expectDelete && deletes != 1 || (err == nil) != expectSuccess {
				t.Fatal("readiness/refusal gained an unexpected DELETE or result")
			}
			if expectDelete && (sent.PropagationPolicy == nil || *sent.PropagationPolicy != metav1.DeletePropagationForeground || sent.Preconditions == nil || sent.Preconditions.UID == nil || *sent.Preconditions.UID != original.UID || sent.Preconditions.ResourceVersion == nil || *sent.Preconditions.ResourceVersion != "3" || len(sent.DryRun) != 0 || sent.GracePeriodSeconds != nil || sent.OrphanDependents != nil) {
				t.Fatal("one original DELETE lost exact UID/RV or gained force/dry-run options")
			}
			if (scenario == "evolving-status" || scenario == "ready-rv-change") && gets != 3 || scenario == "readiness-regression" && gets != 4 {
				t.Fatal("unfinished status was treated as ready or settling omitted")
			}
			outcome := gcComponentOutcome(err)
			if scenario == "delete-conflict" && outcome != "conflict" || (scenario == "get-forbidden" || scenario == "delete-forbidden") && outcome != "forbidden" || (scenario == "delete-canary" || scenario == "delete-throttled") && outcome != "unknown" {
				t.Fatal("fixed refusal outcome lost its classification")
			}
			flags := gcComponentDenialFlags(err, "template", original.Namespace)
			if strings.Contains(outcome+flags, "fixture-sensitive-private-canary") || flags != "policy-present=false message-present=false cause-policy-present=false field=unknown cause-type=unknown" {
				t.Fatal("fixed diagnostics exposed native error content or invented attribution")
			}
		})
	}
}
