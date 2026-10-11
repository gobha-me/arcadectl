//go:build kindinstall

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installrender"
	appsv1 "k8s.io/api/apps/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	authv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
)

// Component proof only: authentic historical runtime admission plus current
// baseline, native Deployment/ReplicaSet/Pod creation and foreground GC. The
// Cases cover scheduling-gated GC and an inert Running/node-bound pause Pod;
// no Secret, world or PVC is created. This
// does not replace signed-installer lifecycle, enrollment or durable WAL proof.
func TestKindBaselineNativeForegroundGarbageCollection(t *testing.T) {
	t.Run("diagnostic-controls", testGCNativeDiagnosticControls)
	ctx, config, images, _, node := targetKindFixtureImagesWithOwnedNode(t, targetKind137, false, false, false, false, false)
	apiImage := images.API
	admin, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatal("owned native client unavailable")
	}
	access, err := NewDirectHTTPAccess(config)
	if err != nil {
		t.Fatal("owned native direct access unavailable")
	}
	historical, _ := lifecycleTransitionPlans(t)
	namespace := historical.Namespace()
	var desired appsv1.Deployment
	var policyNames []string
	for _, resource := range historical.Resources() {
		object := resource.Object
		switch object.GetKind() {
		case "Namespace", "ServiceAccount", "ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding":
			key := baselineObjectKey(object)
			if _, err := access.Create(ctx, key, object, false); err != nil {
				t.Fatal("authentic historical admission fixture creation refused")
			}
			if object.GetKind() == "ValidatingAdmissionPolicy" {
				policyNames = append(policyNames, object.GetName())
			}
		case "Deployment":
			if object.GetName() == "arcadectl-api" && runtime.DefaultUnstructuredConverter.FromUnstructured(object.Object, &desired) != nil {
				t.Fatal("authentic historical API template unavailable")
			}
		}
	}
	baseline, _ := installStandaloneBaselineContract(t, ctx, access, namespace, installrender.Profile137)
	boundNamespace, err := admin.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{})
	if err != nil || boundNamespace.Labels["kubernetes.io/metadata.name"] != namespace {
		t.Fatal("actual Namespace does not match the exact baseline binding selector")
	}
	for _, resource := range baseline.Resources() {
		if resource.Object.GetKind() == "ValidatingAdmissionPolicy" {
			policyNames = append(policyNames, resource.Object.GetName())
		}
	}
	if wait.PollUntilContextTimeout(ctx, 200*time.Millisecond, 30*time.Second, true, func(ctx context.Context) (bool, error) {
		for _, name := range policyNames {
			policy, err := admin.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				return false, err
			}
			if policy.Status.ObservedGeneration != policy.Generation || policy.Status.TypeChecking == nil {
				return false, nil
			}
			if len(policy.Status.TypeChecking.ExpressionWarnings) != 0 {
				return false, ErrSecurityBaseline
			}
		}
		return true, nil
	}) != nil {
		t.Fatal("actual native baseline typechecking refused")
	}
	actor := func(user string, groups []string) *kubernetes.Clientset {
		c := rest.CopyConfig(config)
		c.Impersonate = rest.ImpersonationConfig{UserName: user, Groups: groups}
		client, err := kubernetes.NewForConfig(c)
		if err != nil {
			t.Fatal("closed native actor unavailable")
		}
		identity, err := client.AuthenticationV1().SelfSubjectReviews().Create(ctx, &authenticationv1.SelfSubjectReview{}, metav1.CreateOptions{})
		if err != nil {
			t.Fatal("native actor identity readback unavailable")
		}
		actualGroups, expectedGroups := slices.Clone(identity.Status.UserInfo.Groups), slices.Clone(groups)
		slices.Sort(actualGroups)
		slices.Sort(expectedGroups)
		if identity.Status.UserInfo.Username != user || !slices.Equal(actualGroups, expectedGroups) || len(identity.Status.UserInfo.Extra) != 0 {
			t.Fatal("native actor identity differs from the closed impersonation request")
		}
		return client
	}
	gc := actor("system:serviceaccount:kube-system:generic-garbage-collector", []string{"system:serviceaccounts", "system:serviceaccounts:kube-system", "system:authenticated"})
	foreignName := "arcadectl-gc-negative"
	foreign := actor(foreignName, []string{"system:authenticated"})
	role := &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: foreignName, Namespace: namespace}, Rules: []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods", "services"}, Verbs: []string{"get", "patch"}}}}
	if _, err := admin.RbacV1().Roles(namespace).Create(ctx, role, metav1.CreateOptions{}); err != nil {
		t.Fatal("bounded negative actor authority unavailable")
	}
	if _, err := admin.RbacV1().RoleBindings(namespace).Create(ctx, &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: foreignName, Namespace: namespace}, Subjects: []rbacv1.Subject{{Kind: "User", APIGroup: rbacv1.GroupName, Name: foreignName}}, RoleRef: rbacv1.RoleRef{Kind: "Role", APIGroup: rbacv1.GroupName, Name: foreignName}}, metav1.CreateOptions{}); err != nil {
		t.Fatal("bounded negative actor binding unavailable")
	}
	can := func(client *kubernetes.Clientset, verb, resource, name string, want bool) {
		t.Helper()
		review, err := client.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, &authv1.SelfSubjectAccessReview{Spec: authv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authv1.ResourceAttributes{Namespace: namespace, Verb: verb, Resource: resource, Name: name}}}, metav1.CreateOptions{})
		if err != nil || review.Status.Allowed != want || want && review.Status.Denied || review.Status.EvaluationError != "" {
			t.Fatal("native authorization differs from fixed admission control")
		}
	}
	for _, client := range []*kubernetes.Clientset{gc, foreign} {
		can(client, "patch", "pods", "", true)
		can(client, "patch", "services", "arcadectl-api", true)
		can(client, "impersonate", "serviceaccounts", "arcadectl-destroy-controller", false)
	}
	if desired.Name != "arcadectl-api" || len(desired.Spec.Template.Spec.Containers) != 1 || desired.Spec.Template.Spec.ServiceAccountName != "arcadectl-api" {
		t.Fatal("historical API executable identity differs")
	}
	desired.Spec.Replicas = ptr.To(int32(1))
	desired.Spec.Template.Spec.Containers[0].Image = apiImage
	desired.Spec.Template.Spec.SchedulingGates = []corev1.PodSchedulingGate{{Name: "arcade.gobha.me/gc-component-inert"}}
	deployment, err := admin.AppsV1().Deployments(namespace).Create(ctx, &desired, metav1.CreateOptions{})
	if err != nil || deployment.UID == "" {
		t.Fatal("owned inert API Deployment unavailable")
	}
	var replicaSet appsv1.ReplicaSet
	var pod corev1.Pod
	if wait.PollUntilContextTimeout(ctx, 200*time.Millisecond, 60*time.Second, true, func(ctx context.Context) (bool, error) {
		sets, err := admin.AppsV1().ReplicaSets(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return false, err
		}
		pods, err := admin.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return false, err
		}
		if sets.Continue != "" || sets.RemainingItemCount != nil && *sets.RemainingItemCount != 0 || pods.Continue != "" || pods.RemainingItemCount != nil && *pods.RemainingItemCount != 0 {
			return false, ErrOutcomeUnknown
		}
		if len(sets.Items) != 1 || len(pods.Items) != 1 {
			return false, nil
		}
		replicaSet, pod = sets.Items[0], pods.Items[0]
		setOwner, podOwner := metav1.GetControllerOf(&replicaSet), metav1.GetControllerOf(&pod)
		return replicaSet.UID != "" && pod.UID != "" && setOwner != nil && setOwner.UID == deployment.UID && setOwner.Name == deployment.Name && setOwner.Kind == "Deployment" && podOwner != nil && podOwner.UID == replicaSet.UID && podOwner.Name == replicaSet.Name && podOwner.Kind == "ReplicaSet" && pod.Spec.ServiceAccountName == "arcadectl-api" && pod.Spec.NodeName == "" && len(pod.Spec.SchedulingGates) == 1 && pod.Spec.SchedulingGates[0].Name == "arcade.gobha.me/gc-component-inert", nil
	}) != nil {
		t.Fatal("actual native original Deployment/ReplicaSet/Pod chain unavailable")
	}
	patch := func(client *kubernetes.Clientset, resource, name string, body map[string]any) error {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal("closed metadata patch encoding unavailable")
		}
		// DoRaw deliberately discards structured Status attribution on errors.
		// Error decodes the native policy/binding/message; generic HTTP 422 is
		// never sufficient evidence that the expected policy denied this request.
		return client.CoreV1().RESTClient().Patch(types.MergePatchType).Namespace(namespace).Resource(resource).Name(name).Body(encoded).Param("dryRun", "All").Do(ctx).Error()
	}
	metadata := map[string]any{"metadata": map[string]any{"uid": string(pod.UID), "resourceVersion": pod.ResourceVersion, "finalizers": []string{}}}
	if err := patch(admin, "pods", pod.Name, metadata); err != nil {
		t.Fatal("admin identical metadata PATCH refused: outcome=" + gcComponentOutcome(err) + " " + gcComponentDenialFlags(err, namespace))
	}
	// Typechecking status is not a serving barrier: policy and binding
	// informers converge independently. Repeating this identical dry run has
	// no resource effects and proves the exact denial before any GC assertion.
	// This is test readiness only, not a retry of a production mutation.
	var lastDenial error
	if wait.PollUntilContextTimeout(ctx, 200*time.Millisecond, 30*time.Second, true, func(ctx context.Context) (bool, error) {
		lastDenial = patch(foreign, "pods", pod.Name, metadata)
		return baselineDenial(lastDenial, "pod", namespace), nil
	}) != nil {
		t.Fatal("foreign metadata PATCH lacks exact Pod policy denial: outcome=" + gcComponentOutcome(lastDenial) + " " + gcComponentDenialFlags(lastDenial, namespace))
	}
	if err := patch(gc, "pods", pod.Name, metadata); err != nil {
		if baselineDenial(err, "pod", namespace) {
			t.Error("native GC metadata-only Pod UPDATE denied by exact Pod baseline policy")
		} else {
			t.Fatal("native GC metadata-only Pod UPDATE refused without expected attribution: outcome=" + gcComponentOutcome(err) + " " + gcComponentDenialFlags(err, namespace))
		}
	}
	changedContainers := pod.DeepCopy().Spec.Containers
	changedContainers[0].Image = "registry.example/foreign@sha256:" + strings.Repeat("b", 64)
	changed := map[string]any{"metadata": metadata["metadata"], "spec": map[string]any{"containers": changedContainers}}
	if err := patch(gc, "pods", pod.Name, changed); !baselineDenial(err, "pod", namespace) {
		t.Fatal("native GC executable substitution lacks exact Pod baseline denial")
	}
	livePod, err := admin.CoreV1().Pods(namespace).Get(ctx, pod.Name, metav1.GetOptions{})
	if err != nil || livePod.UID != pod.UID || livePod.ResourceVersion != pod.ResourceVersion || !reflect.DeepEqual(livePod.Spec, pod.Spec) || !reflect.DeepEqual(livePod.Finalizers, pod.Finalizers) {
		t.Fatal("dry-run metadata/spec controls changed original Pod")
	}
	live, err := admin.AppsV1().Deployments(namespace).Get(ctx, deployment.Name, metav1.GetOptions{})
	if err != nil || live.UID != deployment.UID || !reflect.DeepEqual(live.Spec, deployment.Spec) {
		t.Fatal("original Deployment changed before its one foreground DELETE")
	}
	uid, rv, foreground := live.UID, live.ResourceVersion, metav1.DeletePropagationForeground
	if admin.AppsV1().Deployments(namespace).Delete(ctx, live.Name, metav1.DeleteOptions{PropagationPolicy: &foreground, Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &rv}}) != nil {
		t.Fatal("one original Deployment foreground DELETE refused")
	}
	if wait.PollUntilContextTimeout(ctx, 200*time.Millisecond, 5*time.Minute, true, func(ctx context.Context) (bool, error) {
		_, deploymentErr := admin.AppsV1().Deployments(namespace).Get(ctx, deployment.Name, metav1.GetOptions{})
		sets, setErr := admin.AppsV1().ReplicaSets(namespace).List(ctx, metav1.ListOptions{})
		pods, podErr := admin.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
		if deploymentErr != nil && !apierrors.IsNotFound(deploymentErr) || setErr != nil || podErr != nil {
			return false, ErrOutcomeUnknown
		}
		if sets.Continue != "" || sets.RemainingItemCount != nil && *sets.RemainingItemCount != 0 || pods.Continue != "" || pods.RemainingItemCount != nil && *pods.RemainingItemCount != 0 {
			return false, ErrOutcomeUnknown
		}
		return apierrors.IsNotFound(deploymentErr) && len(sets.Items) == 0 && len(pods.Items) == 0, nil
	}) != nil {
		t.Error("original native Deployment/ReplicaSet/Pod foreground absence not proved")
	} else {
		t.Log("original native Deployment/ReplicaSet/Pod foreground chain absent without manual finalizer removal")
	}
	service, err := admin.CoreV1().Services(namespace).Create(ctx, &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "arcadectl-api", Namespace: namespace}, Spec: corev1.ServiceSpec{Ports: []corev1.ServicePort{{Port: 8443}}}}, metav1.CreateOptions{})
	if err != nil || service.UID == "" {
		t.Fatal("owned reserved-name API Service unavailable")
	}
	serviceMetadata := map[string]any{"metadata": map[string]any{"uid": string(service.UID), "resourceVersion": service.ResourceVersion, "finalizers": []string{}}}
	if err := patch(foreign, "services", service.Name, serviceMetadata); !baselineDenial(err, "identity", namespace) {
		t.Fatal("foreign Service PATCH lacks exact identity policy denial")
	}
	if err := patch(gc, "services", service.Name, serviceMetadata); err != nil {
		if baselineDenial(err, "identity", namespace) {
			t.Error("native GC metadata-only Service UPDATE denied by exact identity baseline policy")
		} else {
			t.Fatal("native GC Service UPDATE refused without expected attribution: outcome=" + gcComponentOutcome(err) + " " + gcComponentDenialFlags(err, namespace))
		}
	}
	changedPorts := append([]corev1.ServicePort(nil), service.Spec.Ports...)
	changedPorts[0].Port = 8444
	if err := patch(gc, "services", service.Name, map[string]any{"metadata": serviceMetadata["metadata"], "spec": map[string]any{"ports": changedPorts}}); !baselineDenial(err, "identity", namespace) {
		t.Fatal("native GC Service spec change lacks exact identity baseline denial")
	}
	liveService, err := admin.CoreV1().Services(namespace).Get(ctx, service.Name, metav1.GetOptions{})
	if err != nil || liveService.UID != service.UID || liveService.ResourceVersion != service.ResourceVersion || !reflect.DeepEqual(liveService.Spec, service.Spec) || !reflect.DeepEqual(liveService.Finalizers, service.Finalizers) {
		t.Fatal("dry-run metadata/spec controls changed original Service")
	}
	uid, rv = service.UID, service.ResourceVersion
	if admin.CoreV1().Services(namespace).Delete(ctx, service.Name, metav1.DeleteOptions{PropagationPolicy: &foreground, Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &rv}}) != nil {
		t.Fatal("one original API Service foreground DELETE refused")
	}
	if wait.PollUntilContextTimeout(ctx, 200*time.Millisecond, 5*time.Minute, true, func(ctx context.Context) (bool, error) {
		live, err := admin.CoreV1().Services(namespace).Get(ctx, service.Name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return true, nil
		}
		if err != nil || live.UID != uid {
			return false, ErrOutcomeUnknown
		}
		return false, nil
	}) != nil {
		t.Error("original API Service foreground absence not proved without manual finalizer removal")
	}
	t.Run("node-termination", func(t *testing.T) {
		nodeActor := actor("system:node:"+node.name, []string{"system:nodes", "system:authenticated"})
		can(nodeActor, "delete", "pods", "", true)
		can(nodeActor, "impersonate", "serviceaccounts", "arcadectl-destroy-controller", false)
		proveKindNodeTermination(t, ctx, admin, nodeActor, node, namespace)
	})
}

// Fixture diagnostics are closed classifications, never raw server errors,
// object bodies, identities or credentials.
func gcComponentOutcome(err error) string {
	switch {
	case err == nil:
		return "accepted"
	case apierrors.IsConflict(err):
		return "conflict"
	case apierrors.IsUnauthorized(err):
		return "unauthorized"
	case apierrors.IsForbidden(err):
		return "forbidden"
	case apierrors.IsInvalid(err):
		return "invalid"
	case apierrors.IsBadRequest(err):
		return "bad-request"
	case apierrors.IsNotFound(err):
		return "not-found"
	case apierrors.IsInternalError(err):
		return "internal-error"
	}
	return "unknown"
}

func gcComponentDenialFlags(err error, namespace string) string {
	policy := "arcadectl-identity-pod-" + namespace
	policyPresent, messagePresent, causePresent := false, false, false
	if err != nil {
		policyPresent = strings.Contains(err.Error(), policy)
		messagePresent = strings.Contains(err.Error(), "Arcadectl installation identities and executables require trusted maintenance authority.")
	}
	field, causeType := "unknown", "unknown"
	var status apierrors.APIStatus
	if errors.As(err, &status) && status.Status().Details != nil {
		for _, cause := range status.Status().Details.Causes {
			causePresent = causePresent || strings.Contains(cause.Message, policy)
			switch cause.Field {
			case "spec", "metadata", "metadata.name", "metadata.namespace", "metadata.uid", "metadata.resourceVersion", "metadata.finalizers", "metadata.ownerReferences", "metadata.annotations", "metadata.labels", "spec.serviceAccountName", "spec.schedulingGates":
				field = cause.Field
			}
			switch cause.Type {
			case metav1.CauseTypeFieldValueInvalid, metav1.CauseTypeFieldValueRequired, metav1.CauseTypeFieldValueNotSupported:
				causeType = string(cause.Type)
			}
		}
	}
	return fmt.Sprintf("policy-present=%t message-present=%t cause-policy-present=%t field=%s cause-type=%s", policyPresent, messagePresent, causePresent, field, causeType)
}
