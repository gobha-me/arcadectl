//go:build envtest

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	authv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

// API-only authenticated boundary controls. Test-owned finalizers retain inert
// terminating seeds; their removal cleans fixtures, never proves native GC or
// actual container termination. No controller, scheduler or kubelet executes.
func testStandaloneNodeTerminationBoundary(t *testing.T, ctx context.Context, environment *envtest.Environment, config *rest.Config, admin *kubernetes.Clientset, namespace, profile string, spec *corev1.PodSpec,
	actorCan func(*kubernetes.Clientset, string, string, string, string, string, bool)) {
	t.Helper()
	const node = "baseline-boundary-node"
	// Kubernetes 1.37 resize admission consults the assigned Node's Linux
	// label and allocatable resources. This inert API fixture has no kubelet
	// or Ready claim; it only makes the administrator resize candidate valid.
	nodeSeed, err := admin.CoreV1().Nodes().Create(ctx, &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: node, Labels: map[string]string{corev1.LabelOSStable: "linux"}}}, metav1.CreateOptions{})
	if err != nil || nodeSeed.UID == "" {
		t.Fatal("owned inert resize Node seed unavailable")
	}
	nodeSeed.Status.Capacity = corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("1"), corev1.ResourceMemory: resource.MustParse("512Mi")}
	nodeSeed.Status.Allocatable = nodeSeed.Status.Capacity.DeepCopy()
	nodeSeed, err = admin.CoreV1().Nodes().UpdateStatus(ctx, nodeSeed, metav1.UpdateOptions{})
	if err != nil {
		t.Fatal("owned inert resize Node capacity seed unavailable")
	}
	identities := []struct {
		name   string
		groups []string
	}{
		{"system:node:" + node, []string{"system:nodes", "system:authenticated"}},
		{"system:node:foreign-node", []string{"system:nodes", "system:authenticated"}},
		{"system:node:" + node + "-foreign", []string{"system:nodes", "system:authenticated"}},
		{"foreign-system:node:" + node, []string{"system:nodes", "system:authenticated"}},
		{"system:node:" + node, []string{"system:authenticated"}},
	}
	role := &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "node-boundary-probe", Namespace: namespace}, Rules: []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods", "pods/resize", "pods/ephemeralcontainers", "serviceaccounts", "services"}, Verbs: []string{"get", "create", "update", "delete"}}}}
	if _, err := admin.RbacV1().Roles(namespace).Create(ctx, role, metav1.CreateOptions{}); err != nil {
		t.Fatal("owned node boundary authority unavailable")
	}
	subjects := make([]rbacv1.Subject, 0, len(identities)-1)
	for _, identity := range identities[:len(identities)-1] {
		subjects = append(subjects, rbacv1.Subject{Kind: "User", APIGroup: rbacv1.GroupName, Name: identity.name})
	}
	if _, err := admin.RbacV1().RoleBindings(namespace).Create(ctx, &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: role.Name, Namespace: namespace}, RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: role.Name}, Subjects: subjects}, metav1.CreateOptions{}); err != nil {
		t.Fatal("owned node boundary binding unavailable")
	}
	clients := make([]*kubernetes.Clientset, len(identities))
	for i, identity := range identities {
		user, err := environment.AddUser(envtest.User{Name: identity.name, Groups: identity.groups}, config)
		if err != nil {
			t.Fatal("authenticated node boundary identity unavailable")
		}
		clients[i], err = kubernetes.NewForConfig(user.Config())
		if err != nil {
			t.Fatal("authenticated node boundary client unavailable")
		}
		review, err := clients[i].AuthenticationV1().SelfSubjectReviews().Create(ctx, &authenticationv1.SelfSubjectReview{}, metav1.CreateOptions{})
		if err != nil {
			t.Fatal("node boundary authenticated identity readback unavailable")
		}
		groups, expected := slices.Clone(review.Status.UserInfo.Groups), slices.Clone(identity.groups)
		slices.Sort(groups)
		slices.Sort(expected)
		// Native X509 authentication returns a credential ID derived from the
		// leaf certificate DER on both supported profiles. Verify it exactly,
		// without printing certificate bytes or credential hashes.
		block, _ := pem.Decode(user.Config().CertData)
		if block == nil || block.Type != "CERTIFICATE" {
			t.Fatal("owned node client certificate unavailable")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal("owned node client certificate malformed")
		}
		sum := sha256.Sum256(certificate.Raw)
		extra := map[string]authenticationv1.ExtraValue{"authentication.kubernetes.io/credential-id": {"X509SHA256=" + hex.EncodeToString(sum[:])}}
		if review.Status.UserInfo.Username != identity.name || review.Status.UserInfo.UID != "" || !slices.Equal(groups, expected) || !reflect.DeepEqual(review.Status.UserInfo.Extra, extra) {
			t.Fatalf("node boundary authenticated identity differs: username-matches=%t uid-empty=%t groups-match=%t credential-matches=%t", review.Status.UserInfo.Username == identity.name, review.Status.UserInfo.UID == "", slices.Equal(groups, expected), reflect.DeepEqual(review.Status.UserInfo.Extra, extra))
		}
		actorCan(clients[i], "delete", "", "pods", "", "", true)
		actorCan(clients[i], "impersonate", "", "serviceaccounts", "", "arcadectl-destroy-controller", false)
	}
	deny := func(err error) {
		t.Helper()
		if !baselineDenial(err, "pod", namespace) {
			t.Fatal("node boundary lacks exact Pod policy/binding/message refusal")
		}
	}
	// Historical worker gates read serviceAccountName without a has guard and
	// therefore fail closed on otherwise valid mirror CREATE with no account.
	// Isolate ONLY the baseline mirror-key predicate, not legacy compatibility.
	// All ordinary node rows and the real native GC gate keep combined policies.
	mirrorNamespace := namespace + "-mirror-boundary"
	if _, err := admin.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: mirrorNamespace}}, metav1.CreateOptions{}); err != nil {
		t.Fatal("owned mirror boundary Namespace unavailable")
	}
	access, err := NewDirectHTTPAccess(config)
	if err != nil {
		t.Fatal("owned mirror boundary transport unavailable")
	}
	installStandaloneBaselineContract(t, ctx, access, mirrorNamespace, profile)
	mirrorRole := role.DeepCopy()
	mirrorRole.Namespace = mirrorNamespace
	if _, err := admin.RbacV1().Roles(mirrorNamespace).Create(ctx, mirrorRole, metav1.CreateOptions{}); err != nil {
		t.Fatal("owned mirror boundary authority unavailable")
	}
	if _, err := admin.RbacV1().RoleBindings(mirrorNamespace).Create(ctx, &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: role.Name, Namespace: mirrorNamespace}, RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: role.Name}, Subjects: subjects}, metav1.CreateOptions{}); err != nil {
		t.Fatal("owned mirror boundary binding unavailable")
	}
	for _, client := range clients {
		for _, permission := range []struct {
			verb, resource, name string
			allowed              bool
		}{{"delete", "pods", "", true}, {"impersonate", "serviceaccounts", "arcadectl-destroy-controller", false}} {
			if wait.PollUntilContextTimeout(ctx, 100*time.Millisecond, 15*time.Second, true, func(ctx context.Context) (bool, error) {
				review, err := client.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, &authv1.SelfSubjectAccessReview{Spec: authv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authv1.ResourceAttributes{Namespace: mirrorNamespace, Verb: permission.verb, Resource: permission.resource, Name: permission.name}}}, metav1.CreateOptions{})
				return err == nil && review.Status.Allowed == permission.allowed && review.Status.EvaluationError == "", nil
			}) != nil {
				t.Fatal("mirror boundary authorization differs from admission control")
			}
		}
	}
	mirrorProbe := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "arcadectl-api", Namespace: mirrorNamespace, Annotations: map[string]string{"kubernetes.io/config.mirror": "owned-inert-mirror"}}, Spec: *spec.DeepCopy()}
	mirrorProbe.Spec.NodeName = node
	mirrorProbe.Spec.ServiceAccountName, mirrorProbe.Spec.DeprecatedServiceAccount = "", ""
	mirrorProbe.Spec.AutomountServiceAccountToken = ptr.To(false)
	createDry := metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}}
	if _, err := admin.CoreV1().Pods(mirrorNamespace).Create(ctx, mirrorProbe, createDry); err != nil {
		t.Fatal("native mirror serving candidate invalid")
	}
	// Baseline/binding/RBAC informer readiness is not a production mutation
	// retry. This identical valid dry run has no effects and must receive the
	// exact scoped baseline denial before any mirror DELETE assertion.
	if wait.PollUntilContextTimeout(ctx, 100*time.Millisecond, 15*time.Second, true, func(ctx context.Context) (bool, error) {
		_, err := clients[0].CoreV1().Pods(mirrorNamespace).Create(ctx, mirrorProbe, createDry)
		return baselineDenial(err, "pod", mirrorNamespace), nil
	}) != nil {
		t.Fatal("exact mirror boundary baseline is not serving")
	}
	cases := []struct {
		name, node string
		phase      corev1.PodPhase
		deleting   bool
		mirror     *string
		allowed    bool
	}{
		{"succeeded", node, corev1.PodSucceeded, true, nil, true},
		{"failed", node, corev1.PodFailed, true, nil, true},
		{"no-delete", node, corev1.PodSucceeded, false, nil, false},
		{"live-pending", node, corev1.PodPending, false, nil, false},
		{"pending", node, corev1.PodPending, true, nil, false},
		{"running", node, corev1.PodRunning, true, nil, false},
		{"unknown", node, corev1.PodUnknown, true, nil, false},
		{"unassigned", "", corev1.PodSucceeded, true, nil, false},
		{"mirror", node, corev1.PodSucceeded, true, ptr.To("owned-inert-mirror"), false},
		{"empty-mirror", node, corev1.PodSucceeded, true, ptr.To(""), false},
	}
	for _, row := range cases {
		t.Run("node-"+row.name, func(t *testing.T) {
			caseNamespace := namespace
			if row.mirror != nil {
				caseNamespace = mirrorNamespace
			}
			rowDeny := func(err error) {
				t.Helper()
				if !baselineDenial(err, "pod", caseNamespace) {
					t.Fatal("node row lacks exact scoped Pod policy/binding/message refusal")
				}
			}
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "node-boundary-" + row.name, Namespace: caseNamespace, Finalizers: []string{"arcade.gobha.me/baseline-boundary"}}, Spec: *spec.DeepCopy()}
			pod.Spec.NodeName, pod.Spec.AutomountServiceAccountToken = row.node, ptr.To(false)
			pod.Spec.Containers[0].Resources = corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("100m"), corev1.ResourceMemory: resource.MustParse("64Mi")}, Limits: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("100m"), corev1.ResourceMemory: resource.MustParse("64Mi")}}
			if row.mirror != nil {
				pod.Name = "arcadectl-api"
				pod.Spec.ServiceAccountName, pod.Spec.DeprecatedServiceAccount = "", ""
				pod.Annotations = map[string]string{"kubernetes.io/config.mirror": *row.mirror}
			}
			seed, err := admin.CoreV1().Pods(caseNamespace).Create(ctx, pod, metav1.CreateOptions{})
			if err != nil {
				t.Fatalf("owned inert node boundary seed unavailable: forbidden=%t invalid=%t mirror-mentioned=%t serviceaccount-mentioned=%t runtime-policy-mentioned=%t missing-key-mentioned=%t", apierrors.IsForbidden(err), apierrors.IsInvalid(err), strings.Contains(err.Error(), "mirror"), strings.Contains(err.Error(), "serviceaccount") || strings.Contains(err.Error(), "serviceAccount"), strings.Contains(err.Error(), "arcadectl-backup-worker-gate") || strings.Contains(err.Error(), "arcadectl-restore-worker-gate") || strings.Contains(err.Error(), "arcadectl-destroy-worker-gate"), strings.Contains(err.Error(), "no such key"))
			}
			seed.Status.Phase = row.phase
			seed, err = admin.CoreV1().Pods(caseNamespace).UpdateStatus(ctx, seed, metav1.UpdateOptions{})
			if err != nil {
				t.Fatal("owned inert node boundary status unavailable")
			}
			if row.deleting {
				if admin.CoreV1().Pods(caseNamespace).Delete(ctx, seed.Name, metav1.DeleteOptions{GracePeriodSeconds: ptr.To(int64(0)), Preconditions: &metav1.Preconditions{UID: &seed.UID, ResourceVersion: &seed.ResourceVersion}}) != nil {
					t.Fatal("owned inert node boundary deletion seed unavailable")
				}
				seed, err = admin.CoreV1().Pods(caseNamespace).Get(ctx, seed.Name, metav1.GetOptions{})
				if err != nil || seed.DeletionTimestamp == nil {
					t.Fatal("actual retained terminating node boundary seed unavailable")
				}
			}
			if seed.Status.Phase != row.phase || seed.Spec.NodeName != row.node || seed.UID == "" {
				t.Fatal("actual inert node boundary fields differ")
			}
			if row.mirror != nil && (seed.Name != "arcadectl-api" || seed.Namespace != mirrorNamespace || seed.Spec.ServiceAccountName != "" || seed.Spec.DeprecatedServiceAccount != "" || seed.Annotations["kubernetes.io/config.mirror"] != *row.mirror) {
				t.Fatal("actual guarded mirror predicate seed fields differ")
			}
			options := metav1.DeleteOptions{DryRun: []string{metav1.DryRunAll}, GracePeriodSeconds: ptr.To(int64(0)), Preconditions: &metav1.Preconditions{UID: &seed.UID}}
			for i, client := range clients {
				err := client.CoreV1().Pods(caseNamespace).Delete(ctx, seed.Name, options)
				if row.allowed && i == 0 {
					if err != nil {
						t.Fatal("exact own-node terminal completion DELETE refused")
					}
				} else {
					if !baselineDenial(err, "pod", caseNamespace) {
						t.Fatalf("node DELETE lacks exact refusal: actor-index=%d accepted=%t forbidden=%t invalid=%t not-found=%t conflict=%t", i, err == nil, apierrors.IsForbidden(err), apierrors.IsInvalid(err), apierrors.IsNotFound(err), apierrors.IsConflict(err))
					}
					rowDeny(err)
				}
			}
			if row.allowed {
				wrong := types.UID("wrong-node-boundary-original")
				bad := options.DeepCopy()
				bad.Preconditions.UID = &wrong
				if err := clients[0].CoreV1().Pods(caseNamespace).Delete(ctx, seed.Name, *bad); !apierrors.IsConflict(err) {
					t.Fatal("node completion DELETE bypassed native UID precondition")
				}
			}
			metadata := seed.DeepCopy()
			metadata.Annotations = maps.Clone(seed.Annotations)
			if metadata.Annotations == nil {
				metadata.Annotations = map[string]string{}
			}
			metadata.Annotations["test"] = "node-update-negative"
			if _, err := admin.CoreV1().Pods(caseNamespace).Update(ctx, metadata, metav1.UpdateOptions{DryRun: []string{metav1.DryRunAll}}); err != nil {
				t.Fatal("native node metadata-update negative candidate invalid")
			}
			_, err = clients[0].CoreV1().Pods(caseNamespace).Update(ctx, metadata, metav1.UpdateOptions{DryRun: []string{metav1.DryRunAll}})
			rowDeny(err)
			if row.name == "live-pending" {
				updateDry := metav1.UpdateOptions{DryRun: []string{metav1.DryRunAll}}
				ephemeral := seed.DeepCopy()
				ephemeral.Spec.EphemeralContainers = []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "node-debug-negative", Image: seed.Spec.Containers[0].Image, SecurityContext: seed.Spec.Containers[0].SecurityContext.DeepCopy()}, TargetContainerName: seed.Spec.Containers[0].Name}}
				if _, err := admin.CoreV1().Pods(namespace).UpdateEphemeralContainers(ctx, seed.Name, ephemeral, updateDry); err != nil {
					t.Fatal("native node ephemeral-container negative candidate invalid")
				}
				_, err = clients[0].CoreV1().Pods(namespace).UpdateEphemeralContainers(ctx, seed.Name, ephemeral, updateDry)
				deny(err)
				resized := seed.DeepCopy()
				resized.Spec.Containers[0].Resources.Requests[corev1.ResourceCPU] = resource.MustParse("200m")
				resized.Spec.Containers[0].Resources.Limits[corev1.ResourceCPU] = resource.MustParse("200m")
				if _, err := admin.CoreV1().Pods(namespace).UpdateResize(ctx, seed.Name, resized, updateDry); err != nil {
					t.Fatalf("native node resize negative candidate invalid: forbidden=%t invalid=%t not-found=%t", apierrors.IsForbidden(err), apierrors.IsInvalid(err), apierrors.IsNotFound(err))
				}
				_, err = clients[0].CoreV1().Pods(namespace).UpdateResize(ctx, seed.Name, resized, updateDry)
				deny(err)
			}
			current, err := admin.CoreV1().Pods(caseNamespace).Get(ctx, seed.Name, metav1.GetOptions{})
			if err != nil || !reflect.DeepEqual(current, seed) {
				t.Fatal("node dry-run controls changed the original inert seed")
			}
			if !row.deleting {
				if admin.CoreV1().Pods(caseNamespace).Delete(ctx, seed.Name, metav1.DeleteOptions{GracePeriodSeconds: ptr.To(int64(0)), Preconditions: &metav1.Preconditions{UID: &seed.UID, ResourceVersion: &seed.ResourceVersion}}) != nil {
					t.Fatal("owned nonterminating seed cleanup DELETE refused")
				}
				current, err = admin.CoreV1().Pods(caseNamespace).Get(ctx, seed.Name, metav1.GetOptions{})
				if err != nil {
					t.Fatal("owned cleanup seed readback unavailable")
				}
			}
			current.Finalizers = nil
			if _, err := admin.CoreV1().Pods(caseNamespace).Update(ctx, current, metav1.UpdateOptions{}); err != nil {
				t.Fatal("owned inert boundary finalizer cleanup refused")
			}
			if _, err := admin.CoreV1().Pods(caseNamespace).Get(ctx, seed.Name, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
				t.Fatal("owned inert boundary seed absence not proved")
			}
		})
	}
	probe := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "node-create-negative", Namespace: namespace}, Spec: *spec.DeepCopy()}
	probe.Spec.NodeName = node
	_, err = clients[0].CoreV1().Pods(namespace).Create(ctx, probe, metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}})
	deny(err)
	for _, name := range []string{"arcadectl-api", "arcadectl-destroy-controller"} {
		if err := clients[0].CoreV1().ServiceAccounts(namespace).Delete(ctx, name, metav1.DeleteOptions{DryRun: []string{metav1.DryRunAll}}); !baselineDenial(err, "identity", namespace) {
			t.Fatal("node completion identity exemption escaped Pod family")
		}
	}
}
