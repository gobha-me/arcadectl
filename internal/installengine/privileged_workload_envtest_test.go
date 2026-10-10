//go:build envtest

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installbaseline"
	"github.com/gobha-me/arcadectl/internal/installcontract"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	authv1 "k8s.io/api/authorization/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

// These are native RBAC/admission dry runs in owned API servers without a
// scheduler, controller-manager or kubelet. No privileged workload executes,
// no bearer token is requested, and no world or PVC is created or deleted.
func TestEnvtestOrdinaryControllerCannotLaunchPrivilegedIdentity(t *testing.T) {
	testPrivilegedIdentityBoundary(t, false)
}

// This independently exercises signed guard compilation/native shape and
// behavior, not journal ownership or production installation integration.
func TestEnvtestReservedIdentityGuardStandalone(t *testing.T) {
	testPrivilegedIdentityBoundary(t, true)
}

func testPrivilegedIdentityBoundary(t *testing.T, standaloneGuard bool) {
	for _, profile := range []string{installrender.Profile135, installrender.Profile137} {
		t.Run(profile, func(t *testing.T) {
			plan := fixturePlanProfile(t, "identity-boundary", profile)
			crds, err := filepath.Abs("../../config/crd/bases")
			if err != nil {
				t.Fatal("owned CRD fixture unavailable")
			}
			environment := &envtest.Environment{
				UseExistingCluster: new(bool), CRDDirectoryPaths: []string{crds}, ErrorIfCRDPathMissing: true,
				DownloadBinaryAssets: true, DownloadBinaryAssetsVersion: plan.Profile().KubernetesVersion,
				DownloadBinaryAssetsIndexURL: "https://raw.githubusercontent.com/kubernetes-sigs/controller-tools/1031496fc98a4f51010c3bdfdeb57b5d67bea7bd/envtest-releases.yaml",
				BinaryAssetsDirectory:        t.TempDir(), ControlPlaneStartTimeout: 90 * time.Second, ControlPlaneStopTimeout: 30 * time.Second,
			}
			if profile == installrender.Profile135 {
				prerequisite135Assets(t, environment)
			} else {
				environment.ControlPlane.APIServer = &envtest.APIServer{}
			}
			environment.ControlPlane.APIServer.Configure().Set("disable-admission-plugins", "")
			config, err := environment.Start()
			if err != nil {
				t.Fatal("owned API server unavailable")
			}
			t.Cleanup(func() {
				if environment.Stop() != nil {
					t.Error("owned API server cleanup failed")
				}
			})
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()
			access, err := NewDirectHTTPAccess(config)
			if err != nil {
				t.Fatal("owned administration transport unavailable")
			}
			for _, resource := range plan.Resources() {
				switch resource.Object.GetKind() {
				case "Namespace", "ServiceAccount", "Role", "RoleBinding", "ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding":
					if _, err := access.Create(ctx, resourceKey(resource), resource.Object, false); err != nil {
						t.Fatal("signed fixture dependency refused")
					}
				}
			}
			if standaloneGuard {
				installStandaloneBaselineContract(t, ctx, access, plan.Namespace(), profile)
			}
			// Authenticate the exact ordinary actor, not an omnipotent admin.
			user, err := environment.AddUser(envtest.User{
				Name:   "system:serviceaccount:" + plan.Namespace() + ":arcadectl-controller",
				Groups: []string{"system:serviceaccounts", "system:serviceaccounts:" + plan.Namespace(), "system:authenticated"},
			}, config)
			if err != nil {
				t.Fatal("owned ordinary identity unavailable")
			}
			ordinary, err := kubernetes.NewForConfig(user.Config())
			if err != nil {
				t.Fatal("ordinary client unavailable")
			}
			actorCan := func(client *kubernetes.Clientset, verb, group, resource, subresource, name string, expected bool) {
				t.Helper()
				if wait.PollUntilContextTimeout(ctx, 100*time.Millisecond, 15*time.Second, true, func(ctx context.Context) (bool, error) {
					result, err := client.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, &authv1.SelfSubjectAccessReview{
						Spec: authv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authv1.ResourceAttributes{
							Namespace: plan.Namespace(), Group: group, Version: "v1", Resource: resource, Subresource: subresource, Verb: verb, Name: name,
						}},
					}, metav1.CreateOptions{})
					return err == nil && result.Status.Allowed == expected && result.Status.EvaluationError == "", nil
				}) != nil {
					t.Fatal("actor authorization did not match the independently required fixture permission")
				}
			}
			for _, verb := range []string{"create", "update", "delete"} {
				actorCan(ordinary, verb, "apps", "deployments", "", "arcadectl-destroy-controller", true)
			}
			actorCan(ordinary, "delete", "", "serviceaccounts", "", "arcadectl-destroy-controller", true)
			actorCan(ordinary, "impersonate", "", "serviceaccounts", "", "arcadectl-destroy-controller", false)
			for _, resource := range []string{"deployments", "replicasets", "statefulsets", "replicationcontrollers"} {
				group := "apps"
				if resource == "replicationcontrollers" {
					group = ""
				}
				for _, verb := range []string{"create", "update", "patch", "delete"} {
					actorCan(ordinary, verb, group, resource, "scale", "not-a-reserved-name", false)
				}
			}
			if wait.PollUntilContextTimeout(ctx, 100*time.Millisecond, 15*time.Second, true, func(ctx context.Context) (bool, error) {
				result, err := ordinary.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, &authv1.SelfSubjectAccessReview{
					Spec: authv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authv1.ResourceAttributes{
						Namespace: plan.Namespace(), Group: "batch", Version: "v1", Resource: "jobs", Verb: "create",
					}},
				}, metav1.CreateOptions{})
				return err == nil && result.Status.Allowed, nil
			}) != nil {
				t.Fatal("ordinary actor lacks expected Job creation authority")
			}
			// A known negative probe establishes that actual admission is serving;
			// absence of a status controller is not replaced with fabricated status.
			for _, resource := range plan.Resources() {
				if resource.Object.GetKind() != "ValidatingAdmissionPolicy" || !strings.HasPrefix(resource.Object.GetName(), "arcadectl-destroy-worker-gate") {
					continue
				}
				name := resource.Object.GetName()
				_, negative, index, err := admissionCreateProbe(plan, name, "arcadectl-controller", "arcadectl-probe-0123456789abcdef0123456789abcdef")
				if err != nil {
					t.Fatal("serving probe unavailable")
				}
				var policy admissionv1.ValidatingAdmissionPolicy
				if decodeServing(resource.Object, &policy) != nil || index >= len(policy.Spec.Validations) {
					t.Fatal("serving policy unavailable")
				}
				binding := ""
				for _, candidate := range plan.Resources() {
					if candidate.Object.GetKind() == "ValidatingAdmissionPolicyBinding" {
						value, _, _ := unstructured.NestedString(candidate.Object.Object, "spec", "policyName")
						if value == name {
							binding = candidate.Object.GetName()
						}
					}
				}
				if binding == "" || wait.PollUntilContextTimeout(ctx, 100*time.Millisecond, 15*time.Second, true, func(ctx context.Context) (bool, error) {
					_, err := access.probeCreate(ctx, negative, name, binding, policy.Spec.Validations[index].Message)
					return err == nil, nil
				}) != nil {
					t.Fatal("native admission serving negative proof unavailable")
				}
			}
			job := &batchv1.Job{
				ObjectMeta: metav1.ObjectMeta{Name: "innocent-looking-worker", Namespace: plan.Namespace()},
				Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
					ServiceAccountName: "arcadectl-destroy-controller", RestartPolicy: corev1.RestartPolicyNever,
					SecurityContext: &corev1.PodSecurityContext{RunAsNonRoot: ptr.To(true), RunAsUser: ptr.To(int64(65532)), SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}},
					Containers: []corev1.Container{{Name: "no-execution", Image: plan.Manifest().Images.Controller,
						SecurityContext: &corev1.SecurityContext{AllowPrivilegeEscalation: ptr.To(false), ReadOnlyRootFilesystem: ptr.To(true), Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}}}},
				}}},
			}
			if standaloneGuard {
				if wait.PollUntilContextTimeout(ctx, 100*time.Millisecond, 15*time.Second, true, func(ctx context.Context) (bool, error) {
					_, err := ordinary.BatchV1().Jobs(plan.Namespace()).Create(ctx, job, metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}, FieldValidation: "Strict"})
					return baselineDenial(err, "template", plan.Namespace()), nil
				}) != nil {
					t.Fatal("standalone guard's exact native denial was not observed")
				}
				allowed := job.DeepCopy()
				allowed.Name = "ordinary-unprivileged-worker"
				allowed.Spec.Template.Spec.ServiceAccountName = "default"
				if _, err := ordinary.BatchV1().Jobs(plan.Namespace()).Create(ctx, allowed, metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}, FieldValidation: "Strict"}); err != nil {
					t.Fatal("standalone guard rejected an ordinary unprivileged Job")
				}
			}
			_, err = ordinary.BatchV1().Jobs(plan.Namespace()).Create(ctx, job, metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}, FieldValidation: "Strict"})
			if err == nil {
				t.Error("ordinary controller can launch a workload with the privileged destroy identity")
			} else if !baselineDenial(err, "template", plan.Namespace()) {
				t.Error("privileged workload refusal was not attributed to the exact baseline policy and binding")
			}
			admin, err := kubernetes.NewForConfig(config)
			if err != nil {
				t.Fatal("owned inventory unavailable")
			}
			deny := func(name, family string, err error) {
				t.Helper()
				if err == nil {
					t.Errorf("ordinary controller can %s", name)
				} else if !baselineDenial(err, family, plan.Namespace()) {
					t.Errorf("%s did not receive the exact baseline policy/binding denial", name)
				}
			}
			deployment := &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Name: "innocent-looking-runtime", Namespace: plan.Namespace()},
				Spec: appsv1.DeploymentSpec{
					Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"test": "privileged-identity"}},
					Template: *job.Spec.Template.DeepCopy(),
				},
			}
			deployment.Spec.Template.Labels = map[string]string{"test": "privileged-identity"}
			deployment.Spec.Template.Spec.RestartPolicy = corev1.RestartPolicyAlways
			_, err = ordinary.AppsV1().Deployments(plan.Namespace()).Create(ctx, deployment, metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}, FieldValidation: "Strict"})
			deny("create a Deployment selecting the privileged destroy identity", "template", err)
			// Seed the exact signed administrative Deployment. This is safe only
			// in this owned API server with no workload-producing controllers.
			var installed *appsv1.Deployment
			for _, resource := range plan.Resources() {
				if resource.Object.GetKind() == "Deployment" && resource.Object.GetName() == "arcadectl-destroy-controller" {
					var desired appsv1.Deployment
					if decodeServing(resource.Object, &desired) != nil {
						t.Fatal("signed privileged Deployment unavailable")
					}
					installed, err = admin.AppsV1().Deployments(plan.Namespace()).Create(ctx, &desired, metav1.CreateOptions{})
					if err != nil {
						t.Fatal("owned signed administrative fixture refused")
					}
				}
			}
			if installed == nil {
				t.Fatal("signed privileged Deployment missing")
			}
			changed := installed.DeepCopy()
			changed.Spec.Template.Spec.Containers[0].Image = plan.Manifest().Images.API
			_, err = ordinary.AppsV1().Deployments(plan.Namespace()).Update(ctx, changed, metav1.UpdateOptions{DryRun: []string{metav1.DryRunAll}, FieldValidation: "Strict"})
			deny("change the installed privileged Deployment executable", "template", err)
			err = ordinary.AppsV1().Deployments(plan.Namespace()).Delete(ctx, installed.Name, metav1.DeleteOptions{
				DryRun: []string{metav1.DryRunAll}, Preconditions: &metav1.Preconditions{UID: &installed.UID, ResourceVersion: &installed.ResourceVersion},
			})
			deny("delete the installed privileged Deployment", "template", err)
			account, err := admin.CoreV1().ServiceAccounts(plan.Namespace()).Get(ctx, "arcadectl-destroy-controller", metav1.GetOptions{})
			if err != nil {
				t.Fatal("owned privileged account unavailable")
			}
			err = ordinary.CoreV1().ServiceAccounts(plan.Namespace()).Delete(ctx, account.Name, metav1.DeleteOptions{
				DryRun: []string{metav1.DryRunAll}, Preconditions: &metav1.Preconditions{UID: &account.UID, ResourceVersion: &account.ResourceVersion},
			})
			deny("delete the reserved privileged ServiceAccount", "identity", err)
			if standaloneGuard {
				testStandaloneProducerBoundary(t, ctx, environment, config, admin, ordinary, plan.Namespace(), job, installed, actorCan)
			}
			current, err := admin.AppsV1().Deployments(plan.Namespace()).Get(ctx, installed.Name, metav1.GetOptions{})
			if err != nil || current.UID != installed.UID || current.ResourceVersion != installed.ResourceVersion || current.Spec.Template.Spec.Containers[0].Image != installed.Spec.Template.Spec.Containers[0].Image {
				t.Error("dry-run requests changed the original privileged Deployment")
			}
			accounts, err := admin.CoreV1().ServiceAccounts(plan.Namespace()).Get(ctx, account.Name, metav1.GetOptions{})
			if err != nil || accounts.UID != account.UID || accounts.ResourceVersion != account.ResourceVersion {
				t.Error("dry-run requests changed the privileged ServiceAccount")
			}
			jobs, err := admin.BatchV1().Jobs(plan.Namespace()).List(ctx, metav1.ListOptions{})
			if err != nil || len(jobs.Items) != 0 {
				t.Fatal("dry-run privilege test persisted a workload")
			}
			pods, err := admin.CoreV1().Pods(plan.Namespace()).List(ctx, metav1.ListOptions{})
			if err != nil || len(pods.Items) != 0 {
				t.Fatal("dry-run privilege test persisted a Pod")
			}
			deployments, err := admin.AppsV1().Deployments(plan.Namespace()).List(ctx, metav1.ListOptions{})
			if err != nil || len(deployments.Items) != 1 || deployments.Items[0].UID != installed.UID {
				t.Fatal("dry-run privilege test changed the administrative fixture inventory")
			}
		})
	}
}

// The fixture's acknowledged native UID proves matching behavior only. There
// is no production journal/effect receipt here, so it cannot certify durable
// ownership or recovery and must not replace the signed executable gates.
func installStandaloneBaselineContract(t *testing.T, ctx context.Context, access *HTTPAccess, namespace, profile string) (*installbaseline.Plan, map[installstate.Key]*unstructured.Unstructured) {
	t.Helper()
	manifest, payload, err := installbaseline.Build(strings.Repeat("a", 40), 1)
	if err != nil {
		t.Fatal("reviewed baseline fixture build failed")
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x35}, ed25519.SeedSize))
	signature, err := installbaseline.Sign(manifest, key)
	if err != nil {
		t.Fatal("baseline fixture signing failed")
	}
	verified, err := installbaseline.Verify(manifest, signature, payload, key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal("baseline fixture authentication failed")
	}
	plan, err := installbaseline.Compile(verified, namespace, profile)
	if err != nil {
		t.Fatal("baseline fixture semantic compilation failed")
	}
	contract, err := installcontract.NewBaseline(plan)
	if err != nil {
		t.Fatal("baseline matching contract unavailable")
	}
	acknowledgements := map[installstate.Key]*unstructured.Unstructured{}
	for _, resource := range plan.Resources() {
		object := resource.Object
		address := installstate.Key{APIVersion: object.GetAPIVersion(), Kind: object.GetKind(), Name: object.GetName()}
		template, err := contract.Template(address, false)
		if err != nil || template.Hash() != resource.TemplateSHA256 {
			t.Fatal("baseline parameterized template identity changed")
		}
		candidate, err := template.Candidate(strings.Repeat("b", 32))
		if err != nil {
			t.Fatal("baseline fixture candidate unavailable")
		}
		admitted, err := access.Create(ctx, address, candidate, true)
		if err != nil || template.MatchAdmitted(admitted) != nil {
			t.Fatal("native baseline dry run differs from reviewed defaults")
		}
		ack, err := access.Create(ctx, address, candidate, false)
		if err != nil || ack == nil || ack.GetUID() == "" || template.MatchLive(ack, ack.GetUID()) != nil {
			t.Fatal("native baseline create acknowledgement differs from reviewed contract")
		}
		acknowledgements[address] = ack.DeepCopy()
		live, err := access.Get(ctx, address)
		if err != nil || template.MatchLive(live, ack.GetUID()) != nil || live.GetAnnotations()[installstate.MutationAnnotation] != strings.Repeat("b", 32) {
			t.Fatal("native baseline independent readback differs from its original acknowledgement")
		}
	}
	return plan, acknowledgements
}

func baselineDenial(err error, family, namespace string) bool {
	if err == nil || (!apierrors.IsForbidden(err) && !apierrors.IsInvalid(err)) {
		return false
	}
	name := "arcadectl-identity-" + family + "-" + namespace
	return strings.Contains(err.Error(), "ValidatingAdmissionPolicy '"+name+"'") &&
		strings.Contains(err.Error(), "binding '"+name+"'") && strings.Contains(err.Error(), installbaseline.DenialMessage)
}

// Explicit local RBAC lets these tests distinguish admission from authorization.
// None of these users can impersonate the maintenance ServiceAccount. There are
// still no controllers or kubelets, and every caller mutation is a dry run.
func testStandaloneProducerBoundary(t *testing.T, ctx context.Context, environment *envtest.Environment, config *rest.Config,
	admin, ordinary *kubernetes.Clientset, namespace string, job *batchv1.Job, installed *appsv1.Deployment,
	actorCan func(*kubernetes.Clientset, string, string, string, string, string, bool)) {
	t.Helper()
	role := &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "baseline-probe-authority", Namespace: namespace}, Rules: []rbacv1.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"pods", "pods/ephemeralcontainers", "pods/resize", "services", "serviceaccounts", "replicationcontrollers"}, Verbs: []string{"create", "get", "update", "patch", "delete"}},
		{APIGroups: []string{"apps"}, Resources: []string{"deployments", "deployments/scale", "replicasets", "replicasets/scale"}, Verbs: []string{"create", "get", "update", "patch", "delete"}},
		{APIGroups: []string{"batch"}, Resources: []string{"jobs", "cronjobs"}, Verbs: []string{"create", "get", "update", "patch", "delete"}},
		{APIGroups: []string{"rbac.authorization.k8s.io"}, Resources: []string{"roles", "rolebindings"}, Verbs: []string{"get", "update", "delete"}},
	}}
	if _, err := admin.RbacV1().Roles(namespace).Create(ctx, role, metav1.CreateOptions{}); err != nil {
		t.Fatal("bounded producer fixture authority unavailable")
	}
	users := []string{"baseline-nonadmin", "system:kube-controller-manager", "system:serviceaccount:kube-system:deployment-controller",
		"system:serviceaccount:kube-system:replicaset-controller", "system:serviceaccount:kube-system:job-controller",
		"system:serviceaccount:kube-system:cronjob-controller", "system:serviceaccount:kube-system:generic-garbage-collector"}
	subjects := make([]rbacv1.Subject, 0, len(users))
	for _, name := range users {
		subjects = append(subjects, rbacv1.Subject{Kind: "User", APIGroup: rbacv1.GroupName, Name: name})
	}
	if _, err := admin.RbacV1().RoleBindings(namespace).Create(ctx, &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: role.Name, Namespace: namespace}, RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: role.Name}, Subjects: subjects,
	}, metav1.CreateOptions{}); err != nil {
		t.Fatal("bounded producer fixture binding unavailable")
	}
	clients := make(map[string]*kubernetes.Clientset, len(users))
	for _, name := range users {
		user, err := environment.AddUser(envtest.User{Name: name, Groups: []string{"system:authenticated"}}, config)
		if err != nil {
			t.Fatal("bounded authenticated producer unavailable")
		}
		client, err := kubernetes.NewForConfig(user.Config())
		if err != nil {
			t.Fatal("producer transport unavailable")
		}
		actorCan(client, "create", "apps", "replicasets", "", "", true)
		actorCan(client, "impersonate", "", "serviceaccounts", "", "arcadectl-destroy-controller", false)
		clients[name] = client
	}
	nonadmin := clients[users[0]]
	deny := func(family string, err error) {
		t.Helper()
		if !baselineDenial(err, family, namespace) {
			t.Fatal("required exact baseline policy/binding/message refusal was not observed")
		}
	}
	createDry := metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}, FieldValidation: "Strict"}
	updateDry := metav1.UpdateOptions{DryRun: []string{metav1.DryRunAll}, FieldValidation: "Strict"}
	deleteDry := metav1.DeleteOptions{DryRun: []string{metav1.DryRunAll}}
	for _, account := range []string{"arcadectl-controller", "arcadectl-api", "arcadectl-destroy-controller", "arcadectl-destroy-admin"} {
		copy := job.DeepCopy()
		copy.Spec.Template.Spec.ServiceAccountName = account
		_, err := ordinary.BatchV1().Jobs(namespace).Create(ctx, copy, createDry)
		deny("template", err)
		_, err = nonadmin.BatchV1().Jobs(namespace).Create(ctx, copy, createDry)
		deny("template", err)
		alias := copy.DeepCopy()
		alias.Spec.Template.Spec.ServiceAccountName = ""
		alias.Spec.Template.Spec.DeprecatedServiceAccount = account
		_, err = nonadmin.BatchV1().Jobs(namespace).Create(ctx, alias, createDry)
		deny("template", err)
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "no-execution-pod", Namespace: namespace}, Spec: *copy.Spec.Template.Spec.DeepCopy()}
		_, err = nonadmin.CoreV1().Pods(namespace).Create(ctx, pod, createDry)
		deny("pod", err)
		for _, producer := range []string{users[1], users[3], users[4]} {
			if _, err := clients[producer].CoreV1().Pods(namespace).Create(ctx, pod, createDry); err != nil {
				t.Fatal("legitimate authenticated Pod producer was refused")
			}
		}
		cron := &batchv1.CronJob{ObjectMeta: metav1.ObjectMeta{Name: "no-execution-cron", Namespace: namespace}, Spec: batchv1.CronJobSpec{
			Schedule: "0 0 * * *", JobTemplate: batchv1.JobTemplateSpec{Spec: copy.Spec},
		}}
		_, err = nonadmin.BatchV1().CronJobs(namespace).Create(ctx, cron, createDry)
		deny("cronjob", err)
		if _, err := admin.BatchV1().CronJobs(namespace).Create(ctx, cron, createDry); err != nil {
			t.Fatal("trusted maintenance CronJob was refused")
		}
		if _, err := clients[users[5]].BatchV1().Jobs(namespace).Create(ctx, copy, createDry); err != nil {
			t.Fatal("legitimate authenticated CronJob child producer was refused")
		}
	}
	// Both supported native APIs require an RC template. An invalid object is
	// not a policy positive probe; prove native validation separately, then use
	// a valid ordinary template to check unrelated workload compatibility.
	optional := &corev1.ReplicationController{ObjectMeta: metav1.ObjectMeta{Name: "unrelated-template-absent", Namespace: namespace}, Spec: corev1.ReplicationControllerSpec{Replicas: ptr.To(int32(0)), Selector: map[string]string{"test": "absent"}}}
	if _, err := admin.CoreV1().ReplicationControllers(namespace).Create(ctx, optional, createDry); !apierrors.IsInvalid(err) {
		t.Fatal("native absent-template invalidity was not proved")
	}
	optional.Spec.Template = installed.Spec.Template.DeepCopy()
	optional.Spec.Template.Labels = optional.Spec.Selector
	optional.Spec.Template.Spec.ServiceAccountName = "default"
	if _, err := nonadmin.CoreV1().ReplicationControllers(namespace).Create(ctx, optional, createDry); err != nil {
		t.Fatal("guard obstructed a valid unrelated producer")
	}
	optional.Spec.Template.Spec.ServiceAccountName = "arcadectl-destroy-controller"
	_, err := nonadmin.CoreV1().ReplicationControllers(namespace).Create(ctx, optional, createDry)
	deny("template", err)
	oldOnly := installed.DeepCopy()
	oldOnly.Spec.Template.Spec.ServiceAccountName = "default"
	_, err = ordinary.AppsV1().Deployments(namespace).Update(ctx, oldOnly, updateDry)
	deny("template", err)
	// A caller-supplied label cannot remove reserved-name or old-template guards.
	oldOnly.Labels = map[string]string{"app.kubernetes.io/part-of": "unrelated"}
	_, err = ordinary.AppsV1().Deployments(namespace).Update(ctx, oldOnly, updateDry)
	deny("template", err)
	// Establish native serving for the metadata-only family independently.
	for _, account := range []string{"arcadectl-controller", "arcadectl-api", "arcadectl-destroy-controller", "arcadectl-destroy-admin"} {
		actorCan(nonadmin, "delete", "", "serviceaccounts", "", account, true)
		deny("identity", nonadmin.CoreV1().ServiceAccounts(namespace).Delete(ctx, account, deleteDry))
	}
	roles, err := admin.RbacV1().Roles(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal("owned reserved-role inventory unavailable")
	}
	roleProofs := 0
	for _, candidate := range roles.Items {
		if candidate.Name == "arcadectl-controller" || candidate.Name == "arcadectl-destroy-controller" {
			actorCan(nonadmin, "delete", rbacv1.GroupName, "roles", "", candidate.Name, true)
			deny("identity", nonadmin.RbacV1().Roles(namespace).Delete(ctx, candidate.Name, deleteDry))
			roleProofs++
		}
	}
	if roleProofs != 2 {
		t.Fatal("reserved-role denial inventory is incomplete")
	}
	bindings, err := admin.RbacV1().RoleBindings(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal("owned reserved-binding inventory unavailable")
	}
	bindingProofs := 0
	for _, candidate := range bindings.Items {
		if candidate.Name == "arcadectl-controller" || candidate.Name == "arcadectl-destroy-controller" {
			deny("identity", nonadmin.RbacV1().RoleBindings(namespace).Delete(ctx, candidate.Name, deleteDry))
			bindingProofs++
		}
	}
	if bindingProofs != 2 {
		t.Fatal("reserved-binding denial inventory is incomplete")
	}
	service := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "arcadectl-api", Namespace: namespace}, Spec: corev1.ServiceSpec{Ports: []corev1.ServicePort{{Port: 443}}}}
	_, err = nonadmin.CoreV1().Services(namespace).Create(ctx, service, createDry)
	deny("identity", err)
	// Seed only an inert ReplicaSet in this API-only fixture. No child is made.
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "owned-producer-proof", Namespace: namespace}, Spec: appsv1.ReplicaSetSpec{
		Replicas: ptr.To(int32(1)), Selector: installed.Spec.Selector.DeepCopy(), Template: *installed.Spec.Template.DeepCopy(),
	}}
	for _, producer := range []string{users[1], users[2]} {
		if _, err := clients[producer].AppsV1().ReplicaSets(namespace).Create(ctx, rs, createDry); err != nil {
			t.Fatal("trusted ReplicaSet producer creation was refused")
		}
	}
	_, err = nonadmin.AppsV1().ReplicaSets(namespace).Create(ctx, rs, createDry)
	deny("replicaset", err)
	seeded, err := admin.AppsV1().ReplicaSets(namespace).Create(ctx, rs, metav1.CreateOptions{})
	if err != nil {
		t.Fatal("owned inert ReplicaSet seed was refused")
	}
	for _, producer := range []string{users[1], users[2]} {
		for _, replicas := range []int32{0, 3} {
			changed := seeded.DeepCopy()
			changed.Spec.Replicas = ptr.To(replicas)
			changed.Annotations = map[string]string{"deployment.kubernetes.io/revision": "2"}
			if _, err := clients[producer].AppsV1().ReplicaSets(namespace).Update(ctx, changed, updateDry); err != nil {
				t.Fatal("legitimate authenticated ReplicaSet scaling was refused")
			}
			_, err = nonadmin.AppsV1().ReplicaSets(namespace).Update(ctx, changed, updateDry)
			deny("replicaset", err)
		}
		changed := seeded.DeepCopy()
		changed.Spec.Template.Spec.Containers[0].Image = "example.invalid/untrusted:latest"
		_, err = clients[producer].AppsV1().ReplicaSets(namespace).Update(ctx, changed, updateDry)
		deny("replicaset", err)
		changed = seeded.DeepCopy()
		changed.Spec.MinReadySeconds = 9
		_, err = clients[producer].AppsV1().ReplicaSets(namespace).Update(ctx, changed, updateDry)
		deny("replicaset", err)
	}
	if err := clients[users[6]].AppsV1().ReplicaSets(namespace).Delete(ctx, seeded.Name, deleteDry); err != nil {
		t.Fatal("legitimate authenticated ReplicaSet garbage collection was refused")
	}
	// Scale has no template identity. Reserved names are guarded and the
	// ordinary shipped Role's lack of all Scale writes is proved separately.
	actorCan(nonadmin, "update", "apps", "deployments", "scale", installed.Name, true)
	scale, err := admin.AppsV1().Deployments(namespace).GetScale(ctx, installed.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal("owned executable Scale fixture unavailable")
	}
	scale.Spec.Replicas = 0
	_, err = nonadmin.AppsV1().Deployments(namespace).UpdateScale(ctx, installed.Name, scale, updateDry)
	deny("scale", err)
	if _, err := admin.AppsV1().Deployments(namespace).UpdateScale(ctx, installed.Name, scale, updateDry); err != nil {
		t.Fatal("trusted maintenance Scale request was refused")
	}
	// Seed one inert privileged Pod to exercise oldObject and executable
	// subresource updates. There is no scheduler/kubelet to run its image.
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "owned-pod-proof", Namespace: namespace}, Spec: *job.Spec.Template.Spec.DeepCopy()}
	pod.Spec.Containers[0].Resources = corev1.ResourceRequirements{
		Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("100m"), corev1.ResourceMemory: resource.MustParse("64Mi")},
		Limits:   corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("100m"), corev1.ResourceMemory: resource.MustParse("64Mi")},
	}
	seedPod, err := admin.CoreV1().Pods(namespace).Create(ctx, pod, metav1.CreateOptions{})
	if err != nil {
		t.Fatal("owned inert privileged Pod seed was refused")
	}
	actorCan(ordinary, "update", "", "pods", "", seedPod.Name, true)
	imageChange := seedPod.DeepCopy()
	imageChange.Spec.Containers[0].Image = "example.invalid/untrusted:latest"
	if _, err := admin.CoreV1().Pods(namespace).Update(ctx, imageChange, updateDry); err != nil {
		t.Fatal("native Pod image-change probe was not valid")
	}
	_, err = ordinary.CoreV1().Pods(namespace).Update(ctx, imageChange, updateDry)
	deny("pod", err)
	_, err = clients[users[3]].CoreV1().Pods(namespace).Update(ctx, imageChange, updateDry)
	deny("pod", err)
	metadataOnly := seedPod.DeepCopy()
	metadataOnly.Annotations = map[string]string{"test": "producer-metadata"}
	if _, err := clients[users[3]].CoreV1().Pods(namespace).Update(ctx, metadataOnly, updateDry); err != nil {
		t.Fatal("legitimate producer metadata-only Pod update was refused")
	}
	_, err = ordinary.CoreV1().Pods(namespace).Update(ctx, metadataOnly, updateDry)
	deny("pod", err)
	actorCan(nonadmin, "update", "", "pods", "ephemeralcontainers", seedPod.Name, true)
	ephemeral := seedPod.DeepCopy()
	ephemeral.Spec.EphemeralContainers = []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{
		Name: "no-execution-debug", Image: "example.invalid/untrusted:latest", SecurityContext: seedPod.Spec.Containers[0].SecurityContext.DeepCopy(),
	}, TargetContainerName: seedPod.Spec.Containers[0].Name}}
	if _, err := admin.CoreV1().Pods(namespace).UpdateEphemeralContainers(ctx, seedPod.Name, ephemeral, updateDry); err != nil {
		t.Fatal("native ephemeral-container probe was not valid")
	}
	_, err = nonadmin.CoreV1().Pods(namespace).UpdateEphemeralContainers(ctx, seedPod.Name, ephemeral, updateDry)
	deny("pod", err)
	_, err = clients[users[3]].CoreV1().Pods(namespace).UpdateEphemeralContainers(ctx, seedPod.Name, ephemeral, updateDry)
	deny("pod", err)
	actorCan(nonadmin, "update", "", "pods", "resize", seedPod.Name, true)
	resized := seedPod.DeepCopy()
	resized.Spec.Containers[0].Resources.Requests[corev1.ResourceCPU] = resource.MustParse("200m")
	resized.Spec.Containers[0].Resources.Limits[corev1.ResourceCPU] = resource.MustParse("200m")
	if _, err := admin.CoreV1().Pods(namespace).UpdateResize(ctx, seedPod.Name, resized, updateDry); err != nil {
		t.Fatal("native Pod resize probe was not valid")
	}
	_, err = nonadmin.CoreV1().Pods(namespace).UpdateResize(ctx, seedPod.Name, resized, updateDry)
	deny("pod", err)
	if err := clients[users[6]].CoreV1().Pods(namespace).Delete(ctx, seedPod.Name, deleteDry); err != nil {
		t.Fatal("legitimate Pod garbage collection was refused")
	}
	deny("pod", nonadmin.CoreV1().Pods(namespace).Delete(ctx, seedPod.Name, deleteDry))
	currentPod, err := admin.CoreV1().Pods(namespace).Get(ctx, seedPod.Name, metav1.GetOptions{})
	if err != nil || currentPod.UID != seedPod.UID || currentPod.ResourceVersion != seedPod.ResourceVersion || currentPod.Spec.Containers[0].Image != seedPod.Spec.Containers[0].Image || len(currentPod.Spec.EphemeralContainers) != 0 {
		t.Fatal("Pod mutation dry runs changed the inert original")
	}
	if err := admin.CoreV1().Pods(namespace).Delete(ctx, seedPod.Name, metav1.DeleteOptions{GracePeriodSeconds: ptr.To(int64(0)), Preconditions: &metav1.Preconditions{UID: &seedPod.UID, ResourceVersion: &seedPod.ResourceVersion}}); err != nil {
		t.Fatal("owned inert Pod cleanup failed")
	}
	// Assert dry runs did not actually scale or replace the seeded producer.
	current, err := admin.AppsV1().ReplicaSets(namespace).Get(ctx, seeded.Name, metav1.GetOptions{})
	if err != nil || current.UID != seeded.UID || current.ResourceVersion != seeded.ResourceVersion || *current.Spec.Replicas != *seeded.Spec.Replicas {
		t.Fatal("producer dry runs mutated the inert seed")
	}
}
