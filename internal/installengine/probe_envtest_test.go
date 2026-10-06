//go:build envtest

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

// This certifies the private transport's six paired CREATE probes against both
// exact profiles with native ServiceAccount admission enabled. It is not a
// complete lifecycle proof: envtest has no kubelet or VAP status controller,
// and CREATE does not establish UPDATE, subresource or PVC DELETE behavior.
func TestEnvtestNativeAdmissionProbeDeclaredProfiles(t *testing.T) {
	for _, profile := range []string{installrender.Profile135, installrender.Profile137} {
		t.Run(profile, func(t *testing.T) {
			plan := fixturePlanProfile(t, "isolated-install", profile)
			crds, err := filepath.Abs("../../config/crd/bases")
			if err != nil {
				t.Fatal(err)
			}
			environment := &envtest.Environment{UseExistingCluster: new(bool), CRDDirectoryPaths: []string{crds}, ErrorIfCRDPathMissing: true, DownloadBinaryAssets: true, DownloadBinaryAssetsVersion: plan.Profile().KubernetesVersion, DownloadBinaryAssetsIndexURL: "https://raw.githubusercontent.com/kubernetes-sigs/controller-tools/1031496fc98a4f51010c3bdfdeb57b5d67bea7bd/envtest-releases.yaml", BinaryAssetsDirectory: t.TempDir(), ControlPlaneStartTimeout: 90 * time.Second, ControlPlaneStopTimeout: 30 * time.Second}
			if profile == installrender.Profile135 {
				prerequisite135Assets(t, environment)
			} else {
				environment.ControlPlane.APIServer = &envtest.APIServer{}
			}
			environment.ControlPlane.APIServer.Configure().Set("disable-admission-plugins", "")
			config, err := environment.Start()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := environment.Stop(); err != nil {
					t.Error(err)
				}
			})
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()
			access, err := NewDirectHTTPAccess(config)
			if err != nil {
				t.Fatal(err)
			}
			if err := access.checkVersion(ctx, plan.Profile()); err != nil {
				t.Fatal(err)
			}
			admin, err := kubernetes.NewForConfig(config)
			if err != nil {
				t.Fatal(err)
			}
			custom, err := dynamic.NewForConfig(config)
			if err != nil {
				t.Fatal(err)
			}
			policies := map[string]*admissionv1.ValidatingAdmissionPolicy{}
			bindings := map[string]string{}
			for _, resource := range plan.Resources() {
				object := resource.Object
				switch object.GetKind() {
				case "Namespace":
					var ns corev1.Namespace
					if decodeServing(object, &ns) != nil {
						t.Fatal("signed namespace decode")
					}
					if _, err := admin.CoreV1().Namespaces().Create(ctx, &ns, metav1.CreateOptions{}); err != nil {
						t.Fatal(err)
					}
				case "ServiceAccount", "Role", "RoleBinding", "ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding":
					if _, err := access.Create(ctx, resourceKey(resource), object, false); err != nil {
						t.Fatal("signed fixture dependency: ", err)
					}
					if object.GetKind() == "ValidatingAdmissionPolicy" {
						var policy admissionv1.ValidatingAdmissionPolicy
						if decodeServing(object, &policy) != nil {
							t.Fatal("signed policy decode")
						}
						policies[policy.Name] = &policy
					} else if object.GetKind() == "ValidatingAdmissionPolicyBinding" {
						var binding admissionv1.ValidatingAdmissionPolicyBinding
						if decodeServing(object, &binding) != nil {
							t.Fatal("signed binding decode")
						}
						bindings[binding.Spec.PolicyName] = binding.Name
					}
				}
			}
			if len(policies) != 6 || len(bindings) != 6 {
				t.Fatal("not the full signed admission set")
			}
			for name, policy := range policies {
				positive, negative, index, err := admissionCreateProbe(plan, name, "arcadectl-controller", "arcadectl-probe-0123456789abcdef0123456789abcdef")
				if err != nil {
					t.Fatal(err)
				}
				message := policy.Spec.Validations[index].Message
				if err := wait.PollUntilContextTimeout(ctx, 100*time.Millisecond, 15*time.Second, true, func(ctx context.Context) (bool, error) {
					_, err := access.probeCreate(ctx, negative, name, bindings[name], message)
					return err == nil, nil
				}); err != nil {
					// Public-only fixtures in this owned API server: a typed native
					// error diagnoses recipe disagreement without changing the
					// production transport's raw-error redaction contract.
					gvr := schema.GroupVersionResource{Version: "v1", Resource: "pods"}
					if negative.GetKind() == "PersistentVolumeClaim" {
						gvr.Resource = "persistentvolumeclaims"
					}
					if negative.GetKind() == "GameDestroy" {
						gvr = schema.GroupVersionResource{Group: "arcade.gobha.me", Version: "v1alpha1", Resource: "gamedestroys"}
					}
					_, nativeErr := custom.Resource(gvr).Namespace(plan.Namespace()).Create(ctx, negative, metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}, FieldManager: "arcadectl-installer", FieldValidation: "Strict"})
					t.Fatalf("owned public probe native denial mismatch for %s: %v", name, nativeErr)
				}
				start := time.Now().UTC()
				result, err := access.probeCreate(ctx, positive, "", "", "")
				if err != nil {
					t.Fatalf("native positive probe refused for %s: %v", name, err)
				}
				if !validAdmissionProbeResult(positive, result, start, time.Now().UTC()) {
					// Only public fixture shape, never credentials/private errors.
					encoded, _ := json.Marshal(result.Object)
					t.Fatalf("owned native positive shape mismatch %s: %s", name, encoded)
				}
			}
			pods, err := admin.CoreV1().Pods(plan.Namespace()).List(ctx, metav1.ListOptions{})
			if err != nil || len(pods.Items) != 0 {
				t.Fatal("Pod probe persisted")
			}
			claims, err := admin.CoreV1().PersistentVolumeClaims(plan.Namespace()).List(ctx, metav1.ListOptions{})
			if err != nil || len(claims.Items) != 0 {
				t.Fatal("PVC probe persisted")
			}
			destroys, err := custom.Resource(schema.GroupVersionResource{Group: "arcade.gobha.me", Version: "v1alpha1", Resource: "gamedestroys"}).Namespace(plan.Namespace()).List(ctx, metav1.ListOptions{})
			if err != nil || len(destroys.Items) != 0 {
				t.Fatal("GameDestroy probe persisted")
			}
			proveNativeNamedAdmissionProbes(t, ctx, plan, access, custom, config, policies, bindings)
		})
	}
}

// Live oldObjects are essential: dry-run CREATE cannot seed UPDATE/DELETE.
// These fixtures exist ONLY in a test-owned API server, have no executable
// scheduler/kubelet, and use closed scheduling gates and nonprovisioning PVCs.
// This does not grant the production installer fixture mutation privileges or
// constitute a completed AdmissionEffective/lifecycle proof.
func proveNativeNamedAdmissionProbes(t *testing.T, ctx context.Context, plan *installrender.Plan, access *HTTPAccess, custom dynamic.Interface, config *rest.Config, policies map[string]*admissionv1.ValidatingAdmissionPolicy, bindings map[string]string) {
	t.Helper()
	// Native wire/actor authorization evidence only. envtest has no policy
	// status controller, so this does NOT manufacture configured status or
	// claim newActors' complete original-inventory admission proof.
	actorClient := func(actor admissionActor) *HTTPAccess {
		t.Helper()
		key := installstate.Key{APIVersion: "v1", Kind: "ServiceAccount", Namespace: plan.Namespace(), Name: actor.account()}
		permission, err := publicPermission(key, "get")
		if err != nil {
			t.Fatal(err)
		}
		permission.spec.ResourceAttributes.Verb = "impersonate"
		if access.authorize(ctx, permission.spec) != nil {
			t.Fatal("native admin lacks exact actor impersonation right")
		}
		client, err := access.actorClient(actor, plan.Namespace())
		if err != nil {
			t.Fatal(err)
		}
		return client
	}
	ordinaryAccess := actorClient(ordinaryControllerActor)
	destroyAccess := actorClient(destroyControllerActor)
	adminAccess := actorClient(destroyAdministratorActor)
	policyName := func(stem string) string {
		t.Helper()
		found := ""
		for name := range policies {
			if name == stem || strings.HasPrefix(name, stem+"-") {
				if found != "" {
					t.Fatal("ambiguous signed policy stem")
				}
				found = name
			}
		}
		if found == "" {
			t.Fatal("missing signed policy stem:", stem)
		}
		return found
	}
	clientFor := func(o *unstructured.Unstructured) dynamic.ResourceInterface {
		key := schema.GroupVersionResource{Version: "v1", Resource: "pods"}
		if o.GetKind() == "PersistentVolumeClaim" {
			key.Resource = "persistentvolumeclaims"
		}
		if o.GetKind() == "GameDestroy" {
			key = schema.GroupVersionResource{Group: "arcade.gobha.me", Version: "v1alpha1", Resource: "gamedestroys"}
		}
		return custom.Resource(key).Namespace(plan.Namespace())
	}
	create := func(o *unstructured.Unstructured) *unstructured.Unstructured {
		t.Helper()
		live, err := clientFor(o).Create(ctx, o, metav1.CreateOptions{FieldManager: "arcadectl-installer", FieldValidation: "Strict"})
		if err != nil {
			t.Fatal("owned inert native fixture create:", err)
		}
		return live
	}
	check := func(name string, a *HTTPAccess, op admissionProbeOperation, original, desired *unstructured.Unstructured, policy string, index int) {
		t.Helper()
		if a.actor != nil {
			permission, err := actorPermission(resourceKeyFromObject(desired), op)
			if err != nil || a.authorize(ctx, permission.spec) != nil {
				t.Fatal("native actor lacks exact operation authority", name)
			}
		}
		binding, message := "", ""
		if policy != "" {
			binding = bindings[policy]
			message = policies[policy].Spec.Validations[index].Message
		}
		result, err := a.probeOperation(ctx, op, desired, policy, binding, message)
		if err != nil {
			// Public-only test objects in our private API server may be decoded
			// for diagnosis; production errors remain fixed and fully stripped.
			var native *unstructured.Unstructured
			var nativeErr error
			if op == probeDeletePVCOperation {
				uid, rv := desired.GetUID(), desired.GetResourceVersion()
				nativeErr = clientFor(desired).Delete(ctx, desired.GetName(), metav1.DeleteOptions{DryRun: []string{metav1.DryRunAll}, Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &rv}})
			} else {
				var sub []string
				if op == probeEphemeralOperation {
					sub = []string{"ephemeralcontainers"}
				}
				if op == probeResizeOperation {
					sub = []string{"resize"}
				}
				native, nativeErr = clientFor(desired).Update(ctx, desired, metav1.UpdateOptions{DryRun: []string{metav1.DryRunAll}, FieldValidation: "Strict", FieldManager: "arcadectl-installer"}, sub...)
			}
			encoded, _ := json.Marshal(native)
			t.Fatalf("owned native %s probe refused: %v; public native result %s error %v", name, err, encoded, nativeErr)
		}
		if policy == "" && result == nil || policy != "" && result != nil {
			t.Fatal("unexpected native operation result")
		}
		// The private seam checks native identity only, never treats an accepted
		// response as whole-template or live ownership proof. Independently
		// certify this fixture's result shape and nonpersistence here.
		if result != nil {
			if op == probeDeletePVCOperation {
				if result.GetDeletionTimestamp() == nil {
					t.Fatal("native PVC DELETE omitted deletion timestamp")
				}
			} else if !reflect.DeepEqual(result.Object["spec"], desired.Object["spec"]) {
				encoded, _ := json.Marshal(result.Object)
				t.Fatalf("owned native %s defaulted spec mismatch: %s", name, encoded)
			}
		}
		after, err := clientFor(original).Get(ctx, original.GetName(), metav1.GetOptions{})
		if err != nil || !reflect.DeepEqual(after.Object, original.Object) {
			t.Fatalf("owned native %s dry-run changed original fixture: %v", name, err)
		}
	}
	checkCreate := func(name string, a *HTTPAccess, desired *unstructured.Unstructured, policy string, index int) {
		t.Helper()
		permission, err := actorPermission(resourceKeyFromObject(desired), probeCreateOperation)
		if err != nil || a.authorize(ctx, permission.spec) != nil {
			t.Fatal("native actor lacks collection CREATE authority", name)
		}
		binding, message := "", ""
		if policy != "" {
			binding, message = bindings[policy], policies[policy].Spec.Validations[index].Message
		}
		start := time.Now().UTC()
		result, err := a.probeCreate(ctx, desired, policy, binding, message)
		if err != nil || policy != "" && result != nil || policy == "" && !validAdmissionProbeResult(desired, result, start, time.Now().UTC()) {
			// All input/output here is a fixed public fixture in our disposable
			// API server, never cluster credentials or a production response.
			encoded, _ := json.Marshal(result)
			t.Fatalf("native actor CREATE evidence refused %s: %v; public shape %s", name, err, encoded)
		}
		if _, err := clientFor(desired).Get(ctx, desired.GetName(), metav1.GetOptions{}); !apierrors.IsNotFound(err) {
			t.Fatal("native actor CREATE persisted", name)
		}
	}
	for _, worker := range []string{"backup", "restore", "destroy"} {
		policy := policyName("arcadectl-" + worker + "-worker-gate")
		positive, _, _, err := admissionCreateProbe(plan, policy, "arcadectl-controller", "arcadectl-probe-0123456789abcdef0123456789abcdef")
		if err != nil {
			t.Fatal(err)
		}
		positive.SetName("arcadectl-probe-" + worker)
		// Real workers have a Job owner. Restore/destroy executable-field
		// checks compare that metadata directly, so an ownerless CREATE probe
		// is not a valid positive UPDATE fixture. Seed an actual suspended,
		// parallelism-zero Job; do not invent an owner UID or run a worker.
		job := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "batch/v1", "kind": "Job",
			"metadata": map[string]any{"name": worker + "-admission-probe", "namespace": plan.Namespace()},
			"spec":     map[string]any{"parallelism": int64(0), "suspend": true, "template": map[string]any{"metadata": map[string]any{"labels": positive.Object["metadata"].(map[string]any)["labels"]}, "spec": positive.Object["spec"]}},
		}}
		owner, err := custom.Resource(schema.GroupVersionResource{Group: "batch", Version: "v1", Resource: "jobs"}).Namespace(plan.Namespace()).Create(ctx, job, metav1.CreateOptions{})
		if err != nil {
			t.Fatal("owned inert Job fixture create:", err)
		}
		yes := true
		positive.SetOwnerReferences([]metav1.OwnerReference{{APIVersion: "batch/v1", Kind: "Job", Name: owner.GetName(), UID: owner.GetUID(), Controller: &yes, BlockOwnerDeletion: &yes}})
		live := create(positive)
		check(worker+" unchanged update", access, probeUpdateOperation, live, live.DeepCopy(), "", 0)
		changed := live.DeepCopy()
		containers, _, _ := unstructured.NestedSlice(changed.Object, "spec", "containers")
		containers[0].(map[string]any)["image"] = "registry.example/foreign:test"
		_ = unstructured.SetNestedSlice(changed.Object, containers, "spec", "containers")
		check(worker+" executable update", access, probeUpdateOperation, live, changed, policy, 2)
		changed = live.DeepCopy()
		unstructured.RemoveNestedField(changed.Object, "spec", "schedulingGates")
		check(worker+" unauthorized gate removal", access, probeUpdateOperation, live, changed, policy, 3)
		changed = live.DeepCopy()
		changed.SetAnnotations(map[string]string{"arcade.gobha.me/" + worker + "-pod-authorized": "foreign-uid"})
		check(worker+" UID marker update", access, probeUpdateOperation, live, changed, policy, 3)
		correct, wrong := ordinaryAccess, destroyAccess
		if worker == "destroy" {
			correct, wrong = destroyAccess, ordinaryAccess
		}
		changed = live.DeepCopy()
		unstructured.RemoveNestedField(changed.Object, "spec", "schedulingGates")
		changed.SetAnnotations(map[string]string{"arcade.gobha.me/" + worker + "-pod-authorized": string(live.GetUID())})
		check(worker+" original actor gate authorization", correct, probeUpdateOperation, live, changed, "", 0)
		check(worker+" wrong actor gate authorization", wrong, probeUpdateOperation, live, changed, policy, 3)
		check(worker+" ephemeral subresource", access, probeEphemeralOperation, live, live.DeepCopy(), policy, 0)
		check(worker+" resize subresource", access, probeResizeOperation, live, live.DeepCopy(), policy, 0)
	}
	// Paired native subresource successes on a non-worker, still gated Pod
	// establish route/verb validity; a worker rejection cannot be a 404/RBAC
	// substitute. Persistent setup remains owned by this fixture, not engine.
	plain, _, _, err := admissionCreateProbe(plan, policyName("arcadectl-backup-worker-gate"), "arcadectl-controller", "arcadectl-probe-0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	plain.SetName("arcadectl-probe-plain")
	plain.SetLabels(nil)
	_ = unstructured.SetNestedSlice(plain.Object, []any{map[string]any{"name": "example.com/hold"}}, "spec", "schedulingGates")
	pl := create(plain)
	check("plain ephemeral", access, probeEphemeralOperation, pl, pl.DeepCopy(), "", 0)
	check("plain resize", access, probeResizeOperation, pl, pl.DeepCopy(), "", 0)
	_, candidate, _, err := admissionCreateProbe(plan, policyName("arcadectl-restore-candidate-pvc-create"), "arcadectl-controller", "arcadectl-probe-0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	checkCreate("ordinary restore candidate", ordinaryAccess, candidate, "", 0)

	retained, _, _, err := admissionCreateProbe(plan, policyName("arcadectl-retained-world-pvc-delete"), "arcadectl-controller", "arcadectl-probe-0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	retained.SetName("arcadectl-probe-retained")
	claim := create(retained)
	policy := policyName("arcadectl-retained-world-pvc-delete")
	check("retained unchanged update", access, probeUpdateOperation, claim, claim.DeepCopy(), "", 0)
	changed := claim.DeepCopy()
	labels := changed.GetLabels()
	delete(labels, "arcade.gobha.me/data-policy")
	changed.SetLabels(labels)
	check("retained label removal", access, probeUpdateOperation, claim, changed, policy, 3)
	changed = claim.DeepCopy()
	changed.SetAnnotations(map[string]string{"arcade.gobha.me/cold-backup-uid": "foreign-backup"})
	check("retained marker change", access, probeUpdateOperation, claim, changed, policy, 1)
	check("ordinary retained marker change", ordinaryAccess, probeUpdateOperation, claim, changed, "", 0)
	check("retained DELETE", access, probeDeletePVCOperation, claim, claim.DeepCopy(), policy, 2)
	check("dedicated retained DELETE", destroyAccess, probeDeletePVCOperation, claim, claim.DeepCopy(), "", 0)
	// Seed a native old marker using the actual signed ordinary-controller
	// RBAC, solely in this fixture. Removing an existing marker is a distinct
	// oldObject branch from trying to forge a new one.
	ordinaryConfig := rest.CopyConfig(config)
	ordinaryConfig.Impersonate = rest.ImpersonationConfig{UserName: "system:serviceaccount:" + plan.Namespace() + ":arcadectl-controller"}
	ordinaryCustom, err := dynamic.NewForConfig(ordinaryConfig)
	if err != nil {
		t.Fatal(err)
	}
	marked, err := ordinaryCustom.Resource(schema.GroupVersionResource{Version: "v1", Resource: "persistentvolumeclaims"}).Namespace(plan.Namespace()).Update(ctx, changed, metav1.UpdateOptions{})
	if err != nil {
		t.Fatal("owned marker fixture update:", err)
	}
	cleared := marked.DeepCopy()
	cleared.SetAnnotations(nil)
	check("retained marker removal", access, probeUpdateOperation, marked, cleared, policy, 1)
	check("ordinary retained marker removal", ordinaryAccess, probeUpdateOperation, marked, cleared, "", 0)
	plainClaim := retained.DeepCopy()
	plainClaim.SetName("arcadectl-probe-plain-claim")
	plainClaim.SetLabels(nil)
	cl := create(plainClaim)
	check("plain DELETE", access, probeDeletePVCOperation, cl, cl.DeepCopy(), "", 0)
	liveRV, err := strconv.ParseUint(cl.GetResourceVersion(), 10, 64)
	if err != nil || liveRV <= 1 {
		t.Fatal("unexpected native fixture RV")
	}
	for _, op := range []admissionProbeOperation{probeUpdateOperation, probeDeletePVCOperation} {
		for _, field := range []string{"uid", "resourceVersion"} {
			wrong := cl.DeepCopy()
			if field == "uid" {
				wrong.SetUID("foreign-uid")
			} else {
				wrong.SetResourceVersion(strconv.FormatUint(liveRV-1, 10))
			}
			if _, err := access.probeOperation(ctx, op, wrong, "", "", ""); err != ErrAdmission {
				t.Fatal("native named operation accepted foreign old identity")
			}
			if field == "resourceVersion" {
				// Independently prove the server conflict, not merely the
				// seam refusing a changed response RV after an unconditional
				// update. In particular RV zero is NOT a stale-RV fixture.
				var nativeErr error
				if op == probeUpdateOperation {
					_, nativeErr = clientFor(cl).Update(ctx, wrong, metav1.UpdateOptions{DryRun: []string{metav1.DryRunAll}})
				} else {
					uid, rv := wrong.GetUID(), wrong.GetResourceVersion()
					nativeErr = clientFor(cl).Delete(ctx, wrong.GetName(), metav1.DeleteOptions{DryRun: []string{metav1.DryRunAll}, Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &rv}})
				}
				if !apierrors.IsConflict(nativeErr) {
					t.Fatalf("native nonzero stale RV was not a conflict: %v", nativeErr)
				}
			}
			after, err := clientFor(cl).Get(ctx, cl.GetName(), metav1.GetOptions{})
			if err != nil || !reflect.DeepEqual(after.Object, cl.Object) {
				t.Fatal("foreign-identity dry-run changed fixture")
			}
		}
	}

	destroy, _, _, err := admissionCreateProbe(plan, policyName("arcadectl-destroy-unsafe-admin"), "arcadectl-controller", "arcadectl-probe-0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	destroy.SetName("arcadectl-probe-destroy")
	d := create(destroy)
	check("destroy unchanged update", access, probeUpdateOperation, d, d.DeepCopy(), "", 0)
	unsafe := d.DeepCopy()
	unstructured.RemoveNestedField(unsafe.Object, "spec", "backupRef")
	unstructured.RemoveNestedField(unsafe.Object, "spec", "repositorySecretRef")
	_ = unstructured.SetNestedField(unsafe.Object, "UnsafeNoBackup", "spec", "mode")
	_ = unstructured.SetNestedField(unsafe.Object, "owned native admission fixture", "spec", "unsafeReason")
	unsafe.SetAnnotations(map[string]string{"arcade.gobha.me/unsafe-requested-by": "system:serviceaccount:" + plan.Namespace() + ":arcadectl-destroy-admin"})
	// Typed setup stays test-owned. Closed actor clients use the production
	// wire guard; no TokenRequest, extra grant or identity fallback is added.
	adminConfig := rest.CopyConfig(config)
	adminConfig.Impersonate = rest.ImpersonationConfig{UserName: "system:serviceaccount:" + plan.Namespace() + ":arcadectl-destroy-admin"}
	adminCustom, err := dynamic.NewForConfig(adminConfig)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"uid", "resourceVersion", "managedFields", "creationTimestamp", "generation"} {
		unstructured.RemoveNestedField(unsafe.Object, "metadata", field)
	}
	unsafe.SetName("arcadectl-probe-unsafe")
	checkCreate("distinct unsafe admin CREATE", adminAccess, unsafe, "", 0)
	badAudit := unsafe.DeepCopy()
	badAudit.SetAnnotations(map[string]string{"arcade.gobha.me/unsafe-requested-by": "foreign-admin"})
	checkCreate("distinct unsafe malformed audit CREATE", adminAccess, badAudit, policyName("arcadectl-destroy-unsafe-admin"), 1)
	u, err := adminCustom.Resource(schema.GroupVersionResource{Group: "arcade.gobha.me", Version: "v1alpha1", Resource: "gamedestroys"}).Namespace(plan.Namespace()).Create(ctx, unsafe, metav1.CreateOptions{})
	if err != nil {
		t.Fatal("owned unsafe fixture create:", err)
	}
	// Mode changes are refused by CRD transition validation before VAP.
	// Exercise the intended VAP UPDATE branch with a valid mutable spec
	// field on an already-unsafe object, using the destroy controller's
	// metadata-only exception rather than a mode-changing false positive.
	check("unsafe controller unchanged update", destroyAccess, probeUpdateOperation, u, u.DeepCopy(), "", 0)
	changed = u.DeepCopy()
	_ = unstructured.SetNestedField(changed.Object, true, "spec", "cancelRequested")
	check("unsafe controller spec update", destroyAccess, probeUpdateOperation, u, changed, policyName("arcadectl-destroy-unsafe-admin"), 0)
	check("unsafe admin mutable spec update", adminAccess, probeUpdateOperation, u, changed, "", 0)
	changed = u.DeepCopy()
	changed.SetAnnotations(map[string]string{"arcade.gobha.me/unsafe-requested-by": "foreign-admin"})
	check("unsafe audit identity update", adminAccess, probeUpdateOperation, u, changed, policyName("arcadectl-destroy-unsafe-admin"), 1)
}
