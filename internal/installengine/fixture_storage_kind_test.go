//go:build kindinstall

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// Test-only candidate recipe certification, not production fixture ownership or
// permission. Called only inside the freshly created exact-profile Kind cluster;
// no external kubeconfig, shared PV, world or storage path is used. Empty storage
// class alone is NOT safe: ordinary static or prebound PVs can still bind it.
// Both pinned PV-controller sources instead route bind-completed + empty
// volumeName through ClaimLost, never binding/provisioning. Here actual running
// controllers must do so even with available/prebound PVs and repeated events.
// Never put this annotation on a real world or adopt an existing PVC with it.
func proveKindAdmissionFixtureStorage(t *testing.T, parent context.Context, config *rest.Config, anchor installstate.Anchor, plan *installrender.Plan) {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 3*time.Minute)
	defer cancel()
	admin, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatal("owned storage proof client unavailable")
	}
	checkNamespace := func(ctx context.Context) {
		t.Helper()
		ns, err := admin.CoreV1().Namespaces().Get(ctx, anchor.Namespace, metav1.GetOptions{})
		if err != nil || ns.UID != anchor.UID || ns.DeletionTimestamp != nil {
			t.Fatal("owned original namespace changed during storage proof")
		}
	}
	checkNamespace(ctx)
	priorVolumes, err := admin.CoreV1().PersistentVolumes().List(ctx, metav1.ListOptions{})
	if err != nil || len(priorVolumes.Items) != 0 {
		t.Fatal("fresh owned cluster storage absence unproved")
	}
	nonce, err := installstate.NewID()
	if err != nil {
		t.Fatal("storage proof nonce unavailable")
	}
	prefix := "arcadectl-probe-" + nonce + "-" // retained instance label <= 63 bytes
	type original struct {
		name     string
		uid      types.UID
		retained bool
	}
	var claims, volumes []original
	// An acknowledged UID is required for every cleanup. A lost acknowledgement
	// never becomes name/label adoption; the enclosing original Kind cluster is
	// independently removed by its own exact container/label cleanup.
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cleanupCancel()
		cleanupAdmin, err := kubernetes.NewForConfig(config)
		if err != nil {
			t.Error("storage cleanup client unavailable")
			return
		}
		// Retained synthetic claims use the ORIGINAL signed destroy account and
		// its existing PVC DELETE right. No Role or impersonation grant is added.
		destroyConfig := rest.CopyConfig(config)
		destroyConfig.Impersonate = rest.ImpersonationConfig{UserName: "system:serviceaccount:" + anchor.Namespace + ":arcadectl-destroy-controller"}
		destroy, err := kubernetes.NewForConfig(destroyConfig)
		if err != nil {
			t.Error("original destroy cleanup client unavailable")
			return
		}
		for _, original := range claims {
			live, err := cleanupAdmin.CoreV1().PersistentVolumeClaims(anchor.Namespace).Get(cleanupCtx, original.name, metav1.GetOptions{})
			if apierrors.IsNotFound(err) {
				continue
			}
			if err != nil || live.UID != original.uid || live.ResourceVersion == "" {
				t.Error("refusing unproved synthetic claim cleanup")
				continue
			}
			client := cleanupAdmin
			if original.retained {
				client = destroy
			}
			uid, rv := live.UID, live.ResourceVersion
			if err := client.CoreV1().PersistentVolumeClaims(anchor.Namespace).Delete(cleanupCtx, live.Name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &rv}}); err != nil {
				t.Error("original synthetic claim deletion refused")
				continue
			}
			if err := wait.PollUntilContextTimeout(cleanupCtx, 100*time.Millisecond, 20*time.Second, true, func(ctx context.Context) (bool, error) {
				live, err := cleanupAdmin.CoreV1().PersistentVolumeClaims(anchor.Namespace).Get(ctx, original.name, metav1.GetOptions{})
				if apierrors.IsNotFound(err) {
					return true, nil
				}
				if err != nil || live.UID != original.uid {
					return false, ErrOwnership
				}
				return false, nil
			}); err != nil {
				t.Error("synthetic claim actual absence unproved")
			}
		}
		for _, original := range volumes {
			live, err := cleanupAdmin.CoreV1().PersistentVolumes().Get(cleanupCtx, original.name, metav1.GetOptions{})
			if apierrors.IsNotFound(err) {
				continue
			}
			if err != nil || live.UID != original.uid || live.ResourceVersion == "" || live.Spec.PersistentVolumeReclaimPolicy != corev1.PersistentVolumeReclaimRetain {
				t.Error("refusing unproved synthetic volume cleanup")
				continue
			}
			uid, rv := live.UID, live.ResourceVersion
			if err := cleanupAdmin.CoreV1().PersistentVolumes().Delete(cleanupCtx, live.Name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &rv}}); err != nil {
				t.Error("original synthetic volume deletion refused")
				continue
			}
			if err := wait.PollUntilContextTimeout(cleanupCtx, 100*time.Millisecond, 20*time.Second, true, func(ctx context.Context) (bool, error) {
				live, err := cleanupAdmin.CoreV1().PersistentVolumes().Get(ctx, original.name, metav1.GetOptions{})
				if apierrors.IsNotFound(err) {
					return true, nil
				}
				if err != nil || live.UID != original.uid {
					return false, ErrOwnership
				}
				return false, nil
			}); err != nil {
				t.Error("synthetic volume actual absence unproved")
			}
		}
	})
	createPV := func(suffix, reservedFor string) *corev1.PersistentVolume {
		t.Helper()
		mode, pathType := corev1.PersistentVolumeFilesystem, corev1.HostPathDirectory
		pv := &corev1.PersistentVolume{ObjectMeta: metav1.ObjectMeta{Name: prefix + suffix}, Spec: corev1.PersistentVolumeSpec{
			Capacity: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("1Mi")}, AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			VolumeMode: &mode, StorageClassName: "", PersistentVolumeReclaimPolicy: corev1.PersistentVolumeReclaimRetain,
			// This path is NEVER created, mounted or written. No Pod exists for
			// any claim. Retain prevents reclaim from deleting a backing path.
			PersistentVolumeSource: corev1.PersistentVolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/arcadectl-inert-storage-proof/" + nonce, Type: &pathType}},
		}}
		if reservedFor != "" {
			pv.Spec.ClaimRef = &corev1.ObjectReference{Namespace: anchor.Namespace, Name: reservedFor}
		}
		live, err := admin.CoreV1().PersistentVolumes().Create(ctx, pv, metav1.CreateOptions{FieldManager: "arcadectl-installer", FieldValidation: "Strict"})
		if err != nil || live == nil || live.UID == "" {
			t.Fatalf("owned synthetic static PV %s create unacknowledged: %v", suffix, err)
		}
		volumes = append(volumes, original{name: live.Name, uid: live.UID})
		if !apiequality.Semantic.DeepEqual(live.Spec, pv.Spec) {
			t.Fatal("synthetic static PV desired shape changed")
		}
		return live
	}
	createPVC := func(suffix string, inert, retained bool, volumeName string) *corev1.PersistentVolumeClaim {
		t.Helper()
		empty, mode := "", corev1.PersistentVolumeFilesystem
		pvc := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: prefix + suffix, Namespace: anchor.Namespace}, Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce}, StorageClassName: &empty, VolumeMode: &mode, VolumeName: volumeName,
			Resources: corev1.VolumeResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("1Mi")}},
		}}
		if inert {
			pvc.Annotations = map[string]string{"pv.kubernetes.io/bind-completed": "yes"}
		}
		if retained {
			pvc.Labels = map[string]string{"app.kubernetes.io/managed-by": "arcadectl", "app.kubernetes.io/instance": pvc.Name,
				"arcade.gobha.me/data-policy": "retain", "arcade.gobha.me/data-identity": "synthetic-proof", "arcade.gobha.me/data-path": "data"}
		}
		live, err := admin.CoreV1().PersistentVolumeClaims(anchor.Namespace).Create(ctx, pvc, metav1.CreateOptions{FieldManager: "arcadectl-installer", FieldValidation: "Strict"})
		if err != nil || live == nil || live.UID == "" {
			t.Fatalf("owned synthetic PVC %s create unacknowledged: %v", suffix, err)
		}
		claims = append(claims, original{name: live.Name, uid: live.UID, retained: retained})
		if !apiequality.Semantic.DeepEqual(live.Spec, pvc.Spec) || !apiequality.Semantic.DeepEqual(live.Labels, pvc.Labels) {
			t.Fatal("synthetic PVC desired shape changed")
		}
		return live
	}
	// Match-capable PVs exist BEFORE the inert claims, including explicit
	// prebindings. A nonce selector would not suffice: PV prebinding bypasses it.
	available := createPV("available", "")
	preboundPlain := createPV("prebound-plain", prefix+"plain")
	preboundRetained := createPV("prebound-retained", prefix+"retained")
	controlPV := createPV("control", "")
	plain := createPVC("plain", true, false, "")
	retained := createPVC("retained", true, true, "")
	control := createPVC("control", false, false, controlPV.Name)
	if err := wait.PollUntilContextTimeout(ctx, 200*time.Millisecond, 30*time.Second, true, func(ctx context.Context) (bool, error) {
		live, err := admin.CoreV1().PersistentVolumeClaims(anchor.Namespace).Get(ctx, control.Name, metav1.GetOptions{})
		if err != nil || live.UID != control.UID || live.Spec.VolumeName != controlPV.Name {
			return false, ErrOwnership
		}
		return live.Status.Phase == corev1.ClaimBound, nil
	}); err != nil {
		t.Fatal("positive control did not prove an active real PV binder")
	}
	for _, want := range []*corev1.PersistentVolumeClaim{plain, retained} {
		if err := wait.PollUntilContextTimeout(ctx, 200*time.Millisecond, 30*time.Second, true, func(ctx context.Context) (bool, error) {
			live, err := admin.CoreV1().PersistentVolumeClaims(anchor.Namespace).Get(ctx, want.Name, metav1.GetOptions{})
			if err != nil || live.UID != want.UID || !apiequality.Semantic.DeepEqual(live.Spec, want.Spec) || !apiequality.Semantic.DeepEqual(live.Labels, want.Labels) || live.Annotations["pv.kubernetes.io/bind-completed"] != "yes" || live.Annotations["volume.kubernetes.io/selected-node"] != "" {
				return false, ErrOwnership
			}
			return live.Status.Phase == corev1.ClaimLost, nil
		}); err != nil {
			t.Fatal("synthetic inert claim did not converge to unbound ClaimLost")
		}
	}
	// ClaimLost is not a deletion-policy exception. Prove the exact signed
	// ordinary administrator denial, with the actual original UID/RV and a
	// complete unchanged raw reread, before attempting test-owned cleanup.
	access, err := NewDirectHTTPAccess(config)
	if err != nil {
		t.Fatal("native storage denial transport unavailable")
	}
	custom, err := dynamic.NewForConfig(config)
	if err != nil {
		t.Fatal("native storage observation client unavailable")
	}
	policyName := probePolicyName(t, plan, "arcadectl-retained-world-pvc-delete")
	var policy admissionv1.ValidatingAdmissionPolicy
	bindingName := ""
	for _, signed := range plan.Resources() {
		if signed.Object.GetKind() == "ValidatingAdmissionPolicy" && signed.Object.GetName() == policyName {
			if decodeServing(signed.Object, &policy) != nil {
				t.Fatal("signed retained policy unavailable")
			}
		}
		if signed.Object.GetKind() == "ValidatingAdmissionPolicyBinding" {
			var binding admissionv1.ValidatingAdmissionPolicyBinding
			if decodeServing(signed.Object, &binding) != nil {
				t.Fatal("signed retained binding unavailable")
			}
			if binding.Spec.PolicyName == policyName {
				if bindingName != "" {
					t.Fatal("ambiguous signed retained binding")
				}
				bindingName = binding.Name
			}
		}
	}
	if len(policy.Spec.Validations) < 3 || bindingName == "" {
		t.Fatal("signed retained denial branch unavailable")
	}
	collection := custom.Resource(schema.GroupVersionResource{Version: "v1", Resource: "persistentvolumeclaims"}).Namespace(anchor.Namespace)
	before, err := collection.Get(ctx, retained.Name, metav1.GetOptions{})
	if err != nil || before.GetUID() != retained.UID {
		t.Fatal("original retained denial target unavailable")
	}
	if result, err := access.probeOperation(ctx, probeDeletePVCOperation, before.DeepCopy(), policyName, bindingName, policy.Spec.Validations[2].Message); err != nil || result != nil {
		t.Fatal("original retained ClaimLost claim did not yield exact signed DELETE denial")
	}
	after, err := collection.Get(ctx, retained.Name, metav1.GetOptions{})
	if err != nil || !apiequality.Semantic.DeepEqual(after.Object, before.Object) {
		t.Fatal("retained dry-run denial changed original claim")
	}
	// Explicit PVC/PV UPDATE events requeue both controller directions. Continue
	// checking through more than two default 15-second binder sync periods; do
	// not infer controller absence from a short Pending observation.
	for _, want := range []*corev1.PersistentVolumeClaim{plain, retained} {
		live, err := admin.CoreV1().PersistentVolumeClaims(anchor.Namespace).Get(ctx, want.Name, metav1.GetOptions{})
		if err != nil || live.UID != want.UID {
			t.Fatal("synthetic claim resync identity changed")
		}
		live.Annotations["arcade.gobha.me/e2e-resync"] = nonce
		if _, err := admin.CoreV1().PersistentVolumeClaims(anchor.Namespace).Update(ctx, live, metav1.UpdateOptions{FieldValidation: "Strict"}); err != nil {
			t.Fatal("synthetic claim resync refused")
		}
	}
	for _, want := range []*corev1.PersistentVolume{available, preboundPlain, preboundRetained} {
		live, err := admin.CoreV1().PersistentVolumes().Get(ctx, want.Name, metav1.GetOptions{})
		if err != nil || live.UID != want.UID {
			t.Fatal("synthetic volume resync identity changed")
		}
		live.Annotations = map[string]string{"arcade.gobha.me/e2e-resync": nonce}
		if _, err := admin.CoreV1().PersistentVolumes().Update(ctx, live, metav1.UpdateOptions{FieldValidation: "Strict"}); err != nil {
			t.Fatal("synthetic volume resync refused")
		}
	}
	window, windowCancel := context.WithTimeout(ctx, 40*time.Second)
	defer windowCancel()
	// Reads use the longer bounded parent, not the sampling window: its normal
	// deadline must not cancel the last in-flight read and look like drift.
	err = wait.PollUntilContextCancel(window, 500*time.Millisecond, true, func(_ context.Context) (bool, error) {
		for _, want := range []*corev1.PersistentVolumeClaim{plain, retained} {
			live, err := admin.CoreV1().PersistentVolumeClaims(anchor.Namespace).Get(ctx, want.Name, metav1.GetOptions{})
			if err != nil || live.UID != want.UID || !apiequality.Semantic.DeepEqual(live.Spec, want.Spec) || !apiequality.Semantic.DeepEqual(live.Labels, want.Labels) || live.Status.Phase != corev1.ClaimLost || live.Annotations["pv.kubernetes.io/bind-completed"] != "yes" || live.Annotations["volume.kubernetes.io/selected-node"] != "" {
				return false, ErrOwnership
			}
		}
		for _, want := range []*corev1.PersistentVolume{available, preboundPlain, preboundRetained} {
			live, err := admin.CoreV1().PersistentVolumes().Get(ctx, want.Name, metav1.GetOptions{})
			if err != nil || live.UID != want.UID || !apiequality.Semantic.DeepEqual(live.Spec, want.Spec) || live.Status.Phase != corev1.VolumeAvailable {
				return false, ErrOwnership
			}
		}
		all, err := admin.CoreV1().PersistentVolumes().List(ctx, metav1.ListOptions{})
		if err != nil || len(all.Items) != len(volumes) {
			return false, ErrOwnership // no unexpected dynamically provisioned PV
		}
		for _, live := range all.Items {
			found := false
			for _, original := range volumes {
				found = found || live.Name == original.name && live.UID == original.uid
			}
			if !found {
				return false, ErrOwnership
			}
		}
		return false, nil // the entire window must elapse without binding
	})
	if !errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
		t.Fatal("synthetic storage resync proof failed")
	}
	checkNamespace(ctx)
	t.Log("real PV binder: positive control Bound; plain/retained inert claims Lost; exact ordinary retained DELETE denial; available/prebound PV specs unchanged across resync events and 40-second window; no unexpected PV in the owned cluster")
}
