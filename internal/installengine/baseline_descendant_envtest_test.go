//go:build envtest

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"encoding/json"
	"maps"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installobserve"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/ptr"
)

// Only the already-owned API-server-only fixture: no scheduler, kubelet,
// controller manager, executed workload, TokenRequest or world resources.
// Administrative CREATE acknowledgements authorize this test's exact cleanup,
// not adoption by the production installer or runtime enforcement.
func testBaselineNativeDescendantIdentity(t *testing.T, ctx context.Context, admin *kubernetes.Clientset, access *HTTPAccess, plan *installrender.Plan, callbacks ...func(installstate.Document, map[installstate.Key]*unstructured.Unstructured)) {
	t.Helper()
	f := newFixtureWithPlans(t, false, plan)
	d := f.snapshot.Document()
	parents := map[string]*baselineParent{}
	parentACKs := map[installstate.Key]*unstructured.Unstructured{}
	witness := map[installstate.Key]admissionIdentity{}
	for _, name := range []string{"arcadectl-controller", "arcadectl-destroy-controller", "arcadectl-api", "arcadectl-destroy-admin"} {
		account, err := admin.CoreV1().ServiceAccounts(d.Namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil || !nativeFixtureUID(string(account.UID)) {
			t.Fatal("native original account witness unavailable")
		}
		witness[installstate.Key{APIVersion: "v1", Kind: "ServiceAccount", Namespace: d.Namespace, Name: name}] = admissionIdentity{UID: account.UID, ResourceVersion: account.ResourceVersion}
	}
	// Register every ACK immediately, even if a later fixture assertion fails.
	type owned struct {
		kind, name string
		uid        types.UID
	}
	var originals []owned
	originalACK := func(kind, name string, uid types.UID) bool {
		for _, original := range originals {
			if original.kind == kind && original.name == name && original.uid == uid && nativeFixtureUID(string(uid)) {
				return true
			}
		}
		return false
	}
	cleaned := false
	cleanup := func(ctx context.Context) bool {
		ok := true
		for i := len(originals) - 1; i >= 0; i-- {
			o := originals[i]
			var rv string
			var finalizers []string
			var uid types.UID
			switch o.kind {
			case "Pod":
				v, err := admin.CoreV1().Pods(d.Namespace).Get(ctx, o.name, metav1.GetOptions{})
				if apierrors.IsNotFound(err) {
					continue
				}
				if err != nil {
					ok = false
					continue
				}
				rv, uid, finalizers = v.ResourceVersion, v.UID, v.Finalizers
			case "ReplicaSet":
				v, err := admin.AppsV1().ReplicaSets(d.Namespace).Get(ctx, o.name, metav1.GetOptions{})
				if apierrors.IsNotFound(err) {
					continue
				}
				if err != nil {
					ok = false
					continue
				}
				rv, uid, finalizers = v.ResourceVersion, v.UID, v.Finalizers
			case "Deployment":
				v, err := admin.AppsV1().Deployments(d.Namespace).Get(ctx, o.name, metav1.GetOptions{})
				if apierrors.IsNotFound(err) {
					continue
				}
				if err != nil {
					ok = false
					continue
				}
				rv, uid, finalizers = v.ResourceVersion, v.UID, v.Finalizers
			}
			if uid != o.uid || !baselineParentRV(rv) {
				ok = false
				continue
			}
			if len(finalizers) != 0 {
				if o.kind != "ReplicaSet" || !reflect.DeepEqual(finalizers, []string{metav1.FinalizerDeleteDependents}) {
					ok = false
					continue
				}
				patch, _ := json.Marshal([]map[string]any{{"op": "test", "path": "/metadata/uid", "value": string(uid)}, {"op": "test", "path": "/metadata/resourceVersion", "value": rv}, {"op": "test", "path": "/metadata/finalizers", "value": finalizers}, {"op": "replace", "path": "/metadata/finalizers", "value": []string{}}})
				if _, err := admin.AppsV1().ReplicaSets(d.Namespace).Patch(ctx, o.name, types.JSONPatchType, patch, metav1.PatchOptions{FieldValidation: "Strict"}); err != nil {
					ok = false
					continue
				}
				if _, err := admin.AppsV1().ReplicaSets(d.Namespace).Get(ctx, o.name, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
					ok = false
				}
				continue
			}
			background := metav1.DeletePropagationBackground
			options := metav1.DeleteOptions{GracePeriodSeconds: ptr.To[int64](0), PropagationPolicy: &background, Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &rv}}
			var deleteErr, readErr error
			switch o.kind {
			case "Pod":
				deleteErr = admin.CoreV1().Pods(d.Namespace).Delete(ctx, o.name, options)
				_, readErr = admin.CoreV1().Pods(d.Namespace).Get(ctx, o.name, metav1.GetOptions{})
			case "ReplicaSet":
				deleteErr = admin.AppsV1().ReplicaSets(d.Namespace).Delete(ctx, o.name, options)
				_, readErr = admin.AppsV1().ReplicaSets(d.Namespace).Get(ctx, o.name, metav1.GetOptions{})
			case "Deployment":
				deleteErr = admin.AppsV1().Deployments(d.Namespace).Delete(ctx, o.name, options)
				_, readErr = admin.AppsV1().Deployments(d.Namespace).Get(ctx, o.name, metav1.GetOptions{})
			}
			if deleteErr != nil || !apierrors.IsNotFound(readErr) {
				ok = false
			}
		}
		return ok
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if !cleaned && !cleanup(cleanupCtx) {
			t.Error("original-only native descendant cleanup failed")
		}
	})
	for _, name := range []string{"arcadectl-controller", "arcadectl-destroy-controller", "arcadectl-api"} {
		key := deploymentKey(d.Namespace, name)
		// Only the controller packages have signed paused variants. The API
		// keeps its authentic normal shape; this fixture has no executor.
		template, err := f.engine.contracts[d.TargetPackage].Template(key, name != apiFamily)
		if err != nil {
			t.Fatal("signed paused parent unavailable")
		}
		candidate, err := template.Candidate(strings.Repeat("e", 32))
		if err != nil {
			t.Fatal("native signed parent candidate unavailable")
		}
		ack, err := access.Create(ctx, key, candidate, false)
		if err != nil || ack == nil {
			t.Fatal("native signed parent CREATE refused")
		}
		originals = append(originals, owned{"Deployment", name, ack.GetUID()})
		parentACKs[key] = ack.DeepCopy()
		live, err := access.Get(ctx, key)
		if err != nil || live == nil || !reflect.DeepEqual(ack.Object, live.Object) {
			t.Fatal("whole native parent acknowledgement changed")
		}
		d.Resources = append(d.Resources, installstate.Resource{Key: key, UID: ack.GetUID(), TemplateSHA256: template.Hash(), Phase: template.Phase()})
		parent, err := f.engine.originalBaselineParent(d, key, live)
		t.Cleanup(parent.release)
		if err != nil || parent == nil {
			t.Fatal("actual native paused parent identity refused")
		}
		parents[name] = parent
		set := inertFixture(parent.parent, "bcdfg23456", 1)
		set.UID, set.ResourceVersion, set.Generation = "", "", 0
		set.Status = appsv1.ReplicaSetStatus{}
		set.Spec.Template = *parent.parent.Spec.Template.DeepCopy()
		set.Spec.Template.Labels[appsv1.DefaultDeploymentUniqueLabelKey] = "bcdfg23456"
		set.Labels = maps.Clone(set.Spec.Template.Labels)
		setACK, err := admin.AppsV1().ReplicaSets(d.Namespace).Create(ctx, set, metav1.CreateOptions{FieldManager: "arcadectl-installer", FieldValidation: "Strict"})
		if err != nil {
			t.Fatal("native zero-replica signed set refused")
		}
		originals = append(originals, owned{"ReplicaSet", setACK.Name, setACK.UID})
		// No kubelet exists in this private fixture. A literal node assignment
		// exercises native graceful deletion without executing the Pod.
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{GenerateName: setACK.Name + "-", Namespace: d.Namespace, Labels: maps.Clone(setACK.Spec.Template.Labels), Annotations: maps.Clone(setACK.Spec.Template.Annotations), OwnerReferences: fixtureOwner("apps/v1", "ReplicaSet", setACK.Name, setACK.UID)}, Spec: *setACK.Spec.Template.Spec.DeepCopy()}
		pod.Spec.NodeName = "fixture-no-kubelet"
		podACK, err := admin.CoreV1().Pods(d.Namespace).Create(ctx, pod, metav1.CreateOptions{FieldManager: "arcadectl-installer", FieldValidation: "Strict"})
		if err != nil {
			t.Fatal("native admitted signed Pod refused")
		}
		originals = append(originals, owned{"Pod", podACK.Name, podACK.UID})
	}
	// Complete-driver tests consume original immediate CREATE acknowledgements
	// while all three genuine chains are live, before any drain/cleanup effect.
	for _, callback := range callbacks {
		callback(d, parentACKs)
	}
	observe := func() *installobserve.ExecutableCollections {
		c := &installobserve.ExecutableCollections{}
		var err error
		if c.Pods, err = admin.CoreV1().Pods(d.Namespace).List(ctx, metav1.ListOptions{}); err != nil {
			t.Fatal("native Pod inventory unavailable")
		}
		if c.Jobs, err = admin.BatchV1().Jobs(d.Namespace).List(ctx, metav1.ListOptions{}); err != nil {
			t.Fatal("native Job inventory unavailable")
		}
		if c.Deployments, err = admin.AppsV1().Deployments(d.Namespace).List(ctx, metav1.ListOptions{}); err != nil {
			t.Fatal("native Deployment inventory unavailable")
		}
		if c.ReplicaSets, err = admin.AppsV1().ReplicaSets(d.Namespace).List(ctx, metav1.ListOptions{}); err != nil {
			t.Fatal("native ReplicaSet inventory unavailable")
		}
		if c.StatefulSets, err = admin.AppsV1().StatefulSets(d.Namespace).List(ctx, metav1.ListOptions{}); err != nil {
			t.Fatal("native StatefulSet inventory unavailable")
		}
		if c.DaemonSets, err = admin.AppsV1().DaemonSets(d.Namespace).List(ctx, metav1.ListOptions{}); err != nil {
			t.Fatal("native DaemonSet inventory unavailable")
		}
		if c.ReplicationControllers, err = admin.CoreV1().ReplicationControllers(d.Namespace).List(ctx, metav1.ListOptions{}); err != nil {
			t.Fatal("native RC inventory unavailable")
		}
		if c.CronJobs, err = admin.BatchV1().CronJobs(d.Namespace).List(ctx, metav1.ListOptions{}); err != nil {
			t.Fatal("native CronJob inventory unavailable")
		}
		return c
	}
	for _, draining := range []bool{false, true} {
		if draining {
			c := observe()
			if len(c.Pods.Items) != 3 || len(c.ReplicaSets.Items) != 3 {
				t.Fatal("native descendant inventory differs from exact acknowledged fixture")
			}
			for _, pod := range c.Pods.Items {
				if !originalACK("Pod", pod.Name, pod.UID) {
					t.Fatal("foreign Pod refused by original-only fixture DELETE")
				}
				uid, rv := pod.UID, pod.ResourceVersion
				if err := admin.CoreV1().Pods(d.Namespace).Delete(ctx, pod.Name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &rv}}); err != nil {
					t.Fatal("original native graceful Pod DELETE refused")
				}
			}
			for _, set := range c.ReplicaSets.Items {
				if !originalACK("ReplicaSet", set.Name, set.UID) {
					t.Fatal("foreign ReplicaSet refused by original-only fixture DELETE")
				}
				uid, rv, foreground := set.UID, set.ResourceVersion, metav1.DeletePropagationForeground
				if err := admin.AppsV1().ReplicaSets(d.Namespace).Delete(ctx, set.Name, metav1.DeleteOptions{PropagationPolicy: &foreground, Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &rv}}); err != nil {
					t.Fatal("original native foreground set DELETE refused")
				}
			}
		}
		c := observe()
		before := c.DeepCopy()
		if draining {
			for _, pod := range c.Pods.Items {
				if pod.DeletionTimestamp == nil || pod.DeletionGracePeriodSeconds == nil || *pod.DeletionGracePeriodSeconds != 30 || len(pod.Finalizers) != 0 {
					t.Fatal("native scheduled Pod did not expose signed ordinary drain envelope")
				}
			}
			for _, set := range c.ReplicaSets.Items {
				if set.DeletionTimestamp == nil || !reflect.DeepEqual(set.Finalizers, []string{metav1.FinalizerDeleteDependents}) {
					t.Fatal("native original ReplicaSet foreground envelope unavailable")
				}
			}
		}
		w, err := f.engine.baselineDescendants(d, parents, witness, c)
		if err != nil || w == nil || len(w.sets) != 3 || len(w.pods) != 3 || !reflect.DeepEqual(c, before) {
			t.Fatal("actual native original descendants refused or whole evidence changed")
		}
	}
	testBaselineNativeDeniedCatalog(t, ctx, admin, access, f, d, observe())
	if !cleanup(ctx) {
		t.Fatal("original native descendant finalization failed")
	}
	cleaned = true
	c := observe()
	if len(c.Pods.Items) != 0 || len(c.ReplicaSets.Items) != 0 || len(c.Deployments.Items) != 0 {
		t.Fatal("native descendant cleanup did not establish complete named absence")
	}
}
