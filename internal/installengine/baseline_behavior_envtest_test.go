//go:build envtest

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installbaseline"
	"github.com/gobha-me/arcadectl/internal/installcontract"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/kubernetes"
)

// The actual composed constructor and driver over a private native API server.
// Every original inventory UID comes from its immediate administrative CREATE
// acknowledgement, never first readback adoption. The journal enrollment and
// generation-current VAP status are explicitly TEST-ONLY synthetic setup: no
// controller-manager/typechecking certification, runtime guard, production
// enrollment or full installation lifecycle is claimed. No executor exists.
func testBaselineNativeWholeBehavior(t *testing.T, ctx context.Context, admin *kubernetes.Clientset, access *HTTPAccess, plan *installrender.Plan, baseline *installbaseline.Plan, baselineACKs, accessACKs map[installstate.Key]*unstructured.Unstructured, document installstate.Document, parentACKs map[installstate.Key]*unstructured.Unstructured) {
	t.Helper()
	ctx, cancel := context.WithTimeout(ctx, 8*time.Minute)
	defer cancel()
	contract, err := installcontract.New(plan)
	if err != nil || len(parentACKs) != 3 || len(baselineACKs) != 12 {
		t.Fatal("native composed original contract/ACK catalog unavailable")
	}
	namespaceKey := namespaceKey(plan.Namespace())
	namespaceACK := accessACKs[namespaceKey]
	if namespaceACK == nil || !nativeFixtureUID(string(namespaceACK.GetUID())) {
		t.Fatal("native original Namespace CREATE acknowledgement unavailable")
	}
	document.NamespaceUID = namespaceACK.GetUID()
	document.SecurityBaseline, err = installstate.PinnedSecurityBaseline(baseline)
	if err != nil {
		t.Fatal("native synthetic enrollment pin unavailable")
	}
	document.SecurityBaseline.Stage = installstate.BaselineVerified
	for _, resource := range baseline.Resources() {
		key := baselineObjectKey(resource.Object)
		ack := baselineACKs[key]
		if ack == nil || !nativeFixtureUID(string(ack.GetUID())) {
			t.Fatal("native baseline original CREATE acknowledgement missing")
		}
		document.SecurityBaseline.Resources = append(document.SecurityBaseline.Resources, installstate.BaselineResource{Key: key, UID: ack.GetUID(), TemplateSHA256: resource.TemplateSHA256})
	}
	installstate.SortBaselineResources(document.SecurityBaseline.Resources)
	// Replace only the fixture's synthetic Namespace identity with its actual
	// original ACK. Its three Deployment entries already carry immediate ACKs.
	for i, resource := range document.Resources {
		if resource.Key == namespaceKey {
			document.Resources[i].UID = namespaceACK.GetUID()
		} else if resource.Key.Kind == "Deployment" {
			ack := parentACKs[resource.Key]
			if ack == nil || ack.GetUID() != resource.UID {
				t.Fatal("native parent inventory is not bound to original CREATE ACK")
			}
		} else {
			t.Fatal("native composed fixture contains unexpected preexisting inventory")
		}
	}
	for key, ack := range accessACKs {
		if key == namespaceKey {
			continue
		}
		template, err := contract.Template(key, false)
		if !accessRetirementKey(key) || err != nil || ack == nil || template.MatchLive(ack, ack.GetUID()) != nil {
			t.Fatal("native signed access inventory has no original CREATE ACK")
		}
		document.Resources = append(document.Resources, installstate.Resource{Key: key, UID: ack.GetUID(), TemplateSHA256: template.Hash(), Phase: template.Phase(), Retained: template.Retained()})
	}
	serviceKey := installstate.Key{APIVersion: "v1", Kind: "Service", Namespace: plan.Namespace(), Name: "arcadectl-api"}
	template, err := contract.Template(serviceKey, false)
	if err != nil {
		t.Fatal("native signed composed Service unavailable")
	}
	noEndpoints := func(checkCtx context.Context) bool {
		_, err := admin.CoreV1().Endpoints(serviceKey.Namespace).Get(checkCtx, serviceKey.Name, metav1.GetOptions{})
		return apierrors.IsNotFound(err)
	}
	if !noEndpoints(ctx) {
		t.Fatal("native composed Service has unowned legacy Endpoints")
	}
	candidate, err := template.Candidate(strings.Repeat("e", 32))
	if err != nil {
		t.Fatal("native composed signed Service candidate unavailable")
	}
	serviceACK, err := access.Create(ctx, serviceKey, candidate, false)
	if err != nil || serviceACK == nil || !nativeFixtureUID(string(serviceACK.GetUID())) {
		t.Fatal("native composed Service CREATE ACK unavailable")
	}
	// Exact ACK authorizes cleanup immediately, including an assertion failure.
	cleanup := func(cleanupCtx context.Context) bool {
		live, err := access.Get(cleanupCtx, serviceKey)
		if apierrors.IsNotFound(err) {
			return true
		}
		if err != nil || live == nil || live.GetUID() != serviceACK.GetUID() || !noEndpoints(cleanupCtx) || template.MatchLive(live, serviceACK.GetUID()) != nil || !baselineParentRV(live.GetResourceVersion()) {
			return false
		}
		uid, rv, background := live.GetUID(), live.GetResourceVersion(), metav1.DeletePropagationBackground
		if admin.CoreV1().Services(serviceKey.Namespace).Delete(cleanupCtx, serviceKey.Name, metav1.DeleteOptions{PropagationPolicy: &background, Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &rv}}) != nil {
			return false
		}
		_, err = access.Get(cleanupCtx, serviceKey)
		return apierrors.IsNotFound(err)
	}
	cleaned := false
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if !cleaned && !cleanup(cleanupCtx) {
			t.Error("native composed original-only Service cleanup failed")
		}
	})
	if template.MatchLive(serviceACK, serviceACK.GetUID()) != nil {
		t.Fatal("native composed Service allocated shape refused")
	}
	document.Resources = append(document.Resources, installstate.Resource{Key: serviceKey, UID: serviceACK.GetUID(), TemplateSHA256: template.Hash(), Phase: template.Phase(), Retained: template.Retained()})
	installstate.SortResources(document.Resources)
	document.Revision++
	body, err := installstate.EncodeWithBaseline(document, baseline, plan)
	if err != nil {
		t.Fatal("native ACK-bound synthetic enrollment encoding refused")
	}
	namespace, err := admin.CoreV1().Namespaces().Get(ctx, plan.Namespace(), metav1.GetOptions{})
	if err != nil || namespace.UID != namespaceACK.GetUID() || namespace.Annotations[installstate.Annotation] != "" || namespace.Annotations[installstate.BootstrapAnnotation] != "" {
		t.Fatal("native synthetic enrollment would replace unrelated original state")
	}
	if namespace.Annotations == nil {
		namespace.Annotations = map[string]string{}
	}
	namespace.Annotations[installstate.Annotation], namespace.Annotations[installstate.BootstrapAnnotation] = string(body), document.InstallationID
	// The closed Namespace writer internally fixes manager/strict validation;
	// its caller-facing options deliberately accept no override.
	if _, err := access.Namespaces().Update(ctx, namespace, metav1.UpdateOptions{}); err != nil {
		t.Fatal("native ACK-bound synthetic enrollment CAS refused")
	}
	path := t.TempDir()
	if os.Chmod(path, 0700) != nil {
		t.Fatal("native protected composed evidence directory unavailable")
	}
	files, err := privatefs.Open(path, false)
	if err != nil {
		t.Fatal("native protected composed evidence store unavailable")
	}
	t.Cleanup(func() { _ = files.Close() })
	store, err := installstate.NewWithBaseline(access.Namespaces(), baseline, plan)
	if err != nil {
		t.Fatal("native original composed journal store unavailable")
	}
	engine, err := NewWithBaselineAccess(access, store, files, baseline, plan)
	if err != nil {
		t.Fatal("native original composed engine unavailable")
	}
	anchor := installstate.Anchor{Namespace: document.Namespace, UID: namespaceACK.GetUID(), InstallationID: document.InstallationID}
	snapshot, err := store.Load(ctx, anchor)
	if err != nil {
		t.Fatal("native original composed journal unavailable")
	}
	provider, err := NewClusterSecurityBaseline(engine, access)
	if err != nil {
		t.Fatal("native composed provider unavailable")
	}
	if provider.VerifyConfigured(ctx, snapshot) != ErrSecurityBaseline {
		t.Fatal("API-only fixture falsely certified native typechecking health")
	}
	// Explicit synthetic status injection only. The real API server still
	// serves and attributes all 97 behavioral requests and native RBAC reviews.
	for key, ack := range baselineACKs {
		if key.Kind != "ValidatingAdmissionPolicy" {
			continue
		}
		policy, err := admin.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, key.Name, metav1.GetOptions{})
		if err != nil || policy.UID != ack.GetUID() || policy.Generation != ack.GetGeneration() {
			t.Fatal("native original policy changed before test-only health setup")
		}
		policy.Status = admissionv1.ValidatingAdmissionPolicyStatus{ObservedGeneration: policy.Generation, TypeChecking: &admissionv1.TypeChecking{}}
		if _, err := admin.AdmissionregistrationV1().ValidatingAdmissionPolicies().UpdateStatus(ctx, policy, metav1.UpdateOptions{FieldManager: "fixture-synthetic-health", FieldValidation: "Strict"}); err != nil {
			t.Fatal("explicit test-only native policy status setup refused")
		}
	}
	guard := &baselineParentRefusingRuntimeGuard{}
	engine.baseline.runtimeGuard = guard // Nonrecursion instrument, never a proof.
	defer func() { engine.baseline.runtimeGuard = nil }()
	behavior, err := provider.newBaselineBehavior(ctx, snapshot)
	t.Cleanup(behavior.release)
	if err != nil || behavior == nil || len(behavior.parents) != 3 || len(behavior.family.pods) != 3 {
		t.Fatal("native whole constructor refused original acknowledged chains")
	}
	if provider.Verify(ctx, snapshot) != nil {
		t.Fatal("native complete behavioral driver refused")
	}
	closed, err := store.Load(ctx, anchor)
	if err != nil || closed.ResourceVersion() != snapshot.ResourceVersion() || !bytes.Equal(closed.Bytes(), snapshot.Bytes()) || guard.calls.Load() != 0 {
		t.Fatal("native behavioral proof changed journal or recursed into runtime guard")
	}
	jobs, err := admin.BatchV1().Jobs(plan.Namespace()).List(ctx, metav1.ListOptions{})
	if err != nil || len(jobs.Items) != 0 {
		t.Fatal("native behavioral dry run persisted a producer")
	}
	live, err := access.Get(ctx, serviceKey)
	if err != nil || live == nil || !reflect.DeepEqual(live.Object, serviceACK.Object) {
		t.Fatal("native complete proof changed the original allocated Service")
	}
	if !cleanup(ctx) {
		t.Fatal("native composed Service final cleanup refused")
	}
	cleaned = true
}
