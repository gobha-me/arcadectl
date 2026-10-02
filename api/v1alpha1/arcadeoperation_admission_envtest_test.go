//go:build envtest

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package v1alpha1_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	arcade "github.com/gobha-me/arcadectl/api/v1alpha1"
	"github.com/gobha-me/arcadectl/internal/operations"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

// One serial apiserver installs the complete five-CRD surface. These are real
// admission requests, not fake-client tests or source-string assertions.
func TestArcadeOperationAdmissionImmutability(t *testing.T) {
	environment := &envtest.Environment{
		CRDDirectoryPaths: []string{filepath.Join("..", "..", "config", "crd", "bases")}, ErrorIfCRDPathMissing: true,
		DownloadBinaryAssets: true, DownloadBinaryAssetsVersion: "1.37.0",
		DownloadBinaryAssetsIndexURL: "https://raw.githubusercontent.com/kubernetes-sigs/controller-tools/1031496fc98a4f51010c3bdfdeb57b5d67bea7bd/envtest-releases.yaml",
		BinaryAssetsDirectory:        t.TempDir(), ControlPlaneStartTimeout: 90 * time.Second, ControlPlaneStopTimeout: 30 * time.Second,
	}
	configuration, err := environment.Start()
	if err != nil {
		t.Fatalf("start envtest: %v", err)
	}
	t.Cleanup(func() {
		if err := environment.Stop(); err != nil {
			t.Errorf("stop envtest: %v", err)
		}
	})
	scheme := runtime.NewScheme()
	for _, register := range []func(*runtime.Scheme) error{arcade.AddToScheme, corev1.AddToScheme, apiextensionsv1.AddToScheme} {
		if err := register(scheme); err != nil {
			t.Fatal(err)
		}
	}
	kube, err := client.New(configuration, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, name := range []string{"gameservers", "gamebackups", "gamerestores", "gamedestroys", "arcadeoperations"} {
		if err := kube.Get(ctx, client.ObjectKey{Name: name + ".arcade.gobha.me"}, &apiextensionsv1.CustomResourceDefinition{}); err != nil {
			t.Fatalf("complete CRD inventory %s: %v", name, err)
		}
	}
	if err := kube.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "operation-admission"}}); err != nil {
		t.Fatal(err)
	}
	receipt := operationAdmissionFixture(t, "immutable-spec")
	if err := kube.Create(ctx, receipt); err != nil {
		t.Fatalf("create complete receipt: %v", err)
	}
	fetch := func(t *testing.T, reference *arcade.ArcadeOperation) *arcade.ArcadeOperation {
		t.Helper()
		stored := &arcade.ArcadeOperation{}
		if err := kube.Get(ctx, client.ObjectKeyFromObject(reference), stored); err != nil {
			t.Fatal(err)
		}
		return stored
	}
	for _, test := range []struct {
		name   string
		mutate func(*arcade.ArcadeOperation)
	}{
		{"settings-json", func(o *arcade.ArcadeOperation) { o.Spec.Request.Create.SettingsJSON = `{"name":"changed"}` }},
		{"image-digest", func(o *arcade.ArcadeOperation) {
			o.Spec.Request.Image.Digest = "sha256:" + strings.Repeat("b", 64)
			o.Spec.Request.Image.Resolution.Digest = o.Spec.Request.Image.Digest
		}},
		{"image-repository", func(o *arcade.ArcadeOperation) { o.Spec.Request.Image.Resolution.Repository = "example.org/other/game" }},
		{"image-tag-binding", func(o *arcade.ArcadeOperation) {
			o.Spec.Request.Image.Digest = ""
			o.Spec.Request.Image.Version = "2.0.73"
			o.Spec.Request.Image.Resolution.Tag = "2.0.73"
			o.Spec.Request.Image.Resolution.ResolverVersion = "registry-v1"
		}},
		{"image-resolution-time", func(o *arcade.ArcadeOperation) {
			o.Spec.Request.Image.Resolution.ResolvedAt = metav1.NewTime(o.Spec.Request.Image.Resolution.ResolvedAt.Add(time.Hour))
		}},
		{"precondition", func(o *arcade.ArcadeOperation) { o.Spec.Request.Precondition = "\"server:replacement:2\"" }},
		{"key-digest", func(o *arcade.ArcadeOperation) { o.Spec.KeyDigest = "sha256:" + strings.Repeat("c", 64) }},
		{"request-digest", func(o *arcade.ArcadeOperation) { o.Spec.RequestDigest = "sha256:" + strings.Repeat("d", 64) }},
		{"principal", func(o *arcade.ArcadeOperation) { o.Spec.Admission.PrincipalID = "other-admin" }},
		{"credential-id", func(o *arcade.ArcadeOperation) { o.Spec.Admission.CredentialID = "other-key" }},
		{"request-id", func(o *arcade.ArcadeOperation) { o.Spec.Admission.RequestID = strings.Repeat("b", 32) }},
		{"admission-time", func(o *arcade.ArcadeOperation) {
			o.Spec.Admission.AdmittedAt = metav1.NewTime(o.Spec.Admission.AdmittedAt.Add(time.Minute))
		}},
		{"credential-expiry", func(o *arcade.ArcadeOperation) {
			o.Spec.Admission.CredentialExpiresAt = metav1.NewTime(o.Spec.Admission.CredentialExpiresAt.Add(time.Hour))
		}},
		{"server-name", func(o *arcade.ArcadeOperation) { o.Spec.Request.ServerName = "other-server" }},
		{"action", func(o *arcade.ArcadeOperation) { o.Spec.Action = arcade.OperationServerStop }},
	} {
		t.Run("spec/"+test.name, func(t *testing.T) {
			stored := fetch(t, receipt)
			test.mutate(stored)
			operationAdmissionRejected(t, kube.Update(ctx, stored), "operation admission and request are immutable")
		})
	}
	statusReceipt := operationAdmissionFixture(t, "immutable-status")
	if err := kube.Create(ctx, statusReceipt); err != nil {
		t.Fatal(err)
	}
	stored := fetch(t, statusReceipt)
	stored.Status = operationAdmissionStatusFixture(t, stored.Generation)
	if err := kube.Status().Update(ctx, stored); err != nil {
		t.Fatalf("write once-set plan/child/snapshot/journal: %v", err)
	}
	for _, test := range []struct {
		name, reason string
		mutate       func(*arcade.ArcadeOperation)
	}{
		{"plan-change", "operation plan cannot be cleared or changed", func(o *arcade.ArcadeOperation) { o.Status.Plan.ServerIntent.SettingsJSON = `{"name":"changed"}` }},
		{"plan-clear", "operation plan cannot be cleared or changed", func(o *arcade.ArcadeOperation) { o.Status.Plan = nil }},
		{"plan-secret-binding", "operation plan cannot be cleared or changed", func(o *arcade.ArcadeOperation) { o.Status.Plan.RepositorySecretRef.ResourceVersion = "43" }},
		{"child-change", "operation child cannot be cleared or changed", func(o *arcade.ArcadeOperation) { o.Status.Child.UID = "replacement-child" }},
		{"child-generation", "operation child cannot be cleared or changed", func(o *arcade.ArcadeOperation) { o.Status.Child.Generation++ }},
		{"child-clear", "operation child cannot be cleared or changed", func(o *arcade.ArcadeOperation) { o.Status.Child = nil }},
		{"snapshot-change", "retained world snapshot cannot be cleared or changed", func(o *arcade.ArcadeOperation) {
			o.Status.RetainedWorld.Target.Data.Claims[0].ClaimRef.UID = "replacement-world"
		}},
		{"snapshot-clear", "retained world snapshot cannot be cleared or changed", func(o *arcade.ArcadeOperation) { o.Status.RetainedWorld = nil }},
		{"snapshot-digest", "retained world snapshot cannot be cleared or changed", func(o *arcade.ArcadeOperation) {
			o.Status.RetainedWorld.SnapshotDigest = "sha256:" + strings.Repeat("b", 64)
		}},
		{"journal-clear", "operation journal cannot be removed or changed", func(o *arcade.ArcadeOperation) { o.Status.Transitions = nil }},
		{"journal-generation", "operation journal cannot be removed or changed", func(o *arcade.ArcadeOperation) { o.Status.Transitions[0].ToGeneration++ }},
		{"journal-step-rewrite", "operation journal cannot be removed or changed", func(o *arcade.ArcadeOperation) { o.Status.Transitions[0].Step = "Start" }},
		{"journal-digest", "operation journal cannot be removed or changed", func(o *arcade.ArcadeOperation) {
			o.Status.Transitions[0].SpecDigest = "sha256:" + strings.Repeat("b", 64)
		}},
		{"journal-time", "operation journal cannot be removed or changed", func(o *arcade.ArcadeOperation) {
			o.Status.Transitions[0].RequestedAt = metav1.NewTime(o.Status.Transitions[0].RequestedAt.Add(time.Second))
		}},
	} {
		t.Run("status/"+test.name, func(t *testing.T) {
			copy := fetch(t, statusReceipt)
			test.mutate(copy)
			operationAdmissionRejected(t, kube.Status().Update(ctx, copy), test.reason)
		})
	}
	t.Run("status/remove-entire-status", func(t *testing.T) { operationAdmissionRemoveStatusRejected(t, ctx, kube, fetch(t, statusReceipt)) })
	// Appending a new step and exact replay are legal; updating/removing an old
	// map-list entry is not. This proves the journal is append-only, not frozen.
	stored = fetch(t, statusReceipt)
	stop := stored.Status.Transitions[0]
	stop.Step = "Stop"
	stop.FromGeneration = 2
	stop.ToGeneration = 3
	stop.DesiredState = arcade.DesiredStateStopped
	stored.Status.Transitions = append(stored.Status.Transitions, stop)
	if err := kube.Status().Update(ctx, stored); err != nil {
		t.Fatalf("append Stop journal: %v", err)
	}
	stored = fetch(t, statusReceipt)
	if err := kube.Status().Update(ctx, stored); err != nil {
		t.Fatalf("exact journal replay: %v", err)
	}
	for _, phase := range []arcade.ArcadeOperationPhase{arcade.OperationPhaseSucceeded, arcade.OperationPhaseFailed, arcade.OperationPhaseCancelled} {
		t.Run("terminal/"+string(phase), func(t *testing.T) {
			terminal := operationAdmissionFixture(t, "terminal-"+strings.ToLower(string(phase)))
			if err := kube.Create(ctx, terminal); err != nil {
				t.Fatal(err)
			}
			terminal = fetch(t, terminal)
			terminal.Status = operationAdmissionStatusFixture(t, terminal.Generation)
			terminal.Status.Phase = phase
			now := metav1.Now()
			terminal.Status.CompletedAt = &now
			if phase == arcade.OperationPhaseFailed {
				terminal.Status.Failure = &arcade.OperationFailure{Code: "worker_failed", Message: "Native operation failed.", SuggestedAction: "Inspect the native operation."}
			}
			if err := kube.Status().Update(ctx, terminal); err != nil {
				t.Fatalf("write terminal status: %v", err)
			}
			for _, mutation := range []struct {
				name   string
				modify func(*arcade.ArcadeOperation)
			}{
				{"phase", func(o *arcade.ArcadeOperation) { o.Status.Phase = arcade.OperationPhaseRunning }},
				{"phase-removal", func(o *arcade.ArcadeOperation) { o.Status.Phase = "" }},
				{"timestamp", func(o *arcade.ArcadeOperation) { o.Status.CompletedAt = nil }},
				{"observed-generation", func(o *arcade.ArcadeOperation) { o.Status.ObservedGeneration++ }},
				{"failure-guidance", func(o *arcade.ArcadeOperation) {
					o.Status.Failure = &arcade.OperationFailure{Code: "api_unavailable", Retryable: true, Message: "Changed terminal evidence.", SuggestedAction: "Observe again."}
				}},
			} {
				t.Run(mutation.name, func(t *testing.T) {
					copy := fetch(t, terminal)
					mutation.modify(copy)
					operationAdmissionRejected(t, kube.Status().Update(ctx, copy), "terminal operation status is immutable")
				})
			}
			operationAdmissionRemoveStatusRejected(t, ctx, kube, fetch(t, terminal))
			unchanged := fetch(t, terminal)
			if err := kube.Status().Update(ctx, unchanged); err != nil {
				t.Fatalf("exact terminal replay: %v", err)
			}
		})
	}
}

func operationAdmissionRejected(t *testing.T, err error, reason string) {
	t.Helper()
	if err == nil || !apierrors.IsInvalid(err) || reason != "" && !strings.Contains(err.Error(), reason) {
		t.Fatalf("admission error = %v, want Invalid containing %q", err, reason)
	}
}
func operationAdmissionRemoveStatusRejected(t *testing.T, ctx context.Context, kube client.Client, o *arcade.ArcadeOperation) {
	t.Helper()
	patch, err := json.Marshal([]map[string]any{{"op": "test", "path": "/metadata/uid", "value": string(o.UID)}, {"op": "test", "path": "/metadata/resourceVersion", "value": o.ResourceVersion}, {"op": "remove", "path": "/status"}})
	if err != nil {
		t.Fatal(err)
	}
	operationAdmissionRejected(t, kube.Status().Patch(ctx, o, client.RawPatch(types.JSONPatchType, patch)), "")
}
func operationAdmissionFixture(t *testing.T, name string) *arcade.ArcadeOperation {
	t.Helper()
	now := metav1.Now()
	request := arcade.OperationRequest{Precondition: "absent", ServerName: "factory", Create: &arcade.OperationCreateInput{Game: "factorio", DesiredState: arcade.DesiredStateStopped,
		Compute: arcade.ComputeSpec{CPURequest: resource.MustParse("100m"), CPULimit: resource.MustParse("1"), MemoryRequest: resource.MustParse("64Mi"), MemoryLimit: resource.MustParse("256Mi")},
		Storage: arcade.StorageSpec{Size: resource.MustParse("1Gi")}, SettingsJSON: `{"name":"world"}`},
		Image: &arcade.OperationImageInput{Digest: "sha256:" + strings.Repeat("a", 64), Resolution: arcade.OperationImageResolution{Repository: "ghcr.io/gobha-me/arcadectl-factorio", Digest: "sha256:" + strings.Repeat("a", 64), ResolvedAt: now, ResolverVersion: "digest-v1"}}}
	digest, err := operations.RequestDigest(arcade.OperationServerCreate, request)
	if err != nil {
		t.Fatal(err)
	}
	return &arcade.ArcadeOperation{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "operation-admission"}, Spec: arcade.ArcadeOperationSpec{Version: "v1", Action: arcade.OperationServerCreate, KeyDigest: "sha256:" + strings.Repeat("a", 64), RequestDigest: digest, Request: request,
		Admission: arcade.OperationAdmission{PrincipalID: "admin", CredentialID: "key-1", RequestID: strings.Repeat("a", 32), AdmittedAt: now, CredentialExpiresAt: metav1.NewTime(now.Add(time.Hour))}}}
}
func operationAdmissionStatusFixture(t *testing.T, generation int64) arcade.ArcadeOperationStatus {
	t.Helper()
	receipt := operationAdmissionFixture(t, "template")
	intent := arcade.OperationServerIntent{Game: "factorio", ImageDigest: receipt.Spec.Request.Image.Digest, DesiredState: arcade.DesiredStateRunning, Compute: receipt.Spec.Request.Create.Compute, Storage: receipt.Spec.Request.Create.Storage, SettingsJSON: receipt.Spec.Request.Create.SettingsJSON}
	spec, err := operations.ServerSpec(intent)
	if err != nil {
		t.Fatal(err)
	}
	specDigest, err := operations.SpecDigest(spec)
	if err != nil {
		t.Fatal(err)
	}
	target := arcade.GameDestroyTarget{GameServer: arcade.ExactLocalReference{Name: "factory", UID: "original-server"}, Game: "factorio", Data: arcade.RetainedDataReference{Identity: "data-world", Claims: []arcade.RetainedDataClaimReference{{Path: "world", ClaimRef: arcade.ExactLocalReference{Name: "world", UID: "original-world"}}}}}
	snapshotDigest, err := operations.RetainedSnapshotDigest(target)
	if err != nil {
		t.Fatal(err)
	}
	now := metav1.Now()
	return arcade.ArcadeOperationStatus{ObservedGeneration: generation, Phase: arcade.OperationPhaseRunning, StartedAt: &now,
		Plan:  &arcade.OperationPlan{Server: &arcade.ExactGameServerReference{ExactLocalReference: target.GameServer, Generation: 1, DesiredState: arcade.DesiredStateStopped}, ServerIntent: &intent, Data: target.Data.DeepCopy(), RepositorySecretRef: &arcade.ExactSecretReference{ExactLocalReference: arcade.ExactLocalReference{Name: "repository", UID: "original-secret"}, ResourceVersion: "42"}},
		Child: &arcade.OperationChildReference{Kind: "GameServer", ExactLocalReference: target.GameServer, Generation: 1}, RetainedWorld: &arcade.OperationRetainedWorld{Target: target, SnapshotDigest: snapshotDigest},
		Transitions: []arcade.OperationServerTransition{{Step: "Apply", FromGeneration: 1, ToGeneration: 2, DesiredState: arcade.DesiredStateRunning, SpecDigest: specDigest, RequestedAt: now}}}
}
