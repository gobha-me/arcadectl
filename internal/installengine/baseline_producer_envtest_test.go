//go:build envtest

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installbaseline"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

// Whole native reply certification through the production inner guarded
// dry-run actor transport, not endpoint-only success or fabricated managed
// fields. This API-server-only fixture has no controllers or kubelets. Named
// controls seed inert original producers and signed original Pod chains in a
// private API server with no executor, PVCs or TokenRequests. They do NOT
// certify production original ownership,
// configured typechecking health or the still-unwired runtime guard.
func TestEnvtestBaselineProducerWholeReplies(t *testing.T) {
	for _, profile := range []string{installrender.Profile135, installrender.Profile137} {
		t.Run(profile, func(t *testing.T) {
			plan := fixturePlanProfile(t, "baseline-producer-replies", profile)
			environment := &envtest.Environment{
				UseExistingCluster: new(bool), DownloadBinaryAssets: true,
				DownloadBinaryAssetsVersion:  plan.Profile().KubernetesVersion,
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
			ctx, cancel := context.WithTimeout(t.Context(), 12*time.Minute)
			defer cancel()
			access, err := NewDirectHTTPAccess(config)
			if err != nil || access.checkVersion(ctx, plan.Profile()) != nil {
				t.Fatal("exact-profile owned transport unavailable")
			}
			signedOriginals := map[installstate.Key]*unstructured.Unstructured{}
			for _, resource := range plan.Resources() {
				switch resource.Object.GetKind() {
				case "Namespace", "ServiceAccount", "Role", "RoleBinding", "ClusterRole", "ClusterRoleBinding":
					ack, err := access.Create(ctx, resourceKey(resource), resource.Object, false)
					if err != nil || ack == nil || !nativeFixtureUID(string(ack.GetUID())) || !fixtureRV(ack.GetResourceVersion()) {
						t.Fatal("signed native actor dependency refused")
					}
					signedOriginals[resourceKey(resource)] = ack.DeepCopy()
				}
			}
			baseline, baselineACKs := installStandaloneBaselineContract(t, ctx, access, plan.Namespace(), profile)
			admin, err := kubernetes.NewForConfig(config)
			if err != nil {
				t.Fatal("owned independent inventory unavailable")
			}
			testBaselineNativeWildcardContainment(t, ctx, admin, access, plan.Namespace())
			testBaselineNativeIdentityDenials(t, ctx, admin, access, plan, signedOriginals)
			testBaselineNativeDescendantIdentity(t, ctx, admin, access, plan, func(document installstate.Document, parentACKs map[installstate.Key]*unstructured.Unstructured) {
				testBaselineNativeWholeBehavior(t, ctx, admin, access, plan, baseline, baselineACKs, signedOriginals, document, parentACKs)
			})
			testBaselineNativeForegroundParent(t, ctx, admin, access, plan)
			testBaselineNativeForegroundService(t, ctx, admin, access, plan)
			for _, row := range []struct {
				actor admissionActor
				kind  string
			}{{ordinaryControllerActor, "Job"}, {destroyControllerActor, "Job"}, {ordinaryControllerActor, "Deployment"}} {
				t.Run(row.actor.account()+"-"+row.kind, func(t *testing.T) {
					actor, err := access.actorClientForPurpose(row.actor, plan.Namespace(), baselineAdmissionPurpose)
					if err != nil {
						t.Fatal("closed native actor transport unavailable")
					}
					desired, err := baselineProducerProbe(plan, row.kind, strings.Repeat("a", 32))
					if err != nil {
						t.Fatal("closed inert producer constructor refused")
					}
					// Exact native attribution proves baseline admission is serving;
					// RBAC/schema/another policy failure is not a successful control.
					negative, err := baselineNegativeProducerProbe(plan, row.kind, strings.Repeat("a", 32), baselineProducerReservedAccount, "arcadectl-destroy-controller")
					if err != nil {
						t.Fatal("native reserved-identity negative unavailable")
					}
					policy := "arcadectl-identity-template-" + plan.Namespace()
					if wait.PollUntilContextTimeout(ctx, 100*time.Millisecond, 15*time.Second, true, func(ctx context.Context) (bool, error) {
						_, err := actor.probeCreate(ctx, negative, policy, policy, installbaseline.DenialMessage)
						return err == nil, nil
					}) != nil {
						t.Fatal("exact native baseline denial unavailable")
					}
					testBaselineNativeClosedProducerVariants(t, ctx, admin, actor, plan, row.kind, policy)
					start := time.Now().UTC()
					reply, err := actor.probeCreate(ctx, desired, "", "", "")
					end := time.Now().UTC()
					if err != nil || reply == nil {
						t.Fatal("native whole positive dry-run reply unavailable")
					}
					if !validBaselineProducerResult(plan, row.kind, strings.Repeat("a", 32), reply, start, end) {
						// Emit only fixed structural booleans, never raw responses,
						// errors, identities, managed fields or server metadata.
						fields, _, _ := unstructured.NestedFieldCopy(reply.Object, "metadata", "managedFields")
						entries, ok := fields.([]any)
						fieldMatch := false
						if ok && len(entries) == 1 {
							entry, ok := entries[0].(map[string]any)
							fieldMatch = ok && reflect.DeepEqual(entry["fieldsV1"], baselineProducerFieldset(desired))
						}
						t.Errorf("native whole reply refused: spec_equal=%t status_empty=%t field_tree_equal=%t", reflect.DeepEqual(reply.Object["spec"], desired.Object["spec"]), reflect.DeepEqual(reply.Object["status"], map[string]any{}), fieldMatch)
					}
					// Independent reads must establish that neither the accepted
					// dry run nor its denied control persisted an executable.
					if row.kind == "Job" {
						_, err = admin.BatchV1().Jobs(plan.Namespace()).Get(ctx, desired.GetName(), metav1.GetOptions{})
					} else {
						_, err = admin.AppsV1().Deployments(plan.Namespace()).Get(ctx, desired.GetName(), metav1.GetOptions{})
					}
					if !apierrors.IsNotFound(err) {
						t.Fatal("producer dry run persisted or independent absence read failed")
					}
					testBaselineProducerNamedDenials(t, ctx, admin, actor, negative, policy)
				})
			}
			jobs, jobErr := admin.BatchV1().Jobs(plan.Namespace()).List(ctx, metav1.ListOptions{})
			deployments, deploymentErr := admin.AppsV1().Deployments(plan.Namespace()).List(ctx, metav1.ListOptions{})
			pods, podErr := admin.CoreV1().Pods(plan.Namespace()).List(ctx, metav1.ListOptions{})
			if jobErr != nil || deploymentErr != nil || podErr != nil || len(jobs.Items) != 0 || len(deployments.Items) != 0 || len(pods.Items) != 0 {
				t.Fatal("native dry-run producer inventory is not completely empty")
			}
		})
	}
}

func testBaselineNativeClosedProducerVariants(t *testing.T, ctx context.Context, admin *kubernetes.Clientset, actor *HTTPAccess, plan *installrender.Plan, kind, policy string) {
	t.Helper()
	for _, reserved := range []string{"arcadectl-controller", "arcadectl-api", "arcadectl-destroy-controller", "arcadectl-destroy-admin"} {
		for _, variant := range []baselineProducerNegative{baselineProducerReservedAccount, baselineProducerReservedName} {
			object, err := baselineNegativeProducerProbe(plan, kind, strings.Repeat("b", 32), variant, reserved)
			if err != nil || object == nil {
				t.Fatal("closed native negative producer variant unavailable")
			}
			absent := func() bool {
				var err error
				if kind == "Job" {
					_, err = admin.BatchV1().Jobs(plan.Namespace()).Get(ctx, object.GetName(), metav1.GetOptions{})
				} else {
					_, err = admin.AppsV1().Deployments(plan.Namespace()).Get(ctx, object.GetName(), metav1.GetOptions{})
				}
				return apierrors.IsNotFound(err)
			}
			if !absent() {
				t.Fatal("negative producer address has an unowned original")
			}
			if reply, err := actor.probeCreate(ctx, object, policy, policy, installbaseline.DenialMessage); err != nil || reply != nil {
				t.Fatal("native closed producer variant lacks attributed template denial")
			}
			if !absent() {
				t.Fatal("native negative producer dry-run persisted or absence unavailable")
			}
		}
	}
}

// Seed only an administrative acknowledged suspended/zero-replica original
// with a reserved account. The actor may neither update nor dry-run delete it.
// No CREATE reply is converted into installer ownership or a cleanup target;
// only this test's actual persistent administrative ACK authorizes its cleanup.
func testBaselineProducerNamedDenials(t *testing.T, ctx context.Context, admin *kubernetes.Clientset, actor *HTTPAccess, seed *unstructured.Unstructured, policy string) {
	t.Helper()
	kind, namespace, name := seed.GetKind(), seed.GetNamespace(), seed.GetName()
	read := func(ctx context.Context) (*unstructured.Unstructured, error) {
		var value any
		var err error
		if kind == "Job" {
			value, err = admin.BatchV1().Jobs(namespace).Get(ctx, name, metav1.GetOptions{})
		} else {
			value, err = admin.AppsV1().Deployments(namespace).Get(ctx, name, metav1.GetOptions{})
		}
		if err != nil {
			return nil, ErrRead
		}
		fields, err := runtime.DefaultUnstructuredConverter.ToUnstructured(value)
		if err != nil {
			return nil, ErrRead
		}
		fields["apiVersion"], fields["kind"] = seed.GetAPIVersion(), kind
		return &unstructured.Unstructured{Object: fields}, nil
	}
	var ack metav1.Object
	if kind == "Job" {
		var desired batchv1.Job
		if decodeServing(seed, &desired) != nil {
			t.Fatal("inert native Job seed unavailable")
		}
		value, err := admin.BatchV1().Jobs(namespace).Create(ctx, &desired, metav1.CreateOptions{FieldManager: "arcadectl-installer", FieldValidation: "Strict"})
		if err != nil {
			t.Fatal("administrative inert Job seed refused")
		}
		ack = value
	} else {
		var desired appsv1.Deployment
		if decodeServing(seed, &desired) != nil {
			t.Fatal("inert native Deployment seed unavailable")
		}
		value, err := admin.AppsV1().Deployments(namespace).Create(ctx, &desired, metav1.CreateOptions{FieldManager: "arcadectl-installer", FieldValidation: "Strict"})
		if err != nil {
			t.Fatal("administrative inert Deployment seed refused")
		}
		ack = value
	}
	uid, rv := ack.GetUID(), ack.GetResourceVersion()
	if !nativeFixtureUID(string(uid)) || !fixtureRV(rv) {
		t.Fatal("native producer seed lacks original acknowledgement")
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		// This API-server-only fixture has no garbage-collector controller.
		// Do not request the implicit orphan/foreground finalizer workflow.
		background := metav1.DeletePropagationBackground
		options := metav1.DeleteOptions{PropagationPolicy: &background, Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &rv}}
		var err error
		if kind == "Job" {
			err = admin.BatchV1().Jobs(namespace).Delete(cleanupCtx, name, options)
		} else {
			err = admin.AppsV1().Deployments(namespace).Delete(cleanupCtx, name, options)
		}
		if err != nil {
			t.Error("original-only inert producer cleanup failed")
			return
		}
		if kind == "Job" {
			_, err = admin.BatchV1().Jobs(namespace).Get(cleanupCtx, name, metav1.GetOptions{})
		} else {
			_, err = admin.AppsV1().Deployments(namespace).Get(cleanupCtx, name, metav1.GetOptions{})
		}
		if !apierrors.IsNotFound(err) {
			t.Error("original inert producer cleanup absence was not established")
		}
	})
	original, err := read(ctx)
	if err != nil || original.GetUID() != uid || original.GetResourceVersion() != rv {
		t.Fatal("independent original producer readback refused")
	}
	operations := []admissionProbeOperation{probeUpdateOperation, probeDeleteExecutableOperation}
	if kind == "Deployment" {
		operations = append(operations, probePatchMetadataOperation)
	}
	for _, operation := range operations {
		candidate := original.DeepCopy()
		if operation == probeUpdateOperation {
			candidate.SetAnnotations(map[string]string{"arcade.gobha.me/inert-denial": "test-only"})
		}
		result, err := actor.probeOperation(ctx, operation, candidate, policy, policy, installbaseline.DenialMessage)
		if err != nil || result != nil {
			t.Error("native original producer mutation lacks exact baseline denial")
		}
		fresh, err := read(ctx)
		if err != nil || !reflect.DeepEqual(fresh.Object, original.Object) {
			t.Fatal("denied native producer mutation changed or replaced the original")
		}
	}
}
