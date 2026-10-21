//go:build envtest

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installbaseline"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
)

// Native endpoint evidence with schema-valid requests and existing signed actor
// permissions, not RBAC/schema/AlreadyExists substitute failures. All named
// originals come from actual administrator CREATE acknowledgements. This owned
// API server has no controllers/kubelets and the four Service seeds select no
// Pods. No tokens/worlds/executing workload or extra actor privilege is created.
func testBaselineNativeIdentityDenials(t *testing.T, ctx context.Context, admin *kubernetes.Clientset, access *HTTPAccess, plan *installrender.Plan, signedOriginals map[installstate.Key]*unstructured.Unstructured) {
	t.Helper()
	ordinary, err := access.actorClientForPurpose(ordinaryControllerActor, plan.Namespace(), baselineAdmissionPurpose)
	if err != nil {
		t.Fatal("native identity serving actor unavailable")
	}
	first, err := baselineIdentityCreateProbe(plan, ordinaryControllerActor, "ServiceAccount", "arcadectl-controller")
	if err != nil {
		t.Fatal("native identity serving constructor unavailable")
	}
	policy := "arcadectl-identity-identity-" + plan.Namespace()
	if wait.PollUntilContextTimeout(ctx, 100*time.Millisecond, 15*time.Second, true, func(ctx context.Context) (bool, error) {
		_, err := ordinary.probeCreate(ctx, first, policy, policy, installbaseline.DenialMessage)
		return err == nil, nil
	}) != nil {
		t.Fatal("native exact identity admission serving unavailable")
	}
	for _, name := range []string{"arcadectl-controller", "arcadectl-api", "arcadectl-destroy-controller", "arcadectl-destroy-admin"} {
		for _, kind := range []string{"ServiceAccount", "Role", "RoleBinding", "Service"} {
			t.Run("identity-original-"+kind+"-"+name, func(t *testing.T) {
				desired, err := baselineIdentityCreateProbe(plan, ordinaryControllerActor, kind, name)
				if err != nil {
					t.Fatal("native inert identity constructor unavailable")
				}
				key := installstate.Key{APIVersion: desired.GetAPIVersion(), Kind: kind, Namespace: plan.Namespace(), Name: name}
				ack := signedOriginals[key]
				if kind == "Service" {
					ack, err = access.Create(ctx, key, desired, false)
					if err != nil || ack == nil {
						t.Fatal("native administrative inert Service seed refused")
					}
				}
				if ack == nil || !nativeFixtureUID(string(ack.GetUID())) || !fixtureRV(ack.GetResourceVersion()) {
					t.Fatal("native identity lacks original administrative acknowledgement")
				}
				uid, rv := ack.GetUID(), ack.GetResourceVersion()
				if kind == "Service" {
					t.Cleanup(func() {
						cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
						defer cancel()
						background := metav1.DeletePropagationBackground
						options := metav1.DeleteOptions{PropagationPolicy: &background, Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &rv}}
						if err := admin.CoreV1().Services(plan.Namespace()).Delete(cleanupCtx, name, options); err != nil {
							t.Error("original-only inert Service cleanup refused")
							return
						}
						if _, err := admin.CoreV1().Services(plan.Namespace()).Get(cleanupCtx, name, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
							t.Error("original inert Service cleanup absence not established")
						}
					})
				}
				original, err := access.Get(ctx, key)
				if err != nil || original == nil || original.GetUID() != uid || original.GetResourceVersion() != rv || !reflect.DeepEqual(original.Object, ack.Object) {
					t.Fatal("native independent original identity readback refused")
				}
				for _, actorID := range []admissionActor{ordinaryControllerActor, destroyControllerActor} {
					if kind == "Service" && actorID == destroyControllerActor {
						continue
					}
					actor, err := access.actorClientForPurpose(actorID, plan.Namespace(), baselineAdmissionPurpose)
					if err != nil {
						t.Fatal("native original identity actor unavailable")
					}
					create, err := baselineIdentityCreateProbe(plan, actorID, kind, name)
					if err != nil {
						t.Fatal("native schema-valid identity CREATE unavailable")
					}
					operations := []admissionProbeOperation{probeCreateOperation}
					switch kind {
					case "ServiceAccount":
						operations = append(operations, probeDeleteAccountOperation)
					case "Role", "RoleBinding":
						operations = append(operations, probeDeleteIdentityOperation)
					case "Service":
						operations = append(operations, probeUpdateOperation, probePatchMetadataOperation, probeDeleteIdentityOperation)
					}
					for _, operation := range operations {
						t.Run(fmt.Sprintf("%s-%d", actorID.account(), operation), func(t *testing.T) {
							candidate := original.DeepCopy()
							if operation == probeCreateOperation {
								candidate = create.DeepCopy()
							} else if operation == probeUpdateOperation {
								candidate, err = baselineMetadataUpdateProbe(plan.Namespace(), key, original)
								if err != nil {
									t.Fatal("closed whole-original metadata UPDATE unavailable")
								}
							}
							permission, err := baselineActorPermission(actor.actor, key, operation)
							if err != nil || actor.authorize(ctx, permission) != nil {
								t.Fatal("native signed actor identity operation permission unavailable")
							}
							result, err := actor.probeOperation(ctx, operation, candidate, policy, policy, installbaseline.DenialMessage)
							if err != nil || result != nil {
								t.Error("native identity operation lacks exact baseline denial")
							}
							fresh, err := access.Get(ctx, key)
							if err != nil || fresh == nil || !reflect.DeepEqual(fresh.Object, original.Object) {
								t.Fatal("denied native identity operation changed or replaced its original")
							}
						})
					}
				}
			})
		}
	}
}
