//go:build kindinstall

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installrender"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/dynamic"
)

// Only within targetKindFixture's fresh exclusively owned cluster, with no
// application controllers deployed. These scans are additional safety evidence,
// not universal GC closure or an arbitrary-cluster production cold provider.
func proveKindCancelledDestroySeed(t *testing.T, ctx context.Context, wire *fixtureWire, admin dynamic.Interface, plan *installrender.Plan) {
	t.Helper()
	ledger := wire.ledger
	cold := func() {
		t.Helper()
		for _, resource := range plan.Resources() {
			if resource.Phase == installrender.Controllers && resource.Object.GetKind() == "Deployment" {
				if _, err := wire.actors.admission.prerequisites.access.Get(ctx, resourceKey(resource)); !apierrors.IsNotFound(err) {
					t.Fatal("synthetic status requires actual absent signed application controllers")
				}
			}
		}
		for _, plural := range []string{"gameservers", "gamebackups", "gamerestores", "gamedestroys", "arcadeoperations", "leases"} {
			gv := schema.GroupVersionResource{Group: "arcade.gobha.me", Version: "v1alpha1", Resource: plural}
			if plural == "leases" {
				gv.Group, gv.Version = "coordination.k8s.io", "v1"
			}
			objects, err := admin.Resource(gv).Namespace(plan.Namespace()).List(ctx, metav1.ListOptions{})
			if err != nil {
				t.Fatal("synthetic status cold domain/lease observation unavailable")
			}
			for _, o := range objects.Items {
				if plural != "gamedestroys" || o.GetName() != ledger.document.Entries[fixtureCancelledDestroy].Key.Name || o.GetUID() != ledger.document.Entries[fixtureCancelledDestroy].OriginalUID {
					t.Fatal("synthetic status found nonfixture domain/lease evidence")
				}
			}
		}
	}
	cold()
	original, absent, err := wire.get(ctx, fixtureCancelledDestroy)
	if err != nil || absent || ledger.validateResult(fixtureCancelledDestroy, fixtureStableResult, original, time.Now().UTC()) != nil {
		t.Fatal("original absent-status seed body unproved")
	}
	next, err := ledger.nextDocument()
	if err != nil {
		t.Fatal("seed intent unavailable")
	}
	next.DestroySeed = &fixtureDestroySeedReceipt{State: fixtureDestroySeedAttempted, BeforeResourceVersion: original.GetResourceVersion()}
	if ledger.advance(next) != nil {
		t.Fatal("seed intent durability refused")
	}
	seeded, err := wire.seedDestroyStatus(ctx)
	if err != nil {
		if ledger.document.DestroySeed.State == fixtureDestroySeedAcknowledged {
			if live, absent, getErr := wire.get(ctx, fixtureCancelledDestroy); getErr == nil && !absent {
				_ = captureNativeFixtureShape(ledger, fixtureCancelledDestroy, "seed", live)
			}
		}
		t.Fatal("original native status seed acknowledgement/whole shape refused")
	}
	if seeded == nil || seeded.GetUID() != original.GetUID() || seeded.GetResourceVersion() == original.GetResourceVersion() || ledger.document.DestroySeed.State != fixtureDestroySeedAcknowledged || seeded.GetResourceVersion() != ledger.document.DestroySeed.AcknowledgedResourceVersion || ledger.seedAck || ledger.seedEffect || captureNativeFixtureShape(ledger, fixtureCancelledDestroy, "seed", seeded) != nil {
		t.Fatal("native seed original ACK/fieldshape/capability contract failed")
	}
	before := bytes.Clone(ledger.body)
	unchanged := func() {
		t.Helper()
		live, absent, err := wire.get(ctx, fixtureCancelledDestroy)
		if err != nil || absent || !reflect.DeepEqual(live.Object, seeded.Object) || ledger.validateDestroySeedResult(live, time.Now().UTC()) != nil || !bytes.Equal(before, ledger.body) || ledger.seedAck || ledger.seedEffect {
			t.Fatal("dry-run persisted confirmation or changed seeded original/WAL")
		}
		cold()
	}
	unchanged()
	control, err := wire.actors.probe(ctx, destroyControllerActor, probeUpdateOperation, seeded.DeepCopy(), "", "", "")
	if err != nil || control == nil || control.GetResourceVersion() != seeded.GetResourceVersion() || ledger.validateDestroySeedResult(control, time.Now().UTC()) != nil {
		t.Fatal("original destroy-controller unchanged update control failed")
	}
	unchanged()
	changed := seeded.DeepCopy()
	if unstructured.SetNestedField(changed.Object, ledger.document.RunID, "spec", "confirmationChallenge") != nil {
		t.Fatal("fixed dry-run confirmation unavailable")
	}
	seedFields := seeded.GetManagedFields()
	if len(seedFields) != 2 || seedFields[1].Time == nil {
		t.Fatal("native seed status timestamp unavailable")
	}
	seedTime := seedFields[1].Time.Time
	if wait.PollUntilContextTimeout(ctx, 50*time.Millisecond, 2*time.Second, true, func(context.Context) (bool, error) {
		return time.Now().UTC().Truncate(time.Second).After(seedTime), nil
	}) != nil {
		t.Fatal("later-second confirmation control unavailable")
	}
	accepted, err := wire.actors.probe(ctx, destroyAdministratorActor, probeUpdateOperation, changed.DeepCopy(), "", "", "")
	if err != nil || accepted == nil || ledger.validateDestroyConfirmationResult(accepted, time.Now().UTC()) != nil {
		t.Fatal("distinct-admin valid confirmation dry-run whole acceptance failed")
	}
	confirmationFields := accepted.GetManagedFields()
	if len(confirmationFields) != 2 || confirmationFields[0].Subresource != "status" || confirmationFields[1].Subresource != "" || confirmationFields[0].Time == nil || confirmationFields[1].Time == nil || !confirmationFields[1].Time.After(confirmationFields[0].Time.Time) {
		t.Fatal("later-second native confirmation ownership ordering unproved")
	}
	unchanged()
	policyName, bindingName := "", ""
	for name := range wire.actors.policies.policies {
		if name == "arcadectl-destroy-unsafe-admin" || strings.HasPrefix(name, "arcadectl-destroy-unsafe-admin-") {
			if policyName != "" {
				t.Fatal("ambiguous original unsafe policy")
			}
			policyName = name
		}
	}
	policy := wire.actors.policies.policies[policyName]
	if policy == nil || len(policy.Spec.Validations) < 1 {
		t.Fatal("original unsafe policy unavailable")
	}
	for name, binding := range wire.actors.policies.bindings {
		if binding.Spec.PolicyName == policyName {
			if bindingName != "" {
				t.Fatal("ambiguous original unsafe binding")
			}
			bindingName = name
		}
	}
	denied, err := wire.actors.probe(ctx, destroyControllerActor, probeUpdateOperation, changed.DeepCopy(), policyName, bindingName, policy.Spec.Validations[0].Message)
	if err != nil || denied != nil {
		t.Fatal("valid confirmation update did not yield exact original unsafe policy denial")
	}
	unchanged()
	if _, err := wire.seedDestroyStatus(ctx); err != ErrFixtures {
		t.Fatal("native status seed replay accepted")
	}
	unchanged()
}
