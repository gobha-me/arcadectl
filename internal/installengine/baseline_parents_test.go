// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installcontract"
	"github.com/gobha-me/arcadectl/internal/installstate"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
)

// Synthetic signed original-state classification, not native admission,
// deletion completion, parent/descendant closure or a wired runtime guard.
func TestBaselineOriginalParentsPendingIdentityNotReadiness(t *testing.T) {
	plan := fixturePlan(t)
	for _, family := range []string{"arcadectl-controller", "arcadectl-destroy-controller", "arcadectl-api"} {
		for _, scenario := range []string{
			"absent", "foreign-present", "recorded", "recorded-missing", "replacement", "unsigned-spec", "unknown-field",
			"create-absent", "create-ack", "create-empty-receipt", "create-no-receipt", "create-copied-nonce", "create-foreign-receipt", "create-before-fields", "create-wrong-hash", "create-wrong-phase",
			"update-before", "update-after", "update-replacement", "update-before-rv", "update-new-nonce-old-rv", "update-wrong-hash", "update-missing",
			"delete-before", "delete-draining", "delete-absent", "delete-replacement", "delete-foreign-finalizer", "delete-nonzero-grace", "delete-unsigned-spec", "delete-wrong-rv", "delete-no-intent", "delete-wrong-mode",
		} {
			t.Run(family+"/"+scenario, func(t *testing.T) {
				f := newFixtureWithPlans(t, false, plan)
				d := f.snapshot.Document()
				key := deploymentKey(d.Namespace, family)
				template, err := f.engine.contracts[plan.Digest()].Template(key, false)
				if err != nil {
					t.Fatal("signed original parent template unavailable")
				}
				live := testBaselineParentLive(t, template, strings.Repeat("b", 32))
				live.SetUID(types.UID("original-" + family))
				live.SetResourceVersion("17")
				live.SetGeneration(1)
				// Pending/failed/unscheduled is deliberately not Ready. Status
				// cannot confer or withdraw signed original parent identity.
				live.Object["status"] = map[string]any{"observedGeneration": int64(0), "unavailableReplicas": int64(1)}
				recorded := !strings.HasPrefix(scenario, "create-") && scenario != "absent" && scenario != "foreign-present"
				if recorded {
					d.Resources = append(d.Resources, installstate.Resource{Key: key, UID: live.GetUID(), TemplateSHA256: template.Hash(), Retained: template.Retained(), Phase: template.Phase()})
				}
				if strings.HasPrefix(scenario, "create-") || strings.HasPrefix(scenario, "update-") {
					d.Pending = &installstate.Pending{Action: installstate.Create, Key: key, CreateNonce: strings.Repeat("c", 32), AfterSHA256: template.Hash()}
					if strings.HasPrefix(scenario, "update-") {
						d.Pending.Action = installstate.Update
						d.Pending.BeforeUID, d.Pending.BeforeResourceVersion, d.Pending.BeforeSHA256 = live.GetUID(), "17", template.Hash()
					}
				}
				if strings.HasPrefix(scenario, "delete-") {
					d.Mode, d.ActivePackage, d.Installed = installstate.Uninstall, d.TargetPackage, true
					d.Pending = &installstate.Pending{Action: installstate.Delete, Key: key, CreateNonce: strings.Repeat("c", 32), BeforeUID: live.GetUID(), BeforeResourceVersion: "17", BeforeSHA256: template.Hash()}
				}
				if strings.HasPrefix(scenario, "create-") && scenario != "create-absent" {
					annotations := live.GetAnnotations()
					annotations[installstate.MutationAnnotation] = d.Pending.CreateNonce
					live.SetAnnotations(annotations)
					if scenario != "create-no-receipt" {
						receiptDoc := d
						if scenario == "create-foreign-receipt" {
							receiptDoc.NamespaceUID = "foreign-namespace"
						}
						if f.engine.prepareCreateReceipt(receiptDoc) != nil || scenario != "create-empty-receipt" && f.engine.saveCreateUID(receiptDoc, live.GetUID()) != nil {
							t.Fatal("test original acknowledgement seed unavailable")
						}
					}
				}
				if strings.HasPrefix(scenario, "delete-") && scenario != "delete-before" && scenario != "delete-absent" {
					stamp := metav1.NewTime(time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC))
					live.SetDeletionTimestamp(&stamp)
					live.SetFinalizers([]string{"foregroundDeletion"})
					zero := int64(0)
					live.SetDeletionGracePeriodSeconds(&zero)
					live.SetResourceVersion("18")
				}
				accepted, absent := false, false
				switch scenario {
				case "absent", "create-absent", "delete-absent":
					live, accepted, absent = nil, true, true
				case "recorded", "create-ack", "update-before", "delete-before", "delete-draining":
					accepted = true
				case "recorded-missing", "update-missing":
					live = nil
				case "replacement", "create-copied-nonce", "update-replacement", "delete-replacement":
					live.SetUID("foreign-same-name")
				case "unsigned-spec", "delete-unsigned-spec":
					_ = unstructured.SetNestedField(live.Object, "foreign-account", "spec", "template", "spec", "serviceAccountName")
				case "unknown-field":
					live.Object["privateUnknown"] = "PRIVATE-CANARY"
				case "create-before-fields":
					d.Pending.BeforeUID = "foreign-before"
				case "create-wrong-hash", "update-wrong-hash":
					d.Pending.AfterSHA256 = strings.Repeat("f", 64)
				case "create-wrong-phase":
					d.Stage = installstate.Verifying
				case "update-after", "update-new-nonce-old-rv":
					annotations := live.GetAnnotations()
					annotations[installstate.MutationAnnotation] = d.Pending.CreateNonce
					live.SetAnnotations(annotations)
					if scenario == "update-after" {
						live.SetResourceVersion("18")
						accepted = true
					}
				case "update-before-rv":
					d.Pending.BeforeResourceVersion = "16"
				case "delete-foreign-finalizer":
					live.SetFinalizers([]string{"foreign.example/hold"})
				case "delete-nonzero-grace":
					nonzero := int64(1)
					live.SetDeletionGracePeriodSeconds(&nonzero)
				case "delete-wrong-rv":
					live.SetResourceVersion("17")
				case "delete-no-intent":
					d.Pending = nil
				case "delete-wrong-mode":
					d.Mode = installstate.Install
				}
				var original *unstructured.Unstructured
				if live != nil {
					original = live.DeepCopy()
				}
				writes, namespaceWrites := f.access.writes, f.nsUpdates
				parent, err := f.engine.originalBaselineParent(d, key, live)
				t.Cleanup(parent.release)
				if (err == nil) != accepted || accepted && (parent == nil) != absent || err != nil && parent != nil {
					t.Fatal("parent identity confused original intent, readiness, absence or foreign state")
				}
				if !reflect.DeepEqual(original, live) || f.access.writes != writes || f.nsUpdates != namespaceWrites {
					t.Fatal("read-only parent classifier changed original input or performed an effect")
				}
				if parent != nil {
					if !reflect.DeepEqual(parent.whole.Object, live.Object) || parent.parent.UID != live.GetUID() || parent.template.Hash() != template.Hash() || (parent.receipt != nil) != (scenario == "create-ack") {
						t.Fatal("parent witness lost exact raw evidence, signed shape or protected acknowledgement")
					}
					parent.whole.SetUID("changed-local-copy")
					parent.parent.UID = "changed-local-copy"
					if !reflect.DeepEqual(original, live) {
						t.Fatal("parent witness shares mutable source evidence")
					}
				}
			})
		}
	}
}

func TestBaselineOriginalParentPrivateRouteRefusesNonInstallationKeys(t *testing.T) {
	f := newFixture(t, false)
	d := f.snapshot.Document()
	for _, key := range []installstate.Key{
		deploymentKey(d.Namespace, "unreserved"),
		deploymentKey(d.Namespace, "arcadectl-destroy-admin"),
		deploymentKey("foreign", "arcadectl-controller"),
		{APIVersion: "batch/v1", Kind: "Job", Namespace: d.Namespace, Name: "arcadectl-controller"},
		{APIVersion: "v1", Kind: "ServiceAccount", Namespace: d.Namespace, Name: "arcadectl-controller"},
	} {
		if parent, err := f.engine.originalBaselineParent(d, key, nil); err == nil || parent != nil {
			t.Fatal("private parent identity route widened to another object or namespace")
		}
	}
}

func TestBaselineOriginalParentSignedUpgradeRollbackAndQuiescence(t *testing.T) {
	previous, target := lifecycleTransitionPlans(t)
	for _, family := range []string{"arcadectl-controller", "arcadectl-destroy-controller", "arcadectl-api"} {
		for _, phase := range []string{"upgrade", "rollback", "quiesce", "quiesce-delete"} {
			if phase == "quiesce" && family == "arcadectl-api" || phase == "quiesce-delete" && family != "arcadectl-api" {
				continue
			}
			t.Run(family+"/"+phase, func(t *testing.T) {
				f := newFixtureWithPlans(t, false, previous, target)
				d := f.snapshot.Document()
				d.Mode, d.ActivePackage, d.TargetPackage, d.Installed = installstate.Upgrade, previous.Digest(), target.Digest(), true
				if phase == "rollback" {
					d.Mode, d.ActivePackage, d.TargetPackage, d.PreviousPackage = installstate.Rollback, target.Digest(), previous.Digest(), previous.Digest()
				}
				if strings.HasPrefix(phase, "quiesce") {
					d.Stage = installstate.Quiescing
				}
				key := deploymentKey(d.Namespace, family)
				before, err := f.engine.contracts[d.ActivePackage].Template(key, false)
				if err != nil {
					t.Fatal("authenticated predecessor parent unavailable")
				}
				liveBefore := testBaselineParentLive(t, before, strings.Repeat("b", 32))
				liveBefore.SetUID("original-transition-parent")
				liveBefore.SetResourceVersion("17")
				d.Resources = append(d.Resources, installstate.Resource{Key: key, UID: liveBefore.GetUID(), TemplateSHA256: before.Hash(), Retained: before.Retained(), Phase: before.Phase()})
				if phase == "quiesce-delete" {
					d.Pending = &installstate.Pending{Action: installstate.Delete, Key: key, CreateNonce: strings.Repeat("c", 32), BeforeUID: liveBefore.GetUID(), BeforeResourceVersion: "17", BeforeSHA256: before.Hash()}
					parent, err := f.engine.originalBaselineParent(d, key, liveBefore)
					t.Cleanup(parent.release)
					if err != nil || parent == nil {
						t.Fatal("original API withdrawal before controller quiescence refused")
					}
					if parent, err := f.engine.originalBaselineParent(d, key, nil); err != nil || parent != nil {
						t.Fatal("acknowledged API withdrawal absence refused")
					}
					return
				}
				digest, paused := d.TargetPackage, false
				if phase == "quiesce" {
					digest, paused = d.ActivePackage, true
				}
				after, err := f.engine.contracts[digest].Template(key, paused)
				if err != nil || after.Hash() == before.Hash() {
					t.Fatal("genuinely different signed transition parent unavailable")
				}
				d.Pending = &installstate.Pending{Action: installstate.Update, Key: key, CreateNonce: strings.Repeat("c", 32), BeforeUID: liveBefore.GetUID(), BeforeResourceVersion: "17", BeforeSHA256: before.Hash(), AfterSHA256: after.Hash()}
				for _, state := range []string{"before", "after", "unsigned", "replacement"} {
					live := liveBefore.DeepCopy()
					expected := before.Hash()
					if state != "before" {
						live = testBaselineParentLive(t, after, d.Pending.CreateNonce)
						live.SetUID(liveBefore.GetUID())
						live.SetResourceVersion("18")
						expected = after.Hash()
					}
					if state == "unsigned" {
						_ = unstructured.SetNestedField(live.Object, "foreign", "spec", "template", "spec", "serviceAccountName")
					}
					if state == "replacement" {
						live.SetUID("foreign-same-name")
					}
					parent, err := f.engine.originalBaselineParent(d, key, live)
					t.Cleanup(parent.release)
					if (err == nil) != (state == "before" || state == "after") || err == nil && (parent == nil || parent.template.Hash() != expected || parent.parent.UID != liveBefore.GetUID()) {
						t.Fatal("transition parent confused signed before/after with unsigned or replaced execution")
					}
				}
			})
		}
	}
}

// Explicit synthetic native defaults, not a real API acknowledgement. Signed
// PodTemplate supplies the already reviewed template defaults; independent
// literal Deployment defaults match the two native profile contracts.
func testBaselineParentLive(t *testing.T, template *installcontract.Template, nonce string) *unstructured.Unstructured {
	t.Helper()
	candidate, err := template.Candidate(nonce)
	if err != nil {
		t.Fatal("signed original parent candidate unavailable")
	}
	var parent appsv1.Deployment
	if decodeServing(candidate, &parent) != nil {
		t.Fatal("signed parent fixture decode unavailable")
	}
	pod, err := template.PodTemplate()
	if err != nil {
		t.Fatal("signed defaulted PodTemplate unavailable")
	}
	parent.Spec.Template = *pod
	parent.Spec.RevisionHistoryLimit = ptr.To[int32](10)
	parent.Spec.ProgressDeadlineSeconds = ptr.To[int32](600)
	if parent.Spec.Strategy.Type == "" {
		parent.Spec.Strategy.Type = appsv1.RollingUpdateDeploymentStrategyType
	}
	if parent.Spec.Strategy.Type == appsv1.RollingUpdateDeploymentStrategyType {
		if parent.Spec.Strategy.RollingUpdate == nil {
			parent.Spec.Strategy.RollingUpdate = &appsv1.RollingUpdateDeployment{}
		}
		if parent.Spec.Strategy.RollingUpdate.MaxSurge == nil {
			parent.Spec.Strategy.RollingUpdate.MaxSurge = ptr.To(intstr.FromString("25%"))
		}
		if parent.Spec.Strategy.RollingUpdate.MaxUnavailable == nil {
			parent.Spec.Strategy.RollingUpdate.MaxUnavailable = ptr.To(intstr.FromString("25%"))
		}
	}
	return servingObject(t, &parent)
}
