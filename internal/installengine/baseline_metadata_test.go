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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
)

// Independent literal address oracle: absence at an unsigned reserved Service
// is still an obligation, not a reason to remove the address from the witness.
func testBaselineMetadataKeys(namespace string) []installstate.Key {
	var keys []installstate.Key
	for _, name := range []string{"arcadectl-controller", "arcadectl-api", "arcadectl-destroy-controller", "arcadectl-destroy-admin"} {
		for _, pair := range [][2]string{{"v1", "ServiceAccount"}, {"rbac.authorization.k8s.io/v1", "Role"}, {"rbac.authorization.k8s.io/v1", "RoleBinding"}, {"v1", "Service"}} {
			keys = append(keys, installstate.Key{APIVersion: pair[0], Kind: pair[1], Namespace: namespace, Name: name})
		}
	}
	return keys
}

func TestBaselineMetadataFixedAddressDomain(t *testing.T) {
	want := testBaselineMetadataKeys("isolated-install")
	if len(want) != 16 || !reflect.DeepEqual(want, baselineMetadataKeys("isolated-install")) {
		t.Fatal("fixed reserved metadata catalog dropped an address")
	}
	f := newFixture(t, false)
	d := f.snapshot.Document()
	for _, key := range []installstate.Key{
		{APIVersion: "v1", Kind: "Secret", Namespace: d.Namespace, Name: "arcadectl-api"},
		{APIVersion: "v1", Kind: "Service", Namespace: "foreign", Name: "arcadectl-api"},
		{APIVersion: "v1", Kind: "Service", Namespace: d.Namespace, Name: "unreserved"},
		{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRole", Name: "arcadectl-controller"},
	} {
		if object, err := f.engine.originalBaselineObject(d, key, nil); err == nil || object != nil || baselineMetadataKey(d.Namespace, key) {
			t.Fatal("reserved original route admitted another resource or namespace")
		}
	}
}

func TestBaselineMetadataOriginalPendingStates(t *testing.T) {
	plan := fixturePlan(t)
	for _, key := range testBaselineMetadataKeys(plan.Namespace()) {
		for _, scenario := range []string{
			"absent", "foreign-present", "recorded", "recorded-missing", "replacement", "unknown-field", "unsigned-shape", "bad-rv", "bad-uid", "negative-generation",
			"create-absent", "create-ack", "create-empty-receipt", "create-no-receipt", "create-copied-nonce", "create-foreign-receipt", "create-before-fields", "create-wrong-hash", "create-wrong-phase",
			"update-before", "update-after", "update-replacement", "update-before-rv", "update-new-nonce-old-rv", "update-wrong-hash", "update-missing",
			"delete-before", "delete-draining", "delete-absent", "delete-replacement", "delete-foreign-finalizer", "delete-extra-finalizer", "delete-nonzero-grace", "delete-unsigned-shape", "delete-wrong-rv", "delete-no-intent", "delete-wrong-mode", "delete-wrong-phase", "delete-after-hash",
		} {
			if key.Kind == "Service" && key.Name != "arcadectl-api" && scenario != "absent" && scenario != "foreign-present" {
				continue // No sealed template exists; no invented ownership seeds.
			}
			t.Run(key.Kind+"/"+key.Name+"/"+scenario, func(t *testing.T) {
				f := newFixtureWithPlans(t, false, plan)
				d := f.snapshot.Document()
				template, templateErr := f.engine.contracts[plan.Digest()].Template(key, false)
				var live *unstructured.Unstructured
				if templateErr == nil {
					live = testBaselineMetadataLive(t, template, strings.Repeat("b", 32))
				} else {
					live = &unstructured.Unstructured{Object: map[string]any{"apiVersion": key.APIVersion, "kind": key.Kind, "metadata": map[string]any{"namespace": key.Namespace, "name": key.Name}}}
				}
				live.SetUID(types.UID("original-" + key.Kind + "-" + key.Name))
				live.SetResourceVersion("17")
				// Native metadata objects may have generation zero. Do not use
				// Deployment generation as an accidental acceptance oracle.
				live.SetGeneration(0)
				if !strings.HasPrefix(scenario, "create-") && scenario != "absent" && scenario != "foreign-present" {
					d.Resources = append(d.Resources, installstate.Resource{Key: key, UID: live.GetUID(), TemplateSHA256: template.Hash(), Retained: template.Retained(), Phase: template.Phase()})
				}
				if strings.HasPrefix(scenario, "create-") || strings.HasPrefix(scenario, "update-") {
					d.Pending = &installstate.Pending{Action: installstate.Create, Key: key, CreateNonce: strings.Repeat("c", 32), AfterSHA256: template.Hash()}
					if strings.HasPrefix(scenario, "update-") {
						d.Pending.Action, d.Pending.BeforeUID, d.Pending.BeforeResourceVersion, d.Pending.BeforeSHA256 = installstate.Update, live.GetUID(), "17", template.Hash()
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
							t.Fatal("synthetic protected CREATE ACK unavailable")
						}
					}
				}
				if strings.HasPrefix(scenario, "delete-") && scenario != "delete-before" && scenario != "delete-absent" {
					stamp := metav1.NewTime(time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC))
					live.SetDeletionTimestamp(&stamp)
					live.SetDeletionGracePeriodSeconds(ptr.To[int64](0))
					live.SetFinalizers([]string{"foregroundDeletion"})
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
				case "unknown-field":
					live.Object["unknownField"] = "PRIVATE-CANARY"
				case "unsigned-shape", "delete-unsigned-shape":
					testBaselineMetadataUnsigned(live)
				case "bad-rv":
					live.SetResourceVersion("+0017")
				case "bad-uid":
					live.SetUID("invalid uid")
					// Bind the inventory to the same invalid UID so refusal
					// tests the UID contract, not just replacement detection.
					d.Resources[len(d.Resources)-1].UID = live.GetUID()
				case "negative-generation":
					live.SetGeneration(-1)
				case "create-before-fields":
					d.Pending.BeforeUID = "foreign"
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
				case "delete-extra-finalizer":
					live.SetFinalizers([]string{"foregroundDeletion", "foreign.example/hold"})
				case "delete-nonzero-grace":
					live.SetDeletionGracePeriodSeconds(ptr.To[int64](1))
				case "delete-wrong-rv":
					live.SetResourceVersion("17")
				case "delete-no-intent":
					d.Pending = nil
				case "delete-wrong-mode":
					d.Mode = installstate.Install
				case "delete-wrong-phase":
					d.Stage = installstate.Quiescing
				case "delete-after-hash":
					d.Pending.AfterSHA256 = template.Hash()
				}
				var original *unstructured.Unstructured
				if live != nil {
					original = live.DeepCopy()
				}
				writes, namespaceWrites := f.access.writes, f.nsUpdates
				object, err := f.engine.originalBaselineObject(d, key, live)
				t.Cleanup(object.release)
				if (err == nil) != accepted || accepted && (object == nil) != absent || err != nil && object != nil {
					t.Fatal("metadata original classifier confused intent, absence or foreign state")
				}
				if !reflect.DeepEqual(original, live) || f.access.writes != writes || f.nsUpdates != namespaceWrites {
					t.Fatal("metadata classifier mutated evidence or performed an effect")
				}
				if object != nil {
					if !reflect.DeepEqual(object.whole.Object, live.Object) || object.template.Hash() != template.Hash() || (object.receipt != nil) != (scenario == "create-ack") {
						t.Fatal("metadata witness lost whole original or protected receipt")
					}
					object.whole.SetUID("changed-copy")
					if !reflect.DeepEqual(original, live) {
						t.Fatal("metadata witness shares mutable original")
					}
				}
			})
		}
	}
}

func TestBaselineMetadataSignedRoleUpgradeRollback(t *testing.T) {
	previous, target := lifecycleTransitionPlans(t)
	for _, mode := range []installstate.Mode{installstate.Upgrade, installstate.Rollback} {
		t.Run(string(mode), func(t *testing.T) {
			f := newFixtureWithPlans(t, false, previous, target)
			d := f.snapshot.Document()
			d.Mode, d.ActivePackage, d.TargetPackage, d.Installed = mode, previous.Digest(), target.Digest(), true
			if mode == installstate.Rollback {
				d.ActivePackage, d.TargetPackage, d.PreviousPackage = target.Digest(), previous.Digest(), previous.Digest()
			}
			key := installstate.Key{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "Role", Namespace: d.Namespace, Name: "arcadectl-controller"}
			before, err := f.engine.contracts[d.ActivePackage].Template(key, false)
			if err != nil {
				t.Fatal("signed original Role unavailable")
			}
			after, err := f.engine.contracts[d.TargetPackage].Template(key, false)
			if err != nil || after.Hash() == before.Hash() {
				t.Fatal("genuinely distinct signed Role transition unavailable")
			}
			old := testBaselineMetadataLive(t, before, strings.Repeat("b", 32))
			old.SetUID("original-transition-role")
			old.SetResourceVersion("17")
			d.Resources = append(d.Resources, installstate.Resource{Key: key, UID: old.GetUID(), TemplateSHA256: before.Hash(), Phase: before.Phase(), Retained: before.Retained()})
			d.Pending = &installstate.Pending{Action: installstate.Update, Key: key, CreateNonce: strings.Repeat("c", 32), BeforeUID: old.GetUID(), BeforeResourceVersion: "17", BeforeSHA256: before.Hash(), AfterSHA256: after.Hash()}
			for _, state := range []string{"before", "after", "unsigned", "replacement", "after-old-rv"} {
				live, want := old.DeepCopy(), before.Hash()
				if state != "before" {
					live, want = testBaselineMetadataLive(t, after, d.Pending.CreateNonce), after.Hash()
					live.SetUID(old.GetUID())
					live.SetResourceVersion("18")
				}
				switch state {
				case "unsigned":
					testBaselineMetadataUnsigned(live)
				case "replacement":
					live.SetUID("foreign-transition-role")
				case "after-old-rv":
					live.SetResourceVersion("17")
				}
				object, err := f.engine.originalBaselineObject(d, key, live)
				t.Cleanup(object.release)
				positive := state == "before" || state == "after"
				if (err == nil) != positive || positive && (object == nil || object.template.Hash() != want || object.whole.GetUID() != old.GetUID()) {
					t.Fatal("signed metadata transition confused original before/after shape")
				}
			}
		})
	}
}

// Explicit independently specified native Service defaults/allocation, not a
// manufactured API acknowledgement or inference from the production matcher.
func testBaselineMetadataLive(t *testing.T, template *installcontract.Template, nonce string) *unstructured.Unstructured {
	t.Helper()
	object, err := template.Candidate(nonce)
	if err != nil {
		t.Fatal("signed metadata candidate unavailable")
	}
	if template.Key().Kind == "Service" {
		var service corev1.Service
		if decodeServing(object, &service) != nil {
			t.Fatal("signed Service decode unavailable")
		}
		service.Spec.SessionAffinity = corev1.ServiceAffinityNone
		service.Spec.InternalTrafficPolicy = ptr.To(corev1.ServiceInternalTrafficPolicyCluster)
		service.Spec.IPFamilyPolicy = ptr.To(corev1.IPFamilyPolicySingleStack)
		service.Spec.ClusterIP = "10.96.0.42"
		service.Spec.ClusterIPs = []string{"10.96.0.42"}
		service.Spec.IPFamilies = []corev1.IPFamily{corev1.IPv4Protocol}
		object = servingObject(t, &service)
	}
	return object
}

func testBaselineMetadataUnsigned(object *unstructured.Unstructured) {
	switch object.GetKind() {
	case "ServiceAccount":
		object.Object["secrets"] = []any{map[string]any{"name": "foreign-secret"}}
	case "Role":
		object.Object["rules"] = []any{map[string]any{"verbs": []any{"*"}, "apiGroups": []any{"*"}, "resources": []any{"*"}}}
	case "RoleBinding":
		object.Object["subjects"] = []any{map[string]any{"kind": "User", "name": "foreign", "apiGroup": "rbac.authorization.k8s.io"}}
	case "Service":
		_ = unstructured.SetNestedField(object.Object, map[string]any{"foreign": "target"}, "spec", "selector")
	}
}
