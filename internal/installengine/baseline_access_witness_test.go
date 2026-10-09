// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestBaselineAccessWitnessMissingOriginalRBACCannotUseAmbientAuthority(t *testing.T) {
	plan := fixturePlan(t)
	for _, metadata := range plan.ResourceMetadata() {
		key := installstate.Key{APIVersion: metadata.APIVersion, Kind: metadata.Kind, Namespace: metadata.Namespace, Name: metadata.Name}
		if !bootstrapRBACKey(key) {
			continue
		}
		t.Run(key.Kind+"/"+key.Name, func(t *testing.T) {
			f := seedBaselineAccessWitness(t)
			d := f.snapshot.Document()
			index := slices.IndexFunc(d.Resources, func(resource installstate.Resource) bool { return resource.Key == key })
			if index < 0 {
				t.Fatal("unit original access dependency absent")
			}
			d.Resources = slices.Delete(d.Resources, index, index+1)
			d.Revision++
			seedBaselineAccessUnitDocument(t, f, d)
			delete(f.access.objects, key)
			if _, err := f.engine.baseline.runtimeAccessWitness(t.Context(), f.snapshot); err != ErrSecurityBaseline {
				t.Fatal("missing original RBAC became actor authority")
			}
		})
	}
}

// Synthetic original objects test the read-only acceptance boundary, NOT
// native admission or effect ownership. No permissive runtime guard is wired.
func seedBaselineAccessWitness(t *testing.T) *fixture {
	return seedBaselineAccessWitnessWithPlans(t, fixturePlan(t))
}

func seedBaselineAccessWitnessWithPlans(t *testing.T, plans ...*installrender.Plan) *fixture {
	t.Helper()
	f := newBaselineFixtureWithPlans(t, plans...)
	completeBaselineFixture(t, f)
	d := f.snapshot.Document()
	for i, resource := range f.plan.ResourceMetadata() {
		key := installstate.Key{APIVersion: resource.APIVersion, Kind: resource.Kind, Namespace: resource.Namespace, Name: resource.Name}
		if !accessRetirementKey(key) {
			continue
		}
		template, err := f.engine.contracts[f.plan.Digest()].Template(key, false)
		if err != nil {
			t.Fatal("signed unit access template unavailable")
		}
		object, err := template.Candidate(strings.Repeat("b", 32))
		if err != nil {
			t.Fatal("signed unit access candidate unavailable")
		}
		object.SetUID(types.UID("unit-access-" + strconv.Itoa(i)))
		object.SetResourceVersion(strconv.Itoa(1000 + i))
		f.access.objects[key] = object
		d.Resources = append(d.Resources, installstate.Resource{Key: key, UID: object.GetUID(), TemplateSHA256: template.Hash(), Retained: template.Retained(), Phase: template.Phase()})
	}
	installstate.SortResources(d.Resources)
	d.Revision++
	seedBaselineAccessUnitDocument(t, f, d)
	return f
}

// These fixtures seed synthetic existing state, not a series of acknowledged
// CREATE effects. Keep production Commit transition checks intact: they must
// refuse bulk inventory changes without one durable intent per effect.
func seedBaselineAccessUnitDocument(t *testing.T, f *fixture, d installstate.Document) {
	t.Helper()
	plans := []*installrender.Plan{f.plan}
	for digest, plan := range f.engine.plans {
		if digest != f.plan.Digest() {
			plans = append(plans, plan)
		}
	}
	body, err := installstate.EncodeWithBaseline(d, f.engine.baselinePlan(), plans...)
	if err != nil {
		t.Fatal("unit access journal encoding refused")
	}
	ns, err := f.access.client.CoreV1().Namespaces().Get(t.Context(), f.plan.Namespace(), metav1.GetOptions{})
	if err != nil {
		t.Fatal("unit original namespace unavailable")
	}
	ns.Annotations[installstate.Annotation] = string(body)
	rv, _ := strconv.Atoi(ns.ResourceVersion)
	ns.ResourceVersion = strconv.Itoa(rv + 1)
	if f.access.client.Tracker().Update(corev1.SchemeGroupVersion.WithResource("namespaces"), ns, "") != nil {
		t.Fatal("unit access journal seed refused")
	}
	f.snapshot, err = f.store.Load(t.Context(), f.snapshot.Anchor())
	if err != nil {
		t.Fatal("unit sealed access journal observation refused")
	}
}

func TestBaselineAccessWitnessMixedPackagePendingRoleUpdate(t *testing.T) {
	previous, target := lifecycleTransitionPlans(t)
	for _, mode := range []string{"before", "after", "replacement", "unsigned-rules"} {
		t.Run(mode, func(t *testing.T) {
			f := seedBaselineAccessWitnessWithPlans(t, previous, target)
			d := f.snapshot.Document()
			key := installstate.Key{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "Role", Namespace: previous.Namespace(), Name: "arcadectl-controller"}
			entry, before := f.engine.inventory(d, key)
			after, err := f.engine.contracts[target.Digest()].Template(key, false)
			if err != nil || entry == nil || before == nil || before.Hash() == after.Hash() {
				t.Fatal("genuinely distinct signed predecessor/current Role templates unavailable")
			}
			original := f.access.objects[key]
			d.Mode, d.ActivePackage, d.TargetPackage, d.Installed = installstate.Upgrade, previous.Digest(), target.Digest(), true
			d.Pending = &installstate.Pending{Action: installstate.Update, Key: key, CreateNonce: strings.Repeat("c", 32), BeforeUID: original.GetUID(), BeforeResourceVersion: original.GetResourceVersion(), BeforeSHA256: before.Hash(), AfterSHA256: after.Hash()}
			d.Revision++
			seedBaselineAccessUnitDocument(t, f, d)
			if mode != "before" {
				live, err := after.Candidate(d.Pending.CreateNonce)
				if err != nil {
					t.Fatal("signed pending after template unavailable")
				}
				live.SetUID(original.GetUID())
				live.SetResourceVersion("3000")
				if mode == "replacement" {
					live.SetUID("foreign-same-name")
				}
				if mode == "unsigned-rules" {
					live.Object["rules"] = []any{map[string]any{"apiGroups": []any{"*"}, "resources": []any{"*"}, "verbs": []any{"*"}}}
				}
				f.access.objects[key] = live
			}
			witness, err := f.engine.baseline.runtimeAccessWitness(t.Context(), f.snapshot)
			if (err == nil) != (mode == "before" || mode == "after") {
				t.Fatal("mixed-package pending authority refused a signed original or accepted replacement/unsigned rules")
			}
			if err == nil {
				expected := before.Hash()
				if mode == "after" {
					expected = after.Hash()
				}
				if witness[key].TemplateSHA256 != expected || witness[key].UID != entry.UID {
					t.Fatal("pending access witness substituted prospective or foreign authority")
				}
			}
		})
	}
}

func TestBaselineRuntimeAccessWitnessRequiresCompleteOriginalSignedAccess(t *testing.T) {
	for _, mode := range []string{"complete", "missing", "replacement", "drift", "fixture-fence", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			f := seedBaselineAccessWitness(t)
			beforeWrites, beforeUpdates := f.access.writes, f.nsUpdates
			switch mode {
			case "missing":
				delete(f.access.objects, f.key)
			case "replacement":
				f.access.objects[f.key].SetUID("foreign-same-name")
			case "drift":
				f.access.objects[f.key].SetAnnotations(map[string]string{"foreign": "authority"})
			case "fixture-fence":
				if _, err := f.engine.files.CreateExclusive(fixtureLedgerName(f.snapshot), []byte("unresolved evidence")); err != nil {
					t.Fatal("unit fence unavailable")
				}
			}
			ctx := t.Context()
			if mode == "cancelled" {
				var cancel func()
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			witness, err := f.engine.baseline.runtimeAccessWitness(ctx, f.snapshot)
			if (err == nil) != (mode == "complete") || mode == "complete" && len(witness) < 4 {
				t.Fatal("access witness accepted incomplete/foreign evidence or refused complete signed originals")
			}
			if beforeWrites != f.access.writes || beforeUpdates != f.nsUpdates {
				t.Fatal("access witness mutated effects or journal")
			}
		})
	}
}

func TestBaselineAccessPendingUpdateOnlySealedBeforeOrAfter(t *testing.T) {
	for _, mode := range []string{"before", "after", "replacement", "before-rv-drift", "copied-after-before-rv", "wrong-nonce", "wrong-before-hash", "wrong-after-hash", "wrong-before-uid", "delete", "create", "wrong-stage"} {
		t.Run(mode, func(t *testing.T) {
			f := seedBaselineAccessWitness(t)
			d := f.snapshot.Document()
			entry, template := f.engine.inventory(d, f.key)
			before := f.access.objects[f.key].DeepCopy()
			d.Pending = &installstate.Pending{Action: installstate.Update, Key: f.key, CreateNonce: strings.Repeat("c", 32), BeforeUID: entry.UID, BeforeResourceVersion: before.GetResourceVersion(), BeforeSHA256: template.Hash(), AfterSHA256: template.Hash()}
			live := before.DeepCopy()
			if mode == "after" || mode == "replacement" || mode == "copied-after-before-rv" || mode == "wrong-nonce" {
				live.SetAnnotations(map[string]string{installstate.MutationAnnotation: d.Pending.CreateNonce})
				live.SetResourceVersion("2000")
			}
			switch mode {
			case "replacement":
				live.SetUID("foreign-same-name")
			case "before-rv-drift":
				live.SetResourceVersion("2000")
			case "copied-after-before-rv":
				live.SetResourceVersion(before.GetResourceVersion())
			case "wrong-nonce":
				live.SetAnnotations(map[string]string{installstate.MutationAnnotation: strings.Repeat("d", 32)})
			case "wrong-before-hash":
				d.Pending.BeforeSHA256 = strings.Repeat("0", 64)
			case "wrong-after-hash":
				d.Pending.AfterSHA256 = strings.Repeat("0", 64)
			case "wrong-before-uid":
				d.Pending.BeforeUID = "foreign"
			case "delete":
				d.Pending.Action = installstate.Delete
			case "create":
				d.Pending.Action = installstate.Create
			case "wrong-stage":
				d.Stage = installstate.Quiescing
			}
			accepted, err := f.engine.baselineAccessTemplate(d, entry, template, live)
			if (err == nil) != (mode == "before" || mode == "after") || err == nil && accepted.Hash() != template.Hash() {
				t.Fatal("pending access accepted a third shape, unknown original or unauthorized action")
			}
		})
	}
}
