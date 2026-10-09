// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installcontract

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installbaseline"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func fixtureBaselineContract(t *testing.T) (*Contract, *installbaseline.Plan) {
	t.Helper()
	manifest, payload, err := installbaseline.Build(strings.Repeat("a", 40), 1)
	if err != nil {
		t.Fatal("baseline contract fixture build failed")
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x61}, ed25519.SeedSize))
	signature, err := installbaseline.Sign(manifest, key)
	if err != nil {
		t.Fatal("baseline contract fixture signing failed")
	}
	verified, err := installbaseline.Verify(manifest, signature, payload, key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal("baseline contract fixture authentication failed")
	}
	plan, err := installbaseline.Compile(verified, "isolated-baseline", "kubernetes-1.37.0")
	if err != nil {
		t.Fatal("baseline contract fixture compilation failed")
	}
	contract, err := NewBaseline(plan)
	if err != nil {
		t.Fatal("sealed baseline contract construction failed")
	}
	return contract, plan
}

func TestBaselineContractMatchesOnlyReviewedTemplateAndOriginalIdentity(t *testing.T) {
	contract, plan := fixtureBaselineContract(t)
	for _, resource := range plan.Resources() {
		object := resource.Object
		key := installstate.Key{APIVersion: object.GetAPIVersion(), Kind: object.GetKind(), Namespace: object.GetNamespace(), Name: object.GetName()}
		template, err := contract.Template(key, false)
		if err != nil || template.Hash() != resource.TemplateSHA256 || !template.Retained() || template.Phase() != installrender.Policies {
			t.Fatal("baseline contract changed independent template identity")
		}
		if _, err := contract.Template(key, true); err != ErrInvalid {
			t.Fatal("baseline template offered a paused/rollback variant")
		}
		candidate, err := template.Candidate(strings.Repeat("b", 32))
		if err != nil || template.MatchAdmitted(candidate) != nil {
			t.Fatal("reviewed baseline candidate does not match its contract")
		}
		if err := template.MatchLive(candidate, "owned-original"); err != ErrIdentity {
			t.Fatal("admitted candidate became original ownership proof")
		}
		live := candidate.DeepCopy()
		live.SetUID("owned-original")
		live.SetResourceVersion("10")
		if err := template.MatchLive(live, "owned-original"); err != nil {
			t.Fatal("original baseline shape and identity were refused")
		}
		if err := template.MatchLive(live, "replacement"); err != ErrIdentity {
			t.Fatal("baseline same-name replacement was accepted")
		}
		if _, err := template.UpdateCandidate(template, live, live.GetUID(), strings.Repeat("c", 32)); err != ErrDrift {
			t.Fatal("non-rollback baseline offered a runtime update candidate")
		}
		if _, err := template.PodTemplate(); err != ErrInvalid {
			t.Fatal("baseline offered an executable Pod template")
		}
		for _, mutate := range []func(*unstructured.Unstructured){
			func(o *unstructured.Unstructured) {
				o.SetLabels(map[string]string{"app.kubernetes.io/part-of": "foreign"})
			},
			func(o *unstructured.Unstructured) { o.SetAnnotations(map[string]string{"unreviewed": "must-not-echo"}) },
			func(o *unstructured.Unstructured) {
				_ = unstructured.SetNestedField(o.Object, "must-not-echo", "spec", "unknown")
			},
			func(o *unstructured.Unstructured) { o.SetName("same-looking-substitution") },
		} {
			changed := live.DeepCopy()
			mutate(changed)
			if err := template.MatchLive(changed, live.GetUID()); err == nil || strings.Contains(err.Error(), "must-not-echo") {
				t.Fatal("baseline drift was accepted or reflected into diagnostics")
			}
		}
		if key.Kind == "ValidatingAdmissionPolicy" {
			ignored := live.DeepCopy()
			if unstructured.SetNestedField(ignored.Object, "Ignore", "spec", "failurePolicy") != nil {
				t.Fatal("weakening fixture construction failed")
			}
			if err := template.MatchLive(ignored, live.GetUID()); err != ErrDrift {
				t.Fatal("known-field fail-open policy weakening was accepted")
			}
			weakened := live.DeepCopy()
			if unstructured.SetNestedSlice(weakened.Object, []any{map[string]any{"expression": "true", "message": installbaseline.DenialMessage}}, "spec", "validations") != nil {
				t.Fatal("weakening fixture construction failed")
			}
			if err := template.MatchLive(weakened, live.GetUID()); err != ErrDrift {
				t.Fatal("known-field allow-all validation was accepted")
			}
		} else {
			warn := live.DeepCopy()
			if unstructured.SetNestedStringSlice(warn.Object, []string{"Warn"}, "spec", "validationActions") != nil {
				t.Fatal("binding action fixture construction failed")
			}
			if err := template.MatchLive(warn, live.GetUID()); err != ErrDrift {
				t.Fatal("known-field non-enforcing binding was accepted")
			}
			escaped := live.DeepCopy()
			if unstructured.SetNestedStringMap(escaped.Object, map[string]string{"kubernetes.io/metadata.name": "foreign-namespace"}, "spec", "matchResources", "namespaceSelector", "matchLabels") != nil {
				t.Fatal("binding scope fixture construction failed")
			}
			if err := template.MatchLive(escaped, live.GetUID()); err != ErrDrift {
				t.Fatal("known-field binding scope substitution was accepted")
			}
		}
	}
}

func TestBaselineContractRejectsUntrustedPlansAndRuntimeKeys(t *testing.T) {
	for _, zero := range []*installbaseline.Plan{nil, {}} {
		if _, err := NewBaseline(zero); err != ErrInvalid {
			t.Fatal("unverified baseline became a live matching contract")
		}
	}
	contract, _ := fixtureBaselineContract(t)
	for _, key := range []installstate.Key{
		{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "isolated-baseline", Name: "arcadectl-controller"},
		{APIVersion: "admissionregistration.k8s.io/v1", Kind: "ValidatingAdmissionPolicy", Name: "arcadectl-destroy-worker-gate-isolated-baseline"},
	} {
		if _, err := contract.Template(key, false); err != ErrInvalid {
			t.Fatal("security matching contract adopted runtime inventory")
		}
	}
}
