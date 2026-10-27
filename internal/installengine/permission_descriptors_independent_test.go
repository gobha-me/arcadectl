// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	authv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func independentResourcePerm(ns, verb, group, version, plural, subresource, name, kind string) proofPermission {
	return proofPermission{
		spec: authv1.SelfSubjectAccessReviewSpec{
			ResourceAttributes: &authv1.ResourceAttributes{
				Namespace:   ns,
				Verb:        verb,
				Group:       group,
				Version:     version,
				Resource:    plural,
				Subresource: subresource,
				Name:        name,
			},
		},
		kind: kind,
	}
}

func independentNonResourcePerm(path, verb, kind string) proofPermission {
	return proofPermission{
		spec: authv1.SelfSubjectAccessReviewSpec{
			NonResourceAttributes: &authv1.NonResourceAttributes{
				Path: path,
				Verb: verb,
			},
		},
		kind: kind,
	}
}

func TestIndependentPermissionDescriptorsRejectMalformedInputs(t *testing.T) {
	validRes := independentResourcePerm("arcadectl-system", "get", "apps", "v1", "deployments", "", "api", "Deployment")
	validNonRes := independentNonResourcePerm("/version", "get", "")

	withFieldSelector := independentResourcePerm("arcadectl-system", "list", "", "v1", "pods", "", "", "Pod")
	withFieldSelector.spec.ResourceAttributes.FieldSelector = &authv1.FieldSelectorAttributes{RawSelector: "metadata.name=pod-0"}

	withEmptyFieldSelector := independentResourcePerm("arcadectl-system", "list", "", "v1", "pods", "", "", "Pod")
	withEmptyFieldSelector.spec.ResourceAttributes.FieldSelector = &authv1.FieldSelectorAttributes{}

	withLabelSelector := independentResourcePerm("arcadectl-system", "list", "", "v1", "pods", "", "", "Pod")
	withLabelSelector.spec.ResourceAttributes.LabelSelector = &authv1.LabelSelectorAttributes{RawSelector: "app=arcade"}

	withEmptyLabelSelector := independentResourcePerm("arcadectl-system", "list", "", "v1", "pods", "", "", "Pod")
	withEmptyLabelSelector.spec.ResourceAttributes.LabelSelector = &authv1.LabelSelectorAttributes{}

	withBothAttrs := proofPermission{
		spec: authv1.SelfSubjectAccessReviewSpec{
			ResourceAttributes:    validRes.spec.ResourceAttributes,
			NonResourceAttributes: validNonRes.spec.NonResourceAttributes,
		},
		kind: "Both",
	}

	malformedCases := []struct {
		name string
		perm proofPermission
	}{
		{"neither-attribute", proofPermission{kind: "Empty"}},
		{"both-attributes", withBothAttrs},
		{"field-selector", withFieldSelector},
		{"empty-field-selector", withEmptyFieldSelector},
		{"label-selector", withLabelSelector},
		{"empty-label-selector", withEmptyLabelSelector},
	}

	for _, tc := range malformedCases {
		t.Run(tc.name, func(t *testing.T) {
			for _, list := range [][]proofPermission{
				{tc.perm},
				{tc.perm, validRes, validNonRes},
				{validRes, tc.perm, validNonRes},
				{validRes, validNonRes, tc.perm},
				{validRes, tc.perm, validRes},
			} {
				got, err := uniqueProofPermissions(list)
				if !errors.Is(err, ErrInvalid) || got != nil {
					t.Fatalf("%s: expected ErrInvalid and nil slice, got len=%d err=%v", tc.name, len(got), err)
				}
			}
		})
	}
}

func TestIndependentPermissionDescriptorsBound255To257AndDuplicates(t *testing.T) {
	makeDistinct := func(n int) []proofPermission {
		out := make([]proofPermission, 0, n)
		for i := range n {
			if i == 0 {
				out = append(out, independentNonResourcePerm("/version", "get", ""))
				continue
			}
			out = append(out, independentResourcePerm(
				"arcadectl-system",
				"get",
				"arcade.gobha.me",
				"v1alpha1",
				fmt.Sprintf("resources-%03d", i),
				"",
				fmt.Sprintf("item-%03d", i),
				"CustomKind",
			))
		}
		return out
	}

	// Unhappy paths first: 257 distinct descriptors must fail with ErrInvalid,
	// both when already unique and when mixed with duplicates.
	over257 := makeDistinct(257)
	if got, err := uniqueProofPermissions(over257); !errors.Is(err, ErrInvalid) || got != nil {
		t.Fatalf("257 distinct specs: got len=%d err=%v, want nil and ErrInvalid", len(got), err)
	}

	over257WithDups := append(slices.Clone(over257[:100]), over257...)
	over257WithDups = append(over257WithDups, over257[200:]...)
	if got, err := uniqueProofPermissions(over257WithDups); !errors.Is(err, ErrInvalid) || got != nil {
		t.Fatalf("257 distinct specs with duplicates: got len=%d err=%v, want nil and ErrInvalid", len(got), err)
	}

	// Boundary happy paths: 0, 255, and 256 distinct descriptors.
	if got, err := uniqueProofPermissions(nil); err != nil || len(got) != 0 {
		t.Fatalf("nil input: got len=%d err=%v, want 0 and nil", len(got), err)
	}
	if got, err := uniqueProofPermissions([]proofPermission{}); err != nil || len(got) != 0 {
		t.Fatalf("empty input: got len=%d err=%v, want 0 and nil", len(got), err)
	}

	for _, count := range []int{255, 256} {
		t.Run(fmt.Sprintf("bound-%d", count), func(t *testing.T) {
			distinct := makeDistinct(count)
			got, err := uniqueProofPermissions(distinct)
			if err != nil || len(got) != count {
				t.Fatalf("%d distinct specs: got len=%d err=%v", count, len(got), err)
			}
			if oracle := jsonProofPermissionOracle(distinct); len(oracle) != count {
				t.Fatalf("%d distinct specs: oracle len=%d", count, len(oracle))
			}

			// Repeating all count descriptors 3x (up to 768 raw elements) must
			// still succeed because the 256 bound applies to unique specs.
			tripled := make([]proofPermission, 0, count*3)
			for round := range 3 {
				for _, item := range distinct {
					dup := item
					dup.kind = fmt.Sprintf("KindRound%d", round)
					tripled = append(tripled, dup)
				}
			}
			gotTripled, err := uniqueProofPermissions(tripled)
			if err != nil || len(gotTripled) != count {
				t.Fatalf("%d distinct specs tripled: got len=%d err=%v", count, len(gotTripled), err)
			}
			for i, item := range gotTripled {
				if item.kind != "KindRound2" {
					t.Fatalf("descriptor %d kept kind %q, want last duplicate kind KindRound2", i, item.kind)
				}
			}
		})
	}
}

func TestIndependentPermissionDescriptorsDistinctSingleFieldAndBoundaryNoMerge(t *testing.T) {
	base := independentResourcePerm("ns1", "get", "apps", "v1", "deployments", "status", "ctrl", "Deployment")
	singleFieldVariants := []proofPermission{
		base,
		independentResourcePerm("ns2", "get", "apps", "v1", "deployments", "status", "ctrl", "Deployment"),
		independentResourcePerm("", "get", "apps", "v1", "deployments", "status", "ctrl", "Deployment"),
		independentResourcePerm("ns1", "list", "apps", "v1", "deployments", "status", "ctrl", "Deployment"),
		independentResourcePerm("ns1", "get", "batch", "v1", "deployments", "status", "ctrl", "Deployment"),
		independentResourcePerm("ns1", "get", "", "v1", "deployments", "status", "ctrl", "Deployment"),
		independentResourcePerm("ns1", "get", "apps", "v2", "deployments", "status", "ctrl", "Deployment"),
		independentResourcePerm("ns1", "get", "apps", "v1", "statefulsets", "status", "ctrl", "Deployment"),
		independentResourcePerm("ns1", "get", "apps", "v1", "deployments", "scale", "ctrl", "Deployment"),
		independentResourcePerm("ns1", "get", "apps", "v1", "deployments", "", "ctrl", "Deployment"),
		independentResourcePerm("ns1", "get", "apps", "v1", "deployments", "status", "api", "Deployment"),
		independentResourcePerm("ns1", "get", "apps", "v1", "deployments", "status", "", "Deployment"),
		// Adjacent-field shift collisions: would collide if keys were concatenated without field boundaries.
		independentResourcePerm("ns", "1get", "apps", "v1", "deployments", "status", "ctrl", "Deployment"),
		independentResourcePerm("ns1", "ge", "tapps", "v1", "deployments", "status", "ctrl", "Deployment"),
		independentResourcePerm("ns1", "get", "app", "sv1", "deployments", "status", "ctrl", "Deployment"),
		independentResourcePerm("ns1", "get", "apps", "v", "1deployments", "status", "ctrl", "Deployment"),
		independentResourcePerm("ns1", "get", "apps", "v1", "deployment", "sstatus", "ctrl", "Deployment"),
		independentResourcePerm("ns1", "get", "apps", "v1", "deployments", "statu", "sctrl", "Deployment"),
		// Non-resource single-field and boundary variants, plus resource vs non-resource with same (namespaceOrPath, verb).
		independentNonResourcePerm("ns1", "get", "DiscoveryA"),
		independentResourcePerm("ns1", "get", "", "", "", "", "", "ResourceLookalike"),
		independentNonResourcePerm("/version", "get", ""),
		independentNonResourcePerm("/version", "post", ""),
		independentNonResourcePerm("/healthz", "get", ""),
		independentNonResourcePerm("/ver", "sionget", ""),
	}

	got, err := uniqueProofPermissions(singleFieldVariants)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	oracle := jsonProofPermissionOracle(singleFieldVariants)
	if len(got) != len(singleFieldVariants) || len(oracle) != len(singleFieldVariants) {
		t.Fatalf("distinct single-field variants merged: got=%d oracle=%d want=%d", len(got), len(oracle), len(singleFieldVariants))
	}
}

func TestIndependentPermissionDescriptorsStableFieldOrderAndLastKindWins(t *testing.T) {
	// Ordered sequence where each adjacent pair is decided by the next key component
	// while later fields are deliberately inverted to prove exact field precedence:
	// 1. resource=false (NonResource) before resource=true (Resource)
	// 2. NonResource: Path, then Verb
	// 3. Resource: Namespace, then Verb, then Group, then Version, then Resource, then Subresource, then Name
	expectedOrder := []proofPermission{
		independentNonResourcePerm("/apis/apps/v1", "get", "NR-1"),
		independentNonResourcePerm("/apis/apps/v1", "post", "NR-2"),
		independentNonResourcePerm("/zzz", "get", "NR-3"),
		independentResourcePerm("", "watch", "zzz", "v9", "zzz", "zzz", "zzz", "R-cluster"),
		independentResourcePerm("alpha", "create", "zzz", "v9", "zzz", "zzz", "zzz", "R-ns-verb-1"),
		independentResourcePerm("alpha", "get", "apps", "v2", "zzz", "zzz", "zzz", "R-group-1"),
		independentResourcePerm("alpha", "get", "batch", "v1", "zzz", "zzz", "zzz", "R-group-2"),
		independentResourcePerm("alpha", "get", "batch", "v2", "deployments", "status", "zzz", "R-version-2"),
		independentResourcePerm("alpha", "get", "batch", "v2", "pods", "", "zzz", "R-plural-2"),
		independentResourcePerm("alpha", "get", "batch", "v2", "pods", "exec", "zzz", "R-subresource-1"),
		independentResourcePerm("alpha", "get", "batch", "v2", "pods", "status", "aaa", "R-subresource-2"),
		independentResourcePerm("alpha", "get", "batch", "v2", "pods", "status", "bbb", "R-name-2"),
		independentResourcePerm("beta", "create", "", "v1", "aaa", "", "aaa", "R-ns-beta"),
	}

	// Build scrambled input with earlier duplicates having stale kinds so we
	// simultaneously verify field-order sorting, stability (last-identical-spec
	// supplies its kind), and caller slice immutability.
	var input []proofPermission
	for i := len(expectedOrder) - 1; i >= 0; i-- {
		first := expectedOrder[i]
		first.kind = fmt.Sprintf("StaleFirst-%d", i)
		middle := expectedOrder[i]
		middle.kind = fmt.Sprintf("StaleMiddle-%d", i)
		input = append(input, first, middle, expectedOrder[i])
	}
	callerCopy := slices.Clone(input)

	got, err := uniqueProofPermissions(input)
	if err != nil {
		t.Fatalf("uniqueProofPermissions failed: %v", err)
	}
	if !reflect.DeepEqual(input, callerCopy) {
		t.Fatal("uniqueProofPermissions mutated the caller's input slice")
	}
	if !reflect.DeepEqual(got, expectedOrder) {
		t.Fatalf("field order or last-kind mismatch:\ngot:  %#v\nwant: %#v", got, expectedOrder)
	}
	tail := got[:cap(got)][len(got):]
	if len(tail) == 0 {
		t.Fatal("deduplicated slice had no spare capacity from collapsed duplicates")
	}
	for i, cleared := range tail {
		if cleared != (proofPermission{}) {
			t.Fatalf("tail element %d past deduplicated length was not cleared: %#v", i, cleared)
		}
	}

	// Verify agreement with the independent JSON oracle on the deduplicated
	// descriptor set (including the winning kind for every spec).
	oracle := jsonProofPermissionOracle(input)
	if len(oracle) != len(got) {
		t.Fatalf("oracle length %d != got length %d", len(oracle), len(got))
	}
	bySpec := func(perms []proofPermission) map[string]string {
		m := make(map[string]string, len(perms))
		for _, p := range perms {
			b, err := json.Marshal(p.spec)
			if err != nil {
				t.Fatal(err)
			}
			m[string(b)] = p.kind
		}
		return m
	}
	if !reflect.DeepEqual(bySpec(got), bySpec(oracle)) {
		t.Fatalf("winning discovery kinds differ from JSON oracle:\ngot:    %v\noracle: %v", bySpec(got), bySpec(oracle))
	}
}

func TestIndependentAdmissionWitnessTransferNoAliasingOrMutationLeak(t *testing.T) {
	f := newActorFixture(t)
	ctx := t.Context()

	// Unhappy path first: an unhealthy policy in the live store must make
	// configured fail with ErrAdmission before any witness is returned.
	var firstPolicyKey installstate.Key
	for key := range f.v.f.access.objects {
		if key.Kind == "ValidatingAdmissionPolicy" && (firstPolicyKey == (installstate.Key{}) || key.Name < firstPolicyKey.Name) {
			firstPolicyKey = key
		}
	}
	if firstPolicyKey == (installstate.Key{}) {
		t.Fatal("no ValidatingAdmissionPolicy found in fixture")
	}
	savedLivePolicy := f.v.f.access.objects[firstPolicyKey].DeepCopy()
	f.v.f.access.objects[firstPolicyKey].SetUID("00000000-0000-4000-8000-000000000999")
	if witness, err := f.admission.configured(ctx, f.request); !errors.Is(err, ErrAdmission) || witness != nil {
		t.Fatalf("corrupted live policy UID was accepted: witness=%v err=%v", witness, err)
	}
	f.v.f.access.objects[firstPolicyKey] = savedLivePolicy

	first, err := f.admission.configured(ctx, f.request)
	if err != nil || first == nil || len(first.policies) != 6 || len(first.bindings) != 6 || len(first.objects) != 12 {
		t.Fatalf("first configured witness failed: %v", err)
	}
	second, err := f.admission.configured(ctx, f.request)
	if err != nil || second == nil || !sameAdmissionConfiguration(first, second) {
		t.Fatalf("second configured witness failed or differed: %v", err)
	}

	snapshotSecondPolicies := make(map[string]*admissionv1.ValidatingAdmissionPolicy, len(second.policies))
	for name, policy := range second.policies {
		if first.policies[name] == policy {
			t.Fatalf("policy %q pointer aliased across witnesses", name)
		}
		snapshotSecondPolicies[name] = policy.DeepCopy()
	}
	snapshotSecondBindings := make(map[string]*admissionv1.ValidatingAdmissionPolicyBinding, len(second.bindings))
	for name, binding := range second.bindings {
		if first.bindings[name] == binding {
			t.Fatalf("binding %q pointer aliased across witnesses", name)
		}
		snapshotSecondBindings[name] = binding.DeepCopy()
	}

	// Mutate every transferred policy and binding inside the first witness in place.
	for name, policy := range first.policies {
		policy.Name = "mutated-" + name
		policy.UID = "mutated-uid"
		policy.ResourceVersion = "mutated-rv"
		policy.Generation = 999
		policy.Status.ObservedGeneration = 0
		if len(policy.Spec.Validations) > 0 {
			policy.Spec.Validations[0].Expression = "false"
			policy.Spec.Validations[0].Message = "mutated-message"
		}
		if len(policy.Status.Conditions) > 0 {
			policy.Status.Conditions[0].Status = metav1.ConditionFalse
		}
		if policy.Status.TypeChecking != nil {
			policy.Status.TypeChecking.ExpressionWarnings = []admissionv1.ExpressionWarning{{FieldRef: "spec", Warning: "mutated"}}
		}
		if healthyAdmissionPolicy(policy) {
			t.Fatalf("mutated policy %q in first witness unexpectedly remained healthy", name)
		}
	}
	for name, binding := range first.bindings {
		binding.Name = "mutated-" + name
		binding.UID = "mutated-binding-uid"
		binding.Spec.PolicyName = "mutated-policy-ref"
		if len(binding.Spec.ValidationActions) > 0 {
			binding.Spec.ValidationActions[0] = admissionv1.Audit
		}
	}

	// Second witness must be completely unaffected by mutating the first witness.
	for name, policy := range second.policies {
		if !healthyAdmissionPolicy(policy) || !reflect.DeepEqual(policy, snapshotSecondPolicies[name]) {
			t.Fatalf("mutating first witness leaked into second witness policy %q", name)
		}
	}
	for name, binding := range second.bindings {
		if !reflect.DeepEqual(binding, snapshotSecondBindings[name]) {
			t.Fatalf("mutating first witness leaked into second witness binding %q", name)
		}
	}

	// A third configured call must still succeed and match the unmutated second witness,
	// proving no template memo or live object was corrupted when DeepCopy was dropped.
	third, err := f.admission.configured(ctx, f.request)
	if err != nil || !sameAdmissionConfiguration(second, third) {
		t.Fatalf("third configured witness failed after mutating first witness: %v", err)
	}
	for name, policy := range third.policies {
		if policy == first.policies[name] || policy == second.policies[name] || !reflect.DeepEqual(policy, snapshotSecondPolicies[name]) {
			t.Fatalf("third witness policy %q aliased or differed from clean snapshot", name)
		}
	}
	for name, binding := range third.bindings {
		if binding == first.bindings[name] || binding == second.bindings[name] || !reflect.DeepEqual(binding, snapshotSecondBindings[name]) {
			t.Fatalf("third witness binding %q aliased or differed from clean snapshot", name)
		}
	}

	configuredReq := f.request
	configuredReq.Checkpoint = AdmissionConfigured
	if err := f.admission.VerifyConfigured(ctx, configuredReq); err != nil {
		t.Fatalf("VerifyConfigured failed after witness mutation: %v", err)
	}
}

func TestIndependentDocumentPermissionsAndPredecessorBehavioralContract(t *testing.T) {
	previous, target := lifecycleTransitionPlans(t)

	t.Run("predecessor-zero-alloc-and-relations", func(t *testing.T) {
		if predecessor(previous, target) || predecessor(previous, previous) || predecessor(target, target) {
			t.Fatal("undeclared predecessor relationship accepted")
		}
		if !predecessor(target, previous) {
			t.Fatal("genuine signed predecessor relationship rejected")
		}
		if allocs := testing.AllocsPerRun(50, func() {
			if !predecessor(target, previous) {
				t.Fatal("expected predecessor match")
			}
		}); allocs != 0 {
			t.Fatalf("predecessor(target, previous) allocated %v times per call, want 0", allocs)
		}
	})

	t.Run("document-permissions-field-order", func(t *testing.T) {
		f := newFixtureWithPlans(t, false, previous, target)
		proof := &ClusterPrerequisites{engine: f.engine}

		// Unhappy path: documentPermissions refuses an incompatible transition.
		badDoc := permissionInventory(t, f, previous)
		if perms, err := proof.documentPermissions(badDoc, installstate.Upgrade, previous); !errors.Is(err, ErrInvalid) || perms != nil {
			t.Fatalf("incompatible Upgrade to self was accepted: len=%d err=%v", len(perms), err)
		}

		doc := permissionInventory(t, f, previous)
		perms, err := proof.documentPermissions(doc, installstate.Upgrade, target)
		if err != nil || len(perms) == 0 || len(perms) > 256 {
			t.Fatalf("documentPermissions(Upgrade) failed: len=%d err=%v", len(perms), err)
		}

		// Verify that documentPermissions outputs descriptors in strict field-tuple order:
		// 1. All NonResourceAttributes come before all ResourceAttributes.
		// 2. Within ResourceAttributes, cluster-scoped entries (Namespace == "") precede
		//    namespaced entries (Namespace == installrender.DefaultNamespace), and empty
		//    Subresource precedes non-empty Subresource.
		tupleOf := func(p proofPermission) [8]string {
			if a := p.spec.ResourceAttributes; a != nil {
				return [8]string{"1", a.Namespace, a.Verb, a.Group, a.Version, a.Resource, a.Subresource, a.Name}
			}
			n := p.spec.NonResourceAttributes
			return [8]string{"0", n.Path, n.Verb}
		}
		sawResource := false
		sawNamespacedResource := false
		for i, p := range perms {
			if p.spec.ResourceAttributes != nil {
				sawResource = true
				if p.spec.ResourceAttributes.Namespace == installrender.DefaultNamespace {
					sawNamespacedResource = true
				} else if p.spec.ResourceAttributes.Namespace == "" && sawNamespacedResource {
					t.Fatalf("cluster-scoped ResourceAttributes at index %d appeared after a namespaced ResourceAttributes entry (JSON-order leak)", i)
				}
			} else if sawResource {
				t.Fatalf("NonResourceAttributes at index %d appeared after ResourceAttributes", i)
			}
			if i > 0 {
				prevTuple, curTuple := tupleOf(perms[i-1]), tupleOf(p)
				cmp := 0
				for k := range prevTuple {
					if c := strings.Compare(prevTuple[k], curTuple[k]); c != 0 {
						cmp = c
						break
					}
				}
				if cmp >= 0 {
					t.Fatalf("descriptors at %d and %d not in strict tuple field order: %v >= %v", i-1, i, prevTuple, curTuple)
				}
			}
		}
		if !sawResource || !sawNamespacedResource {
			t.Fatal("recipe did not exercise both cluster-scoped and namespaced ResourceAttributes")
		}
	})
}
