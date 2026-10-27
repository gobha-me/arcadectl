// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installstate"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	authv1 "k8s.io/api/authorization/v1"
)

func jsonProofPermissionOracle(input []proofPermission) []proofPermission {
	unique := map[string]proofPermission{}
	for _, permission := range input {
		body, _ := json.Marshal(permission.spec)
		unique[string(body)] = permission
	}
	keys := make([]string, 0, len(unique))
	for key := range unique {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	result := make([]proofPermission, 0, len(keys))
	for _, key := range keys {
		result = append(result, unique[key])
	}
	return result
}

func jsonProofPermissionSet(input []proofPermission) map[string]string {
	result := map[string]string{}
	for _, permission := range input {
		body, _ := json.Marshal(permission.spec)
		result[string(body)] = permission.kind
	}
	return result
}

func TestProofPermissionDescriptorsPreserveExactSpecs(t *testing.T) {
	// Keep the compact key exhaustive if the Kubernetes permission spec grows.
	for value, fields := range map[reflect.Type]int{
		reflect.TypeFor[authv1.SelfSubjectAccessReviewSpec](): 2,
		reflect.TypeFor[authv1.ResourceAttributes]():          9,
		reflect.TypeFor[authv1.NonResourceAttributes]():       2,
	} {
		if value.NumField() != fields {
			t.Fatal("native permission shape changed; review descriptor key completeness")
		}
	}
	// Vary every selector-free native field independently. Deduplication must
	// include each one, while the discovery kind keeps its last-spec behavior.
	var input []proofPermission
	base := authv1.ResourceAttributes{Namespace: "games", Verb: "get", Group: "apps", Version: "v1", Resource: "deployments", Subresource: "status", Name: "controller"}
	for _, field := range []string{"Namespace", "Verb", "Group", "Version", "Resource", "Subresource", "Name"} {
		a := base
		reflect.ValueOf(&a).Elem().FieldByName(field).SetString("different")
		input = append(input, proofPermission{spec: authv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &a}, kind: field})
	}
	input = append(input,
		proofPermission{spec: authv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &base}, kind: "first"},
		proofPermission{spec: authv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &base}, kind: "last"})
	for _, a := range []authv1.NonResourceAttributes{{Path: "/version", Verb: "get"}, {Path: "/api/v1", Verb: "get"}, {Path: "/version", Verb: "different"}} {
		input = append(input, proofPermission{spec: authv1.SelfSubjectAccessReviewSpec{NonResourceAttributes: &a}})
	}
	before, _ := json.Marshal(input)
	got, err := uniqueProofPermissions(input)
	if err != nil || len(got) != 11 || !reflect.DeepEqual(jsonProofPermissionSet(got), jsonProofPermissionSet(jsonProofPermissionOracle(input))) {
		t.Fatal("value keys omitted, combined or altered a native permission")
	}
	// No duplicate specs here: permutations must produce the same field order.
	shuffled := slices.Clone(got)
	slices.Reverse(shuffled)
	again, err := uniqueProofPermissions(shuffled)
	if err != nil || !reflect.DeepEqual(got, again) {
		t.Fatal("permission order depends on map iteration or construction order")
	}
	after, _ := json.Marshal(input)
	if string(before) != string(after) {
		t.Fatal("deduplication mutated descriptor inputs")
	}
}

func TestProofPermissionDescriptorsRejectSelectorsAndKeepBound(t *testing.T) {
	for _, spec := range []authv1.SelfSubjectAccessReviewSpec{
		{},
		{ResourceAttributes: &authv1.ResourceAttributes{}, NonResourceAttributes: &authv1.NonResourceAttributes{}},
		{ResourceAttributes: &authv1.ResourceAttributes{FieldSelector: &authv1.FieldSelectorAttributes{RawSelector: "metadata.name=foreign"}}},
		{ResourceAttributes: &authv1.ResourceAttributes{LabelSelector: &authv1.LabelSelectorAttributes{RawSelector: "foreign=true"}}},
	} {
		if got, err := uniqueProofPermissions([]proofPermission{{spec: spec}}); err != ErrInvalid || got != nil {
			t.Fatal("non-recipe spec reached selector-free value keys")
		}
	}
	var input []proofPermission
	for i := range 257 {
		input = append(input, proofPermission{spec: authv1.SelfSubjectAccessReviewSpec{NonResourceAttributes: &authv1.NonResourceAttributes{Path: fmt.Sprintf("/finite/%d", i), Verb: "get"}}})
	}
	if _, err := uniqueProofPermissions(input[:256]); err != nil {
		t.Fatal("exact descriptor bound refused")
	}
	if got, err := uniqueProofPermissions(input); err != ErrInvalid || got != nil {
		t.Fatal("descriptor bound widened")
	}
	if got, err := uniqueProofPermissions(append(input[:256:256], input[0])); err != nil || len(got) != 256 {
		t.Fatal("bound applied before deduplication")
	}
}

func TestAdmissionPermissionDescriptorAllocationProfile(t *testing.T) {
	previous, target := lifecycleTransitionPlans(t)
	f := newFixtureWithPlans(t, false, previous, target)
	p := &ClusterPrerequisites{engine: f.engine}
	for _, mode := range []installstate.Mode{installstate.Upgrade, installstate.Rollback, installstate.Uninstall} {
		t.Run(string(mode), func(t *testing.T) {
			active, next := previous, target
			if mode == installstate.Rollback {
				active, next = target, previous
			} else if mode == installstate.Uninstall {
				next = previous
			}
			d := permissionInventory(t, f, active)
			d.PreviousPackage = previous.Digest()
			permissions, err := p.documentPermissions(d, mode, next)
			if err != nil {
				t.Fatal("transition recipe refused", err)
			}
			assertPermissionBoundary(t, d.Namespace, permissions)
			// Include duplicate recipes as produced by shared collection CREATEs.
			input := append(slices.Clone(permissions), permissions...)
			want := jsonProofPermissionSet(jsonProofPermissionOracle(input))
			got, err := uniqueProofPermissions(input)
			if err != nil || !reflect.DeepEqual(jsonProofPermissionSet(got), want) {
				t.Fatal("transition descriptor set differs from frozen JSON recipe")
			}
			old := testing.AllocsPerRun(20, func() { jsonProofPermissionOracle(input) })
			current := testing.AllocsPerRun(20, func() {
				if _, err := uniqueProofPermissions(input); err != nil {
					t.Fatal("descriptor recipe refused")
				}
			})
			if current >= old {
				t.Fatal("descriptor representation did not reduce allocations")
			}
			t.Logf("permission dedup allocations: JSON=%.0f values=%.0f specs=%d", old, current, len(permissions))
		})
	}
}

func TestAdmissionConfigurationOwnsMatchedPoliciesAndBindings(t *testing.T) {
	h := fixturePhaseFactory(t)(t)
	a, request := h.f.actor.admission, h.f.actor.request
	first, err := a.configured(t.Context(), request)
	if err != nil {
		t.Fatal("original configuration unavailable")
	}
	before, err := json.Marshal([]any{first.policies, first.bindings})
	if err != nil {
		t.Fatal("configuration control encoding unavailable")
	}
	for _, policy := range first.policies {
		if len(policy.Spec.Validations) == 0 || policy.Status.TypeChecking == nil {
			t.Fatal("complete healthy policy fixture unavailable")
		}
		policy.Spec.Validations[0].Expression = "false"
		policy.Status.TypeChecking.ExpressionWarnings = append(policy.Status.TypeChecking.ExpressionWarnings, admissionv1.ExpressionWarning{FieldRef: "spec.validations[0].expression", Warning: "changed"})
		policy.SetResourceVersion("foreign")
	}
	for _, binding := range first.bindings {
		binding.Spec.PolicyName = "foreign"
		if len(binding.Spec.ValidationActions) == 0 {
			t.Fatal("binding action control unavailable")
		}
		binding.Spec.ValidationActions[0] = admissionv1.Audit
	}
	second, err := a.configured(t.Context(), request)
	if err != nil {
		t.Fatal("caller mutation escaped into a subsequent fresh match")
	}
	after, err := json.Marshal([]any{second.policies, second.bindings})
	if err != nil || string(before) != string(after) || !reflect.DeepEqual(first.objects, second.objects) {
		t.Fatal("request-owned result aliased templates, decoder memo or live observations")
	}
	// Adversarial #100 extension seam: testAdmissionCaseProtocolFixture exposes
	// onExact/onProbe for late mutations around real runCaseLocked boundaries.
	// Keep native all-55 broken-fixture proof in the Atlas-gated Kind batch.
}

// Measures only local descriptor representation, not authorization or a matrix.
func BenchmarkProofPermissionDescriptorDedup(b *testing.B) {
	var input []proofPermission
	for _, collection := range proofCollections {
		for _, verb := range []string{"get", "list", "create"} {
			namespace, name := "", ""
			if collection.namespaced {
				namespace = "games"
			}
			if verb == "get" {
				name = "original"
			}
			group, version, _ := strings.Cut(collection.gv, "/")
			if version == "" {
				group, version = "", group
			}
			input = append(input, proofPermission{spec: authv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authv1.ResourceAttributes{Namespace: namespace, Verb: verb, Group: group, Version: version, Resource: collection.plural, Name: name}}, kind: collection.kind})
		}
	}
	input = append(input, input...)
	for _, implementation := range []string{"JSON", "Values"} {
		b.Run(implementation, func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				if implementation == "JSON" {
					jsonProofPermissionOracle(input)
				} else if _, err := uniqueProofPermissions(input); err != nil {
					b.Fatal("local descriptor recipe refused")
				}
			}
		})
	}
}
