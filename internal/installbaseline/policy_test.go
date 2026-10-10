// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installbaseline

import (
	"reflect"
	"testing"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestReviewedPolicyRendering(t *testing.T) {
	for _, namespace := range []string{"arcadectl-system", "isolated-baseline"} {
		objects, err := Render(namespace)
		if err != nil || len(objects) != ResourceCount {
			t.Fatal("reviewed baseline rendering failed")
		}
		again, err := Render(namespace)
		if err != nil || !reflect.DeepEqual(objects, again) {
			t.Fatal("baseline rendering is nondeterministic")
		}
		for index := 0; index < len(objects); index += 2 {
			var policy admissionv1.ValidatingAdmissionPolicy
			var binding admissionv1.ValidatingAdmissionPolicyBinding
			if runtime.DefaultUnstructuredConverter.FromUnstructured(objects[index].Object, &policy) != nil || runtime.DefaultUnstructuredConverter.FromUnstructured(objects[index+1].Object, &binding) != nil {
				t.Fatal("reviewed baseline type decode failed")
			}
			if policy.Namespace != "" || binding.Namespace != "" || policy.Name != binding.Spec.PolicyName || policy.Name != binding.Name || policy.Spec.FailurePolicy == nil || *policy.Spec.FailurePolicy != admissionv1.Fail {
				t.Fatal("baseline does not fail closed with its exact binding")
			}
			if !reflect.DeepEqual(binding.Spec.ValidationActions, []admissionv1.ValidationAction{admissionv1.Deny}) || binding.Spec.MatchResources == nil || !reflect.DeepEqual(binding.Spec.MatchResources.NamespaceSelector.MatchLabels, map[string]string{"kubernetes.io/metadata.name": namespace}) {
				t.Fatal("baseline binding escapes the selected namespace")
			}
			for _, rule := range policy.Spec.MatchConstraints.ResourceRules {
				if rule.Scope == nil || *rule.Scope != admissionv1.NamespacedScope || !reflect.DeepEqual(rule.Operations, []admissionv1.OperationType{admissionv1.Create, admissionv1.Update, admissionv1.Delete}) {
					t.Fatal("baseline does not cover namespaced create/update/delete")
				}
			}
		}
		objects[0].SetName("caller-substitution")
		fresh, err := Render(namespace)
		if err != nil || !reflect.DeepEqual(again, fresh) {
			t.Fatal("caller mutation changed the reviewed renderer")
		}
	}
}

func TestBaselineRejectsUnscopedNamespaces(t *testing.T) {
	for _, namespace := range []string{"", "default", "kube-system", "kube-public", "MixedCase", "two.names", "../escape"} {
		if _, err := Render(namespace); err != ErrInvalid {
			t.Errorf("accepted invalid baseline namespace %q", namespace)
		}
	}
}
