// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installbaseline

import (
	"reflect"
	"strings"
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

// A literal renderer contract, not an executing CEL or native GC certificate.
// Native authenticated positive/negative requests separately prove admission.
func TestReviewedGarbageCollectorProducerBoundaries(t *testing.T) {
	objects, err := Render("isolated-baseline")
	if err != nil {
		t.Fatal("reviewed policies unavailable")
	}
	gc := `
 (request.userInfo.username == 'system:serviceaccount:kube-system:generic-garbage-collector' &&
  (request.operation == 'DELETE' ||
   (request.operation == 'UPDATE' && object != null && oldObject != null && object.spec == oldObject.spec)))`
	wants := map[string]string{
		"template": gc + ` ||
 (request.kind.kind == 'Job' && request.operation in ['CREATE', 'DELETE'] &&
  request.userInfo.username in ['system:kube-controller-manager', 'system:serviceaccount:kube-system:cronjob-controller'])`,
		"replicaset": gc + ` ||
 ((request.userInfo.username in ['system:kube-controller-manager', 'system:serviceaccount:kube-system:deployment-controller']) &&
  (request.operation in ['CREATE', 'DELETE'] ||
   (request.operation == 'UPDATE' && object != null && oldObject != null &&
    object.spec.template == oldObject.spec.template && object.spec.selector == oldObject.spec.selector &&
    ((!has(object.spec.minReadySeconds) && !has(oldObject.spec.minReadySeconds)) ||
     (has(object.spec.minReadySeconds) && has(oldObject.spec.minReadySeconds) && object.spec.minReadySeconds == oldObject.spec.minReadySeconds)))))`,
		"pod": `
 (request.operation in ['CREATE', 'DELETE'] ||
  (request.operation == 'UPDATE' && object != null && oldObject != null && object.spec == oldObject.spec)) &&
 (request.userInfo.username == 'system:kube-controller-manager' ||
  request.userInfo.username in [
    'system:serviceaccount:kube-system:replicaset-controller',
    'system:serviceaccount:kube-system:job-controller',
    'system:serviceaccount:kube-system:replication-controller',
    'system:serviceaccount:kube-system:daemon-set-controller',
    'system:serviceaccount:kube-system:statefulset-controller'] ||
  (request.operation == 'DELETE' && request.userInfo.username == 'system:serviceaccount:kube-system:generic-garbage-collector'))`,
		"cronjob": "false", "identity": "false", "scale": "false",
	}
	seen := map[string]bool{}
	for index := 0; index < len(objects); index += 2 {
		var policy admissionv1.ValidatingAdmissionPolicy
		if runtime.DefaultUnstructuredConverter.FromUnstructured(objects[index].Object, &policy) != nil {
			t.Fatal("literal policy unavailable")
		}
		family := strings.TrimSuffix(strings.TrimPrefix(policy.Name, "arcadectl-identity-"), "-isolated-baseline")
		want, known := wants[family]
		if !known || seen[family] {
			t.Fatal("unexpected/duplicate producer family")
		}
		seen[family] = true
		matches := 0
		for _, variable := range policy.Spec.Variables {
			if variable.Name == "producer" {
				matches++
				if variable.Expression != want {
					t.Fatal("producer authority escaped independently reviewed literal")
				}
			}
		}
		if matches != 1 {
			t.Fatal("missing or duplicate producer predicate")
		}
	}
	if len(seen) != len(wants) {
		t.Fatal("producer family coverage incomplete")
	}
}
