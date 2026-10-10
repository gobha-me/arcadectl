// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

// Package installbaseline contains the reviewed non-rollback installation
// security contract. Rendering public templates alone does not authenticate
// an artifact, establish ownership, or authorize a Kubernetes mutation.
package installbaseline

import (
	"errors"
	"strings"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/utils/ptr"
)

const Version = "privileged-identity-v1"

const DenialMessage = "Arcadectl installation identities and executables require trusted maintenance authority."

// ResourceCount is separate from all historical runtime-package inventories.
const ResourceCount = 12

var ErrInvalid = errors.New("invalid installation security baseline")

// Render returns six homogeneous policy families and their namespace bindings.
// Callers receive independent copies. Signed artifact verification and a sealed
// semantic plan must precede production use; this is only a public renderer.
func Render(namespace string) ([]*unstructured.Unstructured, error) {
	if len(validation.IsDNS1123Label(namespace)) != 0 || namespace == "default" || strings.HasPrefix(namespace, "kube-") {
		return nil, ErrInvalid
	}
	families := []policyFamily{
		{"pod", "spec", []admissionv1.NamedRuleWithOperations{rule("", "v1", "pods", "pods/ephemeralcontainers", "pods/resize")}, podProducer},
		{"template", "spec.template.spec", []admissionv1.NamedRuleWithOperations{
			rule("apps", "v1", "deployments", "daemonsets", "statefulsets"), rule("batch", "v1", "jobs"), rule("", "v1", "replicationcontrollers"),
		}, templateProducer},
		{"replicaset", "spec.template.spec", []admissionv1.NamedRuleWithOperations{rule("apps", "v1", "replicasets")}, replicaSetProducer},
		{"cronjob", "spec.jobTemplate.spec.template.spec", []admissionv1.NamedRuleWithOperations{rule("batch", "v1", "cronjobs")}, "false"},
		{"identity", "", []admissionv1.NamedRuleWithOperations{rule("", "v1", "serviceaccounts", "services"), rule("rbac.authorization.k8s.io", "v1", "roles", "rolebindings")}, "false"},
		{"scale", "", []admissionv1.NamedRuleWithOperations{rule("apps", "v1", "deployments/scale", "replicasets/scale", "statefulsets/scale"), rule("", "v1", "replicationcontrollers/scale")}, "false"},
	}
	result := make([]*unstructured.Unstructured, 0, ResourceCount)
	for _, family := range families {
		objects, err := renderFamily(namespace, family)
		if err != nil {
			return nil, ErrInvalid
		}
		result = append(result, objects...)
	}
	return result, nil
}

type policyFamily struct {
	name, accountPath string
	rules             []admissionv1.NamedRuleWithOperations
	producer          string
}

func renderFamily(namespace string, family policyFamily) ([]*unstructured.Unstructured, error) {
	name := "arcadectl-identity-" + family.name + "-" + namespace
	variables := []admissionv1.Variable{
		{Name: "reservedAccounts", Expression: "['arcadectl-controller', 'arcadectl-api', 'arcadectl-destroy-controller', 'arcadectl-destroy-admin']"},
		{Name: "reservedResource", Expression: `(object != null && object.metadata.name in variables.reservedAccounts) || (oldObject != null && oldObject.metadata.name in variables.reservedAccounts)`},
		{Name: "maintenance", Expression: `authorizer.group('').resource('serviceaccounts').namespace(request.namespace).name('arcadectl-destroy-controller').check('impersonate').allowed()`},
	}
	guarded := "variables.reservedResource"
	if family.accountPath != "" {
		variables = append(variables,
			admissionv1.Variable{Name: "newAccount", Expression: accountExpression("object", family.accountPath)},
			admissionv1.Variable{Name: "oldAccount", Expression: accountExpression("oldObject", family.accountPath)},
		)
		guarded += " || variables.newAccount in variables.reservedAccounts || variables.oldAccount in variables.reservedAccounts"
	}
	variables = append(variables, admissionv1.Variable{Name: "guarded", Expression: guarded}, admissionv1.Variable{Name: "producer", Expression: family.producer})
	policy := &admissionv1.ValidatingAdmissionPolicy{
		TypeMeta:   metav1.TypeMeta{APIVersion: admissionv1.SchemeGroupVersion.String(), Kind: "ValidatingAdmissionPolicy"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{"app.kubernetes.io/part-of": "arcadectl", "arcade.gobha.me/security-baseline": Version}},
		Spec: admissionv1.ValidatingAdmissionPolicySpec{
			FailurePolicy: ptr.To(admissionv1.Fail),
			MatchConstraints: &admissionv1.MatchResources{
				MatchPolicy:       ptr.To(admissionv1.Equivalent),
				NamespaceSelector: &metav1.LabelSelector{}, ObjectSelector: &metav1.LabelSelector{},
				ResourceRules: family.rules,
			},
			Variables:   variables,
			Validations: []admissionv1.Validation{{Expression: "!variables.guarded || variables.maintenance || variables.producer", Message: DenialMessage}},
		},
	}
	binding := &admissionv1.ValidatingAdmissionPolicyBinding{
		TypeMeta:   metav1.TypeMeta{APIVersion: admissionv1.SchemeGroupVersion.String(), Kind: "ValidatingAdmissionPolicyBinding"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{"app.kubernetes.io/part-of": "arcadectl", "arcade.gobha.me/security-baseline": Version}},
		Spec: admissionv1.ValidatingAdmissionPolicyBindingSpec{
			PolicyName: name, ValidationActions: []admissionv1.ValidationAction{admissionv1.Deny},
			MatchResources: &admissionv1.MatchResources{MatchPolicy: ptr.To(admissionv1.Equivalent), ObjectSelector: &metav1.LabelSelector{}, NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": namespace}}},
		},
	}
	result := make([]*unstructured.Unstructured, 0, 2)
	for _, object := range []any{policy, binding} {
		value, err := runtime.DefaultUnstructuredConverter.ToUnstructured(object)
		if err != nil {
			return nil, ErrInvalid
		}
		result = append(result, &unstructured.Unstructured{Object: value})
	}
	return result, nil
}

func rule(group, version string, resources ...string) admissionv1.NamedRuleWithOperations {
	return admissionv1.NamedRuleWithOperations{RuleWithOperations: admissionv1.RuleWithOperations{
		Operations: []admissionv1.OperationType{admissionv1.Create, admissionv1.Update, admissionv1.Delete},
		Rule:       admissionv1.Rule{APIGroups: []string{group}, APIVersions: []string{version}, Resources: resources, Scope: ptr.To(admissionv1.NamespacedScope)},
	}}
}

func accountExpression(object, path string) string {
	parents := []string{}
	prefix := object
	for _, field := range strings.Split(path+".serviceAccountName", ".") {
		prefix += "." + field
		parents = append(parents, "has("+prefix+")")
	}
	return object + " == null ? '' : (" + strings.Join(parents, " && ") + " ? " + prefix + " : '')"
}

// Explicit producer identities are scoped to child resources and operations.
// They are never a general kube-system prefix exemption or permission for a
// caller-supplied parent. Parent templates are independently guarded above.
// UPDATE exceptions cannot change executable templates; status is not matched.
const podProducer = `
 (request.operation in ['CREATE', 'DELETE'] ||
  (request.operation == 'UPDATE' && object != null && oldObject != null && object.spec == oldObject.spec)) &&
 (request.userInfo.username == 'system:kube-controller-manager' ||
  request.userInfo.username in [
    'system:serviceaccount:kube-system:replicaset-controller',
    'system:serviceaccount:kube-system:job-controller',
    'system:serviceaccount:kube-system:replication-controller',
    'system:serviceaccount:kube-system:daemon-set-controller',
    'system:serviceaccount:kube-system:statefulset-controller'] ||
  (request.operation == 'DELETE' && request.userInfo.username == 'system:serviceaccount:kube-system:generic-garbage-collector'))`

// ReplicaSetSpec has replicas, minReadySeconds, selector and template. Only the
// replicas field may change under the producer exception; metadata revisions
// are allowed. Neither the executable template nor selector can be substituted.
const replicaSetProducer = `
 (request.operation == 'DELETE' && request.userInfo.username == 'system:serviceaccount:kube-system:generic-garbage-collector') ||
 ((request.userInfo.username in ['system:kube-controller-manager', 'system:serviceaccount:kube-system:deployment-controller']) &&
  (request.operation in ['CREATE', 'DELETE'] ||
   (request.operation == 'UPDATE' && object != null && oldObject != null &&
    object.spec.template == oldObject.spec.template && object.spec.selector == oldObject.spec.selector &&
    ((!has(object.spec.minReadySeconds) && !has(oldObject.spec.minReadySeconds)) ||
     (has(object.spec.minReadySeconds) && has(oldObject.spec.minReadySeconds) && object.spec.minReadySeconds == oldObject.spec.minReadySeconds)))))`

const templateProducer = `
 (request.operation == 'DELETE' && request.userInfo.username == 'system:serviceaccount:kube-system:generic-garbage-collector') ||
 (request.kind.kind == 'Job' && request.operation in ['CREATE', 'DELETE'] &&
  request.userInfo.username in ['system:kube-controller-manager', 'system:serviceaccount:kube-system:cronjob-controller'])`
