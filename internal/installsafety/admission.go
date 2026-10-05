// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installsafety

import (
	"reflect"

	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

func validateAdmission(plan *installrender.Plan, s *Snapshot, owned map[installstate.Key]types.UID, removable map[types.UID]bool) error {
	policies := map[string]*admissionv1.ValidatingAdmissionPolicy{}
	for i := range s.Policies.Items {
		o := &s.Policies.Items[i]
		if o.Name == "" || len(o.Name) > 253 || o.Namespace != "" || !boundedIdentity(string(o.UID)) || !boundedIdentity(o.ResourceVersion) || policies[o.Name] != nil {
			return ErrInvalid
		}
		policies[o.Name] = o
	}
	bindings := map[string]*admissionv1.ValidatingAdmissionPolicyBinding{}
	for i := range s.Bindings.Items {
		o := &s.Bindings.Items[i]
		if o.Name == "" || len(o.Name) > 253 || o.Namespace != "" || !boundedIdentity(string(o.UID)) || !boundedIdentity(o.ResourceVersion) || bindings[o.Name] != nil {
			return ErrInvalid
		}
		bindings[o.Name] = o
	}
	countPolicies, countBindings := 0, 0
	for _, r := range plan.Resources() {
		o := r.Object
		key := installstate.Key{APIVersion: o.GetAPIVersion(), Kind: o.GetKind(), Name: o.GetName()}
		switch o.GetKind() {
		case "ValidatingAdmissionPolicy":
			countPolicies++
			actual := policies[o.GetName()]
			var expected admissionv1.ValidatingAdmissionPolicy
			if runtime.DefaultUnstructuredConverter.FromUnstructured(o.Object, &expected) != nil {
				return ErrInvalid
			}
			if actual == nil || owned[key] == "" || actual.UID != owned[key] {
				return ErrOwnership
			}
			if actual.DeletionTimestamp != nil || actual.Generation < 1 || actual.Status.ObservedGeneration != actual.Generation || actual.Status.TypeChecking == nil || len(actual.Status.TypeChecking.ExpressionWarnings) != 0 || !reflect.DeepEqual(actual.Spec, expected.Spec) {
				return ErrAdmission
			}
			if gcHazard(actual, removable) {
				return ErrRetention
			}
		case "ValidatingAdmissionPolicyBinding":
			countBindings++
			actual := bindings[o.GetName()]
			var expected admissionv1.ValidatingAdmissionPolicyBinding
			if runtime.DefaultUnstructuredConverter.FromUnstructured(o.Object, &expected) != nil {
				return ErrInvalid
			}
			if actual == nil || owned[key] == "" || actual.UID != owned[key] {
				return ErrOwnership
			}
			if actual.DeletionTimestamp != nil || !reflect.DeepEqual(actual.Spec, expected.Spec) {
				return ErrAdmission
			}
			if gcHazard(actual, removable) {
				return ErrRetention
			}
		}
	}
	if countPolicies != 6 || countBindings != 6 {
		return ErrInvalid
	}
	return nil
}
