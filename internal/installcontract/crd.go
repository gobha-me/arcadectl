// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installcontract

import (
	"reflect"

	crdv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
)

// CheckCRD is required BEFORE upgrade/rollback quiescence. A shape match alone
// does not prove stored-version safety or establishment. The initial supported
// transition permits only an identical signed CRD spec, no schema/conversion or
// storage migration. Discovery must independently prove the served resource.
func (t *Template) CheckCRD(live *unstructured.Unstructured, originalUID types.UID, target *Template) error {
	if t == nil || target == nil || t.contract == nil || target.contract == nil || t.key.Kind != "CustomResourceDefinition" || t.key != target.key || t.contract.plan.Namespace() != target.contract.plan.Namespace() || t.contract.plan.Profile().ID != target.contract.plan.Profile().ID || !sameCRDSpec(t.resource.Object, target.resource.Object) || t.MatchLive(live, originalUID) != nil {
		return ErrCRD
	}
	// Presence matters: zero is stale when explicitly provided for generation
	// one, but absent is valid on older profiles/disabled feature gates. Typed
	// omitempty fields alone cannot distinguish these two observations.
	observed, present, err := unstructured.NestedInt64(live.Object, "status", "observedGeneration")
	if err != nil || present && observed != live.GetGeneration() {
		return ErrCRD
	}
	conditions, _, err := unstructured.NestedSlice(live.Object, "status", "conditions")
	if err != nil {
		return ErrCRD
	}
	for _, value := range conditions {
		condition, ok := value.(map[string]any)
		if !ok {
			return ErrCRD
		}
		if value, present := condition["observedGeneration"]; present {
			generation, ok := value.(int64)
			if !ok || generation != live.GetGeneration() {
				return ErrCRD
			}
		}
	}
	object, err := decode(live)
	if err != nil {
		return ErrCRD
	}
	o := object.(*crdv1.CustomResourceDefinition)
	if o.Generation < 1 || o.Status.ObservedGeneration != 0 && o.Status.ObservedGeneration != o.Generation || len(o.Spec.Versions) != 1 || o.Spec.Versions[0].Name != "v1alpha1" || !o.Spec.Versions[0].Served || !o.Spec.Versions[0].Storage || o.Spec.Conversion == nil || o.Spec.Conversion.Strategy != crdv1.NoneConverter || o.Spec.Conversion.Webhook != nil || o.Spec.PreserveUnknownFields || !reflect.DeepEqual(o.Status.StoredVersions, []string{"v1alpha1"}) || !reflect.DeepEqual(o.Status.AcceptedNames, o.Spec.Names) {
		return ErrCRD
	}
	seen := map[crdv1.CustomResourceDefinitionConditionType]bool{}
	established, accepted := false, false
	for _, c := range o.Status.Conditions {
		if seen[c.Type] || c.ObservedGeneration != 0 && c.ObservedGeneration != o.Generation {
			return ErrCRD
		}
		seen[c.Type] = true
		switch c.Type {
		case crdv1.Established:
			established = c.Status == crdv1.ConditionTrue
		case crdv1.NamesAccepted:
			accepted = c.Status == crdv1.ConditionTrue
		case crdv1.Terminating, crdv1.NonStructuralSchema, crdv1.StorageMigrating:
			if c.Status != crdv1.ConditionFalse {
				return ErrCRD
			}
		}
	}
	if !established || !accepted {
		return ErrCRD
	}
	return nil
}
