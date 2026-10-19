// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installcontract

import (
	crdv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// copyObservedOwning retains the generated whole-object copy, but repairs the
// five mutable fields omitted by the pinned v0.37.1 JSONSchemaProps.DeepCopy.
// Every schema edge is visited on the already structurally owned DESTINATION.
// Do not reserialize: JSON.Raw bytes and the original decode/error ordering
// must remain unchanged. Inputs here originate from bounded strict conversion.
func copyObservedOwning(object runtime.Object) runtime.Object {
	result := object.DeepCopyObject()
	if crd, ok := result.(*crdv1.CustomResourceDefinition); ok {
		for i := range crd.Spec.Versions {
			if schema := crd.Spec.Versions[i].Schema; schema != nil {
				ownObservedSchema(schema.OpenAPIV3Schema)
			}
		}
	}
	return result
}

func ownObservedSchema(schema *crdv1.JSONSchemaProps) {
	if schema == nil {
		return
	}
	schema.Default = schema.Default.DeepCopy()
	schema.Example = schema.Example.DeepCopy()
	if schema.Enum != nil {
		values := make([]crdv1.JSON, len(schema.Enum))
		for i := range schema.Enum {
			schema.Enum[i].DeepCopyInto(&values[i])
		}
		schema.Enum = values
	}
	if schema.XListMapKeys != nil {
		keys := make([]string, len(schema.XListMapKeys))
		copy(keys, schema.XListMapKeys)
		schema.XListMapKeys = keys
	}
	if schema.XListType != nil {
		value := *schema.XListType
		schema.XListType = &value
	}
	if schema.Items != nil {
		ownObservedSchema(schema.Items.Schema)
		for i := range schema.Items.JSONSchemas {
			ownObservedSchema(&schema.Items.JSONSchemas[i])
		}
	}
	for i := range schema.AllOf {
		ownObservedSchema(&schema.AllOf[i])
	}
	for i := range schema.OneOf {
		ownObservedSchema(&schema.OneOf[i])
	}
	for i := range schema.AnyOf {
		ownObservedSchema(&schema.AnyOf[i])
	}
	ownObservedSchema(schema.Not)
	for name, value := range schema.Properties {
		ownObservedSchema(&value)
		schema.Properties[name] = value
	}
	for name, value := range schema.PatternProperties {
		ownObservedSchema(&value)
		schema.PatternProperties[name] = value
	}
	if schema.AdditionalProperties != nil {
		ownObservedSchema(schema.AdditionalProperties.Schema)
	}
	for name, value := range schema.Dependencies {
		ownObservedSchema(value.Schema)
		schema.Dependencies[name] = value
	}
	if schema.AdditionalItems != nil {
		ownObservedSchema(schema.AdditionalItems.Schema)
	}
	for name, value := range schema.Definitions {
		ownObservedSchema(&value)
		schema.Definitions[name] = value
	}
}
