// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installcontract

import (
	"bytes"
	"encoding/json"
	"reflect"
	"sort"
	"testing"

	crdv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func observedOwningSchemaLeaf() *crdv1.JSONSchemaProps {
	listType := "map"
	return &crdv1.JSONSchemaProps{
		Type: "object", Default: &crdv1.JSON{Raw: []byte("{ \"x\": 1 }")},
		Enum:         []crdv1.JSON{{Raw: []byte(" { \"x\":2 } ")}},
		Example:      &crdv1.JSON{Raw: []byte("{ \"x\": 3 }")},
		XListMapKeys: []string{"name"}, XListType: &listType,
		Required: []string{"spec"},
	}
}

// Independent reflection walk: never reuse production traversal to decide what
// aliases are covered. Map values are recursively inspected; structural maps
// with JSON schema values always carry the deliberately populated leaf fields.
func assertObservedSchemaNoAlias(t testing.TB, first, second reflect.Value) {
	t.Helper()
	if first.Type() != second.Type() {
		t.Fatal("copy type changed")
	}
	switch first.Kind() {
	case reflect.Ptr:
		if first.IsNil() {
			return
		}
		if first.Pointer() == second.Pointer() {
			t.Fatal("owning copy retained mutable pointer")
		}
		assertObservedSchemaNoAlias(t, first.Elem(), second.Elem())
	case reflect.Slice:
		if first.Len() > 0 && first.Pointer() == second.Pointer() {
			t.Fatal("owning copy retained mutable slice")
		}
		for i := 0; i < first.Len(); i++ {
			assertObservedSchemaNoAlias(t, first.Index(i), second.Index(i))
		}
	case reflect.Map:
		for _, key := range first.MapKeys() {
			assertObservedSchemaNoAlias(t, first.MapIndex(key), second.MapIndex(key))
		}
	case reflect.Struct:
		for i := 0; i < first.NumField(); i++ {
			if first.Field(i).CanInterface() {
				assertObservedSchemaNoAlias(t, first.Field(i), second.Field(i))
			}
		}
	}
}

// Exercise nested Raw mutation concurrently with private check readers without
// relying on which signed schema happens to place a default at its root.
func mutateObservedCopyJSONBytes(value reflect.Value) {
	if value.Type() == reflect.TypeOf((*crdv1.JSON)(nil)) {
		if !value.IsNil() {
			if raw := value.Interface().(*crdv1.JSON).Raw; len(raw) > 0 {
				raw[0] = '['
			}
		}
		return
	}
	switch value.Kind() {
	case reflect.Ptr:
		if !value.IsNil() {
			mutateObservedCopyJSONBytes(value.Elem())
		}
	case reflect.Struct:
		for i := 0; i < value.NumField(); i++ {
			if value.Field(i).CanInterface() {
				mutateObservedCopyJSONBytes(value.Field(i))
			}
		}
	case reflect.Slice:
		for i := 0; i < value.Len(); i++ {
			mutateObservedCopyJSONBytes(value.Index(i))
		}
	case reflect.Map:
		for _, key := range value.MapKeys() {
			mutateObservedCopyJSONBytes(value.MapIndex(key))
		}
	}
}

func TestObservedCRDOwningCopyRepairsEverySchemaEdge(t *testing.T) {
	for _, edge := range []struct {
		name   string
		attach func(*crdv1.JSONSchemaProps, *crdv1.JSONSchemaProps)
	}{
		{"ItemsSchema", func(p, c *crdv1.JSONSchemaProps) { p.Items = &crdv1.JSONSchemaPropsOrArray{Schema: c} }},
		{"ItemsArray", func(p, c *crdv1.JSONSchemaProps) {
			p.Items = &crdv1.JSONSchemaPropsOrArray{JSONSchemas: []crdv1.JSONSchemaProps{*c}}
		}},
		{"AllOf", func(p, c *crdv1.JSONSchemaProps) { p.AllOf = []crdv1.JSONSchemaProps{*c} }},
		{"OneOf", func(p, c *crdv1.JSONSchemaProps) { p.OneOf = []crdv1.JSONSchemaProps{*c} }},
		{"AnyOf", func(p, c *crdv1.JSONSchemaProps) { p.AnyOf = []crdv1.JSONSchemaProps{*c} }},
		{"Not", func(p, c *crdv1.JSONSchemaProps) { p.Not = c }},
		{"Properties", func(p, c *crdv1.JSONSchemaProps) { p.Properties = map[string]crdv1.JSONSchemaProps{"child": *c} }},
		{"PatternProperties", func(p, c *crdv1.JSONSchemaProps) { p.PatternProperties = map[string]crdv1.JSONSchemaProps{"child": *c} }},
		{"AdditionalProperties", func(p, c *crdv1.JSONSchemaProps) {
			p.AdditionalProperties = &crdv1.JSONSchemaPropsOrBool{Allows: true, Schema: c}
		}},
		{"Dependencies", func(p, c *crdv1.JSONSchemaProps) {
			p.Dependencies = crdv1.JSONSchemaDependencies{"child": {Schema: c, Property: []string{"spec"}}}
		}},
		{"AdditionalItems", func(p, c *crdv1.JSONSchemaProps) {
			p.AdditionalItems = &crdv1.JSONSchemaPropsOrBool{Allows: true, Schema: c}
		}},
		{"Definitions", func(p, c *crdv1.JSONSchemaProps) { p.Definitions = crdv1.JSONSchemaDefinitions{"child": *c} }},
	} {
		t.Run(edge.name, func(t *testing.T) {
			root, child := observedOwningSchemaLeaf(), observedOwningSchemaLeaf()
			child.Properties = map[string]crdv1.JSONSchemaProps{"grandchild": *observedOwningSchemaLeaf()}
			edge.attach(root, child)
			object := &crdv1.CustomResourceDefinition{Spec: crdv1.CustomResourceDefinitionSpec{
				Versions: []crdv1.CustomResourceDefinitionVersion{
					{Name: "v1alpha1", Schema: &crdv1.CustomResourceValidation{OpenAPIV3Schema: root}},
					{Name: "v1beta1", Schema: &crdv1.CustomResourceValidation{OpenAPIV3Schema: observedOwningSchemaLeaf()}},
					{Name: "nil-schema"}, {Name: "nil-root", Schema: &crdv1.CustomResourceValidation{}},
				},
			}}
			before, _ := json.Marshal(object)
			copied := copyObservedOwning(object).(*crdv1.CustomResourceDefinition)
			if !reflect.DeepEqual(object, copied) {
				t.Fatal("owning repair changed exact schema values or raw bytes")
			}
			for i := 0; i < 2; i++ {
				original, next := object.Spec.Versions[i].Schema.OpenAPIV3Schema, copied.Spec.Versions[i].Schema.OpenAPIV3Schema
				assertObservedSchemaNoAlias(t, reflect.ValueOf(original), reflect.ValueOf(next))
				next.Default.Raw[0] = '['
				next.Enum[0].Raw[0] = '['
				next.Enum[0] = crdv1.JSON{Raw: []byte("null")}
				next.Example.Raw[0] = '['
				next.XListMapKeys[0] = "foreign"
				*next.XListType = "foreign"
				next.Required[0] = "foreign"
			}
			after, _ := json.Marshal(object)
			if !bytes.Equal(before, after) {
				t.Fatal("owning repair mutated its source")
			}
		})
	}
}

func TestObservedCRDOwningCopyPreservesNilEmptyAndOtherFields(t *testing.T) {
	for _, schema := range []*crdv1.JSONSchemaProps{
		{}, {Enum: []crdv1.JSON{}, XListMapKeys: []string{}},
		{Default: &crdv1.JSON{}, Example: &crdv1.JSON{Raw: []byte{}}, Enum: []crdv1.JSON{{}, {Raw: []byte{}}}},
	} {
		object := &crdv1.CustomResourceDefinition{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"scope": "original"}, Annotations: map[string]string{"proof": "original"}},
			Spec: crdv1.CustomResourceDefinitionSpec{Names: crdv1.CustomResourceDefinitionNames{ShortNames: []string{"original"}}, Conversion: &crdv1.CustomResourceConversion{Strategy: crdv1.WebhookConverter, Webhook: &crdv1.WebhookConversion{ClientConfig: &crdv1.WebhookClientConfig{CABundle: []byte("original")}, ConversionReviewVersions: []string{"v1"}}},
				Versions: []crdv1.CustomResourceDefinitionVersion{{Name: "v1", Schema: &crdv1.CustomResourceValidation{OpenAPIV3Schema: schema}, Subresources: &crdv1.CustomResourceSubresources{Status: &crdv1.CustomResourceSubresourceStatus{}}}}},
			Status: crdv1.CustomResourceDefinitionStatus{StoredVersions: []string{"v1"}, Conditions: []crdv1.CustomResourceDefinitionCondition{{Message: "original"}}},
		}
		copied := copyObservedOwning(object).(*crdv1.CustomResourceDefinition)
		if !reflect.DeepEqual(object, copied) {
			t.Fatal("nil/empty or generated whole-copy values changed")
		}
		copied.Labels["scope"] = "foreign"
		copied.Annotations["proof"] = "foreign"
		copied.Spec.Names.ShortNames[0] = "foreign"
		copied.Spec.Conversion.Webhook.ClientConfig.CABundle[0] = 'x'
		copied.Spec.Conversion.Webhook.ConversionReviewVersions[0] = "foreign"
		copied.Spec.Versions[0].Name = "foreign"
		copied.Status.StoredVersions[0] = "foreign"
		copied.Status.Conditions[0].Message = "foreign"
		if object.Labels["scope"] != "original" || object.Annotations["proof"] != "original" || object.Spec.Names.ShortNames[0] != "original" || string(object.Spec.Conversion.Webhook.ClientConfig.CABundle) != "original" || object.Spec.Conversion.Webhook.ConversionReviewVersions[0] != "v1" || object.Spec.Versions[0].Name != "v1" || object.Status.StoredVersions[0] != "v1" || object.Status.Conditions[0].Message != "original" {
			t.Fatal("repair regressed generated ownership")
		}
	}
}

func TestObservedCRDOwningSchemaMutableFieldInventory(t *testing.T) {
	expected := []string{"Ref", "Default", "Maximum", "Minimum", "MaxLength", "MinLength", "MaxItems", "MinItems", "MultipleOf", "Enum", "MaxProperties", "MinProperties", "Required", "Items", "AllOf", "OneOf", "AnyOf", "Not", "Properties", "AdditionalProperties", "PatternProperties", "Dependencies", "AdditionalItems", "Definitions", "ExternalDocs", "Example", "XPreserveUnknownFields", "XListMapKeys", "XListType", "XMapType", "XValidations"}
	var actual []string
	schema := reflect.TypeOf(crdv1.JSONSchemaProps{})
	for i := 0; i < schema.NumField(); i++ {
		field := schema.Field(i)
		switch field.Type.Kind() {
		case reflect.Ptr, reflect.Slice, reflect.Map:
			actual = append(actual, field.Name)
		}
	}
	sort.Strings(expected)
	sort.Strings(actual)
	if !reflect.DeepEqual(expected, actual) {
		t.Fatal("mutable schema inventory changed; audit owning repair and traversal")
	}
}
