// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package game

import (
	"bytes"
	"encoding/json"
	"math"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
)

const maxOptions = 64

func optionError(category string) error { return &OptionMetadataError{Category: category} }

func (d Definition) validateOptions() error {
	m := d.Options
	if m == nil {
		return nil
	}
	if m.Version != OptionMetadataVersion {
		return optionError("version")
	}
	encoded, err := json.Marshal(m)
	if err != nil || len(encoded) > 64*1024 || len(m.Supported)+len(m.Unsupported) > maxOptions {
		return optionError("bounds")
	}
	var root struct {
		Type                 string                     `json:"type"`
		AdditionalProperties *bool                      `json:"additionalProperties"`
		Properties           map[string]json.RawMessage `json:"properties"`
		Required             []string                   `json:"required"`
	}
	decoder := json.NewDecoder(bytes.NewReader(d.SettingsSchema))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&root); err != nil || root.AdditionalProperties == nil || *root.AdditionalProperties {
		return optionError("schema")
	}
	var rootKeys map[string]json.RawMessage
	if json.Unmarshal(d.SettingsSchema, &rootKeys) != nil {
		return optionError("schema")
	}
	for key, value := range rootKeys {
		switch key {
		case "type", "additionalProperties", "properties", "required":
			if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
				return optionError("schema")
			}
		default:
			return optionError("schema")
		}
	}
	if len(root.Properties) != len(m.Supported) {
		return optionError("inventory")
	}
	required := make(map[string]bool, len(root.Required))
	for _, name := range root.Required {
		if _, ok := root.Properties[name]; !ok || required[name] {
			return optionError("schema")
		}
		required[name] = true
	}
	ids, properties := map[string]bool{}, map[string]bool{}
	for _, o := range m.Supported {
		if !namePattern.MatchString(o.ID) || ids[o.ID] || properties[o.Property] || root.Properties[o.Property] == nil {
			return optionError("inventory")
		}
		ids[o.ID], properties[o.Property] = true, true
		if !optionText(o.Label, 256) || !optionText(o.Help, 1024) || !namePattern.MatchString(o.Group) {
			return optionError("presentation")
		}
		if o.Lifecycle != OptionRestartRequired && o.Lifecycle != OptionCreateOnly {
			return optionError("lifecycle")
		}
		if err := d.validateAvailability(o.Availability); err != nil {
			return err
		}
		if err := validateOptionSchema(o, root.Properties[o.Property], required[o.Property]); err != nil {
			return err
		}
	}
	for _, o := range m.Unsupported {
		if !namePattern.MatchString(o.ID) || ids[o.ID] || properties[o.ID] {
			return optionError("inventory")
		}
		ids[o.ID] = true
		if !optionText(o.Reason, 1024) {
			return optionError("presentation")
		}
	}
	return nil
}

func optionText(s string, limit int) bool {
	if len(s) > limit || strings.TrimSpace(s) == "" || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// The discoverable subset is deliberately scalar and closed. In particular,
// dependency expressions and arbitrary schema evaluation are not form metadata.
type optionSchema struct {
	Type      string            `json:"type"`
	Enum      []json.RawMessage `json:"enum,omitempty"`
	Minimum   *float64          `json:"minimum,omitempty"`
	Maximum   *float64          `json:"maximum,omitempty"`
	MinLength *int              `json:"minLength,omitempty"`
	MaxLength *int              `json:"maxLength,omitempty"`
	Pattern   string            `json:"pattern,omitempty"`
}

func validateOptionSchema(o SettingOption, property json.RawMessage, required bool) error {
	var actual, declared any
	if json.Unmarshal(property, &actual) != nil || json.Unmarshal(o.Schema, &declared) != nil || !reflect.DeepEqual(actual, declared) {
		return optionError("schema")
	}
	keywords, ok := actual.(map[string]any)
	if !ok {
		return optionError("schema")
	}
	for key, value := range keywords {
		switch key {
		case "type", "enum", "minimum", "maximum", "minLength", "maxLength", "pattern":
			if value == nil {
				return optionError("schema")
			}
		default:
			return optionError("schema")
		}
	}
	if values, exists := keywords["enum"]; exists {
		if list, ok := values.([]any); !ok || len(list) == 0 {
			return optionError("schema")
		}
	}
	var s optionSchema
	decoder := json.NewDecoder(bytes.NewReader(o.Schema))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&s); err != nil {
		return optionError("schema")
	}
	if err := s.validate(); err != nil {
		return err
	}
	compiler := jsonschema.NewCompiler()
	const resource = "arcadectl://adapter/option.json"
	if err := compiler.AddResource(resource, actual); err != nil {
		return optionError("schema")
	}
	compiled, err := compiler.Compile(resource)
	if err != nil {
		return optionError("schema")
	}
	var seen []any
	for _, value := range s.Enum {
		var instance any
		if json.Unmarshal(value, &instance) != nil || compiled.Validate(instance) != nil {
			return optionError("schema")
		}
		for _, prior := range seen {
			if reflect.DeepEqual(prior, instance) {
				return optionError("schema")
			}
		}
		seen = append(seen, instance)
	}
	if len(o.Default) > 0 {
		var value any
		if json.Unmarshal(o.Default, &value) != nil || compiled.Validate(value) != nil {
			return optionError("omission")
		}
	}
	if required {
		if o.Omission != OptionRequired || len(o.OmittedValue) != 0 {
			return optionError("omission")
		}
		return nil
	}
	// Renderer omission may intentionally be outside explicit-input bounds (for
	// example a zero sentinel). It must still have the declared scalar type.
	var omitted any
	if o.Omission != OptionRendererValue || json.Unmarshal(o.OmittedValue, &omitted) != nil || !optionValueType(omitted, s.Type) {
		return optionError("omission")
	}
	return nil
}

func (s optionSchema) validate() error {
	if len(s.Enum) > 32 {
		return optionError("bounds")
	}
	switch s.Type {
	case "string":
		if s.Minimum != nil || s.Maximum != nil {
			return optionError("schema")
		}
		if s.MaxLength == nil && len(s.Enum) == 0 || s.MaxLength != nil && (*s.MaxLength < 0 || *s.MaxLength > MaxRenderedSettingsBytes) || s.MinLength != nil && (*s.MinLength < 0 || s.MaxLength != nil && *s.MinLength > *s.MaxLength) {
			return optionError("bounds")
		}
		for _, value := range s.Enum {
			if len(value) > MaxRenderedSettingsBytes {
				return optionError("bounds")
			}
		}
		if s.Pattern != "" {
			if len(s.Pattern) > 256 {
				return optionError("bounds")
			}
			if _, err := regexp.Compile(s.Pattern); err != nil {
				return optionError("schema")
			}
		}
	case "number", "integer":
		if s.MinLength != nil || s.MaxLength != nil || s.Pattern != "" {
			return optionError("schema")
		}
		if s.Minimum == nil || s.Maximum == nil || *s.Minimum > *s.Maximum {
			return optionError("bounds")
		}
		if s.Type == "integer" && math.Ceil(*s.Minimum) > math.Floor(*s.Maximum) {
			return optionError("bounds")
		}
	case "boolean":
		if s.Minimum != nil || s.Maximum != nil || s.MinLength != nil || s.MaxLength != nil || s.Pattern != "" {
			return optionError("schema")
		}
	default:
		return optionError("schema")
	}
	return nil
}

func optionValueType(v any, kind string) bool {
	switch kind {
	case "boolean":
		_, ok := v.(bool)
		return ok
	case "string":
		_, ok := v.(string)
		return ok
	case "number", "integer":
		n, ok := v.(float64)
		return ok && (kind != "integer" || n == math.Trunc(n))
	}
	return false
}

func (d Definition) validateAvailability(a OptionAvailability) error {
	var bounds [2][3]int
	for i, value := range []string{a.Since, a.Before} {
		if value == "" {
			continue
		}
		if _, err := ResolveVersionTag(d, value); err != nil {
			return optionError("availability")
		}
		parts := strings.Split(value, ".")
		if len(parts) != 3 {
			return optionError("availability")
		}
		for j, part := range parts {
			if len(part) == 0 || len(part) > 6 || len(part) > 1 && part[0] == '0' {
				return optionError("availability")
			}
			n, err := strconv.Atoi(part)
			if err != nil || n < 0 || strings.ContainsAny(part, "+-") {
				return optionError("availability")
			}
			bounds[i][j] = n
		}
	}
	if a.Since != "" && a.Before != "" {
		for i := range 3 {
			if bounds[0][i] < bounds[1][i] {
				return nil
			}
			if bounds[0][i] > bounds[1][i] {
				return optionError("availability")
			}
		}
		return optionError("availability")
	}
	return nil
}
