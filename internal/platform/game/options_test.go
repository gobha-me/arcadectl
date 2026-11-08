// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package game

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// The dependency fixture is a schema, not a replacement validator or renderer.
// All refusals below exercise the real Definition.Validate boundary.
func optionFixture() Definition {
	d := validDefinition()
	d.SettingsSchema = json.RawMessage(`{"type":"object","additionalProperties":false,"properties":{"mode":{"type":"string","enum":["a","b"],"maxLength":1},"enabled":{"type":"boolean"},"capacity":{"type":"number","minimum":1,"maximum":10}},"required":["mode"]}`)
	d.Options = &OptionMetadata{Version: OptionMetadataVersion, Supported: []SettingOption{
		{ID: "mode", Property: "mode", Label: "Mode", Help: "Select a mode.", Group: "world", Schema: json.RawMessage(`{"type":"string","enum":["a","b"],"maxLength":1}`), Lifecycle: OptionCreateOnly, Omission: OptionRequired, Default: json.RawMessage(`"a"`)},
		{ID: "enabled", Property: "enabled", Label: "Enabled", Help: "Enable the fixture feature.", Group: "runtime", Schema: json.RawMessage(`{"type":"boolean"}`), Lifecycle: OptionRestartRequired, Omission: OptionRendererValue, OmittedValue: json.RawMessage(`false`)},
		{ID: "capacity", Property: "capacity", Label: "Capacity", Help: "Bound the fixture capacity.", Group: "runtime", Schema: json.RawMessage(`{"type":"number","minimum":1,"maximum":10}`), Lifecycle: OptionRestartRequired, Omission: OptionRendererValue, OmittedValue: json.RawMessage(`1`), Availability: OptionAvailability{Since: "1.0.0", Before: "2.0.0"}},
	}, Unsupported: []UnsupportedOption{{ID: "commands", Reason: "Arbitrary commands are unavailable."}}}
	d.VersionPolicy = &VersionPolicy{Pattern: `^[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}$`}
	return d
}

func TestOptionMetadataRefusals(t *testing.T) {
	if err := optionFixture().Validate(); err != nil {
		t.Fatalf("valid scalar metadata fixture: %v", err)
	}
	tests := []struct {
		name, category string
		mutate         func(*Definition)
	}{
		{"version", "version", func(d *Definition) { d.Options.Version = "v99" }},
		{"duplicate ID", "inventory", func(d *Definition) { d.Options.Supported[1].ID = "mode" }},
		{"duplicate property", "inventory", func(d *Definition) { d.Options.Supported[1].Property = "mode" }},
		{"missing entry", "inventory", func(d *Definition) { d.Options.Supported = d.Options.Supported[:2] }},
		{"dangling property", "inventory", func(d *Definition) { d.Options.Supported[0].Property = "absent" }},
		{"invalid ID", "inventory", func(d *Definition) { d.Options.Supported[0].ID = "Bad ID" }},
		{"unsupported collision", "inventory", func(d *Definition) { d.Options.Unsupported[0].ID = "mode" }},
		{"unsupported reason", "presentation", func(d *Definition) { d.Options.Unsupported[0].Reason = "" }},
		{"long label", "presentation", func(d *Definition) { d.Options.Supported[0].Label = strings.Repeat("x", 257) }},
		{"control text", "presentation", func(d *Definition) { d.Options.Supported[0].Help = "line\x00two" }},
		{"lifecycle", "lifecycle", func(d *Definition) { d.Options.Supported[0].Lifecycle = "execute" }},
		{"reverse interval", "availability", func(d *Definition) { d.Options.Supported[2].Availability.Since = "3.0.0" }},
		{"empty interval", "availability", func(d *Definition) { d.Options.Supported[2].Availability.Since = "2.0.0" }},
		{"invalid version", "availability", func(d *Definition) { d.Options.Supported[2].Availability.Since = "latest" }},
		{"no policy", "availability", func(d *Definition) { d.VersionPolicy = nil }},
		{"required omission", "omission", func(d *Definition) { d.Options.Supported[0].Omission = OptionRendererValue }},
		{"optional required", "omission", func(d *Definition) { d.Options.Supported[1].Omission = OptionRequired }},
		{"missing omitted value", "omission", func(d *Definition) { d.Options.Supported[1].OmittedValue = nil }},
		{"wrong omitted type", "omission", func(d *Definition) { d.Options.Supported[1].OmittedValue = json.RawMessage(`"no"`) }},
		{"invalid default", "omission", func(d *Definition) { d.Options.Supported[0].Default = json.RawMessage(`"c"`) }},
		{"schema mismatch", "schema", func(d *Definition) { d.Options.Supported[1].Schema = json.RawMessage(`{"type":"string"}`) }},
		{"precise schema mismatch", "schema", func(d *Definition) {
			d.SettingsSchema = json.RawMessage(strings.ReplaceAll(string(d.SettingsSchema), `"minimum":1,"maximum":10`, `"minimum":9007199254740993,"maximum":9007199254740994`))
			d.Options.Supported[2].Schema = json.RawMessage(`{"type":"number","minimum":9007199254740992,"maximum":9007199254740994}`)
		}},
		{"unknown expression", "schema", func(d *Definition) {
			d.SettingsSchema = json.RawMessage(`{"type":"object","additionalProperties":false,"properties":{"mode":{"type":"string","maxLength":1,"dependencies":{"exec":"canary"}},"enabled":{"type":"boolean"},"capacity":{"type":"number","minimum":1,"maximum":10}},"required":["mode"]}`)
			d.Options.Supported[0].Schema = json.RawMessage(`{"type":"string","maxLength":1,"dependencies":{"exec":"canary"}}`)
		}},
		{"invalid numeric bounds", "bounds", func(d *Definition) {
			d.SettingsSchema = json.RawMessage(strings.ReplaceAll(string(d.SettingsSchema), `"minimum":1`, `"minimum":11`))
			d.Options.Supported[2].Schema = json.RawMessage(`{"type":"number","minimum":11,"maximum":10}`)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := optionFixture()
			tt.mutate(&d)
			err := d.Validate()
			var metadataErr *OptionMetadataError
			if !errors.As(err, &metadataErr) || metadataErr.Category != tt.category {
				t.Fatalf("got %v; want metadata category %s", err, tt.category)
			}
			if strings.Contains(err.Error(), "canary") {
				t.Fatal("refusal reflected untrusted metadata")
			}
		})
	}
}

func TestOptionMetadataSchemaSubset(t *testing.T) {
	for _, tt := range []struct{ name, schema, category string }{
		{"unknown type", `{"type":"array"}`, "schema"},
		{"case folded keyword", `{"Type":"boolean"}`, "schema"},
		{"null constraint", `{"type":"boolean","enum":null}`, "schema"},
		{"unbounded string", `{"type":"string"}`, "bounds"},
		{"negative length", `{"type":"string","maxLength":-1}`, "bounds"},
		{"reversed length", `{"type":"string","minLength":2,"maxLength":1}`, "bounds"},
		{"oversized length", `{"type":"string","maxLength":65537}`, "bounds"},
		{"invalid regex", `{"type":"string","maxLength":2,"pattern":"["}`, "schema"},
		{"enum type", `{"type":"string","enum":[true]}`, "schema"},
		{"duplicate enum", `{"type":"string","enum":["a","a"]}`, "schema"},
		{"empty enum", `{"type":"boolean","enum":[]}`, "schema"},
		{"numeric equivalent enum", `{"type":"number","minimum":0,"maximum":2,"enum":[1,1.0]}`, "schema"},
		{"quoted numeric bound", `{"type":"number","minimum":"0","maximum":2}`, "schema"},
		{"enum outside bound", `{"type":"string","maxLength":1,"enum":["aa"]}`, "schema"},
		{"crossed constraints", `{"type":"boolean","maximum":1}`, "schema"},
		{"unknown dependency", `{"type":"boolean","dependentSchemas":{}}`, "schema"},
		{"unbounded number", `{"type":"number","minimum":0}`, "bounds"},
		{"no integer in interval", `{"type":"integer","minimum":1.2,"maximum":1.8}`, "bounds"},
		{"precise reversed bounds", `{"type":"number","minimum":9007199254740993,"maximum":9007199254740992}`, "bounds"},
		{"precise empty integer interval", `{"type":"integer","minimum":0.999999999999999999999,"maximum":0.999999999999999999999}`, "bounds"},
		{"negative empty integer interval", `{"type":"integer","minimum":-0.1,"maximum":-0.1}`, "bounds"},
		{"bounded exponent", `{"type":"number","minimum":0,"maximum":1e129}`, "bounds"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			d := optionFixture()
			var document map[string]any
			if err := json.Unmarshal(d.SettingsSchema, &document); err != nil {
				t.Fatal(err)
			}
			document["properties"].(map[string]any)["mode"] = json.RawMessage(tt.schema)
			var err error
			d.SettingsSchema, err = json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			d.Options.Supported[0].Schema = json.RawMessage(tt.schema)
			d.Options.Supported[0].Default = nil
			var got *OptionMetadataError
			if err := d.Validate(); !errors.As(err, &got) || got.Category != tt.category {
				t.Fatalf("got %v, want category %s", err, tt.category)
			}
		})
	}
}

func TestOptionMetadataGlobalBoundsAndVersionOrdering(t *testing.T) {
	for _, mutate := range []func(*Definition){
		func(d *Definition) { d.Options.Unsupported = make([]UnsupportedOption, maxOptions+1) },
		func(d *Definition) { d.Options.Supported[0].Help = strings.Repeat("x", 64*1024) },
	} {
		d := optionFixture()
		mutate(&d)
		var got *OptionMetadataError
		if err := d.Validate(); !errors.As(err, &got) || got.Category != "bounds" {
			t.Fatalf("unbounded metadata: got %v", err)
		}
	}
	for _, a := range []OptionAvailability{
		{Since: "1.9.0", Before: "1.10.0"},
		{Since: "1.0.9", Before: "1.0.10"},
		{Since: "1.0.0"}, {Before: "1.0.0"}, {},
	} {
		d := optionFixture()
		d.Options.Supported[2].Availability = a
		if err := d.Validate(); err != nil {
			t.Fatalf("numeric version interval %+v: %v", a, err)
		}
	}
	for _, v := range []string{"01.0.0", "1.0", "1.0.-1", "1000000.0.0", "1.0.0+meta", "1.0.0-beta"} {
		d := optionFixture()
		d.Options.Supported[2].Availability = OptionAvailability{Since: v}
		var got *OptionMetadataError
		if err := d.Validate(); !errors.As(err, &got) || got.Category != "availability" {
			t.Fatalf("noncanonical version %q: got %v", v, err)
		}
	}
}
