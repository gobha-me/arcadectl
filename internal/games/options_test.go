// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package games_test

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/gobha-me/arcadectl/internal/catalog"
	"github.com/gobha-me/arcadectl/internal/games/factorio"
	"github.com/gobha-me/arcadectl/internal/games/synthetic"
	"github.com/gobha-me/arcadectl/internal/platform/game"
)

func TestSupportedOptionInventory(t *testing.T) {
	for _, tt := range []struct {
		d    game.Definition
		want map[string]string
	}{
		{factorio.Definition(), map[string]string{"name": "name", "description": "description", "max-players": "maxPlayers", "visibility": "visibility"}},
		{synthetic.Definition(), map[string]string{"seed": "seed", "motd": "motd"}},
	} {
		t.Run(tt.d.ID, func(t *testing.T) {
			if err := tt.d.Validate(); err != nil {
				t.Fatal(err)
			}
			if tt.d.Options == nil || tt.d.Options.Version != game.OptionMetadataVersion || len(tt.d.Options.Unsupported) == 0 {
				t.Fatal("metadata must state a version and unsupported reasons")
			}
			got := map[string]string{}
			for _, o := range tt.d.Options.Supported {
				got[o.ID] = o.Property
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("inventory = %v; want %v", got, tt.want)
			}
		})
	}
}

func TestOptionMetadataCloneIsolation(t *testing.T) {
	original := synthetic.Definition()
	snapshot := synthetic.Definition()
	c, err := catalog.New(original)
	if err != nil {
		t.Fatal(err)
	}
	mutateMetadata := func(d game.Definition) {
		d.Options.Version = "changed"
		d.Options.Supported[0].ID = "changed"
		d.Options.Supported[0].Property = "changed"
		d.Options.Supported[0].Label = "changed"
		d.Options.Supported[0].Help = "changed"
		d.Options.Supported[0].Group = "changed"
		d.Options.Supported[0].Lifecycle = "changed"
		d.Options.Supported[0].Availability.Since = "changed"
		d.Options.Supported[0].Schema[0] = '!'
		d.Options.Supported[0].Omission = "changed"
		d.Options.Supported[0].OmittedValue[0] = '!'
		d.Options.Supported[0].Default[0] = '!'
		d.Options.Unsupported[0].Reason = "changed"
	}
	mutateMetadata(original.Clone())
	if !reflect.DeepEqual(original.Options, snapshot.Options) {
		t.Fatal("Clone leaked metadata mutations")
	}
	mutateMetadata(original)
	for _, source := range []string{"get", "list"} {
		var d game.Definition
		if source == "get" {
			d, err = c.Get(snapshot.ID)
			if err != nil {
				t.Fatal(err)
			}
		} else {
			d = c.List()[0]
		}
		if !reflect.DeepEqual(d.Options, snapshot.Options) {
			t.Fatalf("catalog %s shares constructor input", source)
		}
		mutateMetadata(d)
		fresh, err := c.Get(snapshot.ID)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(fresh.Options, snapshot.Options) {
			t.Fatalf("catalog %s leaked returned metadata", source)
		}
	}
}

func TestMetadataPreservesFactorioRenderedBytesAndOmission(t *testing.T) {
	d := factorio.Definition()
	for _, tt := range []struct{ input, want string }{
		{`{"name":"Factory","visibility":"private"}`, "{\n  \"name\": \"Factory\",\n  \"description\": \"\",\n  \"max_players\": 0,\n  \"visibility\": {\n    \"public\": false,\n    \"lan\": false\n  }\n}\n"},
		{`{"name":"Factory","description":"safe","maxPlayers":16,"visibility":"lan"}`, "{\n  \"name\": \"Factory\",\n  \"description\": \"safe\",\n  \"max_players\": 16,\n  \"visibility\": {\n    \"public\": false,\n    \"lan\": true\n  }\n}\n"},
	} {
		files, err := d.RenderSettingsFiles(json.RawMessage(tt.input))
		if err != nil {
			t.Fatal(err)
		}
		if len(files) != 1 || string(files[0].Contents) != tt.want {
			t.Fatalf("rendered bytes changed: %v", files)
		}
	}
	if d.Options == nil {
		t.Fatal("missing metadata")
	}
	for _, o := range d.Options.Supported {
		switch o.Property {
		case "maxPlayers":
			if o.Omission != game.OptionRendererValue || string(o.OmittedValue) != "0" || len(o.Default) != 0 {
				t.Fatal("omitted player capacity must remain a zero sentinel, with no invented explicit default")
			}
		case "description":
			if string(o.OmittedValue) != `""` || string(o.Default) != `""` {
				t.Fatal("description omission must describe the rendered empty string")
			}
		case "name", "visibility":
			if o.Omission != game.OptionRequired || len(o.OmittedValue) != 0 {
				t.Fatal("required fields cannot advertise omission values")
			}
		}
	}
}

func TestSyntheticMetadataOmissionMatchesRenderer(t *testing.T) {
	d := synthetic.Definition()
	files, err := d.RenderSettingsFiles(json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if d.Options == nil {
		t.Fatal("missing metadata")
	}
	for _, o := range d.Options.Supported {
		var expected string
		if err := json.Unmarshal(o.OmittedValue, &expected); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, f := range files {
			if f.Name == o.Property {
				found = true
				if string(f.Contents) != expected+"\n" {
					t.Fatalf("%s omission disagrees with the real renderer", o.Property)
				}
			}
		}
		if !found {
			t.Fatalf("no rendered file for %s", o.Property)
		}
	}
}
