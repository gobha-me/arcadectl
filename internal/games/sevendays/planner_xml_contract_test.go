// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package sevendays_test

import (
	"encoding/xml"
	"testing"

	"github.com/gobha-me/arcadectl/internal/games/sevendays"
)

func TestSevenDaysServerConfigPublicProperties(t *testing.T) {
	t.Parallel()
	definition := sevendays.Definition()
	worldRoot := ""
	for _, persistent := range definition.PersistentPaths {
		if persistent.Name == "world" {
			worldRoot = persistent.MountPath
		}
	}
	if worldRoot == "" {
		t.Fatal("adapter has no declared world mount")
	}
	render := func(settings string) map[string]string {
		t.Helper()
		files, err := definition.RenderSettingsFiles([]byte(settings))
		if err != nil {
			t.Fatal(err)
		}
		if len(files) != 1 || files[0].Name != "serverconfig" {
			t.Fatalf("adapter rendered %d files, want one serverconfig artifact", len(files))
		}
		var document struct {
			XMLName    xml.Name `xml:"ServerSettings"`
			Properties []struct {
				Name  string `xml:"name,attr"`
				Value string `xml:"value,attr"`
			} `xml:"property"`
		}
		if err := xml.Unmarshal(files[0].Contents, &document); err != nil {
			t.Fatalf("invalid serverconfig XML: %v", err)
		}
		properties := make(map[string]string, len(document.Properties))
		for _, property := range document.Properties {
			if _, exists := properties[property.Name]; exists {
				t.Fatalf("serverconfig declares %q twice", property.Name)
			}
			properties[property.Name] = property.Value
		}
		return properties
	}
	minimal := render(`{"name":"First world","visibility":"unlisted"}`)
	explicit := render(`{"name":"R&D <world> \"Q\"","description":"Settings & plans","maxPlayers":16,"visibility":"unlisted"}`)
	if got := minimal["ServerName"]; got != "First world" {
		t.Errorf("minimal ServerName = %q, want First world", got)
	}
	for property, want := range map[string]string{
		"ServerName": "R&D <world> \"Q\"", "ServerDescription": "Settings & plans", "ServerMaxPlayerCount": "16",
	} {
		if got := explicit[property]; got != want {
			t.Errorf("explicit %s = %q, want %q", property, got, want)
		}
	}
	if _, present := minimal["ServerMaxPlayerCount"]; present {
		t.Error("omitted maxPlayers must leave the game default in effect")
	}
	for property, want := range map[string]string{
		"ServerVisibility": "0", "TelnetEnabled": "false", "WebDashboardEnabled": "false", "UserDataFolder": worldRoot,
	} {
		if minimal[property] != want || explicit[property] != want {
			t.Errorf("%s = %q with minimal settings and %q with explicit settings, want %q in both", property, minimal[property], explicit[property], want)
		}
	}
	for _, property := range []string{"GameWorld", "GameName"} {
		if first := minimal[property]; first == "" || explicit[property] != first {
			t.Errorf("%s changed with settings: %q to %q", property, first, explicit[property])
		}
	}
}
