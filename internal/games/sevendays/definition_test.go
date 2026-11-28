// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package sevendays_test

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"reflect"
	"strings"
	"testing"

	"github.com/gobha-me/arcadectl/internal/catalog"
	"github.com/gobha-me/arcadectl/internal/games/factorio"
	"github.com/gobha-me/arcadectl/internal/games/sevendays"
	"github.com/gobha-me/arcadectl/internal/games/synthetic"
	"github.com/gobha-me/arcadectl/internal/platform/game"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
)

func renderedProperties(t *testing.T, raw string) map[string]string {
	t.Helper()
	files, err := sevendays.Definition().RenderSettingsFiles(json.RawMessage(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0].Name != "serverconfig" || files[0].MountPath != "/sdtd/config/serverconfig.xml" {
		t.Fatalf("unexpected configuration targets: %#v", files)
	}
	var document struct {
		XMLName    xml.Name `xml:"ServerSettings"`
		Properties []struct {
			Name  string `xml:"name,attr"`
			Value string `xml:"value,attr"`
		} `xml:"property"`
	}
	if err := xml.Unmarshal(files[0].Contents, &document); err != nil {
		t.Fatal(err)
	}
	properties := map[string]string{}
	for _, property := range document.Properties {
		if _, duplicate := properties[property.Name]; duplicate {
			t.Fatalf("duplicate property %q", property.Name)
		}
		properties[property.Name] = property.Value
	}
	return properties
}

func TestDefinitionContractAndProductionExclusion(t *testing.T) {
	definition := sevendays.Definition()
	if err := definition.Validate(); err != nil {
		t.Fatal(err)
	}
	if definition.ID != "seven-days-to-die" || definition.DisplayName != "7 Days to Die" || definition.ImageRepository != "ghcr.io/gobha-me/arcadectl-7dtd" {
		t.Fatal("experimental adapter identity changed")
	}
	want := []game.Endpoint{
		{Name: "game-tcp", Protocol: game.ProtocolTCP, ContainerPort: 26900, Scope: game.ScopePlayer},
		{Name: "game-udp", Protocol: game.ProtocolUDP, ContainerPort: 26900, Scope: game.ScopePlayer},
		{Name: "steam-udp", Protocol: game.ProtocolUDP, ContainerPort: 26901, Scope: game.ScopePlayer},
		{Name: "network-udp", Protocol: game.ProtocolUDP, ContainerPort: 26902, Scope: game.ScopePlayer},
		{Name: "reserved-udp", Protocol: game.ProtocolUDP, ContainerPort: 26903, Scope: game.ScopePlayer},
	}
	if !reflect.DeepEqual(definition.Endpoints, want) {
		t.Fatalf("endpoints: %#v", definition.Endpoints)
	}
	if definition.ReadinessMode != game.ReadinessTCP || definition.ReadinessEndpoint != "game-tcp" {
		t.Fatal("readiness must use the player TCP endpoint")
	}
	if !reflect.DeepEqual(definition.PersistentPaths, []game.PersistentPath{{Name: "world", MountPath: "/sdtd"}}) {
		t.Fatal("persistent world path changed")
	}
	if definition.RuntimeIdentity.UserID == 0 || definition.RuntimeIdentity.GroupID == 0 || definition.RuntimeIdentity.FSGroup == 0 || definition.RuntimeIdentity == factorio.Definition().RuntimeIdentity || definition.RuntimeIdentity == synthetic.Definition().RuntimeIdentity {
		t.Fatal("runtime identity must be distinct and non-root")
	}
	if definition.Capabilities != (game.Capabilities{ColdBackup: true, Restore: true, GracefulShutdown: true}) {
		t.Fatal("declared lifecycle capabilities changed")
	}
	builtins, err := catalog.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	if got := builtins.List(); len(got) != 1 || got[0].ID != "factorio" {
		t.Fatal("experimental adapter entered the production catalog")
	}
}

func TestVersionPolicyAdmitsOnlyReleaseTokens(t *testing.T) {
	for _, version := range []string{"V2.5", "V3.3.0"} {
		if got, err := game.ResolveVersionTag(sevendays.Definition(), version); err != nil || got != version {
			t.Fatalf("release token %q: %q, %v", version, got, err)
		}
	}
	for _, version := range []string{"latest", "3.3.0", "V3.3.0 b1", "V3.3.0/escape", "V1000.1", "V3.3.0;cmd"} {
		if _, err := game.ResolveVersionTag(sevendays.Definition(), version); err == nil {
			t.Errorf("unsafe release token accepted: %q", version)
		}
	}
}

func TestSettingsMinimalFullAndFixedIdentity(t *testing.T) {
	minimal := renderedProperties(t, `{"name":"first","visibility":"unlisted"}`)
	want := map[string]string{"ServerName": "first", "ServerDescription": "", "ServerPort": "26900", "ServerVisibility": "0", "TelnetEnabled": "false", "WebDashboardEnabled": "false", "GameWorld": "Navezgane", "GameName": "arcadectl-world", "UserDataFolder": "/sdtd"}
	if !reflect.DeepEqual(minimal, want) {
		t.Fatalf("minimal properties = %#v", minimal)
	}
	full := renderedProperties(t, `{"name":"second","description":"different","maxPlayers":64,"visibility":"unlisted"}`)
	want["ServerName"], want["ServerDescription"], want["ServerMaxPlayerCount"] = "second", "different", "64"
	if !reflect.DeepEqual(full, want) {
		t.Fatalf("full properties = %#v", full)
	}
	for _, name := range []string{"GameWorld", "GameName", "UserDataFolder", "TelnetEnabled", "WebDashboardEnabled", "ServerVisibility"} {
		if minimal[name] != full[name] {
			t.Errorf("display settings changed fixed property %s", name)
		}
	}
	if got := renderedProperties(t, `{"name":"one","maxPlayers":1,"visibility":"unlisted"}`)["ServerMaxPlayerCount"]; got != "1" {
		t.Fatalf("minimum player count: %q", got)
	}
}

func TestSettingsRejectUnsafeInput(t *testing.T) {
	for _, raw := range []string{
		`{}`, `null`, `[]`, `{`, `{"name":"x","visibility":"unlisted"} {}`, `{"name":"x","visibility":"unlisted"} junk`,
		`{"name":"x","visibility":"unlisted","password":"no"}`, `{"name":"","visibility":"unlisted"}`, `{"name":"x"}`,
		`{"name":"line\nbreak","visibility":"unlisted"}`, `{"name":"x","description":"tab\tcontrol","visibility":"unlisted"}`,
		`{"name":"x\u0000","visibility":"unlisted"}`, `{"name":"x","description":"\u0085","visibility":"unlisted"}`,
		`{"name":"x\uffff","visibility":"unlisted"}`, `{"name":"x","description":"\ufffe","visibility":"unlisted"}`,
		`{"name":"x","maxPlayers":0,"visibility":"unlisted"}`, `{"name":"x","maxPlayers":-1,"visibility":"unlisted"}`, `{"name":"x","maxPlayers":65,"visibility":"unlisted"}`,
		`{"name":"x","maxPlayers":1.5,"visibility":"unlisted"}`, `{"name":"x","maxPlayers":"8","visibility":"unlisted"}`, `{"name":"x","maxPlayers":null,"visibility":"unlisted"}`,
		`{"name":"x","visibility":"private"}`, `{"name":"` + strings.Repeat("a", 81) + `","visibility":"unlisted"}`,
		`{"name":"x","description":"` + strings.Repeat("a", 201) + `","visibility":"unlisted"}`,
		"{\"name\":\"\xff\",\"visibility\":\"unlisted\"}",
	} {
		if _, err := sevendays.Definition().RenderSettingsFiles(json.RawMessage(raw)); err == nil {
			t.Errorf("unsafe settings accepted: %q", raw)
		}
	}
	for _, visibility := range []string{"public", "listed"} {
		_, err := sevendays.Definition().RenderSettingsFiles(json.RawMessage(`{"name":"x","visibility":"` + visibility + `"}`))
		if err == nil || !strings.Contains(err.Error(), "future secret-reference contract") {
			t.Fatalf("listed visibility lacks actionable refusal: %v", err)
		}
	}
}

func TestSchemaAdmitsOnlyRuntimeSafeSettings(t *testing.T) {
	document, err := jsonschema.UnmarshalJSON(bytes.NewReader(sevendays.Definition().SettingsSchema))
	if err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource("adapter.json", document); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile("adapter.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		raw   string
		valid bool
	}{
		{`{"name":"minimal","visibility":"unlisted"}`, true},
		{`{"name":"full","description":"safe","visibility":"unlisted","maxPlayers":64}`, true},
		{`{}`, false}, {`{"name":"x"}`, false}, {`{"visibility":"unlisted"}`, false},
		{`{"name":"","visibility":"unlisted"}`, false},
		{`{"name":"` + strings.Repeat("a", 81) + `","visibility":"unlisted"}`, false},
		{`{"name":"x","description":"` + strings.Repeat("a", 201) + `","visibility":"unlisted"}`, false},
		{`{"name":"x","maxPlayers":0,"visibility":"unlisted"}`, false},
		{`{"name":"x","maxPlayers":65,"visibility":"unlisted"}`, false},
		{`{"name":"x","maxPlayers":1.5,"visibility":"unlisted"}`, false},
		{`{"name":"x","maxPlayers":null,"visibility":"unlisted"}`, false},
		{`{"name":"x","visibility":"listed"}`, false},
		{`{"name":"x","visibility":"public"}`, false},
		{`{"name":"x","visibility":"unlisted","GameName":"new-world"}`, false},
	} {
		value, err := jsonschema.UnmarshalJSON(strings.NewReader(test.raw))
		if err != nil {
			t.Fatal(err)
		}
		if err := schema.Validate(value); (err == nil) != test.valid {
			t.Errorf("schema validity = %v, want %v for %s", err == nil, test.valid, test.raw)
		}
	}
}

func TestSettingsXMLEscapingAndUnicodeBounds(t *testing.T) {
	name := `<&"'>`
	raw, err := json.Marshal(map[string]any{"name": name, "description": strings.Repeat("界", 200), "visibility": "unlisted"})
	if err != nil {
		t.Fatal(err)
	}
	properties := renderedProperties(t, string(raw))
	if properties["ServerName"] != name || properties["ServerDescription"] != strings.Repeat("界", 200) {
		t.Fatal("XML did not preserve exact untrusted text")
	}
	if renderedProperties(t, `{"name":"`+strings.Repeat("界", 80)+`","visibility":"unlisted"}`)["ServerName"] != strings.Repeat("界", 80) {
		t.Fatal("valid Unicode name boundary rejected")
	}
}
