// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

// Package sevendays provides an experimental, unregistered adapter fixture.
package sevendays

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strconv"
	"unicode"
	"unicode/utf8"

	"github.com/gobha-me/arcadectl/internal/platform/game"
)

// Definition returns an experimental adapter, never a production catalog entry.
// The image repository is a placeholder; no image is built or pulled here.
func Definition() game.Definition {
	return game.Definition{
		ID: "seven-days-to-die", DisplayName: "7 Days to Die",
		ImageRepository: "ghcr.io/gobha-me/arcadectl-7dtd",
		// Upstream release tokens use Vmajor.minor[.patch], without build labels.
		// Restrict image selection to that bounded token, e.g. V2.5 or V3.3.0.
		VersionPolicy: &game.VersionPolicy{Pattern: `^V[0-9]{1,3}\.[0-9]{1,3}(\.[0-9]{1,3})?$`},
		// The upstream support FAQ requires TCP 26900 and UDP 26900–26903;
		// even the currently unused +3 port may affect joining if omitted:
		// https://community.thefunpimps.com/threads/support-faq-information-and-common-solutions.3998/
		Endpoints: []game.Endpoint{
			{Name: "game-tcp", Protocol: game.ProtocolTCP, ContainerPort: 26900, Scope: game.ScopePlayer},
			{Name: "game-udp", Protocol: game.ProtocolUDP, ContainerPort: 26900, Scope: game.ScopePlayer},
			{Name: "steam-udp", Protocol: game.ProtocolUDP, ContainerPort: 26901, Scope: game.ScopePlayer},
			{Name: "network-udp", Protocol: game.ProtocolUDP, ContainerPort: 26902, Scope: game.ScopePlayer},
			{Name: "reserved-udp", Protocol: game.ProtocolUDP, ContainerPort: 26903, Scope: game.ScopePlayer},
		},
		PersistentPaths:   []game.PersistentPath{{Name: "world", MountPath: "/sdtd"}},
		ReadinessEndpoint: "game-tcp", ReadinessMode: game.ReadinessTCP,
		ConfigurationTargets: []game.ConfigurationTarget{{Name: "serverconfig", MountPath: "/sdtd/config/serverconfig.xml"}},
		RuntimeIdentity:      game.RuntimeIdentity{UserID: 10001, GroupID: 10001, FSGroup: 10001},
		Capabilities:         game.Capabilities{ColdBackup: true, Restore: true, GracefulShutdown: true},
		SettingsSchema: []byte(`{
  "type":"object", "additionalProperties":false,
  "properties":{
    "name":{"type":"string","minLength":1,"maxLength":80},
    "description":{"type":"string","maxLength":200},
    "maxPlayers":{"type":"integer","minimum":1,"maximum":64},
    "visibility":{"type":"string","enum":["unlisted"]}
  },
  "required":["name","visibility"]
}`),
		RenderSettings: renderSettings,
	}
}

type settings struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	MaxPlayers  json.RawMessage `json:"maxPlayers"`
	Visibility  string          `json:"visibility"`
}

type property struct {
	Name  string `xml:"name,attr"`
	Value string `xml:"value,attr"`
}

type configuration struct {
	XMLName    xml.Name   `xml:"ServerSettings"`
	Properties []property `xml:"property"`
}

func renderSettings(raw json.RawMessage) (map[string][]byte, error) {
	if !utf8.Valid(raw) {
		return nil, errors.New("settings must be UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var input settings
	if err := decoder.Decode(&input); err != nil {
		return nil, fmt.Errorf("decode settings: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("settings must contain one JSON value")
	}
	if !safeText(input.Name, 1, 80) {
		return nil, errors.New("name must contain 1–80 characters without controls")
	}
	if !safeText(input.Description, 0, 200) {
		return nil, errors.New("description must contain at most 200 characters without controls")
	}
	if input.Visibility == "public" || input.Visibility == "listed" {
		return nil, errors.New("listed visibility requires the future secret-reference contract")
	}
	if input.Visibility != "unlisted" {
		return nil, errors.New("visibility must be unlisted")
	}
	properties := []property{
		{"ServerName", input.Name}, {"ServerDescription", input.Description},
		{"ServerPort", "26900"}, {"ServerVisibility", "0"},
		{"TelnetEnabled", "false"}, {"WebDashboardEnabled", "false"},
		// Fixed identity keeps edits to display settings from selecting a new world.
		{"GameWorld", "Navezgane"}, {"GameName", "arcadectl-world"}, {"UserDataFolder", "/sdtd"},
	}
	if len(input.MaxPlayers) != 0 {
		var players int
		if err := json.Unmarshal(input.MaxPlayers, &players); err != nil || players < 1 || players > 64 {
			return nil, errors.New("maxPlayers must be an integer between 1 and 64")
		}
		properties = append(properties, property{"ServerMaxPlayerCount", strconv.Itoa(players)})
	}
	contents, err := xml.MarshalIndent(configuration{Properties: properties}, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode configuration: %w", err)
	}
	return map[string][]byte{"serverconfig": append(contents, '\n')}, nil
}

func safeText(value string, minimum, maximum int) bool {
	length := utf8.RuneCountInString(value)
	if length < minimum || length > maximum {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || character == '\ufffe' || character == '\uffff' {
			return false
		}
	}
	return true
}
