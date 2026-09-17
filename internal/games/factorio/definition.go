// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

// Package factorio provides the first certified Arcadectl game adapter.
package factorio

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/gobha-me/arcadectl/internal/platform/game"
)

type settings struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	MaxPlayers  int    `json:"maxPlayers,omitempty"`
	Visibility  string `json:"visibility"`
}

type serverSettings struct {
	Name        string           `json:"name"`
	Description string           `json:"description,omitempty"`
	MaxPlayers  int              `json:"max_players"`
	Visibility  serverVisibility `json:"visibility"`
}

type serverVisibility struct {
	Public bool `json:"public"`
	LAN    bool `json:"lan"`
}

// Definition returns the curated Factorio adapter definition.
func Definition() game.Definition {
	return game.Definition{
		ID:              "factorio",
		DisplayName:     "Factorio",
		ImageRepository: "ghcr.io/gobha-me/arcadectl-factorio",
		Endpoints: []game.Endpoint{
			{Name: "game", Protocol: game.ProtocolUDP, ContainerPort: 34197, Scope: game.ScopePlayer},
			{Name: "rcon", Protocol: game.ProtocolTCP, ContainerPort: 27015, Scope: game.ScopeAdmin},
		},
		PersistentPaths: []game.PersistentPath{{Name: "world", MountPath: "/factorio"}},
		// Factorio's only TCP endpoint is administrator-only RCON. The fixed
		// image helper checks it silently so the port cannot appear in probe
		// Events or the generic platform contract.
		ReadinessEndpoint: "rcon",
		ReadinessMode:     game.ReadinessPrivateExec,
		SettingsSchema: []byte(`{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "name": {"type": "string", "minLength": 1, "maxLength": 80},
    "description": {"type": "string", "maxLength": 200},
    "maxPlayers": {"type": "integer", "minimum": 1, "maximum": 65535},
    "visibility": {"type": "string", "enum": ["private", "lan"]}
  },
  "required": ["name", "visibility"]
}`),
		ConfigurationTargets: []game.ConfigurationTarget{{
			Name:      "server-settings",
			MountPath: "/factorio/config/server-settings.json",
		}},
		RenderSettings:  renderSettings,
		RuntimeIdentity: game.RuntimeIdentity{UserID: 845, GroupID: 845, FSGroup: 845},
		Capabilities: game.Capabilities{
			ColdBackup:       true,
			Restore:          true,
			GracefulShutdown: true,
		},
	}
}

func renderSettings(raw json.RawMessage) (map[string][]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var input settings
	if err := decoder.Decode(&input); err != nil {
		return nil, fmt.Errorf("decode Factorio settings: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return nil, err
	}
	if input.Name == "" {
		return nil, errors.New("Factorio server name is required")
	}
	visibility := serverVisibility{}
	switch input.Visibility {
	case "private":
	case "lan":
		visibility.LAN = true
	case "public":
		return nil, errors.New("public Factorio visibility requires the future secret-reference contract")
	default:
		return nil, fmt.Errorf("unsupported Factorio visibility %q", input.Visibility)
	}
	contents, err := json.MarshalIndent(serverSettings{
		Name:        input.Name,
		Description: input.Description,
		MaxPlayers:  input.MaxPlayers,
		Visibility:  visibility,
	}, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode Factorio server settings: %w", err)
	}
	contents = append(contents, '\n')
	return map[string][]byte{"server-settings": contents}, nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("Factorio settings must contain one JSON value")
		}
		return fmt.Errorf("decode trailing Factorio settings: %w", err)
	}
	return nil
}
