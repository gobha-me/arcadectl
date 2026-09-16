// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

// Package factorio provides the first certified Arcadectl game adapter.
package factorio

import "github.com/gobha-me/arcadectl/internal/platform/game"

// Definition returns the curated Factorio adapter definition.
func Definition() game.Definition {
	return game.Definition{
		ID:              "factorio",
		DisplayName:     "Factorio",
		ImageRepository: "factoriotools/factorio",
		Endpoints: []game.Endpoint{
			{Name: "game", Protocol: game.ProtocolUDP, ContainerPort: 34197, Scope: game.ScopePlayer},
			{Name: "rcon", Protocol: game.ProtocolTCP, ContainerPort: 27015, Scope: game.ScopeAdmin},
		},
		PersistentPaths:   []game.PersistentPath{{Name: "world", MountPath: "/factorio"}},
		ReadinessEndpoint: "rcon",
		SettingsSchema: []byte(`{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "name": {"type": "string", "minLength": 1, "maxLength": 80},
    "description": {"type": "string", "maxLength": 200},
    "maxPlayers": {"type": "integer", "minimum": 1, "maximum": 65535},
    "visibility": {"type": "string", "enum": ["private", "lan", "public"]}
  }
}`),
		Capabilities: game.Capabilities{
			ColdBackup:       true,
			Restore:          true,
			GracefulShutdown: true,
		},
	}
}
