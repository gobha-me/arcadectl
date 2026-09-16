// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

// Package synthetic provides a deliberately non-Factorio conformance adapter.
// It is a test fixture and is not included in the production catalog.
package synthetic

import "github.com/gobha-me/arcadectl/internal/platform/game"

// Definition returns a TCP-only adapter with a distinct data layout.
func Definition() game.Definition {
	return game.Definition{
		ID:              "conformance-echo",
		DisplayName:     "Conformance Echo Server",
		ImageRepository: "ghcr.io/gobha-me/arcadectl-conformance-server",
		Endpoints: []game.Endpoint{{
			Name:          "players",
			Protocol:      game.ProtocolTCP,
			ContainerPort: 8080,
			Scope:         game.ScopePlayer,
		}},
		PersistentPaths:   []game.PersistentPath{{Name: "state", MountPath: "/srv/world"}},
		ReadinessEndpoint: "players",
		SettingsSchema:    []byte(`{"type":"object","additionalProperties":false}`),
		Capabilities: game.Capabilities{
			ColdBackup:       true,
			Restore:          true,
			GracefulShutdown: false,
		},
	}
}
