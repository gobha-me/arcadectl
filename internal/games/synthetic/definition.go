// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

// Package synthetic provides a deliberately non-Factorio conformance adapter.
// It is a test fixture and is not included in the production catalog.
package synthetic

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/gobha-me/arcadectl/internal/platform/game"
)

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
		ReadinessMode:     game.ReadinessTCP,
		SettingsSchema: []byte(`{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "seed": {"type": "string", "minLength": 1, "maxLength": 64, "pattern": "^[a-z0-9-]+$"},
    "motd": {"type": "string", "minLength": 1, "maxLength": 128}
  }
}`),
		ConfigurationTargets: []game.ConfigurationTarget{
			{Name: "echo-config", MountPath: "/srv/world/config/echo.conf"},
			{Name: "motd", MountPath: "/srv/world/config/motd.txt"},
			{Name: "seed", MountPath: "/srv/world/config/seed.txt"},
		},
		RenderSettings: func(raw json.RawMessage) (map[string][]byte, error) {
			settings := struct {
				Seed string `json:"seed"`
				MOTD string `json:"motd"`
			}{Seed: "default-seed", MOTD: "Arcadectl conformance server"}
			decoder := json.NewDecoder(bytes.NewReader(raw))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&settings); err != nil {
				return nil, fmt.Errorf("decode synthetic settings: %w", err)
			}
			var extra any
			if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
				if err == nil {
					return nil, errors.New("synthetic settings must contain one JSON value")
				}
				return nil, fmt.Errorf("decode trailing synthetic settings: %w", err)
			}
			if len(settings.Seed) == 0 || len(settings.Seed) > 64 {
				return nil, errors.New("synthetic seed must contain between 1 and 64 characters")
			}
			for _, character := range settings.Seed {
				if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
					return nil, errors.New("synthetic seed contains an unsupported character")
				}
			}
			if len(settings.MOTD) == 0 || len(settings.MOTD) > 128 || bytes.ContainsAny([]byte(settings.MOTD), "\r\n") {
				return nil, errors.New("synthetic MOTD must be a single line between 1 and 128 characters")
			}
			return map[string][]byte{
				"echo-config": []byte("listen=0.0.0.0:8080\n"),
				"motd":        []byte(settings.MOTD + "\n"),
				"seed":        []byte(settings.Seed + "\n"),
			}, nil
		},
		RuntimeIdentity: game.RuntimeIdentity{UserID: 65532, GroupID: 65532, FSGroup: 65532},
		Capabilities: game.Capabilities{
			ColdBackup:       true,
			Restore:          true,
			GracefulShutdown: false,
		},
	}
}
