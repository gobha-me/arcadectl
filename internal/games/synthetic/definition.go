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
		SettingsSchema:    []byte(`{"type":"object","additionalProperties":false}`),
		ConfigurationTargets: []game.ConfigurationTarget{
			{Name: "echo-config", MountPath: "/srv/world/config/echo.conf"},
			{Name: "motd", MountPath: "/srv/world/config/motd.txt"},
		},
		RenderSettings: func(raw json.RawMessage) (map[string][]byte, error) {
			decoder := json.NewDecoder(bytes.NewReader(raw))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&struct{}{}); err != nil {
				return nil, fmt.Errorf("decode synthetic settings: %w", err)
			}
			var extra any
			if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
				if err == nil {
					return nil, errors.New("synthetic settings must contain one JSON value")
				}
				return nil, fmt.Errorf("decode trailing synthetic settings: %w", err)
			}
			return map[string][]byte{
				"echo-config": []byte("listen=0.0.0.0:8080\n"),
				"motd":        []byte("Arcadectl conformance server\n"),
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
