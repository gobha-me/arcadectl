// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package game

import (
	"strings"
	"testing"
)

func validDefinition() Definition {
	return Definition{
		ID:              "test-game",
		DisplayName:     "Test Game",
		ImageRepository: "registry.example/test/game",
		Endpoints: []Endpoint{{
			Name:          "players",
			Protocol:      ProtocolTCP,
			ContainerPort: 8080,
			Scope:         ScopePlayer,
		}},
		PersistentPaths:   []PersistentPath{{Name: "world", MountPath: "/srv/world"}},
		ReadinessEndpoint: "players",
		SettingsSchema:    []byte(`{"type":"object","additionalProperties":false}`),
		Capabilities: Capabilities{
			ColdBackup:       true,
			Restore:          true,
			GracefulShutdown: true,
		},
	}
}

func TestDefinitionValidate(t *testing.T) {
	t.Parallel()

	if err := validDefinition().Validate(); err != nil {
		t.Fatalf("valid definition rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*Definition)
		want   string
	}{
		{"bad id", func(d *Definition) { d.ID = "Bad ID" }, "game id"},
		{"missing image", func(d *Definition) { d.ImageRepository = "" }, "image repository"},
		{"digest in repository", func(d *Definition) { d.ImageRepository += "@sha256:deadbeef" }, "must not contain"},
		{"missing endpoints", func(d *Definition) { d.Endpoints = nil }, "at least one endpoint"},
		{"duplicate endpoint", func(d *Definition) { d.Endpoints = append(d.Endpoints, d.Endpoints[0]) }, "duplicated"},
		{"no player endpoint", func(d *Definition) { d.Endpoints[0].Scope = ScopeAdmin }, "player endpoint"},
		{"udp readiness", func(d *Definition) { d.Endpoints[0].Protocol = ProtocolUDP }, "must use TCP"},
		{"root persistence", func(d *Definition) { d.PersistentPaths[0].MountPath = "/" }, "non-root"},
		{"restore without backup", func(d *Definition) { d.Capabilities.ColdBackup = false }, "requires cold backup"},
		{"missing schema", func(d *Definition) { d.SettingsSchema = nil }, "schema is required"},
		{"non-object schema", func(d *Definition) { d.SettingsSchema = []byte(`{"type":"array"}`) }, "describe an object"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			definition := validDefinition()
			test.mutate(&definition)
			err := definition.Validate()
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Validate() error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestResolvedImage(t *testing.T) {
	t.Parallel()

	digest := "sha256:" + strings.Repeat("a", 64)
	got, err := ResolvedImage("registry.example/game/server", digest)
	if err != nil {
		t.Fatalf("ResolvedImage() error = %v", err)
	}
	if want := "registry.example/game/server@" + digest; got != want {
		t.Fatalf("ResolvedImage() = %q, want %q", got, want)
	}

	if _, err := ResolvedImage("registry.example/game/server", "latest"); err == nil {
		t.Fatal("ResolvedImage() accepted a mutable tag")
	}
}

func TestCloneDoesNotAlias(t *testing.T) {
	t.Parallel()

	original := validDefinition()
	clone := original.Clone()
	clone.Endpoints[0].Name = "changed"
	clone.PersistentPaths[0].MountPath = "/changed"
	clone.SettingsSchema[0] = 'x'

	if original.Endpoints[0].Name == "changed" || original.PersistentPaths[0].MountPath == "/changed" || original.SettingsSchema[0] == 'x' {
		t.Fatal("Clone() returned aliased mutable data")
	}
}
