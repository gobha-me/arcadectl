// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package game

import (
	"encoding/json"
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
		ReadinessMode:     ReadinessTCP,
		SettingsSchema:    []byte(`{"type":"object","additionalProperties":false}`),
		ConfigurationTargets: []ConfigurationTarget{{
			Name:      "server-config",
			MountPath: "/srv/world/config/server.conf",
		}},
		RenderSettings: func(json.RawMessage) (map[string][]byte, error) {
			return map[string][]byte{"server-config": []byte("enabled=true\n")}, nil
		},
		RuntimeIdentity: RuntimeIdentity{UserID: 1000, GroupID: 1000, FSGroup: 1000},
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
		{"admin readiness", func(d *Definition) {
			d.Endpoints = append(d.Endpoints, Endpoint{Name: "admin", Protocol: ProtocolTCP, ContainerPort: 8081, Scope: ScopeAdmin})
			d.ReadinessEndpoint = "admin"
		}, "must be player-scoped"},
		{"private readiness on player endpoint", func(d *Definition) { d.ReadinessMode = ReadinessPrivateExec }, "administrator or internal"},
		{"unknown readiness mode", func(d *Definition) { d.ReadinessMode = "Shell" }, "unsupported readiness mode"},
		{"root persistence", func(d *Definition) { d.PersistentPaths[0].MountPath = "/" }, "non-root"},
		{"reserved persistence", func(d *Definition) { d.PersistentPaths[0].MountPath = "/arcadectl/data" }, "reserved platform mount"},
		{"overlapping persistence", func(d *Definition) {
			d.PersistentPaths = append(d.PersistentPaths, PersistentPath{Name: "nested", MountPath: "/srv/world/nested"})
		}, "overlaps"},
		{"root runtime user", func(d *Definition) { d.RuntimeIdentity.UserID = 0 }, "runtime user ID"},
		{"root runtime group", func(d *Definition) { d.RuntimeIdentity.GroupID = 0 }, "runtime group ID"},
		{"root runtime filesystem group", func(d *Definition) { d.RuntimeIdentity.FSGroup = 0 }, "filesystem group ID"},
		{"configuration outside data", func(d *Definition) { d.ConfigurationTargets[0].MountPath = "/etc/server.conf" }, "nested below"},
		{"duplicate configuration target", func(d *Definition) {
			d.ConfigurationTargets = append(d.ConfigurationTargets, d.ConfigurationTargets[0])
		}, "duplicated"},
		{"overlapping configuration target", func(d *Definition) {
			d.ConfigurationTargets = append(d.ConfigurationTargets, ConfigurationTarget{Name: "nested", MountPath: "/srv/world/config/server.conf/nested"})
		}, "overlaps"},
		{"restore without backup", func(d *Definition) { d.Capabilities.ColdBackup = false }, "requires cold backup"},
		{"missing schema", func(d *Definition) { d.SettingsSchema = nil }, "schema is required"},
		{"missing targets", func(d *Definition) { d.ConfigurationTargets = nil }, "configuration target"},
		{"missing renderer", func(d *Definition) { d.RenderSettings = nil }, "renderer is required"},
		{"non-object schema", func(d *Definition) { d.SettingsSchema = []byte(`{"type":"array"}`) }, "describe an object"},
		{"nested reference", func(d *Definition) {
			d.SettingsSchema = []byte(`{"type":"object","properties":{"value":{"$ref":"https://example.invalid/schema"}}}`)
		}, "keyword \"$ref\" is not allowed"},
		{"oversized schema", func(d *Definition) { d.SettingsSchema = []byte(strings.Repeat(" ", 64*1024+1)) }, "64 KiB"},
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
	clone.ConfigurationTargets[0].MountPath = "/changed/config"
	clone.SettingsSchema[0] = 'x'

	if original.Endpoints[0].Name == "changed" || original.PersistentPaths[0].MountPath == "/changed" || original.ConfigurationTargets[0].MountPath == "/changed/config" || original.SettingsSchema[0] == 'x' {
		t.Fatal("Clone() returned aliased mutable data")
	}
}
