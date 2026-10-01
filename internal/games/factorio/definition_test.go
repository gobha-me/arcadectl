// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package factorio

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRenderSettings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		visibility string
		wantLAN    bool
	}{
		{name: "private", visibility: "private", wantLAN: false},
		{name: "LAN", visibility: "lan", wantLAN: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			definition := Definition()
			files, err := definition.RenderSettingsFiles(json.RawMessage(`{"name":"Factory","description":"safe","maxPlayers":16,"visibility":"` + test.visibility + `"}`))
			if err != nil {
				t.Fatalf("RenderSettingsFiles() error = %v", err)
			}
			if len(files) != 1 || files[0].MountPath != "/factorio/config/server-settings.json" {
				t.Fatalf("files = %#v", files)
			}
			var rendered map[string]any
			if err := json.Unmarshal(files[0].Contents, &rendered); err != nil {
				t.Fatalf("decode rendered settings: %v", err)
			}
			visibility := rendered["visibility"].(map[string]any)
			if visibility["public"] != false || visibility["lan"] != test.wantLAN {
				t.Fatalf("visibility = %#v, want public=false lan=%v", visibility, test.wantLAN)
			}
			if rendered["max_players"] != float64(16) {
				t.Fatalf("max_players = %#v", rendered["max_players"])
			}
			for _, forbidden := range []string{"username", "token", "password"} {
				if strings.Contains(strings.ToLower(string(files[0].Contents)), forbidden) {
					t.Fatalf("rendered settings contain credential key %q", forbidden)
				}
			}
		})
	}
}

func TestRenderMinimalSettingsIncludesEngineRequiredDescription(t *testing.T) {
	t.Parallel()

	files, err := Definition().RenderSettingsFiles(json.RawMessage(`{"name":"Factory","visibility":"private"}`))
	if err != nil {
		t.Fatalf("render schema-minimal settings: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("rendered files = %d, want 1", len(files))
	}
	var rendered map[string]any
	if err := json.Unmarshal(files[0].Contents, &rendered); err != nil {
		t.Fatalf("decode rendered settings: %v", err)
	}
	if description, present := rendered["description"]; !present || description != "" {
		t.Fatalf("description = %#v (present=%v), want explicit empty string", description, present)
	}
	if rendered["max_players"] != float64(0) {
		t.Fatalf("omitted maxPlayers = %#v, want engine default unlimited (0)", rendered["max_players"])
	}
	visibility, ok := rendered["visibility"].(map[string]any)
	if !ok || visibility["public"] != false || visibility["lan"] != false {
		t.Fatalf("private visibility = %#v", rendered["visibility"])
	}
	for _, forbidden := range []string{"username", "token", "password"} {
		if strings.Contains(strings.ToLower(string(files[0].Contents)), forbidden) {
			t.Fatalf("minimal settings contain credential key %q", forbidden)
		}
	}
}

func TestRenderSettingsRejectsPublicVisibilityAndCredentials(t *testing.T) {
	t.Parallel()

	definition := Definition()
	for _, raw := range []string{
		`{"name":"Factory","visibility":"public"}`,
		`{"name":"Factory","visibility":"private","token":"secret"}`,
		`{"name":"Factory","visibility":"private","game_password":"secret"}`,
	} {
		if _, err := definition.RenderSettingsFiles(json.RawMessage(raw)); err == nil {
			t.Fatalf("RenderSettingsFiles(%s) unexpectedly succeeded", raw)
		}
	}
}
