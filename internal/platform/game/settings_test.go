// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package game

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRenderSettingsFilesReturnsStableIsolatedOutput(t *testing.T) {
	t.Parallel()

	definition := validDefinition()
	definition.ConfigurationTargets = []ConfigurationTarget{
		{Name: "z-config", MountPath: "/srv/world/config/z.conf"},
		{Name: "a-config", MountPath: "/srv/world/config/a.conf"},
	}
	shared := []byte("enabled=true\n")
	definition.RenderSettings = func(raw json.RawMessage) (map[string][]byte, error) {
		raw[0] = '['
		return map[string][]byte{"z-config": shared, "a-config": []byte("mode=test\n")}, nil
	}
	settings := json.RawMessage(`{}`)
	files, err := definition.RenderSettingsFiles(settings)
	if err != nil {
		t.Fatalf("RenderSettingsFiles() error = %v", err)
	}
	if string(settings) != `{}` {
		t.Fatalf("renderer mutated input settings: %q", settings)
	}
	if len(files) != 2 || files[0].Name != "a-config" || files[1].Name != "z-config" {
		t.Fatalf("files = %#v, want stable name order", files)
	}
	files[1].Contents[0] = 'x'
	if string(shared) != "enabled=true\n" {
		t.Fatal("returned configuration aliases renderer-owned bytes")
	}
}

func TestRenderSettingsFilesRejectsUnsafeOutput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		render SettingsRenderer
		want   string
	}{
		{"missing target", func(json.RawMessage) (map[string][]byte, error) { return map[string][]byte{}, nil }, "does not match"},
		{"unknown target", func(json.RawMessage) (map[string][]byte, error) {
			return map[string][]byte{"other.conf": []byte("x")}, nil
		}, "omitted declared"},
		{"empty file", func(json.RawMessage) (map[string][]byte, error) {
			return map[string][]byte{"server-config": nil}, nil
		}, "is empty"},
		{"NUL file", func(json.RawMessage) (map[string][]byte, error) {
			return map[string][]byte{"server-config": []byte{'x', 0}}, nil
		}, "non-NUL UTF-8"},
		{"oversized output", func(json.RawMessage) (map[string][]byte, error) {
			return map[string][]byte{"server-config": []byte(strings.Repeat("x", MaxRenderedSettingsBytes+1))}, nil
		}, "exceeds"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			definition := validDefinition()
			definition.RenderSettings = test.render
			_, err := definition.RenderSettingsFiles(json.RawMessage(`{}`))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("RenderSettingsFiles() error = %v, want substring %q", err, test.want)
			}
		})
	}
}
