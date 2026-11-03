// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package adaptertest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/gobha-me/arcadectl/internal/platform/game"
)

func fixtureCase() Case {
	return Case{
		Definition: game.Definition{
			ID: "kit-fixture", DisplayName: "Kit Fixture", ImageRepository: "registry.example.com/game/fixture",
			VersionPolicy:        &game.VersionPolicy{Pattern: `^[0-9]+$`},
			Endpoints:            []game.Endpoint{{Name: "players", Protocol: game.ProtocolTCP, ContainerPort: 8080, Scope: game.ScopePlayer}},
			PersistentPaths:      []game.PersistentPath{{Name: "state", MountPath: "/srv/state"}},
			SettingsSchema:       json.RawMessage(`{"type":"object","properties":{"name":{"type":"string"}}}`),
			ConfigurationTargets: []game.ConfigurationTarget{{Name: "config", MountPath: "/srv/state/config.txt"}},
			RenderSettings:       fixtureRenderer(true, true),
			RuntimeIdentity:      game.RuntimeIdentity{UserID: 1000, GroupID: 1000, FSGroup: 1000},
		},
		Valid:      []json.RawMessage{json.RawMessage(`{"name":"one"}`)},
		Equivalent: []EquivalentPair{{Left: json.RawMessage(`{"name":"one"}`), Right: json.RawMessage(`{ "name": "one" }`)}},
		Invalid:    []json.RawMessage{json.RawMessage(`{"name":""}`)},
	}
}

// These are real deliberately faulty adapter implementations. Check itself and
// the platform's rendering/clone functions are never replaced with mocks.
func fixtureRenderer(strict, eof bool) game.SettingsRenderer {
	return func(raw json.RawMessage) (map[string][]byte, error) {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		if strict {
			decoder.DisallowUnknownFields()
		}
		var input struct {
			Name string `json:"name"`
		}
		if err := decoder.Decode(&input); err != nil {
			return nil, err
		}
		if eof {
			var extra any
			if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
				return nil, errors.New("expected one JSON value")
			}
		}
		if input.Name == "" {
			return nil, errors.New("name is required")
		}
		return map[string][]byte{"config": []byte(input.Name)}, nil
	}
}

func hasFailure(failures []error, text string) bool {
	for _, err := range failures {
		if strings.Contains(err.Error(), text) {
			return true
		}
	}
	return false
}

func TestCheckAcceptsConformingAdapterAndPreservesCaller(t *testing.T) {
	c := fixtureCase()
	before := detached(c.Definition)
	validBefore := bytes.Clone(c.Valid[0])
	if failures := Check(c); len(failures) != 0 {
		t.Fatalf("conforming adapter failed: %v", failures)
	}
	if failures := Check(c); len(failures) != 0 {
		t.Fatalf("repeat check failed: %v", failures)
	}
	if !reflect.DeepEqual(before.Endpoints, c.Definition.Endpoints) ||
		!reflect.DeepEqual(before.PersistentPaths, c.Definition.PersistentPaths) ||
		!reflect.DeepEqual(before.ConfigurationTargets, c.Definition.ConfigurationTargets) ||
		!reflect.DeepEqual(before.VersionPolicy, c.Definition.VersionPolicy) ||
		!bytes.Equal(before.SettingsSchema, c.Definition.SettingsSchema) || !bytes.Equal(validBefore, c.Valid[0]) {
		t.Fatal("Check modified caller-owned data")
	}
}

func TestCheckRejectsBrokenAdapters(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Case)
		want   string
	}{
		{"invalid definition", func(c *Case) { c.Definition.ID = "Invalid ID" }, "definition:"},
		{"missing samples", func(c *Case) { c.Valid = nil }, "requires valid"},
		{"missing equivalents", func(c *Case) { c.Equivalent = nil }, "requires valid"},
		{"missing invalids", func(c *Case) { c.Invalid = nil }, "requires valid"},
		{"render failure", func(c *Case) {
			c.Definition.RenderSettings = func(json.RawMessage) (map[string][]byte, error) { return nil, errors.New("render failed") }
		}, "valid[0] render:"},
		{"wrong target name", func(c *Case) {
			c.Definition.RenderSettings = func(json.RawMessage) (map[string][]byte, error) {
				return map[string][]byte{"other": []byte("data")}, nil
			}
		}, "omitted declared target"},
		{"non-deterministic renderer", func(c *Case) {
			calls := 0
			c.Definition.RenderSettings = func(json.RawMessage) (map[string][]byte, error) {
				calls++
				return map[string][]byte{"config": fmt.Appendf(nil, "%d", calls)}, nil
			}
		}, "not deterministic"},
		{"repeat failure", func(c *Case) {
			calls := 0
			c.Definition.RenderSettings = func(raw json.RawMessage) (map[string][]byte, error) {
				calls++
				if calls == 2 {
					return nil, errors.New("second render failed")
				}
				return fixtureRenderer(true, true)(raw)
			}
		}, "repeat render:"},
		{"unknown fields accepted", func(c *Case) { c.Definition.RenderSettings = fixtureRenderer(false, true) }, "accepted unknown top-level field"},
		{"trailing value accepted", func(c *Case) { c.Definition.RenderSettings = fixtureRenderer(true, false) }, "accepted trailing JSON value"},
		{"invalid settings accepted", func(c *Case) { c.Invalid = []json.RawMessage{json.RawMessage(`{"name":"accepted"}`)} }, "invalid[0] renderer accepted"},
		{"unequal equivalents", func(c *Case) { c.Equivalent[0].Right = json.RawMessage(`{"name":"different"}`) }, "settings digests differ"},
		{"left digest error", func(c *Case) { c.Equivalent[0].Left = json.RawMessage(`{}`) }, "digest errors:"},
		{"right digest error", func(c *Case) { c.Equivalent[0].Right = json.RawMessage(`{}`) }, "digest errors:"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := fixtureCase()
			tc.mutate(&c)
			if failures := Check(c); !hasFailure(failures, tc.want) {
				t.Fatalf("failures = %v, want %q", failures, tc.want)
			}
		})
	}
}

func TestCloneIsolationRejectsEachAliasedField(t *testing.T) {
	for _, tc := range []struct {
		name  string
		alias func(*game.Definition, game.Definition)
	}{
		{"endpoints", func(clone *game.Definition, original game.Definition) { clone.Endpoints = original.Endpoints }},
		{"persistent paths", func(clone *game.Definition, original game.Definition) {
			clone.PersistentPaths = original.PersistentPaths
		}},
		{"configuration targets", func(clone *game.Definition, original game.Definition) {
			clone.ConfigurationTargets = original.ConfigurationTargets
		}},
		{"schema bytes", func(clone *game.Definition, original game.Definition) { clone.SettingsSchema = original.SettingsSchema }},
		{"version policy", func(clone *game.Definition, original game.Definition) { clone.VersionPolicy = original.VersionPolicy }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := fixtureCase().Definition
			clone := original.Clone()
			tc.alias(&clone, original)
			if failures := cloneIsolation(original, clone); !hasFailure(failures, "clone aliases "+tc.name) || !hasFailure(failures, "invalidated original") {
				t.Fatalf("aliased clone not detected: %v", failures)
			}
		})
	}
}
