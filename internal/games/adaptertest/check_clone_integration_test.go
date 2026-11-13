// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package adaptertest

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/gobha-me/arcadectl/internal/games/factorio"
	"github.com/gobha-me/arcadectl/internal/platform/game"
)

func cloneIntegrationCase() Case {
	return Case{
		Definition: factorio.Definition(),
		Valid: []json.RawMessage{
			json.RawMessage(`{"name":"clone-integration","visibility":"private"}`),
			json.RawMessage(`{"name":"clone-order","visibility":"lan","description":"fixture","maxPlayers":4}`),
		},
		Equivalent: []EquivalentPair{{
			Left:  json.RawMessage(`{"name":"clone-integration","visibility":"private"}`),
			Right: json.RawMessage(`{ "visibility": "private", "name": "clone-integration" }`),
		}},
		Invalid: []json.RawMessage{
			json.RawMessage(`{"name":"","visibility":"private"}`),
			json.RawMessage(`{"name":"invalid","visibility":"public"}`),
			json.RawMessage(`{"name":`),
		},
	}
}

func requireCloneIntegrationCallerUnchanged(t *testing.T, got Case) {
	t.Helper()
	// Construct fresh expected buffers independently of Clone and detached:
	// neither boundary under test can corrupt this comparison's preimage.
	want := cloneIntegrationCase()
	got.Definition.RenderSettings = nil
	want.Definition.RenderSettings = nil
	if !reflect.DeepEqual(got, want) {
		t.Error("check changed the caller-owned definition or settings sample buffers")
	}
}

func TestCheckCloneBoundaryAcceptsRealClone(t *testing.T) {
	c := cloneIntegrationCase()
	for attempt := range 2 {
		if failures := check(c, game.Definition.Clone); len(failures) != 0 {
			t.Fatalf("attempt %d: real Factorio adapter and Clone failed: %v", attempt, failures)
		}
		if failures := Check(c); len(failures) != 0 {
			t.Fatalf("attempt %d: public Check failed: %v", attempt, failures)
		}
		requireCloneIntegrationCallerUnchanged(t, c)
	}
}

func TestCheckCloneBoundaryReportsAliasingAndPreservesCaller(t *testing.T) {
	for _, tc := range []struct {
		name       string
		clone      func(game.Definition) game.Definition
		wantFields []string
	}{
		{
			name:  "identity callback aliases every field",
			clone: func(d game.Definition) game.Definition { return d },
			wantFields: []string{
				"endpoints", "persistent paths", "configuration targets", "schema bytes", "version policy",
			},
		},
		{
			name: "endpoints only",
			clone: func(d game.Definition) game.Definition {
				clone := d.Clone()
				clone.Endpoints = d.Endpoints
				return clone
			},
			wantFields: []string{"endpoints"},
		},
		{
			name: "persistent paths only",
			clone: func(d game.Definition) game.Definition {
				clone := d.Clone()
				clone.PersistentPaths = d.PersistentPaths
				return clone
			},
			wantFields: []string{"persistent paths"},
		},
		{
			name: "configuration targets only",
			clone: func(d game.Definition) game.Definition {
				clone := d.Clone()
				clone.ConfigurationTargets = d.ConfigurationTargets
				return clone
			},
			wantFields: []string{"configuration targets"},
		},
		{
			name: "schema bytes only",
			clone: func(d game.Definition) game.Definition {
				clone := d.Clone()
				clone.SettingsSchema = d.SettingsSchema
				return clone
			},
			wantFields: []string{"schema bytes"},
		},
		{
			name: "version policy only",
			clone: func(d game.Definition) game.Definition {
				clone := d.Clone()
				clone.VersionPolicy = d.VersionPolicy
				return clone
			},
			wantFields: []string{"version policy"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := cloneIntegrationCase()
			for attempt := range 2 {
				calls := 0
				// Inject only the requested cloning boundary. The real check,
				// renderer, validation and clone-isolation path all execute.
				failures := check(c, func(d game.Definition) game.Definition {
					calls++
					return tc.clone(d)
				})
				if calls != 1 {
					t.Errorf("attempt %d: clone callback called %d times, want 1", attempt, calls)
				}
				if len(failures) != len(tc.wantFields)+1 {
					t.Errorf("attempt %d: failures = %v, want each alias and invalidated-original error", attempt, failures)
				}
				for _, field := range tc.wantFields {
					want := "clone aliases " + field
					found := false
					for _, err := range failures {
						if err.Error() == want {
							found = true
						}
					}
					if !found {
						t.Errorf("attempt %d: failures = %v, missing %q", attempt, failures, want)
					}
				}
				invalidated := false
				for _, err := range failures {
					if strings.HasPrefix(err.Error(), "clone mutation invalidated original: ") {
						invalidated = true
					}
				}
				if !invalidated {
					t.Errorf("attempt %d: failures = %v, missing original validation failure", attempt, failures)
				}
				requireCloneIntegrationCallerUnchanged(t, c)
				if failures := check(c, game.Definition.Clone); len(failures) != 0 {
					t.Fatalf("attempt %d: aliasing check poisoned later conforming check: %v", attempt, failures)
				}
				requireCloneIntegrationCallerUnchanged(t, c)
			}
		})
	}
}
