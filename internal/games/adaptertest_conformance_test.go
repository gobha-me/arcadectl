// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package games_test

import (
	"encoding/json"
	"testing"

	"github.com/gobha-me/arcadectl/internal/games/adaptertest"
	"github.com/gobha-me/arcadectl/internal/games/factorio"
	"github.com/gobha-me/arcadectl/internal/games/synthetic"
)

func TestAdapterKitConformance(t *testing.T) {
	for _, c := range []adaptertest.Case{
		{
			Definition: factorio.Definition(),
			Valid: []json.RawMessage{
				json.RawMessage(`{"name":"test","visibility":"private"}`),
				json.RawMessage(`{"name":"LAN","description":"hello","visibility":"lan","maxPlayers":4}`),
			},
			Equivalent: []adaptertest.EquivalentPair{{
				Left:  json.RawMessage(`{"name":"test","visibility":"private"}`),
				Right: json.RawMessage(`{ "visibility": "private", "name": "test" }`),
			}},
			Invalid: []json.RawMessage{json.RawMessage(`{}`), json.RawMessage(`{"name":"test","visibility":"public"}`)},
		},
		{
			Definition: synthetic.Definition(),
			Valid:      []json.RawMessage{json.RawMessage(`{}`), json.RawMessage(`{"seed":"other","motd":"hello"}`)},
			Equivalent: []adaptertest.EquivalentPair{{
				Left:  json.RawMessage(`{"seed":"other","motd":"hello"}`),
				Right: json.RawMessage(`{ "motd": "hello", "seed": "other" }`),
			}},
			Invalid: []json.RawMessage{json.RawMessage(`{"seed":""}`), json.RawMessage(`{"motd":"hello\nworld"}`)},
		},
	} {
		t.Run(c.Definition.ID, func(t *testing.T) {
			adaptertest.Run(t, c)
		})
	}
}
