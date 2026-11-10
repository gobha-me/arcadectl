// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package factorio

import (
	"encoding/json"

	"github.com/gobha-me/arcadectl/internal/platform/game"
)

func optionMetadata() *game.OptionMetadata {
	return &game.OptionMetadata{Version: game.OptionMetadataVersion, Supported: []game.SettingOption{
		{ID: "name", Property: "name", Label: "Server name", Help: "Name written to server settings.", Group: "server", Schema: json.RawMessage(`{"type":"string","minLength":1,"maxLength":80}`), Lifecycle: game.OptionRestartRequired, Omission: game.OptionRequired},
		{ID: "description", Property: "description", Label: "Description", Help: "Omission renders an empty description.", Group: "server", Schema: json.RawMessage(`{"type":"string","maxLength":200}`), Lifecycle: game.OptionRestartRequired, Omission: game.OptionRendererValue, OmittedValue: json.RawMessage(`""`), Default: json.RawMessage(`""`)},
		{ID: "max-players", Property: "maxPlayers", Label: "Player capacity", Help: "Explicit values are 1 through 65535. Omission renders the engine's zero sentinel; it is not an explicit allowed value.", Group: "server", Schema: json.RawMessage(`{"type":"integer","minimum":1,"maximum":65535}`), Lifecycle: game.OptionRestartRequired, Omission: game.OptionRendererValue, OmittedValue: json.RawMessage(`0`)},
		{ID: "visibility", Property: "visibility", Label: "Visibility", Help: "Private or LAN visibility. Public listing requires a future secret-reference contract.", Group: "network", Schema: json.RawMessage(`{"type":"string","enum":["private","lan"]}`), Lifecycle: game.OptionRestartRequired, Omission: game.OptionRequired},
	}, Unsupported: []game.UnsupportedOption{
		{ID: "world-generation", Reason: "World generation is outside the supported settings subset; create-only enforcement needs a reviewed capability."},
		{ID: "game-credentials", Reason: "Settings are non-secret. Game credential references require a reviewed secret capability."},
		{ID: "public-listing", Reason: "Public visibility is refused until the secret-reference contract exists."},
	}}
}
