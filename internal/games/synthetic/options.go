// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package synthetic

import (
	"encoding/json"

	"github.com/gobha-me/arcadectl/internal/platform/game"
)

func optionMetadata() *game.OptionMetadata {
	return &game.OptionMetadata{Version: game.OptionMetadataVersion, Supported: []game.SettingOption{
		{ID: "seed", Property: "seed", Label: "Seed", Help: "Lowercase seed text for the conformance fixture. Omission uses default-seed.", Group: "fixture", Schema: json.RawMessage(`{"type":"string","minLength":1,"maxLength":64,"pattern":"^[a-z0-9-]+$"}`), Lifecycle: game.OptionRestartRequired, Omission: game.OptionRendererValue, OmittedValue: json.RawMessage(`"default-seed"`), Default: json.RawMessage(`"default-seed"`)},
		{ID: "motd", Property: "motd", Label: "Message of the day", Help: "Single-line greeting. The renderer additionally refuses carriage returns and newlines.", Group: "fixture", Schema: json.RawMessage(`{"type":"string","minLength":1,"maxLength":128}`), Lifecycle: game.OptionRestartRequired, Omission: game.OptionRendererValue, OmittedValue: json.RawMessage(`"Arcadectl conformance server"`), Default: json.RawMessage(`"Arcadectl conformance server"`)},
	}, Unsupported: []game.UnsupportedOption{
		{ID: "commands", Reason: "Arbitrary commands are outside the adapter contract."},
	}}
}
