// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package games_test

import (
	"encoding/json"
	"testing"

	"github.com/gobha-me/arcadectl/internal/games/factorio"
	"github.com/gobha-me/arcadectl/internal/games/synthetic"
	"github.com/gobha-me/arcadectl/internal/platform/game"
)

func TestDefinitionsConform(t *testing.T) {
	t.Parallel()

	tests := []struct {
		definition game.Definition
		settings   json.RawMessage
	}{
		{factorio.Definition(), json.RawMessage(`{"name":"test","visibility":"private"}`)},
		{synthetic.Definition(), json.RawMessage(`{}`)},
	}
	for _, test := range tests {
		test := test
		t.Run(test.definition.ID, func(t *testing.T) {
			t.Parallel()
			if err := test.definition.Validate(); err != nil {
				t.Fatalf("adapter definition is invalid: %v", err)
			}
			files, err := test.definition.RenderSettingsFiles(test.settings)
			if err != nil {
				t.Fatalf("adapter settings renderer is invalid: %v", err)
			}
			if len(files) != len(test.definition.ConfigurationTargets) {
				t.Fatalf("rendered files = %d, targets = %d", len(files), len(test.definition.ConfigurationTargets))
			}
		})
	}
}

func TestSyntheticAdapterIsARealCounterexample(t *testing.T) {
	t.Parallel()

	reference := factorio.Definition()
	counterexample := synthetic.Definition()
	if counterexample.PersistentPaths[0].MountPath == reference.PersistentPaths[0].MountPath {
		t.Fatal("synthetic adapter must use a different persistent path")
	}
	if counterexample.Endpoints[0].Protocol == reference.Endpoints[0].Protocol {
		t.Fatal("synthetic adapter must exercise a different player protocol")
	}
	if len(counterexample.Endpoints) == len(reference.Endpoints) {
		t.Fatal("synthetic adapter must exercise a different endpoint shape")
	}
	if len(counterexample.ConfigurationTargets) == len(reference.ConfigurationTargets) {
		t.Fatal("synthetic adapter must exercise a different configuration shape")
	}
	if counterexample.RuntimeIdentity == reference.RuntimeIdentity {
		t.Fatal("synthetic adapter must exercise a different runtime identity")
	}
}
