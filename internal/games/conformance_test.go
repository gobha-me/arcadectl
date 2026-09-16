// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package games_test

import (
	"testing"

	"github.com/gobha-me/arcadectl/internal/games/factorio"
	"github.com/gobha-me/arcadectl/internal/games/synthetic"
	"github.com/gobha-me/arcadectl/internal/platform/game"
)

func TestDefinitionsConform(t *testing.T) {
	t.Parallel()

	definitions := []game.Definition{factorio.Definition(), synthetic.Definition()}
	for _, definition := range definitions {
		definition := definition
		t.Run(definition.ID, func(t *testing.T) {
			t.Parallel()
			if err := definition.Validate(); err != nil {
				t.Fatalf("adapter definition is invalid: %v", err)
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
}
