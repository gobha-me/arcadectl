// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

// Package catalog stores validated, curated game definitions.
package catalog

import (
	"errors"
	"fmt"
	"sort"

	"github.com/gobha-me/arcadectl/internal/games/factorio"
	"github.com/gobha-me/arcadectl/internal/platform/game"
)

// Catalog is an immutable registry of validated game definitions.
type Catalog struct {
	definitions map[string]game.Definition
}

// New validates definitions and rejects duplicate identifiers.
func New(definitions ...game.Definition) (*Catalog, error) {
	catalog := &Catalog{definitions: make(map[string]game.Definition, len(definitions))}
	for _, definition := range definitions {
		if err := definition.Validate(); err != nil {
			return nil, fmt.Errorf("validate game %q: %w", definition.ID, err)
		}
		if _, exists := catalog.definitions[definition.ID]; exists {
			return nil, fmt.Errorf("game id %q is duplicated", definition.ID)
		}
		catalog.definitions[definition.ID] = definition.Clone()
	}
	return catalog, nil
}

// Builtins returns the production catalog. Test-only conformance adapters are
// deliberately excluded.
func Builtins() (*Catalog, error) {
	return New(factorio.Definition())
}

// Get returns an isolated copy of a definition.
func (c *Catalog) Get(id string) (game.Definition, error) {
	definition, exists := c.definitions[id]
	if !exists {
		return game.Definition{}, errors.New("game is not installed")
	}
	return definition.Clone(), nil
}

// List returns isolated definition copies ordered by stable identifier.
func (c *Catalog) List() []game.Definition {
	ids := make([]string, 0, len(c.definitions))
	for id := range c.definitions {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	definitions := make([]game.Definition, 0, len(ids))
	for _, id := range ids {
		definitions = append(definitions, c.definitions[id].Clone())
	}
	return definitions
}
