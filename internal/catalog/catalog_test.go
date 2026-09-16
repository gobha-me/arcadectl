// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package catalog

import (
	"testing"

	"github.com/gobha-me/arcadectl/internal/games/factorio"
)

func TestBuiltinsContainsOnlyCertifiedAdapters(t *testing.T) {
	t.Parallel()

	catalog, err := Builtins()
	if err != nil {
		t.Fatalf("Builtins() error = %v", err)
	}
	definitions := catalog.List()
	if len(definitions) != 1 || definitions[0].ID != "factorio" {
		t.Fatalf("Builtins() = %#v, want only factorio", definitions)
	}
}

func TestCatalogRejectsDuplicates(t *testing.T) {
	t.Parallel()

	definition := factorio.Definition()
	if _, err := New(definition, definition); err == nil {
		t.Fatal("New() accepted duplicate game identifiers")
	}
}

func TestCatalogReturnsIsolatedDefinitions(t *testing.T) {
	t.Parallel()

	catalog, err := Builtins()
	if err != nil {
		t.Fatalf("Builtins() error = %v", err)
	}
	first, err := catalog.Get("factorio")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	first.Endpoints[0].Name = "changed"

	second, err := catalog.Get("factorio")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if second.Endpoints[0].Name == "changed" {
		t.Fatal("Get() exposed mutable catalog state")
	}
}
