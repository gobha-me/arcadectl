//go:build lifecycletest

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"github.com/gobha-me/arcadectl/internal/catalog"
	"github.com/gobha-me/arcadectl/internal/games/synthetic"
)

// controllerCatalog keeps the conformance adapter behind a compile-time test
// boundary. The production controller cannot enable it with a flag or
// environment variable.
func controllerCatalog() (*catalog.Catalog, error) {
	return catalog.New(synthetic.Definition())
}
