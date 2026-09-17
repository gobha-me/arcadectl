//go:build !lifecycletest

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package main

import "github.com/gobha-me/arcadectl/internal/catalog"

func controllerCatalog() (*catalog.Catalog, error) {
	return catalog.Builtins()
}
