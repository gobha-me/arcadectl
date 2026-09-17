//go:build lifecycletest

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package main

import "testing"

func TestLifecycleControllerCatalogContainsOnlySyntheticAdapter(t *testing.T) {
	t.Parallel()

	gameCatalog, err := controllerCatalog()
	if err != nil {
		t.Fatalf("controllerCatalog() error = %v", err)
	}
	definitions := gameCatalog.List()
	if len(definitions) != 1 || definitions[0].ID != "conformance-echo" {
		t.Fatalf("lifecycle controller catalog = %#v, want only synthetic fixture", definitions)
	}
}
