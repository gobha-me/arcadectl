// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package game

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProductionCoreContainsNoReferenceAdapterAssumptions(t *testing.T) {
	t.Parallel()

	forbidden := []string{"factorio", "/factorio", "rcon", "34197", "27015"}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir(): %v", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".go" || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		contents, err := os.ReadFile(entry.Name())
		if err != nil {
			t.Fatalf("ReadFile(%q): %v", entry.Name(), err)
		}
		lower := strings.ToLower(string(contents))
		for _, token := range forbidden {
			if strings.Contains(lower, token) {
				t.Errorf("production core file %s contains adapter-specific token %q", entry.Name(), token)
			}
		}
	}
}
