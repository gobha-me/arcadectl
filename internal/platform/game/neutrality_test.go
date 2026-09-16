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

	forbidden := []string{"factorio", "/factorio", "rcon", "34197", "27015", "845"}
	err := filepath.WalkDir("..", func(filename string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || filepath.Ext(filename) != ".go" || strings.HasSuffix(filename, "_test.go") {
			return nil
		}
		contents, err := os.ReadFile(filename)
		if err != nil {
			return err
		}
		lower := strings.ToLower(string(contents))
		for _, token := range forbidden {
			if strings.Contains(lower, token) {
				t.Errorf("production core file %s contains adapter-specific token %q", filename, token)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scan production core: %v", err)
	}
}
