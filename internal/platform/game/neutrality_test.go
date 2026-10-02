// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package game

import (
	"os"
	"path/filepath"
	"regexp"
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
			if referenceAdapterToken(lower, token) {
				t.Errorf("production core file %s contains adapter-specific token %q", filename, token)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scan production core: %v", err)
	}
}

// Exclude only the complete standard-library identifier/import strconv, whose
// spelling happens to include rcon. Keep the original broad scan elsewhere,
// including adapter vocabulary embedded inside camel-case identifiers.
func referenceAdapterToken(source, token string) bool {
	withoutStandardLibrary := regexp.MustCompile(`\bstrconv\b`).ReplaceAllString(source, "")
	return strings.Contains(withoutStandardLibrary, token)
}

func TestReferenceAdapterTokenDoesNotConfuseStandardLibraryNames(t *testing.T) {
	for _, source := range []string{`"strconv"`, `strconv.ParseInt(value, 10, 64)`, `maxVersionDigits = 128`} {
		if referenceAdapterToken(strings.ToLower(source), "rcon") {
			t.Fatal("standard library identifier misclassified")
		}
	}
	for _, source := range []string{`"rcon"`, `RCONPort`, `legacyRCONPort`, `"/factorio/saves"`, `port = 34197`} {
		token := "rcon"
		if strings.Contains(source, "factorio") {
			token = "factorio"
		} else if strings.Contains(source, "34197") {
			token = "34197"
		}
		if !referenceAdapterToken(strings.ToLower(source), token) {
			t.Fatal("adapter assumption not detected")
		}
	}
}
