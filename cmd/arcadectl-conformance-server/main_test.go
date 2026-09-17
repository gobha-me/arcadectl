// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStateStorePreservesMarkerAcrossConfigurationUpdates(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFixtureFile(t, filepath.Join(root, "config", "seed.txt"), "first-seed\n")
	writeFixtureFile(t, filepath.Join(root, "config", "motd.txt"), "first message\n")
	store := stateStore{root: root}
	first, err := store.initialize()
	if err != nil {
		t.Fatalf("initialize first boot: %v", err)
	}
	if first.Marker != "first-seed" || first.Seed != "first-seed" || first.MOTD != "first message" || first.Boots != 1 {
		t.Fatalf("first snapshot = %#v", first)
	}

	writeFixtureFile(t, filepath.Join(root, "config", "seed.txt"), "second-seed\n")
	writeFixtureFile(t, filepath.Join(root, "config", "motd.txt"), "updated message\n")
	second, err := store.initialize()
	if err != nil {
		t.Fatalf("initialize second boot: %v", err)
	}
	if second.Marker != "first-seed" || second.Seed != "second-seed" || second.MOTD != "updated message" || second.Boots != 2 {
		t.Fatalf("second snapshot = %#v", second)
	}
}

func TestReadLineRejectsMultipleLines(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "value")
	writeFixtureFile(t, path, "one\ntwo\n")
	if _, err := readLine(path); err == nil {
		t.Fatal("readLine accepted multiple lines")
	}
}

func TestOperationCategoriesDoNotEchoArguments(t *testing.T) {
	t.Parallel()

	tests := []struct {
		arguments []string
		want      string
	}{
		{arguments: nil, want: "server startup"},
		{arguments: []string{"get", "http://sensitive.invalid"}, want: "service probe"},
		{arguments: []string{"read-marker"}, want: "marker read"},
	}
	for _, test := range tests {
		if got := operation(test.arguments); got != test.want {
			t.Errorf("operation(%q) = %q, want %q", test.arguments, got, test.want)
		}
	}
}

func writeFixtureFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("create fixture directory: %v", err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("write fixture file: %v", err)
	}
}
