// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package cligen

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestOfflineDeterministicGeneratedArtifacts(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/invalid/no-context")
	t.Setenv("XDG_STATE_HOME", "/invalid/no-state")
	t.Setenv("HTTPS_PROXY", "http://invalid:1")
	first, err := Files()
	if err != nil {
		t.Fatal("offline generation failed")
	}
	second, err := Files()
	if err != nil {
		t.Fatal("offline regeneration failed")
	}
	_, source, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(source), "..", "..", "docs", "generated", "cli")
	for name, contents := range first {
		expected, err := os.ReadFile(filepath.Join(root, name))
		if err != nil || !bytes.Equal(expected, contents) || !bytes.Equal(contents, second[name]) {
			t.Fatalf("generated CLI artifact drift: %s", name)
		}
	}
	help := string(first["commands.md"])
	for _, command := range []string{"login", "context use", "server create", "server configure", "server start", "server stop", "server restart", "server update", "server backup", "server restore", "server decommission", "server destroy", "retained-world destroy", "destroy confirm", "destroy cancel", "operation resume", "operation resolve"} {
		if !strings.Contains(help, "## arcadectl "+command+"\n") {
			t.Fatalf("command help missing: %s", command)
		}
	}
	for _, unsafe := range []string{"--token ", "--bearer ", "--yes ", "--challenge ", "--unsafe "} {
		if strings.Contains(help, unsafe) {
			t.Fatal("unsafe CLI flag introduced")
		}
	}
}
