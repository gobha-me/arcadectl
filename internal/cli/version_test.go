// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/gobha-me/arcadectl/internal/buildinfo"
)

func TestVersionIsOfflineAndDoesNotCreateClientState(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "must-not-exist")
	var out, stderr bytes.Buffer
	options := Options{Out: &out, Err: &stderr, ConfigDir: directory, StateDir: directory}
	if code := Run(context.Background(), []string{"version", "--output", "json"}, options); code != 0 || stderr.Len() != 0 {
		t.Fatal("offline version required authentication or state")
	}
	var got buildinfo.Info
	if json.Unmarshal(out.Bytes(), &got) != nil || got != buildinfo.Current() {
		t.Fatal("version output lost source/platform claims")
	}
	if _, err := os.Stat(directory); !os.IsNotExist(err) {
		t.Fatal("version created client state")
	}
}
