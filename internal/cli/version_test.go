// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
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

func TestVersionHumanOutputRemainsOffline(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "must-not-exist")
	var out, stderr bytes.Buffer
	options := Options{Out: &out, Err: &stderr, ConfigDir: directory, StateDir: directory}
	if code := Run(t.Context(), []string{"version"}, options); code != 0 || stderr.Len() != 0 {
		t.Fatal("human version required authentication or state")
	}
	if !strings.HasPrefix(out.String(), "arcadectl source=") || !strings.Contains(out.String(), buildinfo.Current().GoVersion) {
		t.Fatal("human version lost its build identity output")
	}
	if _, err := os.Stat(directory); !os.IsNotExist(err) {
		t.Fatal("human version created client state")
	}
}

type versionOutputFailure struct{}

func (versionOutputFailure) Write([]byte) (int, error) {
	return 0, errors.New("PRIVATE-VERSION-WRITER-CANARY")
}

func TestVersionWriteFailuresRemainOffline(t *testing.T) {
	for _, format := range []string{"human", "json"} {
		t.Run(format, func(t *testing.T) {
			directory := filepath.Join(t.TempDir(), "must-not-exist")
			var stderr bytes.Buffer
			options := Options{Out: versionOutputFailure{}, Err: &stderr, ConfigDir: directory, StateDir: directory}
			if code := Run(t.Context(), []string{"version", "--output", format}, options); code != 1 {
				t.Fatalf("version output failure returned exit %d, want local I/O exit 1", code)
			}
			if !strings.Contains(stderr.String(), "local_io") || strings.Contains(stderr.String(), "PRIVATE-VERSION-WRITER-CANARY") {
				t.Fatal("version write failure lost its stable error or leaked writer details")
			}
			if _, err := os.Stat(directory); !os.IsNotExist(err) {
				t.Fatal("version output failure created client state")
			}
		})
	}
}
