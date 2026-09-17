// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package synthetic

import (
	"bytes"
	"testing"
)

func TestDefinitionRendersBoundedLifecycleSettings(t *testing.T) {
	t.Parallel()

	definition := Definition()
	files, err := definition.RenderSettingsFiles([]byte(`{"seed":"first-seed","motd":"first message"}`))
	if err != nil {
		t.Fatalf("RenderSettingsFiles() error = %v", err)
	}
	want := map[string][]byte{
		"echo-config": []byte("listen=0.0.0.0:8080\n"),
		"motd":        []byte("first message\n"),
		"seed":        []byte("first-seed\n"),
	}
	if len(files) != len(want) {
		t.Fatalf("rendered files = %#v", files)
	}
	for _, file := range files {
		if !bytes.Equal(file.Contents, want[file.Name]) {
			t.Errorf("file %q = %q, want %q", file.Name, file.Contents, want[file.Name])
		}
	}
}

func TestDefinitionRejectsUnsafeLifecycleSettings(t *testing.T) {
	t.Parallel()

	definition := Definition()
	for _, settings := range [][]byte{
		[]byte(`{"seed":"contains spaces"}`),
		[]byte(`{"unknown":"value"}`),
		[]byte(`{"motd":""}`),
	} {
		if _, err := definition.RenderSettingsFiles(settings); err == nil {
			t.Errorf("RenderSettingsFiles(%s) succeeded", settings)
		}
	}
}
