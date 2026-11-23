// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package sevendays_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/gobha-me/arcadectl/internal/games/sevendays"
)

// These fixtures preserve the complete experimental artifact, including fixed
// world/data identity, disabled administration, property order and omission.
// They describe renderer output, not a certified upstream server config.
func TestServerConfigXMLGolden(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, settings string
	}{
		{"minimal", `{"name":"Survival","visibility":"unlisted"}`},
		{"full", `{"name":"Co-op & friends","description":"Welcome <survivors> — café","maxPlayers":16,"visibility":"unlisted"}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			files, err := sevendays.Definition().RenderSettingsFiles(json.RawMessage(test.settings))
			if err != nil {
				t.Fatal(err)
			}
			if len(files) != 1 || files[0].Name != "serverconfig" || files[0].MountPath != "/sdtd/config/serverconfig.xml" {
				t.Fatalf("configuration targets = %#v, want only the declared XML file", files)
			}
			want, err := os.ReadFile(filepath.Join("testdata", test.name+".xml"))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(files[0].Contents, want) {
				t.Errorf("serverconfig XML differs from %s.xml\nwant:\n%s\ngot:\n%s", test.name, want, files[0].Contents)
			}
		})
	}
}
