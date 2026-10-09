// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installrender

import (
	"bytes"
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/gobha-me/arcadectl/config"
	"github.com/gobha-me/arcadectl/internal/installpackage"
)

func TestAuthenticLegacyAssetTreeIsSeparateAndCannotBeRelabelled(t *testing.T) {
	legacy, err := fs.Sub(config.LegacyInstallation, "legacy7dcbad")
	if err != nil {
		t.Fatal(err)
	}
	copy := make(fstest.MapFS)
	if err := fs.WalkDir(legacy, ".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		body, err := fs.ReadFile(legacy, path)
		if err != nil {
			return err
		}
		copy[path] = &fstest.MapFile{Data: bytes.Clone(body)}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(copy) != 31 || !legacyAssetTreeMatches(copy) {
		t.Fatal("authentic predecessor bytes or whole-tree hash changed")
	}
	currentRole, err := config.Installation.ReadFile("rbac/role.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(currentRole, copy["rbac/role.yaml"].Data) {
		t.Fatal("current ReplicaSet read authority leaked into frozen predecessor")
	}
	copy["rbac/role.yaml"].Data = currentRole
	if legacyAssetTreeMatches(copy) {
		t.Fatal("current Role was silently relabelled as authentic predecessor")
	}
	if _, err := config.Installation.ReadFile("legacy7dcbad/rbac/role.yaml"); err == nil {
		t.Fatal("frozen assets were admitted into current embed surface")
	}
}

func TestLegacyAndCurrentRenderUseTheirOwnReviewedRoles(t *testing.T) {
	images := installpackage.Images{Controller: "registry.example/controller@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", API: "registry.example/api@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
	legacy, _, err := RenderPayloads(images, true)
	if err != nil {
		t.Fatal(err)
	}
	current, _, err := RenderPayloads(images, false)
	if err != nil {
		t.Fatal(err)
	}
	legacyObjects, err := decodeRendered(legacy[installpackage.ControllerPath])
	if err != nil {
		t.Fatal(err)
	}
	currentObjects, err := decodeRendered(current[installpackage.ControllerPath])
	if err != nil {
		t.Fatal(err)
	}
	if len(legacyObjects) != 27 || len(currentObjects) != 27 {
		t.Fatal("renderer resource counts changed")
	}
	if bytes.Contains(legacy[installpackage.ControllerPath], []byte(`"replicasets"`)) || !bytes.Contains(current[installpackage.ControllerPath], []byte(`"replicasets"`)) {
		t.Fatal("legacy/current read authority was not routed independently")
	}
	// Existing signed-package Compile tests must still validate the genuine
	// predecessor, not merely a new manifest declaring that predecessor exists.
	mustCompile(t, true, DefaultNamespace, Profile137)
	mustCompile(t, false, "isolated-install", Profile135)
}
