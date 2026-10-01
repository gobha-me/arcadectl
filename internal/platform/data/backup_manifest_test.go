// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package data

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	arcadev1alpha1 "github.com/gobha-me/arcadectl/api/v1alpha1"
)

func TestBuildBackupManifestIsCanonicalAndComplete(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	for _, path := range []string{"world", "mods"} {
		if err := os.Mkdir(filepath.Join(root, path), 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", path, err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "world", "save.zip"), []byte("world-bytes"), 0o600); err != nil {
		t.Fatalf("write world: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "mods", "mod-list.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write mods: %v", err)
	}
	input := backupManifestInput()
	manifest, first, err := BuildBackupManifest(input, root)
	if err != nil {
		t.Fatalf("BuildBackupManifest() error = %v", err)
	}
	_, second, err := BuildBackupManifest(input, root)
	if err != nil {
		t.Fatalf("BuildBackupManifest() repeat error = %v", err)
	}
	if string(first) != string(second) {
		t.Fatal("canonical manifest changed across identical reads")
	}
	if manifest.FormatVersion != BackupFormatVersion || manifest.ServerUID != "server-uid" || manifest.Game != "factorio" || len(manifest.Paths) != 2 {
		t.Fatalf("manifest identity = %#v", manifest)
	}
	if manifest.Paths[0].Name != "mods" || manifest.Paths[1].Name != "world" {
		t.Fatalf("path order = %#v, want stable name order", manifest.Paths)
	}
	for _, path := range manifest.Paths {
		if len(path.Files) != 1 || !strings.HasPrefix(path.Files[0].SHA256, "sha256:") {
			t.Fatalf("path checksums = %#v, want one SHA-256 file", path)
		}
	}
	if !strings.HasPrefix(ManifestDigest(first), "sha256:") {
		t.Fatalf("manifest digest = %q", ManifestDigest(first))
	}
	if !json.Valid(first) || strings.Contains(string(first), "repository-password") {
		t.Fatal("manifest is invalid JSON or contains credential material")
	}
}

func TestBuildBackupManifestRejectsSpecialFiles(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	for _, path := range []string{"world", "mods"} {
		if err := os.Mkdir(filepath.Join(root, path), 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", path, err)
		}
	}
	if err := os.Symlink("outside", filepath.Join(root, "world", "unsafe")); err != nil {
		t.Fatalf("create symlink: %v", err)
	}
	if _, _, err := BuildBackupManifest(backupManifestInput(), root); err == nil || !strings.Contains(err.Error(), "non-regular") {
		t.Fatalf("BuildBackupManifest() error = %v, want special-file refusal", err)
	}
}

func backupManifestInput() BackupWorkerInput {
	return BackupWorkerInput{
		Version: WorkerInputVersion, ArtifactID: "backup-artifact",
		OperationRef:    arcadev1alpha1.ExactLocalReference{Name: "backup", UID: "backup-uid"},
		WorkerLeaseName: "data-operation-lease",
		RepositorySecretRef: arcadev1alpha1.ExactSecretReference{
			ExactLocalReference: arcadev1alpha1.ExactLocalReference{Name: "repository", UID: "secret-uid"}, ResourceVersion: "42",
		},
		Source: arcadev1alpha1.DataSourceSnapshot{
			GameServer: arcadev1alpha1.ExactGameServerReference{
				ExactLocalReference: arcadev1alpha1.ExactLocalReference{Name: "factory", UID: "server-uid"},
				Generation:          1, DesiredState: arcadev1alpha1.DesiredStateStopped,
			},
			Game: "factorio", ImageDigest: "sha256:" + strings.Repeat("1", 64), SettingsDigest: "sha256:" + strings.Repeat("2", 64),
			Paths: []arcadev1alpha1.DataPathIdentity{
				{Name: "world", MountPath: "/factorio", ClaimRef: arcadev1alpha1.ExactLocalReference{Name: "world-pvc", UID: "world-uid"}},
				{Name: "mods", MountPath: "/factorio-mods", ClaimRef: arcadev1alpha1.ExactLocalReference{Name: "mods-pvc", UID: "mods-uid"}},
			},
		},
	}
}
